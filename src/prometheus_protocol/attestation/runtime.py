"""Resolve the live posture by building what the runtime would actually build.

This is the half that makes PIH-4a mean anything: it does not read
:class:`~prometheus_protocol.core.config.Config` fields and report them back. It
calls the same builders the production path calls — ``build_sandbox_for``,
``build_tip_anchor_for``, ``resolve_substrate_policy`` / ``probe_substrate`` —
and records what came back. Where a builder refuses, resolution raises, and the
verify entrypoint reports NOT_VERIFIABLE rather than attesting a posture nobody
could establish.

The signer is passed in rather than rebuilt, because it is the same object the
attestor signs with: the posture records the custody actually in use, and there
is no second path that could resolve a different one.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from prometheus_protocol.attestation.attest import (
    AttestationTarget,
    ConfigAttestor,
    build_attestation_target,
)
from prometheus_protocol.attestation.posture import (
    TARGET_NONE,
    ResolvedPosture,
)
from prometheus_protocol.chokepoint.signer import ApprovalSigner
from prometheus_protocol.chokepoint.substrate import (
    SUBSTRATE_UNKNOWN,
    probe_substrate,
    resolve_substrate_policy,
)
from prometheus_protocol.core.anchor_spec import parse_anchor_spec
from prometheus_protocol.core.booleans import parse_env_bool
from prometheus_protocol.core.config import Config
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.runtime.factory import (
    build_sandbox_for,
    build_tip_anchor_for,
    ledger_anchor_required,
)

_LOG = logging.getLogger(__name__)

#: The environment half of the requirement, so it is the OR of its sources the
#: same way every other security requirement in this repository is.
CONFIG_ATTESTATION_REQUIRED_ENV = "PROM_REQUIRE_CONFIG_ATTESTATION"


def config_attestation_required(env: Mapping[str, str] | None = None) -> bool:
    """Read through the one strict boolean parser (F9, ``core/booleans.py``):
    unset takes the default, a misspelling is refused, never read as False."""

    import os

    env = os.environ if env is None else env
    return parse_env_bool(
        CONFIG_ATTESTATION_REQUIRED_ENV,
        env.get(CONFIG_ATTESTATION_REQUIRED_ENV),
        default=False,
    )


def attestation_target_for(
    config: Config, *, env: Mapping[str, str] | None = None
) -> AttestationTarget | None:
    """The target ``config`` names, or ``None`` when attestation is not set up.

    A requirement that cannot be honoured is refused here rather than degraded:
    required with no target configured, or with a ``file://`` one — a single
    local file the config-changing adversary rewrites in the same breath — is a
    ``ConfigError``, exactly as a required ledger anchor is.
    """

    required = bool(config.require_config_attestation) or config_attestation_required(env)
    if not config.config_attestation_target:
        if required:
            raise ConfigError(
                "config attestation is required "
                f"({CONFIG_ATTESTATION_REQUIRED_ENV}=1 or "
                "require_config_attestation=True) and no target is configured. "
                "Set PROM_CONFIG_ATTESTATION_TARGET to worm:///directory or "
                "https://host/path (docs/threat-model.md §4)."
            )
        return None
    spec = parse_anchor_spec(
        config.config_attestation_target,
        name="config_attestation_target",
        allow_insecure_loopback=config.allow_insecure_loopback,
    )
    target = build_attestation_target(
        spec,
        token=config.config_attestation_token,
        retain_for_s=config.ledger_anchor_retention_days * 86_400.0,
        timeout_s=config.request_timeout_s,
        allow_insecure_loopback=config.allow_insecure_loopback,
    )
    if required and not target.external:
        raise ConfigError(
            "a required config attestation cannot be honoured by "
            f"{config.config_attestation_target!r}: a single local file is "
            "rewritten in place, so whoever changes the running configuration "
            "rewrites the record of it in the same breath. The requirement is "
            "for an external witness; use worm:// or https://."
        )
    if not target.external:
        _LOG.warning(
            "config attestation target %s is a single local file: NON-PROTECTING "
            "against anyone who can change this host's configuration, which is "
            "the adversary it exists for. Development only; production uses "
            "worm:// or https://.",
            config.config_attestation_target,
        )
    return target


@dataclass(frozen=True)
class _SignerRequest:
    """An argument carrier for PIH-2's ``resolve_signer``, which reads exactly
    these three attributes. It is not a second custody decision: the policy —
    whether an external signer is required, and the refusal of a local key
    under it — stays in ``chokepoint.runner.resolve_signer``."""

    signer: ApprovalSigner | None = None
    signing_key: bytes | None = None
    require_external_signer: bool = False


def resolve_attestation_signer(
    config: Config,
    *,
    signer: ApprovalSigner | None = None,
    signing_key: bytes | None = None,
    env: Mapping[str, str] | None = None,
) -> ApprovalSigner:
    """The signer the attestation is sealed with, through PIH-2's own resolver.

    ``require_external_signer`` therefore applies to attestations exactly as it
    applies to approvals: under it a local key is refused, and there is no path
    from a configured external signer back to one.

    A signer or a key must be supplied. A key generated per process would give
    every process a different ``signer_key_id`` — a genuinely different custody
    posture — so the next process could never verify the last one's attestation.
    Refusing is clearer than that trap.
    """

    from prometheus_protocol.chokepoint.runner import resolve_signer

    if signer is None and signing_key is None:
        raise ConfigError(
            "config attestation needs a signer: wire an external signer "
            "(KmsSigner, docs/key-custody.md) or supply a local development "
            "key. A key generated per process would make each attestation "
            "unverifiable by the next one."
        )
    return resolve_signer(
        _SignerRequest(signer=signer, signing_key=signing_key),
        settings=config,
        env=env,
    )


def resolve_posture(
    config: Config,
    *,
    signer: ApprovalSigner,
    env: Mapping[str, str] | None = None,
    storage_path: str | Path | None = None,
    target: AttestationTarget | None = None,
) -> ResolvedPosture:
    """Build what the runtime would build, and report what came back.

    ``storage_path`` is the directory whose filesystem the execution guard's
    substrate check classifies; it defaults to the ledger's directory, which is
    where this runtime's durable state lives.
    """

    sandbox = build_sandbox_for(config, env=env)
    anchor = build_tip_anchor_for(config, env=env)
    anchor_class = TARGET_NONE
    if config.ledger_anchor:
        anchor_class = parse_anchor_spec(
            config.ledger_anchor,
            name="ledger_anchor",
            allow_insecure_loopback=config.allow_insecure_loopback,
        ).kind
    if target is None:
        target = attestation_target_for(config, env=env)

    policy = resolve_substrate_policy(settings=config, env=env)
    location = Path(storage_path) if storage_path is not None else Path(config.ledger_path).parent
    if str(config.ledger_path) == ":memory:" and storage_path is None:
        # No durable store to classify; unknown is the honest answer, and it is
        # the same answer the guard itself would reach.
        substrate_verdict, substrate_fs_type = SUBSTRATE_UNKNOWN, None
    else:
        report = probe_substrate(location)
        substrate_verdict, substrate_fs_type = report.verdict, report.fs_type

    return ResolvedPosture(
        sandbox_adapter=sandbox.name,
        sandbox_isolating=bool(sandbox.isolating),
        digest_pin_active=bool(getattr(sandbox, "require_digest_pin", False)),
        provider=config.provider,
        tls_required=not config.allow_insecure_loopback,
        anchor_required=bool(config.require_ledger_anchor) or ledger_anchor_required(env),
        anchor_target_class=anchor_class,
        anchor_append_only=bool(getattr(anchor, "append_only", False)) if anchor else False,
        signer_scheme=str(getattr(signer, "scheme", "")),
        signer_external=bool(getattr(signer, "external", False)),
        signer_key_id=str(getattr(signer, "key_id", "")),
        substrate_require_verified=policy.require_verified,
        substrate_allow_unverified=policy.allow_unverified,
        substrate_verdict=substrate_verdict,
        substrate_fs_type=substrate_fs_type,
        attestation_required=bool(config.require_config_attestation)
        or config_attestation_required(env),
        attestation_target_class=target.kind if target is not None else TARGET_NONE,
        attestation_target_external=bool(target.external) if target is not None else False,
        verifier_timeout_s=float(config.verifier_timeout_s),
        verifier_memory_mb=int(config.verifier_memory_mb),
        verifier_cpu_seconds=int(config.verifier_cpu_seconds),
        verifier_max_processes=int(config.verifier_max_processes),
        request_timeout_s=float(config.request_timeout_s),
        provider_max_response_bytes=int(config.provider_max_response_bytes),
        max_role_calls=int(config.max_role_calls),
        pending_ttl_seconds=int(config.pending_ttl_seconds),
        gate_threshold=float(config.gate_threshold),
        escalate_below=float(config.escalate_below),
        ledger_anchor_retention_days=int(config.ledger_anchor_retention_days),
    )


def attest_at_startup(
    config: Config,
    *,
    signer: ApprovalSigner,
    env: Mapping[str, str] | None = None,
    storage_path: str | Path | None = None,
    interval_s: float = 3600.0,
) -> ConfigAttestor | None:
    """Publish the posture once, now, and hand back the attestor for the cadence.

    This is the startup half, as one call rather than a build-then-remember-to-
    attest pair. It returns ``None`` only when no target is configured and none
    is required; under the requirement a target that cannot be honoured, a
    signer that cannot sign, or a publish that fails all raise here — at
    startup, which is where a posture that cannot be attested should stop.

    The periodic half is :meth:`ConfigAttestor.attest_if_due` on the returned
    object, driven by the caller's own loop. Deliberately not a thread: see the
    ``attest`` module docstring.
    """

    attestor = build_config_attestor(
        config, signer=signer, env=env, storage_path=storage_path, interval_s=interval_s
    )
    if attestor is None:
        return None
    attestor.attest()
    return attestor


def build_config_attestor(
    config: Config,
    *,
    signer: ApprovalSigner,
    env: Mapping[str, str] | None = None,
    storage_path: str | Path | None = None,
    interval_s: float = 3600.0,
    clock: Callable[[], float] | None = None,
) -> ConfigAttestor | None:
    """The attestor this configuration asks for, or ``None`` when unconfigured.

    Refuses, rather than degrades, when the requirement cannot be honoured —
    the target check happens here, before anything is signed.
    """

    target = attestation_target_for(config, env=env)
    required = bool(config.require_config_attestation) or config_attestation_required(env)
    if target is None:
        if required:  # pragma: no cover - attestation_target_for already refused
            raise ConfigError("config attestation is required and no target is configured")
        return None
    return ConfigAttestor(
        target=target,
        signer=signer,
        resolve=lambda: resolve_posture(
            config, signer=signer, env=env, storage_path=storage_path, target=target
        ),
        required=required,
        interval_s=interval_s,
        # Passed as a keyword, not splatted from an untyped dict. The dict was
        # there only to omit the argument and let the callee's default apply;
        # naming the default here says the same thing and keeps the argument
        # typed. (A test injects a clock; production takes the wall clock.)
        clock=time.time if clock is None else clock,
    )
