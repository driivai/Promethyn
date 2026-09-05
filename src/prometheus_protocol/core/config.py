"""Runtime configuration, resolved from the environment.

All knobs are read from ``PROM_*`` environment variables so the same build
runs unchanged across a laptop, CI, and a server. Nothing here is specific to
any model vendor: the provider boundary is selected by name and configured by
generic endpoint settings.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from prometheus_protocol.core.endpoint import validate_endpoint
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.core.validation import (
    require_int_in_range,
    require_non_negative_int,
    require_positive,
    require_positive_int,
    require_range,
    require_unit_interval,
)

PROVIDER_MOCK = "mock"
PROVIDER_REMOTE = "remote"

#: The sandbox adapters ``build_sandbox`` knows. Validated at load so an unknown
#: name fails here, not at the first run.
SANDBOX_NAMES = ("auto", "namespace", "container", "unsafe")

#: Every Config field that expresses a security requirement or a security bound.
#:
#: A field listed here must be CONSUMED by the code that honours it. A
#: conformance test parses the source tree and fails if any of these is read
#: nowhere outside this module — which is exactly how ``require_digest_pin``
#: shipped: a setting an operator could turn on, that ``build_sandbox`` never
#: received, so a deployment asking for digest pinning got a sandbox reporting
#: ``False`` (threat model §5). The same test fails if a field whose NAME looks
#: like a security flag (``require_*``, ``allow_*``, ``enforce_*``, ``deny_*``,
#: ``strict*``) is added without being listed here, so the list ratchets both
#: ways: it cannot silently miss a flag, and a flag cannot silently do nothing.
SECURITY_FIELDS = (
    "sandbox",
    "require_digest_pin",
    "allow_insecure_loopback",
    "escalate_below",
    "gate_threshold",
    "pending_ttl_seconds",
    "verifier_timeout_s",
    "verifier_memory_mb",
    "verifier_cpu_seconds",
    "verifier_max_processes",
    "request_timeout_s",
    "provider_max_response_bytes",
    "max_role_calls",
)


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_float(value: str | None, default: float) -> float:
    if value is None or value.strip() == "":
        return default
    return float(value)


def _as_int(value: str | None, default: int) -> int:
    if value is None or value.strip() == "":
        return default
    return int(value)


@dataclass(frozen=True)
class Config:
    """Resolved configuration for a runtime instance."""

    provider: str = PROVIDER_MOCK
    api_base: str | None = None
    model: str | None = None
    api_key: str | None = None

    # Soft model-judge advisor. Off by default: it issues model calls and the
    # offline default provider cannot meaningfully judge. ``judge_model``, when
    # set, runs the judge on a model independent of the actor/roles model to
    # reduce correlated error (the same model proposing and grading inflates
    # agreement); otherwise the judge reuses the actor provider and the runtime
    # logs a one-line correlated-grader notice. ``judge_api_base`` /
    # ``judge_api_key`` optionally point the judge at a different gateway (a
    # fully independent grading endpoint); unset, they inherit the actor's.
    enable_model_judge: bool = False
    judge_model: str | None = None
    judge_api_base: str | None = None
    judge_api_key: str | None = None
    # Judge sampling temperature. Default 0.0 keeps the judge deterministic
    # (unchanged behaviour). It exists so the self-consistency / repeated-
    # sampling calibration lever can draw genuinely varied samples: at
    # temperature 0 repeated calls are identical and majority-of-k is a no-op.
    # Only the judge's `assess` path reads this; the actor/proposer path stays
    # deterministic regardless.
    judge_temperature: float = 0.0

    registry_dir: Path = Path(".prometheus/skills")
    ledger_path: Path = Path(".prometheus/ledger.db")
    trust_store_path: Path = Path(".prometheus/trust.db")

    verifier_timeout_s: float = 5.0
    verifier_memory_mb: int = 256
    verifier_cpu_seconds: int = 5
    verifier_max_processes: int = 64

    # Sandbox adapter for executing untrusted candidate code: "auto" (pick the
    # best available isolating adapter), "namespace", "container", or "unsafe"
    # (the unsafe direct runner, which additionally requires
    # PROM_ALLOW_UNSAFE_EXEC=1). Default is an isolating adapter.
    sandbox: str = "auto"

    # Container image provenance. When set, the container adapter REFUSES to run
    # an image referenced by a bare tag — only a digest-pinned image
    # (``…@sha256:…``) is allowed, so a tag cannot be silently repointed after it
    # was vetted. Off by default for dev convenience; the recommended production
    # posture. A bare tag is always logged as a supply-chain risk regardless.
    require_digest_pin: bool = False

    gate_threshold: float = 0.0
    retrieval_k: int = 5

    # Action-authorization human-routing. When the action gate is run in
    # routing mode, an authoritative PASS whose confidence is below
    # ``escalate_below`` (or any high-risk action) is not auto-executed: it
    # halts as a pending action for a human to approve or reject. Mirrors the
    # verifier bank's escalate_below default.
    escalate_below: float = 0.75

    # How long a pending (human-hold) action stays approvable before it lapses.
    # A `sweep` transitions holds older than this to EXPIRED, and approval
    # re-checks it at decision time; an expired hold can never execute. Default
    # is 24h; set to 0 to disable expiry (holds live until decided).
    pending_ttl_seconds: int = 86_400

    # Swarm cost control: the maximum number of role/provider generation calls a
    # single swarm task may make. Modest by default so a run cannot make
    # unbounded provider calls; raise it for wider role panels.
    max_role_calls: int = 16

    request_timeout_s: float = 30.0

    # Transport hardening (threat model §4). A remote endpoint must be https://;
    # plaintext is allowed only to a loopback host and only with this opt-out,
    # which logs a warning at construction. There is no opt-out for a remote
    # plaintext endpoint: a credential sent there crosses the network in clear.
    allow_insecure_loopback: bool = False
    # Ceiling on a provider response body. A response that exceeds it is refused
    # outright — never truncated and parsed as if complete.
    provider_max_response_bytes: int = 4 * 1024 * 1024

    def __post_init__(self) -> None:
        """Reject non-finite, out-of-range and wrong-signed numeric settings.

        Validated here rather than at each use because this is the one place every
        value passes through, including :meth:`from_env` — and ``float("nan")``
        and ``float("inf")`` are both things ``float()`` happily returns for an
        environment variable. A ``PROM_ESCALATE_BELOW=nan`` would otherwise leave
        the human-escalation gate present and permanently non-escalating, which
        is the failure this project exists to name.
        """

        require_range(
            self.judge_temperature, name="judge_temperature", minimum=0.0, maximum=2.0
        )
        require_positive(self.verifier_timeout_s, name="verifier_timeout_s")
        require_non_negative_int(self.verifier_memory_mb, name="verifier_memory_mb")
        require_non_negative_int(self.verifier_cpu_seconds, name="verifier_cpu_seconds")
        require_non_negative_int(self.verifier_max_processes, name="verifier_max_processes")
        require_unit_interval(self.gate_threshold, name="gate_threshold")
        require_non_negative_int(self.retrieval_k, name="retrieval_k")
        require_unit_interval(self.escalate_below, name="escalate_below")
        # 0 disables expiry (documented above); negative was never a setting, it
        # just fell into the same "<= 0" branch and silently disabled it too.
        require_non_negative_int(self.pending_ttl_seconds, name="pending_ttl_seconds")
        require_positive_int(self.max_role_calls, name="max_role_calls")
        require_positive(self.request_timeout_s, name="request_timeout_s")
        require_int_in_range(
            self.provider_max_response_bytes,
            name="provider_max_response_bytes",
            minimum=1024,
            maximum=1 << 30,
        )
        # Endpoints are refused at load, not at the first request: by then the
        # Authorization header has been built and is about to leave.
        for field_name in ("api_base", "judge_api_base"):
            value = getattr(self, field_name)
            if value:
                validate_endpoint(
                    value,
                    name=field_name,
                    allow_insecure_loopback=self.allow_insecure_loopback,
                )

        # -- coherence: combinations that are each valid and jointly unsafe ----
        # Refused here, at load, with the reason. A requested security property
        # that the rest of the configuration makes impossible to honour is not
        # dropped and not deferred to the first run (threat model §5).
        sandbox = (self.sandbox or "auto").strip().lower()
        if sandbox not in SANDBOX_NAMES:
            raise ConfigError(
                f"unknown sandbox {self.sandbox!r}; expected one of {', '.join(SANDBOX_NAMES)}"
            )
        if self.require_digest_pin and sandbox in ("namespace", "unsafe"):
            raise ConfigError(
                f"require_digest_pin=True cannot be honoured by sandbox={sandbox!r}: "
                "digest pinning is a property of a container image, and that "
                "adapter runs none. Select sandbox=container (or auto, which "
                "will then insist on it) or withdraw the requirement."
            )
        if self.provider == PROVIDER_REMOTE and sandbox == "unsafe":
            raise ConfigError(
                "provider=remote with sandbox=unsafe would execute a remote "
                "model's output with no isolation at all. The unsafe adapter "
                "exists for offline development against the mock provider; "
                "it is refused for remote output even with PROM_ALLOW_UNSAFE_EXEC."
            )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Config":
        env = os.environ if env is None else env
        return cls(
            provider=env.get("PROM_PROVIDER", PROVIDER_MOCK),
            api_base=env.get("PROM_API_BASE"),
            model=env.get("PROM_MODEL"),
            api_key=env.get("PROM_API_KEY"),
            enable_model_judge=_as_bool(env.get("PROM_ENABLE_MODEL_JUDGE"), False),
            judge_model=env.get("PROM_JUDGE_MODEL"),
            # Empty means unset for both: they then inherit the actor's endpoint.
            judge_api_base=env.get("PROM_JUDGE_API_BASE") or None,
            judge_api_key=env.get("PROM_JUDGE_API_KEY") or None,
            judge_temperature=_as_float(env.get("PROM_JUDGE_TEMPERATURE"), 0.0),
            registry_dir=Path(env.get("PROM_REGISTRY_DIR", ".prometheus/skills")),
            ledger_path=Path(env.get("PROM_LEDGER_PATH", ".prometheus/ledger.db")),
            trust_store_path=Path(
                env.get("PROM_TRUST_STORE_PATH", ".prometheus/trust.db")
            ),
            verifier_timeout_s=_as_float(env.get("PROM_VERIFIER_TIMEOUT_S"), 5.0),
            verifier_memory_mb=_as_int(env.get("PROM_VERIFIER_MEMORY_MB"), 256),
            verifier_cpu_seconds=_as_int(env.get("PROM_VERIFIER_CPU_SECONDS"), 5),
            verifier_max_processes=_as_int(env.get("PROM_VERIFIER_MAX_PROCESSES"), 64),
            sandbox=env.get("PROM_SANDBOX", "auto"),
            require_digest_pin=_as_bool(env.get("PROM_REQUIRE_DIGEST_PIN"), False),
            gate_threshold=_as_float(env.get("PROM_GATE_THRESHOLD"), 0.0),
            retrieval_k=_as_int(env.get("PROM_RETRIEVAL_K"), 5),
            escalate_below=_as_float(env.get("PROM_ESCALATE_BELOW"), 0.75),
            pending_ttl_seconds=_as_int(env.get("PROM_PENDING_TTL"), 86_400),
            max_role_calls=_as_int(env.get("PROM_MAX_ROLE_CALLS"), 16),
            request_timeout_s=_as_float(env.get("PROM_REQUEST_TIMEOUT_S"), 30.0),
            allow_insecure_loopback=_as_bool(env.get("PROM_ALLOW_INSECURE_LOOPBACK"), False),
            provider_max_response_bytes=_as_int(
                env.get("PROM_PROVIDER_MAX_RESPONSE_BYTES"), 4 * 1024 * 1024
            ),
        )
