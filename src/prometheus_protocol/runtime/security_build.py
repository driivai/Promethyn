"""Fail closed on unapplied Config obligations at supported composition roots.

Schema discovery is exhaustive; implementation is not inferred from a read or a
constructor spelling. Inspect the returned object graph, then publish. Trusted
Python can change this guard, falsify adapters, or bypass supported factories;
this is a composition contract, not a boundary against an in-process attacker.
"""
from __future__ import annotations

import inspect
import os
from contextvars import ContextVar
from dataclasses import fields, replace
from functools import wraps
from typing import Any, Callable, Iterable

from prometheus_protocol.core.booleans import parse_env_bool
from prometheus_protocol.core.config import Config
from prometheus_protocol.core.errors import ConfigError


class BuildRefused(ConfigError):
    def __init__(self, property_name: str, detail: str) -> None:
        self.property_name = property_name
        super().__init__(f"security build refused: {property_name}: {detail}")


#: THE REPORT VOCABULARY. Every value ``validate_build`` can write into its
#: report, as named constants, because the difference between two of them is
#: the difference between a checked mechanism and an unchecked one.
#:
#: APPLIED means: this property was requested, and it was compared against the
#: live components that honour it. It is the only token that says a mechanism
#: was checked.
#:
#: NOT_REQUESTED means: the operator asked for nothing, so there was nothing to
#: check and nothing was checked. A disabled requirement is not evidence that
#: its mechanism exists — ``docs/reachability-build.md`` states that rule, and
#: the first implementation contradicted it by writing APPLIED on three rows
#: (``ledger_anchor=None``, ``require_ledger_anchor=False``,
#: ``require_digest_pin=False``). A consumer reading APPLIED for an absent
#: anchor was reading the opposite of the truth.
#:
#: DEFAULT_NOT_APPLICABLE means: the domain this property governs is absent
#: from the returned graph and the value is the default. See the traversal
#: limit named in ``_objects``: absence here is not distinguished from a
#: component the traversal could not reach.
#:
#: PUBLICATION_PENDING / PUBLISHED are the two attestation rows' states, held
#: back until every other property validates and then resolved.
#:
#: ``test_security_build.py`` reads this module's source and pins the set of
#: tokens actually written into the report equal to ``REPORT_TOKENS``, exactly
#: — so a new token cannot arrive unnamed and a named one cannot fall out of
#: use unnoticed. The membership lesson from #120: a count is not a
#: composition, and a floor would have caught neither direction.
APPLIED = "applied"
NOT_REQUESTED = "not_requested"
DEFAULT_NOT_APPLICABLE = "default_not_applicable"
PUBLICATION_PENDING = "publication_pending"
PUBLISHED = "published"

REPORT_TOKENS = frozenset({
    APPLIED,
    NOT_REQUESTED,
    DEFAULT_NOT_APPLICABLE,
    PUBLICATION_PENDING,
    PUBLISHED,
})

_BUILDING: ContextVar[Config | None] = ContextVar("security_building", default=None)


def component_builder(function: Callable[..., Any]) -> Callable[..., Any]:
    """Explicitly a partial builder, not an executable production root."""
    function.__dict__["_security_component"] = True
    return function


@component_builder
def security_fields(config: Config) -> tuple[str, ...]:
    declared = fields(config)
    for item in declared:
        if type(item.metadata.get("security")) is not bool:
            raise BuildRefused(item.name, "Config field has no security classification")
    return tuple(item.name for item in declared if item.metadata.get("security", False))


#: The container shapes this traversal descends. Named, because what is NOT in
#: this tuple is the guard's largest stated limit and a reader should be able
#: to find the boundary at the mechanism rather than in a report.
_WALKED_CONTAINERS = (tuple, list, dict)


def _objects(root: object) -> list[Any]:
    """Live instances, including a gateway's bound controller; never Config values.

    Only package-owned objects are traversed. Arbitrary injected implementations
    are opaque, not credited with a property because an attribute says so.

    THE LIMIT, AND IT IS NOT THE ONE THE OTHER LIMITS DESCRIBE. This walk
    descends ``_WALKED_CONTAINERS`` and ``__dict__`` and nothing else. A
    package-owned component held in a ``set``, a ``frozenset``, a ``dict`` KEY,
    a ``SimpleNamespace``, a closure cell, a generator, a ``__slots__`` object
    or any other container is NOT REACHED — and a component that is not
    reached is reported by ``validate_build`` as ``DEFAULT_NOT_APPLICABLE``
    whenever the Config value is its default, which reads downstream as fine.

    Every other limit this guard states describes something it declines to
    cover. This one describes something it actively reports as applicable-
    and-absent when it is neither. Measured on the four runtime roots: an
    exhaustive walk that also descends sets, slots, closures and namespaces
    finds exactly one object this one misses, ``Config``, which is excluded
    deliberately — so the gap is latent in the shipped graph and open in
    principle. ``test_security_build.py`` pins both halves of that sentence.
    Making non-discovery REFUSE is filed rather than done here; see
    ``docs/OPEN-GAPS.md`` G43.
    """
    todo = [root]
    seen: set[int] = set()
    result: list[Any] = []
    while todo:
        obj = todo.pop()
        if id(obj) in seen or isinstance(obj, Config):
            continue
        seen.add(id(obj))
        if inspect.ismethod(obj):
            todo.append(obj.__self__)
        elif isinstance(obj, _WALKED_CONTAINERS):
            if isinstance(obj, dict):
                todo.extend(obj.values())
            else:
                todo.extend(obj)
        elif type(obj).__module__.startswith("prometheus_protocol."):
            result.append(obj)
            if hasattr(obj, "__dict__"):
                todo.extend(vars(obj).values())
        elif any(base.__module__.startswith("prometheus_protocol.") for base in type(obj).__mro__):
            # A foreign subclass is present, not an absent/default domain.
            # Its overridden behavior is not established by reflected fields.
            raise BuildRefused("component", "unsupported external subclass in security runtime")
    return result


@component_builder
def validate_ledger(config: Config, ledger: object) -> None:
    """Validate injected as well as constructed storage, before controller sweeps."""
    from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
    from prometheus_protocol.runtime.factory import ledger_anchor_required

    required = config.require_ledger_anchor or ledger_anchor_required()
    if not (required or config.ledger_anchor):
        return
    if not isinstance(ledger, SqliteLedger) or ledger.tip_anchor is None:
        raise BuildRefused("ledger_anchor", "ledger has no supported tip anchor")
    if required and not ledger.tip_anchor.append_only:
        raise BuildRefused("require_ledger_anchor", "anchor is not append-only")
    # A different witness is not the witness the operator configured. Compare
    # the trusted adapter's destination, not merely append_only=True.
    from prometheus_protocol.runtime.factory import build_tip_anchor_for
    expected = build_tip_anchor_for(config)
    actual = ledger.tip_anchor
    if type(actual) is not type(expected):
        raise BuildRefused("ledger_anchor", "injected anchor has a different adapter")
    def destination(anchor: Any) -> object:
        if hasattr(anchor, "_store"):
            return getattr(anchor._store, "root", None)
        if hasattr(anchor, "_log"):
            return getattr(anchor._log, "url", None)
        return getattr(anchor, "path", None)
    if destination(actual) is None or destination(actual) != destination(expected):
        raise BuildRefused("ledger_anchor", "injected anchor has a different destination")


@component_builder
def validate_build(config: Config, runtime: object, *, signer: Any = None) -> dict[str, str]:
    """Every schema-derived property gets applied/default-unrequested/refused.

    Unsupported *non-default* tuning is a refusal, not a guessed application.
    Unknown security fields have no implementation and are always refused.
    """
    from prometheus_protocol.execution.controller import ExecutionController
    from prometheus_protocol.execution.pending import PendingActionService
    from prometheus_protocol.gate.authorization import ActionGate
    from prometheus_protocol.gate.promotion import PromotionGate
    from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
    from prometheus_protocol.provider.remote import RemoteModelProvider
    from prometheus_protocol.sandbox.base import Limits, Sandbox
    from prometheus_protocol.sandbox.container import ContainerSandbox
    from prometheus_protocol.swarm.synthesis import RoleSynthesisEngine
    from prometheus_protocol.verifier.runner import SubprocessVerifier
    from prometheus_protocol.verifier.bank import VerifierBank
    from prometheus_protocol.policy.profile import load_profile
    from prometheus_protocol.policy.execution import ExecutionAuthorizer
    from prometheus_protocol.chokepoint.approval import ApprovalAuthority
    from prometheus_protocol.chokepoint.substrate import SubstratePolicy
    from prometheus_protocol.chokepoint.runner import BrokeredMigrationRunner, MigrationRuntime
    from prometheus_protocol.ledger.anchor_http import HttpAppendOnlyLog

    names = security_fields(config)
    nodes = _objects(runtime)
    report: dict[str, str] = {}
    defaults = {item.name: item.default for item in fields(config)}

    def instances(cls: type) -> list[Any]:
        found = []
        for obj in nodes:
            if isinstance(obj, cls):
                found.append(obj)
        return found

    def matches(cls: type, attr: str, value: object) -> bool | None:
        candidates = instances(cls)
        return all(getattr(obj, attr) == value for obj in candidates) if candidates else None

    sandboxes = instances(Sandbox)
    ledgers = instances(SqliteLedger)
    migration = False
    if isinstance(runtime, (BrokeredMigrationRunner, MigrationRuntime)):
        migration = True
    for controller in instances(ExecutionController):
        if controller.pending.reobservation is None:
            raise BuildRefused("reobservation", "production controller has no registry")

    for name in names:
        value = getattr(config, name)
        applied: bool | None
        if name == "sandbox":
            applied = bool(sandboxes) and all(
                (config.sandbox == "auto" or obj.name == config.sandbox)
                and (config.provider != "remote" or obj.isolating)
                for obj in sandboxes
            )
            if migration and not sandboxes:
                applied = None
        elif name == "require_digest_pin":
            if not value:
                # Nothing was asked for, so nothing was checked. Saying APPLIED
                # here claimed a digest-pinning mechanism had been verified on
                # a build that never looked at one.
                report[name] = NOT_REQUESTED
                continue
            applied = bool(sandboxes)
            for obj in sandboxes:
                if isinstance(obj, ContainerSandbox):
                    applied = applied and obj.require_digest_pin
                else:
                    applied = False
        elif name in {"ledger_anchor", "require_ledger_anchor"}:
            if not value:
                # An unconfigured witness and an unrequested requirement are
                # both "nothing was asked for". Neither is evidence that the
                # anchoring mechanism reached a ledger.
                report[name] = NOT_REQUESTED
                continue
            if not ledgers:
                raise BuildRefused(name, "no supported ledger in returned runtime")
            for ledger in ledgers:
                validate_ledger(config, ledger)
            applied = True
        elif name == "ledger_anchor_retention_days":
            anchors = [ledger.tip_anchor for ledger in ledgers if ledger.tip_anchor is not None]
            applicable = []
            for a in anchors:
                if hasattr(a, "_retain_for_s"):
                    applicable.append(a)
            applied = all(a._retain_for_s == value * 86400 for a in applicable) if applicable else None
        elif name in {"config_attestation_target", "require_config_attestation"}:
            # Publication happens only after all other applications validate.
            report[name] = PUBLICATION_PENDING if value else NOT_REQUESTED
            continue
        elif name == "require_external_signer":
            signers = [authority.signer for authority in instances(ApprovalAuthority)]
            if signer is not None and (config.config_attestation_target or config.require_config_attestation):
                signers.append(signer)
            applied = all(not value or s.external for s in signers) if signers else None
        elif name in {"require_verified_substrate", "allow_unverified_substrate"}:
            applied = matches(SubstratePolicy, "require_verified" if name == "require_verified_substrate" else "allow_unverified", value)
        elif name == "verification_profile":
            banks = instances(VerifierBank)
            selected = load_profile(value)
            policy_checks = [
                bank.has_policy_supplier and bank._policy_supplier() == selected for bank in banks
            ]
            # A correct bank cannot stand in for an execution authorizer that
            # resolved a different policy. Both consumers must agree whenever
            # both exist (the workflow and swarm graphs contain both).
            policy_checks.extend(
                a._supplier() == selected for a in instances(ExecutionAuthorizer)
            )
            applied = all(policy_checks) if policy_checks else None
        elif name == "gate_threshold":
            applied = matches(PromotionGate, "threshold", value)
        elif name == "escalate_below":
            comparisons = [g._escalate_below == value for g in instances(ActionGate)]
            comparisons.extend(bank.escalate_below == value for bank in instances(VerifierBank))
            applied = all(comparisons) if comparisons else None
        elif name == "pending_ttl_seconds":
            applied = matches(PendingActionService, "_ttl_seconds", value)
        elif name == "max_role_calls":
            engines = instances(RoleSynthesisEngine)
            applied = all(obj._budget.limit == value for obj in engines) if engines else None
        elif name in {"verifier_timeout_s", "verifier_memory_mb", "verifier_cpu_seconds", "verifier_max_processes"}:
            verifier_attr, limit_attr = {
                "verifier_timeout_s": ("timeout_s", "wall_time_s"),
                "verifier_memory_mb": ("memory_mb", "memory_bytes"),
                "verifier_cpu_seconds": ("cpu_seconds", "cpu_time_s"),
                "verifier_max_processes": ("max_processes", "max_processes"),
            }[name]
            values = [getattr(obj, verifier_attr) == value for obj in instances(SubprocessVerifier)]
            converted = value
            if name == "verifier_memory_mb" and isinstance(value, int):
                converted = value * 1024 * 1024
            values.extend(getattr(obj, limit_attr) == converted for obj in instances(Limits))
            applied = all(values) if values else None
        elif name in {"request_timeout_s", "provider_max_response_bytes"}:
            applied = matches(RemoteModelProvider, "timeout_s" if name == "request_timeout_s" else "max_response_bytes", value)
            if name == "request_timeout_s":
                http = matches(HttpAppendOnlyLog, "timeout_s", value)
                if http is not None:
                    applied = http and applied is not False
        elif name == "allow_insecure_loopback":
            from prometheus_protocol.core.endpoint import validate_endpoint
            endpoints = [obj.api_base for obj in instances(RemoteModelProvider)]
            endpoints.extend(obj.url for obj in instances(HttpAppendOnlyLog))
            for endpoint in endpoints:
                validate_endpoint(endpoint, name="runtime endpoint", allow_insecure_loopback=value)
            # Permission permits loopback HTTP; it does not require it.
            applied = True if endpoints else None
        else:
            raise BuildRefused(name, "no application validator for this Config security field")
        if applied is True:
            report[name] = APPLIED
        elif applied is None and value == defaults[name]:
            report[name] = DEFAULT_NOT_APPLICABLE
        else:
            raise BuildRefused(name, "requested property is absent or disagrees with live components")
    return report


def guarded_root(function: Callable[..., Any]) -> Callable[..., Any]:
    signature = inspect.signature(function)

    @wraps(function)
    def build(*args: Any, **kwargs: Any) -> Any:
        signer = kwargs.pop("attestation_signer", None)
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        configs = []
        def discover(value: Any, ancestors: frozenset[int] = frozenset()) -> None:
            if isinstance(value, Config):
                configs.append(value)
            elif isinstance(value, (dict, list, tuple)):
                if id(value) in ancestors:
                    raise BuildRefused("Config", "cyclic argument containers are not supported")
                nested: Iterable[Any] = value
                if isinstance(value, dict):
                    nested = value.values()
                for item in nested:
                    discover(item, ancestors | {id(value)})
        for value in bound.arguments.values():
            discover(value)
        if len(configs) > 1:
            raise BuildRefused("Config", "multiple configuration objects at one root")
        from prometheus_protocol.chokepoint.runner import MigrationRunnerConfig
        migration_config = bound.arguments.get("config")
        if isinstance(migration_config, MigrationRunnerConfig) and not configs:
            if bound.arguments.get("settings") is not None:
                raise BuildRefused("Config", "migration settings must be a classified Config")
        environment = bound.arguments.get("env")
        if environment is None:
            environment = os.environ
        config = configs[0] if configs else Config.from_env(environment)
        security_fields(config)  # refuses unclassified future fields before construction
        # Strict requirements are the OR of trusted sources, including for
        # Config(...) callers that did not use Config.from_env().
        overrides: dict[str, Any] = {
            name: bool(getattr(config, name)) or bool(getattr(migration_config, name, False)) or parse_env_bool(
                "PROM_" + name.upper(), environment.get("PROM_" + name.upper()), default=False
            )
            for name in security_fields(config) if name.startswith("require_") or name == "allow_unverified_substrate"
        }
        checked = replace(config, **overrides)
        def resolved(value: Any) -> Any:
            if isinstance(value, Config):
                return checked
            if isinstance(value, dict):
                return {key: resolved(item) for key, item in value.items()}
            if isinstance(value, list):
                return [resolved(item) for item in value]
            if isinstance(value, tuple):
                return tuple(resolved(item) for item in value)
            return value
        for name, value in tuple(bound.arguments.items()):
            bound.arguments[name] = resolved(value)
        if bound.arguments.get("config") is None and "config" in bound.arguments:
            bound.arguments["config"] = checked
        if isinstance(migration_config, MigrationRunnerConfig):
            bound.arguments["settings"] = checked
        active = _BUILDING.get()
        if active is not None:
            # Ordinary settings (e.g. provider) can also affect application of
            # a security field. Do not let nested roots substitute that context.
            active_contract = {item.name: getattr(active, item.name) for item in fields(active)}
            nested_contract = {item.name: getattr(checked, item.name) for item in fields(checked)}
            if nested_contract != active_contract:
                raise BuildRefused("Config", "nested roots must share the outer security contract")
        outer = active is None
        token = _BUILDING.set(checked)
        try:
            result = function(*bound.args, **bound.kwargs)
            if outer:
                from prometheus_protocol.chokepoint.runner import BrokeredMigrationRunner, MigrationRuntime
                retained = result
                if isinstance(result, MigrationRuntime):
                    retained = result.runner
                if signer is None and isinstance(retained, BrokeredMigrationRunner):
                    signer = retained._authority.signer
                report = validate_build(checked, result, signer=signer)
                if checked.config_attestation_target or checked.require_config_attestation:
                    from prometheus_protocol.attestation import runtime as attestation
                    resolved = attestation.resolve_attestation_signer(
                        checked, signer=signer, signing_key=None
                    )
                    attestor = attestation.attest_at_startup(checked, signer=resolved)
                    if attestor is None or attestor.last_digest is None:
                        raise BuildRefused("config_attestation_target", "startup publication did not complete")
                    setattr(retained, "config_attestor", attestor)
                    for name in ("config_attestation_target", "require_config_attestation"):
                        report[name] = PUBLISHED
                setattr(retained, "_security_build_report", report)
            return result
        except Exception:
            # A root may already have opened the durable approval store before
            # the post-construction contract refuses it. Release that ownership.
            result_to_close = locals().get("result")
            from prometheus_protocol.chokepoint.runner import BrokeredMigrationRunner, MigrationRuntime
            if isinstance(result_to_close, (BrokeredMigrationRunner, MigrationRuntime)):
                result_to_close.close()
            raise
        finally:
            _BUILDING.reset(token)
    build.__dict__["_security_root"] = True
    return build


def install_build_guards(namespace: dict[str, Any]) -> None:
    """Discover *all* public functions defined here, regardless of names/types.

    Partial helpers must explicitly declare that role. New roots need no
    decorator, constructor-name match, parameter-name match, or return hint.
    Install at module end, after definitions. New modules need installation;
    the production inventory test and documentation state that boundary.
    """
    for name, function in tuple(namespace.items()):
        if (not name.startswith("_") and inspect.isfunction(function)
                and function.__module__ == namespace["__name__"]
                and not getattr(function, "_security_component", False)
                and not getattr(function, "_security_root", False)):
            namespace[name] = guarded_root(function)
