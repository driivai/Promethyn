"""Fail closed on unapplied Config obligations at supported composition roots.

Schema discovery is exhaustive; implementation is not inferred from a read or a
constructor spelling. Inspect the returned object graph, then publish. Trusted
Python can change this guard, falsify adapters, or bypass supported factories;
this is a composition contract, not a boundary against an in-process attacker.
"""
from __future__ import annotations

import gc
import inspect
import os
import types
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

#: THE THREE COMPONENT-LEVEL REFUSALS, named apart rather than sharing one
#: label. They are different findings and a proof that cannot tell them apart
#: stops isolating its own mechanism the moment a second one is added --
#: measured here, not predicted: with all three sharing ``"component"``, the
#: ``external-subclass-refusal-deleted`` mutation SURVIVED, because deleting
#: that refusal left components behind the foreign object undiscovered and the
#: discovery rule refused in its place. The proof went green while the
#: mechanism it names was gone. That is G44's shape, and naming the causes is
#: what keeps each proof pointed at one of them.
COMPONENT_EXTERNAL_SUBCLASS = "component"
COMPONENT_NOT_DISCOVERED = "component_not_discovered"
COMPONENT_UNREGISTERED_CARRIER = "component_unregistered_carrier"

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

    THE CREDITED POPULATION, WHICH IS NARROWER THAN THE DISCOVERED ONE ON
    PURPOSE. This walk descends ``_WALKED_CONTAINERS`` and ``__dict__`` and
    nothing else, because those are the shapes in which holding an object means
    "this runtime is composed of it". An object captured in a closure or used
    as a dict KEY is reachable but not obviously a component, and crediting it
    would let an incidental reference satisfy a security property.

    Narrow crediting used to mean SILENT non-discovery: a component in a
    ``set``, a ``frozenset``, a ``dict`` key, a ``SimpleNamespace``, a closure
    cell, a generator or a ``__slots__`` object was not reached, and the row it
    should have contradicted was reported clean. Measured before the fix, with
    one live defect planted in each shape on a real ``build_orchestrator``
    graph: three shapes refused and SEVEN reported ``applied`` -- not
    ``default_not_applicable``, because a legitimate consumer was also present
    and ``all()`` over the reachable ones was True. ``applied`` is the strongest
    token this report has; it says the property was compared against the live
    components that honour it.

    That is now impossible for any object that could bear on a property:
    ``_discovered`` below is a SECOND, WIDER scope, and ``validate_build``
    refuses when it finds an object carrying a compared attribute that this
    walk did not credit. Non-discovery is a refusal, not a clean row. The two
    scopes are derived independently and neither is trusted alone -- the same
    shape as the ledger read guard, which takes its table scope from SQLite's
    own authorizer rather than from parsed SQL.
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


#: Shapes ``_discovered`` will not look inside. A class, a module and a builtin
#: are not components of a runtime; following them reaches the whole package and
#: says nothing about what this graph is composed of. A plain function is opaque
#: for the same reason -- its ``__globals__`` IS the module namespace -- but its
#: CLOSURE CELLS are followed, because a component captured in a closure is a
#: component of this graph and was measured to be invisible to both walks
#: without that one step.
_DISCOVERY_OPAQUE = (type, types.ModuleType, types.BuiltinFunctionType)


def _discovered(root: object) -> list[Any]:
    """Every package-owned instance the INTERPRETER can reach from ``root``.

    THE SECOND SCOPE. ``_objects`` decides what may satisfy a property;
    this decides what the guard is allowed to claim it has seen. Where they
    disagree, ``validate_build`` refuses, because a component the guard cannot
    reach is one whose compliance it does not know.

    ``gc.get_referents`` is the interpreter's own account of what an object
    references. It is not a second hand-written list of container shapes to
    keep in step with ``_WALKED_CONTAINERS`` -- that would be two populations
    with one maintainer and the same blind spot. It sees sets, frozensets, dict
    KEYS, ``__slots__``, generator frames and cells because the garbage
    collector must.

    Measured on the four shipped runtime roots: 208 objects visited in 0.1 ms
    from ``build_orchestrator``, and the gap against ``_objects`` is EMPTY on
    all four. So the refusal is latent in the shipped graph and fires only on a
    composition that hides something a property is compared on.

    WHAT IT STILL CANNOT SEE, named rather than left to be found. A total
    traversal of arbitrary Python objects is not achievable, and these are the
    residuals, each a place where a component could exist and neither scope
    would know:

    * an object that does not exist yet -- built lazily on first use, after
      this guard has run;
    * an object reachable only through ``__getattr__`` or a property, which
      this walk will not invoke because invoking arbitrary code during a
      security check is a worse bargain than the gap it closes;
    * an object captured by a closure the CALLER wrote. Only this package's own
      closures are followed, because a callback the caller injected is not a
      composition the package made. Measured: following every closure cell
      failed 4 chokepoint tests and errored 71 more on an in-memory audit
      medium held behind a test-supplied executor;
    * an object held only by a C extension that does not implement
      ``tp_traverse``, which the collector cannot see either;
    * an object reachable only from module globals, not from the root at all.

    ``test_security_build.py`` pins four of those shapes behaviourally and the
    emptiness of the gap on every shipped root; ``docs/OPEN-GAPS.md`` G49 holds
    the residual.
    """

    seen: set[int] = {id(root)}
    todo: list[Any] = [root]
    found: list[Any] = []
    while todo:
        obj = todo.pop()
        if isinstance(obj, _DISCOVERY_OPAQUE) or isinstance(obj, Config):
            continue
        if isinstance(obj, types.FunctionType):
            # ONLY THE PACKAGE'S OWN CLOSURES. A closure this package wrote
            # that captures a component is a composition the package made; a
            # callback the CALLER injected is not, and whatever it captured is
            # the caller's business. Measured: following every closure cell
            # refused 71 chokepoint tests outright, because their runtimes hold
            # a test-supplied executor lambda and the objects behind it are not
            # components of the runtime at all. `_objects` declines closure
            # captures for exactly this reason, and a discovery scope that used
            # a different notion of "component" would refuse ordinary builds.
            if not obj.__module__.startswith("prometheus_protocol."):
                continue
            for cell in obj.__closure__ or ():
                try:
                    captured = cell.cell_contents
                except ValueError:
                    # An empty cell: a recursive closure not yet bound. There is
                    # no object to inspect, which is not the same as one hidden.
                    continue
                if id(captured) not in seen:
                    seen.add(id(captured))
                    todo.append(captured)
            continue
        if type(obj).__module__.startswith("prometheus_protocol."):
            found.append(obj)
        for referent in gc.get_referents(obj):
            if id(referent) not in seen:
                seen.add(id(referent))
                todo.append(referent)
    return found


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


def _configs_reachable_from(values: Iterable[Any]) -> list[Config]:
    """Configs the interpreter can reach from a root's arguments (F-8).

    The wider scope for ``guarded_root``'s ``discover``, and the same instrument
    Section 1 uses for components: ``gc.get_referents`` rather than a second
    hand-written list of carrier shapes. Classes, modules and functions are
    opaque -- following them reaches every module-level Config in the package
    and would refuse every root.
    """

    seen: set[int] = set()
    todo = [value for value in values]
    found: list[Config] = []
    while todo:
        obj = todo.pop()
        if id(obj) in seen or isinstance(obj, _DISCOVERY_OPAQUE + (types.FunctionType,)):
            continue
        seen.add(id(obj))
        if isinstance(obj, Config):
            found.append(obj)
            continue
        todo.extend(gc.get_referents(obj))
    return found


def security_attribute_carriers() -> dict[str, tuple[type, ...]]:
    """Attribute name -> the ONLY classes permitted to carry it, fail-closed.

    F-4: the consumer classes in ``validate_build`` are hand-written, so a NEW
    consumer of an EXISTING field is silently uncovered while its row still
    reads ``applied``. The fix a draft of that finding proposed was to add the
    second consumer to the list, which is the same hand-list one entry longer.

    WHY THE POPULATION IS NOT DERIVED, stated rather than left implied. Which
    class honours a Config field is a SEMANTIC fact -- "this object is the one
    that implements this policy" -- and nothing in the type system records it.
    The obvious derivation, keying on the attribute a property is compared on,
    does not work on its own: measured in the shipped graph, ``timeout_s`` is
    carried by ``SubprocessVerifier``, ``RemoteModelProvider`` and
    ``HttpAppendOnlyLog`` for three DIFFERENT Config fields, so the attribute
    name alone cannot tell a consumer from a coincidence.

    So the hand-list is kept and made to FAIL CLOSED instead. Any credited
    object carrying one of these attribute names that is not one of its
    permitted classes refuses the build. A new consumer of an existing field
    now has to be registered here to ship, rather than being covered by a
    sentence and not by the guard.

    THE RESIDUAL, measured: ``name`` is deliberately absent. ``sandbox``
    compares ``obj.name``, but ``name`` is carried by
    ``prometheus_protocol.core.models.Tier`` in the shipped swarm graph and by
    much else besides, so keying on it would refuse a correct build. An
    attribute distinctive enough to key on is the precondition for this rule,
    and ``name`` does not meet it. ``docs/OPEN-GAPS.md`` G50 holds that gap.
    """

    from prometheus_protocol.chokepoint.approval import ApprovalAuthority
    from prometheus_protocol.chokepoint.authorization_record import AuthorizationContext
    from prometheus_protocol.chokepoint.substrate import SubstratePolicy
    from prometheus_protocol.execution.pending import PendingActionService
    from prometheus_protocol.gate.authorization import ActionGate
    from prometheus_protocol.gate.promotion import PromotionGate
    from prometheus_protocol.ledger.anchor_http import HttpAppendOnlyLog
    from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
    from prometheus_protocol.policy.execution import ExecutionAuthorizer
    from prometheus_protocol.provider.remote import RemoteModelProvider
    from prometheus_protocol.sandbox.base import Limits, Sandbox
    from prometheus_protocol.sandbox.container import ContainerSandbox
    from prometheus_protocol.swarm.synthesis import RoleSynthesisEngine, _BudgetedProvider
    from prometheus_protocol.verifier.bank import VerifierBank
    from prometheus_protocol.verifier.runner import SubprocessVerifier

    return {
        "isolating": (Sandbox,),
        "require_digest_pin": (ContainerSandbox,),
        "tip_anchor": (SqliteLedger,),
        # Two known carriers, one of them not a consumer. Measured across the
        # whole suite, `signer` is the ONLY attribute in this map carried by a
        # class that does not implement the property, and
        # `AuthorizationContext.signer` is a dict of identity metadata rather
        # than a signer object with `.external`. It is registered so a correct
        # build is not refused, and registered EXPLICITLY rather than by
        # dropping `signer` from the map, so a genuinely new signer-carrying
        # consumer still refuses until someone looks at it.
        "signer": (ApprovalAuthority, AuthorizationContext),
        "require_verified": (SubstratePolicy,),
        "allow_unverified": (SubstratePolicy,),
        "has_policy_supplier": (VerifierBank,),
        "_policy_supplier": (VerifierBank,),
        "_supplier": (ExecutionAuthorizer,),
        "threshold": (PromotionGate,),
        "_escalate_below": (ActionGate,),
        "escalate_below": (VerifierBank,),
        "_ttl_seconds": (PendingActionService,),
        # Two carriers, one object: measured, ``_BudgetedProvider`` holds the
        # SAME budget instance as the engine that wraps it, so it is a shared
        # reference rather than a second consumer. Registered because it
        # carries the attribute, not because it is independently checked.
        "_budget": (RoleSynthesisEngine, _BudgetedProvider),
        "timeout_s": (SubprocessVerifier, RemoteModelProvider, HttpAppendOnlyLog),
        "memory_mb": (SubprocessVerifier,),
        "cpu_seconds": (SubprocessVerifier,),
        "max_processes": (SubprocessVerifier, Limits),
        "wall_time_s": (Limits,),
        "memory_bytes": (Limits,),
        "cpu_time_s": (Limits,),
        "max_response_bytes": (RemoteModelProvider,),
        "api_base": (RemoteModelProvider,),
        "url": (HttpAppendOnlyLog,),
    }


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
    # NON-DISCOVERY REFUSES, SCOPED TO OBJECTS THAT COULD BEAR ON A PROPERTY.
    #
    # The ruling is that a guard which cannot see a component does not know the
    # property is inapplicable. The words that matter are "the property": an
    # object carrying none of the attributes any property is compared on cannot
    # change any row, and refusing over it is not fail-closed, it is broken.
    #
    # Measured, not reasoned: refusing on EVERY uncredited package-owned object
    # failed 4 tests and errored 71 more, on `_Medium` and
    # `ModelAuditAdministrator` -- an in-memory audit medium reached through a
    # closure this package legitimately wrote, carrying no security attribute
    # at all. Scoped to the carrier map, the same run is clean and a planted
    # component that DOES carry one still refuses in all seven hiding shapes.
    #
    # So both component refusals key on the same fact -- this object could
    # satisfy or contradict a property -- and differ only in which way it is
    # wrong: unreachable, or reachable and unregistered.
    carriers = security_attribute_carriers()
    credited = {id(obj) for obj in nodes}
    for obj in _discovered(runtime):
        for attribute, permitted in carriers.items():
            if not hasattr(obj, attribute):
                continue
            if id(obj) not in credited:
                raise BuildRefused(
                    COMPONENT_NOT_DISCOVERED,
                    f"{type(obj).__module__}.{type(obj).__name__} carries "
                    f"{attribute!r} and is reachable from the returned runtime, but "
                    "it is not held in a traversed container, so whether it honours "
                    "that property cannot be established",
                )
            if not isinstance(obj, permitted):
                raise BuildRefused(
                    COMPONENT_UNREGISTERED_CARRIER,
                    f"{type(obj).__module__}.{type(obj).__name__} carries {attribute!r}, "
                    "which a security property is compared on, but it is not a "
                    "registered consumer of that property",
                )
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
        if not configs:
            # F-8. THE GUARD USED TO SUBSTITUTE A DIFFERENT CONFIG HERE, SILENTLY.
            #
            # `discover` walks Config, dict, list and tuple. A Config held by any
            # other carrier is invisible to it, `configs` stays empty, and the
            # fallback below builds one from the environment instead. The guard
            # does not decline: it validates that OTHER Config and writes a
            # report describing it. Reproduced on a root taking one opaque
            # holder, with `require_ledger_anchor=True` and `ledger_anchor` set:
            #
            #     discoverable parameter  -> REFUSED, "ledger has no supported tip anchor"
            #     opaque carrier          -> BUILT, ledger_anchor='not_requested'
            #
            # "Not requested" for a property that WAS requested is the same
            # class of defect as F-1's `applied` for a component never seen:
            # a state the guard could not establish, written down as a clean
            # one. So it refuses, by the same two-scope method -- the carrier's
            # referents are asked whether a Config is in there, and the
            # env fallback survives only when genuinely none is.
            hidden = _configs_reachable_from(bound.arguments.values())
            if hidden:
                raise BuildRefused(
                    "Config",
                    "a Config is reachable from this root's arguments but is not "
                    "held in a traversed container, so the guard would validate a "
                    "DIFFERENT Config built from the environment and report on that "
                    "one instead",
                )
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
