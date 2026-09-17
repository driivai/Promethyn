"""Reachability regressions: exercise real public roots, not helper spellings."""
from dataclasses import replace
import dataclasses
import inspect
from pathlib import Path

import pytest

from prometheus_protocol.attestation import runtime as attestation
from prometheus_protocol.core.config import Config
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.provider.mock import MockProvider
from prometheus_protocol.runtime import factory
from prometheus_protocol.sandbox.namespace import NamespaceSandbox
from prometheus_protocol.chokepoint.signer import LocalHmacSigner
from prometheus_protocol.runtime.security_build import (
    APPLIED,
    COMPONENT_NOT_DISCOVERED,
    COMPONENT_UNREGISTERED_CARRIER,
    DEFAULT_NOT_APPLICABLE,
    NOT_REQUESTED,
    REPORT_TOKENS,
    BuildRefused,
    install_build_guards,
)


@pytest.fixture
def build_config(tmp_path, monkeypatch):
    # Build only: never execute a candidate or claim this Mac provides Linux isolation.
    monkeypatch.setattr(NamespaceSandbox, "available", classmethod(lambda cls: True))
    return Config(sandbox="namespace", ledger_path=":memory:",
                  registry_dir=tmp_path / "skills", trust_store_path=tmp_path / "trust.db")


@pytest.mark.parametrize("failure", ["publisher_raises", "publisher_returns_nothing"])
def test_f1_required_attestation_reaches_startup(build_config, tmp_path, monkeypatch, failure):
    """F1: the production root must CALL the startup publisher.

    The first version of this test asserted only ``pytest.raises(ConfigError)``
    with no ``match``, collected the publisher's calls into a list and never
    asserted it. ``BuildRefused`` subclasses ``ConfigError``, so ANY refusal
    for ANY cause satisfied that — and measured, the cause was a different one:
    ``resolve_attestation_signer`` raised for the missing signer BEFORE
    ``attest_at_startup`` was reached, leaving the monkeypatch inert and
    ``calls == []``. The test named for F1 never established F1.

    So: supply the signer, so reaching the publisher is the only way forward;
    assert the reach; and assert WHICH property the refusal names.
    ``test_the_signer_refusal_is_a_different_cause_and_says_so`` holds the
    other branch apart rather than letting it stand in for this one.
    """

    calls = []

    def unavailable(*args, **kwargs):
        calls.append(True)
        if failure == "publisher_raises":
            raise ConfigError("publication unavailable")
        return None

    monkeypatch.setattr(attestation, "attest_at_startup", unavailable)
    config = replace(build_config, require_config_attestation=True,
                     config_attestation_target=f"worm://{tmp_path}/attest")
    with pytest.raises(ConfigError) as caught:
        factory.build_execution_controller(
            config, attestation_signer=LocalHmacSigner(b"s" * 32)
        )

    assert calls == [True], (
        "the root refused without ever calling the startup publisher: this "
        "test cannot tell publication-not-reached from any other refusal"
    )
    if failure == "publisher_returns_nothing":
        assert isinstance(caught.value, BuildRefused)
        assert caught.value.property_name == "config_attestation_target"
    else:
        assert "publication unavailable" in str(caught.value)


def test_the_signer_refusal_is_a_different_cause_and_says_so(build_config, tmp_path, monkeypatch):
    """The branch that used to satisfy the F1 test, held apart from it.

    With no signer the root still refuses — correctly — but the publisher is
    NOT reached, and the refusal is about custody, not publication. Pinning
    both facts is what stops this branch standing in for the one above.
    """

    calls = []
    monkeypatch.setattr(
        attestation, "attest_at_startup",
        lambda *args, **kwargs: calls.append(True),
    )
    config = replace(build_config, require_config_attestation=True,
                     config_attestation_target=f"worm://{tmp_path}/attest")
    with pytest.raises(ConfigError) as caught:
        factory.build_execution_controller(config)

    assert calls == [], "the publisher must not be reached without a signer"
    assert not isinstance(caught.value, BuildRefused)
    assert "signer" in str(caught.value)


def build_root(name, config, **kwargs):
    if name == "swarm":
        return factory.build_swarm_runtime(config, provider=MockProvider(), **kwargs)
    return getattr(factory, "build_" + name)(config, **kwargs)


@pytest.mark.parametrize("root", ["execution_controller", "workflow_runtime", "orchestrator", "swarm"])
def test_startup_publication_failure_never_returns_runtime(build_config, tmp_path, monkeypatch, root):
    calls = []
    def unavailable(*args, **kwargs):
        calls.append(True)
        raise RuntimeError("publish sentinel")
    monkeypatch.setattr(attestation, "attest_at_startup", unavailable)
    config = replace(build_config, require_config_attestation=True,
                     config_attestation_target=f"worm://{tmp_path}/attest")
    with pytest.raises(RuntimeError, match="publish sentinel"):
        build_root(root, config, attestation_signer=LocalHmacSigner(b"s" * 32))
    assert calls == [True]


@pytest.mark.parametrize("root", ["execution_controller", "workflow_runtime", "orchestrator", "swarm"])
def test_startup_positive_publishes_and_retains_attestor(build_config, tmp_path, root):
    config = replace(build_config, require_config_attestation=True,
                     config_attestation_target=f"worm://{tmp_path}/attest")
    runtime = build_root(root, config, attestation_signer=LocalHmacSigner(b"s" * 32))
    assert runtime.config_attestor.last_digest is not None
    records = attestation.attestation_target_for(config).records()
    assert [record.digest for record in records] == [runtime.config_attestor.last_digest]
    assert runtime._security_build_report["require_config_attestation"] == "published"


def test_f2_workflow_applies_required_anchor(build_config, tmp_path):
    config = replace(build_config, require_ledger_anchor=True,
                     ledger_anchor=f"worm://{tmp_path}/tips")
    runtime = factory.build_workflow_runtime(config)
    assert runtime._ledger.tip_anchor is not None
    assert runtime._ledger.tip_anchor.append_only


@pytest.mark.parametrize("root", ["execution", "swarm"])
def test_f2_injected_unanchored_ledger_is_refused(build_config, tmp_path, root):
    """Nine other tests in this module assert ``caught.value.property_name``;
    this one and F1's were the two that did not, and they are the two carrying
    the names of the gaps this sprint closed. Measured before adding it, the
    cause was already ``ledger_anchor`` — under-asserted rather than wrong."""

    config = replace(build_config, ledger_path=tmp_path / "audit.db",
                     require_ledger_anchor=True, ledger_anchor=f"worm://{tmp_path}/tips")
    ledger = SqliteLedger(":memory:")
    with pytest.raises(BuildRefused) as caught:
        if root == "execution":
            factory.build_execution_controller(config, ledger=ledger)
        else:
            factory.build_swarm_runtime(config, provider=MockProvider(), ledger=ledger)
    assert caught.value.property_name == "ledger_anchor"


@pytest.mark.parametrize("root", ["execution_controller", "workflow_runtime", "orchestrator", "swarm"])
def test_required_anchor_positive_is_real_runtime_anchor(build_config, tmp_path, root):
    config = replace(build_config, require_ledger_anchor=True,
                     ledger_anchor=f"worm://{tmp_path}/tips")
    runtime = build_root(root, config)
    ledger = getattr(runtime, "_ledger", getattr(runtime, "ledger", None))
    assert ledger.tip_anchor.append_only is True
    ledger.record_chained(event="build-probe", subject="probe", payload={"complete": True}, created_at="2026-09-16T00:00:00Z")
    assert ledger.tip_anchor.read().seq == 1
    assert runtime._security_build_report["require_ledger_anchor"] == "applied"


@pytest.mark.parametrize("metadata", [{}, {"security": True}])
def test_future_config_field_cannot_escape_derivation(build_config, metadata):
    NewConfig = dataclasses.make_dataclass(
        "NewConfig", [("new_security_property", bool, dataclasses.field(default=True, metadata=metadata))],
        bases=(Config,), frozen=True,
    )
    config = NewConfig(**{f.name: getattr(build_config, f.name) for f in dataclasses.fields(Config)})
    with pytest.raises(BuildRefused) as caught:
        factory.build_execution_controller(config)
    assert caught.value.property_name == "new_security_property"


@pytest.mark.parametrize("alias", [False, True])
@pytest.mark.parametrize("omission", ["anchor", "registry"])
def test_new_root_with_alias_and_indirect_none_is_still_guarded(build_config, tmp_path, alias, omission):
    from prometheus_protocol.execution.controller import ExecutionController
    config = replace(build_config, require_ledger_anchor=True, ledger_anchor=f"worm://{tmp_path}/tips")
    good = factory.build_execution_controller(config)
    constructor = ExecutionController
    if alias:
        Alias = constructor
        constructor = Alias
    def newly_added_root(options):
        registry = None if omission == "registry" else good.pending.reobservation
        return constructor(gate=good._gate, executor=good._executor,
                           ledger=SqliteLedger(":memory:") if omission == "anchor" else good._ledger,
                           reobservation=registry)
    namespace = {"__name__": newly_added_root.__module__, "newly_added_root": newly_added_root}
    install_build_guards(namespace)
    with pytest.raises(BuildRefused) as caught:
        namespace["newly_added_root"](config)
    assert caught.value.property_name == ("reobservation" if omission == "registry" else "ledger_anchor")


def test_all_factory_roots_classified_without_name_allowlist():
    functions = [value for name, value in vars(factory).items()
                 if not name.startswith("_") and inspect.isfunction(value)
                 and value.__module__ == factory.__name__]
    assert functions
    assert all(getattr(value, "_security_root", False) or getattr(value, "_security_component", False)
               for value in functions)


def test_default_value_is_not_permission_to_discard_a_bound(build_config):
    runtime = factory.build_execution_controller(build_config)
    runtime.pending._ttl_seconds = 0
    from prometheus_protocol.runtime.security_build import validate_build
    with pytest.raises(BuildRefused) as caught:
        validate_build(build_config, runtime)
    assert caught.value.property_name == "pending_ttl_seconds"


def test_injected_anchor_cannot_substitute_another_witness(build_config, tmp_path):
    config = replace(build_config, require_ledger_anchor=True, ledger_anchor=f"worm://{tmp_path}/selected")
    wrong = factory.build_ledger(replace(config, ledger_anchor=f"worm://{tmp_path}/other"))
    with pytest.raises(BuildRefused) as caught:
        factory.build_execution_controller(config, ledger=wrong)
    assert caught.value.property_name == "ledger_anchor"


def test_configured_optional_publication_failure_is_not_credited(build_config, tmp_path, monkeypatch):
    config = replace(build_config, config_attestation_target=f"worm://{tmp_path}/attest")
    monkeypatch.setattr(attestation, "attest_at_startup", lambda *args, **kwargs: None)
    with pytest.raises(BuildRefused) as caught:
        factory.build_execution_controller(config, attestation_signer=LocalHmacSigner(b"s" * 32))
    assert caught.value.property_name == "config_attestation_target"


@pytest.mark.parametrize("root", ["build_migration_runtime", "build_migration_runner"])
def test_migration_startup_publication_is_required_and_uses_its_signer(tmp_path, monkeypatch, root):
    import sys
    from prometheus_protocol.chokepoint import runner
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "chokepoint"))
    from f11_support import authorization_context
    signer = LocalHmacSigner(b"s" * 32)
    runner_config = runner.MigrationRunnerConfig(
        target=runner.DbTarget(host="127.0.0.1", port=5432, dbname="fixture", user="migrator", password="fixture-not-used"),
        approval_store_path=tmp_path / "consumed.db", signer=signer,
        allow_unverified_substrate=sys.platform != "linux",
    )
    config = Config(require_config_attestation=True, config_attestation_target=f"worm://{tmp_path}/attest")
    audit = SqliteLedger.private(tmp_path / "authorization.db")
    extra = {"authorization": authorization_context(signer)} if root == "build_migration_runtime" else {}
    factory_fn = getattr(runner, root)
    built = factory_fn(runner_config, settings=config, audit=audit, env={}, **extra)
    retained = getattr(built, "runner", built)
    assert retained.config_attestor.last_digest is not None
    assert retained.config_attestor._signer is signer
    built.close()
    calls = []
    def unavailable(*args, **kwargs):
        calls.append(kwargs["signer"])
        raise RuntimeError("migration publication sentinel")
    monkeypatch.setattr(attestation, "attest_at_startup", unavailable)
    with pytest.raises(RuntimeError, match="migration publication sentinel"):
        factory_fn(runner_config, settings=config, audit=audit, env={}, **extra)
    assert calls == [signer]


def test_default_escalation_cannot_be_relabelled_not_applicable(build_config):
    from prometheus_protocol.runtime.security_build import validate_build
    runtime = factory.build_execution_controller(build_config)
    runtime._gate._escalate_below = None
    with pytest.raises(BuildRefused) as caught:
        validate_build(build_config, runtime)
    assert caught.value.property_name == "escalate_below"


def test_config_in_new_root_default_argument_is_not_discarded(build_config, tmp_path):
    from prometheus_protocol.runtime.security_build import guarded_root
    runtime = factory.build_execution_controller(build_config)
    requested = replace(build_config, require_ledger_anchor=True, ledger_anchor=f"worm://{tmp_path}/tips")
    @guarded_root
    def future_root(options=requested):
        return runtime
    with pytest.raises(BuildRefused) as caught:
        future_root()
    assert caught.value.property_name == "ledger_anchor"
    # The same root is viable when the request actually agrees with its runtime.
    assert future_root(build_config) is runtime


def test_runner_without_settings_does_not_drop_environment_anchor_requirement(tmp_path):
    import sys
    from prometheus_protocol.chokepoint import runner
    signer = LocalHmacSigner(b"s" * 32)
    runner_config = runner.MigrationRunnerConfig(
        target=runner.DbTarget(host="127.0.0.1", port=5432, dbname="fixture", user="migrator", password="not-used"),
        approval_store_path=tmp_path / "consumed.db", signer=signer,
        allow_unverified_substrate=sys.platform != "linux",
    )
    env = {"PROM_REQUIRE_LEDGER_ANCHOR": "1", "PROM_LEDGER_ANCHOR": f"worm://{tmp_path}/tips"}
    with pytest.raises(BuildRefused) as caught:
        runner.build_migration_runner(runner_config, audit=SqliteLedger(":memory:"), env=env)
    assert caught.value.property_name == "ledger_anchor"
    config = Config.from_env(env)
    ledger = factory.build_ledger(config, env=env)
    built = runner.build_migration_runner(runner_config, audit=ledger, env=env)
    assert built._security_build_report["require_ledger_anchor"] == "applied"
    built.close()


@pytest.mark.parametrize("form", ["args", "kwargs"])
def test_variadic_root_cannot_hide_requested_config(build_config, tmp_path, form):
    from prometheus_protocol.runtime.security_build import guarded_root
    runtime = factory.build_execution_controller(build_config)
    requested = replace(build_config, require_ledger_anchor=True, ledger_anchor=f"worm://{tmp_path}/tips")
    @guarded_root
    def future_root(*args, **options):
        return runtime
    with pytest.raises(BuildRefused) as caught:
        if form == "args":
            future_root(requested)
        else:
            future_root(config=requested)
    assert caught.value.property_name == "ledger_anchor"
    assert future_root(build_config) is runtime


def test_unused_signer_argument_cannot_satisfy_custody_requirement(build_config):
    from types import SimpleNamespace
    config = replace(build_config, require_external_signer=True)
    # An unused injected value is not an applied mechanism, even if it claims
    # external custody. No signing operation in this build would consume it.
    kwargs = {"attestation_signer": SimpleNamespace(external=True)}
    with pytest.raises(BuildRefused) as caught:
        factory.build_execution_controller(config, **kwargs)
    assert caught.value.property_name == "require_external_signer"


@pytest.mark.parametrize("change", ["publication", "anchor", "provider"])
def test_nested_root_cannot_discard_a_different_security_contract(build_config, tmp_path, change):
    from prometheus_protocol.runtime.security_build import guarded_root
    changes = {
        "publication": {"require_config_attestation": True,
                        "config_attestation_target": f"worm://{tmp_path}/attest"},
        "anchor": {"require_ledger_anchor": True, "ledger_anchor": f"worm://{tmp_path}/tips"},
        "provider": {"provider": "remote", "api_base": "https://fixture.invalid/v1",
                     "model": "fixture", "api_key": "fixture-not-used"},
    }
    child_config = replace(build_config, **changes[change])
    @guarded_root
    def outer(config):
        return factory.build_execution_controller(child_config)
    with pytest.raises(BuildRefused) as caught:
        outer(build_config)
    assert caught.value.property_name == "Config"


def test_nested_root_with_the_same_contract_is_validated_and_published_once(build_config, tmp_path):
    from prometheus_protocol.runtime.security_build import guarded_root
    config = replace(build_config, require_config_attestation=True,
                     config_attestation_target=f"worm://{tmp_path}/attest")
    @guarded_root
    def outer(config):
        return factory.build_execution_controller(config)
    runtime = outer(config, attestation_signer=LocalHmacSigner(b"s" * 32))
    assert runtime.config_attestor.last_digest is not None
    assert len(attestation.attestation_target_for(config).records()) == 1


@pytest.mark.parametrize("root", ["swarm", "workflow_runtime"])
@pytest.mark.parametrize("changed", ["bank", "authorizer"])
def test_build_checks_policy_at_both_bank_and_execution_authorizer(build_config, root, changed):
    from prometheus_protocol.policy.profile import load_profile
    from prometheus_protocol.runtime.security_build import validate_build

    config = replace(build_config, verification_profile="defense-in-depth")
    runtime = build_root(root, config)
    if root == "swarm":
        bank, authorizer = runtime.bank, runtime.gate.authorizer
    else:
        bank = runtime._bank
        authorizer = runtime._gateway._submit.__self__._gate.authorizer
    # Paired positive: agreement at both consumers is a viable build.
    assert validate_build(config, runtime)["verification_profile"] == "applied"
    if changed == "bank":
        bank._policy_supplier = lambda: load_profile("baseline")
    else:
        authorizer._supplier = lambda: load_profile("baseline")
    with pytest.raises(BuildRefused) as caught:
        validate_build(config, runtime)
    assert caught.value.property_name == "verification_profile"


def test_external_security_subclass_is_not_an_absent_default_domain(build_config):
    from prometheus_protocol.execution.pending import PendingActionService
    from prometheus_protocol.runtime.security_build import validate_build
    runtime = factory.build_execution_controller(build_config)
    assert validate_build(build_config, runtime)["pending_ttl_seconds"] == "applied"
    class CustomPending(PendingActionService):
        pass
    # The subclass changes no behavior, but a foreign module used to make the
    # live object disappear from the validator and hide its incompatible bound.
    runtime.pending.__class__ = CustomPending
    runtime.pending._ttl_seconds = 0
    with pytest.raises(BuildRefused) as caught:
        validate_build(build_config, runtime)
    assert caught.value.property_name == "component"


# ---------------------------------------------------------------------------
# The report vocabulary: a MEMBERSHIP, exact in both directions (#120's lesson)
# ---------------------------------------------------------------------------


def _report_tokens_in_source() -> set[str]:
    """Every value assigned into ``report[...]``, read off the module source.

    Two sources, as always: the constants say what the vocabulary IS and this
    says what the code WRITES. A single hand-maintained list would agree with
    itself no matter what the code did.
    """

    import ast

    from prometheus_protocol.runtime import security_build

    tree = ast.parse(Path(security_build.__file__).read_text(encoding="utf-8"))
    constants = {
        target.id: node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
        for target in node.targets
        if isinstance(target, ast.Name) and isinstance(node.value.value, str)
    }

    def resolve(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return {node.value}
        if isinstance(node, ast.Name) and node.id in constants:
            return {constants[node.id]}
        if isinstance(node, ast.IfExp):
            return resolve(node.body) | resolve(node.orelse)
        raise AssertionError(f"unresolvable report value at line {node.lineno}")

    written: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if (
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Name)
            and target.value.id == "report"
        ):
            written |= resolve(node.value)
    return written


def test_the_report_vocabulary_is_pinned_exactly():
    """A new token must be named before it can ship, and a named token that
    stopped being written must be noticed. EXACT — a floor catches neither."""

    assert _report_tokens_in_source() == set(REPORT_TOKENS)


def test_a_disabled_requirement_is_not_reported_as_applied(build_config):
    """F-6. ``docs/reachability-build.md`` states the rule — "a disabled
    requirement is not evidence its mechanism exists" — and the first
    implementation wrote APPLIED on these three rows anyway, using the same
    token as ``verifier_timeout_s``, which WAS compared against live
    ``SubprocessVerifier``/``Limits`` objects."""

    runtime = factory.build_execution_controller(build_config)
    report = runtime._security_build_report
    assert build_config.ledger_anchor is None
    assert build_config.require_ledger_anchor is False
    assert build_config.require_digest_pin is False
    assert report["ledger_anchor"] == NOT_REQUESTED
    assert report["require_ledger_anchor"] == NOT_REQUESTED
    assert report["require_digest_pin"] == NOT_REQUESTED
    # ...while a property that WAS compared against live components still says so.
    assert report["verifier_timeout_s"] == APPLIED


def test_a_requested_anchor_is_still_reported_as_applied(build_config, tmp_path):
    """The paired positive: APPLIED must still mean what it meant, or the fix
    above would be indistinguishable from deleting the token."""

    config = replace(build_config, require_ledger_anchor=True,
                     ledger_anchor=f"worm://{tmp_path}/tips")
    runtime = factory.build_execution_controller(config)
    report = runtime._security_build_report
    assert report["require_ledger_anchor"] == APPLIED
    assert report["ledger_anchor"] == APPLIED


def test_every_reported_token_is_a_member_of_the_vocabulary(build_config, tmp_path):
    """Across all four roots, on two configurations, nothing outside the set."""

    from prometheus_protocol.provider.mock import MockProvider

    requested = replace(build_config, require_ledger_anchor=True,
                        ledger_anchor=f"worm://{tmp_path}/tips")
    seen: set[str] = set()
    for config in (build_config, requested):
        for root in ("execution_controller", "workflow_runtime", "orchestrator", "swarm"):
            if root == "swarm":
                runtime = factory.build_swarm_runtime(config, provider=MockProvider())
            else:
                runtime = getattr(factory, "build_" + root)(config)
            seen |= set(runtime._security_build_report.values())
    assert seen and seen <= set(REPORT_TOKENS)


# ---------------------------------------------------------------------------
# The traversal limit, stated where the mechanism is (and both halves pinned)
# ---------------------------------------------------------------------------


def _exhaustive(root):
    """Descends everything ``_objects`` does NOT: sets, slots, closures, keys."""

    todo, seen, out = [root], set(), []
    while todo:
        obj = todo.pop()
        if id(obj) in seen:
            continue
        seen.add(id(obj))
        if type(obj).__module__.startswith("prometheus_protocol."):
            out.append(obj)
        if isinstance(obj, (str, bytes, int, float, bool, type(None), Path)):
            continue
        if isinstance(obj, dict):
            todo.extend(obj.keys())
            todo.extend(obj.values())
            continue
        if isinstance(obj, (list, tuple, set, frozenset)):
            todo.extend(obj)
            continue
        if hasattr(obj, "__self__"):
            todo.append(obj.__self__)
        if getattr(obj, "__closure__", None):
            todo.extend(cell.cell_contents for cell in obj.__closure__)
        if hasattr(obj, "__dict__"):
            todo.extend(vars(obj).values())
        for slot in getattr(type(obj), "__slots__", ()) or ():
            if hasattr(obj, slot):
                todo.append(getattr(obj, slot))
    return out


@pytest.mark.parametrize("root", ["execution_controller", "workflow_runtime", "orchestrator"])
def test_the_shipped_graph_hides_nothing_from_the_traversal(build_config, root):
    """Half one of the stated limit: LATENT. An exhaustive walk of each shipped
    root finds exactly one object ``_objects`` misses — ``Config``, excluded
    deliberately. If a future component moves into a set or behind slots, this
    reddens and the limit stops being latent."""

    from prometheus_protocol.runtime.security_build import _objects

    runtime = getattr(factory, "build_" + root)(build_config)
    reachable = {id(obj) for obj in _objects(runtime)}
    missed = {
        f"{type(obj).__module__}.{type(obj).__name__}"
        for obj in _exhaustive(runtime)
        if id(obj) not in reachable
    }
    assert missed == {"prometheus_protocol.core.config.Config"}


class _Slotted:
    """A component held behind ``__slots__``, which has no ``__dict__``."""

    __slots__ = ("policy",)

    def __init__(self, policy: object) -> None:
        self.policy = policy


#: Every container shape measured to hide a component from the credited walk.
#: Three of them (list, tuple, dict value) ARE credited and are the positive
#: control below; these seven were not, and each is now a refusal.
_HIDING_CONTAINERS = ["set", "frozenset", "dict_key", "namespace", "generator", "slots"]


@pytest.mark.parametrize("container", _HIDING_CONTAINERS)
def test_a_component_the_traversal_cannot_credit_refuses_the_build(build_config, container):
    """THE RULING, replacing the limit this test used to pin.

    It previously asserted ``DEFAULT_NOT_APPLICABLE`` and said in its own
    docstring that the fix filed as G43 would have to flip it. This is that
    flip. A guard that cannot see a component does not know the property is
    inapplicable, and reporting couldn't-verify as verified-clean is the class
    of defect this guard exists to end.

    MEASURED, AND WORSE THAN THE LIMIT DESCRIBED. The old behaviour was not
    always ``default_not_applicable``. That token needs NO reachable consumer;
    when a compliant sibling is present — the ordinary case on a real graph —
    ``all()`` over the reachable ones is True and the row read ``applied``,
    the strongest token the report has. Both were observed: this fixture
    produces the former, and a ``PromotionGate`` planted on a
    ``build_orchestrator`` graph produced the latter.
    """

    import types

    from prometheus_protocol.chokepoint.substrate import SubstratePolicy
    from prometheus_protocol.runtime.security_build import validate_build

    defect = SubstratePolicy(require_verified=False, allow_unverified=True)
    assert build_config.allow_unverified_substrate is False

    hidden = factory.build_execution_controller(build_config)
    hidden.probe_attribute = {
        "set": lambda: {defect},
        "frozenset": lambda: frozenset({defect}),
        "dict_key": lambda: {defect: 1},
        "namespace": lambda: types.SimpleNamespace(policy=defect),
        "generator": lambda: (item for item in [defect]),
        "slots": lambda: _Slotted(defect),
    }[container]()
    with pytest.raises(BuildRefused) as caught:
        validate_build(build_config, hidden)
    assert caught.value.property_name == COMPONENT_NOT_DISCOVERED, (
        "the refusal must name non-discovery specifically. Sharing one "
        "'component' label with the external-subclass refusal was measured to "
        "disarm that refusal's own mutation proof (G44's shape)."
    )
    assert "SubstratePolicy" in str(caught.value)


def test_the_same_defect_in_a_credited_container_is_refused_on_its_merits(build_config):
    """The paired positive control for the seven refusals above.

    The SAME defect in a container the walk credits is refused for the PROPERTY
    it violates rather than for being unreachable — so the refusals above are
    caused by the hiding and not by the guard refusing every graph that has a
    substrate policy in it.
    """

    from prometheus_protocol.chokepoint.substrate import SubstratePolicy
    from prometheus_protocol.runtime.security_build import validate_build

    defect = SubstratePolicy(require_verified=False, allow_unverified=True)
    reachable = factory.build_execution_controller(build_config)
    reachable.probe_attribute = defect
    with pytest.raises(BuildRefused) as caught:
        validate_build(build_config, reachable)
    assert caught.value.property_name == "allow_unverified_substrate"


# ---------------------------------------------------------------------------
# F-1 / F-4: the two scopes, and what each is allowed to claim
# ---------------------------------------------------------------------------


def test_the_discovery_scope_is_derived_from_the_interpreter_not_hand_listed():
    """The whole point of the second scope is that it is not a second list.

    A hand-written second tuple of container shapes would have the same blind
    spot as ``_WALKED_CONTAINERS`` and the same maintainer, so the comparison
    between them would prove nothing. ``gc.get_referents`` is the collector's
    own account of what an object references.
    """

    import ast
    import textwrap

    from prometheus_protocol.runtime import security_build

    tree = ast.parse(textwrap.dedent(inspect.getsource(security_build._discovered)))
    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "get_referents" in calls, (
        "the discovery scope must come from the interpreter; a second hand-written "
        "container list is the first list with extra steps"
    )
    # Over the CODE, not the source text: the docstring names
    # ``_WALKED_CONTAINERS`` to explain why it is not used, and a substring
    # search cannot tell an explanation from a dependency.
    referenced = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert "_WALKED_CONTAINERS" not in referenced, (
        "the discovery scope must not be derived from the credited scope's own "
        "container tuple, or the two cannot disagree"
    )


@pytest.mark.parametrize(
    "root", ["execution_controller", "workflow_runtime", "orchestrator", "swarm"]
)
def test_no_shipped_root_hides_a_component_from_the_credited_walk(build_config, root):
    """The refusal is LATENT: every shipped root's two scopes agree exactly.

    Exact, not a floor. If a future component moves into a set or behind slots,
    this reddens and the build refuses — which is the intended consequence, not
    a regression to tolerate.
    """

    from prometheus_protocol.runtime.security_build import _discovered, _objects

    if root == "swarm":
        runtime = factory.build_swarm_runtime(build_config, provider=MockProvider())
    else:
        runtime = getattr(factory, "build_" + root)(build_config)
    credited = {id(obj) for obj in _objects(runtime)}
    hidden = {
        f"{type(obj).__module__}.{type(obj).__name__}"
        for obj in _discovered(runtime)
        if id(obj) not in credited
    }
    assert hidden == set()


def test_an_unregistered_carrier_of_a_compared_attribute_refuses(build_config):
    """F-4 made fail-closed: a NEW consumer of an EXISTING field must register.

    The hand-list cannot be derived — which class honours a field is semantic —
    so instead an object carrying an attribute a property is compared on, that
    is not a registered carrier of it, refuses the build.
    """

    from prometheus_protocol.execution.pending import PendingActionService
    from prometheus_protocol.runtime.security_build import _objects, validate_build

    # A PACKAGE-OWNED object that grows a second consumer's attribute. A class
    # defined in this test module would not be credited at all — the walk
    # already declines foreign objects — so it could not exercise this rule.
    runtime = factory.build_execution_controller(build_config)
    services = [obj for obj in _objects(runtime) if isinstance(obj, PendingActionService)]
    assert services, "fixture precondition: the controller graph has a pending service"
    services[0].threshold = 0.99

    with pytest.raises(BuildRefused) as caught:
        validate_build(build_config, runtime)
    assert caught.value.property_name == COMPONENT_UNREGISTERED_CARRIER
    assert "threshold" in str(caught.value)
    assert "PendingActionService" in str(caught.value)


def test_every_registered_carrier_is_a_class_and_the_map_is_exact():
    """Membership, not a count, and no string names.

    A carrier map keyed on ``"module.ClassName"`` would be F-7's defect —
    a name pin on a writable attribute — inside the fix for F-4.
    """

    from prometheus_protocol.runtime.security_build import security_attribute_carriers

    carriers = security_attribute_carriers()
    assert set(carriers) == {
        "isolating", "require_digest_pin", "tip_anchor", "signer", "require_verified",
        "allow_unverified", "has_policy_supplier", "_policy_supplier", "_supplier",
        "threshold", "_escalate_below", "escalate_below", "_ttl_seconds", "_budget",
        "timeout_s", "memory_mb", "cpu_seconds", "max_processes", "wall_time_s",
        "memory_bytes", "cpu_time_s", "max_response_bytes", "api_base", "url",
    }
    for attribute, permitted in carriers.items():
        assert isinstance(permitted, tuple) and permitted, attribute
        for entry in permitted:
            assert isinstance(entry, type), f"{attribute} carries a non-class entry"
    assert "name" not in carriers, (
        "`name` is not distinctive enough to key on — core.models.Tier carries it "
        "in the shipped swarm graph. The gap is docs/OPEN-GAPS.md G50."
    )


@pytest.mark.parametrize("residual", ["lazy", "getattr", "module_global", "foreign_closure"])
def test_the_named_residuals_of_the_discovery_scope_are_real(build_config, residual):
    """Doctrine #5: the stated limit is a PASSING TEST, not a paragraph.

    Each of these is a place a component can exist that neither scope sees.
    They are named in ``_discovered``'s docstring and in G49. If one of them
    stops being true, this reddens and the docstring is wrong.
    """

    from prometheus_protocol.chokepoint.substrate import SubstratePolicy
    from prometheus_protocol.runtime.security_build import _discovered

    defect = SubstratePolicy(require_verified=False, allow_unverified=True)
    runtime = factory.build_execution_controller(build_config)

    if residual == "lazy":
        # Nothing holds it yet; it is built on first use, after the guard ran.
        class BuildsOnUse:
            def make(self) -> object:
                return SubstratePolicy(require_verified=False, allow_unverified=True)

        runtime.probe_attribute = BuildsOnUse()
    elif residual == "getattr":
        class Dynamic:
            def __getattr__(self, name: str) -> object:
                return defect

        runtime.probe_attribute = Dynamic()
    elif residual == "foreign_closure":
        # A closure THIS MODULE wrote, not the package. `_discovered` follows
        # only the package's own closures: a callback the caller injected is
        # not a composition the package made, and whatever it captured is the
        # caller's business. Measured — following every closure cell instead
        # failed 4 chokepoint tests and errored 71 more on an in-memory audit
        # medium reached through a test-supplied executor.
        runtime.probe_attribute = lambda: defect
    else:
        # Reachable from the module, never from the root.
        globals()["_module_level_defect"] = defect
        runtime.probe_attribute = None

    found = {id(obj) for obj in _discovered(runtime)}
    assert id(defect) not in found, (
        f"the {residual} residual is no longer real; _discovered's docstring and "
        "docs/OPEN-GAPS.md G49 both claim it is"
    )
