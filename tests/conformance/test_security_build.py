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


@pytest.mark.parametrize("container", ["set", "frozenset", "dict_key", "namespace", "closure"])
def test_an_unreachable_component_reads_as_not_applicable_not_as_a_refusal(build_config, container):
    """Half two: OPEN IN PRINCIPLE, and this is the limit's whole point.

    The SAME live defect — a substrate policy permitting what the Config
    forbids — is refused when the traversal reaches it and reported
    ``default_not_applicable`` when it does not. This test asserts the
    behaviour the guard HAS, so the limit in ``_objects`` is measured rather
    than asserted, and so the fix filed as G43 has a test that must flip.
    """

    import types

    from prometheus_protocol.chokepoint.substrate import SubstratePolicy
    from prometheus_protocol.runtime.security_build import validate_build

    defect = SubstratePolicy(require_verified=False, allow_unverified=True)
    assert build_config.allow_unverified_substrate is False

    reachable = factory.build_execution_controller(build_config)
    reachable.probe_attribute = defect
    with pytest.raises(BuildRefused) as caught:
        validate_build(build_config, reachable)
    assert caught.value.property_name == "allow_unverified_substrate"

    hidden = factory.build_execution_controller(build_config)
    hidden.probe_attribute = {
        "set": lambda: {defect},
        "frozenset": lambda: frozenset({defect}),
        "dict_key": lambda: {defect: 1},
        "namespace": lambda: types.SimpleNamespace(policy=defect),
        "closure": lambda: (lambda: defect),
    }[container]()
    assert validate_build(build_config, hidden)["allow_unverified_substrate"] == (
        DEFAULT_NOT_APPLICABLE
    ), "the limit named in _objects has changed; update the docstring and G43"
