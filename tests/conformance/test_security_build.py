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
from prometheus_protocol.runtime.security_build import BuildRefused, install_build_guards


@pytest.fixture
def build_config(tmp_path, monkeypatch):
    # Build only: never execute a candidate or claim this Mac provides Linux isolation.
    monkeypatch.setattr(NamespaceSandbox, "available", classmethod(lambda cls: True))
    return Config(sandbox="namespace", ledger_path=":memory:",
                  registry_dir=tmp_path / "skills", trust_store_path=tmp_path / "trust.db")


def test_f1_required_attestation_reaches_startup(build_config, tmp_path, monkeypatch):
    calls = []

    def unavailable(*args, **kwargs):
        calls.append(True)
        raise ConfigError("publication unavailable")

    monkeypatch.setattr(attestation, "attest_at_startup", unavailable)
    config = replace(build_config, require_config_attestation=True,
                     config_attestation_target=f"worm://{tmp_path}/attest")
    with pytest.raises(ConfigError):
        factory.build_execution_controller(config)
    # Missing signer is also a refusal, but must not silently return a controller.


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
    config = replace(build_config, ledger_path=tmp_path / "audit.db",
                     require_ledger_anchor=True, ledger_anchor=f"worm://{tmp_path}/tips")
    ledger = SqliteLedger(":memory:")
    with pytest.raises(ConfigError):
        if root == "execution":
            factory.build_execution_controller(config, ledger=ledger)
        else:
            factory.build_swarm_runtime(config, provider=MockProvider(), ledger=ledger)


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
