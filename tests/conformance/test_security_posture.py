"""A requested security property that cannot be honoured is refused, never
degraded — as a tested invariant, not a per-flag patch (threat model §5).

The model defect: ``Config(require_digest_pin=True)`` built a container sandbox
that reported ``require_digest_pin=False``. The field existed, an operator could
set it, and ``build_sandbox`` never received it — a control present, plausible,
and wired to nothing. Measured on the pre-fix tree, not inferred.

Three things are held to account here:

1. **The named bug**, closed in both directions: the requirement now reaches the
   sandbox, and an adapter that *cannot* provide it (namespace, unsafe, or
   ``auto`` with no container runtime) refuses to construct rather than
   returning something that quietly lacks it.
2. **The class**, as a mechanism: ``Config.SECURITY_FIELDS`` declares every
   security-relevant field, and a test parses the source tree to prove each one
   is consumed somewhere outside ``config.py`` — so the next dead flag fails CI
   instead of shipping. A second test proves every field whose *name* looks like
   a security flag is on that list, so the list cannot quietly miss one.
3. **Coherence and defaults**: combinations that are each valid and jointly
   unsafe are refused at load, and a ``Config()`` with nothing set lands in the
   hardened posture — with the one permissive default named rather than hidden.

Every refusal is asserted with ``pytest.raises``: the wrong outcome is not a
failing assertion on a returned object, it is a returned object at all.
"""

from __future__ import annotations

import ast
import dataclasses
import pathlib
import re

import pytest

from prometheus_protocol.core.config import (
    PROVIDER_MOCK,
    SANDBOX_NAMES,
    SECURITY_FIELDS,
    Config,
)
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.runtime.factory import build_execution_controller, build_sandbox_for
from prometheus_protocol.sandbox.base import Limits
from prometheus_protocol.sandbox.container import ContainerSandbox
from prometheus_protocol.sandbox.factory import build_sandbox, digest_pin_required
from prometheus_protocol.sandbox.namespace import NamespaceSandbox
from prometheus_protocol.sandbox.unsafe import NullSandbox, UnsafeLocalSandbox

UNSAFE_OPT_IN = {"PROM_ALLOW_UNSAFE_EXEC": "1"}
REMOTE = dict(provider="remote", api_base="https://gw.example.invalid/v1", model="m", api_key="k")
SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "prometheus_protocol"


@pytest.fixture
def no_pin_env(monkeypatch):
    """The container adapter also reads the environment directly; clear it so the
    only source of the requirement in a test is the one the test supplies."""

    monkeypatch.delenv("PROM_REQUIRE_DIGEST_PIN", raising=False)


def _availability(monkeypatch, *, namespace: bool, container: bool) -> None:
    monkeypatch.setattr(NamespaceSandbox, "available", classmethod(lambda cls: namespace))
    monkeypatch.setattr(ContainerSandbox, "available", classmethod(lambda cls: container))


# ===========================================================================
# 1. require_digest_pin — the model
# ===========================================================================


def test_the_named_bug_is_closed_the_requirement_reaches_the_sandbox(no_pin_env):
    direct = build_sandbox("container", env={}, require_digest_pin=True)
    assert isinstance(direct, ContainerSandbox)
    assert direct.require_digest_pin is True

    via_config = build_sandbox_for(Config(sandbox="container", require_digest_pin=True), env={})
    assert via_config.require_digest_pin is True


def test_what_the_factory_used_to_return(no_pin_env):
    """The object the old wiring handed back for a Config that required pinning:
    a bare ``ContainerSandbox()`` reporting False. Kept so the defect stays
    legible next to its fix."""

    assert ContainerSandbox().require_digest_pin is False


@pytest.mark.parametrize("adapter", ["namespace", "unsafe"])
def test_an_adapter_that_cannot_pin_is_refused_not_downgraded(adapter, no_pin_env):
    with pytest.raises(ConfigError, match="cannot be honoured"):
        build_sandbox(adapter, env=UNSAFE_OPT_IN, require_digest_pin=True)


def test_auto_refuses_when_pinning_is_required_and_no_container_runtime(monkeypatch, no_pin_env):
    _availability(monkeypatch, namespace=True, container=False)

    # Positive control: without the requirement, auto is perfectly able to build
    # a sandbox here — so the refusal below is the requirement's doing.
    assert isinstance(build_sandbox("auto", env={}), NamespaceSandbox)

    with pytest.raises(ConfigError, match="no container runtime"):
        build_sandbox("auto", env={}, require_digest_pin=True)


def test_auto_selects_the_only_adapter_that_can_pin_when_required(monkeypatch, no_pin_env):
    _availability(monkeypatch, namespace=True, container=True)

    # Control: auto's ordinary preference is the namespace adapter.
    assert isinstance(build_sandbox("auto", env={}), NamespaceSandbox)

    chosen = build_sandbox("auto", env={}, require_digest_pin=True)
    assert isinstance(chosen, ContainerSandbox)
    assert chosen.require_digest_pin is True


@pytest.mark.parametrize(
    "env,argument,expected",
    [({"PROM_REQUIRE_DIGEST_PIN": "1"}, False, True),
     ({}, True, True),
     ({}, None, False),
     ({"PROM_REQUIRE_DIGEST_PIN": "0"}, True, True),
     ({"PROM_REQUIRE_DIGEST_PIN": "1"}, None, True)],
    ids=["env-raises", "config-raises", "neither", "env-cannot-lower", "env-alone"],
)
def test_the_requirement_is_the_or_of_its_sources(env, argument, expected, no_pin_env):
    """Config and environment can each RAISE the requirement; neither lowers the
    other. A programmatic Config(False) beside PROM_REQUIRE_DIGEST_PIN=1 must
    not switch pinning off."""

    assert digest_pin_required(env) is (env.get("PROM_REQUIRE_DIGEST_PIN") == "1")
    sandbox = build_sandbox("container", env=env, require_digest_pin=argument)
    assert sandbox.require_digest_pin is expected


# ===========================================================================
# 2. Coherence: refused at load, with the reason
# ===========================================================================


@pytest.mark.parametrize("adapter", ["namespace", "unsafe"])
def test_config_refuses_pinning_with_an_adapter_that_cannot_pin(adapter):
    with pytest.raises(ConfigError, match="cannot be honoured"):
        Config(sandbox=adapter, require_digest_pin=True)


@pytest.mark.parametrize("adapter", ["container", "auto"])
def test_config_accepts_pinning_with_an_adapter_that_can(adapter):
    assert Config(sandbox=adapter, require_digest_pin=True).require_digest_pin is True


def test_config_refuses_a_remote_provider_with_the_unsafe_sandbox():
    with pytest.raises(ConfigError, match="no isolation"):
        Config(sandbox="unsafe", **REMOTE)


def test_config_still_allows_the_mock_provider_with_the_unsafe_sandbox():
    """The documented development path stays open at load; the runtime opt-in
    (PROM_ALLOW_UNSAFE_EXEC) is still required to actually build it."""

    assert Config(sandbox="unsafe").sandbox == "unsafe"
    with pytest.raises(ConfigError, match="PROM_ALLOW_UNSAFE_EXEC"):
        build_sandbox_for(Config(sandbox="unsafe"), env={})
    assert isinstance(build_sandbox_for(Config(sandbox="unsafe"), env=UNSAFE_OPT_IN), UnsafeLocalSandbox)


def test_auto_never_falls_back_to_unsafe_for_a_remote_provider(monkeypatch, no_pin_env):
    """The runtime half of the same rule: auto with the opt-in and nothing
    isolating available falls back to unsafe for the mock provider (control),
    and refuses for a remote one."""

    _availability(monkeypatch, namespace=False, container=False)

    assert isinstance(build_sandbox_for(Config(), env=UNSAFE_OPT_IN), UnsafeLocalSandbox)

    with pytest.raises(ConfigError, match="without isolation"):
        build_sandbox_for(Config(**REMOTE), env=UNSAFE_OPT_IN)


def test_config_rejects_an_unknown_sandbox_at_load():
    with pytest.raises(ConfigError, match="unknown sandbox"):
        Config(sandbox="docker")
    for name in SANDBOX_NAMES:
        Config(sandbox=name)


# ===========================================================================
# 3. Knobs that cannot grant what they name
# ===========================================================================


def test_deny_network_cannot_be_lowered():
    assert Limits().deny_network is True
    with pytest.raises(ValueError, match="cannot be honoured"):
        Limits(deny_network=False)


def test_high_risk_routing_cannot_be_disabled_by_configuration():
    """``escalate_below=0.0`` is the most permissive confidence floor a Config can
    express. Even then, high-risk actions route to a human: the routing flag is
    not a Config field at all."""

    controller = build_execution_controller(Config(ledger_path=":memory:", escalate_below=0.0))
    assert controller._gate._route_high_risk is True


# ===========================================================================
# 4. The class, as a mechanism: no security field may be set and read nowhere
# ===========================================================================


def _attribute_reads_outside_config() -> set[str]:
    names: set[str] = set()
    for path in SRC.rglob("*.py"):
        if path.name == "config.py" and path.parent.name == "core":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                names.add(node.attr)
    return names


_SECURITY_SHAPED = re.compile(r"^(require_|allow_|enforce_|deny_|strict)")


def test_every_declared_security_field_is_consumed_somewhere():
    """The require_digest_pin defect, generalised into a build-time check: a
    Config field on SECURITY_FIELDS that no code outside config.py ever reads is
    a control wired to nothing, and it fails here before it ships."""

    reads = _attribute_reads_outside_config()
    dead = [name for name in SECURITY_FIELDS if name not in reads]
    assert dead == [], (
        f"security settings that can be set but are read by nothing: {dead} — "
        "the require_digest_pin defect again"
    )


def test_every_security_shaped_field_is_declared():
    """The list cannot quietly miss a flag: a field NAMED like a security flag
    must be on SECURITY_FIELDS, or this fails when it is added."""

    names = [f.name for f in dataclasses.fields(Config)]
    shaped = [n for n in names if _SECURITY_SHAPED.match(n)]
    undeclared = [n for n in shaped if n not in SECURITY_FIELDS]
    assert undeclared == [], f"security-shaped Config fields not on SECURITY_FIELDS: {undeclared}"


def test_security_fields_are_real_config_fields():
    names = {f.name for f in dataclasses.fields(Config)}
    assert set(SECURITY_FIELDS) <= names, set(SECURITY_FIELDS) - names


def test_the_mechanism_has_teeth():
    """A field that exists on Config and is read nowhere IS detected by the same
    walk — proven by asking about a name that is certainly not read."""

    reads = _attribute_reads_outside_config()
    assert "require_digest_pin" in reads  # the fix is visible to the mechanism
    assert "this_field_is_read_nowhere_xyz" not in reads


# ===========================================================================
# 5. Defaults: an operator who sets nothing gets the hardened posture
# ===========================================================================


def test_defaults_are_the_hardened_posture(monkeypatch):
    config = Config()
    assert config.provider == PROVIDER_MOCK, "no network by default"
    assert config.sandbox == "auto", "isolating adapters preferred by default"
    assert config.allow_insecure_loopback is False
    assert config.enable_model_judge is False
    assert config.pending_ttl_seconds > 0, "human holds expire by default"
    assert 0.0 < config.escalate_below <= 1.0
    assert config.request_timeout_s > 0 and config.verifier_timeout_s > 0
    assert config.provider_max_response_bytes > 0

    # With nothing isolating available and no opt-in, the default refuses to run
    # code at all — it never reaches for the unsafe adapter.
    _availability(monkeypatch, namespace=False, container=False)
    assert isinstance(build_sandbox("auto", env={}), NullSandbox)

    # The one permissive default, stated rather than hidden (threat model §5.4):
    # digest pinning is off because the shipped default image is a floating tag
    # by design, and pinning is a per-deployment property. auto prefers the
    # namespace adapter, which runs no image to substitute.
    assert config.require_digest_pin is False
