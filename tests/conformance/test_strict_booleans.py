"""F9: one strict boolean parser at every entry point (PROM-FIX-B part 1).

The independent review reproduced two fail-opens in the old truth-set parser:
``allow_unverified_substrate="false"`` enabled the opt-out (``bool("false")``
is ``True``), and ``PROM_REQUIRE_VERIFIED_SUBSTRATE=tru`` silently became
``False`` while a valid opt-out stayed on. Every entry point is exercised
here against the same value matrix, and a sweep proves the old pattern is
gone from the source and test trees: a parser fixed at one site is this
finding's own shape.

Positive controls come first in every group: a parser that rejected
everything would pass a rejection test vacuously.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import re
from types import SimpleNamespace

import pytest

from prometheus_protocol.chokepoint import (
    DbTarget,
    MigrationRunnerConfig,
    external_signer_required,
    resolve_substrate_policy,
    unverified_substrate_allowed,
    verified_substrate_required,
)
from prometheus_protocol.core import config as _config_module
from prometheus_protocol.core.booleans import FALSE_WORDS, TRUE_WORDS, parse_env_bool, require_bool
from prometheus_protocol.core.config import BOOLEAN_FIELDS, SECURITY_FIELDS, Config
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.runtime.factory import ledger_anchor_required
from prometheus_protocol.sandbox.container import ContainerSandbox, _require_digest_pin
from prometheus_protocol.sandbox.factory import build_sandbox, digest_pin_required, unsafe_exec_allowed

KEY = b"strict-boolean-test-key-32-bytes!!"
REPO = pathlib.Path(__file__).resolve().parents[2]

VALID_TRUE = ["1", "true", "TRUE", "True ", " yes", "on", "ON"]
VALID_FALSE = ["0", "false", "FALSE", " False ", "no", "off"]
INVALID = ["tru", "y", "t", "enabled", "", " ", "2", "none", "true false", "yes,no", "-1", "1.0"]
NOT_BOOLS = ["false", "true", "", 0, 1, None, 2.0, [], "1"]

ENV_READERS = [
    ("PROM_REQUIRE_EXTERNAL_SIGNER", external_signer_required),
    ("PROM_REQUIRE_VERIFIED_SUBSTRATE", verified_substrate_required),
    ("PROM_ALLOW_UNVERIFIED_SUBSTRATE", unverified_substrate_allowed),
    ("PROM_ALLOW_UNSAFE_EXEC", unsafe_exec_allowed),
    ("PROM_REQUIRE_DIGEST_PIN", digest_pin_required),
    ("PROM_REQUIRE_DIGEST_PIN", _require_digest_pin),
    ("PROM_REQUIRE_LEDGER_ANCHOR", ledger_anchor_required),
]

CONFIG_ENV = {
    "enable_model_judge": "PROM_ENABLE_MODEL_JUDGE",
    "require_digest_pin": "PROM_REQUIRE_DIGEST_PIN",
    "allow_insecure_loopback": "PROM_ALLOW_INSECURE_LOOPBACK",
    "require_ledger_anchor": "PROM_REQUIRE_LEDGER_ANCHOR",
    "require_external_signer": "PROM_REQUIRE_EXTERNAL_SIGNER",
    "require_verified_substrate": "PROM_REQUIRE_VERIFIED_SUBSTRATE",
    "allow_unverified_substrate": "PROM_ALLOW_UNVERIFIED_SUBSTRATE",
    "require_config_attestation": "PROM_REQUIRE_CONFIG_ATTESTATION",
}
# Coherence rules refuse some true values unless a companion is set; supply it.
COMPANION = {
    "PROM_REQUIRE_LEDGER_ANCHOR": {"PROM_LEDGER_ANCHOR": "https://log.example.invalid/v1"},
    "PROM_REQUIRE_CONFIG_ATTESTATION": {
        "PROM_CONFIG_ATTESTATION_TARGET": "https://witness.example.invalid/attestations"
    },
}


def runner_config(**flags):
    return MigrationRunnerConfig(
        target=DbTarget("localhost", 5432, "appdb", "migrator", "synthetic-secret"),
        signing_key=KEY,
        approval_store_path="/tmp/unused-store.db",
        **flags,
    )


# ---------------------------------------------------------------------------
# 1. The parser itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw", VALID_TRUE)
def test_true_words_parse_true(raw):
    assert parse_env_bool("X", raw, default=False) is True


@pytest.mark.parametrize("raw", VALID_FALSE)
def test_false_words_parse_false(raw):
    assert parse_env_bool("X", raw, default=True) is False


def test_absent_takes_the_default_present_and_invalid_does_not():
    assert parse_env_bool("X", None, default=True) is True
    assert parse_env_bool("X", None, default=False) is False
    for raw in INVALID:
        with pytest.raises(ConfigError, match="not a boolean"):
            parse_env_bool("X", raw, default=False)
        with pytest.raises(ConfigError, match="not a boolean"):
            parse_env_bool("X", raw, default=True)


def test_the_word_sets_are_exactly_the_enumerated_ones():
    assert TRUE_WORDS == {"1", "true", "yes", "on"} and FALSE_WORDS == {"0", "false", "no", "off"}
    assert not (TRUE_WORDS & FALSE_WORDS)


@pytest.mark.parametrize("value", NOT_BOOLS)
def test_require_bool_refuses_everything_that_is_not_a_bool(value):
    with pytest.raises(ConfigError, match="must be True or False"):
        require_bool(value, name="flag")


def test_require_bool_accepts_both_booleans():
    assert require_bool(True, name="flag") is True and require_bool(False, name="flag") is False


# ---------------------------------------------------------------------------
# 2. Config: programmatic fields and Config.from_env
# ---------------------------------------------------------------------------


def test_every_config_boolean_is_listed_and_every_listed_field_is_a_boolean():
    import dataclasses

    booleans = {f.name for f in dataclasses.fields(Config) if f.type in ("bool", bool)}
    assert booleans == set(BOOLEAN_FIELDS)
    assert set(CONFIG_ENV) == set(BOOLEAN_FIELDS)
    assert {"require_verified_substrate", "allow_unverified_substrate"} <= set(SECURITY_FIELDS)


@pytest.mark.parametrize("field", BOOLEAN_FIELDS)
@pytest.mark.parametrize("value", NOT_BOOLS)
def test_config_refuses_a_non_bool_for_every_boolean_field(field, value):
    with pytest.raises(ConfigError, match="must be True or False"):
        Config(**{field: value})


@pytest.mark.parametrize("field", BOOLEAN_FIELDS)
def test_config_accepts_real_booleans_for_every_boolean_field(field):
    assert getattr(Config(**{field: False}), field) is False
    # Two requirements refuse at load unless the target they require is
    # configured; supply it so this test is about the boolean, not the
    # coherence rule (which has its own tests).
    companions = {
        "require_ledger_anchor": {"ledger_anchor": "https://log.example.invalid/v1"},
        "require_config_attestation": {
            "config_attestation_target": "https://witness.example.invalid/attestations"
        },
    }
    extra = companions.get(field, {})
    assert getattr(Config(**{field: True}, **extra), field) is True


@pytest.mark.parametrize("field,var", sorted(CONFIG_ENV.items()))
def test_config_from_env_parses_every_boolean_variable_strictly(field, var):
    companion = COMPANION.get(var, {})
    for raw in VALID_TRUE:
        assert getattr(Config.from_env({var: raw, **companion}), field) is True
    for raw in VALID_FALSE:
        assert getattr(Config.from_env({var: raw}), field) is False
    assert getattr(Config.from_env({}), field) is False, "absent takes the default"
    for raw in INVALID:
        with pytest.raises(ConfigError, match=re.escape(f"{var}={raw!r}")):
            Config.from_env({var: raw, **companion})


def test_the_review_case_a_misspelled_requirement_is_refused_not_false():
    """``PROM_REQUIRE_VERIFIED_SUBSTRATE=tru`` used to be silently False while a
    valid opt-out stayed on. Now the load refuses, and the opt-out never takes
    effect on that load."""

    with pytest.raises(ConfigError, match="PROM_REQUIRE_VERIFIED_SUBSTRATE='tru'"):
        Config.from_env({"PROM_REQUIRE_VERIFIED_SUBSTRATE": "tru", "PROM_ALLOW_UNVERIFIED_SUBSTRATE": "1"})
    with pytest.raises(ConfigError, match="PROM_REQUIRE_VERIFIED_SUBSTRATE='tru'"):
        resolve_substrate_policy(env={"PROM_REQUIRE_VERIFIED_SUBSTRATE": "tru", "PROM_ALLOW_UNVERIFIED_SUBSTRATE": "1"})


# ---------------------------------------------------------------------------
# 3. MigrationRunnerConfig and the substrate policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flag", ["require_external_signer", "require_verified_substrate", "allow_unverified_substrate"])
@pytest.mark.parametrize("value", NOT_BOOLS)
def test_runner_config_refuses_a_non_bool_flag(flag, value):
    with pytest.raises(ConfigError, match="must be True or False"):
        runner_config(**{flag: value})


def test_runner_config_accepts_real_booleans():
    assert runner_config(require_verified_substrate=True).require_verified_substrate is True
    assert runner_config(allow_unverified_substrate=True).allow_unverified_substrate is True
    assert runner_config().require_external_signer is False


def test_the_review_case_a_string_false_no_longer_enables_the_opt_out():
    """``allow_unverified_substrate="false"`` ENABLED the opt-out through
    ``bool()``. It is now refused at every layer that reads it."""

    with pytest.raises(ConfigError, match="must be True or False"):
        resolve_substrate_policy(SimpleNamespace(allow_unverified_substrate="false"), env={})
    with pytest.raises(ConfigError, match="must be True or False"):
        resolve_substrate_policy(settings=SimpleNamespace(allow_unverified_substrate="false"), env={})
    with pytest.raises(ConfigError, match="must be True or False"):
        resolve_substrate_policy(SimpleNamespace(require_verified_substrate=1), env={})
    with pytest.raises(ConfigError, match="must be True or False"):
        runner_config(allow_unverified_substrate="false")
    with pytest.raises(ConfigError, match="must be True or False"):
        Config(allow_unverified_substrate="false")
    # Positive control: the real booleans resolve as before.
    policy = resolve_substrate_policy(SimpleNamespace(allow_unverified_substrate=True), env={})
    assert policy.allow_unverified is True and policy.require_verified is False
    assert resolve_substrate_policy(env={}).allow_unverified is False


# ---------------------------------------------------------------------------
# 4. Every environment reader outside Config
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("var,reader", ENV_READERS, ids=[f"{v}:{r.__name__}" for v, r in ENV_READERS])
def test_every_environment_reader_uses_the_strict_parser(var, reader):
    for raw in VALID_TRUE:
        assert reader({var: raw}) is True
    for raw in VALID_FALSE:
        assert reader({var: raw}) is False
    assert reader({}) is False
    for raw in INVALID:
        with pytest.raises(ConfigError, match=re.escape(f"{var}={raw!r}")):
            reader({var: raw})


@pytest.mark.parametrize("value", ["false", "true", 0, 1, "1"])
def test_sandbox_builders_refuse_a_non_bool_pin_requirement(value, monkeypatch):
    monkeypatch.delenv("PROM_REQUIRE_DIGEST_PIN", raising=False)
    with pytest.raises(ConfigError, match="must be True or False"):
        build_sandbox("container", env={}, require_digest_pin=value)
    with pytest.raises(ConfigError, match="must be True or False"):
        ContainerSandbox(require_digest_pin=value)


def test_sandbox_builders_accept_real_booleans_and_absent(monkeypatch):
    monkeypatch.delenv("PROM_REQUIRE_DIGEST_PIN", raising=False)
    assert build_sandbox("container", env={}, require_digest_pin=True).require_digest_pin is True
    assert build_sandbox("container", env={}, require_digest_pin=None).require_digest_pin is False
    assert ContainerSandbox(require_digest_pin=False).require_digest_pin is False
    with pytest.raises(ConfigError, match="PROM_REQUIRE_DIGEST_PIN='enabled'"):
        build_sandbox("container", env={"PROM_REQUIRE_DIGEST_PIN": "enabled"})


# ---------------------------------------------------------------------------
# 5. The CI "fail, do not skip" flags, and the sweep
# ---------------------------------------------------------------------------

CI_FLAGS = ("PROM_REQUIRE_SANDBOX", "PROM_REQUIRE_PG", "PROM_REQUIRE_PRIVILEGED", "PROM_REQUIRE_CONTAINER")


def _test_sources() -> list[pathlib.Path]:
    return sorted(p for p in (REPO / "tests").rglob("*.py") if p.name != pathlib.Path(__file__).name)


def test_every_ci_gate_flag_is_read_through_the_strict_parser():
    """A typo in a CI flag used to turn a mandatory gate into a silent skip.
    Every read of these four flags in the test tree now goes through
    ``parse_env_bool``, and none goes through anything else."""

    strict = re.compile(r'parse_env_bool\(\s*"(PROM_REQUIRE_[A-Z]+)"')
    loose = re.compile(r'environ\.get\(\s*"(PROM_REQUIRE_(?:SANDBOX|PG|PRIVILEGED|CONTAINER))"[^\n]*\)\s*(?:or "")?\s*\)?\.(?:strip\(\)\.)?lower\(\)')
    seen = set()
    for path in _test_sources():
        text = path.read_text(encoding="utf-8")
        assert loose.search(text) is None, f"{path}: a CI flag is read by the old truth-set parser"
        seen.update(strict.findall(text))
        if "def required(name)" in text:
            assert "parse_env_bool(name" in text, f"{path}: required() bypasses the strict parser"
            seen.update(CI_FLAGS[i] for i in (0, 3))  # required("PROM_REQUIRE_SANDBOX"/"PROM_REQUIRE_CONTAINER")
    assert set(CI_FLAGS) <= seen, f"CI flags not read through the strict parser: {set(CI_FLAGS) - seen}"


def test_the_old_truth_set_pattern_appears_nowhere_else():
    """The literal tuple the fail-open was copied from, pinned at one site.

    WHAT THIS PROVES, narrowed to the truth. It proves that THIS SPELLING —
    ``"1", "true", "yes", "on"`` in that order — occurs nowhere but the parser.
    It does not prove that no loose boolean reader exists: a reordered tuple, a
    ``frozenset``, a ``casefold()`` membership test or a new coercion wrapper all
    walk past it, because it is a regex over one literal and what varies is how
    somebody writes a truth set.

    It is kept because it is cheap and because that literal really is the shape
    that was copied. The property is carried by
    ``test_no_boolean_security_setting_is_read_outside_the_strict_parser``, which
    constrains where the setting is READ instead of how a truth set is SPELLED.
    """

    pattern = re.compile(r'"1",\s*"true",\s*"yes",\s*"on"')
    offenders = []
    for root in ("src", "tests", "scripts"):
        for path in sorted((REPO / root).rglob("*.py")):
            if path.name == "booleans.py" and path.parent.name == "core":
                continue
            if path.name == pathlib.Path(__file__).name:
                continue
            if pattern.search(path.read_text(encoding="utf-8")):
                offenders.append(str(path.relative_to(REPO)))
    assert offenders == [], offenders


# ---------------------------------------------------------------------------
# 5b. The property: a boolean security setting is read ONE way
# ---------------------------------------------------------------------------
#
# The sweep above is a regex over a spelling. This is the property it was
# standing in for, and it is enforceable structurally because every boolean
# security setting in this repository is read out of a Mapping by name: find
# every such read in the source, test and script trees, and require it to be
# lexically inside a ``parse_env_bool(...)`` call. A reordered tuple, a
# ``frozenset``, a ``casefold()`` membership test, a helper, or a coercion
# wrapper nobody has invented yet all fail identically — not because the shape
# was anticipated, but because the read is not going through the parser.

#: The house naming convention for a boolean setting, which is what makes this
#: enforceable for settings that DO NOT YET EXIST. Derived names (below) cover
#: what is wired up today; the pattern covers the next one, which is the case a
#: derived-only set would miss.
_BOOLEAN_ENV_PATTERN = re.compile(r"^PROM_(?:REQUIRE|ALLOW|ENABLE|DISABLE)_[A-Z0-9_]+$")

#: Reads that are not security reads, sanctioned by ``path::<normalized source>``
#: — content, not line, so rewriting the expression stops matching.
_SANCTIONED_LOOSE_READS = frozenset({
    # A parametrized test restating its own fixture: the dict on the left of the
    # comparison is the one the test itself just built, and the assertion is that
    # the READER agrees with it. Not a setting being consumed.
    "tests/conformance/test_security_posture.py::env.get('PROM_REQUIRE_DIGEST_PIN')",
})

_STRICT_CALLS = {"parse_env_bool", "_env_bool"}


def _boolean_env_names() -> set[str]:
    """Every boolean setting name that is wired up today, from live objects."""

    return {name for name, _ in ENV_READERS} | set(CONFIG_ENV.values()) | set(CI_FLAGS)


def _module_level_aliases(tree: ast.Module, names: set[str]) -> dict[str, str]:
    """``EXTERNAL_SIGNER_REQUIRED_ENV = "PROM_REQUIRE_EXTERNAL_SIGNER"``.

    Every reader in this repository names its variable through a constant like
    this, so a sweep that only understood string literals would see almost none
    of the real reads.
    """

    aliases = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            value = node.value.value
            if isinstance(value, str) and (
                value in names or _BOOLEAN_ENV_PATTERN.match(value)
            ):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        aliases[target.id] = value
    return aliases


def test_the_config_helper_really_delegates_to_the_one_parser():
    """``_env_bool`` is treated as strict by the sweep below, so that has to be
    true rather than assumed: a helper that stopped delegating would launder
    every read in ``core/config.py``."""

    source = inspect.getsource(_config_module._env_bool)
    assert "parse_env_bool(name, env.get(name), default=default)" in source, source


def test_no_boolean_security_setting_is_read_outside_the_strict_parser():
    """THE PROPERTY. Every read of a boolean security setting goes through
    ``core.booleans.parse_env_bool``, and nothing else reads one.

    WHAT THE PERMITTED SET IS OVER: the READ SITE — every ``env.get(NAME)``,
    ``os.getenv(NAME)`` and ``env[NAME]`` in the three checked trees, where NAME
    is a boolean setting by the wired-up list or by the naming convention. What
    varies is where and how somebody reads the variable, and every read is
    covered.

    WHAT CAN STILL VARY THAT THIS DOES NOT CONSTRAIN, stated rather than left to
    be found: a key that is neither a literal nor a module-level constant —
    ``os.environ.get(prefix + suffix)``, or a name passed in from a caller. The
    repository has no such read today (all thirty are literals or ``*_ENV``
    constants), and a reader written that way would be conspicuous next to the
    convention every other one follows; it is not caught here.
    """

    names = _boolean_env_names()
    assert len(names) >= 13, f"the derived name set collapsed to {sorted(names)}"

    offenders = []
    for root in ("src/prometheus_protocol", "scripts", "tests"):
        for path in sorted((REPO / root).rglob("*.py")):
            relative = path.relative_to(REPO)
            tree = ast.parse(path.read_text(encoding="utf-8"))
            aliases = _module_level_aliases(tree, names)
            parents = {
                child: node
                for node in ast.walk(tree)
                for child in ast.iter_child_nodes(node)
            }

            def setting_read(node: ast.AST) -> str | None:
                key = None
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("get", "getenv") and node.args:
                        key = node.args[0]
                elif isinstance(node, ast.Subscript):
                    key = node.slice
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    name = key.value
                elif isinstance(key, ast.Name):
                    name = aliases.get(key.id, "")
                else:
                    return None
                strict = name in names or bool(_BOOLEAN_ENV_PATTERN.match(name))
                return name if strict else None

            for node in ast.walk(tree):
                name = setting_read(node)
                if name is None:
                    continue
                enclosing = parents.get(node)
                through_parser = False
                while enclosing is not None:
                    if isinstance(enclosing, ast.Call):
                        function = enclosing.func
                        called = (
                            function.id if isinstance(function, ast.Name)
                            else function.attr if isinstance(function, ast.Attribute)
                            else ""
                        )
                        if called in _STRICT_CALLS:
                            through_parser = True
                            break
                    enclosing = parents.get(enclosing)
                if through_parser:
                    continue
                if f"{relative}::{ast.unparse(node)}" in _SANCTIONED_LOOSE_READS:
                    continue
                offenders.append(f"{relative}:{node.lineno} {ast.unparse(node)}")

    assert offenders == [], (
        f"boolean security setting read outside parse_env_bool at {offenders}. "
        "bool('false') is True and 'tru' is silently False — that is the "
        "fail-open pair this parser exists to stop, and it comes back the moment "
        "a setting is read any other way. Route the read through "
        "core.booleans.parse_env_bool. If the read genuinely is not a setting "
        "being consumed, sanction it in _SANCTIONED_LOOSE_READS by its exact "
        "source, with the reason."
    )


def test_ci_flag_misspelling_is_refused_at_import_of_a_gated_module(monkeypatch, tmp_path):
    """The gate helper each test module uses at import time: a misspelled
    value raises, so pytest reports a collection error, never a skip."""

    monkeypatch.setenv("PROM_REQUIRE_SANDBOX", "tru")
    import os

    with pytest.raises(ConfigError, match="PROM_REQUIRE_SANDBOX='tru'"):
        parse_env_bool("PROM_REQUIRE_SANDBOX", os.environ.get("PROM_REQUIRE_SANDBOX"), default=False)
    monkeypatch.setenv("PROM_REQUIRE_SANDBOX", "1")
    assert parse_env_bool("PROM_REQUIRE_SANDBOX", os.environ.get("PROM_REQUIRE_SANDBOX"), default=False) is True
