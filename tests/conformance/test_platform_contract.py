"""The platform gate is itself proven, in both directions.

A skip that nobody has observed fire is a guard that cannot fail — the exact
shape this repository's own scanner reports (VG-1-001 aggregates skipif
conditions and says: "for capability probes, ensure at least one CI job provides
the capability and would FAIL (not skip) without it"). So the gate added for the
platform contract is exercised here on BOTH branches, on every platform, with no
skipping of its own.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from prometheus_protocol.core.errors import ConfigError
from tests.support import platform_gate
from prometheus_protocol.chokepoint.runner import _PlatformUnsupported
from prometheus_protocol.chokepoint.substrate import UnsupportedPlatform
from tests.support.platform_gate import (
    REQUIRE_LINUX_ENV,
    is_linux,
    is_platform_refusal,
    require_linux,
)

REPO = Path(__file__).resolve().parents[2]


def _declared_classifiers() -> list[str]:
    """The ``classifiers`` array from pyproject, without a TOML parser.

    ``tomllib`` is standard library only from 3.11 and this project supports
    3.10 (``requires-python = ">=3.10"``, and the CI matrix runs 3.10). An
    earlier version of this test imported it and broke the 3.10 build — a test
    asserting the PLATFORM contract that violated the PYTHON VERSION contract.
    Adding ``tomli`` as a runtime dependency for one assertion is out of
    proportion, and a tomllib/tomli fork would leave one branch unexercised on
    whichever interpreter ran, so this parses the one array it needs on every
    version identically.

    Comment lines are stripped FIRST, deliberately: the comment beside the
    classifier in pyproject quotes the old bare ``Operating System :: POSIX``
    string to explain why it was replaced, so a scan of the raw text would find
    the very value this test asserts is gone.
    """

    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    block = re.search(r"^classifiers\s*=\s*\[(.*?)^\]", text, re.S | re.M)
    assert block, "pyproject has no classifiers array to check"
    uncommented = "\n".join(
        line for line in block.group(1).splitlines() if not line.lstrip().startswith("#")
    )
    return re.findall(r'"([^"]*)"', uncommented)


def test_the_declared_contract_is_linux_not_merely_posix():
    """``Operating System :: POSIX`` is satisfied by macOS, so it promised
    support this code does not deliver. The classifier has to name Linux."""

    classifiers = _declared_classifiers()
    assert "Operating System :: POSIX :: Linux" in classifiers
    assert "Operating System :: POSIX" not in classifiers, (
        "the bare POSIX classifier is back; macOS satisfies it and the chokepoint "
        "does not run there"
    )


def test_the_classifier_reader_ignores_the_explanatory_comment():
    """The reader's own control. The comment in pyproject quotes the retired
    classifier, so a reader that did not strip comments would report it as
    still declared and this file's main assertion would fail for the wrong
    reason — or, with the polarity reversed, pass while the classifier was
    genuinely wrong."""

    raw = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert '"Operating System :: POSIX"' in raw, (
        "the comment that makes this control meaningful is gone; if the "
        "explanation was removed deliberately, remove this test with it"
    )
    assert "Operating System :: POSIX" not in _declared_classifiers()


def test_on_linux_the_gate_does_nothing(monkeypatch):
    """The positive control. On the supported platform the gate is transparent —
    it must not skip, fail, or raise."""

    monkeypatch.setattr(platform_gate.sys, "platform", "linux")
    assert is_linux() is True
    require_linux()  # must simply return


def test_off_linux_the_gate_skips_with_a_reason(monkeypatch):
    """The developer-machine branch: a platform mismatch is a SKIP that says so,
    not a failure indistinguishable from a regression."""

    monkeypatch.setattr(platform_gate.sys, "platform", "darwin")
    monkeypatch.delenv(REQUIRE_LINUX_ENV, raising=False)
    assert is_linux() is False
    with pytest.raises(Skipped) as raised:
        require_linux()
    assert "requires Linux" in str(raised.value)
    assert "darwin" in str(raised.value)


def test_off_linux_under_the_ci_flag_the_gate_FAILS(monkeypatch):
    """The CI branch, and the reason this is not a guard that cannot fail. CI
    sets PROM_REQUIRE_LINUX=1; under it a gated test that cannot run is a
    failure, so the gate is never a silent no-op where Linux was promised."""

    monkeypatch.setattr(platform_gate.sys, "platform", "darwin")
    monkeypatch.setenv(REQUIRE_LINUX_ENV, "1")
    with pytest.raises(Failed) as raised:
        require_linux()
    assert REQUIRE_LINUX_ENV in str(raised.value)


def test_the_flag_is_parsed_strictly_not_truthily(monkeypatch):
    """It goes through ``parse_env_bool``, so a typo is refused rather than
    silently read as false — which would disarm the CI branch above."""

    monkeypatch.setattr(platform_gate.sys, "platform", "darwin")
    monkeypatch.setenv(REQUIRE_LINUX_ENV, "yes-please")
    with pytest.raises(ConfigError):
        require_linux()


def test_the_refusal_matcher_keys_on_a_TYPE_not_on_wording():
    """The hook keys on the type the production code raises.

    The wording is deliberately nonsense here: a matcher that recognised the
    refusal by its diagnostic text would not see this, and a matcher that
    recognises it by type does. That is the property being asserted — a
    reworded diagnostic must not silently drop a case out of the cause set.
    """

    assert is_platform_refusal(UnsupportedPlatform("wording entirely changed"))
    assert is_platform_refusal(_PlatformUnsupported("also reworded"))


def test_the_typed_refusal_is_still_a_ConfigError():
    """Subclass, not replacement: every existing handler keeps working."""

    assert issubclass(UnsupportedPlatform, ConfigError)


def test_the_old_diagnostic_TEXT_alone_is_no_longer_sufficient():
    """The negative that proves the conversion actually happened.

    A plain ConfigError carrying the exact former marker string is NOT a
    platform refusal any more. If this passes while the matcher is still
    text-based, it fails — which is what makes it a check rather than a claim.
    """

    assert not is_platform_refusal(
        ConfigError("no filesystem probe is implemented for darwin")
    )


def test_an_assertion_whose_MESSAGE_quotes_the_marker_is_not_converted():
    """The control that was missing, and the defect it now pins.

    The first version of this gate matched substrings of the probe's
    diagnostics. pytest rewrites assertions to include the repr of both
    operands, and the repr of a refused ``MigrationResult`` carries
    ``detail='execution ownership unavailable: _PlatformUnsupported'``. So a
    GENUINE assertion failure — a test asserting an execution outcome that the
    refusal made impossible — arrived carrying the marker in its message, and
    the matcher converted it to a skip.

    Measured: 9 real failures were being skipped that way, hidden inside a
    conversion that looked like it was only reclassifying platform refusals. A
    type cannot appear in a message by accident.
    """

    quoted = (
        "assert (not False and None == 'execution_unknown')\n"
        " +  where False = MigrationResult(executed=False, refused=True, "
        "reason='approval_store_unavailable', "
        "detail='execution ownership unavailable: _PlatformUnsupported', "
        "audit_recorded=True).executed"
    )
    assert not is_platform_refusal(AssertionError(quoted))


def test_the_refusal_matcher_follows_a_chained_cause():
    """The refusal usually arrives wrapped. Testing only the outermost
    exception would miss it and leave the failure looking like a regression,
    which is the thing being fixed."""

    try:
        try:
            raise UnsupportedPlatform("no probe here")
        except UnsupportedPlatform as inner:
            raise ConfigError("the store could not be verified") from inner
    except ConfigError as outer:
        assert is_platform_refusal(outer)


def test_the_matcher_terminates_on_a_cause_cycle():
    """Bounded walk. A self-referential cause must not hang the test run."""

    a = ConfigError("a")
    b = ConfigError("b")
    a.__cause__ = b
    b.__cause__ = a
    assert is_platform_refusal(a) is False


def test_an_ordinary_misconfiguration_is_NEVER_converted_to_a_skip():
    """The negative control for the matcher, and the one that matters: a real
    ConfigError must keep failing. A matcher that swallowed those would hide
    exactly the regressions this contract exists to keep visible."""

    assert not is_platform_refusal(ConfigError("ledger_anchor is required"))
    assert not is_platform_refusal(ValueError("unknown profile 'typo'"))
    assert not is_platform_refusal(AssertionError("expected 3 rows, got 2"))


# ``pytest.skip``/``pytest.fail`` raise private exception types; bind them once
# here rather than reaching into ``_pytest`` at each call site.
Skipped = pytest.skip.Exception
Failed = pytest.fail.Exception
