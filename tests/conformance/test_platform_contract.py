"""The platform gate is itself proven, in both directions.

A skip that nobody has observed fire is a guard that cannot fail — the exact
shape this repository's own scanner reports (VG-1-001 aggregates skipif
conditions and says: "for capability probes, ensure at least one CI job provides
the capability and would FAIL (not skip) without it"). So the gate added for the
platform contract is exercised here on BOTH branches, on every platform, with no
skipping of its own.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from prometheus_protocol.core.errors import ConfigError
from tests.support import platform_gate
from tests.support.platform_gate import (
    REQUIRE_LINUX_ENV,
    is_linux,
    is_platform_refusal,
    require_linux,
)

REPO = Path(__file__).resolve().parents[2]


def test_the_declared_contract_is_linux_not_merely_posix():
    """``Operating System :: POSIX`` is satisfied by macOS, so it promised
    support this code does not deliver. The classifier has to name Linux."""

    data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    classifiers = data["project"]["classifiers"]
    assert "Operating System :: POSIX :: Linux" in classifiers
    assert "Operating System :: POSIX" not in classifiers, (
        "the bare POSIX classifier is back; macOS satisfies it and the chokepoint "
        "does not run there"
    )


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


def test_the_refusal_matcher_reads_the_cause_not_a_test_name():
    """The chokepoint hook keys on the diagnostic the PRODUCTION code emits."""

    assert is_platform_refusal(
        ConfigError("no filesystem probe is implemented for darwin")
    )
    assert is_platform_refusal(ConfigError("Linux O_PATH inspection is unavailable"))


def test_the_refusal_matcher_follows_a_chained_cause():
    """The refusal usually arrives wrapped. Matching only ``str(exc)`` of the
    outermost exception would miss it and leave the failure looking like a
    regression, which is the thing being fixed."""

    try:
        try:
            raise RuntimeError("no filesystem probe is implemented for darwin")
        except RuntimeError as inner:
            raise ConfigError("the store could not be verified") from inner
    except ConfigError as outer:
        assert is_platform_refusal(outer)


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
