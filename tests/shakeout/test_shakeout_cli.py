"""Shakeout repro for F1 — RED BY DESIGN.

The CLI surfaces known errors (e.g. a remote provider with no endpoint) as raw
Python tracebacks instead of a clean message + non-zero exit. This test asserts
the *desired* behaviour and is expected to fail until the CLI catches known
errors. See ``docs/shakeout-report.md`` (F1).
"""

from __future__ import annotations

import pytest

from prometheus_protocol.cli.main import main


@pytest.mark.xfail(
    strict=True,
    reason="F1: CLI lets exceptions propagate as tracebacks; should print a clean "
    "error and return a non-zero exit code",
)
def test_cli_reports_provider_misconfig_cleanly(monkeypatch, tmp_path):
    monkeypatch.setenv("PROM_PROVIDER", "remote")  # remote provider...
    monkeypatch.delenv("PROM_API_BASE", raising=False)  # ...but no endpoint
    monkeypatch.delenv("PROM_MODEL", raising=False)
    # Keep all state ephemeral so the probe has no filesystem side effects.
    monkeypatch.setenv("PROM_LEDGER_PATH", ":memory:")
    monkeypatch.setenv("PROM_TRUST_STORE_PATH", ":memory:")
    monkeypatch.setenv("PROM_REGISTRY_DIR", str(tmp_path / "skills"))

    # Desired: a clean non-zero return, not a raised exception.
    assert main(["baseline"]) == 1
