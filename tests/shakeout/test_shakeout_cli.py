"""Operability coverage for the CLI boundary.

Originally an F1 repro (RED by design); now green. The CLI surfaces known
errors as a clean ``error: <message>`` line with a non-zero exit instead of a
raw Python traceback, exposes a read-only ``status`` view (F4), and emits
lifecycle logs under ``-v`` (F5). See ``docs/shakeout-report.md`` (F1/F4/F5).
"""

from __future__ import annotations

import logging

import pytest

from prometheus_protocol.cli.main import main


def _ephemeral_env(monkeypatch, tmp_path):
    """Keep all state ephemeral so a probe has no filesystem side effects."""

    monkeypatch.setenv("PROM_LEDGER_PATH", ":memory:")
    monkeypatch.setenv("PROM_TRUST_STORE_PATH", ":memory:")
    monkeypatch.setenv("PROM_REGISTRY_DIR", str(tmp_path / "skills"))


# --- F1: known errors are reported cleanly --------------------------------


def test_cli_reports_provider_misconfig_cleanly(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("PROM_PROVIDER", "remote")  # remote provider...
    monkeypatch.delenv("PROM_API_BASE", raising=False)  # ...but no endpoint
    monkeypatch.delenv("PROM_MODEL", raising=False)
    _ephemeral_env(monkeypatch, tmp_path)

    # A clean non-zero return, not a raised exception.
    assert main(["baseline"]) == 1

    captured = capsys.readouterr()
    # One actionable line on stderr, no traceback.
    assert "error:" in captured.err
    assert "api_base" in captured.err
    assert "Traceback" not in captured.err


# --- F4: a read-only status view ------------------------------------------


def test_status_on_empty_state_is_graceful(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("PROM_PROVIDER", "mock")
    # Point at paths that do not exist yet; status must not create them.
    ledger = tmp_path / "state" / "ledger.db"
    trust = tmp_path / "state" / "trust.db"
    skills = tmp_path / "state" / "skills"
    monkeypatch.setenv("PROM_LEDGER_PATH", str(ledger))
    monkeypatch.setenv("PROM_TRUST_STORE_PATH", str(trust))
    monkeypatch.setenv("PROM_REGISTRY_DIR", str(skills))

    assert main(["status"]) == 0

    out = capsys.readouterr().out
    assert "status" in out
    assert "no trust store yet" in out
    # Read-only: it created none of the configured state.
    assert not ledger.exists()
    assert not trust.exists()
    assert not skills.exists()


def test_status_renders_ranking_and_skills_after_a_cycle(monkeypatch, tmp_path, capsys):
    state = tmp_path / "state"
    monkeypatch.setenv("PROM_PROVIDER", "mock")
    monkeypatch.setenv("PROM_LEDGER_PATH", str(state / "ledger.db"))
    monkeypatch.setenv("PROM_TRUST_STORE_PATH", str(state / "trust.db"))
    monkeypatch.setenv("PROM_REGISTRY_DIR", str(state / "skills"))
    monkeypatch.setenv("PROM_VERIFIER_MEMORY_MB", "0")

    assert main(["cycle"]) == 0  # populate the trust store + registry
    capsys.readouterr()  # discard cycle output

    assert main(["status"]) == 0
    out = capsys.readouterr().out
    # The hard verifier appears in the ranking with calibration samples...
    assert "subprocess-tests" in out
    assert "reliability=" in out
    assert "samples=" in out
    # ...and the promoted skill is listed.
    assert "skill-empty-input" in out


# --- F5: lifecycle logging under -v ---------------------------------------


def test_verbose_flag_emits_lifecycle_logs(monkeypatch, tmp_path, caplog):
    monkeypatch.setenv("PROM_PROVIDER", "mock")
    _ephemeral_env(monkeypatch, tmp_path)

    with caplog.at_level(logging.INFO, logger="prometheus_protocol"):
        assert main(["-v", "baseline"]) == 0

    records = [r for r in caplog.records if r.name.startswith("prometheus_protocol")]
    assert records  # at least one lifecycle record
    assert any("run" in r.getMessage() for r in records)


def test_default_verbosity_is_quiet(monkeypatch, tmp_path, caplog):
    monkeypatch.setenv("PROM_PROVIDER", "mock")
    _ephemeral_env(monkeypatch, tmp_path)

    # No -v and no PROM_LOG_LEVEL: the package logger sits at WARNING, so no
    # INFO lifecycle records are emitted.
    monkeypatch.delenv("PROM_LOG_LEVEL", raising=False)
    caplog.set_level(logging.INFO, logger="prometheus_protocol")
    assert main(["baseline"]) == 0
    infos = [
        r
        for r in caplog.records
        if r.name.startswith("prometheus_protocol") and r.levelno == logging.INFO
    ]
    assert infos == []
