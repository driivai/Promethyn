"""Fixture suite: one synthetic repo per detection rule.

Every rule is tested BOTH ways: the known-void guard must be flagged, and the
known-live guard must NOT be — a noisy scanner gets uninstalled in a day, so
false-positive tests carry the same weight as true-positive ones.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from voidguard import cli, engine
from voidguard.model import UNKNOWN, VOID, WARN

FIXTURES = Path(__file__).parent / "fixtures"


def scan(sub: str, probe=None):
    return engine.scan(str(FIXTURES / sub), schedule_probe=probe)


def by_rule(result, rule: str):
    return [f for f in result.findings if f.rule == rule]


# -- meta: no verdict without its enumerated evidence ------------------------------


def test_every_finding_carries_evidence_and_search_set():
    for sub in sorted(p.relative_to(FIXTURES) for p in FIXTURES.glob("*/*")):
        result = scan(str(sub))
        for f in result.findings:
            assert f.evidence.summary, f"{sub}: {f.id} has no evidence summary"
            assert f.evidence.searched, f"{sub}: {f.id} enumerates no search set"
            assert f.question and f.fix, f"{sub}: {f.id} missing question/fix"


# -- class 1 ------------------------------------------------------------------------


def test_r1a_void_env_gate_is_flagged():
    result = scan("r1a_env_skip/void")
    hits = by_rule(result, "R1a")
    voids = [f for f in hits if f.verdict == VOID]
    warns = [f for f in hits if f.verdict == WARN]
    assert any("NEVER_SET_FLAG" in f.mechanism for f in voids), result.findings
    # documented-only flag is WARN, not VOID (no executable path sets it)
    assert any("DOC_ONLY_FLAG" in f.mechanism for f in warns), result.findings
    void = next(f for f in voids if "NEVER_SET_FLAG" in f.mechanism)
    assert "0 of 1 workflows" in void.evidence.summary
    assert any("ci.yml" in s for s in void.evidence.searched)


def test_r1a_live_env_gate_is_not_flagged():
    result = scan("r1a_env_skip/live")
    hits = [f for f in by_rule(result, "R1a") if f.verdict != "UNKNOWN"]
    # covers BOTH live shapes: a flag set in a workflow, and a platform-provided
    # var (CI) that GitHub sets on every run without any repo file setting it —
    # the exact false positive measured on a large public repo during v0
    assert not hits, [f.to_dict() for f in hits]


def test_r1b_stale_unconditional_skip_flagged_and_fresh_not(tmp_path):
    def make_repo(days_ago: int) -> Path:
        root = tmp_path / f"repo_{days_ago}"
        (root / "tests").mkdir(parents=True)
        (root / "tests" / "test_old.py").write_text(
            "import pytest\n\n\n"
            "@pytest.mark.skip(reason='temporarily disabled')\n"
            "def test_disabled():\n    assert True\n",
            encoding="utf-8",
        )
        env = dict(os.environ)
        stamp = f"{int(time.time()) - days_ago * 86400} +0000"
        env.update({
            "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp,
            "GIT_AUTHOR_NAME": "fx", "GIT_AUTHOR_EMAIL": "fx@example.invalid",
            "GIT_COMMITTER_NAME": "fx", "GIT_COMMITTER_EMAIL": "fx@example.invalid",
        })
        ident = ["-c", "user.name=fx", "-c", "user.email=fx@example.invalid",
                 "-c", "commit.gpgsign=false"]
        for cmd in (["git", *ident, "init", "-q"], ["git", *ident, "add", "."],
                    ["git", *ident, "commit", "-qm", "fixture"]):
            proc = subprocess.run(cmd, cwd=root, env=env, capture_output=True, text=True)
            assert proc.returncode == 0, proc.stderr
        return root

    stale = engine.scan(str(make_repo(400)))
    assert any(f.rule == "R1b" and f.verdict == WARN for f in stale.findings), \
        [f.to_dict() for f in stale.findings]

    fresh = engine.scan(str(make_repo(2)))
    assert not [f for f in fresh.findings if f.rule == "R1b"]


def test_r1c_marker_excluded_everywhere_is_void_in_ci():
    result = scan("r1c_marker/void")
    hits = by_rule(result, "R1c")
    assert len(hits) == 1 and hits[0].verdict == VOID
    assert "slow" in hits[0].mechanism
    assert "unit" not in hits[0].mechanism  # 'unit' runs via "not slow"


def test_r1c_marker_with_a_selecting_job_is_not_flagged():
    result = scan("r1c_marker/live")
    assert not by_rule(result, "R1c"), [f.to_dict() for f in by_rule(result, "R1c")]


def test_r1d_polyglot_void_and_live():
    void = scan("r1d_polyglot/void")
    assert any(f.rule == "R1d-go" and "CLUSTER_FLAG" in f.mechanism for f in void.findings)
    assert any(f.rule == "R1d-rs" and f.verdict == WARN for f in void.findings)
    assert any(f.rule == "R1d-js" and f.verdict == WARN for f in void.findings)
    live = scan("r1d_polyglot/live")
    assert not [f for f in live.findings if f.rule.startswith("R1d")], \
        [f.to_dict() for f in live.findings]


# -- class 2 ------------------------------------------------------------------------


def test_r2a_vacuous_mypy_resolution_is_void():
    result = scan("r2a_mypy/void")
    hits = by_rule(result, "R2a")
    assert len(hits) == 1 and hits[0].verdict == VOID, \
        [f.to_dict() for f in result.findings]
    assert "ignore_missing_imports" in hits[0].mechanism


def test_r2a_configured_resolution_is_not_flagged():
    assert not by_rule(scan("r2a_mypy/live"), "R2a")


def test_r2a_flat_layout_is_not_flagged():
    # flat layout resolves from the cwd: flagging it would be a false positive
    assert not by_rule(scan("r2a_mypy/flat"), "R2a")


def test_r2b_follow_imports_skip_is_void_and_live_is_clean():
    hits = by_rule(scan("r2b_scope/void"), "R2b")
    assert len(hits) == 1 and hits[0].verdict == VOID
    assert not by_rule(scan("r2b_scope/live"), "R2b")


def test_r2c_dead_target_is_void_and_existing_target_is_clean():
    hits = by_rule(scan("r2c_target/void"), "R2c")
    assert len(hits) == 1 and hits[0].verdict == VOID
    assert "renamed_pkg" in hits[0].evidence.summary
    assert not by_rule(scan("r2c_target/live"), "R2c")


def test_r2d_weak_tsconfig_is_warn_not_void_and_strict_is_clean():
    hits = by_rule(scan("r2d_tsconfig/void"), "R2d")
    assert len(hits) == 1 and hits[0].verdict == WARN  # precision: weak, not void
    assert not by_rule(scan("r2d_tsconfig/live"), "R2d")


# -- class 3 ------------------------------------------------------------------------


def test_r3a_isolated_interpreter_drops_python_env():
    result = scan("r3a_isolated/void")
    hits = by_rule(result, "R3a")
    workflow_voids = [f for f in hits if f.verdict == VOID and "ci.yml" in f.guard]
    docker_voids = [f for f in hits if f.verdict == VOID and "Dockerfile" in f.guard]
    code_warns = [f for f in hits if f.verdict == WARN and "launch.py" in f.guard]
    assert workflow_voids and "PYTHONDONTWRITEBYTECODE" in workflow_voids[0].guard
    assert docker_voids and "PYTHONHASHSEED" in docker_voids[0].guard
    assert code_warns, [f.to_dict() for f in hits]  # same-file heuristic stays WARN


def test_r3a_non_isolated_invocation_is_not_flagged():
    assert not by_rule(scan("r3a_isolated/live"), "R3a")


def test_r3b_unread_env_is_warn_and_read_env_is_clean():
    hits = by_rule(scan("r3b_unread/void"), "R3b")
    assert len(hits) == 1 and hits[0].verdict == WARN
    assert "LEGACY_TUNING_KNOB" in hits[0].guard
    assert not by_rule(scan("r3b_unread/live"), "R3b")


def test_r3c_arg_after_from_is_void_and_redeclared_is_clean():
    hits = by_rule(scan("r3c_dockerarg/void"), "R3c")
    assert len(hits) == 1 and hits[0].verdict == VOID
    assert "APP_VERSION" in hits[0].guard
    assert not by_rule(scan("r3c_dockerarg/live"), "R3c")


# -- class 4 ------------------------------------------------------------------------


def test_r4a_impossible_event_is_void_and_secret_condition_is_unknown():
    result = scan("r4a_event/void")
    hits = by_rule(result, "R4a")
    assert any(f.verdict == VOID and "workflow_dispatch" in f.mechanism for f in hits)
    assert any(f.verdict == UNKNOWN and "secret" in f.mechanism for f in hits)


def test_r4a_possible_event_is_not_flagged():
    hits = by_rule(scan("r4a_event/live"), "R4a")
    assert not [f for f in hits if f.verdict == VOID], [f.to_dict() for f in hits]


def test_r4b_schedule_static_unknown_api_warn_and_on_record_clean():
    static = scan("r4b_schedule/void")
    assert any(f.rule == "R4b" and f.verdict == UNKNOWN for f in static.findings)

    never_ran = scan("r4b_schedule/void", probe=lambda basename: 0)
    warns = [f for f in never_ran.findings if f.rule == "R4b"]
    assert len(warns) == 1 and warns[0].verdict == WARN
    assert "not yet on the record" in warns[0].evidence.summary

    on_record = scan("r4b_schedule/void", probe=lambda basename: 7)
    assert not [f for f in on_record.findings if f.rule == "R4b"]


def test_r4d_missing_golden_is_void_and_present_golden_is_clean():
    hits = by_rule(scan("r4d_golden/void"), "R4d")
    assert len(hits) == 1 and hits[0].verdict == VOID
    assert "docs/expected-report.md" in hits[0].mechanism
    assert not by_rule(scan("r4d_golden/live"), "R4d")


# -- CLI contract ---------------------------------------------------------------------


def test_cli_exit_codes_and_json(tmp_path, capsys):
    out = tmp_path / "report.json"
    rc = cli.main(["scan", str(FIXTURES / "r1a_env_skip" / "void"),
                   "--json", str(out)])
    assert rc == 1  # findings exist
    data = json.loads(out.read_text())
    assert data["counts"]["VOID"] >= 1
    assert all(f["evidence"]["searched"] for f in data["findings"])
    human = capsys.readouterr().out
    assert "never been observed to fail." in human.splitlines()[0]

    rc_clean = cli.main(["scan", str(FIXTURES / "r4d_golden" / "live")])
    assert rc_clean == 0


def test_cli_baseline_ratchet(tmp_path, capsys):
    target = str(FIXTURES / "r1a_env_skip" / "void")
    base = tmp_path / "baseline.json"
    assert cli.main(["baseline", target, "-o", str(base)]) == 0
    # with every current finding acknowledged, the scan is clean (exit 0)
    assert cli.main(["scan", target, "--baseline", str(base)]) == 0
    out = capsys.readouterr().out
    assert "suppressed" in out


def test_cli_fail_on_thresholds():
    target = str(FIXTURES / "r2d_tsconfig" / "void")  # WARN-only fixture
    assert cli.main(["scan", target, "--fail-on", "any"]) == 1
    assert cli.main(["scan", target, "--fail-on", "void"]) == 0
    assert cli.main(["scan", target, "--fail-on", "never"]) == 0
