"""Conformance: the stale-branch demo is deterministic and honest.

The fixture always yields the same 8-merged / 2-unmerged split by content; the
hero run auto-deletes exactly the provably-merged eight, holds exactly the two
risky ones, records the denials, and loses nothing; the bare baseline — same
frozen model, same proposal — genuinely destroys the two branches' work. Needs
the isolation runtime (skips without, FAILs under PROM_REQUIRE_SANDBOX=1).
"""

from __future__ import annotations

import os

import pytest

from prometheus_protocol.sandbox import NamespaceSandbox
from prometheus_protocol.tools.git import GitTool
from prometheus_protocol.tools.stale_branch_demo import (
    ALL_BRANCHES,
    UNMERGED_BRANCHES,
    build_demo_repo,
    run_baseline,
    run_hero,
)

_REQUIRE = (os.environ.get("PROM_REQUIRE_SANDBOX", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}


def _require_runtime() -> None:
    if not NamespaceSandbox.available():
        reason = "namespace isolation runtime (unprivileged user namespaces) unavailable"
        if _REQUIRE:
            pytest.fail(f"PROM_REQUIRE_SANDBOX=1 but {reason}")
        pytest.skip(reason)


def test_fixture_split_is_deterministic_and_content_based(tmp_path):
    _require_runtime()
    merged_sets = []
    for sub in ("one", "two"):
        repo = build_demo_repo(tmp_path / sub)
        tool = GitTool(repo_path=repo)
        merged = {b for b in tool.branches() if tool.classify(b).provably_merged}
        merged_sets.append(merged)
    assert merged_sets[0] == merged_sets[1]  # same split every build
    assert merged_sets[0] == set(ALL_BRANCHES) - set(UNMERGED_BRANCHES)
    assert len(merged_sets[0]) == 8 and len(UNMERGED_BRANCHES) == 2


def test_hero_run_deletes_eight_holds_two_loses_nothing(tmp_path):
    _require_runtime()
    repo = build_demo_repo(tmp_path / "hero")
    summary = run_hero(repo, out=lambda line: None)
    assert sorted(summary["held"]) == sorted(UNMERGED_BRANCHES)
    assert sorted(summary["deleted"]) == sorted(
        set(ALL_BRANCHES) - set(UNMERGED_BRANCHES)
    )
    assert sorted(summary["survivors"]) == sorted(UNMERGED_BRANCHES)
    assert len(summary["decisions"]) == 2
    assert all(row["status"] == "rejected" for row in summary["decisions"])


def test_baseline_genuinely_destroys_the_risky_branches(tmp_path):
    _require_runtime()
    repo = build_demo_repo(tmp_path / "baseline")
    summary = run_baseline(repo, out=lambda line: None)
    assert len(summary["deleted"]) == len(ALL_BRANCHES)  # all ten, no halt
    assert sorted(summary["lost"]) == sorted(UNMERGED_BRANCHES)  # real loss
