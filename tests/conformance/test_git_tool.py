"""Conformance: the git connector rides every existing execution safeguard.

The delete op is destructive and irreversible, so the invariants are the
INV-EXEC family applied to the first external tool: a branch that is not
provably merged NEVER auto-deletes (it halts for a human), a human denial is
recorded and the branch survives, a dry-run mutates nothing, execution is
fail-closed without isolation, and classification is the real content-diff —
never a name heuristic. These tests need the namespace isolation runtime (the
merge check and the delete run in the sandbox): they SKIP without it and FAIL
under PROM_REQUIRE_SANDBOX=1, so green CI proves them under real isolation.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from prometheus_protocol.core.models import ACTION_PYTHON_CODE, ExecutableAction
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.executor import SandboxExecutor
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import OUTCOME_APPROVE, OUTCOME_ROUTE
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.sandbox import NamespaceSandbox
from prometheus_protocol.sandbox.unsafe import NullSandbox
from prometheus_protocol.tools.git import (
    GitBranchDeleteExecutor,
    GitTool,
    judgment_for,
)

_REQUIRE = (os.environ.get("PROM_REQUIRE_SANDBOX", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}

_FIXED_ENV = {
    **os.environ,
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
}


def _sandbox() -> NamespaceSandbox:
    if not NamespaceSandbox.available():
        reason = "namespace isolation runtime (unprivileged user namespaces) unavailable"
        if _REQUIRE:
            pytest.fail(f"PROM_REQUIRE_SANDBOX=1 but {reason}")
        pytest.skip(reason)
    return NamespaceSandbox()


def _git(repo, *args) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=fixture@example.invalid",
         "-c", "user.name=fixture", *args],
        check=True, capture_output=True, text=True, env=_FIXED_ENV,
    ).stdout


def _make_repo(path) -> None:
    """A tiny deterministic repo: names deliberately lie about mergedness.

    ``risky-experiment`` is FULLY merged (only its name looks scary);
    ``merged-cleanup`` carries a commit NOT on main (only its name looks safe).
    Classification must come from the content-diff, never the name.
    """

    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(path), "-c", "init.defaultBranch=main", "init", "-q"],
                   check=True, env=_FIXED_ENV)
    _git(path, "commit", "-q", "--allow-empty", "-m", "base")
    # Fully merged: branch, commit, merge back into main.
    _git(path, "checkout", "-q", "-b", "risky-experiment")
    (path / "a.txt").write_text("a\n", encoding="utf-8")
    _git(path, "add", "a.txt")
    _git(path, "commit", "-q", "-m", "work")
    _git(path, "checkout", "-q", "main")
    _git(path, "merge", "-q", "--no-ff", "-m", "merge", "risky-experiment")
    # Unmerged: branch with a commit main never received.
    _git(path, "checkout", "-q", "-b", "merged-cleanup")
    (path / "b.txt").write_text("b\n", encoding="utf-8")
    _git(path, "add", "b.txt")
    _git(path, "commit", "-q", "-m", "unmerged work")
    _git(path, "checkout", "-q", "main")


def _branches(repo) -> set[str]:
    out = _git(repo, "for-each-ref", "refs/heads", "--format=%(refname:short)")
    return {line.strip() for line in out.splitlines() if line.strip()}


def _controller(repo, sandbox) -> ExecutionController:
    return ExecutionController(
        gate=ActionGate(escalate_below=0.75, route_high_risk=True),
        executor=GitBranchDeleteExecutor(repo_path=repo, sandbox=sandbox),
        ledger=SqliteLedger(":memory:"),
    )


def _submit(controller, tool, branch):
    judgment, risk = judgment_for(tool.classify(branch))
    return controller.submit(
        judgment=judgment,
        action=tool.delete_action(branch),
        risk_class=risk,
        subject_id=f"delete-branch:{branch}",
    )


# -- classification is the real content-diff, never a name heuristic ---------


def test_classification_is_content_based(tmp_path):
    sandbox = _sandbox()
    _make_repo(tmp_path)
    tool = GitTool(repo_path=tmp_path, sandbox=sandbox)
    scary_name = tool.classify("risky-experiment")
    safe_name = tool.classify("merged-cleanup")
    assert scary_name.provably_merged and scary_name.unmerged_commits == 0
    assert not safe_name.provably_merged and safe_name.unmerged_commits == 1


def test_unknown_or_unsafe_branch_is_never_provably_merged(tmp_path):
    sandbox = _sandbox()
    _make_repo(tmp_path)
    tool = GitTool(repo_path=tmp_path, sandbox=sandbox)
    assert tool.classify("does-not-exist").unmerged_commits is None
    assert tool.classify("-rf").unmerged_commits is None  # option-shaped: refused
    # Fail-closed classification: a check that cannot run is high risk.
    _, risk = judgment_for(tool.classify("does-not-exist"))
    assert risk == "high"


# -- INV: a not-merged branch NEVER auto-deletes ------------------------------


def test_inv_not_merged_branch_halts_for_a_human(tmp_path):
    sandbox = _sandbox()
    _make_repo(tmp_path)
    tool = GitTool(repo_path=tmp_path, sandbox=sandbox)
    controller = _controller(tmp_path, sandbox)

    outcome = _submit(controller, tool, "merged-cleanup")
    assert outcome.outcome == OUTCOME_ROUTE
    assert outcome.execution is None and outcome.pending is not None
    assert "merged-cleanup" in _branches(tmp_path)  # nothing happened
    held = controller.list_pending()
    assert [p.id for p in held] == [outcome.pending.id]


def test_inv_merged_branch_is_eligible_for_auto_approval(tmp_path):
    sandbox = _sandbox()
    _make_repo(tmp_path)
    tool = GitTool(repo_path=tmp_path, sandbox=sandbox)
    controller = _controller(tmp_path, sandbox)

    outcome = _submit(controller, tool, "risky-experiment")
    assert outcome.outcome == OUTCOME_APPROVE
    assert outcome.execution is not None and not outcome.execution.refused


def test_inv_denied_hold_never_deletes_and_the_decision_is_recorded(tmp_path):
    sandbox = _sandbox()
    _make_repo(tmp_path)
    tool = GitTool(repo_path=tmp_path, sandbox=sandbox)
    ledger = SqliteLedger(":memory:")
    controller = ExecutionController(
        gate=ActionGate(escalate_below=0.75, route_high_risk=True),
        executor=GitBranchDeleteExecutor(repo_path=tmp_path, sandbox=sandbox),
        ledger=ledger,
    )
    outcome = _submit(controller, tool, "merged-cleanup")
    controller.reject(
        outcome.pending.id,
        identity="reviewer",
        reason="carries unmerged work",
    )
    assert "merged-cleanup" in _branches(tmp_path)  # survived
    decisions = ledger.human_decisions()
    assert len(decisions) == 1
    assert decisions[0]["decided_by"] == "reviewer"
    assert decisions[0]["status"] == "rejected"
    # And a rejected hold cannot be driven to execution afterwards.
    with pytest.raises(ValueError):
        controller.approve(outcome.pending.id, identity="reviewer")


# -- Phase 1: the delete op is a dry-run and mutates nothing ------------------


def test_dry_run_records_intent_and_performs_no_git_mutation(tmp_path):
    sandbox = _sandbox()
    _make_repo(tmp_path)
    tool = GitTool(repo_path=tmp_path, sandbox=sandbox)
    controller = _controller(tmp_path, sandbox)
    before = _branches(tmp_path)

    outcome = _submit(controller, tool, "risky-experiment")
    assert outcome.outcome == OUTCOME_APPROVE
    assert not outcome.execution.executed and not outcome.execution.refused
    assert "would delete branch 'risky-experiment'" in outcome.execution.detail
    assert _branches(tmp_path) == before  # zero mutation


# -- the wall and the base-branch guard ---------------------------------------


def test_wall_raw_actions_and_unapproved_decisions_cannot_execute(tmp_path):
    sandbox = _sandbox()
    _make_repo(tmp_path)
    executor = GitBranchDeleteExecutor(repo_path=tmp_path, sandbox=sandbox)
    with pytest.raises(TypeError):
        executor.execute(ExecutableAction(kind=ACTION_PYTHON_CODE, code="pass"))
    tool = GitTool(repo_path=tmp_path, sandbox=sandbox)
    judgment, risk = judgment_for(tool.classify("merged-cleanup"))
    routed = ActionGate(escalate_below=0.75, route_high_risk=True).decide(
        judgment, risk_class=risk, action=tool.delete_action("merged-cleanup")
    )
    assert not routed.approved
    with pytest.raises(ValueError):
        executor.execute(routed)


def test_base_branch_is_refused_even_when_approved(tmp_path):
    sandbox = _sandbox()
    _make_repo(tmp_path)
    executor = GitBranchDeleteExecutor(repo_path=tmp_path, sandbox=sandbox)
    gate = ActionGate()  # bare authorizer: approve a (mis)judged main-delete
    from prometheus_protocol.core.models import Judgment, Verdict

    approved = gate.decide(
        Judgment(verdict=Verdict.PASS, confidence=1.0, authoritative=True),
        risk_class="low",
        action=GitTool(repo_path=tmp_path, sandbox=sandbox).delete_action("main"),
    )
    assert approved.approved
    result = executor.execute(approved)
    assert result.refused and "base branch" in result.detail
    assert "main" in _branches(tmp_path)


# -- regression: the in-sandbox code executor refuses the git kind ------------


def test_sandbox_executor_still_refuses_the_git_kind(tmp_path):
    sandbox = _sandbox()
    _make_repo(tmp_path)
    tool = GitTool(repo_path=tmp_path, sandbox=sandbox)
    judgment, _ = judgment_for(tool.classify("risky-experiment"))
    decision = ActionGate().decide(
        judgment, risk_class="low", action=tool.delete_action("risky-experiment")
    )
    assert decision.approved
    result = SandboxExecutor(sandbox=sandbox).execute(decision)
    assert result.refused and "unsupported action kind" in result.detail
    assert "risky-experiment" in _branches(tmp_path)
