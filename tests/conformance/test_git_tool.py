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

from prometheus_protocol.core.booleans import parse_env_bool
from prometheus_protocol.core.models import ACTION_PYTHON_CODE, ExecutableAction
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.executor import SandboxExecutor
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import (
    OUTCOME_APPROVE,
    OUTCOME_BLOCK,
    OUTCOME_ROUTE,
)
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.sandbox import NamespaceSandbox
from prometheus_protocol.sandbox.unsafe import NullSandbox
from prometheus_protocol.tools.git import (
    GitBranchDeleteExecutor,
    GitTool,
    evidence_for,
    risk_class_for,
)

from prometheus_protocol.core.models import Tier
from prometheus_protocol.policy.coverage import BoundResult
from prometheus_protocol.policy.profile import CHECK_MERGE_PROOF, DEFAULT_PROFILE_ID, load_profile
from prometheus_protocol.policy.resolver import resolve
from prometheus_protocol.policy.snapshot import ACTION_BRANCH_DELETE, snapshot_digest
from prometheus_protocol.swarm.models import content_hash
from prometheus_protocol.tools.git import MERGE_CHECK_VERIFIER_ID
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.store import InMemoryTrustStore

_REQUIRE = parse_env_bool("PROM_REQUIRE_SANDBOX", os.environ.get("PROM_REQUIRE_SANDBOX"), default=False)

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




def _assessment(tool, branch):
    """The REAL path: policy -> snapshot -> bound merge-check result -> assess.

    PHASE-1.2b. These tests used ``judgment_for``, which handed an unbound
    authoritative Judgment straight to the gate. The git tool now reports
    evidence and the bank produces the verdict, so the tests drive that.
    """

    snapshot = resolve(
        load_profile(DEFAULT_PROFILE_ID),
        artifact_sha256=content_hash(branch),
        target_canonical=f"git://{tool.repo_path}",
        action_class=ACTION_BRANCH_DELETE,
        attempt_id=f"delete-branch:{branch}",
    )
    bank = VerifierBank(InMemoryTrustStore())
    bank.register(MERGE_CHECK_VERIFIER_ID, Tier.HARD)
    return bank.assess(snapshot, [BoundResult(
        check_id=CHECK_MERGE_PROOF,
        snapshot_digest=snapshot_digest(snapshot),
        implementation=MERGE_CHECK_VERIFIER_ID,
        outcome=evidence_for(tool.classify(branch)),
    )])

def _submit(controller, tool, branch, risk=None):
    """``risk=None`` uses the tool's own classification.

    PHASE-1.2b — the hold tests below pass ``risk="high"`` on a branch whose
    merge proof SUCCEEDS. That is deliberate and it separates two controls that
    used to be tangled: the policy decides whether the requirement is met, the
    risk class decides how much confidence an allowed action needs. Holding a
    fully-satisfied delete for a human is a real deployment choice; it is no
    longer the only thing standing between an unproven delete and the executor.
    """

    return controller.submit(
        assessment=_assessment(tool, branch),
        action=tool.delete_action(branch),
        risk_class=risk if risk is not None else risk_class_for(tool.classify(branch)),
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
    assert risk_class_for(tool.classify("does-not-exist")) == "high"


# -- INV: a not-merged branch NEVER auto-deletes ------------------------------


def test_inv_not_merged_branch_is_refused_by_policy(tmp_path):
    """PHASE-1.2b CHANGED THIS ROW, and the change is a tightening.

    It used to HALT for a human: the merge check returned an authoritative PASS
    at confidence 0.0 and the HIGH risk class routed it. That judgment was
    unbound — no policy, no coverage — and a verdict-shaped object saying "pass"
    while meaning "do not do this" is the substitution the coverage layer exists
    to end.

    Now the policy REQUIRES ``branch.merge_proof`` for a delete, an unmerged
    branch FAILS that check, coverage refuses as unsatisfactory, and the gate
    blocks. Nothing executes and nothing is held, one decision earlier. The
    branch survives either way; what changed is that it survives because a
    requirement was unmet rather than because a risk heuristic routed it.
    """

    sandbox = _sandbox()
    _make_repo(tmp_path)
    tool = GitTool(repo_path=tmp_path, sandbox=sandbox)
    controller = _controller(tmp_path, sandbox)

    outcome = _submit(controller, tool, "merged-cleanup")
    assert outcome.outcome == OUTCOME_BLOCK
    assert outcome.execution is None and outcome.pending is None
    assert "merged-cleanup" in _branches(tmp_path)  # nothing happened
    assert controller.list_pending() == []


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
    outcome = _submit(controller, tool, "risky-experiment", risk="high")
    assert outcome.outcome == OUTCOME_ROUTE
    controller.reject(
        outcome.pending.id,
        identity="reviewer",
        reason="not deleting this today",
    )
    assert "risky-experiment" in _branches(tmp_path)  # survived
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
    routed = ActionGate(escalate_below=0.75, route_high_risk=True).decide(
        _assessment(tool, "merged-cleanup"),
        risk_class=risk_class_for(tool.classify("merged-cleanup")),
        action=tool.delete_action("merged-cleanup"),
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

    from tests.support.assessments import carrying

    # A fully-satisfied assessment pointed at the BASE branch. The point of this
    # test is that the executor refuses the base branch regardless of how good
    # the authorization looks, so the authorization here is made deliberately
    # perfect rather than deliberately unbound.
    approved = gate.decide(
        carrying(
            Judgment(verdict=Verdict.PASS, confidence=1.0, authoritative=True),
            action_class=ACTION_BRANCH_DELETE,
        ),
        risk_class="low",
        action=GitTool(repo_path=tmp_path, sandbox=sandbox).delete_action("main"),
    )
    assert approved.approved
    result = executor.execute(approved)
    assert result.refused and "base branch" in result.detail
    assert "main" in _branches(tmp_path)


# -- Phase 2: the real delete, still behind every safeguard -------------------


def _real_controller(repo, sandbox, ledger=None):
    return ExecutionController(
        gate=ActionGate(escalate_below=0.75, route_high_risk=True),
        executor=GitBranchDeleteExecutor(
            repo_path=repo, sandbox=sandbox, allow_delete=True
        ),
        ledger=ledger if ledger is not None else SqliteLedger(":memory:"),
    )


def test_approved_merged_branch_really_deletes_in_the_sandbox(tmp_path):
    sandbox = _sandbox()
    _make_repo(tmp_path)
    tool = GitTool(repo_path=tmp_path, sandbox=sandbox)
    controller = _real_controller(tmp_path, sandbox)

    outcome = _submit(controller, tool, "risky-experiment")
    assert outcome.outcome == OUTCOME_APPROVE
    assert outcome.execution.executed and outcome.execution.exit_status == 0
    assert "risky-experiment" not in _branches(tmp_path)  # really gone
    # The merged branch's history is untouched: its commits stay on main.
    assert "work" in _git(tmp_path, "log", "--format=%s", "main")


def test_denied_hold_never_deletes_even_with_deletes_enabled(tmp_path):
    sandbox = _sandbox()
    _make_repo(tmp_path)
    tool = GitTool(repo_path=tmp_path, sandbox=sandbox)
    controller = _real_controller(tmp_path, sandbox)

    outcome = _submit(controller, tool, "risky-experiment", risk="high")
    controller.reject(outcome.pending.id, identity="reviewer", reason="keep")
    assert "risky-experiment" in _branches(tmp_path)  # survived the real executor


def test_human_approved_hold_executes_the_real_delete(tmp_path):
    sandbox = _sandbox()
    _make_repo(tmp_path)
    tool = GitTool(repo_path=tmp_path, sandbox=sandbox)
    ledger = SqliteLedger(":memory:")
    controller = _real_controller(tmp_path, sandbox, ledger)

    outcome = _submit(controller, tool, "risky-experiment", risk="high")
    result = controller.approve(
        outcome.pending.id, identity="reviewer", reason="reviewed and accepted"
    )
    assert result.executed and "risky-experiment" not in _branches(tmp_path)
    decisions = ledger.human_decisions()
    assert decisions and decisions[0]["decided_by"] == "reviewer"


def test_fail_closed_when_isolation_cannot_start(tmp_path):
    _sandbox()  # still require the runtime context for parity of gating
    _make_repo(tmp_path)
    tool = GitTool(repo_path=tmp_path, sandbox=_sandbox())
    controller = ExecutionController(
        gate=ActionGate(escalate_below=0.75, route_high_risk=True),
        executor=GitBranchDeleteExecutor(
            repo_path=tmp_path, sandbox=NullSandbox(), allow_delete=True
        ),
        ledger=SqliteLedger(":memory:"),
    )
    outcome = _submit(controller, tool, "risky-experiment")
    assert outcome.outcome == OUTCOME_APPROVE  # judged safe on real evidence
    assert outcome.execution.refused and not outcome.execution.executed
    assert not outcome.execution.started_ok
    assert "risky-experiment" in _branches(tmp_path)  # fail-closed: survived


# -- regression: the in-sandbox code executor refuses the git kind ------------


def test_sandbox_executor_still_refuses_the_git_kind(tmp_path):
    sandbox = _sandbox()
    _make_repo(tmp_path)
    tool = GitTool(repo_path=tmp_path, sandbox=sandbox)
    assessment = _assessment(tool, "risky-experiment")
    decision = ActionGate().decide(
        assessment, risk_class="low", action=tool.delete_action("risky-experiment")
    )
    assert decision.approved
    result = SandboxExecutor(sandbox=sandbox).execute(decision)
    assert result.refused and "unsupported action kind" in result.detail
    assert "risky-experiment" in _branches(tmp_path)
