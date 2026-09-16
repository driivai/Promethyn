"""Re-observation at execution, for ``branch.delete``: the gap, and the closure.

THE GAP, AND WHY THIS ACTION CLASS FIRST. A hold records evidence at assessment
time and executes later against that evidence REPLAYED from the persisted
record — ``execution/pending.py`` restores the coverage report from the record
and calls no verifier, and a search of ``src/prometheus_protocol/execution/``
for ``.verify(`` returns nothing. ``branch.delete`` is the class where that is
demonstrable rather than hypothetical, because its live-state check already
exists: the merge proof counts commits reachable from the branch and absent
from the base (``tools/git.py``, ``rev-list --count``). A branch reviewed as
"zero commits absent from the base" can gain commits before the human approves,
and the delete executes on the replayed sentence. That is irreversible loss of
work that may exist nowhere else.

THE REPRODUCTION IS FIRST, AND IT IS KEPT. ``test_the_gap_...`` wires the
controller with NO re-observation and shows the executor reached with an
approved decision for a branch that gained a commit after review. It passes —
it is a measurement of the unfixed path, kept permanently, the way a named gap
is kept as a passing test (doctrine #5). Everything below it is the same
scenario with re-observation wired.

WHAT IS REAL HERE AND WHAT IS NOT, because a test that hides its seams is a
test nobody can size. The REPOSITORY is real: a temporary git repo, real
commits, real branches. The OBSERVER is real: ``GitBranchStateObserver`` over
``GitTool``, the same reader the merge proof uses, running real ``git`` through
a sandbox adapter. The EXECUTOR is a spy. It has to be: the shipped
``GitBranchDeleteExecutor`` refuses without an isolating sandbox, so on a runner
with no namespace isolation a real executor would refuse for a reason that has
nothing to do with state, and the property under test — whether the executor is
REACHED — would be invisible. ``tests/conformance/test_git_tool.py`` covers the
real executor under real isolation; what this module proves is the path to it.

THE SANDBOX IS THE NON-ISOLATING ADAPTER, deliberately and only for READS. The
observer runs ``git rev-parse`` and ``git rev-list --count`` against a fixture
repository this test created. Nothing untrusted is executed, no candidate code
is involved, and the alternative — requiring namespace isolation — would make
every proof below skip on a runner without it, which is the one thing a proof
may not do.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from prometheus_protocol.core.models import (
    ACTION_GIT_DELETE_BRANCH,
    ExecutableAction,
    Tier,
    Unavailability,
    Unavailable,
)
from prometheus_protocol.core.errors import CONFIG_REFUSAL_REASONS, ConfigError
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.models import PendingStatus
from prometheus_protocol.execution.pending import PendingActionService
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import OUTCOME_ROUTE, GateDecision
from prometheus_protocol.ledger.sqlite_ledger import (
    _APPROVED_STATUS,
    _PENDING_STATUS,
    _STATE_MOVED_STATUS,
    SqliteLedger,
)
from prometheus_protocol.policy.coverage import BoundResult
from prometheus_protocol.policy.execution import (
    EXECUTION_REFUSAL_REASONS,
    ExecutionAuthorizer,
)
from prometheus_protocol.policy.profile import (
    CHECK_MERGE_PROOF,
    DEFAULT_PROFILE_ID,
    load_profile,
)
from prometheus_protocol.policy.reobservation import (
    MOMENT_PRE_APPROVAL,
    MOMENT_PRE_EXECUTION,
    NOT_THIS_PRINCIPAL,
    OBSERVATION_EVENT,
    OUTCOME_MATCHED,
    OUTCOME_MOVED,
    Observation,
    ReObservation,
    StateMoved,
    StateUnobservable,
    StateUnreadable,
    Unreadable,
    compare,
    observation_subject,
)
from prometheus_protocol.policy.resolver import resolve
from prometheus_protocol.policy.snapshot import (
    ACTION_BRANCH_DELETE,
    ACTION_CLASSES,
    ACTION_DATABASE_MIGRATE,
    ACTION_SANDBOX_EXECUTE,
    snapshot_digest,
)
from prometheus_protocol.policy.target_state import BranchDeleteState, aspects_of
from prometheus_protocol.sandbox.unsafe import UnsafeLocalSandbox
from prometheus_protocol.swarm.executor import Executor
from prometheus_protocol.swarm.models import ExecutionResult, content_hash
from prometheus_protocol.tools.git import (
    MERGE_CHECK_VERIFIER_ID,
    GitBranchStateObserver,
    GitTool,
    evidence_for,
)
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.store import InMemoryTrustStore

BRANCH = "feature-work"
CLOCK = "2026-09-15T00:00:00+00:00"


# ---------------------------------------------------------------------------
# the fixture repository, and the wiring
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "user.name=fixture",
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _make_repo(path: Path) -> None:
    """``main`` plus a branch that is FULLY merged: zero commits absent."""

    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "-C", str(path), "-c", "init.defaultBranch=main", "init", "-q"],
        check=True,
    )
    _git(path, "commit", "-q", "--allow-empty", "-m", "base")
    _git(path, "checkout", "-q", "-b", BRANCH)
    (path / "a.txt").write_text("a\n", encoding="utf-8")
    _git(path, "add", "a.txt")
    _git(path, "commit", "-q", "-m", "work")
    _git(path, "checkout", "-q", "main")
    _git(path, "merge", "-q", "--no-ff", "-m", "merge", BRANCH)


def _add_commit_to_branch(path: Path) -> None:
    """What happens while the human is deciding: the branch gains work."""

    _git(path, "checkout", "-q", BRANCH)
    (path / "b.txt").write_text("b\n", encoding="utf-8")
    _git(path, "add", "b.txt")
    _git(path, "commit", "-q", "-m", "work nobody reviewed")
    _git(path, "checkout", "-q", "main")


def _tool(repo: Path) -> GitTool:
    return GitTool(repo_path=repo, sandbox=UnsafeLocalSandbox(), base_branch="main")


class Spy(Executor):
    """Records that the executor was REACHED. The property under test."""

    def __init__(self) -> None:
        self.calls: list[GateDecision] = []

    def execute(self, decision: GateDecision) -> ExecutionResult:
        self.calls.append(decision)
        return ExecutionResult(executed=True, subject_id=decision.subject_id)


def _reobservation(repo: Path, **overrides) -> ReObservation:
    """branch.delete observed; the other two classes opted out BY NAME.

    The opt-outs are real and deliberate: this sprint covers one action class,
    and a class that is simply absent from the registry would be silently
    unobserved — the posture-by-absence G21 exists to refuse.
    """

    observers = {ACTION_BRANCH_DELETE: GitBranchStateObserver(_tool(repo))}
    observers.update(overrides.pop("observers", {}))
    return ReObservation(
        observers=observers,
        opted_out={
            ACTION_SANDBOX_EXECUTE: "phase 1 covers branch.delete only",
            ACTION_DATABASE_MIGRATE: "phase 1 covers branch.delete only",
            **overrides.pop("opted_out", {}),
        },
    )


def _controller(repo: Path, *, reobservation: ReObservation | None) -> tuple:
    ledger = SqliteLedger(":memory:")
    spy = Spy()
    controller = ExecutionController(
        gate=ActionGate(
            route_high_risk=True,
            authorizer=ExecutionAuthorizer(lambda: load_profile(DEFAULT_PROFILE_ID)),
            target_canonical=f"git://{Path(repo).resolve()}",
        ),
        executor=spy,
        ledger=ledger,
        reobservation=reobservation,
    )
    return controller, spy, ledger


def _assessment(tool: GitTool, branch: str):
    """The real path: policy -> snapshot -> bound merge-check result -> assess."""

    policy = load_profile(DEFAULT_PROFILE_ID)
    snapshot = resolve(
        policy,
        artifact_sha256=content_hash(branch),
        target_canonical=f"git://{tool.repo_path}",
        action_class=ACTION_BRANCH_DELETE,
        attempt_id=f"delete-branch:{branch}",
    )
    bank = VerifierBank(InMemoryTrustStore(), policy_supplier=lambda: policy)
    bank.register(MERGE_CHECK_VERIFIER_ID, Tier.HARD)
    return bank.assess(
        snapshot,
        [
            BoundResult(
                check_id=CHECK_MERGE_PROOF,
                snapshot_digest=snapshot_digest(snapshot),
                implementation=MERGE_CHECK_VERIFIER_ID,
                outcome=evidence_for(tool.classify(branch)),
            )
        ],
    )


def _hold(controller: ExecutionController, tool: GitTool, branch: str = BRANCH):
    outcome = controller.submit(
        attempt_id=f"delete-branch:{branch}",
        assessment=_assessment(tool, branch),
        action=tool.delete_action(branch),
        risk_class="high",
        subject_id=f"delete-branch:{branch}",
    )
    assert outcome.outcome == OUTCOME_ROUTE, outcome.outcome
    assert outcome.pending is not None
    return outcome.pending


def _observations(ledger: SqliteLedger) -> list[dict]:
    found = []
    for entry in ledger.chained_events():
        if entry.get("event") != OBSERVATION_EVENT:
            continue
        payload = entry.get("payload")
        if isinstance(payload, str):
            payload = json.loads(payload)
        found.append({"subject": entry.get("subject"), "payload": payload})
    return found


# ---------------------------------------------------------------------------
# PART 1 — the reproduction
# ---------------------------------------------------------------------------


def test_the_gap_without_reobservation_a_delete_executes_on_replayed_evidence(tmp_path):
    """THE REPRODUCTION. Kept permanently as the measurement of the unfixed path.

    Review the branch as provably lossless, let it gain a commit, approve,
    execute. With no re-observation wired the executor is REACHED with an
    approved decision, and the evidence that authorized it — "0 commits absent
    from the base" — is false by the time it runs. The live count at execution
    is asserted here so the test states the size of the lie rather than implying
    it.
    """

    _make_repo(tmp_path)
    tool = _tool(tmp_path)
    assert tool.classify(BRANCH).unmerged_commits == 0
    controller, spy, _ = _controller(tmp_path, reobservation=None)
    pending = _hold(controller, tool)

    _add_commit_to_branch(tmp_path)
    assert tool.classify(BRANCH).unmerged_commits == 1

    result = controller.approve(pending.id, identity="reviewer")

    assert spy.calls, "the executor was never reached"
    assert result.executed
    # The record the execution carries still says the delete is lossless.
    assert pending.record["coverage"]["answered_by"] == {
        CHECK_MERGE_PROOF: MERGE_CHECK_VERIFIER_ID
    }
    assert tool.classify(BRANCH).unmerged_commits == 1


def test_the_unfixed_record_says_plainly_that_nothing_was_observed(tmp_path):
    """The other half of the reproduction, and the reason the record version
    moved. An unconfigured deployment does not get a record that is SILENT about
    live state — silence and "compared, matched" would be the same bytes. It
    gets a block that says no re-observation was wired."""

    _make_repo(tmp_path)
    controller, _, _ = _controller(tmp_path, reobservation=None)
    pending = _hold(controller, _tool(tmp_path))

    block = pending.record["target_state"]
    assert block["observed"] is False
    assert "not_configured" in block
    assert "digest" not in block


# ---------------------------------------------------------------------------
# PART 2 — the pre-approval comparison
# ---------------------------------------------------------------------------


def test_a_branch_that_gained_commits_is_refused_BEFORE_the_approval_is_recorded(
    tmp_path,
):
    """The first comparison. The approval is not recorded, the hold stays
    PENDING, and the executor is never reached.

    This is the test the mutation "remove the pre-approval comparison" reddens,
    and it is the reproduction above with the mechanism wired.
    """

    _make_repo(tmp_path)
    tool = _tool(tmp_path)
    controller, spy, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, tool)
    _add_commit_to_branch(tmp_path)

    with pytest.raises(StateMoved) as refusal:
        controller.approve(pending.id, identity="reviewer")

    assert refusal.value.reason == "target_state_moved_before_approval"
    assert refusal.value.reason in EXECUTION_REFUSAL_REASONS
    assert spy.calls == [], "the executor was reached despite the refusal"
    row = ledger.pending_action(pending.id)
    assert row["status"] == _PENDING_STATUS
    assert row["decided_by"] in (None, ""), "an approval was recorded"


def test_an_unchanged_branch_records_the_approval_and_executes(tmp_path):
    """THE PAIRED POSITIVE CONTROL (doctrine #4). Without it every refusal in
    this module is consistent with a mechanism that refuses everything, which
    would be a different defect and a worse one."""

    _make_repo(tmp_path)
    tool = _tool(tmp_path)
    controller, spy, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, tool)

    result = controller.approve(pending.id, identity="reviewer")

    assert result.executed
    assert len(spy.calls) == 1
    assert ledger.pending_action(pending.id)["status"] == _APPROVED_STATUS
    outcomes = [o["payload"]["outcome"] for o in _observations(ledger)]
    assert outcomes == [OUTCOME_MATCHED, OUTCOME_MATCHED], outcomes


def test_the_pinned_record_carries_the_digest_and_the_aspect_list(tmp_path):
    """§6.1. The record names the covered set AS ACTUALLY ENCODED, so a record
    written by an older version names its own narrower set instead of being read
    under today's — the anti-G17 field."""

    _make_repo(tmp_path)
    controller, _, _ = _controller(tmp_path, reobservation=_reobservation(tmp_path))
    pending = _hold(controller, _tool(tmp_path))

    block = pending.record["target_state"]
    assert block["observed"] is True
    assert block["capture_point"] == "review"
    assert len(block["digest"]) == 64
    assert block["aspects"] == list(
        aspects_of(BranchDeleteState(branch_tip="a" * 40, base_tip="b" * 40, unmerged_commits=0))
    )
    # NEVER THE STATE ITSELF. The aspect NAMES are present by design — that is
    # what makes the covered set legible — so what must be absent is the VALUE
    # each name stands for: the real commit ids the observer read.
    tool = _tool(tmp_path)
    blob = json.dumps(block)
    for tip in (tool.rev(BRANCH), tool.rev("main")):
        assert tip and tip not in blob


# ---------------------------------------------------------------------------
# PART 3 — the pre-execution re-read and the terminal hold
# ---------------------------------------------------------------------------


def _approve_without_executing(controller, pending_id: int):
    """Record the approval through the pending service, executing nothing.

    ``controller.approve`` approves AND executes in one call, so a state change
    between those two moments cannot be staged through it. This is the same
    approval the controller records, taken alone.
    """

    return controller.pending.approve(pending_id, identity="reviewer")


def test_a_branch_that_moves_AFTER_approval_refuses_execution_and_the_hold_is_terminal(
    tmp_path,
):
    """The second comparison, and the ruling that a mismatch here is terminal.

    The approval is real and stays on the record — it was a correct decision on
    the state it was shown. What cannot stand is executing on it, and what must
    not happen is the hold remaining retry-eligible.
    """

    _make_repo(tmp_path)
    tool = _tool(tmp_path)
    controller, spy, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, tool)
    _approve_without_executing(controller, pending.id)
    assert ledger.pending_action(pending.id)["status"] == _APPROVED_STATUS

    _add_commit_to_branch(tmp_path)

    with pytest.raises(StateMoved) as refusal:
        controller.retry_execution(pending.id, identity="operator")

    assert refusal.value.reason == "state_moved_after_approval"
    assert refusal.value.reason in EXECUTION_REFUSAL_REASONS
    assert spy.calls == [], "the executor was reached after the state moved"
    row = ledger.pending_action(pending.id)
    assert row["status"] == _STATE_MOVED_STATUS
    assert row["status"] == PendingStatus.STATE_MOVED.value
    # The human decision is untouched: the approval happened and was correct.
    assert row["decided_by"] == "reviewer"
    assert row["invalidated_reason"]


def test_the_terminal_hold_is_not_retry_eligible(tmp_path):
    """The load-bearing half of "terminal". A hold whose target moved must not
    be re-drivable by any verb, or the ruling is a label rather than a state."""

    _make_repo(tmp_path)
    controller, spy, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, _tool(tmp_path))
    _approve_without_executing(controller, pending.id)
    _add_commit_to_branch(tmp_path)
    with pytest.raises(StateMoved):
        controller.retry_execution(pending.id, identity="operator")

    with pytest.raises(ValueError, match="state_moved_after_approval|can never execute"):
        controller.retry_execution(pending.id, identity="operator")
    assert spy.calls == []
    assert ledger.pending_action(pending.id)["status"] == _STATE_MOVED_STATUS


def test_an_unchanged_branch_executes_on_the_retry_path_too(tmp_path):
    """The positive control for the pre-execution comparison specifically: the
    retry path reaches the executor when the target did not move."""

    _make_repo(tmp_path)
    controller, spy, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, _tool(tmp_path))
    _approve_without_executing(controller, pending.id)

    result = controller.retry_execution(pending.id, identity="operator")

    assert result.executed
    assert len(spy.calls) == 1
    assert ledger.pending_action(pending.id)["status"] == _APPROVED_STATUS


def test_the_ledger_transition_cannot_touch_a_hold_that_is_not_approved(tmp_path):
    """The guard's own scope, both directions. ``mark_state_moved`` is the one
    transition out of APPROVED, and it must be no more able to touch a PENDING
    hold than the two pending-guarded resolvers are able to touch a decided one.
    """

    _make_repo(tmp_path)
    controller, _, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, _tool(tmp_path))

    assert ledger.mark_state_moved(pending.id, at=CLOCK, reason="probe") is False
    assert ledger.pending_action(pending.id)["status"] == _PENDING_STATUS

    _approve_without_executing(controller, pending.id)
    assert ledger.mark_state_moved(pending.id, at=CLOCK, reason="probe") is True
    assert ledger.pending_action(pending.id)["status"] == _STATE_MOVED_STATUS
    # Idempotence in the safe direction: it cannot fire twice.
    assert ledger.mark_state_moved(pending.id, at=CLOCK, reason="probe") is False


def test_the_ledger_status_literals_equal_the_enum(tmp_path):
    """G26's answer applied to a value that cannot be imported. The ledger
    spells these three because importing ``PendingStatus`` would invert the
    package's layering; what cannot be derived is the value, so the CHECK is
    derived instead."""

    assert _PENDING_STATUS == PendingStatus.PENDING.value
    assert _APPROVED_STATUS == PendingStatus.APPROVED.value
    assert _STATE_MOVED_STATUS == PendingStatus.STATE_MOVED.value


# ---------------------------------------------------------------------------
# PART 3b — the observation record
# ---------------------------------------------------------------------------


def test_the_observation_record_is_chained_keyed_on_the_execution_attempt(tmp_path):
    """§2.2 and §6.2. Two entries, both in the chain, keyed on the attempt: the
    pre-approval reading at ordinal 0 and the execution's at 1."""

    _make_repo(tmp_path)
    controller, _, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, _tool(tmp_path))
    controller.approve(pending.id, identity="reviewer")

    found = _observations(ledger)
    assert [o["payload"]["moment"] if "moment" in o["payload"] else o["payload"]["observed"]["moment"] for o in found] == [
        MOMENT_PRE_APPROVAL,
        MOMENT_PRE_EXECUTION,
    ]
    attempt = pending.record["attempt_id"]
    assert [o["subject"] for o in found] == [
        observation_subject(attempt, 0, pending_id=pending.id),
        observation_subject(attempt, 1, pending_id=pending.id),
    ]
    assert ledger.verify_chain().ok


def test_the_execution_entry_restates_the_pre_approval_one(tmp_path):
    """Obligation (a): ONE receipt shows state was checked twice and what moved
    between the two, rather than requiring a reader to join two rows."""

    _make_repo(tmp_path)
    controller, _, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, _tool(tmp_path))
    controller.approve(pending.id, identity="reviewer")

    first, second = _observations(ledger)
    assert first["payload"]["prior"] is None
    prior = second["payload"]["prior"]
    assert prior is not None
    assert prior["observed"]["digest"] == first["payload"]["observed"]["digest"]
    assert prior["outcome"] == first["payload"]["outcome"]


def test_a_refused_comparison_is_recorded_not_only_a_passing_one(tmp_path):
    """An observation recorded only when it PASSES is one a reader cannot
    distinguish from one that never ran. The refusal is chained before it is
    raised."""

    _make_repo(tmp_path)
    controller, _, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, _tool(tmp_path))
    _add_commit_to_branch(tmp_path)
    with pytest.raises(StateMoved):
        controller.approve(pending.id, identity="reviewer")

    found = _observations(ledger)
    assert len(found) == 1
    assert found[0]["payload"]["outcome"] == OUTCOME_MOVED
    assert found[0]["payload"]["pinned"]["digest"]
    assert found[0]["payload"]["observed"]["digest"]
    assert (
        found[0]["payload"]["observed"]["digest"]
        != found[0]["payload"]["pinned"]["digest"]
    )
    assert ledger.verify_chain().ok


def test_the_observation_record_never_carries_the_state_itself(tmp_path):
    """§6.3. Digests and aspect NAMES only. A catalog dump in the ledger is an
    unbounded persisted blob, and the F8 defect is the measured precedent."""

    _make_repo(tmp_path)
    tool = _tool(tmp_path)
    controller, _, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, tool)
    controller.approve(pending.id, identity="reviewer")

    tip = tool.rev(BRANCH)
    assert tip
    blob = json.dumps(_observations(ledger))
    assert tip not in blob, "the record carries a real commit id"


# ---------------------------------------------------------------------------
# PART 4 — unavailability halts, wholly and partially
# ---------------------------------------------------------------------------


class Broken:
    """An observer whose target cannot be read at all."""

    def observe(self, *, target_canonical, action):
        return Unavailable(
            verifier_id=MERGE_CHECK_VERIFIER_ID,
            tier=Tier.HARD,
            reason=Unavailability.INFRA_FAULT,
            detail="the repository could not be reached",
        )


class Raising:
    """An observer that faults. A broken instrument is never a moved subject."""

    def observe(self, *, target_canonical, action):
        raise RuntimeError("the reader crashed")


def test_a_target_that_cannot_be_read_at_hold_creation_halts_and_holds_nothing(
    tmp_path,
):
    """Unavailability at capture. No hold is created: a hold pinned to nothing
    would read, downstream, as one that was checked."""

    _make_repo(tmp_path)
    controller, spy, ledger = _controller(
        tmp_path,
        reobservation=_reobservation(tmp_path, observers={ACTION_BRANCH_DELETE: Broken()}),
    )
    with pytest.raises(StateUnreadable) as refusal:
        _hold(controller, _tool(tmp_path))

    assert refusal.value.reason == "target_state_unreadable"
    assert spy.calls == []
    assert ledger.pending_actions() == []


def test_a_target_that_becomes_unreadable_before_approval_halts(tmp_path):
    """Unavailability at the first comparison. It ALWAYS halts: there is no
    routing path, because a human asked to approve an action whose live state
    could not be read is being asked to approve on no information."""

    _make_repo(tmp_path)
    controller, spy, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, _tool(tmp_path))
    controller.pending._reobservation = _reobservation(
        tmp_path, observers={ACTION_BRANCH_DELETE: Broken()}
    )

    with pytest.raises(StateUnreadable) as refusal:
        controller.approve(pending.id, identity="reviewer")

    assert refusal.value.reason == "target_state_unreadable"
    assert spy.calls == []
    assert ledger.pending_action(pending.id)["status"] == _PENDING_STATUS


def test_an_observer_that_faults_is_unavailable_and_never_a_mismatch(tmp_path):
    """"The instrument broke" and "the subject changed" are different findings.
    Collapsing them would report a move nobody made — and, on the execution
    path, would make a hold terminal because a reader crashed."""

    _make_repo(tmp_path)
    controller, _, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, _tool(tmp_path))
    controller.pending._reobservation = _reobservation(
        tmp_path, observers={ACTION_BRANCH_DELETE: Raising()}
    )

    with pytest.raises(StateUnreadable) as refusal:
        controller.approve(pending.id, identity="reviewer")

    assert refusal.value.reason == "target_state_unreadable"
    assert ledger.pending_action(pending.id)["status"] == _PENDING_STATUS
    recorded = _observations(ledger)[-1]["payload"]
    assert recorded["outcome"] == "unavailable"
    assert recorded["observed"]["unavailable"]["reason"] == "observer_fault"


def test_a_PARTIAL_read_is_unavailable_and_is_never_digested(tmp_path):
    """A digest over the readable half is a different measurement wearing the
    same name: it would compare EQUAL while the unreadable half moved. Driven
    against the real observer by deleting the branch it reads."""

    _make_repo(tmp_path)
    tool = _tool(tmp_path)
    controller, _, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, tool)
    # The base is still readable; the branch is not. One aspect of three.
    _git(tmp_path, "branch", "-D", BRANCH)
    assert tool.rev("main") is not None
    assert tool.rev(BRANCH) is None

    with pytest.raises(StateUnreadable) as refusal:
        controller.approve(pending.id, identity="reviewer")

    assert refusal.value.reason == "target_state_unreadable"
    recorded = _observations(ledger)[-1]["payload"]
    assert recorded["observed"]["digest"] is None, "a partial read produced a digest"
    assert "branch_tip" in recorded["observed"]["unavailable"]["aspects_unread"]
    assert "base_tip" not in recorded["observed"]["unavailable"]["aspects_unread"]


def test_the_observer_refuses_a_descriptor_naming_another_repository(tmp_path):
    """Cross-context substitution AT THE OBSERVER: answering for the wrong
    subject under the right name. It is bound to one repository and says so."""

    _make_repo(tmp_path)
    observer = GitBranchStateObserver(_tool(tmp_path))
    found = observer.observe(
        target_canonical="git:///somewhere/else",
        action=ExecutableAction(kind=ACTION_GIT_DELETE_BRANCH, code=BRANCH),
    )
    assert isinstance(found, Unreadable)
    assert "bound to" in found.detail
    assert set(found.aspects_unread) == set(
        aspects_of(BranchDeleteState(branch_tip="a" * 40, base_tip="b" * 40, unmerged_commits=0))
    )


# ---------------------------------------------------------------------------
# PART 5 — the opt-out, per action class
# ---------------------------------------------------------------------------


def test_an_opted_out_class_is_not_observed_and_the_record_NAMES_the_choice(tmp_path):
    """G21's precedent. "Removed the requirement" and "never had one" are
    indistinguishable; a named value in the record is not."""

    _make_repo(tmp_path)
    reobs = ReObservation(
        observers={},
        opted_out={
            ACTION_BRANCH_DELETE: "deletes are reviewed out of band on this deployment",
            ACTION_SANDBOX_EXECUTE: "phase 1",
            ACTION_DATABASE_MIGRATE: "phase 1",
        },
    )
    controller, spy, _ = _controller(tmp_path, reobservation=reobs)
    pending = _hold(controller, _tool(tmp_path))
    _add_commit_to_branch(tmp_path)

    result = controller.approve(pending.id, identity="reviewer")

    assert result.executed, "an opted-out class must still execute"
    assert len(spy.calls) == 1
    block = pending.record["target_state"]
    assert block["observed"] is False
    assert block["opted_out"] == "deletes are reviewed out of band on this deployment"
    assert block["action_class"] == ACTION_BRANCH_DELETE


def test_the_registry_is_total_over_the_closed_set_and_refuses_a_gap(tmp_path):
    """A class in NEITHER is silently unobserved, which is what an unset
    variable and a deliberate choice both look like."""

    with pytest.raises(ValueError, match="neither re-observed nor opted out"):
        ReObservation(observers={}, opted_out={ACTION_BRANCH_DELETE: "x"})


def test_the_registry_refuses_a_class_that_is_both_observed_and_opted_out(tmp_path):
    _make_repo(tmp_path)
    with pytest.raises(ValueError, match="both observed and opted out"):
        ReObservation(
            observers={ACTION_BRANCH_DELETE: GitBranchStateObserver(_tool(tmp_path))},
            opted_out={
                ACTION_BRANCH_DELETE: "x",
                ACTION_SANDBOX_EXECUTE: "y",
                ACTION_DATABASE_MIGRATE: "z",
            },
        )


def test_the_registry_refuses_an_unnamed_opt_out():
    """An empty reason states nothing, which is the posture-by-absence the
    ruling exists to remove."""

    with pytest.raises(ValueError, match="NAMED reason"):
        ReObservation(
            observers={},
            opted_out={c: ("  " if c == ACTION_BRANCH_DELETE else "named") for c in ACTION_CLASSES},
        )


def test_the_registry_refuses_an_unknown_action_class():
    with pytest.raises(ValueError, match="unknown action class"):
        ReObservation(
            observers={},
            opted_out={**{c: "named" for c in ACTION_CLASSES}, "not.a.class": "x"},
        )


# ---------------------------------------------------------------------------
# PART 6 — the comparison itself, and the aspect guard
# ---------------------------------------------------------------------------


def test_a_digest_compared_against_ITSELF_always_matches_which_is_the_shape_to_refuse():
    """§7.5's cell, as a direct probe. Comparing the observed digest with itself
    passes every deletion probe, so it is stated here as the substitution the
    implementation must not contain: the pinned digest is the OTHER operand.
    """

    observation = Observation(
        moment=MOMENT_PRE_EXECUTION,
        observed_at=CLOCK,
        digest="a" * 64,
        aspects=("branch_tip", "base_tip", "unmerged_commits"),
    )
    assert (
        compare(
            pinned_digest=observation.digest or "",
            pinned_aspects=observation.aspects,
            observation=observation,
        )
        == OUTCOME_MATCHED
    )
    assert (
        compare(
            pinned_digest="b" * 64,
            pinned_aspects=observation.aspects,
            observation=observation,
        )
        == OUTCOME_MOVED
    )


def test_two_digests_over_DIFFERENT_covered_sets_are_not_comparable(tmp_path):
    """Aspects are compared before digests. Reporting "moved" for two readings
    over different sets would name the wrong finding: the target may be
    untouched while the INSTRUMENT changed under it."""

    observation = Observation(
        moment=MOMENT_PRE_APPROVAL,
        observed_at=CLOCK,
        digest="a" * 64,
        aspects=("branch_tip", "base_tip"),
    )
    assert (
        compare(
            pinned_digest="a" * 64,
            pinned_aspects=("branch_tip", "base_tip", "unmerged_commits"),
            observation=observation,
        )
        == "aspects_differ"
    )


def test_an_observation_carrying_neither_a_digest_nor_a_reason_is_refused():
    """The shape that reads downstream as a pass, refused at construction."""

    with pytest.raises(ValueError, match="EITHER a digest or the reason"):
        Observation(moment=MOMENT_PRE_APPROVAL, observed_at=CLOCK)
    with pytest.raises(ValueError, match="EITHER a digest or the reason"):
        Observation(
            moment=MOMENT_PRE_APPROVAL,
            observed_at=CLOCK,
            digest="a" * 64,
            aspects=("x",),
            unavailable=Unreadable(reason="both"),
        )


def test_a_digest_with_no_aspect_list_is_refused():
    with pytest.raises(ValueError, match="names the aspects"):
        Observation(moment=MOMENT_PRE_APPROVAL, observed_at=CLOCK, digest="a" * 64)


def test_the_state_digest_moves_for_every_aspect():
    """Derived-set discipline: an aspect collected but not hashed is not
    covered, so every field must move the digest."""

    from prometheus_protocol.policy.target_state import state_digest

    base = BranchDeleteState(branch_tip="a" * 40, base_tip="b" * 40, unmerged_commits=0)
    changed = {
        "branch_tip": BranchDeleteState(branch_tip="c" * 40, base_tip="b" * 40, unmerged_commits=0),
        "base_tip": BranchDeleteState(branch_tip="a" * 40, base_tip="d" * 40, unmerged_commits=0),
        "unmerged_commits": BranchDeleteState(
            branch_tip="a" * 40, base_tip="b" * 40, unmerged_commits=1
        ),
    }
    assert set(changed) == set(aspects_of(base))
    for name, other in changed.items():
        assert state_digest(other) != state_digest(base), name


def test_the_state_digest_has_its_own_domain_and_commits_to_its_type():
    """Its own domain, so a state preimage can never be reinterpreted as a
    requirements preimage; its type name inside it, so two state types that
    share field values cannot share a digest."""

    from prometheus_protocol.policy.target_state import state_preimage

    preimage = state_preimage(
        BranchDeleteState(branch_tip="a" * 40, base_tip="b" * 40, unmerged_commits=0)
    )
    assert preimage.startswith(b"prom-target-state-v1\x00")
    assert b"prom-bound-requirements-v1" not in preimage
    assert b"BranchDeleteState" in preimage


# ---------------------------------------------------------------------------
# PART 7 — the real composition root
# ---------------------------------------------------------------------------
#
# Everything above builds the controller by hand, and none of it proves the
# mechanism is REACHED by anything shipped. When phase 1 merged it was not:
# every non-test construction of ExecutionController omitted ``reobservation=``.
# These two drive ``runtime/factory.build_execution_controller`` — the root the
# CLI's ``approve`` and ``retry-execution`` commands build — with nothing wired
# by hand but the ledger and the fixture repository.
#
# The executor here is the REAL SandboxExecutor the factory builds, not the spy,
# so "the executor was not reached" is asserted the only way it can be from
# outside: the branch the delete targets still exists afterwards.


def _factory_controller(repo: Path) -> tuple:
    """The shipped root, with only the ledger redirected to memory."""

    from prometheus_protocol.runtime.factory import build_execution_controller

    ledger = SqliteLedger(":memory:")
    controller = build_execution_controller(
        ledger=ledger,
        target_canonical=f"git://{_tool(repo).repo_path}",
        # NAMED, not defaulted. The factory refuses a git principal it is given
        # no reader and no base for, because a guessed base is a second
        # definition of "unmerged" — and on a repository based on anything but
        # ``main`` the guess refused every hold at creation (OPEN-GAPS G33).
        base_branch="main",
    )
    return controller, ledger


def test_the_real_composition_root_refuses_a_branch_that_moved(tmp_path):
    """THE REPRODUCTION, THROUGH THE SHIPPED ROOT. This is the test that fails
    on a tree where the factory omits ``reobservation=`` — on that tree the
    approval succeeds and the delete proceeds, which is
    ``test_the_gap_without_reobservation_...`` happening in production.

    Nothing about re-observation is passed in here. The registry comes from the
    factory reading its own target.
    """

    _make_repo(tmp_path)
    tool = _tool(tmp_path)
    controller, ledger = _factory_controller(tmp_path)
    pending = _hold(controller, tool)

    _add_commit_to_branch(tmp_path)

    with pytest.raises(StateMoved) as refusal:
        controller.approve(pending.id, identity="reviewer")

    assert refusal.value.reason == "target_state_moved_before_approval"
    assert ledger.pending_action(pending.id)["status"] == _PENDING_STATUS
    # The executor was never reached: the branch is still there, with the
    # commit that was never reviewed still on it.
    assert tool.rev(BRANCH) is not None
    assert tool.classify(BRANCH).unmerged_commits == 1


def test_the_real_composition_root_pins_live_state_on_every_hold_it_creates(tmp_path):
    """The positive half, and the one that says WHICH root wired what. A hold
    created by the shipped factory carries an OBSERVED target-state block, and
    the two classes phase 1 does not cover carry their reason by name rather
    than being absent from the record."""

    _make_repo(tmp_path)
    controller, _ = _factory_controller(tmp_path)
    pending = _hold(controller, _tool(tmp_path))

    block = pending.record["target_state"]
    assert block["observed"] is True
    assert block["capture_point"] == "review"
    assert len(block["digest"]) == 64

    registry = controller.pending.reobservation
    assert registry is not None, "the shipped root built a controller with no registry"
    assert sorted(registry.observers) == [ACTION_BRANCH_DELETE]
    assert sorted(registry.opted_out) == sorted(
        [ACTION_DATABASE_MIGRATE, ACTION_SANDBOX_EXECUTE]
    )
    # Machinery, not coverage: ONE of the three action classes is observed.
    assert len(registry.observers) == 1
    assert set(registry.observers) | set(registry.opted_out) == set(ACTION_CLASSES)


def test_the_real_composition_root_still_approves_a_branch_that_did_not_move(tmp_path):
    """The paired positive control (doctrine #4): the shipped root refuses
    movement, not approval. Without this, the refusal above is consistent with a
    factory that has simply broken the approval path."""

    _make_repo(tmp_path)
    tool = _tool(tmp_path)
    controller, ledger = _factory_controller(tmp_path)
    pending = _hold(controller, tool)

    controller.approve(pending.id, identity="reviewer")

    assert ledger.pending_action(pending.id)["status"] == _APPROVED_STATUS
    outcomes = [o["payload"]["outcome"] for o in _observations(ledger)]
    assert outcomes == [OUTCOME_MATCHED, OUTCOME_MATCHED], outcomes


# ---------------------------------------------------------------------------
# PART 8 — two roots, two registries
# ---------------------------------------------------------------------------
#
# WIRING CREATED THIS CASE. Before it, no root held a registry, so two could
# never disagree. Now they can, and the disagreement is reachable through the
# shipped CLI: `prom approve` builds its controller through
# ``build_execution_controller(config, ledger=ledger)`` with the DEFAULT
# ``sandbox://execution`` target (cli/main.py:341, :386), which opts
# ``branch.delete`` out — while the hold it is approving may have been pinned by
# a root that named a ``git://`` principal and does observe it.
#
# Found by driving the two roots against one ledger, not by reading the code:
# the first run raised a bare KeyError out of `approve`.


def _root(repo: Path | None, ledger_path: str):
    """A controller from the shipped factory. ``repo=None`` builds it the way
    the CLI does — default target, so ``branch.delete`` is opted out."""

    from prometheus_protocol.runtime.factory import build_execution_controller

    ledger = SqliteLedger(ledger_path)
    if repo is None:
        return build_execution_controller(ledger=ledger), ledger
    return (
        build_execution_controller(
            ledger=ledger,
            target_canonical=f"git://{_tool(repo).repo_path}",
            base_branch="main",
        ),
        ledger,
    )


def test_a_hold_pinned_by_an_observing_root_is_REFUSED_by_a_root_that_is_not(
    tmp_path,
):
    """Doctrine #2: a requested security property that cannot be honoured is
    refused, never degraded. The hold's own record says its live state was
    pinned and will be re-checked; this service cannot re-check it; so the
    approval is refused rather than granted unchecked.

    Skipping instead would delete a branch irreversibly on evidence the record
    claims was verified a second time.
    """

    ledger_path = str(tmp_path / "shared.db")
    repo = tmp_path / "repo"
    _make_repo(repo)
    creator, _ = _root(repo, ledger_path)
    pending = _hold(creator, _tool(repo))
    assert pending.record["target_state"]["observed"] is True

    approver, ledger = _root(None, ledger_path)
    assert not approver.pending.reobservation.covers(ACTION_BRANCH_DELETE)

    with pytest.raises(StateUnobservable) as refusal:
        approver.approve(pending.id, identity="reviewer")

    assert refusal.value.reason == "target_state_registry_mismatch"
    assert refusal.value.reason in EXECUTION_REFUSAL_REASONS
    # The refusal names the opt-out it hit, so an operator is told WHY this
    # deployment cannot check the hold rather than only that it would not.
    assert NOT_THIS_PRINCIPAL in str(refusal.value)
    assert ledger.pending_action(pending.id)["status"] == _PENDING_STATUS


def test_the_refusal_is_not_a_move_and_not_an_unreadable_target(tmp_path):
    """Three different findings, three types. "this deployment does not observe
    the class" is a statement about the DEPLOYMENT; collapsing it into
    StateMoved would report a move nobody made, and into StateUnreadable would
    report an outage that is not happening."""

    ledger_path = str(tmp_path / "shared.db")
    repo = tmp_path / "repo"
    _make_repo(repo)
    creator, _ = _root(repo, ledger_path)
    pending = _hold(creator, _tool(repo))
    approver, _ = _root(None, ledger_path)

    with pytest.raises(StateUnobservable) as refusal:
        approver.approve(pending.id, identity="reviewer")

    assert not isinstance(refusal.value, (StateMoved, StateUnreadable))
    assert refusal.value.reason not in {
        "target_state_moved_before_approval",
        "state_moved_after_approval",
        "target_state_unreadable",
    }


def test_the_same_hold_approves_through_a_root_that_DOES_observe_it(tmp_path):
    """THE PAIRED positive control (doctrine #4). Without it the refusal above
    is consistent with a hold that cannot be approved by anything."""

    ledger_path = str(tmp_path / "shared.db")
    repo = tmp_path / "repo"
    _make_repo(repo)
    creator, _ = _root(repo, ledger_path)
    pending = _hold(creator, _tool(repo))

    approver, ledger = _root(repo, ledger_path)
    approver.approve(pending.id, identity="reviewer")

    assert ledger.pending_action(pending.id)["status"] == _APPROVED_STATUS


def test_a_sandbox_targeted_root_cannot_CREATE_a_git_targeted_hold_at_all(tmp_path):
    """MEASURED WHILE WRITING THE TEST BELOW, and it narrows the blast radius.

    The obvious reverse case — the CLI-style root creating the hold — is not
    reachable: the gate re-resolves the requirements from its OWN
    ``target_canonical``, and a ``sandbox://execution`` re-resolution does not
    cover an assessment resolved against ``git://``. The submission is refused
    at authorization, before any hold exists.

    So the registry disagreement has exactly one reachable direction through the
    shipped factory: a hold CREATED by a git-targeted root and APPROVED by a
    sandbox-targeted one, which is the refusal proven above. Pinned here because
    "the other direction cannot happen" is a load-bearing claim and it is being
    checked rather than reasoned about.
    """

    from prometheus_protocol.policy.execution import ExecutionNotAuthorized

    repo = tmp_path / "repo"
    _make_repo(repo)
    creator, _ = _root(None, str(tmp_path / "shared.db"))

    with pytest.raises(ExecutionNotAuthorized, match="does not cover the requirements"):
        _hold(creator, _tool(repo))


def test_a_hold_that_was_never_pinned_approves_under_an_observing_root(tmp_path):
    """THE ASYMMETRY, NAMED RATHER THAN DISCOVERED. Here the registries differ
    the other way: the hold was created with ``branch.delete`` opted out, so its
    record carries ``observed: false`` and a reason, and the approving root
    observes. It PROCEEDS, because there is no pin to compare against and
    inventing one at approval would compare the target to itself.

    That is honest — the record makes no claim the approval fails to honour —
    but it is NOT symmetric with the refusal above, and the difference is which
    direction makes a false claim. The gate makes this unreachable through the
    factory (the test above), so the registry is supplied directly: what is
    measured here is the comparison's behaviour, not a shipped path.
    """

    repo = tmp_path / "repo"
    _make_repo(repo)
    opted_out_everywhere = ReObservation(
        opted_out={klass: "measuring the reverse direction" for klass in ACTION_CLASSES}
    )
    creator, _, ledger = _controller(repo, reobservation=opted_out_everywhere)
    pending = _hold(creator, _tool(repo))

    block = pending.record["target_state"]
    assert block["observed"] is False
    assert block["opted_out"] == "measuring the reverse direction"

    # Same ledger, a registry that DOES observe branch.delete.
    creator._pending._reobservation = _reobservation(repo)
    creator.approve(pending.id, identity="reviewer")

    assert ledger.pending_action(pending.id)["status"] == _APPROVED_STATUS
    # No observation was chained for it, so no receipt claims a check that did
    # not happen.
    assert _observations(ledger) == []


# ---------------------------------------------------------------------------
# PART 9 — the receipt's identity, and what survives a reload
# ---------------------------------------------------------------------------


def test_two_holds_sharing_an_attempt_id_do_not_share_an_observation_subject(
    tmp_path,
):
    """The observation subject keyed on ``attempt_id`` alone collides.

    ``attempt_id`` is a caller-supplied string and nothing requires it to be
    unique — ``_hold`` derives it from the branch name, so two holds on the same
    branch share one. Keyed on the attempt alone, both holds' receipts land on
    ONE subject, and a reader asking "what was observed for hold #2" gets hold
    #1's reading.

    FIXED BY INCLUDING THE HOLD, not by requiring attempt uniqueness: a
    uniqueness rule would be a new global constraint on every caller, would not
    apply retroactively to holds already in a ledger, and would be enforced far
    from where a duplicate is created. The hold id is already the ledger's
    primary key, so it is the identity that exists.
    """

    _make_repo(tmp_path)
    tool = _tool(tmp_path)
    controller, _, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    first = _hold(controller, tool)
    second = _hold(controller, tool)
    assert first.id != second.id
    assert first.record["attempt_id"] == second.record["attempt_id"], (
        "the collision this test is about did not occur"
    )

    attempt = first.record["attempt_id"]
    assert observation_subject(attempt, 0, pending_id=first.id) != observation_subject(
        attempt, 0, pending_id=second.id
    )

    controller.approve(first.id, identity="reviewer")
    controller.approve(second.id, identity="reviewer")

    subjects = [o["subject"] for o in _observations(ledger)]
    assert len(subjects) == len(set(subjects)), subjects
    # And each hold's own receipt is readable by its own identity.
    for hold in (first, second):
        entry = controller.pending.pre_approval_entry(attempt, pending_id=hold.id)
        assert entry is not None, f"hold #{hold.id} has no pre-approval receipt"


def test_a_reloaded_state_moved_hold_still_names_its_reviewer_and_the_time(tmp_path):
    """Approval metadata survives the reload of a hold that went terminal.

    The design's second human-facing obligation is that the refusal says **the
    approval stands as a record** — with the approver's name and time, because
    it was a correct decision on the state it was shown. A decoder that
    reconstructs the human decision only for ``APPROVED`` and ``REJECTED``
    drops exactly the case where the interface has to show it, and an operator
    reading a terminal hold would see no approver at all.

    The decision is labelled APPROVED rather than the hold's terminal status:
    what the human did was approve. The terminal status is the hold's, and it is
    on the row beside it.
    """

    _make_repo(tmp_path)
    controller, _, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, _tool(tmp_path))
    _approve_without_executing(controller, pending.id)
    _add_commit_to_branch(tmp_path)
    with pytest.raises(StateMoved):
        controller.retry_execution(pending.id, identity="operator")

    # Reloaded from the row, not the object that was held in memory.
    reloaded = controller.pending.get(pending.id)
    assert reloaded is not None
    assert reloaded.status == PendingStatus.STATE_MOVED
    assert reloaded.human_decision is not None, (
        "a terminal hold reloaded from the ledger forgot who approved it"
    )
    assert reloaded.human_decision.identity == "reviewer"
    assert reloaded.human_decision.timestamp
    assert reloaded.human_decision.decision == PendingStatus.APPROVED.value
    assert reloaded.human_decision.decision != PendingStatus.STATE_MOVED.value


# ---------------------------------------------------------------------------
# PART 10 — the claim, and the row a refusal leaves behind
# ---------------------------------------------------------------------------
#
# Both findings are about the SAME line: the pre-execution comparison sits after
# ``claim_pending_execution``, so any refusal it raises leaves the claim spent
# and no execution row written.


def _refused_rows(ledger: SqliteLedger, pending_id: int) -> list[dict]:
    return [r for r in ledger.executions_for_pending(pending_id) if r["refused"]]


def test_a_transient_observer_outage_does_not_permanently_brick_an_approved_hold(
    tmp_path,
):
    """THE REPRODUCTION FOR THE CLAIM LEAK, and its fix in one test.

    The observer is unavailable at execution time. That says nothing about the
    target, so the hold stays APPROVED and is retryable — but the claim was
    already taken, and retaining it would make every later retry fail with
    "already in progress or has completed" no matter how healthy the observer
    became. An approved action permanently unexecutable because a reader was
    down for a moment, with no verb to recover it.

    The second half is what makes this a fix rather than an assertion: the
    observer recovers and the SAME hold executes.
    """

    _make_repo(tmp_path)
    controller, spy, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, _tool(tmp_path))
    _approve_without_executing(controller, pending.id)

    controller.pending._reobservation = _reobservation(
        tmp_path, observers={ACTION_BRANCH_DELETE: Broken()}
    )
    with pytest.raises(StateUnreadable) as refusal:
        controller.retry_execution(pending.id, identity="operator")

    assert refusal.value.reason == "target_state_unreadable"
    assert spy.calls == []
    # Still approved, and the claim was RELEASED: not terminal, so retryable.
    assert ledger.pending_action(pending.id)["status"] == _APPROVED_STATUS
    assert ledger.claim_pending_execution(pending.id, CLOCK), (
        "the claim was not released, so this hold can never execute again"
    )
    ledger.release_pending_execution(pending.id)

    # The observer recovers. The same hold executes.
    controller.pending._reobservation = _reobservation(tmp_path)
    result = controller.retry_execution(pending.id, identity="operator")
    assert result.executed
    assert len(spy.calls) == 1


def test_a_hold_whose_target_MOVED_keeps_its_claim_spent(tmp_path):
    """The other side of the same ruling, and the reason it is keyed on type.

    A move is terminal. Releasing the claim here would be releasing it for a
    hold that must never execute — the status transition already refuses it, and
    the claim is the second lock. The two refusals take opposite branches and
    both are asserted, because a rule with only one measured side is a rule
    whose other side is a guess.
    """

    _make_repo(tmp_path)
    controller, spy, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, _tool(tmp_path))
    _approve_without_executing(controller, pending.id)
    _add_commit_to_branch(tmp_path)

    with pytest.raises(StateMoved):
        controller.retry_execution(pending.id, identity="operator")

    assert spy.calls == []
    assert ledger.pending_action(pending.id)["status"] == _STATE_MOVED_STATUS
    assert not ledger.claim_pending_execution(pending.id, CLOCK), (
        "a terminal hold's claim was released"
    )


def test_the_claim_ruling_is_keyed_on_type_and_the_key_set_is_pinned(tmp_path):
    """G25's shape applied to a behavioural rule: pin the MEMBERSHIP, because a
    fourth refusal type added later would otherwise silently take the default
    branch. The default is to RELEASE, so an unnamed terminal refusal would
    leave a hold that must not execute retry-eligible — the status still
    refuses it, which is why the default is safe, and why this pin is what
    makes adding a type a decision rather than an accident."""

    from prometheus_protocol.policy.reobservation import (
        CLAIM_RETAINED_BY,
        refusal_retains_claim,
    )

    assert CLAIM_RETAINED_BY == frozenset({StateMoved})
    assert refusal_retains_claim(StateMoved("moved", reason="state_moved_after_approval"))
    for other in (
        StateUnreadable("unreadable", reason="target_state_unreadable"),
        StateUnreadable("aspects", reason="target_state_aspects_differ"),
        StateUnobservable("not here", reason="target_state_registry_mismatch"),
    ):
        assert not refusal_retains_claim(other), other


@pytest.mark.parametrize(
    "observer,refusal,reason",
    [
        (None, StateMoved, "state_moved_after_approval"),
        (Broken, StateUnreadable, "target_state_unreadable"),
    ],
)
def test_a_pre_execution_refusal_writes_a_refused_execution_row(
    tmp_path, observer, refusal, reason
):
    """BOTH refusal kinds, because the audit contract does not have an exempt
    one. The hold was claimed and an execution WAS attempted; without a row,
    ``executions_for_pending`` shows nothing and an approved action that did not
    execute is indistinguishable from one nobody ever tried to run.

    The row names the typed reason, so the receipt says WHY rather than only
    that something was refused.
    """

    _make_repo(tmp_path)
    controller, spy, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, _tool(tmp_path))
    _approve_without_executing(controller, pending.id)
    assert _refused_rows(ledger, pending.id) == []

    if observer is None:
        _add_commit_to_branch(tmp_path)
    else:
        controller.pending._reobservation = _reobservation(
            tmp_path, observers={ACTION_BRANCH_DELETE: observer()}
        )

    with pytest.raises(refusal):
        controller.retry_execution(pending.id, identity="operator")

    assert spy.calls == []
    rows = _refused_rows(ledger, pending.id)
    assert len(rows) == 1, rows
    row = rows[0]
    assert row["executed"] == 0 or row["executed"] is False
    assert reason in row["detail"], row["detail"]
    # The row carries the authorization it was decided under, like every other
    # execution row, so the refusal is readable without a join.
    assert row["authorization"]


# ---------------------------------------------------------------------------
# PART 11 — a supplied service and a supplied registry
# ---------------------------------------------------------------------------


def _service(ledger, **kwargs):
    """A service built the way a caller who wires their own would build it."""

    return PendingActionService(
        ledger,
        authorizer=ExecutionAuthorizer(lambda: load_profile(DEFAULT_PROFILE_ID)),
        **kwargs,
    )


def _bare_controller(repo: Path, *, pending, reobservation):
    return ExecutionController(
        gate=ActionGate(
            route_high_risk=True,
            authorizer=ExecutionAuthorizer(lambda: load_profile(DEFAULT_PROFILE_ID)),
            target_canonical=f"git://{Path(repo).resolve()}",
        ),
        executor=Spy(),
        ledger=pending._ledger,
        pending=pending,
        reobservation=reobservation,
    )


def test_a_supplied_service_that_would_discard_the_registry_is_REFUSED(tmp_path):
    """THE REPRODUCTION AND THE RULING (doctrine #2). ``pending or Pending...``
    never constructs the service when one is supplied, so the registry passed
    beside it was silently dropped and both comparisons ran on the service's own
    registry — possibly ``None``.

    That is the worst shape this repository has a name for: every observable
    surface says re-observation is enabled, and neither check runs. Refused at
    construction rather than degraded, with a typed reason.
    """

    _make_repo(tmp_path)
    ledger = SqliteLedger(":memory:")
    service = _service(ledger)  # no registry
    assert service.reobservation is None

    with pytest.raises(ConfigError) as refusal:
        _bare_controller(tmp_path, pending=service, reobservation=_reobservation(tmp_path))

    assert refusal.value.reason == "reobservation_registry_discarded"
    assert refusal.value.reason in CONFIG_REFUSAL_REASONS


def test_a_supplied_service_carrying_a_DIFFERENT_registry_is_refused_too(tmp_path):
    """Not only the ``None`` case. Two registries are two answers to "which
    classes are observed", and the second comparison could then not happen for
    a class the first one covered. Identity, not equality: a caller that means
    to share one passes one."""

    _make_repo(tmp_path)
    ledger = SqliteLedger(":memory:")
    service = _service(ledger, reobservation=_reobservation(tmp_path))
    other = _reobservation(tmp_path)  # equivalent, not the same object
    assert service.reobservation is not other

    with pytest.raises(ConfigError) as refusal:
        _bare_controller(tmp_path, pending=service, reobservation=other)

    assert refusal.value.reason == "reobservation_registry_discarded"


def test_a_supplied_service_carrying_THE_SAME_registry_is_accepted(tmp_path):
    """The positive control (doctrine #4). The refusal is about the registry
    being discarded, not about supplying a service at all — without this the
    rule above is consistent with a controller that has simply stopped
    accepting ``pending=``."""

    _make_repo(tmp_path)
    ledger = SqliteLedger(":memory:")
    registry = _reobservation(tmp_path)
    service = _service(ledger, reobservation=registry)

    controller = _bare_controller(tmp_path, pending=service, reobservation=registry)

    assert controller.pending is service
    assert controller.pending.reobservation is registry


def test_supplying_a_service_with_no_registry_and_asking_for_none_is_accepted(
    tmp_path,
):
    """The other positive control. Nothing was requested, so nothing was
    discarded: a deployment that wires no re-observation is untouched by this
    rule, and its records still say ``observed: false`` with the reason."""

    _make_repo(tmp_path)
    ledger = SqliteLedger(":memory:")
    service = _service(ledger)

    controller = _bare_controller(tmp_path, pending=service, reobservation=None)

    assert controller.pending is service
    assert controller.pending.reobservation is None
    pending = _hold(controller, _tool(tmp_path))
    assert pending.record["target_state"]["observed"] is False


def test_two_registries_that_are_EQUAL_but_not_the_same_object_are_still_refused(
    tmp_path,
):
    """WHY IDENTITY AND NOT EQUALITY, pinned because the two are not the same
    check and a mutation proved this suite could not tell them apart.

    ``ReObservation`` is a dataclass, so ``==`` compares its two mappings, and
    the observers inside them compare with whatever ``__eq__`` their class has.
    ``GitBranchStateObserver`` defines none, so today equality IS identity for
    the observers and an equality check would behave the same. That is exactly
    the problem: the strictness of this refusal would be a property of a class
    this check does not own. An observer that later grew an ``__eq__`` on, say,
    ``repo_path`` would make two observers over DIFFERENT GitTools — different
    sandbox, different base branch — compare equal, and the check would start
    accepting a registry that reads its subject through a different instrument.
    A security check that can loosen without being edited is not a check.

    Identity cannot loosen. The cost is that a caller who builds two equivalent
    registries is refused and told to pass one; that is the correct direction.
    """

    _make_repo(tmp_path)
    ledger = SqliteLedger(":memory:")
    observer = GitBranchStateObserver(_tool(tmp_path))
    opted_out = {
        ACTION_SANDBOX_EXECUTE: "phase 1 covers branch.delete only",
        ACTION_DATABASE_MIGRATE: "phase 1 covers branch.delete only",
    }
    one = ReObservation(observers={ACTION_BRANCH_DELETE: observer}, opted_out=opted_out)
    two = ReObservation(observers={ACTION_BRANCH_DELETE: observer}, opted_out=opted_out)
    assert one == two, "this test needs two registries that ARE equal"
    assert one is not two

    service = _service(ledger, reobservation=one)
    with pytest.raises(ConfigError) as refusal:
        _bare_controller(tmp_path, pending=service, reobservation=two)

    assert refusal.value.reason == "reobservation_registry_discarded"


# ---------------------------------------------------------------------------
# PART 12 — the base branch the observer reads
# ---------------------------------------------------------------------------
#
# REPRODUCTION FIRST. The factory used to synthesise a GitTool with GitTool's
# own default base of "main" whenever a root named a git:// target and passed
# no reader. Measured on a repository based on "master": the caller's own tool
# reported unmerged_commits = 0 — the merge proof worked — while the
# synthesised observer could not read "main" at all, so it returned Unreadable
# and EVERY branch.delete hold was refused at creation.
#
# The direction was fail-closed, and the effect was a total denial of the
# feature for every deployment not based on "main".


def _master_repo(path: Path) -> None:
    """The same fixture as ``_make_repo``, based on ``master`` instead."""

    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "-C", str(path), "-c", "init.defaultBranch=master", "init", "-q"],
        check=True,
    )
    _git(path, "commit", "-q", "--allow-empty", "-m", "base")
    _git(path, "checkout", "-q", "-b", BRANCH)
    (path / "a.txt").write_text("a\n", encoding="utf-8")
    _git(path, "add", "a.txt")
    _git(path, "commit", "-q", "-m", "work")
    _git(path, "checkout", "-q", "master")
    _git(path, "merge", "-q", "--no-ff", "-m", "merge", BRANCH)


def _master_tool(repo: Path) -> GitTool:
    return GitTool(repo_path=repo, sandbox=UnsafeLocalSandbox(), base_branch="master")


def test_a_git_principal_with_no_reader_and_no_base_branch_is_REFUSED(tmp_path):
    """The factory will not guess. Refused at COMPOSITION — early and loud —
    rather than at hold creation, where the refusal reads as "the target could
    not be read" and points at the repository instead of the wiring."""

    from prometheus_protocol.runtime.factory import build_reobservation

    with pytest.raises(ConfigError) as refusal:
        build_reobservation(target_canonical=f"git://{tmp_path}")

    assert refusal.value.reason == "reobservation_base_branch_unknown"
    assert refusal.value.reason in CONFIG_REFUSAL_REASONS


def test_the_synthesised_observer_reads_the_base_branch_it_was_GIVEN(tmp_path):
    """The repository the default would have broken. With the base named, the
    observer reads the same base the merge proof did and the hold is created
    and pinned — the behaviour the default silently denied."""

    from prometheus_protocol.runtime.factory import build_execution_controller

    _master_repo(tmp_path)
    tool = _master_tool(tmp_path)
    assert tool.classify(BRANCH).unmerged_commits == 0
    assert tool.rev("main") is None, "this fixture must NOT have a 'main'"

    controller = build_execution_controller(
        ledger=SqliteLedger(":memory:"),
        target_canonical=f"git://{tool.repo_path}",
        base_branch="master",
    )
    observer = controller.pending.reobservation.observers[ACTION_BRANCH_DELETE]
    assert observer._tool.base_branch == "master"

    pending = _hold(controller, tool)
    assert pending.record["target_state"]["observed"] is True


def test_a_supplied_reader_and_a_conflicting_base_branch_are_refused(tmp_path):
    """Two definitions of "unmerged" for one hold. Neither silently wins: the
    caller is told, because whichever won would be a state pin that does not
    match the evidence the hold was authorized on."""

    from prometheus_protocol.runtime.factory import build_reobservation

    _master_repo(tmp_path)
    with pytest.raises(ConfigError) as refusal:
        build_reobservation(
            target_canonical=f"git://{tmp_path}",
            git_tool=_master_tool(tmp_path),
            base_branch="main",
        )

    assert refusal.value.reason == "reobservation_base_branch_conflict"
    assert refusal.value.reason in CONFIG_REFUSAL_REASONS


def test_a_supplied_reader_and_a_MATCHING_base_branch_are_accepted(tmp_path):
    """The positive control (doctrine #4). The refusal above is about the two
    disagreeing, not about naming both — without this it is consistent with a
    factory that rejects the combination outright."""

    from prometheus_protocol.runtime.factory import build_reobservation

    _master_repo(tmp_path)
    tool = _master_tool(tmp_path)
    registry = build_reobservation(
        target_canonical=f"git://{tmp_path}", git_tool=tool, base_branch="master"
    )

    assert registry.observers[ACTION_BRANCH_DELETE]._tool is tool


def test_the_demo_root_passes_its_own_reader_so_no_base_is_guessed(tmp_path):
    """``run_hero`` takes the preferred route: it hands over the GitTool the
    merge proof reads through, so there is nothing for the factory to guess.
    Pinned because that root is the one that really deletes."""

    import ast

    source = (
        Path(__file__).resolve().parents[2]
        / "src/prometheus_protocol/tools/stale_branch_demo.py"
    ).read_text(encoding="utf-8")
    calls = [
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and getattr(node.func, "id", getattr(node.func, "attr", None))
        == "build_reobservation"
    ]
    assert calls, "the demo root no longer builds a registry"
    for call in calls:
        passed = {kw.arg for kw in call.keywords}
        assert "git_tool" in passed, f"line {call.lineno} synthesises a reader"


# ---------------------------------------------------------------------------
# PART 13 — a receipt written before the subject key changed
# ---------------------------------------------------------------------------
#
# A LEDGER OUTLIVES A DEPLOYMENT. PART 9 added the pending-hold id to the
# observation subject to stop two holds sharing an attempt_id from sharing one
# receipt. A hold approved under the PREVIOUS release wrote its pre-approval
# receipt under the old spelling, and a lookup that searched only the new one
# returned None — which this method's caller reads as "there was no
# pre-approval reading", so the execution receipt said ``prior: null``.
#
# ``prior: null`` is the spelling that means "this was the first reading". The
# record would have stated that state was never checked at approval, for a hold
# where it was — a false claim inside the receipt whose entire purpose is to
# show the check happened twice.


def _approve_under_the_previous_subject_format(controller, pending_id: int):
    """Approve with the pre-upgrade subject key, then restore the current one.

    The patch is on the module the writer imports through, so the receipt
    genuinely lands under the old spelling; restoring it IS the upgrade.
    """

    from prometheus_protocol.execution import pending as pending_module

    current = pending_module.observation_subject
    pending_module.observation_subject = (
        lambda attempt_id, execution_attempt, *, pending_id: (
            f"observation:{attempt_id}#{execution_attempt}"
        )
    )
    try:
        return controller.pending.approve(pending_id, identity="reviewer")
    finally:
        pending_module.observation_subject = current


def test_a_receipt_written_before_the_upgrade_is_still_restated(tmp_path):
    """THE REPRODUCTION AND ITS CLOSURE. Approve under the old key, execute
    under the new one, and the pre-execution receipt still carries the
    approval-time reading."""

    _make_repo(tmp_path)
    controller, _, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, _tool(tmp_path))
    attempt = pending.record["attempt_id"]
    _approve_under_the_previous_subject_format(controller, pending.id)

    subjects = [o["subject"] for o in _observations(ledger)]
    assert subjects == [f"observation:{attempt}#0"], subjects

    controller.pending.require_state_unmoved_for_execution(
        pending.id, execution_attempt=1, now=CLOCK
    )

    prior = _observations(ledger)[-1]["payload"]["prior"]
    assert prior is not None, "the approval-time reading was lost across the upgrade"
    assert prior["outcome"] == OUTCOME_MATCHED
    # MARKED, never passed off as an exact match: a reader must be able to tell
    # an attribution from an identity.
    assert prior["resolved_from_pre_upgrade_subject"] is True


def test_a_receipt_written_under_the_current_key_is_NOT_marked_as_resolved(tmp_path):
    """The positive control (doctrine #4). The marker means something only if
    the ordinary path does not carry it."""

    _make_repo(tmp_path)
    controller, _, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, _tool(tmp_path))
    controller.approve(pending.id, identity="reviewer")

    prior = _observations(ledger)[-1]["payload"]["prior"]
    assert prior is not None
    assert "resolved_from_pre_upgrade_subject" not in prior


def test_two_pre_upgrade_receipts_sharing_a_subject_REFUSE_rather_than_guess(tmp_path):
    """The exact collision the new key was added to remove, met in a ledger
    written before it. Two holds shared an attempt_id under the old spelling,
    so neither receipt can be attributed to THIS hold.

    Refused, not guessed. Taking the first is how the later hold's execution
    comes to restate the earlier hold's reading — the defect that motivated the
    key change, reappearing on the upgrade path.
    """

    _make_repo(tmp_path)
    tool = _tool(tmp_path)
    controller, _, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    first = _hold(controller, tool)
    second = _hold(controller, tool)
    assert first.record["attempt_id"] == second.record["attempt_id"]

    _approve_under_the_previous_subject_format(controller, first.id)
    _approve_under_the_previous_subject_format(controller, second.id)
    subjects = [o["subject"] for o in _observations(ledger)]
    assert len(subjects) == 2 and len(set(subjects)) == 1, subjects

    with pytest.raises(StateUnobservable) as refusal:
        controller.pending.require_state_unmoved_for_execution(
            second.id, execution_attempt=1, now=CLOCK
        )

    assert refusal.value.reason == "pre_approval_receipt_ambiguous"
    assert refusal.value.reason in EXECUTION_REFUSAL_REASONS


def test_a_pinned_hold_whose_receipt_is_gone_entirely_refuses(tmp_path):
    """Neither key matches. The receipt is not merely old, it is absent, and
    executing would write ``prior: null`` for a hold that WAS checked."""

    _make_repo(tmp_path)
    controller, _, ledger = _controller(
        tmp_path, reobservation=_reobservation(tmp_path)
    )
    pending = _hold(controller, _tool(tmp_path))
    # Approve under a subject belonging to neither format.
    from prometheus_protocol.execution import pending as pending_module

    current = pending_module.observation_subject
    pending_module.observation_subject = (
        lambda attempt_id, execution_attempt, *, pending_id: (
            f"observation:elsewhere#{execution_attempt}"
        )
    )
    try:
        controller.pending.approve(pending.id, identity="reviewer")
    finally:
        pending_module.observation_subject = current

    with pytest.raises(StateUnobservable) as refusal:
        controller.pending.require_state_unmoved_for_execution(
            pending.id, execution_attempt=1, now=CLOCK
        )

    assert refusal.value.reason == "pre_approval_receipt_missing"
    assert refusal.value.reason in EXECUTION_REFUSAL_REASONS


def test_an_unpinned_hold_needs_no_receipt_and_is_not_refused(tmp_path):
    """The boundary, and the reason the guard is conditioned rather than
    blanket. A deployment that wires no re-observation pins nothing, so there
    is no reading to restate and nothing to refuse — the refusals above must
    not reach a hold that never claimed to be checked."""

    _make_repo(tmp_path)
    controller, spy, ledger = _controller(tmp_path, reobservation=None)
    pending = _hold(controller, _tool(tmp_path))
    assert pending.record["target_state"]["observed"] is False

    controller.pending.require_state_unmoved_for_execution(
        pending.id, execution_attempt=1, now=CLOCK
    )
    assert _observations(ledger) == []


# ---------------------------------------------------------------------------
# PART 14 — a base branch this tool will not read
# ---------------------------------------------------------------------------
#
# REPRODUCTION FIRST. Requiring a base branch removed the GUESS but not the
# delayed denial: an empty, whitespace-only or dash-leading base built a
# registry that looked configured, and then GitTool refused the name, the
# observer returned Unreadable naming base_tip, and every branch.delete hold
# was refused at creation as target_state_unreadable — blaming the repository
# for a wiring error, which is precisely what the composition-time refusal was
# introduced to stop.
#
# Measured before the fix: "" -> Unreadable('base_tip',); "   " and
# "--upload-pack=x" -> Unreadable('base_tip', 'unmerged_commits'). All three
# built a registry without complaint.


@pytest.mark.parametrize(
    "base",
    ["", "   ", "--upload-pack=x", "-rf", "/leading-slash", "a b"],
    ids=["empty", "whitespace", "option-injection", "dash", "slash", "space"],
)
def test_a_base_branch_this_tool_will_not_read_is_refused_at_composition(
    tmp_path, base
):
    """Every unusable spelling refuses where the operator can see it.

    The dash-leading cases are the option-injection shape ``_BRANCH_RE`` already
    refuses at the read boundary, so this adds no new security property there —
    what it adds is the diagnosis landing at the wiring instead of at the
    repository.
    """

    from prometheus_protocol.runtime.factory import build_reobservation

    with pytest.raises(ConfigError) as refusal:
        build_reobservation(target_canonical=f"git://{tmp_path}", base_branch=base)

    assert refusal.value.reason == "reobservation_base_branch_unusable"
    assert refusal.value.reason in CONFIG_REFUSAL_REASONS


def test_a_SUPPLIED_reader_carrying_an_unusable_base_is_refused_too(tmp_path):
    """BOTH routes, not just the synthesised one. A supplied ``GitTool`` whose
    base this tool will not read fails identically, and checking one route while
    trusting the other is the asymmetry this guard exists to close."""

    from prometheus_protocol.runtime.factory import build_reobservation

    _make_repo(tmp_path)
    tool = GitTool(repo_path=tmp_path, sandbox=UnsafeLocalSandbox(), base_branch="")

    with pytest.raises(ConfigError) as refusal:
        build_reobservation(target_canonical=f"git://{tmp_path}", git_tool=tool)

    assert refusal.value.reason == "reobservation_base_branch_unusable"


def test_a_usable_base_branch_is_still_accepted(tmp_path):
    """The positive control (doctrine #4). Without it the refusals above are
    consistent with a factory that has stopped accepting any base at all."""

    from prometheus_protocol.runtime.factory import build_reobservation

    _make_repo(tmp_path)
    for base in ("main", "release/1.2", "feat-a_b.c"):
        registry = build_reobservation(
            target_canonical=f"git://{tmp_path}", base_branch=base
        )
        assert registry.observers[ACTION_BRANCH_DELETE]._tool.base_branch == base


def test_the_validator_is_the_tools_OWN_rule_not_a_second_spelling(tmp_path):
    """One definition of "a branch name this tool will touch".

    A composition root that re-spelled the rule would be free to drift from the
    one the reads actually use — accepting a name the tool then refuses, which
    is the defect this part fixes, reintroduced at one remove.

    THIS TEST ASSERTED THE WRONG PROPERTY AND PASSED ANYWAY. It pinned
    ``is_usable_branch_name`` as EQUAL to ``_BRANCH_RE``, over the corpus
    ``("main", "", "   ", "--x", "a/b.c-d", "..", "a b", "0")`` on which the two
    happen to agree. Once the rule was strengthened past the charset pattern
    the equality became false — ``is_usable_branch_name("HEAD")`` is ``False``
    where ``_BRANCH_RE.match("HEAD")`` is truthy — and this test would have
    FAILED on a corpus wide enough to contain one divergent name. It did not,
    because the corpus was not.

    So it pinned the predicate TO the pattern: the drift it names in its own
    docstring, asserted as the invariant. It now checks what the name claims —
    that the root and the READS consult one function — and the identity with
    the charset pattern is asserted as a NON-property, since that pattern is a
    strict subset of the rule.
    """

    import ast
    import inspect

    from prometheus_protocol.tools.git import _BRANCH_RE, is_usable_branch_name

    # The pattern is a SUBSET, not the rule. Pinned so nobody restores the
    # equality the corpus above used to imply.
    assert _BRANCH_RE.match("HEAD") and not is_usable_branch_name("HEAD"), (
        "the predicate has collapsed back onto the charset pattern"
    )

    # And the root and the reads consult the same function. Checked on the
    # source of both, because that is the property the name claims.
    from prometheus_protocol.runtime import factory

    assert "is_usable_branch_name" in inspect.getsource(factory.build_reobservation)

    import prometheus_protocol.tools.git as git_module

    tree = ast.parse(Path(git_module.__file__).read_text(encoding="utf-8"))
    for reader in ("classify", "rev", "execute"):
        node = next(
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name == reader
        )
        called = {
            inner.func.id
            for inner in ast.walk(node)
            if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name)
        }
        assert "is_usable_branch_name" in called, (
            f"{reader} does not consult the tool's rule, so the root and the "
            "reads are two definitions again"
        )
