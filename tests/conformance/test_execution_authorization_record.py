"""The execution authorization record, and the chain it is bound into (TASK 6).

Three things this file has to carry, each stated by the brief and each a test:

(a) TAMPER-EVIDENCE BINDING. A hold's pinned record is written into the audit
    chain under the hold's identity, and approval requires the row to match
    its entry on a chain that verifies. An altered pinned requirement set is
    DETECTED — and the limit is a passing test: rewrite the row, the entry and
    every later hash, and without an external anchor nothing sees it.
(c) THE REFUSING PATH EXERCISES COVERAGE. Every Checkpoint-B proof that refuses
    does so before ``judge_covered`` runs, which is how a positional-``Evidence``
    defect that put the implementation name into ``stdout`` survived every
    refusal test. Here coverage runs to completion on both sides — satisfied,
    and refused by a real coverage row — and the record says which row.
(b) lives in ``docs/threat-model.md`` §3.6 and ``docs/execution-authorization-record.md``.
"""

from __future__ import annotations

import json

import pytest

from prometheus_protocol.core.models import (
    ACTION_PYTHON_CODE,
    Evidence,
    ExecutableAction,
    Judgment,
    Tier,
    Unavailability,
    Unavailable,
    Verdict,
)
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.models import PendingStatus
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import GateDecision
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.ledger.tip_anchor import FileTipAnchor
from prometheus_protocol.policy.coverage import (
    REFUSED_ABSTAINED,
    REFUSED_ADVISORY_ONLY,
    REFUSED_INCOMPLETE,
    REFUSED_INVALID_EVIDENCE,
    REFUSED_UNSATISFACTORY,
    BoundResult,
)
from prometheus_protocol.policy.execution import (
    ExecutionAuthorizer,
    ExecutionNotAuthorized,
)
from prometheus_protocol.policy.profile import (
    PolicyRequirement,
    VerificationPolicy,
    policy_digest,
)
from prometheus_protocol.policy.record import PINNED_HOLD_EVENT, RECORD_VERSION
from prometheus_protocol.policy.resolver import resolve
from prometheus_protocol.policy.snapshot import ACTION_SANDBOX_EXECUTE, snapshot_digest
from prometheus_protocol.swarm.executor import Executor
from prometheus_protocol.swarm.models import ExecutionResult, content_hash
from prometheus_protocol.verifier.bank import VerifierBank
from tests.support.chain_rewrite import rewrite_entry_and_rehash

TARGET = "sandbox://record"
ATTEMPT = "attempt-1"
CLOCK = "2026-09-12T00:00:00+00:00"

#: Two requirements, two permitted implementations on one of them, so the
#: record has something to say: WHICH answered, WHICH could not.
POLICY = VerificationPolicy(
    policy_id="record-test",
    version=3,
    requirements=(
        PolicyRequirement(
            check_id="run",
            permitted=("runner-a", "runner-b"),
            applies_to=(ACTION_SANDBOX_EXECUTE,),
        ),
        PolicyRequirement(
            check_id="audit", permitted=("auditor",), applies_to=(ACTION_SANDBOX_EXECUTE,)
        ),
    ),
    require_verification=(ACTION_SANDBOX_EXECUTE,),
)


def action(code: str = "print('record')") -> ExecutableAction:
    return ExecutableAction(kind=ACTION_PYTHON_CODE, code=code)


def snapshot(a: ExecutableAction, policy: VerificationPolicy = POLICY):
    return resolve(
        policy,
        artifact_sha256=content_hash(a.code),
        target_canonical=TARGET,
        action_class=ACTION_SANDBOX_EXECUTE,
        attempt_id=ATTEMPT,
    )


def evidence(
    implementation: str,
    verdict: Verdict = Verdict.PASS,
    *,
    tier: Tier = Tier.HARD,
    verifier_id: str | None = None,
) -> Evidence:
    passed = verdict == Verdict.PASS
    return Evidence(
        passed=passed,
        total=1,
        passed_count=1 if passed else 0,
        failures=() if passed else ("case failed",),
        verifier_id=implementation if verifier_id is None else verifier_id,
        verdict=verdict,
        tier=tier,
    )


def unavailable(implementation: str) -> Unavailable:
    return Unavailable(
        verifier_id=implementation,
        tier=Tier.HARD,
        reason=Unavailability.INFRA_FAULT,
        detail="no sandbox",
    )


def bound(s, check_id: str, implementation: str, outcome) -> BoundResult:
    return BoundResult(
        check_id=check_id,
        snapshot_digest=snapshot_digest(s),
        implementation=implementation,
        outcome=outcome,
    )


def assess(a: ExecutableAction, results, policy: VerificationPolicy = POLICY):
    return VerifierBank(policy_supplier=lambda: policy).assess(snapshot(a, policy), results)


def satisfied(a: ExecutableAction):
    """runner-a answers, runner-b could not, the auditor passes: coverage HOLDS
    and has both an answer and an unavailability to record."""

    s = snapshot(a)
    return assess(
        a,
        [
            bound(s, "run", "runner-a", evidence("runner-a")),
            bound(s, "run", "runner-b", unavailable("runner-b")),
            bound(s, "audit", "auditor", evidence("auditor")),
        ],
    )


class Spy(Executor):
    def __init__(self, *, refuse: bool = False) -> None:
        self.calls: list[GateDecision] = []
        self._refuse = refuse

    def execute(self, decision: GateDecision) -> ExecutionResult:
        self.calls.append(decision)
        if self._refuse:
            return ExecutionResult(
                executed=False, subject_id=decision.subject_id, refused=True, detail="no sandbox"
            )
        return ExecutionResult(executed=True, subject_id=decision.subject_id)


def controller(
    ledger: SqliteLedger | None = None,
    *,
    route_high_risk: bool = False,
    policy: VerificationPolicy = POLICY,
    spy: Spy | None = None,
):
    ledger = ledger if ledger is not None else SqliteLedger(":memory:")
    spy = spy if spy is not None else Spy()
    gate = ActionGate(
        authorizer=ExecutionAuthorizer(lambda: policy),
        target_canonical=TARGET,
        route_high_risk=route_high_risk,
    )
    return ExecutionController(gate=gate, executor=spy, ledger=ledger, clock=lambda: CLOCK), spy, ledger


def hold(ctl, a: ExecutableAction):
    """A hold with a REAL coverage-validated assessment: high risk routes it."""

    held = ctl.submit(assessment=satisfied(a), action=a, attempt_id=ATTEMPT, risk_class="high").pending
    assert held is not None
    return held


def chain_entry_for(ledger: SqliteLedger, pending_id: int) -> dict:
    entries = [
        e
        for e in ledger.chained_events()
        if e["event"] == PINNED_HOLD_EVENT and e["subject"] == f"pending:{pending_id}"
    ]
    assert len(entries) == 1, entries
    return entries[0]


def weakened(record: dict) -> dict:
    """The R1 shape, one layer down: the row now says only ``run`` was required."""

    altered = json.loads(json.dumps(record))
    altered["requirements"] = [r for r in record["requirements"] if r["check_id"] != "audit"]
    return altered


# ---------------------------------------------------------------------------
# The record itself (R5, R6)
# ---------------------------------------------------------------------------


def test_a_hold_persists_a_versioned_record_with_the_pinned_resolution():
    ctl, spy, ledger = controller(route_high_risk=True)
    a = action()
    held = hold(ctl, a)

    row = ledger.pending_action(held.id)
    record = row["authorization"]
    assert held.record == record
    assert record["record_version"] == RECORD_VERSION
    assert record["policy_id"] == "record-test"
    assert record["policy_version"] == 3
    assert record["policy_digest"] == policy_digest(POLICY)
    assert record["snapshot_digest"] == snapshot_digest(snapshot(a))
    assert record["attempt_id"] == ATTEMPT
    assert record["artifact_sha256"] == content_hash(a.code)
    assert record["target_canonical"] == TARGET
    assert record["action_class"] == ACTION_SANDBOX_EXECUTE
    # R5: the resolved requirements, in the resolver's canonical order.
    assert record["requirements"] == [
        {"check_id": "audit", "permitted": ["auditor"]},
        {"check_id": "run", "permitted": ["runner-a", "runner-b"]},
    ]
    # R6: what answered, what could not, and that the report is a real one.
    coverage = record["coverage"]
    assert coverage["recorded"] is True
    assert coverage["answered_by"] == {"audit": "auditor", "run": "runner-a"}
    assert coverage["unavailable"] == [{"check_id": "run", "implementation": "runner-b"}]
    assert coverage["refusal"] is None
    assert coverage["outcome_kind"] == "judgment" and coverage["verdict"] == "pass"
    assert record["pinned_at"] == CLOCK == held.created_at
    assert spy.calls == []


def test_the_hold_record_is_bound_into_the_audit_chain_under_the_holds_identity():
    ctl, _spy, ledger = controller(route_high_risk=True)
    held = hold(ctl, action())
    entry = chain_entry_for(ledger, held.id)
    assert json.loads(entry["payload"]) == held.record
    assert ledger.verify_chain().ok


def test_an_auto_approved_execution_row_carries_the_record():
    """(c), the satisfied side: coverage ran to completion, the action executed,
    and the row that says so says which implementation answered."""

    ctl, spy, ledger = controller()
    a = action()
    outcome = ctl.submit(assessment=satisfied(a), action=a, attempt_id=ATTEMPT)
    assert outcome.execution is not None and outcome.execution.executed
    assert len(spy.calls) == 1
    row = ledger.executions()[-1]
    assert row["source"] == "auto-approved" and row["executed"]
    record = row["authorization"]
    assert record["record_version"] == RECORD_VERSION
    assert record["coverage"]["answered_by"] == {"audit": "auditor", "run": "runner-a"}
    assert record["coverage"]["unavailable"] == [
        {"check_id": "run", "implementation": "runner-b"}
    ]
    assert record["policy_version"] == 3


def test_a_human_approved_execution_row_carries_the_PINNED_record():
    ctl, spy, ledger = controller(route_high_risk=True)
    held = hold(ctl, action())
    result = ctl.approve(held.id, identity="human")
    assert result.executed and len(spy.calls) == 1
    row = ledger.executions()[-1]
    assert row["source"] == "human-approved" and row["pending_id"] == held.id
    assert row["authorization"] == held.record, "the execution row must carry the hold's pinned record, byte for byte"


# ---------------------------------------------------------------------------
# (c) coverage runs to completion and REFUSES on a real coverage row
# ---------------------------------------------------------------------------


def _results_for(kind: str, s):
    audit = bound(s, "audit", "auditor", evidence("auditor"))
    if kind == "invalid_evidence":
        # The result names runner-a and the evidence names someone else — the
        # exact row the positional-Evidence defect hid behind.
        return [bound(s, "run", "runner-a", evidence("runner-a", verifier_id="someone-else")), audit]
    if kind == "abstained":
        return [bound(s, "run", "runner-a", evidence("runner-a", Verdict.ABSTAIN)), audit]
    if kind == "incomplete":
        return [audit]
    if kind == "advisory_only":
        return [bound(s, "run", "runner-a", evidence("runner-a", tier=Tier.SOFT)), audit]
    if kind == "unsatisfactory":
        return [bound(s, "run", "runner-a", evidence("runner-a", Verdict.FAIL)), audit]
    raise AssertionError(kind)


_REFUSING_ROWS = {
    "invalid_evidence": (REFUSED_INVALID_EVIDENCE, "unavailable", Unavailability.POLICY_REFUSAL),
    "abstained": (REFUSED_ABSTAINED, "unavailable", Unavailability.POLICY_REFUSAL),
    "incomplete": (REFUSED_INCOMPLETE, "unavailable", Unavailability.INFRA_FAULT),
    "advisory_only": (REFUSED_ADVISORY_ONLY, "unavailable", Unavailability.POLICY_REFUSAL),
}


@pytest.mark.parametrize("kind", sorted(_REFUSING_ROWS))
def test_a_submission_refused_by_a_real_coverage_row_records_which_row(kind):
    """Coverage RAN — every result was validated, the requirement was decided
    — and refused. The refusal arrives at the gate as an Unavailable, is
    recorded distinctly, executes nothing, and the record names the row."""

    reason, source, unavailability = _REFUSING_ROWS[kind]
    ctl, spy, ledger = controller()
    a = action()
    assessed = assess(a, _results_for(kind, snapshot(a)))
    assert isinstance(assessed.outcome, Unavailable)
    assert assessed.coverage.refusal is not None and assessed.coverage.refusal[0] == reason

    outcome = ctl.submit(assessment=assessed, action=a, attempt_id=ATTEMPT)
    assert outcome.outcome == "unavailable" and outcome.execution is None
    assert spy.calls == []
    row = ledger.executions()[-1]
    assert row["source"] == source and row["refused"] and not row["executed"]
    coverage = row["authorization"]["coverage"]
    assert coverage["refusal"]["reason"] == reason
    assert coverage["refusal"]["check_id"] == "run"
    assert coverage["outcome_kind"] == "unavailable"
    assert coverage["unavailable_reason"] == unavailability.value
    assert coverage["recorded"] is True


def test_a_FAILED_required_check_is_refused_at_the_gate_and_the_row_records_the_row():
    """The one refusing row that produces a VERDICT: the check ran and said no.
    The bank reports an authoritative FAIL, the gate blocks it, and the blocked
    row's record says ``coverage.unsatisfactory``."""

    ctl, spy, ledger = controller()
    a = action()
    assessed = assess(a, _results_for("unsatisfactory", snapshot(a)))
    assert isinstance(assessed.outcome, Judgment) and assessed.outcome.verdict == Verdict.FAIL
    outcome = ctl.submit(assessment=assessed, action=a, attempt_id=ATTEMPT)
    assert outcome.outcome == "block" and spy.calls == []
    row = ledger.executions()[-1]
    assert row["source"] == "blocked"
    coverage = row["authorization"]["coverage"]
    assert coverage["refusal"]["reason"] == REFUSED_UNSATISFACTORY
    assert coverage["outcome_kind"] == "judgment" and coverage["verdict"] == "fail"


def test_an_assessment_minted_without_coverage_validation_says_so_in_the_record():
    """The test forge mints around a caller-named outcome. Its record must not
    read as "nothing was unavailable"; it reads as "no coverage report"."""

    from prometheus_protocol.policy.assessment import mint

    ctl, spy, ledger = controller()
    a = action()
    forged = mint(snapshot(a), Judgment(verdict=Verdict.PASS, confidence=1.0, authoritative=True))
    ctl.submit(assessment=forged, action=a, attempt_id=ATTEMPT)
    assert len(spy.calls) == 1
    coverage = ledger.executions()[-1]["authorization"]["coverage"]
    assert coverage["recorded"] is False
    assert coverage["answered_by"] == {} and coverage["unavailable"] == []


# ---------------------------------------------------------------------------
# (a) the tamper-evidence binding
# ---------------------------------------------------------------------------


def test_an_altered_pinned_requirement_set_is_detected_at_approval():
    """A database write weakens the row's requirements. The chain entry still
    carries the real ones, so approval sees the mismatch and refuses. Nothing
    executes, the chain itself is still valid (only the row was touched), and
    the hold is left pending — this is tampering, not a rotation."""

    ctl, spy, ledger = controller(route_high_risk=True)
    held = hold(ctl, action())
    ledger._conn.execute(
        "UPDATE pending_actions SET authorization = ? WHERE id = ?",
        (json.dumps(weakened(held.record)), held.id),
    )
    ledger._conn.commit()
    with pytest.raises(ExecutionNotAuthorized, match="does not match its tamper-evident chain entry"):
        ctl.approve(held.id, identity="human")
    assert spy.calls == []
    assert ledger.verify_chain().ok
    assert ctl.pending.get(held.id).status == PendingStatus.PENDING


def test_an_altered_chain_entry_breaks_the_chain_and_approval_refuses():
    """The adversary edits the entry to match the weakened row but does not
    re-hash: the row and the entry now agree, and the chain no longer verifies."""

    ctl, spy, ledger = controller(route_high_risk=True)
    held = hold(ctl, action())
    altered = weakened(held.record)
    entry = chain_entry_for(ledger, held.id)
    ledger._conn.execute(
        "UPDATE pending_actions SET authorization = ? WHERE id = ?",
        (json.dumps(altered), held.id),
    )
    ledger._conn.execute(
        "UPDATE audit_chain SET payload = ? WHERE seq = ?",
        (json.dumps(altered, sort_keys=True, separators=(",", ":")), entry["seq"]),
    )
    ledger._conn.commit()
    assert not ledger.verify_chain().ok
    with pytest.raises(ExecutionNotAuthorized, match="did not verify"):
        ctl.approve(held.id, identity="human")
    assert spy.calls == []


def test_the_named_limit_a_full_rewrite_is_NOT_detected_without_an_anchor_and_IS_with_one(tmp_path):
    """The chain binding inherits the chain's own limit, stated as a passing test
    (doctrine #5): an adversary who rewrites the row, the entry AND every later
    hash produces a self-consistent chain, and without an external anchor
    approval proceeds on the lying record. With an anchor the rewrite is
    BROKEN at the anchored seq and approval refuses. Both halves are asserted,
    so the limit cannot quietly become either wider or narrower.

    Note what the lying record does and does not buy: enforcement still
    re-resolves the selected policy for the action (the digest the record
    carries commits to the REAL requirements), so the weakened list misleads
    a reviewer and authorizes nothing extra. The record's integrity is what is
    at stake here, and that is what the anchor restores."""

    # Without an anchor: not detected.
    ctl, spy, ledger = controller(route_high_risk=True)
    held = hold(ctl, action())
    altered = weakened(held.record)
    ledger._conn.execute(
        "UPDATE pending_actions SET authorization = ? WHERE id = ?",
        (json.dumps(altered), held.id),
    )
    ledger._conn.commit()
    rewrite_entry_and_rehash(ledger, seq=chain_entry_for(ledger, held.id)["seq"], payload=altered)
    assert ledger.verify_chain().ok, "the rewrite must be self-consistent or this proves nothing"
    result = ctl.approve(held.id, identity="human")
    assert result.executed and len(spy.calls) == 1
    assert ledger.executions()[-1]["authorization"] == altered

    # With an anchor: BROKEN, and refused.
    anchored = SqliteLedger(tmp_path / "ledger.db", tip_anchor=FileTipAnchor(tmp_path / "tip.json"))
    ctl2, spy2, _ = controller(anchored, route_high_risk=True)
    held2 = hold(ctl2, action())
    altered2 = weakened(held2.record)
    anchored._conn.execute(
        "UPDATE pending_actions SET authorization = ? WHERE id = ?",
        (json.dumps(altered2), held2.id),
    )
    anchored._conn.commit()
    rewrite_entry_and_rehash(anchored, seq=chain_entry_for(anchored, held2.id)["seq"], payload=altered2)
    verdict = anchored.verify_chain()
    assert not verdict.ok and verdict.status == "broken", verdict.render()
    with pytest.raises(ExecutionNotAuthorized, match="did not verify"):
        ctl2.approve(held2.id, identity="human")
    assert spy2.calls == []


def test_a_pre_record_blob_is_refused_as_reverification_required():
    """The seven-field blob holds carried before records existed is not a
    record: no version, no requirements, no coverage. It is refused the way a
    NULL is, not read as a record with empty fields."""

    ctl, spy, ledger = controller(route_high_risk=True)
    held = hold(ctl, action())
    legacy = {
        key: held.record[key]
        for key in (
            "snapshot_digest", "policy_id", "policy_digest", "artifact_sha256",
            "target_canonical", "action_class", "attempt_id",
        )
    }
    ledger._conn.execute(
        "UPDATE pending_actions SET authorization = ? WHERE id = ?",
        (json.dumps(legacy), held.id),
    )
    ledger._conn.commit()
    assert ctl.pending.get(held.id).record is None
    with pytest.raises(ExecutionNotAuthorized, match="re-verification is required"):
        ctl.approve(held.id, identity="human")
    assert spy.calls == []


def test_a_hold_with_no_chain_entry_cannot_be_approved():
    """The fail-closed direction of a chain append that never happened."""

    ctl, spy, ledger = controller(route_high_risk=True)
    held = hold(ctl, action())
    entry = chain_entry_for(ledger, held.id)
    ledger._conn.execute("DELETE FROM audit_chain WHERE seq = ?", (entry["seq"],))
    ledger._conn.commit()
    with pytest.raises(ExecutionNotAuthorized, match="0 tamper-evident chain entries"):
        ctl.approve(held.id, identity="human")
    assert spy.calls == []
