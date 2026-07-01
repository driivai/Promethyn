"""Phase 1 conformance: the gate's human-routing hold.

These prove the human halt *before* any real executor exists: a low-confidence
or high-risk action cannot execute until a recorded human approval flips it, a
rejected action never executes, and the whole chain is in the ledger. They use
the no-op ``RecordingExecutor`` as a spy (its ``executed`` list is every
decision that crossed into execution), so they need no sandbox and always run.

This is INV-EXEC-3 (human halt) and INV-EXEC-4 (audit) proven at the controller
level; the sandboxed executor and its invariants are Phase 2
(``test_execution.py``).
"""

from __future__ import annotations

from prometheus_protocol.core.models import ExecutableAction, Judgment, Verdict
from prometheus_protocol.execution import ExecutionController, PendingStatus
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import (
    OUTCOME_APPROVE,
    OUTCOME_BLOCK,
    OUTCOME_ROUTE,
)
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.swarm.executor import RecordingExecutor

_CLOCK = "2026-07-01T00:00:00Z"
_ACTION = ExecutableAction(kind="python_code", code="print('act')", entry_point="")
_PASS_HIGH = Judgment(verdict=Verdict.PASS, confidence=0.99, authoritative=True)
_PASS_LOW = Judgment(verdict=Verdict.PASS, confidence=0.60, authoritative=True)
_FAIL = Judgment(verdict=Verdict.FAIL, confidence=0.99, authoritative=True)


def _controller() -> tuple[ExecutionController, RecordingExecutor, SqliteLedger]:
    ledger = SqliteLedger(":memory:")
    executor = RecordingExecutor()
    controller = ExecutionController(
        gate=ActionGate(escalate_below=0.75, route_high_risk=True),
        executor=executor,
        ledger=ledger,
        clock=lambda: _CLOCK,
    )
    return controller, executor, ledger


def test_exec_low_confidence_action_halts_as_pending():
    controller, executor, ledger = _controller()
    outcome = controller.submit(
        judgment=_PASS_LOW, action=_ACTION, risk_class="low", subject_id="a/low"
    )
    assert outcome.outcome == OUTCOME_ROUTE
    assert outcome.pending is not None and outcome.execution is None
    # It did NOT execute, and it is recorded as pending in the ledger.
    assert executor.executed == []
    rows = ledger.pending_actions(status="pending")
    assert len(rows) == 1 and rows[0]["subject_id"] == "a/low"


def test_exec_high_risk_action_halts_even_when_confident():
    controller, executor, _ = _controller()
    outcome = controller.submit(
        judgment=_PASS_HIGH, action=_ACTION, risk_class="high", subject_id="a/high"
    )
    assert outcome.outcome == OUTCOME_ROUTE
    assert executor.executed == []  # high-risk halts despite high confidence


def test_exec_recorded_human_approval_flips_pending_to_executed():
    controller, executor, ledger = _controller()
    held = controller.submit(
        judgment=_PASS_LOW, action=_ACTION, subject_id="a/appr"
    ).pending
    assert executor.executed == []  # still not executed while pending

    result = controller.approve(held.id, identity="will@driivai.com", reason="ok")
    assert result.executed
    assert len(executor.executed) == 1  # exactly one crossing, after approval

    pending = controller.pending.get(held.id)
    assert pending.status == PendingStatus.APPROVED
    assert pending.human_decision.identity == "will@driivai.com"
    assert pending.human_decision.timestamp == _CLOCK
    assert pending.human_decision.reason == "ok"


def test_exec_rejected_pending_never_executes():
    controller, executor, ledger = _controller()
    held = controller.submit(
        judgment=_PASS_LOW, action=_ACTION, subject_id="a/rej"
    ).pending
    controller.reject(held.id, identity="will@driivai.com", reason="not now")
    assert executor.executed == []  # a rejected action is never executed
    assert controller.pending.get(held.id).status == PendingStatus.REJECTED
    # No execution row was written for the rejected action.
    assert ledger.executions() == []


def test_exec_blocked_action_never_executes():
    controller, executor, ledger = _controller()
    outcome = controller.submit(judgment=_FAIL, action=_ACTION, subject_id="a/block")
    assert outcome.outcome == OUTCOME_BLOCK
    assert outcome.execution is None and executor.executed == []
    blocked = ledger.executions()
    assert len(blocked) == 1 and blocked[0]["source"] == "blocked"
    assert blocked[0]["executed"] is False


def test_exec_auto_approved_high_confidence_executes():
    controller, executor, _ = _controller()
    outcome = controller.submit(
        judgment=_PASS_HIGH, action=_ACTION, risk_class="low", subject_id="a/auto"
    )
    assert outcome.outcome == OUTCOME_APPROVE
    assert outcome.execution is not None and outcome.execution.executed
    assert len(executor.executed) == 1


def test_exec_full_human_cycle_is_in_the_audit_chain():
    controller, _executor, ledger = _controller()
    held = controller.submit(judgment=_PASS_LOW, action=_ACTION, subject_id="a/audit").pending
    controller.approve(held.id, identity="will@driivai.com", reason="reviewed")

    # The pending row carries the human decision, re-readable end to end.
    row = ledger.pending_action(held.id)
    assert row["status"] == "approved"
    assert row["decided_by"] == "will@driivai.com"
    assert row["decided_at"] == _CLOCK
    assert row["decision_reason"] == "reviewed"
    # The execution is recorded and attributed to the human approval.
    execs = ledger.executions()
    assert len(execs) == 1 and execs[0]["source"] == "human-approved"
    assert execs[0]["subject_id"] == "a/audit"


def test_exec_a_decided_action_cannot_be_re_decided():
    controller, _executor, _ledger = _controller()
    held = controller.submit(judgment=_PASS_LOW, action=_ACTION, subject_id="a/twice").pending
    controller.approve(held.id, identity="will@driivai.com")
    # A human decision is never silently overwritten.
    import pytest

    with pytest.raises(ValueError):
        controller.approve(held.id, identity="someone-else")
    with pytest.raises(ValueError):
        controller.reject(held.id, identity="someone-else")
