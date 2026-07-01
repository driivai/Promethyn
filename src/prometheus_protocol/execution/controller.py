"""Execution controller: the only path from a judged action to a side-effect.

It ties the action gate, the human hold, and the executor together. An approved
decision executes immediately; a routed one *halts* as a pending action and can
become executed **only** through :meth:`approve`, which records the human
decision before the executor is ever called; a blocked action never executes.
Every outcome is written to the ledger, so the whole chain is auditable.

The load-bearing property (INV-EXEC-3) is structural: there is no code path here
from a routed action to ``executor.execute`` that does not pass through
:meth:`approve`, and :meth:`approve` records the human's approval first.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from prometheus_protocol.core.interfaces import Ledger
from prometheus_protocol.core.models import ExecutableAction, Judgment
from prometheus_protocol.execution.models import PendingAction
from prometheus_protocol.execution.pending import (
    _DEFAULT_TTL_SECONDS,
    PendingActionService,
    _judgment_to_dict,
    _utc_now_iso,
)
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import (
    OUTCOME_APPROVE,
    OUTCOME_ROUTE,
    GateDecision,
)
from prometheus_protocol.swarm.executor import Executor
from prometheus_protocol.swarm.models import ExecutionResult


def _judgment_or_none(decision: GateDecision) -> dict | None:
    """The decision's judgment as a ledger dict, or None when it carries none."""

    return (
        _judgment_to_dict(decision.judgment) if decision.judgment is not None else None
    )


@dataclass(frozen=True)
class SubmitOutcome:
    """What happened when an action was submitted for authorization."""

    outcome: str  # OUTCOME_APPROVE / OUTCOME_ROUTE / OUTCOME_BLOCK
    decision: GateDecision
    execution: ExecutionResult | None = None
    pending: PendingAction | None = None


class ExecutionController:
    def __init__(
        self,
        *,
        gate: ActionGate,
        executor: Executor,
        ledger: Ledger,
        pending: PendingActionService | None = None,
        clock: Callable[[], str] | None = None,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        self._gate = gate
        self._executor = executor
        self._ledger = ledger
        self._clock = clock or _utc_now_iso
        self._pending = pending or PendingActionService(
            ledger, clock=self._clock, ttl_seconds=ttl_seconds
        )

    @property
    def pending(self) -> PendingActionService:
        return self._pending

    def submit(
        self,
        *,
        judgment: Judgment,
        action: ExecutableAction,
        risk_class: str = "low",
        subject_id: str = "",
    ) -> SubmitOutcome:
        """Authorize an action and act on the outcome.

        approve -> execute now; route -> halt as a pending action; block ->
        record and never execute.
        """

        decision = self._gate.decide(
            judgment, risk_class=risk_class, subject_id=subject_id, action=action
        )
        outcome = decision.effective_outcome
        if outcome == OUTCOME_APPROVE:
            result = self._execute(decision, source="auto-approved")
            return SubmitOutcome(outcome=outcome, decision=decision, execution=result)
        if outcome == OUTCOME_ROUTE:
            held = self._pending.hold(decision, risk_class=risk_class, action=action)
            return SubmitOutcome(outcome=outcome, decision=decision, pending=held)
        # Blocked: recorded for audit, never executed.
        self._ledger.record_execution(
            subject_id=subject_id,
            source="blocked",
            executed=False,
            refused=False,
            sandbox_name="",
            exit_status=None,
            detail=decision.reason,
            created_at=self._clock(),
            judgment=_judgment_or_none(decision),
        )
        return SubmitOutcome(outcome=outcome, decision=decision)

    def approve(self, pending_id: int, *, identity: str, reason: str = "") -> ExecutionResult:
        """Record a human approval, then execute the held action."""

        decision = self._pending.approve(pending_id, identity=identity, reason=reason)
        return self._execute(decision, source="human-approved")

    def reject(self, pending_id: int, *, identity: str, reason: str = "") -> None:
        """Record a human rejection. The action is never executed."""

        self._pending.reject(pending_id, identity=identity, reason=reason)

    def sweep(self, *, now: str | None = None) -> list[PendingAction]:
        """Expire lapsed pending actions (delegates to the pending service)."""

        return self._pending.sweep(now=now)

    def _execute(self, decision: GateDecision, *, source: str) -> ExecutionResult:
        result = self._executor.execute(decision)
        self._ledger.record_execution(
            subject_id=decision.subject_id,
            source=source,
            executed=result.executed,
            refused=result.refused,
            sandbox_name=result.sandbox_name,
            exit_status=result.exit_status,
            detail=result.detail,
            created_at=self._clock(),
            judgment=_judgment_or_none(decision),
        )
        return result
