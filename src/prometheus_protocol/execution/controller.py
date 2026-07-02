"""Execution controller: the only path from a judged action to a side-effect.

It ties the action gate, the human hold, and the executor together. An approved
decision executes immediately; a routed one *halts* as a pending action and can
become executed **only** through :meth:`approve`, which records the human
decision before the executor is ever called; a blocked action never executes.
Every outcome is written to the ledger, so the whole chain is auditable.

The load-bearing property (INV-EXEC-3) is structural: there is no code path here
from a routed action to ``executor.execute`` that does not pass through
:meth:`approve`, and :meth:`approve` records the human's approval first.
:meth:`retry_execution` preserves it: it re-drives only a hold whose human
approval is already recorded and whose execution never happened, through the
same executor path — it can approve nothing.
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
        # Opportunistic expiry (belt): a controller coming up sweeps lapsed
        # holds, so TTL enforcement does not depend on an operator remembering
        # to run `sweep`. The approval-time stale-guard in the pending service
        # stays authoritative (suspenders) — this only makes expiry happen
        # sooner, never later. Idempotent and fully audited, like any sweep.
        self._pending.sweep()

    @property
    def pending(self) -> PendingActionService:
        return self._pending

    def list_pending(self) -> list[PendingAction]:
        """Open holds awaiting a human, with lapsed ones expired first.

        Sweeping before listing (another opportunistic touchpoint) means the
        list never shows a hold that has already lapsed as if it were still
        approvable.
        """

        self._pending.sweep()
        return self._pending.list_pending()

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

        # Opportunistic expiry before deciding: any hold that has lapsed by now
        # (including this one) is expired first. The pending service's own
        # stale-guard re-checks at decision time regardless, so approval of a
        # lapsed hold is refused even when this sweep is bypassed.
        self._pending.sweep()
        decision = self._pending.approve(pending_id, identity=identity, reason=reason)
        return self._execute(decision, source="human-approved", pending_id=pending_id)

    def reject(self, pending_id: int, *, identity: str, reason: str = "") -> None:
        """Record a human rejection. The action is never executed."""

        self._pending.reject(pending_id, identity=identity, reason=reason)

    def retry_execution(
        self, pending_id: int, *, identity: str, reason: str = ""
    ) -> ExecutionResult:
        """Re-drive execution for an approved hold that has never executed.

        Narrow by design: valid only when the hold is approved and its execution
        was refused (fail-closed) or deferred — never for a pending, rejected,
        expired, or already-executed hold, and never past the approval's TTL
        window. It re-opens nothing: the human decision record is untouched, and
        execution goes through the same gated, sandboxed, fail-closed
        :meth:`_execute` path as an approval. Every attempt is recorded — an
        ineligible retry as a refused audit row, an eligible one as a normal
        execution row (executed, or refused again by a still-missing sandbox).
        """

        try:
            decision = self._pending.retry_decision(pending_id, identity=identity)
        except ValueError as exc:
            # The id exists but is ineligible: record the refused attempt, so
            # even misuse of the retry verb is auditable, then surface the error.
            pending = self._pending.get(pending_id)
            self._ledger.record_execution(
                subject_id=pending.subject_id if pending is not None else "",
                source="retry-refused",
                executed=False,
                refused=True,
                sandbox_name="",
                exit_status=None,
                detail=f"retry by {identity} refused: {exc}",
                created_at=self._clock(),
                judgment=(
                    _judgment_to_dict(pending.judgment) if pending is not None else None
                ),
                pending_id=pending_id,
            )
            raise
        prefix = f"retry of hold #{pending_id} by {identity}"
        if reason:
            prefix += f" ({reason})"
        return self._execute(
            decision,
            source="human-approved-retry",
            pending_id=pending_id,
            detail_prefix=f"{prefix}: ",
        )

    def sweep(self, *, now: str | None = None) -> list[PendingAction]:
        """Expire lapsed pending actions (delegates to the pending service)."""

        return self._pending.sweep(now=now)

    def _execute(
        self,
        decision: GateDecision,
        *,
        source: str,
        pending_id: int | None = None,
        detail_prefix: str = "",
    ) -> ExecutionResult:
        # At-most-once execution per hold: atomically claim the right to run
        # before calling the executor, so two concurrent drivers (a second
        # approve racing the first, or concurrent retries) cannot both execute.
        # The auto-approved path carries no hold (pending_id is None) and needs
        # no claim. This never touches the human decision record.
        if pending_id is not None and not self._ledger.claim_pending_execution(
            pending_id, self._clock()
        ):
            refused = ExecutionResult(
                executed=False,
                subject_id=decision.subject_id,
                detail=(
                    f"{detail_prefix}refused: an execution for hold #{pending_id} "
                    "is already in progress or has completed"
                ),
                refused=True,
            )
            self._ledger.record_execution(
                subject_id=decision.subject_id,
                source=source,
                executed=False,
                refused=True,
                sandbox_name="",
                exit_status=None,
                detail=refused.detail,
                created_at=self._clock(),
                judgment=_judgment_or_none(decision),
                pending_id=pending_id,
            )
            return refused
        result = self._executor.execute(decision)
        self._ledger.record_execution(
            subject_id=decision.subject_id,
            source=source,
            executed=result.executed,
            refused=result.refused,
            sandbox_name=result.sandbox_name,
            exit_status=result.exit_status,
            detail=f"{detail_prefix}{result.detail}",
            created_at=self._clock(),
            judgment=_judgment_or_none(decision),
            pending_id=pending_id,
        )
        # A fail-closed refusal has no side-effect: release the claim so the
        # approved hold stays retry-eligible. A successful execution keeps its
        # claim, so the hold cannot execute again.
        if pending_id is not None and result.refused:
            self._ledger.release_pending_execution(pending_id)
        return result
