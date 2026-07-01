"""The pending-action service: hold routed actions for a human, via the ledger.

This is where a routed :class:`GateDecision` is parked and later resolved. It is
also the *only* place a held action becomes an approved decision the executor
may run — and only after the human's approval has been written to the ledger.
Constructing that approving :class:`GateDecision` here (never on the swarm side)
keeps the proposer/judge wall intact: the human is the HUMAN-tier authority.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from prometheus_protocol.core.interfaces import Ledger
from prometheus_protocol.core.models import ExecutableAction, Judgment, Verdict
from prometheus_protocol.execution.models import (
    HumanDecision,
    PendingAction,
    PendingStatus,
)
from prometheus_protocol.gate.promotion import (
    OUTCOME_APPROVE,
    OUTCOME_ROUTE,
    GateDecision,
)


#: Default time-to-live for a pending human hold (24h). Mirrors Config.
_DEFAULT_TTL_SECONDS = 86_400


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(timestamp: str) -> datetime:
    """Parse an ISO-8601 timestamp, tolerating a trailing ``Z`` and naive values.

    A naive timestamp is read as UTC so a duration comparison always has a
    timezone on both sides. (``datetime.fromisoformat`` before 3.11 rejects the
    ``Z`` suffix that the tests use.)
    """

    text = timestamp.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _action_to_dict(action: ExecutableAction) -> dict:
    return {"kind": action.kind, "code": action.code, "entry_point": action.entry_point}


def _action_from_dict(data: dict) -> ExecutableAction:
    return ExecutableAction(
        kind=data["kind"],
        code=data["code"],
        entry_point=data.get("entry_point", ""),
    )


def _judgment_to_dict(judgment: Judgment) -> dict:
    return {
        "verdict": judgment.verdict.value,
        "confidence": judgment.confidence,
        "authoritative": judgment.authoritative,
        "contributing": list(judgment.contributing),
        "conflict": judgment.conflict,
        "detail": judgment.detail,
    }


def _judgment_from_dict(data: dict) -> Judgment:
    return Judgment(
        verdict=Verdict(data["verdict"]),
        confidence=float(data["confidence"]),
        authoritative=bool(data["authoritative"]),
        contributing=tuple(data.get("contributing", ())),
        conflict=bool(data.get("conflict", False)),
        detail=data.get("detail", ""),
    )


class PendingActionService:
    """Persists routed actions and records the human decision that resolves them.

    The clock is injectable so timestamps are deterministic in tests; it returns
    an ISO-8601 string.
    """

    def __init__(
        self,
        ledger: Ledger,
        *,
        clock: Callable[[], str] | None = None,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        self._ledger = ledger
        self._clock = clock or _utc_now_iso
        self._ttl_seconds = ttl_seconds

    # -- holding -----------------------------------------------------------

    def hold(
        self,
        decision: GateDecision,
        *,
        risk_class: str = "low",
        action: ExecutableAction | None = None,
    ) -> PendingAction:
        """Park a routed decision as a pending action awaiting a human."""

        if decision.effective_outcome != OUTCOME_ROUTE:
            raise ValueError("only a routed gate decision can be held for a human")
        action = action if action is not None else decision.action
        if action is None:
            raise ValueError("a routed action must carry an ExecutableAction to hold")
        judgment = decision.judgment
        if judgment is None:
            raise ValueError("a routed action must carry the judgment it rests on")

        created = self._clock()
        pending_id = self._ledger.record_pending_action(
            subject_id=decision.subject_id,
            risk_class=risk_class,
            reason=decision.reason,
            verdict=judgment.verdict.value,
            confidence=judgment.confidence,
            action=_action_to_dict(action),
            judgment=_judgment_to_dict(judgment),
            created_at=created,
        )
        return PendingAction(
            id=pending_id,
            subject_id=decision.subject_id,
            risk_class=risk_class,
            reason=decision.reason,
            action=action,
            judgment=judgment,
            status=PendingStatus.PENDING,
            created_at=created,
            human_decision=None,
        )

    # -- reading -----------------------------------------------------------

    def list_pending(self) -> list[PendingAction]:
        rows = self._ledger.pending_actions(status=PendingStatus.PENDING.value)
        return [self._from_row(row) for row in rows]

    def all(self) -> list[PendingAction]:
        return [self._from_row(row) for row in self._ledger.pending_actions()]

    def get(self, pending_id: int) -> PendingAction | None:
        row = self._ledger.pending_action(pending_id)
        return self._from_row(row) if row is not None else None

    # -- resolving ---------------------------------------------------------

    def approve(
        self,
        pending_id: int,
        *,
        identity: str,
        reason: str = "",
        now: str | None = None,
    ) -> GateDecision:
        """Record a human approval and return the decision the executor may run.

        This is the sole construction of an *approving* decision from a held
        action: the human is the authority. The ledger write happens first, so
        no execution can follow an unrecorded approval.
        """

        pending = self._require_pending(pending_id)
        timestamp = now or self._clock()
        self._ledger.resolve_pending_action(
            pending_id,
            status=PendingStatus.APPROVED.value,
            decided_by=identity,
            decided_at=timestamp,
            decision_reason=reason,
        )
        detail = f"human-approved by {identity} at {timestamp}"
        if reason:
            detail += f": {reason}"
        return GateDecision(
            approved=True,
            subject_id=pending.subject_id,
            judgment=pending.judgment,
            reason=detail,
            outcome=OUTCOME_APPROVE,
            action=pending.action,
        )

    def reject(
        self,
        pending_id: int,
        *,
        identity: str,
        reason: str = "",
        now: str | None = None,
    ) -> None:
        """Record a human rejection. A rejected action can never execute."""

        self._require_pending(pending_id)
        timestamp = now or self._clock()
        self._ledger.resolve_pending_action(
            pending_id,
            status=PendingStatus.REJECTED.value,
            decided_by=identity,
            decided_at=timestamp,
            decision_reason=reason,
        )

    # -- expiry ------------------------------------------------------------

    def sweep(self, *, now: str | None = None) -> list[PendingAction]:
        """Expire every pending action older than the TTL. Idempotent.

        A lapsed hold transitions pending -> EXPIRED in the ledger (an audited
        transition) and can never be approved or executed thereafter. Running
        the sweep again is a no-op — an already-decided hold is not re-touched.
        Returns the actions expired by this call.
        """

        timestamp = now or self._clock()
        expired: list[PendingAction] = []
        for row in self._ledger.pending_actions(status=PendingStatus.PENDING.value):
            pending = self._from_row(row)
            if self._is_lapsed(pending, now=timestamp):
                self._expire(pending.id, now=timestamp)
                refreshed = self.get(pending.id)
                if refreshed is not None:
                    expired.append(refreshed)
        return expired

    def _is_lapsed(self, pending: PendingAction, *, now: str) -> bool:
        if self._ttl_seconds <= 0:
            return False  # expiry disabled: holds live until decided
        elapsed = (_parse_iso(now) - _parse_iso(pending.created_at)).total_seconds()
        return elapsed >= self._ttl_seconds

    def _expire(self, pending_id: int, *, now: str) -> None:
        # Reuses the single resolver, which only ever transitions a still-pending
        # row — so this is idempotent and never overwrites a human decision.
        self._ledger.resolve_pending_action(
            pending_id,
            status=PendingStatus.EXPIRED.value,
            decided_by="system:sweep",
            decided_at=now,
            decision_reason=f"expired after {self._ttl_seconds}s TTL",
        )

    def _require_pending(self, pending_id: int) -> PendingAction:
        pending = self.get(pending_id)
        if pending is None:
            raise KeyError(f"no pending action with id {pending_id}")
        if pending.status != PendingStatus.PENDING:
            raise ValueError(
                f"pending action {pending_id} is already {pending.status.value}"
            )
        return pending

    @staticmethod
    def _from_row(row: dict) -> PendingAction:
        # A human_decision records an actual human approve/reject. A system
        # expiry is a transition audited in the row (status/decided_at/reason),
        # not a human decision, so it is not surfaced here.
        human_decision = None
        if row["status"] in (
            PendingStatus.APPROVED.value,
            PendingStatus.REJECTED.value,
        ) and row.get("decided_by"):
            human_decision = HumanDecision(
                decision=row["status"],
                identity=row["decided_by"],
                timestamp=row.get("decided_at") or "",
                reason=row.get("decision_reason") or "",
            )
        return PendingAction(
            id=row["id"],
            subject_id=row["subject_id"],
            risk_class=row["risk_class"],
            reason=row["reason"],
            action=_action_from_dict(row["action"]),
            judgment=_judgment_from_dict(row["judgment"]),
            status=PendingStatus(row["status"]),
            created_at=row["created_at"],
            human_decision=human_decision,
        )
