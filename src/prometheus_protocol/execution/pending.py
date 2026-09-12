"""The pending-action service: hold routed actions for a human, via the ledger.

This is where a routed :class:`GateDecision` is parked and later resolved. It is
also the *only* place a held action becomes an approved decision the executor
may run — and only after the human's approval has been written to the ledger.
Constructing that approving :class:`GateDecision` here (never on the swarm side)
keeps the proposer/judge wall intact: the human is the HUMAN-tier authority.

THE PINNED RECORD (PHASE-1.2c, TASK 5/6). A hold persists a versioned
authorization record (``policy/record.py``): the snapshot digest, the attempt,
the requirements the SELECTED policy resolved, that policy's version, and the
coverage report. It is written at hold creation and never rewritten, and it is
bound into the tamper-evident audit chain under the hold's own identity.

Approval compares against that PINNED resolution, in this order:

1. the row's record must equal its chain entry, and the chain must verify —
   pinning removes re-resolution from the approval path, so the stored
   requirements are trusted BECAUSE they are in the record, and a JSON column
   that anyone with a database handle can rewrite is not a record;
2. the deployment must still select the policy the hold is pinned to — a hold
   pinned to a superseded policy is refused as such (a distinct refusal) and
   marked ``invalidated``, in either direction, because the new policy may
   require more or less and neither is what the human was shown;
3. only then is the record decoded inside the seam and the selected policy
   re-resolved for the concrete action, exactly as at hold time.

A rotation can also invalidate the whole pending backlog explicitly
(:meth:`PendingActionService.invalidate_superseded`). The TTL is unchanged: a
lapsed hold expires, an invalidated hold is voided, and the ledger tells the
two apart.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Callable

from prometheus_protocol.core.interfaces import Ledger
from prometheus_protocol.core.validation import require_non_negative_int
from prometheus_protocol.core.models import (
    ExecutableAction,
    Judgment,
    Tier,
    Unavailability,
    Unavailable,
    Verdict,
)
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
from prometheus_protocol.policy.execution import (
    AuthorizedExecution,
    ExecutionAuthorizer,
    ExecutionNotAuthorized,
    PinnedPolicySuperseded,
)
from prometheus_protocol.policy.profile import VerificationPolicy, policy_digest
from prometheus_protocol.policy.record import (
    PINNED_HOLD_EVENT,
    authorization_record,
    is_versioned_record,
    restore_coverage,
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
    data: dict[str, object] = {
        "verdict": judgment.verdict.value,
        "confidence": judgment.confidence,
        "authoritative": judgment.authoritative,
        "contributing": list(judgment.contributing),
        "conflict": judgment.conflict,
        "detail": judgment.detail,
    }
    # An authoritative verifier that could NOT execute is carried on the Judgment
    # (see core.models.Judgment.unavailable) so a could-not-run HARD/HUMAN check
    # beside a success is never invisible. Record it in the audit blob too. Emitted
    # ONLY when non-empty: a clean run's judgment JSON is byte-identical to before,
    # and the KEY'S PRESENCE is the fault signal (its absence is the norm). The
    # blob is opaque and readers require only verdict/confidence, so the extra key
    # is tolerated with no schema change or migration.
    if judgment.unavailable:
        data["unavailable"] = [
            {
                "verifier_id": u.verifier_id,
                "tier": u.tier.value,
                "reason": u.reason.value,
                "detail": u.detail,
            }
            for u in judgment.unavailable
        ]
    return data


def _judgment_from_dict(data: dict) -> Judgment:
    return Judgment(
        verdict=Verdict(data["verdict"]),
        confidence=float(data["confidence"]),
        authoritative=bool(data["authoritative"]),
        contributing=tuple(data.get("contributing", ())),
        conflict=bool(data.get("conflict", False)),
        detail=data.get("detail", ""),
        unavailable=tuple(
            Unavailable(
                verifier_id=item["verifier_id"],
                tier=Tier(item["tier"]),
                reason=Unavailability(item["reason"]),
                detail=item.get("detail", ""),
            )
            for item in data.get("unavailable", ())
        ),
    )


def _hold_subject(pending_id: int) -> str:
    """The chain subject a hold's record is bound under."""

    return f"pending:{pending_id}"


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
        authorizer: ExecutionAuthorizer | None = None,
    ) -> None:
        self._ledger = ledger
        self._clock = clock or _utc_now_iso
        # 0 disables expiry (documented); a negative value fell into the same
        # branch and disabled it too, which was never a chosen setting.
        self._ttl_seconds = require_non_negative_int(ttl_seconds, name="ttl_seconds")
        self._authorizer = authorizer

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
        authorization = decision.authorization
        if not isinstance(authorization, AuthorizedExecution):
            raise ExecutionNotAuthorized(
                "a routed hold requires a validated execution descriptor"
            )
        if action != decision.action or action != authorization.action:
            raise ExecutionNotAuthorized(
                "hold action differs from the gate-validated action"
            )
        if self._authorizer is None:
            raise ExecutionNotAuthorized(
                "pending service has no trusted policy supplier"
            )
        authorization = self._authorizer.revalidate(authorization)

        created = self._clock()
        # THE PINNED RECORD, built from the seam's own re-resolution (the
        # requirements and policy version on the AuthorizedExecution) — never
        # from anything the caller supplied. Written once, here.
        record = authorization_record(authorization, pinned_at=created)
        pending_id = self._ledger.record_pending_action(
            subject_id=decision.subject_id,
            risk_class=risk_class,
            reason=decision.reason,
            verdict=judgment.verdict.value,
            confidence=judgment.confidence,
            action=_action_to_dict(action),
            judgment=_judgment_to_dict(judgment),
            authorization=record,
            created_at=created,
        )
        # THE TAMPER-EVIDENCE BINDING. The same record goes into the audit
        # chain under this hold's identity. Approval requires the row to match
        # this entry and the chain to verify (see ``_require_chain_binding``),
        # so a database write that weakens the row's requirements is detected
        # rather than trusted. If this append raises — an anchor that cannot be
        # written, say — the row exists with no entry and can never be
        # approved, which is the fail-closed direction; the TTL expires it.
        self._ledger.record_chained(
            event=PINNED_HOLD_EVENT,
            subject=_hold_subject(pending_id),
            payload=record,
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
            authorization=authorization,
            record=record,
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
        no execution can follow an unrecorded approval. Approval re-checks the
        hold at decision time — a lapsed (past-TTL) or already-resolved hold
        cannot be approved — closing the stale-approval race.
        """

        timestamp = now or self._clock()
        pending = self._require_pending(pending_id)
        authorization = self._revalidate(pending)
        # Stale-approval guard: a hold past its TTL cannot be approved, even if a
        # sweep has not run yet. Expire it on the spot (audited) and refuse, so no
        # execution can follow a lapsed approval.
        if self._is_lapsed(pending, now=timestamp):
            self._expire(pending_id, now=timestamp)
            raise ValueError(
                f"pending action {pending_id} has expired (TTL {self._ttl_seconds}s) "
                "and can no longer be approved"
            )
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
            authorization=authorization,
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

    # -- retrying a never-executed approval ----------------------------------

    def retry_decision(
        self,
        pending_id: int,
        *,
        identity: str,
        now: str | None = None,
    ) -> GateDecision:
        """The approving decision for a retry of a never-executed approval.

        The one other construction of an approving decision from a held action
        besides :meth:`approve` — and it decides nothing: it only re-materialises
        an approval a human already recorded, for a hold whose execution was
        refused (fail-closed) or deferred and has therefore **never** executed.
        Anything else is refused: a still-pending hold (the halt is not
        bypassable), a rejected, expired or invalidated hold (decided-stays-
        decided), a hold that already executed, or an approval older than the
        TTL (an approval does not authorize execution indefinitely — the same
        window that bounds how long a hold may wait for its decision bounds how
        long a decision may wait for its execution; ``ttl_seconds <= 0`` disables
        both). The human decision record itself is never touched.
        """

        timestamp = now or self._clock()
        pending = self.get(pending_id)
        if pending is None:
            raise KeyError(f"no pending action with id {pending_id}")
        if pending.status == PendingStatus.PENDING:
            raise ValueError(
                f"pending action {pending_id} is still pending: it needs a human "
                "decision first (a retry cannot bypass the halt)"
            )
        authorization = self._revalidate(pending)
        if pending.status != PendingStatus.APPROVED:
            raise ValueError(
                f"pending action {pending_id} is {pending.status.value} and can "
                "never execute"
            )
        executed = [
            row
            for row in self._ledger.executions_for_pending(pending_id)
            if row["executed"]
        ]
        if executed:
            raise ValueError(
                f"pending action {pending_id} already executed (execution "
                f"#{executed[0]['id']}); retry-execution is only for an approved "
                "hold whose execution was refused or deferred"
            )
        # Conservative fallback for approvals recorded before executions carried
        # the pending-hold link: an unlinked executed human approval for the same
        # subject means "never executed" cannot be proven, so refuse.
        for row in self._ledger.executions():
            if (
                row.get("pending_id") is None
                and row["executed"]
                and row["source"] == "human-approved"
                and row["subject_id"] == pending.subject_id
            ):
                raise ValueError(
                    f"pending action {pending_id} cannot be retried: an earlier "
                    f"unlinked execution exists for subject {pending.subject_id!r} "
                    "and 'never executed' cannot be proven"
                )
        decided = pending.human_decision
        if decided is None or not decided.timestamp:
            # Cannot happen through the API (an approval always records who and
            # when); without the record the retry window is unverifiable — refuse.
            raise ValueError(
                f"pending action {pending_id} carries no approval record; "
                "refusing to retry"
            )
        if self._ttl_seconds > 0:
            elapsed = (
                _parse_iso(timestamp) - _parse_iso(decided.timestamp)
            ).total_seconds()
            if elapsed >= self._ttl_seconds:
                raise ValueError(
                    f"pending action {pending_id} was approved at "
                    f"{decided.timestamp} and its retry window "
                    f"(TTL {self._ttl_seconds}s) has lapsed; the approval record "
                    "is unchanged, but the action can no longer be executed"
                )
        detail = f"human-approved by {decided.identity} at {decided.timestamp}"
        if decided.reason:
            detail += f": {decided.reason}"
        detail += f" (execution retried by {identity} at {timestamp})"
        return GateDecision(
            approved=True,
            subject_id=pending.subject_id,
            judgment=pending.judgment,
            reason=detail,
            outcome=OUTCOME_APPROVE,
            action=pending.action,
            authorization=authorization,
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

    # -- rotation ------------------------------------------------------------

    def invalidate_superseded(self, *, now: str | None = None) -> list[PendingAction]:
        """Invalidate every PENDING hold pinned to a policy no longer selected.

        The explicit half of rotation. Approval refuses such a hold anyway (and
        marks it as it does); this lets an operator who has just rotated the
        policy void the whole backlog at once, so the queue does not carry holds
        that read as approvable and are not. Idempotent, and it never touches a
        decided hold. A legacy hold with no record is left for approval to
        refuse as re-verification required. Returns the holds voided by this
        call.
        """

        timestamp = now or self._clock()
        current = self._selected_policy()
        invalidated: list[PendingAction] = []
        for row in self._ledger.pending_actions(status=PendingStatus.PENDING.value):
            pending = self._from_row(row)
            if pending.record is None or self._pinned_to(pending, current):
                continue
            self._invalidate(pending, current=current, now=timestamp)
            refreshed = self.get(pending.id)
            if refreshed is not None:
                invalidated.append(refreshed)
        return invalidated

    def _selected_policy(self) -> VerificationPolicy:
        if self._authorizer is None:
            raise ExecutionNotAuthorized(
                "pending service has no trusted policy supplier"
            )
        return self._authorizer.selected_policy()

    @staticmethod
    def _pinned_to(pending: PendingAction, policy: VerificationPolicy) -> bool:
        """Whether ``pending`` is pinned to exactly ``policy`` — its identity AND
        its content digest, which commits to its version and requirements."""

        record = pending.record
        return (
            record is not None
            and record.get("policy_id") == policy.policy_id
            and record.get("policy_digest") == policy_digest(policy)
        )

    def _invalidate(
        self, pending: PendingAction, *, current: VerificationPolicy, now: str
    ) -> str:
        record = pending.record or {}
        pinned_digest = str(record.get("policy_digest", ""))
        reason = (
            f"policy rotated: hold pinned to {record.get('policy_id')!r} "
            f"v{record.get('policy_version')} ({pinned_digest[:12]}); the deployment "
            f"now selects {current.policy_id!r} v{current.version} "
            f"({policy_digest(current)[:12]}). Re-run verification under the "
            "selected policy; the hold cannot be approved."
        )
        # Only a still-pending row transitions; an approved hold on a retry
        # keeps its decision record and is simply refused.
        self._ledger.invalidate_pending_action(
            pending.id, invalidated_at=now, reason=reason
        )
        return reason

    # -- the checks approval and retry run, in order ----------------------------

    def _require_pending(self, pending_id: int) -> PendingAction:
        pending = self.get(pending_id)
        if pending is None:
            raise KeyError(f"no pending action with id {pending_id}")
        if pending.status != PendingStatus.PENDING:
            raise ValueError(
                f"pending action {pending_id} is already {pending.status.value}"
            )
        return pending

    def _revalidate(
        self, pending: PendingAction
    ) -> AuthorizedExecution[ExecutableAction]:
        """Chain binding, then the pinned policy, then the seam's re-resolution."""

        if self._authorizer is None or pending.record is None:
            raise ExecutionNotAuthorized(
                "legacy hold has no trusted execution descriptor; re-verification is required"
            )
        self._require_chain_binding(pending)
        self._require_pinned_policy(pending)
        # Decode the pinned record inside the seam, which re-resolves the (now
        # confirmed) selected policy for the concrete action, exactly as at hold
        # time. The identities come off the record the chain just vouched for.
        record = pending.record
        return self._authorizer.restore_persisted(
            record,
            outcome=pending.judgment,
            action=pending.action,
            target_canonical=str(record["target_canonical"]),
            attempt_id=str(record["attempt_id"]),
            coverage=restore_coverage(record),
        )

    def _require_chain_binding(self, pending: PendingAction) -> None:
        """The row's record must be the chain's record, on a chain that verifies.

        Detection, not prevention: a writer with a database handle can still
        change the row. What this guarantees is that approval sees the change —
        a mismatch between the row and its chain entry, or a chain that no
        longer verifies — and refuses. Its limit is the chain's (see
        ``docs/ledger-integrity.md``): an adversary who rewrites the row, the
        entry AND every later hash is caught only by an external anchor.
        """

        subject = _hold_subject(pending.id)
        entries = [
            entry
            for entry in self._ledger.chained_events()
            if entry.get("event") == PINNED_HOLD_EVENT and entry.get("subject") == subject
        ]
        if len(entries) != 1:
            raise ExecutionNotAuthorized(
                f"hold #{pending.id} has {len(entries)} tamper-evident chain "
                "entries where exactly one is required; the pinned record cannot "
                "be trusted"
            )
        payload = entries[0].get("payload")
        stored: object = payload
        if isinstance(payload, str):
            try:
                stored = json.loads(payload)
            except ValueError:
                stored = None
        if stored != pending.record:
            raise ExecutionNotAuthorized(
                f"hold #{pending.id}: the pinned authorization record does not "
                "match its tamper-evident chain entry; the row was altered after "
                "it was written"
            )
        verification = self._ledger.verify_chain()
        if not verification.ok:
            raise ExecutionNotAuthorized(
                f"hold #{pending.id}: the tamper-evident chain did not verify "
                f"({verification.render()}); the pinned record cannot be trusted"
            )

    def _require_pinned_policy(self, pending: PendingAction) -> None:
        """The deployment must still select the policy the hold is pinned to."""

        current = self._selected_policy()
        if self._pinned_to(pending, current):
            return
        reason = self._invalidate(pending, current=current, now=self._clock())
        raise PinnedPolicySuperseded(f"hold #{pending.id} is refused: {reason}")

    def _from_row(self, row: dict) -> PendingAction:
        # A human_decision records an actual human approve/reject. A system
        # expiry or invalidation is a transition audited in the row
        # (status/decided_at/reason), not a human decision, so it is not
        # surfaced here.
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
        action = _action_from_dict(row["action"])
        judgment = _judgment_from_dict(row["judgment"])
        # The record is carried as persisted and checked at approval; it is not
        # re-authorized on read, so listing holds after a rotation still works
        # and approval can name the rotation rather than a bare mismatch. A
        # pre-record blob (the seven identity fields) is not a record: it is
        # refused at approval as re-verification required.
        raw = row.get("authorization")
        record = raw if is_versioned_record(raw) else None
        return PendingAction(
            id=row["id"],
            subject_id=row["subject_id"],
            risk_class=row["risk_class"],
            reason=row["reason"],
            action=action,
            judgment=judgment,
            status=PendingStatus(row["status"]),
            created_at=row["created_at"],
            human_decision=human_decision,
            authorization=None,
            record=record,
        )
