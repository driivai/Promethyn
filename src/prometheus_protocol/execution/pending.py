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

1. the row's record must equal its chain entry, and the chain must verify — a
   JSON column that anyone with a database handle can rewrite is not a record,
   so the pinned requirements are worth reading only once the chain vouches
   for them;
2. the deployment must still select the policy the hold is pinned to — a hold
   pinned to a superseded policy is refused as such (a distinct refusal) and
   marked ``invalidated``, in either direction, because the new policy may
   require more or less and neither is what the human was shown;
3. only then is the record decoded inside the seam and the selected policy
   re-resolved for the concrete action, exactly as at hold time.

WHAT PINNING DOES NOT DO — stated here because it has been assumed twice, and
the assumption is the dangerous direction. Pinning does **not** remove
re-resolution from the approval path. Step 3 above re-resolves the selected
policy for the concrete action, exactly as at hold time; the chain check and the
rotation refusal are added IN FRONT of it, never instead of it.
Re-resolve-don't-re-digest is what closes R1, and a version of this path that
trusted the stored requirements *instead* of re-resolving would reintroduce R1
one layer down, with the JSON column as the new forgeable input. The record's
integrity is what makes the record readable; the seam is what makes it
authoritative. An earlier revision of this docstring said the opposite in its
first clause while the code did what is written here; the claim is withdrawn.

A rotation can also invalidate the whole pending backlog explicitly
(:meth:`PendingActionService.invalidate_superseded`).

THE TTL, and where it is evaluated. Both, deliberately: :meth:`approve` and
:meth:`retry_decision` check the hold's age at decision time, and
:meth:`expire_lapsed` sweeps the backlog. Between the moment a hold lapses and
the moment a sweep notices, its stored status is still ``pending`` — the row has
not been touched — but it is no longer approvable: the decision-time guard
refuses it and expires it on the spot, audited. So an expired-but-unswept hold
cannot approve, and the sweep is housekeeping rather than the control. The
boundary is inclusive: a hold whose age has REACHED the TTL has lapsed
(``elapsed >= ttl_seconds``); ``ttl_seconds <= 0`` disables expiry entirely.
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
from prometheus_protocol.policy.reobservation import (
    MOMENT_CAPTURE,
    MOMENT_PRE_APPROVAL,
    MOMENT_PRE_EXECUTION,
    OBSERVATION_EVENT,
    OUTCOME_ASPECTS_DIFFER,
    OUTCOME_MATCHED,
    OUTCOME_MOVED,
    OUTCOME_UNAVAILABLE,
    Observation,
    ReObservation,
    LEGACY_SUBJECT_RESOLVED,
    StateMoved,
    StateUnobservable,
    StateUnreadable,
    legacy_observation_subject,
    compare,
    observation_record,
    observation_subject,
    opted_out_target_state,
    pinned_reading_of,
    pinned_target_state,
)
from prometheus_protocol.policy.record import (
    PINNED_HOLD_EVENT,
    authorization_record,
    is_versioned_record,
    restore_coverage,
)
from prometheus_protocol.ledger.receipts import (
    DECISION_EVENT,
    OUTCOME_EVENT,
    decision_subject,
    differing_fields,
    latest_entry,
    outcome_entries_for,
    outcome_subject,
    project_decision,
    project_outcome,
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
        reobservation: ReObservation | None = None,
    ) -> None:
        self._ledger = ledger
        self._clock = clock or _utc_now_iso
        # 0 disables expiry (documented); a negative value fell into the same
        # branch and disabled it too, which was never a chosen setting.
        self._ttl_seconds = require_non_negative_int(ttl_seconds, name="ttl_seconds")
        self._authorizer = authorizer
        # ``None`` means this deployment wired no re-observation, and the pinned
        # record SAYS SO rather than omitting the block — an absent block and a
        # passing comparison would otherwise be the same bytes. It is not a
        # silent default: it is a stated one, and it is the reason the record
        # version moved to 2.
        self._reobservation = reobservation

    @property
    def reobservation(self) -> ReObservation | None:
        return self._reobservation

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
                "a routed hold requires a validated execution descriptor",
                reason="descriptor_absent",
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
        # THE CAPTURE POINT (design §2.1(b)): the live state is read HERE, at
        # hold creation, which is the moment the human's review is about. It
        # goes into the pinned record and is what both later comparisons are
        # against. An unreadable target HALTS here — no hold is created at all,
        # rather than one pinned to nothing that would read as "checked".
        target_state = self._capture_target_state(authorization, at=created)
        # THE PINNED RECORD, built from the seam's own re-resolution (the
        # requirements and policy version on the AuthorizedExecution) — never
        # from anything the caller supplied. Written once, here.
        record = authorization_record(
            authorization, pinned_at=created, target_state=target_state
        )
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

        ORDER MATTERS, AND THE LITERAL CLAIM IS NARROWER THAN IT READS.
        ``_revalidate`` runs BEFORE the TTL check. So a hold that is BOTH
        expired AND independently broken — a record that no longer matches its
        chain entry, a chain that no longer verifies, a superseded policy —
        refuses for the EARLIER reason and is never marked EXPIRED here: it
        stays stored as PENDING until a sweep transitions it.

        Every outcome is still fail-closed; nothing executes on either path, and
        the hold remains unapprovable because the revalidation that refused it
        will refuse it again. What is narrowed is only "a lapsed hold is expired
        on the spot": that holds when the TTL is the FIRST thing wrong with it.
        This is a description of the ordering, not a bypass.
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
        # THE FIRST COMPARISON, and its placement is load-bearing in two ways.
        #
        # BEFORE the APPROVED write, so an approval on the record is one whose
        # premise still held when the human gave it. That is the invariant; a
        # comparison after the write would leave an approved hold that is
        # refusable, a state nothing else in this system has.
        #
        # AFTER the TTL check, which the design left as "beside ``_revalidate``"
        # and is settled here. Reading a live target costs a real read, and a
        # hold that has already lapsed is refused whatever the target says;
        # observing it first would spend the read to produce an unavailability
        # that then MASKS a plain expiry. Expiry is a pure function of the clock
        # and the cheaper, more common answer, so it goes first.
        self._require_state_unmoved_before_approval(pending, at=timestamp)
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
        # "NEVER EXECUTED" IS READ OFF THE CHAIN, NOT THE ROW (F14). This
        # used to read ``row["executed"]``. Measured: with that flag flipped
        # to 0 and the at-most-once claim nulled — two UPDATEs — retry believed
        # the hold had never run and ran it AGAIN: two execution rows for one
        # approval, ``verify_chain()`` VALID throughout. Each execution row
        # now has an outcome receipt on the chain, and the decision here is
        # made from the receipt: a row with none is refused as
        # ``outcome_entry_missing``, a row that differs from its receipt as
        # ``outcome_differs_from_chain_entry``, and only a receipt that says
        # executed counts as executed.
        #
        # IN BOTH DIRECTIONS, and the second is the one review found. The first
        # version walked the ROWS for this hold and checked each against its
        # receipt. Delete the row — or re-attribute its ``pending_id`` — and
        # null the claim, and that walk saw nothing: the hold read as never
        # executed and the executor ran AGAIN, chain VALID. Measured on #121.
        # So the receipts for this hold are enumerated from the CHAIN, whose
        # payloads carry ``pending_id`` and cannot be re-attributed without
        # the mismatch showing, and each must have its row. The rows are
        # ALSO walked, so an inserted row with no receipt is refused.
        events = self._ledger.chained_events()
        rows_by_id = {row["id"]: row for row in self._ledger.executions()}
        executed: list[dict] = []
        for execution_id, chained in outcome_entries_for(events, pending_id=pending_id):
            row = rows_by_id.get(execution_id)
            if row is None:
                raise ExecutionNotAuthorized(
                    f"pending action {pending_id}: the chain holds an outcome for "
                    f"execution #{execution_id} and the ledger has no such row; "
                    "the row was deleted after its receipt was written, and "
                    "whether the hold executed cannot be read off what remains",
                    reason="execution_row_missing",
                )
            differs = differing_fields(project_outcome(row), chained)
            if differs:
                raise ExecutionNotAuthorized(
                    f"pending action {pending_id}: execution #{execution_id} differs "
                    f"from its chained outcome on {', '.join(differs)}; the row "
                    "was altered after the outcome was recorded",
                    reason="outcome_differs_from_chain_entry",
                )
            if chained["executed"]:
                executed.append(row)
        for row in self._ledger.executions_for_pending(pending_id):
            if latest_entry(events, event=OUTCOME_EVENT, subject=outcome_subject(row["id"])) is None:
                raise ExecutionNotAuthorized(
                    f"pending action {pending_id}: execution #{row['id']} has no "
                    "outcome on the tamper-evident chain, so whether it executed "
                    "cannot be established; refusing to retry",
                    reason="outcome_entry_missing",
                )
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

    # -- re-observation: capture, compare, refuse ------------------------------

    def _capture_target_state(
        self, authorization: AuthorizedExecution[ExecutableAction], *, at: str
    ) -> dict | None:
        """The ``target_state`` block for a new hold, or ``None`` for unconfigured.

        ``None`` is not silence: ``authorization_record`` turns it into the
        explicit "this deployment wired no re-observation" block, so every v2
        record says which of the three cases it is.
        """

        if self._reobservation is None:
            return None
        action_class = authorization.descriptor.action_class
        opted_out = self._reobservation.opt_out_reason(action_class)
        if opted_out is not None:
            return opted_out_target_state(action_class, opted_out)
        observation = self._reobservation.observe(
            action_class=action_class,
            target_canonical=authorization.descriptor.target_canonical,
            action=authorization.action,
            moment=MOMENT_CAPTURE,
            at=at,
        )
        if not observation.readable:
            unread = observation.unavailable
            raise StateUnreadable(
                f"the live state of {authorization.descriptor.target_canonical!r} "
                f"could not be read at hold creation "
                f"({unread.reason if unread else 'unknown'}: "
                f"{unread.detail if unread else ''}); no hold is created, because "
                "a hold pinned to nothing would read as one that was checked",
                reason="target_state_unreadable",
            )
        return pinned_target_state(observation)

    def _compare_now(
        self,
        pending: PendingAction,
        *,
        moment: str,
        execution_attempt: int,
        at: str,
        prior: dict | None = None,
    ) -> tuple[str, dict | None]:
        """Read the target again, compare with the pin, and CHAIN the finding.

        Returns ``(outcome, record)``. The record is written before the caller
        decides what to do about the outcome, and on every outcome including a
        match: an observation that is only recorded when it fails is an
        observation a reader cannot distinguish from one that never ran.
        """

        record = pending.record or {}
        pinned = pinned_reading_of(record)
        if self._reobservation is None or pinned is None:
            return OUTCOME_MATCHED, None
        pinned_digest, pinned_aspects = pinned
        action_class = str(record.get("action_class", ""))
        target_canonical = str(record.get("target_canonical", ""))
        attempt_id = str(record.get("attempt_id", ""))
        # TWO REGISTRIES CAN DISAGREE, and wiring re-observation is what made
        # that reachable. This hold's record says its live state was pinned; the
        # registry in front of it now says the class is not observed here. The
        # comparison the record commits the hold to cannot be made, so the hold
        # is REFUSED rather than passed through as a match — passing it through
        # would execute on evidence the record claims was re-checked, which is
        # the degradation doctrine #2 forbids. Measured: before this branch
        # existed the same path raised a bare KeyError out of ``approve``.
        if not self._reobservation.covers(action_class):
            raise StateUnobservable(
                f"hold #{pending.id} was pinned to the live state of "
                f"{target_canonical!r}, but this service does not observe "
                f"{action_class!r}"
                + (
                    f" ({self._reobservation.opt_out_reason(action_class)})"
                    if self._reobservation.opt_out_reason(action_class)
                    else ""
                )
                + ". The comparison its record commits it to cannot be made "
                "here, so it is refused rather than approved unchecked",
                reason="target_state_registry_mismatch",
            )
        observation = self._reobservation.observe(
            action_class=action_class,
            target_canonical=target_canonical,
            action=pending.action,
            moment=moment,
            at=at,
        )
        outcome = compare(
            pinned_digest=pinned_digest,
            pinned_aspects=pinned_aspects,
            observation=observation,
        )
        entry = observation_record(
            attempt_id=attempt_id,
            execution_attempt=execution_attempt,
            action_class=action_class,
            target_canonical=target_canonical,
            pinned=dict(record.get("target_state") or {}),
            observation=observation,
            outcome=outcome,
            prior=prior,
        )
        # INSIDE THE CHAIN, not in a column beside it. An observation trusted
        # because it is in the record and covered by nothing is the split Block
        # 1a closed when integrity moved from re-resolution to the record; the
        # same argument applies to the record this adds.
        self._ledger.record_chained(
            event=OBSERVATION_EVENT,
            subject=observation_subject(
                attempt_id, execution_attempt, pending_id=pending.id
            ),
            payload=entry,
            created_at=at,
        )
        return outcome, entry

    def _refuse_outcome(
        self, pending: PendingAction, outcome: str, *, moved_reason: str
    ) -> None:
        """Turn a non-matching outcome into the refusal that outcome means."""

        if outcome == OUTCOME_UNAVAILABLE:
            raise StateUnreadable(
                f"hold #{pending.id}: the live state could not be read, so it "
                "was never compared. A target that cannot be read is not a "
                "target that has not changed",
                reason="target_state_unreadable",
            )
        if outcome == OUTCOME_ASPECTS_DIFFER:
            raise StateUnreadable(
                f"hold #{pending.id}: the observed covered set differs from the "
                "set the hold was pinned over, so the two digests are not "
                "comparable. This is a deployment-version finding, not a "
                "statement about the target",
                reason="target_state_aspects_differ",
            )
        raise StateMoved(
            f"hold #{pending.id}: the live state of its target is not what the "
            "pinned record says it was",
            reason=moved_reason,
        )

    def _require_state_unmoved_before_approval(
        self, pending: PendingAction, *, at: str
    ) -> None:
        """The pre-approval comparison. A refusal leaves the hold PENDING."""

        outcome, _ = self._compare_now(
            pending, moment=MOMENT_PRE_APPROVAL, execution_attempt=0, at=at
        )
        if outcome != OUTCOME_MATCHED:
            self._refuse_outcome(
                pending, outcome, moved_reason="target_state_moved_before_approval"
            )

    def pre_approval_entry(self, attempt_id: str, *, pending_id: int) -> dict | None:
        """The pre-approval observation, read back off the chain.

        The pre-execution entry RESTATES it, so one receipt shows that state was
        checked twice and what moved between the two. Read from the chain rather
        than carried in memory: the controller that runs the second comparison
        is not the object that ran the first, and a value passed between them
        would be a value neither of them can show came from the chain.
        """

        subject = observation_subject(attempt_id, 0, pending_id=pending_id)
        legacy = legacy_observation_subject(attempt_id, 0)
        legacy_hits: list[dict] = []
        for entry in self._ledger.chained_events():
            if entry.get("event") != OBSERVATION_EVENT:
                continue
            found = entry.get("subject")
            if found != subject and found != legacy:
                continue
            payload = entry.get("payload")
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except ValueError:
                    continue
            # Narrowed in STATEMENT form, not a ternary. The type gate
            # refuses the expression spelling here and it is right to: a
            # payload of a third shape would be taken by the else-branch and
            # become ``None``, which this method's caller reads as "there
            # was no pre-approval entry" — a missing receipt reported as an
            # absent one.
            if not isinstance(payload, dict):
                continue
            if found == subject:
                return payload
            legacy_hits.append(payload)
        # NOTHING under the current subject. A hold approved by the previous
        # release wrote its receipt before the hold id was part of the key, so
        # the pre-upgrade spelling is searched too — otherwise the execution
        # receipt would say ``prior: null`` for a hold that WAS checked at
        # approval, which is the record claiming the opposite of what happened.
        if len(legacy_hits) == 1:
            resolved = dict(legacy_hits[0])
            # Marked, never passed off as an exact match: a reader must be able
            # to tell an attribution from an identity.
            resolved[LEGACY_SUBJECT_RESOLVED] = True
            return resolved
        if len(legacy_hits) > 1:
            # The collision the hold id was added to remove. Two holds shared an
            # attempt_id under the old key, so neither receipt can be attributed
            # to THIS hold. Refused rather than guessed: picking the first is
            # how the later hold's execution comes to restate the earlier hold's
            # reading, which is the defect that motivated the new key.
            raise StateUnobservable(
                f"hold #{pending_id}: {len(legacy_hits)} pre-upgrade observation "
                f"receipts share the subject {legacy!r}, so none of them can be "
                "attributed to this hold. The pre-approval reading cannot be "
                "restated, and guessing which one belongs here would put another "
                "hold's evidence in this one's receipt",
                reason="pre_approval_receipt_ambiguous",
            )
        return None

    def require_state_unmoved_for_execution(
        self, pending_id: int, *, execution_attempt: int, now: str | None = None
    ) -> None:
        """The pre-execution re-read. A mismatch refuses AND makes the hold terminal.

        The state moved after a human looked at it, so the approval is stale as
        a matter of fact and retrying cannot make it fresh. The hold leaves
        ``APPROVED`` for ``STATE_MOVED``, which ``retry_decision`` refuses like
        any other non-approved status, and the execution claim is deliberately
        NOT released: releasing it is what keeps a refused, side-effect-free
        execution retry-eligible, and retry-eligible is the outcome this ruling
        exists to prevent.
        """

        at = now or self._clock()
        pending = self.get(pending_id)
        if pending is None:
            raise KeyError(f"no pending action with id {pending_id}")
        record = pending.record or {}
        attempt_id = str(record.get("attempt_id", ""))
        prior = (
            self.pre_approval_entry(attempt_id, pending_id=pending_id)
            if attempt_id
            else None
        )
        # A PINNED HOLD THAT THIS SERVICE OBSERVES MUST HAVE A PRE-APPROVAL
        # RECEIPT, because ``approve`` writes one before it records the
        # approval. If it cannot be found under either the current subject or
        # the pre-upgrade one, the receipt is gone — and continuing would write
        # an execution receipt saying ``prior: null``, which is the spelling
        # that means "this was the first reading". The record would state that
        # state was never checked at approval, for a hold where it was.
        #
        # Guarded on coverage so the registry-mismatch refusal in
        # ``_compare_now`` still fires with its OWN reason: "this deployment
        # does not observe the class" is a different fact from "the receipt is
        # missing", and the first explains the second.
        covered = self._reobservation is not None and self._reobservation.covers(
            str(record.get("action_class", ""))
        )
        if prior is None and covered and pinned_reading_of(record) is not None:
            raise StateUnobservable(
                f"hold #{pending_id} is pinned to live state and this service "
                "observes its action class, but no pre-approval observation "
                "receipt could be found on the chain under either the current "
                "subject or the pre-upgrade one. Executing would record that "
                "state was never checked at approval, which is not what "
                "happened",
                reason="pre_approval_receipt_missing",
            )
        outcome, _ = self._compare_now(
            pending,
            moment=MOMENT_PRE_EXECUTION,
            execution_attempt=execution_attempt,
            at=at,
            prior=prior,
        )
        if outcome == OUTCOME_MATCHED:
            return
        if outcome == OUTCOME_MOVED:
            self._ledger.mark_state_moved(
                pending_id,
                at=at,
                reason=(
                    "the target moved between approval and execution; the "
                    "approval stands as a record of a correct decision on the "
                    "state it was shown, and re-verification is a NEW hold"
                ),
            )
        self._refuse_outcome(pending, outcome, moved_reason="state_moved_after_approval")

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
                "legacy hold has no trusted execution descriptor; "
                "re-verification is required",
                reason="reverification_required",
            )
        self._require_chain_binding(pending)
        self._require_decision_binding(pending)
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
                "be trusted",
                reason="chain_entry_count_wrong",
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
                "it was written",
                reason="record_differs_from_chain_entry",
            )
        verification = self._ledger.verify_chain()
        if not verification.ok:
            raise ExecutionNotAuthorized(
                f"hold #{pending.id}: the tamper-evident chain did not verify "
                f"({verification.render()}); the pinned record cannot be trusted",
                reason="chain_did_not_verify",
            )

    def _require_decision_binding(self, pending: PendingAction) -> None:
        """The row's decision must be the chain's decision (F13).

        ``_require_chain_binding`` vouches for what the hold was PERMITTED to
        do. This vouches for what was DECIDED about it. Every writer of the
        row's decision columns appends the row as stored to the chain
        (``ledger/receipts.py``, ``DECISION_EVENT``), and here the row must
        equal the LATEST such entry — so a database write that sets
        ``status='approved'`` with a forged reviewer and time, which retry
        used to honour, now has nothing on the chain to match and is refused.

        Two refusals, because they are two findings: a decided row with no
        entry is ``decision_entry_missing`` — what an adversary who can write
        rows but not the chain leaves behind, and also what every hold decided
        before receipts existed looks like, which is the chosen fail-closed
        consequence of not bumping ``RECORD_VERSION``; a row that differs from
        its entry is ``decision_differs_from_chain_entry``. A still-pending row
        with no entry is the genesis state: the hold's own ``pending.hold``
        entry is its receipt, and no decision has been made to chain.

        Detection, not prevention, with the chain's own limit: a writer who
        rewrites the row, the entry AND every later hash is caught only by an
        external anchor, exactly as for the authorization record.
        """

        row = self._ledger.pending_action(pending.id)
        if row is None:
            raise ExecutionNotAuthorized(
                f"hold #{pending.id} no longer exists in the ledger",
                reason="decision_entry_missing",
            )
        projected = project_decision(row)
        chained = latest_entry(
            self._ledger.chained_events(),
            event=DECISION_EVENT,
            subject=decision_subject(pending.id),
        )
        if chained is None:
            if row.get("status") == PendingStatus.PENDING.value:
                return
            raise ExecutionNotAuthorized(
                f"hold #{pending.id} is {row.get('status')!r} in the row and has "
                "no decision on the tamper-evident chain; the row's decision "
                "cannot be trusted",
                reason="decision_entry_missing",
            )
        differs = differing_fields(projected, chained)
        if differs:
            raise ExecutionNotAuthorized(
                f"hold #{pending.id}: the row's decision differs from its chained "
                f"receipt on {', '.join(differs)}; the row was altered after the "
                "decision was recorded",
                reason="decision_differs_from_chain_entry",
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
        #
        # STATE_MOVED IS THE EXCEPTION, and leaving it out was a defect (PR
        # #113 review). It is a system transition, but unlike expiry and
        # invalidation it happens to a hold that WAS APPROVED: the reviewer's
        # identity and timestamp are still in the row, and the lifecycle says
        # explicitly that the approval remains part of the record because it
        # was a correct decision on the state it was shown. Reconstructing
        # ``None`` there made a reloaded hold claim nobody had approved it —
        # the opposite of what the ruling says the record must show.
        human_decision = None
        if row["status"] in (
            PendingStatus.APPROVED.value,
            PendingStatus.REJECTED.value,
            PendingStatus.STATE_MOVED.value,
        ) and row.get("decided_by"):
            human_decision = HumanDecision(
                # The DECISION the human made, not the hold's current status.
                # A STATE_MOVED hold was approved; what changed afterwards is
                # the hold's fate, not what the reviewer decided, and labelling
                # their approval with the terminal status would rewrite it.
                decision=(
                    PendingStatus.APPROVED.value
                    if row["status"] == PendingStatus.STATE_MOVED.value
                    else row["status"]
                ),
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
