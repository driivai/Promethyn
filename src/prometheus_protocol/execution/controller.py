"""Execution controller: the only path from a judged action to a side-effect.

It ties the action gate, the human hold, and the executor together. An approved
decision executes immediately; a routed one *halts* as a pending action and can
become executed **only** through :meth:`approve`, which records the human
decision before the executor is ever called; a blocked action never executes;
an *unavailable* one — an authoritative check that could not run — is recorded
distinctly and halts without executing, and is deliberately never an approvable
hold (a human must not rubber-stamp an action whose verification never ran).
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
from typing import TYPE_CHECKING, Callable

from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.core.interfaces import Ledger
from prometheus_protocol.core.models import ExecutableAction

if TYPE_CHECKING:  # pragma: no cover - import cycle: policy imports core.models
    from prometheus_protocol.policy.assessment import PolicyAssessment
    from prometheus_protocol.policy.reobservation import ReObservation
from prometheus_protocol.execution.models import PendingAction
from prometheus_protocol.execution.pending import (
    _DEFAULT_TTL_SECONDS,
    PendingActionService,
    _judgment_to_dict,
    _utc_now_iso,
)
from prometheus_protocol.gate.authorization import ActionGate, OUTCOME_UNAVAILABLE
from prometheus_protocol.gate.promotion import (
    OUTCOME_APPROVE,
    OUTCOME_ROUTE,
    GateDecision,
)
from prometheus_protocol.policy.execution import (
    AuthorizedExecution,
    ExecutionNotAuthorized,
)
from prometheus_protocol.ledger.spend import (
    DEFAULT_IDEMPOTENCY_WINDOW_SECONDS,
    KEY_EXPIRED,
    KEY_MISMATCH,
    MAY_EXECUTE,
    NOT_RETRYABLE,
    OUTCOME_UNKNOWN,
    REPLAY,
    RETURN_PRIOR,
    SpendRecordMalformed,
    authorization_key,
    retry_verdict,
)
from prometheus_protocol.policy.reobservation import refusal_retains_claim
from prometheus_protocol.policy.record import authorization_record

#: Which typed reason each refusing spend verdict carries. A table rather than
#: a chain of ``if``s so the mapping is one object a test can compare against
#: the verdict set — a verdict added without a reason is then a missing key and
#: a loud failure, not a refusal that silently borrows its neighbour's cause.
#: What a returned prior result puts in ``stdout``, because the ledger records
#: no such column and an empty string would read as "the program printed
#: nothing". A named unavailable value, never a plausible one.
_STDOUT_NOT_RECORDED = "stdout was not recorded for this execution"

_SPEND_REFUSAL_REASON = {
    REPLAY: "authorization_already_spent",
    KEY_MISMATCH: "idempotency_key_mismatch",
    NOT_RETRYABLE: "authorization_not_retryable",
    OUTCOME_UNKNOWN: "execution_outcome_unknown",
    KEY_EXPIRED: "idempotency_key_expired",
}

#: What each refusal SAYS. Kept beside the reason for the same reason the
#: reasons are separate at all: an operator reading one of these has a
#: different next step for each, and the message is where that is said.
_SPEND_REFUSAL_DETAIL = {
    REPLAY: (
        "this authorization for {subject!r} was already used (spent at "
        "{claimed_at}). An authorization is spent when it is used; a second "
        "execution needs a new one. To retry the first, the original call had "
        "to declare an idempotency key."
    ),
    KEY_MISMATCH: (
        "a retry of this authorization for {subject!r} was declared with an "
        "idempotency key that is not the one recorded when it was spent at "
        "{claimed_at}: this is a different caller's retry, or a replay dressed "
        "as one."
    ),
    NOT_RETRYABLE: (
        "a retry of this authorization for {subject!r} was declared, but the "
        "call that spent it at {claimed_at} declared no idempotency key, so no "
        "retry was ever offered. Retryability is opted into on the FIRST call."
    ),
    OUTCOME_UNKNOWN: (
        "this authorization for {subject!r} was claimed at {claimed_at} and "
        "never completed: whether the side effect happened is unknown. It is "
        "neither re-run nor reported as done — establish what happened, then "
        "authorize deliberately."
    ),
    KEY_EXPIRED: (
        "the idempotency key for {subject!r} matches, and the retry window "
        "since {claimed_at} has passed. The occurrence stays spent and is NOT "
        "re-run; the execution and its receipt are still on the ledger and can "
        "be read there."
    ),
}
from prometheus_protocol.swarm.executor import Executor
from prometheus_protocol.swarm.models import ExecutionResult


def _judgment_or_none(decision: GateDecision) -> dict | None:
    """The decision's judgment as a ledger dict, or None when it carries none."""

    return (
        _judgment_to_dict(decision.judgment) if decision.judgment is not None else None
    )


def _record_or_none(decision: GateDecision, *, at: str) -> dict | None:
    """The decision's authorization as a ledger record, or None when it carries
    none. Every outcome the gate produces carries one — the gate authorizes
    before it reads the verdict — so blocked and unavailable rows say what they
    were decided under too, coverage refusal included."""

    if isinstance(decision.authorization, AuthorizedExecution):
        return authorization_record(decision.authorization, pinned_at=at)
    return None


@dataclass(frozen=True)
class SubmitOutcome:
    """What happened when an action was submitted for authorization."""

    outcome: (
        str  # OUTCOME_APPROVE / OUTCOME_ROUTE / OUTCOME_BLOCK / OUTCOME_UNAVAILABLE
    )
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
        reobservation: "ReObservation | None" = None,
        idempotency_window_seconds: int = DEFAULT_IDEMPOTENCY_WINDOW_SECONDS,
    ) -> None:
        self._gate = gate
        self._executor = executor
        self._ledger = ledger
        self._clock = clock or _utc_now_iso
        # G24 §3. How long a matching idempotency key is still honoured after
        # the claim. A constructor argument rather than a ``Config`` field, and
        # that shortfall is stated in ``ledger/spend.py`` and pinned by
        # ``test_spend_the_authorization.py`` — it is not settable from the
        # environment and does not reach the attested posture.
        self._idempotency_window_seconds = idempotency_window_seconds
        # ONE registry, both comparisons. The pending service runs the
        # pre-approval comparison and this controller runs the pre-execution
        # re-read, and they must agree about which classes are observed and
        # which are opted out — two registries would be two answers to that,
        # and the second comparison could then silently not happen for a class
        # the first one covered.
        if pending is not None and reobservation is not None:
            # REFUSED, NOT DEGRADED (doctrine #2). ``pending or Pending...(...)``
            # never constructs the service when one is supplied, so the registry
            # passed here was silently discarded: both comparisons then ran on
            # the supplied service's registry, which may be ``None``. A
            # controller that LOOKS like it enables re-observation would execute
            # a stale destructive action with neither check — and the caller has
            # no way to tell, because every observable surface says the feature
            # is on.
            #
            # Identity, not equality. Two equivalent registries are still two
            # objects, and "the same registry" is the property the two
            # comparisons need: one answer to which classes are observed. A
            # caller that means to share one passes one.
            if pending.reobservation is not reobservation:
                raise ConfigError(
                    "ExecutionController was given both a pending service and a "
                    "re-observation registry, and the service does not carry "
                    "that registry. The service's registry is what both "
                    "comparisons would use, so the one passed here would be "
                    "discarded and re-observation would appear enabled while "
                    "running neither check. Pass the registry to the service "
                    "you build, or pass no service.",
                    reason="reobservation_registry_discarded",
                )
        self._pending = pending or PendingActionService(
            ledger,
            clock=self._clock,
            ttl_seconds=ttl_seconds,
            authorizer=gate.authorizer,
            reobservation=reobservation,
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
        assessment: "PolicyAssessment",
        action: ExecutableAction,
        attempt_id: str,
        risk_class: str = "low",
        subject_id: str = "",
        idempotency_key: str | None = None,
    ) -> SubmitOutcome:
        """Authorize an action and act on the outcome.

        ``idempotency_key`` is the caller's DECLARATION that this occurrence
        may be retried, and it is opted into on the first call. Supplying the
        same key again for the same occurrence returns that occurrence's
        recorded result without running anything; supplying none, or a
        different one, is a replay and refuses (G24, ``ledger/spend.py``).
        Note what it is NOT: it is not part of the occurrence's identity, so it
        cannot be used to make two executions of one authorization look like
        two authorizations.

        approve -> execute now; route -> halt as a pending action; block ->
        record and never execute; unavailable -> record distinctly and halt, when
        an authoritative check could not run (never executes, and never an
        approvable hold — a human must not rubber-stamp an unverified action).

        HUMAN PATH. A routed decision carries the same validated execution
        descriptor. The pending service checks it at admission, persists it, and
        re-validates it on approval, reload, and retry. A human can resolve the
        risk decision but cannot manufacture completion of a required check.

        PHASE-1.2b — the keyword is ``assessment`` and it is a
        :class:`~prometheus_protocol.policy.assessment.PolicyAssessment`. The old
        ``judgment=`` keyword is gone rather than deprecated: leaving it would
        leave the bypass reachable by a caller that never updated, and a
        migration that keeps the unsafe door open is not a migration.
        """

        decision = self._gate.decide(
            assessment,
            risk_class=risk_class,
            subject_id=subject_id,
            action=action,
            attempt_id=attempt_id,
        )
        outcome = decision.effective_outcome
        if outcome == OUTCOME_APPROVE:
            result = self._execute(
                decision, source="auto-approved", idempotency_key=idempotency_key
            )
            return SubmitOutcome(outcome=outcome, decision=decision, execution=result)
        if outcome == OUTCOME_ROUTE:
            held = self._pending.hold(decision, risk_class=risk_class, action=action)
            return SubmitOutcome(outcome=outcome, decision=decision, pending=held)
        if outcome == OUTCOME_UNAVAILABLE:
            # An authoritative check could NOT execute: there is no verdict to
            # authorize on. Record it distinctly (source "unavailable", so a human
            # can tell a could-not-verify from a policy denial) and halt — it
            # never executes. It is deliberately NOT parked as an approvable hold:
            # a human must not be able to approve execution of an action whose
            # HARD verification never ran. The remedy is to repair the runtime and
            # re-verify, not to approve blind.
            now = self._clock()
            self._ledger.record_execution(
                subject_id=subject_id,
                source="unavailable",
                executed=False,
                refused=True,
                sandbox_name="",
                exit_status=None,
                detail=decision.reason,
                created_at=now,
                judgment=_judgment_or_none(decision),
                authorization=_record_or_none(decision, at=now),
            )
            return SubmitOutcome(outcome=outcome, decision=decision)
        # Blocked: recorded for audit, never executed.
        now = self._clock()
        self._ledger.record_execution(
            subject_id=subject_id,
            source="blocked",
            executed=False,
            refused=False,
            sandbox_name="",
            exit_status=None,
            detail=decision.reason,
            created_at=now,
            judgment=_judgment_or_none(decision),
            authorization=_record_or_none(decision, at=now),
        )
        return SubmitOutcome(outcome=outcome, decision=decision)

    def approve(
        self, pending_id: int, *, identity: str, reason: str = ""
    ) -> ExecutionResult:
        """Record a human approval, then execute the held action."""

        # Opportunistic expiry before deciding: any hold that has lapsed by now
        # (including this one) is expired first. The pending service's own
        # stale-guard re-checks at decision time regardless, so approval of a
        # lapsed hold is refused even when this sweep is bypassed.
        self._pending.sweep()
        decision = self._pending.approve(pending_id, identity=identity, reason=reason)
        return self._execute(
            decision,
            source="human-approved",
            pending_id=pending_id,
            record=self._pinned_record(pending_id),
        )

    def reject(self, pending_id: int, *, identity: str, reason: str = "") -> None:
        """Record a human rejection. The action is never executed."""

        self._pending.reject(pending_id, identity=identity, reason=reason)

    def invalidate_superseded_holds(self) -> list[PendingAction]:
        """Void every pending hold pinned to a policy no longer selected.

        The operator's verb after a policy rotation (delegates to the pending
        service). Approval refuses a superseded hold regardless; this clears
        the backlog so nothing reads as approvable that is not.
        """

        return self._pending.invalidate_superseded()

    def _pinned_record(self, pending_id: int) -> dict | None:
        """The hold's PINNED record, as persisted — what the execution row
        carries, so the row that says a side effect happened says what the
        human was shown when they approved it."""

        pending = self._pending.get(pending_id)
        return pending.record if pending is not None else None

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
                authorization=pending.record if pending is not None else None,
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
            record=self._pinned_record(pending_id),
        )

    def sweep(self, *, now: str | None = None) -> list[PendingAction]:
        """Expire lapsed pending actions (delegates to the pending service)."""

        return self._pending.sweep(now=now)

    def _execution_attempt(self, pending_id: int) -> int:
        """Which execution attempt this is for the hold, counting from 1.

        DERIVED from the rows already written rather than stored in a new
        column: every attempt records an execution row (an ineligible retry
        included), so the count of existing rows plus one IS the ordinal, and a
        schema change would be a second place for the same number to live.

        It is what separates a retry's observation from the first one, so a
        retry ADDS a record instead of overwriting one — which is what makes
        the history of what moved readable at all.
        """

        return len(self._ledger.executions_for_pending(pending_id)) + 1

    def _spend_key(self, decision: GateDecision, record: dict | None) -> str:
        """This occurrence's identity, or a refusal.

        REFUSED, NOT SKIPPED. An approved decision with no authorization record
        is one whose bound fields cannot be named, so no spend can be recorded
        against it — and an execution that cannot be spent is an execution that
        could be replayed forever. Treating a missing record as "no spend
        needed" would re-open the exception this sprint closes, one level down.
        """

        if record is None:
            raise ExecutionNotAuthorized(
                "this decision carries no authorization record, so the "
                "occurrence it would execute cannot be identified or spent",
                reason="descriptor_absent",
            )
        try:
            return authorization_key(record)
        except SpendRecordMalformed as exc:
            raise ExecutionNotAuthorized(
                f"the authorization record cannot be reduced to an occurrence: {exc}",
                reason="spend_record_unreadable",
            ) from exc

    def _settle_spend(
        self,
        key: str,
        decision: GateDecision,
        *,
        idempotency_key: str | None,
        detail_prefix: str,
    ) -> ExecutionResult | None:
        """Dispatch on what this caller is entitled to; ``None`` means run.

        The prior result is returned for a DECLARED retry whose key matches,
        and it is read back through the chain's record of which execution row
        completed the spend — not recomputed and not re-executed. Every other
        used state refuses with its own typed reason.
        """

        try:
            state = self._ledger.authorization_spend_state(key)
        except SpendRecordMalformed as exc:
            raise ExecutionNotAuthorized(
                f"this occurrence's spend record cannot be read: {exc}",
                reason="spend_record_unreadable",
            ) from exc
        verdict = retry_verdict(
            state,
            idempotency_key=idempotency_key,
            now=self._clock(),
            window_seconds=self._idempotency_window_seconds,
        )
        if verdict == MAY_EXECUTE:
            return None
        if verdict == RETURN_PRIOR:
            row = (
                self._ledger.execution(state.execution_id)
                if state.execution_id is not None
                else None
            )
            if row is None:
                # A completed spend whose row is gone: the inverse walk
                # ``receipts.py`` names. There is a recorded execution and no
                # record of what it did, which is not a result to return.
                raise ExecutionNotAuthorized(
                    f"this occurrence completed as execution #{state.execution_id}, "
                    "whose row is missing: the prior result cannot be returned",
                    reason="execution_row_missing",
                )
            # WHAT IS RETURNED IS THE RECORDED OUTCOME, AND IT SAYS SO.
            #
            # ``executions`` has no ``stdout`` column — measured, not assumed:
            # the row carries subject, source, executed, refused, sandbox,
            # exit_status, detail, the judgment and the authorization record,
            # and nothing else. So a retry cannot be handed the program's
            # output, and the first version of this reconstruction left
            # ``stdout`` at its default, which is ``""``.
            #
            # THAT IS THE ONE VALUE IT MUST NOT BE (doctrine #1). An empty
            # string is what a program that printed nothing produces, so
            # "never recorded" and "printed nothing" became the same bytes at
            # the point a caller reads them — could-not-know reported as a
            # fact about the program. Review of #127 named it.
            #
            # NOT FIXED BY ADDING THE COLUMN, deliberately. PROD-FIX-2 (F8)
            # removed a raw model response from ``Evidence.detail`` precisely
            # because an endpoint reflecting a header put a bearer token into
            # the ledger; candidate stdout is the same class of unbounded,
            # attacker-influenced text. The limit is stated instead, in the
            # field a caller actually reads.
            return ExecutionResult(
                executed=bool(row["executed"]),
                subject_id=row["subject_id"],
                detail=f"{detail_prefix}returned the prior result of this "
                f"authorization (execution #{state.execution_id}): {row['detail']}"
                f" [{_STDOUT_NOT_RECORDED}]",
                refused=bool(row["refused"]),
                sandbox_name=row["sandbox"] or "",
                exit_status=row["exit_status"],
                # CARRIED FROM THE STORED ROW, which has held both columns
                # since #120 and which this replay was discarding. The row is
                # three-valued (``None`` means no executor was invoked, see
                # ``sqlite_ledger._execution_row``) and ``ExecutionResult`` is
                # two-valued, so ``None`` reads as ``False``: a replay of a row
                # that never observed isolation does not claim it did. Before
                # this, both were inherited — and the inherited value was
                # ``True``, so every replay asserted isolation had started and
                # the candidate had begun, whatever the row said.
                started_ok=bool(row["started_ok"]),
                candidate_started=bool(row["candidate_started"]),
                # OUT OF BAND. The sentence stays in ``detail``, where prose
                # belongs and where no consumer reads captured output; the
                # FACT that nothing was captured is its own field, because a
                # candidate can print any sentence this one might have chosen.
                # ``stdout`` is left empty rather than carrying a diagnostic a
                # reader could mistake for the program's own.
                stdout="",
                # Explicit although it is now the default: this is the one
                # place the ABSENCE is the point, and a reader here should not
                # have to go and look up what the default is.
                stdout_recorded=False,
            )
        raise ExecutionNotAuthorized(
            _SPEND_REFUSAL_DETAIL[verdict].format(
                subject=decision.subject_id, claimed_at=state.claimed_at
            ),
            reason=_SPEND_REFUSAL_REASON[verdict],
        )

    def _execute(
        self,
        decision: GateDecision,
        *,
        source: str,
        pending_id: int | None = None,
        detail_prefix: str = "",
        record: dict | None = None,
        idempotency_key: str | None = None,
    ) -> ExecutionResult:
        # The authorization record the execution row carries: the hold's PINNED
        # record when it came from one, otherwise the decision's own.
        if record is None:
            record = _record_or_none(decision, at=self._clock())
        # ------------------------------------------------------------------
        # G24: THE SPEND. An authorization is spent when it is USED, and this
        # is the one place every path passes through, so this is where it is
        # consumed. No `pending_id is not None` guard: the exception for the
        # auto-approved path is precisely the finding, and "the same gateway
        # with an exception" is what made the control-plane claim
        # unfalsifiable.
        #
        # ORDER, and why it is this order. The STATE is read here, early, so a
        # replay is refused before any work is done and with a reason that
        # names which of the five states it is in. The CLAIM is taken below,
        # immediately before the executor, because only an atomic claim
        # adjacent to the call is at-most-once under concurrency. The read is
        # for the message; the claim is for the guarantee.
        key = self._spend_key(decision, record)
        prior = self._settle_spend(
            key, decision, idempotency_key=idempotency_key, detail_prefix=detail_prefix
        )
        if prior is not None:
            return prior
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
                authorization=record,
            )
            return refused
        # THE SECOND COMPARISON, and its placement is the whole of the bound it
        # provides. AFTER the claim, so a concurrent driver cannot slip an
        # execution between this read and the executor call; IMMEDIATELY BEFORE
        # ``executor.execute``, with nothing between them, so the window a
        # third party can move the target in is the narrowest this design can
        # make it. It is still a window — see the TOCTOU residual in
        # ``docs/live-state-pinning-design.md`` §7.1, which is bounded and not
        # closed.
        #
        # A refusal here is recorded as a refused execution row BEFORE it is
        # re-raised, and whether it releases the claim depends on WHICH refusal
        # it is (``CLAIM_RETAINED_BY``).
        #
        # THE ROW, because the hold was claimed and an execution was attempted:
        # without it ``executions_for_pending`` shows nothing, and an approved
        # action that did not execute is indistinguishable from one nobody
        # tried. That is the audit contract this controller states, and a
        # refusal is exactly the outcome it exists to record.
        #
        # THE CLAIM: a ``StateMoved`` refusal is terminal and keeps it spent,
        # so a hold whose target moved cannot be re-driven. Every other refusal
        # is "the check could not run" and RELEASES it — a transient observer
        # outage must not permanently brick an approved hold, which is what
        # retaining the claim did: the status stayed ``approved``, so
        # ``retry_decision`` accepted the hold, and ``claim_pending_execution``
        # then failed forever with "already in progress or has completed".
        if pending_id is not None:
            try:
                self._pending.require_state_unmoved_for_execution(
                    pending_id,
                    execution_attempt=self._execution_attempt(pending_id),
                    now=self._clock(),
                )
            except ExecutionNotAuthorized as refusal:
                # STATEMENT form, and no ``getattr`` default. ``reason`` is
                # always present on this exception but is ``str | None``, and a
                # default would make "carried no typed reason" and "the
                # attribute was missing" the same bytes in the row. When there
                # is none the row SAYS there is none, rather than borrowing a
                # reason-shaped string that no member of
                # ``EXECUTION_REFUSAL_REASONS`` matches.
                reason = refusal.reason
                if reason is None:
                    reason = "no typed reason"
                self._ledger.record_execution(
                    subject_id=decision.subject_id,
                    source=source,
                    executed=False,
                    refused=True,
                    sandbox_name="",
                    exit_status=None,
                    detail=(
                        f"{detail_prefix}refused before execution "
                        f"({reason}): {refusal}"
                    ),
                    created_at=self._clock(),
                    judgment=_judgment_or_none(decision),
                    pending_id=pending_id,
                    authorization=record,
                )
                if not refusal_retains_claim(refusal):
                    self._ledger.release_pending_execution(pending_id)
                raise
        # THE CLAIM, adjacent to the executor and nothing between them. One
        # statement against a PRIMARY KEY, so of any number of concurrent
        # drivers on any path exactly one proceeds. The loser refuses with the
        # same reason a replay gets, because from its side that is what it is:
        # the occurrence was spent by someone else.
        attempt_id = str(record.get("attempt_id", "")) if record is not None else ""
        if not self._ledger.claim_authorization(
            key,
            attempt_id=attempt_id,
            idempotency_key=idempotency_key,
            claimed_at=self._clock(),
        ):
            raise ExecutionNotAuthorized(
                f"this authorization for {decision.subject_id!r} was spent by a "
                "concurrent driver between the check and the claim",
                reason="authorization_already_spent",
            )
        result = self._executor.execute(decision)
        execution_id = self._ledger.record_execution(
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
            authorization=record,
            # #120's structural pair, passed through as the executor measured
            # it. Every other ``record_execution`` call in this module records
            # a row for which NO executor was invoked and leaves both at their
            # ``None`` default — the third state, distinct from ``False``.
            started_ok=result.started_ok,
            candidate_started=result.candidate_started,
        )
        # THE SPEND SETTLES, both ways, and on every path.
        #
        # A fail-closed refusal has no side effect, so the authorization is
        # RELEASED — by appending a retraction, never by deleting the spend.
        # Without this a missing sandbox would burn the authorization
        # permanently, which is the same brick the hold claim's release exists
        # to avoid, and the reason a release is available at all.
        #
        # An execution that happened COMPLETES the spend, naming the row it
        # wrote. That is what makes a later declared retry able to return this
        # result rather than run anything, and what separates "ran" from
        # "claimed and never came back".
        if result.refused:
            self._ledger.release_authorization(
                key,
                released_at=self._clock(),
                reason=f"fail-closed refusal, no side effect: {result.detail}"[:200],
            )
        else:
            self._ledger.complete_authorization(
                key, execution_id=execution_id, completed_at=self._clock()
            )
        # A fail-closed refusal has no side-effect: release the claim so the
        # approved hold stays retry-eligible. A successful execution keeps its
        # claim, so the hold cannot execute again.
        if pending_id is not None and result.refused:
            self._ledger.release_pending_execution(pending_id)
        return result
