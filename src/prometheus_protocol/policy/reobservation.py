"""Re-observation at execution: read the target again, compare, refuse on a move.

THE GAP THIS CLOSES, measured rather than supposed. A hold records evidence at
assessment time and executes later against that evidence REPLAYED from the
persisted record — ``execution/pending.py`` restores the coverage report from
the record and calls no verifier, and nothing in ``execution/`` calls one. So a
``branch.delete`` reviewed as "zero commits absent from the base" deletes on
that sentence however long ago it was true, and however much the branch has
gained since. ``tests/conformance/test_reobservation_branch_delete.py`` drives
exactly that and shows what happens with this module absent.

TWO COMPARISONS, ANSWERING DIFFERENT QUESTIONS. Neither replaces the other.

* **Pre-approval** makes the APPROVAL meaningful. It runs before the approval
  is recorded, not after, so an approval on the record is one whose premise
  still held when the human gave it. A mismatch refuses and the hold stays
  PENDING — a state the system already understands.
* **Pre-execution** makes the EXECUTION meaningful. It runs immediately before
  the executor is called. A mismatch refuses AND makes the hold terminal: the
  state moved after a human looked at it, so the approval is stale as a matter
  of fact and retrying cannot make it fresh. Re-verification is a NEW hold with
  a NEW approval, so the human sees the new state rather than re-approving the
  old decision.

Both are required because moving the first one earlier WIDENS the window the
second one exists to narrow. The residual is in §7.1 of the design and is
bounded, not closed.

UNAVAILABILITY ALWAYS HALTS. A target that cannot be read is not a target that
has not changed. There is no routing path here and none is to be added: a human
asked to approve an action whose live state could not be read is being asked to
approve on no information, which is what ``ExecutionController.submit`` already
refuses for an authoritative check that could not run. A PARTIAL read halts too,
and is never digested: a digest over the readable half is a different
measurement wearing the same name, and it would compare equal while the
unreadable half moved.

THE OPT-OUT IS PER ACTION CLASS, NEVER GLOBAL, and it is a NAMED REASON that
travels in the record. G21 is the precedent: a posture reached by ABSENCE
states nothing — it is what an unset variable and a deliberate choice both look
like. A global switch is what a deployment reaches for under pressure and
nothing in the record distinguishes it from "this class does not need it".

TOTAL OVER THE CLOSED SET, BY CONSTRUCTION. Every member of ``ACTION_CLASSES``
is either observed or opted out with a reason, and :class:`ReObservation`
refuses to be built otherwise. A class in neither would be silently
unobserved — the third state that reads like the first — and a class in both is
a contradiction rather than a precedence puzzle.

WHAT THIS MODULE DOES NOT DO. It does not decide whether an aspect list is
COMPLETE over what a target can vary; that judgement is in
``policy/target_state.py`` and its named limit. It does not make the comparison
atomic with the execution — see the TOCTOU residual. And it never carries the
state itself anywhere: digests and aspect names only, because a catalog dump in
the ledger is an unbounded persisted blob and ``verifier/model_judge.py``'s F8
defect is the measured precedent for what ends up in one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Protocol

from prometheus_protocol.core.models import ExecutableAction, Unavailable
from prometheus_protocol.policy.execution import ExecutionNotAuthorized
from prometheus_protocol.policy.snapshot import ACTION_CLASSES, _identity
from prometheus_protocol.policy.target_state import aspects_of, state_digest

#: The moment a reading was taken. Closed, because a record that cannot say
#: WHICH reading it describes cannot show that state was checked twice.
MOMENT_CAPTURE = "capture"
MOMENT_PRE_APPROVAL = "pre_approval"
MOMENT_PRE_EXECUTION = "pre_execution"
MOMENTS: frozenset[str] = frozenset(
    {MOMENT_CAPTURE, MOMENT_PRE_APPROVAL, MOMENT_PRE_EXECUTION}
)

#: What a comparison found. Closed for the same reason the refusal reasons are:
#: a test asserting WHICH outcome fired should not have to match prose.
OUTCOME_MATCHED = "matched"
OUTCOME_MOVED = "moved"
OUTCOME_UNAVAILABLE = "unavailable"
OUTCOME_ASPECTS_DIFFER = "aspects_differ"
OUTCOMES: frozenset[str] = frozenset(
    {OUTCOME_MATCHED, OUTCOME_MOVED, OUTCOME_UNAVAILABLE, OUTCOME_ASPECTS_DIFFER}
)

#: The audit-chain event an observation is bound under.
OBSERVATION_EVENT = "execution.observation"

#: The observation record's shape.
OBSERVATION_RECORD_VERSION = 1


class StateMoved(ExecutionNotAuthorized):
    """The target is not what the pinned record says it was.

    A distinct type so a caller can tell "the state moved" from every other
    refusal the seam makes, and ``reason`` distinguishes WHICH comparison found
    it — the two have different consequences for the hold.
    """


class StateUnreadable(ExecutionNotAuthorized):
    """The target could not be read, wholly or in part. Never a comparison."""


class StateUnobservable(ExecutionNotAuthorized):
    """The hold was pinned to live state that THIS service does not observe.

    Distinct from both siblings, because it is a statement about the DEPLOYMENT
    and not about the target: the state was not read, was not unreadable, and
    did not move — the registry in front of this hold has the hold's action
    class opted out, so the comparison the hold's own record says it is subject
    to cannot be made here.

    WHY THIS IS A REFUSAL AND NOT A SKIP. Two composition roots can disagree,
    and wiring re-observation is what made that possible: a hold created by a
    root naming a ``git://`` principal carries ``observed: true``, and the CLI's
    ``approve`` builds its controller with the default ``sandbox://execution``
    target, which opts ``branch.delete`` out. Skipping the comparison there
    would execute an irreversible delete on evidence the hold's own record
    claims was re-checked — degrading a requested security property instead of
    refusing it (doctrine #2). Measured, not hypothetical: before this type
    existed the same path raised a bare ``KeyError`` out of ``approve``.
    """


#: Which pre-execution refusals leave the hold RETRYABLE, keyed on TYPE.
#:
#: WHY A TYPE AND NOT A REASON STRING. The three refusal types are the closed
#: vocabulary; a reason distinguishes WHICH comparison found it, and two
#: reasons can share a type. Keying on the type is keying on the fact.
#:
#: ONLY ``StateMoved`` RETAINS THE CLAIM. A hold whose target moved must never
#: execute, and the claim is a second lock on that. Everything else is doctrine
#: #1's "the check could not run": an observer outage or a deployment that does
#: not observe the class says nothing about the target, and a hold left claimed
#: after one is a hold that can never execute and can never be retried — the
#: claim is spent forever and every retry reports "already in progress". That
#: is a transient outage permanently bricking an approved action, which is the
#: road an operator ends by removing the requirement (G21).
#:
#: THE DEFAULT FOR A TYPE NOT NAMED HERE IS TO RELEASE, and that is safe
#: because terminal-ness does not live in the claim: ``StateMoved`` transitions
#: the hold's STATUS out of ``approved``, and ``retry_decision`` refuses it on
#: the status alone. The claim is belt; the status is suspenders. A new refusal
#: type that must retain the claim has to be added here deliberately, and
#: ``test_reobservation_branch_delete.py`` pins this mapping's key set so it
#: cannot fall behind the types.
CLAIM_RETAINED_BY: "frozenset[type]" = frozenset({StateMoved})


def refusal_retains_claim(refusal: BaseException) -> bool:
    """Whether ``refusal`` leaves the at-most-once claim spent."""

    return any(isinstance(refusal, kind) for kind in CLAIM_RETAINED_BY)


def legacy_observation_subject(attempt_id: str, execution_attempt: int) -> str:
    """The subject format used BEFORE the pending-hold id was added.

    Kept because a ledger outlives a deployment. A hold approved under the
    previous release carries its pre-approval receipt under this spelling, and
    a lookup that searched only the current one would return ``None`` — which
    the caller reads as "there was no pre-approval reading", so the execution
    receipt would say ``prior: null`` and lose the evidence that state WAS
    checked at approval. A false statement in the record whose whole purpose is
    to show the check happened twice.

    This is NOT a second supported format. Nothing writes it; it exists only so
    the reader can recognise what an older writer left, and a receipt resolved
    through it is marked (see ``LEGACY_SUBJECT_RESOLVED``) rather than passed
    off as a clean match.
    """

    return f"observation:{_identity(attempt_id, what='attempt_id')}#{execution_attempt}"


#: Stamped onto a receipt that was found under the pre-upgrade subject, so the
#: record says how it was attributed instead of implying an exact match.
LEGACY_SUBJECT_RESOLVED = "resolved_from_pre_upgrade_subject"


@dataclass(frozen=True)
class Unreadable:
    """Why a reading could not be taken, and which aspects were not read.

    ``aspects_unread`` is carried rather than inferred: a refusal that says only
    "could not read" leaves an operator unable to tell a whole-target outage
    from one aspect's query failing, and those have different remedies.
    """

    reason: str
    detail: str = ""
    aspects_unread: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identity(self.reason, what="unavailable reason")


@dataclass(frozen=True)
class Observation:
    """One reading of a target: its digest and covered set, or why neither exists.

    Exactly one of ``digest`` and ``unavailable`` is set. Both-or-neither is
    refused at construction rather than left for a reader to interpret, because
    "no digest and no reason" is precisely the shape that reads downstream as a
    pass.
    """

    moment: str
    observed_at: str
    digest: str | None = None
    aspects: tuple[str, ...] = ()
    unavailable: Unreadable | None = None

    def __post_init__(self) -> None:
        if self.moment not in MOMENTS:
            raise ValueError(
                f"{self.moment!r} is not a known observation moment; known: "
                f"{sorted(MOMENTS)}"
            )
        _identity(self.observed_at, what="observed_at")
        if (self.digest is None) == (self.unavailable is None):
            raise ValueError(
                "an observation carries EITHER a digest or the reason it has "
                "none. Carrying neither is the shape that reads as a pass, and "
                "carrying both is two answers to one question."
            )
        if self.digest is not None and not self.aspects:
            raise ValueError(
                "an observation with a digest names the aspects the digest "
                "spanned; a digest whose covered set is unknown cannot be "
                "compared with another"
            )

    @property
    def readable(self) -> bool:
        return self.digest is not None

    def as_dict(self) -> dict:
        return {
            "moment": self.moment,
            "observed_at": self.observed_at,
            "digest": self.digest,
            "aspects": list(self.aspects),
            "unavailable": (
                None
                if self.unavailable is None
                else {
                    "reason": self.unavailable.reason,
                    "detail": self.unavailable.detail,
                    "aspects_unread": list(self.unavailable.aspects_unread),
                }
            ),
        }


class StateObserver(Protocol):
    """Reads the live state of one action class's target.

    Returns a frozen dataclass whose fields ARE the covered set, or an
    ``Unavailable`` when the read could not be completed. It never returns a
    partial state: a partially-read target is unavailable, because a digest
    over the readable half compares equal while the rest moves.
    """

    def observe(
        self, *, target_canonical: str, action: ExecutableAction
    ) -> "object | Unavailable | Unreadable": ...


@dataclass(frozen=True)
class ReObservation:
    """Which action classes are re-observed, which are opted out, and by what.

    Built at the composition root and handed to the pending service and the
    execution controller, so both comparisons read the same registry and the
    same opt-out. Total over ``ACTION_CLASSES`` by construction.
    """

    observers: Mapping[str, StateObserver] = field(default_factory=dict)
    opted_out: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        observed = set(self.observers)
        out = set(self.opted_out)
        unknown = sorted((observed | out) - ACTION_CLASSES)
        if unknown:
            raise ValueError(
                f"re-observation names unknown action class(es) {unknown}. The "
                f"set is closed: {sorted(ACTION_CLASSES)}."
            )
        both = sorted(observed & out)
        if both:
            raise ValueError(
                f"action class(es) {both} are both observed and opted out. That "
                "is two answers to one question, not a precedence to resolve."
            )
        missing = sorted(ACTION_CLASSES - observed - out)
        if missing:
            raise ValueError(
                f"action class(es) {missing} are neither re-observed nor opted "
                "out with a named reason. A class in neither is silently "
                "unobserved, which is what an unset variable and a deliberate "
                "choice both look like (OPEN-GAPS G21). Name the reason."
            )
        for action_class, reason in self.opted_out.items():
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError(
                    f"the opt-out for {action_class!r} must be a NAMED reason; "
                    "an empty one states nothing, which is the posture-by-"
                    "absence this ruling exists to remove"
                )

    def covers(self, action_class: str) -> bool:
        return action_class in self.observers

    def opt_out_reason(self, action_class: str) -> str | None:
        return self.opted_out.get(action_class)

    def observe(
        self,
        *,
        action_class: str,
        target_canonical: str,
        action: ExecutableAction,
        moment: str,
        at: str,
    ) -> Observation:
        """Read the target now. Never raises for an unreadable target — the
        refusal is the CALLER's, because what an unreadable target means differs
        between capture, approval and execution."""

        observer = self.observers.get(action_class)
        if observer is None:
            raise KeyError(
                f"no state observer for action class {action_class!r}; "
                "ReObservation is total over ACTION_CLASSES, so this means the "
                "class is opted out and the caller should not have asked"
            )
        try:
            found = observer.observe(target_canonical=target_canonical, action=action)
        except Exception as exc:  # noqa: BLE001 - an observer fault is unavailability
            # An observer that raises is a target that could not be read. It is
            # NOT a mismatch and must never be one: "the instrument broke" and
            # "the subject changed" are different findings, and collapsing them
            # would report a move nobody made.
            return Observation(
                moment=moment,
                observed_at=at,
                unavailable=Unreadable(
                    reason="observer_fault",
                    detail=f"{type(exc).__name__}: {exc}",
                ),
            )
        if isinstance(found, Unreadable):
            # The observer's own type, which carries WHICH ASPECTS it could not
            # read. Preferred over ``Unavailable`` for exactly that: a refusal
            # saying only "could not read" leaves an operator unable to tell a
            # whole-target outage from one aspect's query failing, and those
            # have different remedies.
            return Observation(moment=moment, observed_at=at, unavailable=found)
        if isinstance(found, Unavailable):
            # Doctrine #1's type, accepted so an observer built out of an
            # existing verifier can return what that verifier already returns.
            # It carries no aspect breakdown, and the record says so by leaving
            # ``aspects_unread`` empty rather than guessing at one.
            return Observation(
                moment=moment,
                observed_at=at,
                unavailable=Unreadable(
                    reason=found.reason.value,
                    detail=found.detail,
                ),
            )
        return Observation(
            moment=moment,
            observed_at=at,
            digest=state_digest(found),
            aspects=aspects_of(found),
        )


#: The opt-out reason a composition root gives for the two action classes
#: phase 1 does not cover. Spelled once, here, because it appears in every hold
#: record those roots create and a reason that drifted between roots would make
#: two deployments' records incomparable for no reason anyone chose.
PHASE_ONE_NOT_COVERED = (
    "re-observation phase 1 covers branch.delete only; this action class is not "
    "observed and its holds execute against replayed evidence"
)

#: The opt-out reason for an action class this root's target cannot BE. A root
#: whose principal is not a git repository has no branch state to read, and
#: saying so is different from saying the class is out of scope: one is about
#: the deployment, the other about the phase.
NOT_THIS_PRINCIPAL = (
    "this composition root's target is not a git principal, so there is no "
    "branch state to observe here"
)

#: The capture point a pinned reading describes. ``review`` is hold creation,
#: which is where §2.1 ruled the capture point. ``rehearsal`` is the successor
#: feature and is deliberately not a value this code can produce yet: a field
#: that can only say one thing still says which one, and a record written today
#: must not read as though it came from a rehearsal that does not exist.
CAPTURE_REVIEW = "review"


def pinned_target_state(observation: Observation) -> dict:
    """The ``target_state`` block for a hold whose target WAS read at creation."""

    if not observation.readable:
        raise ValueError(
            "a pinned target state requires a reading; an unreadable target "
            "halts at hold creation and pins nothing"
        )
    return {
        "observed": True,
        "capture_point": CAPTURE_REVIEW,
        "digest": observation.digest,
        "aspects": list(observation.aspects),
        "observed_at": observation.observed_at,
    }


def opted_out_target_state(action_class: str, reason: str) -> dict:
    """The ``target_state`` block for an action class opted out BY NAME.

    The record says the deployment chose this, and what it called the choice.
    That is the whole point of the ruling: "remove the requirement" and "never
    had one" are indistinguishable, and a named value in the record is not.
    """

    return {"observed": False, "opted_out": reason, "action_class": action_class}


def unconfigured_target_state() -> dict:
    """The ``target_state`` block when the deployment wired no re-observation.

    PRESENT AND EXPLICIT, never absent. A record that omits the field on a
    deployment with no re-observation is indistinguishable from one where the
    comparison ran and passed, and §6.2's rule about the unavailable field
    applies with more force to the whole block: this is the difference between
    "checked" and "never checked" on the row that authorizes a side effect.
    """

    return {
        "observed": False,
        "not_configured": (
            "this deployment wired no re-observation, so no live state was read "
            "at hold creation and none is compared before approval or execution"
        ),
    }


def pinned_reading_of(record: Mapping[str, object]) -> tuple[str, tuple[str, ...]] | None:
    """``(digest, aspects)`` a hold is pinned to, or ``None`` when it pinned none.

    Refuses a record whose ``target_state`` is missing entirely: a versioned
    record that carries no block at all is not "not observed", it is a record
    this code cannot read, and reading it as "nothing to compare" would turn a
    shape mismatch into a silent pass.
    """

    block = record.get("target_state")
    if block is None:
        raise ExecutionNotAuthorized(
            "the pinned record carries no target_state block; re-observation "
            "cannot tell an unobserved hold from an unreadable record",
            reason="target_state_absent",
        )
    if not isinstance(block, Mapping):
        raise ExecutionNotAuthorized(
            f"target_state is {type(block).__name__}, not a record",
            reason="target_state_absent",
        )
    if not block.get("observed"):
        return None
    digest = block.get("digest")
    aspects = block.get("aspects")
    if not isinstance(digest, str) or not digest or not isinstance(aspects, (list, tuple)):
        raise ExecutionNotAuthorized(
            "target_state claims a reading but carries no usable digest and "
            "aspect list",
            reason="target_state_absent",
        )
    return digest, tuple(str(name) for name in aspects)


def compare(
    *, pinned_digest: str, pinned_aspects: tuple[str, ...], observation: Observation
) -> str:
    """One of :data:`OUTCOMES`, for a pinned reading against a fresh one.

    ASPECTS ARE COMPARED BEFORE DIGESTS, deliberately. Two digests taken over
    different covered sets are not comparable at all, and reporting "moved"
    for them would name the wrong finding: the target may be untouched while
    the INSTRUMENT changed under it, which is a deployment-version problem and
    not a state problem.
    """

    if not observation.readable:
        return OUTCOME_UNAVAILABLE
    if tuple(observation.aspects) != tuple(pinned_aspects):
        return OUTCOME_ASPECTS_DIFFER
    return OUTCOME_MATCHED if observation.digest == pinned_digest else OUTCOME_MOVED


def observation_subject(
    attempt_id: str, execution_attempt: int, *, pending_id: int
) -> str:
    """The chain subject an observation is bound under.

    THE HOLD IDENTITY IS IN THE KEY, and leaving it out was a defect (PR #113
    review). The original ruling keyed on the verification attempt alone,
    because that is what the pinned record binds to — but ``attempt_id`` is
    CALLER-SUPPLIED and nothing requires it to be unique. Two holds created with
    the same attempt therefore shared ``observation:<attempt>#0``, and
    ``pre_approval_entry`` returns the first matching event, so the later hold's
    execution receipt restated the EARLIER hold's observation: a receipt for one
    decision carrying another decision's evidence.

    Fixed by including the hold, NOT by requiring attempts to be unique. A
    uniqueness rule would be a new global constraint on every caller, it could
    not be applied retroactively to rows already written, and it would be
    enforced far from where a duplicate is created. The hold id is already
    unique — it is the ledger's own primary key — and it is already the thing
    the pinned record is attached to, so the pairing stays structural.

    The ordinal separates a retry's reading from the first one, so a retry ADDS
    a record instead of overwriting one. ``0`` is the pre-approval reading,
    which precedes every execution attempt.
    """

    if not isinstance(execution_attempt, int) or isinstance(execution_attempt, bool):
        raise ValueError("execution_attempt must be an integer")
    if execution_attempt < 0:
        raise ValueError("execution_attempt counts from 0 (the pre-approval reading)")
    if not isinstance(pending_id, int) or isinstance(pending_id, bool):
        raise ValueError("pending_id must be the hold's integer identity")
    attempt = _identity(attempt_id, what="attempt_id")
    return f"observation:{attempt}@pending:{pending_id}#{execution_attempt}"


def observation_record(
    *,
    attempt_id: str,
    execution_attempt: int,
    action_class: str,
    target_canonical: str,
    pinned: Mapping[str, object],
    observation: Observation,
    outcome: str,
    prior: Mapping[str, object] | None = None,
) -> dict:
    """The append-only record of one comparison.

    It carries what it was compared AGAINST as well as what was found, so the
    entry stands alone rather than requiring a reader to join two rows
    correctly; the covered set at observation time, so a reader knows what the
    digest spanned; and, on the pre-execution entry, ``prior`` — the
    pre-approval entry restated — so one receipt shows that state was checked
    twice and what moved between the two.

    It never carries the state itself.
    """

    if outcome not in OUTCOMES:
        raise ValueError(f"{outcome!r} is not a known comparison outcome")
    return {
        "record_version": OBSERVATION_RECORD_VERSION,
        "attempt_id": attempt_id,
        "execution_attempt": execution_attempt,
        "action_class": action_class,
        "target_canonical": target_canonical,
        "pinned": dict(pinned),
        "observed": observation.as_dict(),
        "outcome": outcome,
        "prior": None if prior is None else dict(prior),
    }
