"""An authorization is SPENT when it is used: the occurrence, not the identity.

WHAT THIS CLOSES (G24). ``ExecutionController._execute`` claimed the right to
run only when the action came from a hold — ``controller.py:367`` said in so
many words that "the auto-approved path carries no hold (pending_id is None)
and needs no claim". Measured at ``7cc2c4c``: submitting the same auto-approved
assessment, action and ``attempt_id`` twice called the executor **twice** and
wrote two execution rows. The same approved ``GateDecision``, retained and
handed to a concrete executor's public ``execute()``, ran **twice**. The
low-risk path carried a weaker guarantee than the held path, in the same
gateway, and the exception is what made the control-plane story unfalsifiable.

THE RULING IS ONE OCCURRENCE, NOT ONE ACTION IDENTITY. "Agents get
capabilities, they don't get keys" is a claim about a grant that does not
survive its use. A replayable decision is a bearer token with a narrow scope —
a better key, not the absence of one. So the unit of spend is the OCCURRENCE:
this assessment, of this artifact, against this policy, for this attempt. Two
submissions that differ in any bound field are two occurrences and both may
run; two that agree in all of them are one, and the second is refused.

WHERE THE SPEND LIVES, AND WHY IT IS NOT A ROW.

The spend is enforcement state, so the thing that records it also decides —
which reopens R1's shape at the database layer: an attacker with write
authority who can reset a spend restores the authority it consumed. A mutable
row is exactly resettable, so a row cannot be the authority.

**The authority is the audit chain, and the state is DERIVED from it** by
folding the append-only entries for one subject (:func:`spend_state`). A row
exists — ``spent_authorizations`` — but only to decide the RACE: its PRIMARY
KEY makes the first of several concurrent claimants the single winner in one
SQL statement, the same shape as the hold claim's conditional ``UPDATE``. The
row is never asked whether an authorization is spent.

That split is what survives the threat model:

* delete or reset the ROW, leave the chain: the fold still says spent, and the
  replay is still refused — the reset restores nothing;
* delete the chain ENTRY: ``verify_chain`` fails against the external anchor,
  which is the detection this repository already has;
* delete both: same, the chain is what breaks.

THE COST, stated rather than discovered. The fold is a walk of the chain's
entries per execution — O(entries), against a table that only grows. It buys
tamper-evidence a row cannot buy. ``spend_state`` takes the events it is given
rather than reading them, so a caller that has already loaded a snapshot pays
for one walk, not two.

APPEND-ONLY DOES NOT MEAN IRREVERSIBLE. A fail-closed refusal has no side
effect and must not brick the authorization, exactly as a refused execution
releases a hold's claim today. Releasing is itself an APPEND — a
``authorization.release`` entry naming the spend it retracts — so the state is
the fold of both, and nothing is ever rewritten. Deleting a release entry can
only make the fold read MORE spent, which is the fail-closed direction; that
is why the retraction is expressed this way round.

RETRY IS DECLARED, NOT INFERRED. Unbounded replay is not a retry story, and a
network failure mid-execute must not become a stuck state with no safe
recovery. A caller that wants to be able to retry supplies an
``idempotency_key`` on the FIRST call; the same key on a later call for the
same occurrence returns the prior outcome instead of running anything. A call
with no key, or a key that does not match, is a replay and is refused. See
:func:`retry_verdict`.

A RETRY CANNOT CHANGE A BOUND FIELD, and this is structural rather than
checked: the spend key is DERIVED from the bound fields, so a retry that
alters one derives a DIFFERENT key, names no prior spend, and is simply a new
authorization that must pass the whole gate on its own. There is no retry path
that reaches an executor around the descriptor comparison, because there is no
retry path that reaches an executor at all — a matching retry returns a
recorded outcome and never calls one.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from prometheus_protocol.ledger.audit_chain import canonical_json

#: The chain event under which an authorization is spent, subject
#: ``authorization:<key>``. Appended by the ledger in the same call that wins
#: the race for the row.
#:
#: NOT inside the ``execute``/``execution`` prefix: ``chokepoint/
#: reconcile_gate.py`` claims that prefix for its own entries and raises on a
#: payload without ``approval_binding``. ``receipts.py`` records the same
#: constraint for ``outcome.execution``; this event is named for the same
#: reason and not by coincidence.
SPEND_EVENT = "authorization.spend"

#: The retraction of a spend whose execution turned out to have NO side effect
#: (a fail-closed refusal). An append, never a delete — see the module
#: docstring on why this direction is the fail-closed one.
RELEASE_EVENT = "authorization.release"

#: The spend COMPLETED, and this execution row is its outcome. Appended after
#: the executor returns, so it cannot be part of the claim.
#:
#: WHY A THIRD EVENT AND NOT A FIELD ON THE OUTCOME RECEIPT. The obvious
#: alternative was to widen ``receipts.OUTCOME_FIELDS`` with the authorization
#: key. Measured: that changes the payload every existing outcome entry was
#: hashed over, so every execution row written before the change reads as
#: ``outcome_differs_from_chain_entry`` and every ledger in existence fails
#: receipt verification. A new event is additive — nothing already chained
#: changes — which is why no ``RECORD_VERSION`` bump is needed and why holds
#: already pending are unaffected.
#:
#: IT ALSO BUYS THE DISTINCTION THAT MATTERS. A spend with no outcome and no
#: release is an occurrence that was claimed and never finished — a crash
#: between the claim and the executor returning. That is not "unspent" and it
#: is not a completed execution either; it is the one state where the system
#: genuinely does not know whether the side effect happened, and collapsing it
#: into either neighbour would be a lie in the direction of running again.
SPEND_OUTCOME_EVENT = "authorization.outcome"

#: The subject prefix both events share.
SUBJECT_PREFIX = "authorization"

#: The bound fields the key is derived from, and the whole of it.
#:
#: These are the descriptor's six fields plus the assessment's
#: ``snapshot_digest``. Together they are the OCCURRENCE: change any one and
#: this is a different authorization, which is exactly the property that makes
#: "a retry may not change a bound field" structural instead of checked.
#:
#: ``pinned_at`` is deliberately NOT here: the same occurrence recorded at two
#: times is one occurrence, and including a timestamp would make every replay
#: derive a fresh key and defeat the whole mechanism. ``coverage`` is not here
#: either — it is the evidence the occurrence was authorized ON, and it is
#: already bound into ``snapshot_digest``.
KEY_FIELDS: tuple[str, ...] = (
    "attempt_id",
    "policy_id",
    "policy_digest",
    "action_class",
    "artifact_sha256",
    "target_canonical",
    "snapshot_digest",
)

#: Claimed, and neither completed nor released: the occurrence was spent and
#: the process never came back. NOT a synonym for either neighbour — see
#: :data:`SPEND_OUTCOME_EVENT`.
SPENT = "spent"
#: Claimed and completed: the execution row named by the outcome entry is this
#: occurrence's one execution.
COMPLETED = "completed"
#: No entry for this key at all: the authorization has never been used.
UNSPENT = "unspent"
#: Spent, then retracted by a later release: free to be claimed again.
RELEASED = "released"


class SpendRecordMalformed(ValueError):
    """A chained spend entry whose payload cannot be read as one.

    REFUSED, NOT SKIPPED (doctrine #2). An unreadable entry for this subject is
    an entry this fold cannot account for, and a fold that ignores it would
    report ``unspent`` — the one answer that lets an execution through. The
    caller turns this into a typed refusal; it never becomes a default.
    """


def authorization_key(record: Mapping[str, Any]) -> str:
    """The occurrence's identity, as a digest over its bound fields.

    Derived from the AUTHORIZATION RECORD rather than from a live descriptor,
    because the record is what both paths have in common: a hold carries its
    pinned record and an auto-approved decision mints one at authorization
    time, and the same occurrence must derive the same key through either.

    Refuses a record missing any bound field rather than hashing ``None`` into
    the key: a key derived from an absent field would collide with every other
    record missing the same field, and a collision here is a refusal to execute
    something that was never authorized — or worse, a spend that silently
    covers two different occurrences.
    """

    if not isinstance(record, Mapping):
        raise SpendRecordMalformed(
            f"an authorization key is derived from a record mapping, not {type(record).__name__}"
        )
    missing = [name for name in KEY_FIELDS if record.get(name) is None]
    if missing:
        raise SpendRecordMalformed(
            f"authorization record carries no {missing}; the occurrence it names "
            "cannot be identified, so no spend can be recorded against it"
        )
    bound = {name: record[name] for name in KEY_FIELDS}
    return hashlib.sha256(canonical_json(bound).encode("utf-8")).hexdigest()


def spend_subject(key: str) -> str:
    """``authorization:<key>`` — the chain subject both events share."""

    return f"{SUBJECT_PREFIX}:{key}"


def spend_payload(
    key: str, *, attempt_id: str, idempotency_key: str | None, claimed_at: str
) -> dict[str, Any]:
    """What the spend entry says, and all it says.

    ``attempt_id`` is carried in the clear beside the key so an auditor reading
    the chain can tell WHICH attempt a spend belongs to without re-deriving
    every key; the key remains the identity. ``idempotency_key`` is the
    caller's declaration that this occurrence may be retried, recorded at the
    moment of the spend so a later claim of retry can be checked against
    something the caller cannot change afterwards.
    """

    return {
        "key": key,
        "attempt_id": attempt_id,
        "idempotency_key": idempotency_key,
        "claimed_at": claimed_at,
    }


def release_payload(key: str, *, released_at: str, reason: str) -> dict[str, Any]:
    """What the retraction says: which key, when, and why it had no effect."""

    return {"key": key, "released_at": released_at, "reason": reason}


def outcome_payload(
    key: str, *, execution_id: int | None, completed_at: str
) -> dict[str, Any]:
    """The spend's completion: which execution row is this occurrence's one.

    ``execution_id`` is the row the executor's result was written to, whose own
    outcome receipt is chained under ``outcome.execution`` by the same ledger
    call. A retry that is owed the prior result reads it through this, so the
    result it returns is the one the chain vouches for.

    ``None`` IS A VALUE HERE, not a missing argument: a caller that writes no
    execution row — the swarm runtime records attempts — still completes its
    spend, because "ran" and "claimed and never came back" are different states
    and it knows which. What it gives up is a prior result to return, which
    ``retry_verdict`` never asks it for: retryability is declared on the first
    call, and that path declares none.
    """

    return {"key": key, "execution_id": execution_id, "completed_at": completed_at}


@dataclass(frozen=True)
class SpendState:
    """The fold of one subject's append-only entries.

    ``status`` is one of :data:`UNSPENT`, :data:`SPENT`, :data:`COMPLETED`,
    :data:`RELEASED`. ``idempotency_key`` is the one recorded with the live
    spend, or ``None`` — and ``None`` means "this occurrence was never declared
    retryable", which is NOT the same as "any key matches". ``execution_id`` is
    the completed execution's row, or ``None``. ``entries`` is the count
    folded, so a caller can report what it read rather than only what it
    concluded.
    """

    status: str
    idempotency_key: str | None
    claimed_at: str | None
    entries: int
    execution_id: int | None = None

    @property
    def is_spent(self) -> bool:
        """Whether this occurrence has been used at all.

        ``SPENT`` and ``COMPLETED`` are both used; they differ in whether the
        outcome is known. A caller asking "may I run?" must treat both as no,
        which is why this is one predicate and the two states stay distinct on
        ``status`` for the caller that has to explain WHY.
        """

        return self.status in (SPENT, COMPLETED)


def _payload_of(entry: Mapping[str, Any]) -> dict[str, Any]:
    payload = entry.get("payload")
    if isinstance(payload, str):
        import json

        try:
            payload = json.loads(payload)
        except ValueError as exc:
            raise SpendRecordMalformed(
                f"a chained {entry.get('event')!r} entry carries a payload that is "
                f"not JSON: {exc}"
            ) from exc
    if not isinstance(payload, dict):
        raise SpendRecordMalformed(
            f"a chained {entry.get('event')!r} entry carries a "
            f"{type(payload).__name__} payload, not an object"
        )
    return payload


def spend_state(events: list[dict], *, key: str) -> SpendState:
    """Fold this subject's entries, in chain order, into the current state.

    THE AUTHORITY. Every caller that needs to know whether an authorization has
    been used asks this, over the chain — never the ``spent_authorizations``
    row, which exists only to decide the race. Resetting that row therefore
    restores nothing.

    The fold is ordered: a spend sets the state, a release clears it, and a
    later spend sets it again, so an occurrence that was claimed, released by a
    fail-closed refusal, and re-claimed reads as spent. Entries for other
    subjects are not this subject's business and are skipped by subject, which
    is a SELECTION and not a filter over the thing being counted — ``entries``
    reports how many were folded.
    """

    subject = spend_subject(key)
    status = UNSPENT
    idempotency_key: str | None = None
    claimed_at: str | None = None
    execution_id: int | None = None
    folded = 0
    for entry in events:
        if entry.get("subject") != subject:
            continue
        event = entry.get("event")
        if event not in (SPEND_EVENT, RELEASE_EVENT, SPEND_OUTCOME_EVENT):
            continue
        payload = _payload_of(entry)
        if payload.get("key") != key:
            # The subject named this key and the payload names another: the
            # entry has been re-attributed. Refused rather than skipped, for
            # the same reason the fold refuses an unreadable payload — and it
            # is the SUBSTITUTION attack, where a spend record from a different
            # occurrence is presented as this one's.
            raise SpendRecordMalformed(
                f"a chained {event!r} entry under {subject!r} carries key "
                f"{payload.get('key')!r}: the entry was re-attributed"
            )
        folded += 1
        if event == SPEND_EVENT:
            status = SPENT
            idempotency_key = payload.get("idempotency_key")
            claimed_at = payload.get("claimed_at")
            execution_id = None
        elif event == SPEND_OUTCOME_EVENT:
            # Only a live spend can complete. An outcome with no spend before
            # it is an entry out of order, which is a broken history rather
            # than a completion, and it refuses.
            if status != SPENT:
                raise SpendRecordMalformed(
                    f"a chained {SPEND_OUTCOME_EVENT!r} entry under {subject!r} "
                    f"follows state {status!r}, not an open spend"
                )
            status = COMPLETED
            execution_id = payload.get("execution_id")
        else:
            status = RELEASED
            idempotency_key = None
            claimed_at = None
            execution_id = None
    return SpendState(
        status=status,
        idempotency_key=idempotency_key,
        claimed_at=claimed_at,
        entries=folded,
        execution_id=execution_id,
    )


#: A caller may run: nothing has spent this occurrence.
MAY_EXECUTE = "may_execute"
#: A caller declared a retry and the key matches: the PRIOR outcome is owed,
#: and no executor is called.
RETURN_PRIOR = "return_prior"
#: Spent, and this is a replay rather than a declared retry.
REPLAY = "replay"
#: Spent and retryable, but the key supplied is not the one recorded.
KEY_MISMATCH = "key_mismatch"
#: Spent, and the caller declared a retry of an occurrence that was never
#: declared retryable. Distinct from ``KEY_MISMATCH``: there is no key to
#: mismatch, and the remedy is different — the FIRST call had to opt in.
NOT_RETRYABLE = "not_retryable"
#: Claimed and never completed: whether the side effect happened is genuinely
#: unknown. Refused for EVERY caller, matching key included — see
#: :func:`retry_verdict`.
OUTCOME_UNKNOWN = "outcome_unknown"
#: Spent, retryable, the key MATCHES — and the window has passed. Refuses; see
#: :data:`DEFAULT_IDEMPOTENCY_WINDOW_SECONDS` for what the window is for.
KEY_EXPIRED = "key_expired"

#: How long after the claim a matching idempotency key is still honoured.
#:
#: 24 HOURS, MIRRORING ``Config.pending_ttl_seconds``, and for the same reason:
#: the repository already rules that an approval a human gave yesterday is not
#: a licence today, and a retry credential minted alongside one should not
#: outlive it.
#:
#: WHAT THE WINDOW BOUNDS, PRECISELY. Not the record — the execution row and
#: its receipt are on the chain for good and an operator can read what happened
#: whenever they like. What expires is the CREDENTIAL: the ability of a caller
#: who holds the key to be handed the prior result automatically, in place of a
#: refusal. That is the credential-shaped half, so that is the half with a
#: lifetime.
#:
#: EXPIRY IS FAIL-CLOSED IN THE ONLY DIRECTION IT COULD BE. An expired key
#: REFUSES; it never falls back to :data:`MAY_EXECUTE`. The opposite reading —
#: "the window lapsed, so the retry becomes a fresh execution" — would make
#: waiting the cheapest way to buy a second side effect, which is the exact
#: thing G24 closes. Expiry can only ever make this function refuse MORE.
#:
#: THE NAMED LIMIT: this is a module constant and a controller argument, not a
#: ``Config`` field, so it is not settable from the environment and does not
#: appear in the attested posture. ``test_spend_the_authorization.py`` pins that
#: limit so it is a stated shortfall rather than an assumed feature.
DEFAULT_IDEMPOTENCY_WINDOW_SECONDS = 86_400


def _expired(claimed_at: str | None, *, now: str, window_seconds: int) -> bool:
    """Whether ``now`` is more than ``window_seconds`` after the claim.

    FAIL-CLOSED ON EVERY UNREADABLE INPUT. A missing or unparseable timestamp
    on either side means the age cannot be established, and an age that cannot
    be established is reported as expired — a credential whose lifetime cannot
    be checked has not been shown to be live. The alternative (treat it as
    fresh) would turn a corrupted timestamp into an unlimited window.
    """

    if window_seconds <= 0:
        # A named disable, matching ``pending_ttl_seconds``'s documented 0.
        return False
    if claimed_at is None:
        return True
    try:
        claimed = _parse_moment(claimed_at)
        current = _parse_moment(now)
    except ValueError:
        return True
    return (current - claimed).total_seconds() > window_seconds


def _parse_moment(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def retry_verdict(
    state: SpendState,
    *,
    idempotency_key: str | None,
    now: str,
    window_seconds: int = DEFAULT_IDEMPOTENCY_WINDOW_SECONDS,
) -> str:
    """What a caller presenting this key against this state is entitled to.

    Seven outcomes, not two, because the ways a claim of retry can fail have
    different remedies and an operator reading a refusal needs to know which
    one they are looking at. Every outcome but :data:`MAY_EXECUTE` and
    :data:`RETURN_PRIOR` refuses, and neither of those two runs an occurrence
    twice: the first IS the occurrence's one execution, and the second calls
    no executor at all.

    THE UNKNOWN OUTCOME REFUSES EVEN A MATCHING KEY, and this is the honest
    cost of strict one-shot rather than an oversight. A spend that was claimed
    and never completed is an occurrence whose side effect may or may not have
    happened; re-running it risks doing it twice, and returning a prior result
    would invent one. Neither is available, so it refuses and SAYS which state
    it is in — an operator can read the claim, establish what happened, and
    decide. That is a safe recovery path; a silent re-execution is not.

    ``now`` IS REQUIRED, with no default. A defaulted clock here would mean a
    caller that forgot to pass one silently got no expiry check at all — the
    disable-by-omission shape this repository refuses elsewhere. Every caller
    already holds a timestamp for the entries it is about to append.

    ORDER: the mismatch is reported BEFORE the expiry. A key that is not the
    recorded one is a different finding with a different remedy, and reporting
    "expired" for a key that was never right would misdirect the reader.
    """

    if not state.is_spent:
        return MAY_EXECUTE
    if state.status == SPENT:
        return OUTCOME_UNKNOWN
    if idempotency_key is None:
        return REPLAY
    if state.idempotency_key is None:
        return NOT_RETRYABLE
    if idempotency_key != state.idempotency_key:
        return KEY_MISMATCH
    if _expired(state.claimed_at, now=now, window_seconds=window_seconds):
        return KEY_EXPIRED
    return RETURN_PRIOR
