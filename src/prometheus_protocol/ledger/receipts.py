"""The decision and the outcome, as chained receipts — and the check that the
rows still agree with them.

WHY THIS MODULE EXISTS (F13 + F14). The tamper-evident chain bound the
AUTHORIZATION record: what a hold was permitted to do. It did not bind the
human's decision on that hold, nor what happened when it executed. Both lived
only in mutable SQL columns — ``pending_actions.status/decided_by/decided_at``
and ``executions.executed/detail`` — so an adversary with database-write
authority could forge an approval that retry would honour, or rewrite an
outcome that an auditor would believe, while ``verify_chain()`` stayed VALID
throughout. The chain was truthful about what it covered; what it covered
excluded the two things a receipt exists to establish.

THE SHAPE: TWO NEW CHAINED EVENT TYPES, NOT A GROWN AUTHORIZATION RECORD.
The authorization record is written once at hold creation and required
byte-equal to its chain entry at every later use (``_require_chain_binding``,
``execution/pending.py``). A decision is known at approval; an outcome at
execution. Neither can be written into a record that must already match its
chain payload — that is the Block 1a constraint the observation record was
built around (``policy/reobservation.py``), and it applies here identically.
So each is its own append-only entry, keyed on its own subject, and the row is
required to equal the LATEST entry for that subject.

THE DERIVATION. The set of row fields a third party relies on is DERIVED from
the two frozen dataclasses below via ``dataclasses.fields`` — the
``_DESCRIPTOR_FIELDS`` precedent (``policy/execution.py``). Field names ARE
column names, so the row is projected by name with no hand-written mapping in
between: a field added to a record is chained, projected and compared by
construction. What can vary outside the derivation is exactly the set of
columns NOT on these dataclasses, and that set is stated in the tracker
(``docs/OPEN-GAPS.md`` G39) rather than implied to be empty.

CHAIN THE STRUCTURAL PAIR, NOT A NEW VOCABULARY. #120 ruled that a harness
fault is expressible through ``(started_ok, candidate_started)`` and has no
typed reason. The outcome record carries that pair as measured. It does not
add an execution-stage reason set; that question is filed separately.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from typing import Any, Mapping

from prometheus_protocol.core.interfaces import Ledger
from prometheus_protocol.ledger.audit_chain import (
    NOT_VERIFIABLE,
    VALID,
    ChainTip,
    ChainVerification,
)

#: The audit-chain event under which a hold's DECISION is bound, subject
#: ``pending:<id>`` — the same subject as the hold's own ``pending.hold``
#: entry, distinguished by event. Every write to the row's decision columns
#: appends one, so the row must equal the latest.
DECISION_EVENT = "pending.decision"

#: The audit-chain event under which an execution's OUTCOME is bound, subject
#: ``execution:<row id>``. One per execution row, appended by the same ledger
#: call that inserts the row.
#:
#: NOT ``execution.outcome``. ``chokepoint/reconcile_gate.py`` classifies any
#: chain event whose name starts with ``execute`` or ``execution`` as one of
#: its own and raises on a payload without ``approval_binding``. This event
#: is not the chokepoint's, and a name inside that prefix would make a shared
#: ledger unreconcilable. The existing ``execution.observation`` sits inside
#: the prefix already; that is recorded in the tracker, not widened here.
OUTCOME_EVENT = "outcome.execution"

#: The hold's own entry. Mirrors ``policy/record.PINNED_HOLD_EVENT`` — spelled
#: here rather than imported so this module stays below ``policy/`` in the
#: import graph; ``test_receipt_derivation.py`` pins the two equal.
HOLD_EVENT = "pending.hold"

#: Receipt-verification reasons, drawn from the closed authorization set in
#: ``policy/execution.py`` so a test can assert WHICH one. Three shapes per
#: record, because they are three findings: the entry is missing (a row the
#: chain never saw), the entry differs (a row rewritten after its receipt), or
#: the ROW is missing (a receipt whose row was deleted — the inverse walk).
DECISION_ENTRY_MISSING = "decision_entry_missing"
DECISION_DIFFERS = "decision_differs_from_chain_entry"
HOLD_ROW_MISSING = "hold_row_missing"
OUTCOME_ENTRY_MISSING = "outcome_entry_missing"
OUTCOME_DIFFERS = "outcome_differs_from_chain_entry"
EXECUTION_ROW_MISSING = "execution_row_missing"

#: A ledger whose chain verifies but whose rows disagree with it.
RECEIPTS_INVALID = "receipts_invalid"


def decision_subject(pending_id: int) -> str:
    """The chain subject a hold's decisions are bound under."""

    return f"pending:{int(pending_id)}"


def outcome_subject(execution_id: int) -> str:
    """The chain subject an execution's outcome is bound under."""

    return f"execution:{int(execution_id)}"


@dataclass(frozen=True)
class DecisionRecord:
    """The hold's decision columns, exactly as the row carries them.

    FIELD NAMES ARE COLUMN NAMES. Every column that any of the three decision
    writers on the ledger mutates — ``resolve_pending_action``,
    ``invalidate_pending_action``, ``mark_state_moved`` — is a field here, so
    the projection below reads them by name and the record is total over what
    those writers can change.
    """

    status: str
    decided_by: str | None
    decided_at: str | None
    decision_reason: str | None
    invalidated_at: str | None
    invalidated_reason: str | None


@dataclass(frozen=True)
class OutcomeRecord:
    """The execution row's outcome columns, exactly as the row carries them.

    ``executed``, ``detail`` and the structural start signals are what the
    audit named. The identity columns (``subject_id``, ``source``,
    ``pending_id``, ``created_at``) are here so a chained outcome cannot be
    re-attributed to a different subject or hold without the mismatch showing.
    """

    subject_id: str
    source: str
    executed: bool
    refused: bool
    sandbox: str
    exit_status: int | None
    detail: str
    created_at: str
    pending_id: int | None
    #: #120's structural pair. ``None`` when no executor was invoked for this
    #: row at all (a blocked, unavailable or pre-execution-refused row) — a
    #: third state, distinct from ``False``, which means the executor was
    #: invoked and isolation did not start.
    started_ok: bool | None
    candidate_started: bool | None


#: The rely-upon fields, DERIVED. Not written out anywhere else.
DECISION_FIELDS: tuple[str, ...] = tuple(f.name for f in dataclasses.fields(DecisionRecord))
OUTCOME_FIELDS: tuple[str, ...] = tuple(f.name for f in dataclasses.fields(OutcomeRecord))


def project_decision(row: Mapping[str, Any]) -> dict[str, Any]:
    """The decision receipt a pending row currently implies: its decision
    columns, read BY NAME from the derived field set, as the chain payload.

    A dict rather than a ``DecisionRecord`` instance, deliberately. The
    dataclass is the SCHEMA — the one declaration the field names are derived
    from — and not a validator: a row whose ``status`` has been overwritten
    with a number is a receipt mismatch to report, not a construction error
    to raise, and the comparison below is value-equality by name either way.
    """

    return {name: row.get(name) for name in DECISION_FIELDS}


def project_outcome(row: Mapping[str, Any]) -> dict[str, Any]:
    """The outcome receipt an execution row currently implies, by name."""

    return {name: row.get(name) for name in OUTCOME_FIELDS}


def _decoded(payload: object) -> dict | None:
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except ValueError:
            return None
    # Narrowed in STATEMENT form, not a ternary: the repository's type gate
    # refuses an ``isinstance`` in expression position on a union, and it is
    # right to — a payload of a third shape would fall through a ternary's
    # else-branch into ``None``, which every caller reads as "no entry", a
    # missing receipt reported as an absent one.
    if not isinstance(payload, dict):
        return None
    return payload


def subject_row_id(subject: object) -> int | None:
    """The integer id a ``pending:<id>`` or ``execution:<id>`` subject names,
    or ``None`` for any other subject shape (an observation, a chokepoint
    entry, a malformed string). Never raises: a subject this module cannot
    parse is a subject this module does not vouch for."""

    if not isinstance(subject, str) or ":" not in subject:
        return None
    _, _, tail = subject.partition(":")
    return int(tail) if tail.isdigit() else None


def outcome_entries_for(events: list[dict], *, pending_id: int) -> list[tuple[int, dict]]:
    """Every chained outcome whose payload names ``pending_id``, as
    ``(execution row id, payload)`` in storage order.

    THE CHAIN-SIDE ENUMERATION, and why it exists. Retry once discovered which
    receipts to check by walking the ROWS for the hold. Review on #121 found
    the inverse: delete the row (or re-attribute its ``pending_id``) and null
    the claim, and that walk saw nothing — the hold read as never executed and
    the executor ran AGAIN. Measured. The chain's payloads carry
    ``pending_id`` and cannot be re-attributed without the mismatch showing, so
    this is the authority on which receipts a hold has.
    """

    found: list[tuple[int, dict]] = []
    for entry in events:
        if entry.get("event") != OUTCOME_EVENT:
            continue
        payload = _decoded(entry.get("payload"))
        if payload is None or payload.get("pending_id") != pending_id:
            continue
        row_id = subject_row_id(entry.get("subject"))
        if row_id is not None:
            found.append((row_id, payload))
    return found


def latest_entry(events: list[dict], *, event: str, subject: str) -> dict | None:
    """The LAST chain entry for ``(event, subject)`` in storage order, decoded,
    or ``None`` when there is none. Storage order is the order verify walks, so
    "latest" is the newest honest append, not the largest seq."""

    found: dict | None = None
    for entry in events:
        if entry.get("event") != event or entry.get("subject") != subject:
            continue
        decoded = _decoded(entry.get("payload"))
        if decoded is not None:
            found = decoded
    return found


def differing_fields(projected: dict[str, Any], chained: Mapping[str, Any]) -> tuple[str, ...]:
    """The field names on which the row and its chained counterpart disagree.

    THE COMPARISON IS BETWEEN TWO DIFFERENT SOURCES — the row's projection and
    the chain's payload. A version of this that compared the projection to
    itself would pass every deletion probe and detect nothing; the mutation
    proofs in ``tests/conformance/test_chained_decision_and_outcome.py`` pin
    that this is not that.
    """

    return tuple(
        name for name in projected
        if projected[name] != chained.get(name)
    )


@dataclass(frozen=True)
class ReceiptFinding:
    """One row whose receipt does not hold, and why."""

    subject: str
    reason: str
    fields: tuple[str, ...] = ()

    def render(self) -> str:
        where = f" on {', '.join(self.fields)}" if self.fields else ""
        return f"{self.subject}: {self.reason}{where}"


@dataclass(frozen=True)
class ReceiptVerification:
    """The auditor's verdict on rows-versus-chain. ``ok`` only when the check
    RAN and every decided hold, every execution row, and every chained receipt
    has its counterpart. ``checked=False`` is the couldn't-verify state — a
    chain that could not be read leaves nothing to compare rows against — and
    it is never ``ok``."""

    holds_checked: int
    executions_checked: int
    findings: tuple[ReceiptFinding, ...]
    checked: bool = True

    @property
    def ok(self) -> bool:
        return self.checked and not self.findings

    def render(self) -> str:
        if not self.checked:
            return "receipts not checked (the chain could not be verified)"
        if self.ok:
            return (
                f"receipts valid ({self.holds_checked} holds, "
                f"{self.executions_checked} executions match their chained entries)"
            )
        lines = [f"receipts INVALID: {len(self.findings)} row(s) disagree with the chain"]
        lines.extend("  " + finding.render() for finding in self.findings)
        return "\n".join(lines)


def verify_receipts(ledger: Ledger) -> ReceiptVerification:
    """Every decided hold and every execution row, against its chained receipt.

    Rows are trusted only where the chain vouches for them. A row with no entry
    is a finding, not an absence: a decided hold nothing chained, or an
    execution row nothing chained, is exactly what an adversary who can write
    rows but not the chain would leave behind — and it is also what every row
    written before this check existed looks like. Both read as unverifiable,
    which is the fail-closed reading.

    This does not walk the chain's hashes; ``verify_chain`` does that, and the
    two are complementary. A ledger can pass this and fail that (an honest set
    of rows over a rewritten chain) or pass that and fail this (an intact chain
    under rewritten rows — F13 and F14). An auditor wants both.
    """

    events = ledger.chained_events()
    findings: list[ReceiptFinding] = []

    holds = ledger.pending_actions()
    for row in holds:
        subject = decision_subject(row["id"])
        projected = project_decision(row)
        chained = latest_entry(events, event=DECISION_EVENT, subject=subject)
        if chained is None:
            # A still-pending hold has had no decision and needs no entry: the
            # hold's own ``pending.hold`` entry is its genesis. Anything else
            # claims a decision the chain never saw.
            if row.get("status") != "pending":
                findings.append(ReceiptFinding(subject, DECISION_ENTRY_MISSING))
            continue
        differs = differing_fields(projected, chained)
        if differs:
            findings.append(ReceiptFinding(subject, DECISION_DIFFERS, differs))

    executions = ledger.executions()
    for row in executions:
        subject = outcome_subject(row["id"])
        projected = project_outcome(row)
        chained = latest_entry(events, event=OUTCOME_EVENT, subject=subject)
        if chained is None:
            findings.append(ReceiptFinding(subject, OUTCOME_ENTRY_MISSING))
            continue
        differs = differing_fields(projected, chained)
        if differs:
            findings.append(ReceiptFinding(subject, OUTCOME_DIFFERS, differs))

    # THE INVERSE WALK: every receipt must have its row. The two walks above
    # project ROWS, so a row that has been DELETED is invisible to them and its
    # receipt sits orphaned on the chain. Measured, before this walk existed:
    # a deleted execution row with the claim nulled was a double execution at
    # retry; a deleted hold row left its two entries orphaned with
    # ``holds_checked=0`` and nothing reported. Subject-keyed, event-filtered,
    # so an entry this module did not write (an observation, a chokepoint
    # record) is not mistaken for a receipt without a row.
    hold_ids = {row["id"] for row in holds}
    execution_ids = {row["id"] for row in executions}
    orphaned: set[str] = set()
    for entry in events:
        event = entry.get("event")
        # Its own name: ``subject`` above is bound as ``str`` by the row walks,
        # and this one is whatever the chain row carries until narrowed.
        chained_subject = entry.get("subject")
        if not isinstance(chained_subject, str) or chained_subject in orphaned:
            continue
        row_id = subject_row_id(chained_subject)
        if row_id is None:
            continue
        if event in (HOLD_EVENT, DECISION_EVENT) and chained_subject.startswith("pending:"):
            if row_id not in hold_ids:
                orphaned.add(chained_subject)
                findings.append(ReceiptFinding(chained_subject, HOLD_ROW_MISSING))
        elif event == OUTCOME_EVENT and chained_subject.startswith("execution:"):
            if row_id not in execution_ids:
                orphaned.add(chained_subject)
                findings.append(ReceiptFinding(chained_subject, EXECUTION_ROW_MISSING))

    return ReceiptVerification(
        holds_checked=len(holds),
        executions_checked=len(executions),
        findings=tuple(findings),
    )


@dataclass(frozen=True)
class LedgerVerification:
    """Both verdicts on one ledger: the hash walk and the receipt check.

    ``ok`` only when both hold. The two are complementary — an intact chain
    under rewritten rows fails the receipts (F13, F14); honest rows over a
    rewritten chain fail the hash walk — and an auditor who runs one is told
    about the other. Review on #121 found the documented programmatic entry
    point, ``verify_ledger_file``, returning VALID over a forged outcome row
    because it ran the hash walk alone; this is what it returns now.

    The chain verdict's fields are proxied so every existing consumer of a
    ``ChainVerification`` — ``.status``, ``.broken_index``, ``.detail``,
    ``.length``, ``.render()`` — keeps working, and ``status`` gains one value:
    ``receipts_invalid``, for a chain that verifies over rows that do not.
    """

    chain: ChainVerification
    receipts: ReceiptVerification

    @property
    def ok(self) -> bool:
        return self.chain.ok and self.receipts.ok

    @property
    def status(self) -> str:
        if not self.chain.ok:
            return self.chain.status
        return VALID if self.receipts.ok else RECEIPTS_INVALID

    @property
    def length(self) -> int:
        return self.chain.length

    @property
    def broken_index(self) -> int | None:
        return self.chain.broken_index

    @property
    def detail(self) -> str:
        if not self.chain.ok:
            return self.chain.detail
        return "" if self.receipts.ok else self.receipts.render()

    def render(self) -> str:
        return f"{self.chain.render()}; {self.receipts.render()}"


def unverifiable(detail: str) -> LedgerVerification:
    """The couldn't-verify verdict for a ledger that could not be opened or
    read: chain NOT_VERIFIABLE, receipts not checked, never ``ok``."""

    return LedgerVerification(
        chain=ChainVerification(NOT_VERIFIABLE, 0, None, detail),
        receipts=ReceiptVerification(0, 0, (), checked=False),
    )


def verify_ledger(
    ledger: Ledger,
    *,
    expected_tip: ChainTip | None = None,
    expected_tips: list[ChainTip] | None = None,
) -> LedgerVerification:
    """The shared programmatic verifier: the hash walk, then the receipts.

    Used by ``verify_ledger_file`` and by ``audit --verify-chain``, so the CLI
    and the API cannot disagree about what "verified" means. When the chain
    itself could not be read there is nothing trustworthy to compare rows
    against, and the receipts are reported as NOT CHECKED rather than as
    clean.
    """

    chain = ledger.verify_chain(expected_tip=expected_tip, expected_tips=expected_tips)
    if chain.status == NOT_VERIFIABLE:
        return LedgerVerification(chain, ReceiptVerification(0, 0, (), checked=False))
    return LedgerVerification(chain, verify_receipts(ledger))
