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
from typing import Any, Mapping, Protocol

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

#: The hold's own authorization record against its ``pending.hold`` entry.
#: Spelled here rather than inline so every reason this module can emit is a
#: named constant that the classification below has to place.
RECORD_DIFFERS = "record_differs_from_chain_entry"
CHAIN_ENTRY_COUNT_WRONG = "chain_entry_count_wrong"

#: A ledger whose chain verifies but whose rows disagree with it.
RECEIPTS_INVALID = "receipts_invalid"

#: A ledger whose chain verifies and whose rows do not disagree with it, but
#: which carries rows the chain never saw. Distinct from ``RECEIPTS_INVALID``
#: because it is a distinct fact — and never ``ok``, exactly like the chain's
#: own ``NOT_VERIFIABLE``.
RECEIPTS_NOT_VERIFIABLE = "receipts_not_verifiable"

#: The two tables that carry receipted rows. ONE spelling each, shared by the
#: snapshot query in ``sqlite_ledger._receipt_source``, by the findings below,
#: and by the read guard that decides which reads a finding reaches. A second
#: spelling is how a table name and the finding that names it drift apart.
HOLD_TABLE = "pending_actions"
EXECUTION_TABLE = "executions"

#: THE CLASSIFICATION, and it is the whole of F-3's answer.
#:
#: These two sets say which kind of fact a finding is. They are NOT
#: interchangeable and the difference is the one doctrine #1 draws everywhere
#: else in this tree: **could not verify is not the same as verified bad.**
#:
#: UNRECEIPTED — the chain never saw this row. That is what an adversary who
#: can write rows but not the chain leaves behind. It is ALSO exactly what
#: every row written before ``ledger/receipts.py`` existed looks like, and the
#: two are not distinguishable from the row alone. So the row can never be
#: evidence — but its presence is not proof that anything was rewritten, and
#: it must not condemn a read that does not return it.
#:
#: TAMPERED — a receipt exists and disagrees with its row, or a receipt exists
#: whose row is gone. Nothing legitimate produces that. It condemns the whole
#: ledger, and every read of it.
#:
#: Measured, on ``d2cba9c`` (the commit before this module existed): that
#: ledger's ``record_execution`` wrote an ``executions`` row and appended
#: nothing to the chain, leaving ``verify_chain -> valid`` and
#: ``verify_receipts -> outcome_entry_missing``. Before this classification,
#: opening that file refused ``executions()``, ``pending_actions()`` AND
#: ``factory.build_execution_controller`` alike.
UNRECEIPTED_REASONS = frozenset({DECISION_ENTRY_MISSING, OUTCOME_ENTRY_MISSING})
TAMPERED_REASONS = frozenset({
    DECISION_DIFFERS,
    OUTCOME_DIFFERS,
    HOLD_ROW_MISSING,
    EXECUTION_ROW_MISSING,
    RECORD_DIFFERS,
    CHAIN_ENTRY_COUNT_WRONG,
})

#: Every reason a ``ReceiptFinding`` can carry, as the union of the two sides.
#: ``test_receipt_classification.py`` reads this module's source and pins that
#: the set of reasons actually passed to ``ReceiptFinding(...)`` equals this
#: exactly — so a new finding cannot arrive unclassified, and a classified
#: reason cannot stop being emitted without the pin noticing. Exact, not a
#: floor: a count would not have caught either direction.
RECEIPT_FINDING_REASONS = UNRECEIPTED_REASONS | TAMPERED_REASONS


class ReceiptSource(Protocol):
    def pending_actions(self, *, status: str | None = None) -> list[dict]: ...
    def executions(self) -> list[dict]: ...
    def chained_events(self) -> list[dict]: ...


@dataclass(frozen=True)
class ReceiptSnapshot:
    """Untrusted diagnostic material, not a verified reader API."""

    holds: list[dict]
    outcomes: list[dict]
    events: list[dict]

    def pending_actions(self, *, status: str | None = None) -> list[dict]:
        return [row for row in self.holds if status is None or row["status"] == status]

    def executions(self) -> list[dict]:
        return self.outcomes

    def chained_events(self) -> list[dict]:
        return self.events

    def _receipt_source(self) -> "ReceiptSnapshot":
        return self


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
    """One row whose receipt does not hold, and why.

    ``table`` is supplied where the finding is made, by the walk that already
    knows which table it is reading — not re-derived afterwards from the
    subject's prefix, which would be a second mapping to keep in step.
    """

    subject: str
    reason: str
    fields: tuple[str, ...] = ()
    table: str = ""

    @property
    def unreceipted(self) -> bool:
        """The chain never saw this row. Not evidence; not proof of a rewrite."""

        return self.reason in UNRECEIPTED_REASONS

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
    def tampered(self) -> tuple[ReceiptFinding, ...]:
        """Findings that condemn the ledger: a rewrite, or a receipt with no row."""

        return tuple(f for f in self.findings if not f.unreceipted)

    @property
    def unreceipted(self) -> tuple[ReceiptFinding, ...]:
        """Findings that condemn a ROW: the chain never saw it."""

        return tuple(f for f in self.findings if f.unreceipted)

    @property
    def unreceipted_rows(self) -> dict[str, frozenset[int]]:
        """The row ids no receipt vouches for, by table."""

        by_table: dict[str, set[int]] = {}
        for finding in self.unreceipted:
            row_id = subject_row_id(finding.subject)
            if finding.table and row_id is not None:
                by_table.setdefault(finding.table, set()).add(row_id)
        return {table: frozenset(ids) for table, ids in by_table.items()}

    @property
    def status(self) -> str:
        """VALID / INVALID / NOT_VERIFIABLE, the same three the chain reports.

        NOT_VERIFIABLE is the couldn't-check state in both directions: the
        chain could not be read at all, or rows exist that the chain never
        saw. INVALID is reserved for a disagreement, which is a different fact.
        """

        if not self.checked:
            return NOT_VERIFIABLE
        if self.tampered:
            return RECEIPTS_INVALID
        if self.unreceipted:
            return RECEIPTS_NOT_VERIFIABLE
        return VALID

    @property
    def ok(self) -> bool:
        """Unchanged: VALID only. NOT_VERIFIABLE has never been ok and is not
        now — an auditor's verdict does not soften because the cause is age."""

        return self.status == VALID

    def render(self) -> str:
        if not self.checked:
            return "receipts not checked (the chain could not be verified)"
        if self.ok:
            return (
                f"receipts valid ({self.holds_checked} holds, "
                f"{self.executions_checked} executions match their chained entries)"
            )
        lines: list[str] = []
        if self.tampered:
            lines.append(
                f"receipts INVALID: {len(self.tampered)} row(s) disagree with the chain"
            )
            lines.extend("  " + finding.render() for finding in self.tampered)
        if self.unreceipted:
            lines.append(
                f"receipts NOT VERIFIABLE: {len(self.unreceipted)} row(s) the chain "
                f"never saw — not evidence, and not proof of a rewrite"
            )
            lines.extend("  " + finding.render() for finding in self.unreceipted)
        return "\n".join(lines)


def verify_receipts(ledger: Ledger | ReceiptSnapshot) -> ReceiptVerification:
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

    try:
        source = ledger._receipt_source()
        events = source.chained_events()
    except json.JSONDecodeError:
        # A malformed JSON column in a corrupted or tampered ledger cannot be
        # decoded into rows to compare. That is the couldn't-check state, not a
        # crash and not a clean verdict: `checked=False` is never `ok`, and
        # `status` reports NOT_VERIFIABLE.
        #
        # The DECODER'S exception, not its base `ValueError`. Narrowed with the
        # guarded read's own handler after review on #124 measured that the
        # base collects faults that are not decoding at all; here the same
        # width would turn any `ValueError` a future snapshot source raises
        # into a polite "not checked", which is doctrine #8 wearing the fix's
        # clothes.
        return ReceiptVerification(0, 0, (), checked=False)
    findings: list[ReceiptFinding] = []

    holds = source.pending_actions()
    for row in holds:
        subject = decision_subject(row["id"])
        # The persisted observation obligation lives inside this authorization
        # record. A decision-only check would leave a forged opt-out readable.
        held = [entry for entry in events if entry.get("event") == HOLD_EVENT and entry.get("subject") == subject]
        authorization = row.get("authorization")
        if held:
            if len(held) != 1:
                findings.append(ReceiptFinding(subject, CHAIN_ENTRY_COUNT_WRONG, table=HOLD_TABLE))
            elif _decoded(held[0].get("payload")) != authorization:
                findings.append(ReceiptFinding(subject, RECORD_DIFFERS, table=HOLD_TABLE))
        elif isinstance(authorization, dict) and "record_version" in authorization:
            findings.append(ReceiptFinding(subject, CHAIN_ENTRY_COUNT_WRONG, table=HOLD_TABLE))
        projected = project_decision(row)
        chained = latest_entry(events, event=DECISION_EVENT, subject=subject)
        if chained is None:
            # A still-pending hold has had no decision and needs no entry: the
            # hold's own ``pending.hold`` entry is its genesis. Anything else
            # claims a decision the chain never saw.
            if row.get("status") != "pending":
                findings.append(ReceiptFinding(subject, DECISION_ENTRY_MISSING, table=HOLD_TABLE))
            continue
        differs = differing_fields(projected, chained)
        if differs:
            findings.append(ReceiptFinding(subject, DECISION_DIFFERS, differs, table=HOLD_TABLE))

    executions = source.executions()
    for row in executions:
        subject = outcome_subject(row["id"])
        projected = project_outcome(row)
        chained = latest_entry(events, event=OUTCOME_EVENT, subject=subject)
        if chained is None:
            findings.append(ReceiptFinding(subject, OUTCOME_ENTRY_MISSING, table=EXECUTION_TABLE))
            continue
        differs = differing_fields(projected, chained)
        if differs:
            findings.append(ReceiptFinding(subject, OUTCOME_DIFFERS, differs, table=EXECUTION_TABLE))

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
                findings.append(ReceiptFinding(chained_subject, HOLD_ROW_MISSING, table=HOLD_TABLE))
        elif event == OUTCOME_EVENT and chained_subject.startswith("execution:"):
            if row_id not in execution_ids:
                orphaned.add(chained_subject)
                findings.append(ReceiptFinding(chained_subject, EXECUTION_ROW_MISSING, table=EXECUTION_TABLE))

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
    ``.length``, ``.render()`` — keeps working, and ``status`` gains two
    values: ``receipts_invalid``, for a chain that verifies over rows that
    disagree with it, and ``receipts_not_verifiable``, for one that verifies
    over rows it never saw. Neither is ``ok``; they are reported apart because
    a rewrite and an unreceipted row are different facts and an auditor acts
    on them differently.
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
        return self.receipts.status

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
