"""THE TEST THAT DECIDES THE SPRINT (F13/F14 item 4): every mutable row field a
third party relies on has a chained counterpart, and a mutation of the row
without a matching chained event is DETECTED — as a DERIVED check.

WHY DERIVED. The rely-upon field sets are read off ``DecisionRecord`` and
``OutcomeRecord`` via ``dataclasses.fields`` (``ledger/receipts.py``), the
``_DESCRIPTOR_FIELDS`` precedent. Every proof below is parametrised over that
derived list, so a field added to a record is covered by construction rather
than by someone remembering to add a test. Three hand-written copies agreeing
by hand is this repository's own cautionary case.

WHAT THE DERIVATION CANNOT REACH, MADE EXECUTABLE. A derivation from the
record covers the record. The columns NOT on the record are exactly what can
vary outside it, and rather than describing that set in prose this module
pins it EXACTLY — no floor, no tolerance — so a column added to either table
without a decision about whether a third party relies on it reddens here and
forces the decision. The excluded sets are then stated in the tracker with
the reason each column is outside.

TWO SOURCES FOR THE DECISION SET, CHECKED AGAINST EACH OTHER. The dataclass
says which columns the writers mutate. The writers' SQL says which columns
they mutate. If the two disagree — a writer gains a ``SET new_col = ?`` and
nobody adds the field — the receipt is silently partial. So the SQL is read
off the source and compared to the derived set.
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import pytest

import test_execution_authorization_record as fx
from prometheus_protocol.ledger.receipts import (
    DECISION_FIELDS,
    OUTCOME_FIELDS,
    DecisionRecord,
    OutcomeRecord,
    verify_receipts,
)
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.ledger.tip_anchor import FileTipAnchor

SRC = Path(__file__).resolve().parents[2] / "src" / "prometheus_protocol"


def anchored(tmp_path) -> SqliteLedger:
    return SqliteLedger(
        tmp_path / "ledger.db", tip_anchor=FileTipAnchor(tmp_path / "tip.json")
    )


def columns(ledger: SqliteLedger, table: str) -> list[str]:
    return [row["name"] for row in ledger._conn.execute(f"PRAGMA table_info({table})")]


# ---------------------------------------------------------------------------
# the derivation itself
# ---------------------------------------------------------------------------


def test_the_field_sets_are_derived_from_the_dataclasses_not_written_out():
    """Both tuples are ``dataclasses.fields`` of their record, in order."""

    assert DECISION_FIELDS == tuple(f.name for f in dataclasses.fields(DecisionRecord))
    assert OUTCOME_FIELDS == tuple(f.name for f in dataclasses.fields(OutcomeRecord))


def test_every_record_field_is_a_real_column_on_its_table():
    """A field with no column would project to ``None`` on every row and
    compare equal to a chained ``None`` forever — a receipt that can never
    disagree. Each derived name must exist on its table."""

    ledger = SqliteLedger(":memory:")
    assert set(DECISION_FIELDS) <= set(columns(ledger, "pending_actions"))
    assert set(OUTCOME_FIELDS) <= set(columns(ledger, "executions"))


def _set_columns_in_writers(source: str, *writers: str) -> set[str]:
    """Every column named in a ``SET`` clause inside the given methods."""

    found: set[str] = set()
    for writer in writers:
        start = source.index(f"def {writer}(")
        end = source.find("\n    def ", start + 1)
        body = source[start:end if end != -1 else None]
        for clause in re.findall(r"\bSET\b(.*?)\bWHERE\b", body, re.S):
            found.update(re.findall(r"(\w+)\s*=\s*\?", clause))
    return found


def test_the_decision_record_covers_every_column_the_decision_writers_mutate():
    """THE TWO-SOURCE CHECK. The three writers of the decision columns are
    read off the ledger's source; the union of the columns their ``SET``
    clauses touch must be exactly the derived field set. A writer that grows
    a column, or a fourth writer, reddens here."""

    source = (SRC / "ledger" / "sqlite_ledger.py").read_text(encoding="utf-8")
    mutated = _set_columns_in_writers(
        source,
        "resolve_pending_action",
        "invalidate_pending_action",
        "mark_state_moved",
    )
    assert mutated == set(DECISION_FIELDS), {
        "mutated by a writer but NOT in the record": sorted(mutated - set(DECISION_FIELDS)),
        "in the record but mutated by NO writer": sorted(set(DECISION_FIELDS) - mutated),
    }


# ---------------------------------------------------------------------------
# totality: each derived field, mutated alone, is detected
# ---------------------------------------------------------------------------

#: A value that differs from anything a genuine row carries, per column type.
_TAMPER = {
    "status": "approved",  # flipped on a hold that is really pending → see below
    "decided_by": "forged-reviewer",
    "decided_at": "1999-01-01T00:00:00+00:00",
    "decision_reason": "forged reason",
    "invalidated_at": "1999-01-01T00:00:00+00:00",
    "invalidated_reason": "forged invalidation",
    "subject_id": "forged-subject",
    "source": "forged-source",
    "executed": 0,
    "refused": 1,
    "sandbox": "forged-sandbox",
    "exit_status": 99,
    "detail": "forged detail",
    "created_at": "1999-01-01T00:00:00+00:00",
    "pending_id": 4242,
    "started_ok": 0,
    "candidate_started": 0,
}


@pytest.mark.parametrize("field", DECISION_FIELDS)
def test_each_decision_field_mutated_alone_is_detected(field, tmp_path):
    """Parametrised over the DERIVED decision fields: after a genuine
    decision, overwrite one column and nothing else — the receipt verifier
    must name exactly that field."""

    ledger = anchored(tmp_path)
    ctl, _spy, _ = fx.controller(ledger, route_high_risk=True)
    held = fx.hold(ctl, fx.action())
    # A real decision, so every decision column has a chained value. Reject
    # rather than approve: it decides without executing, so the outcome table
    # stays out of this proof's way.
    ctl.reject(held.id, identity="human", reason="genuine")
    assert verify_receipts(ledger).ok

    # ``status`` on a rejected hold: flip to approved (a forged approval).
    value = "approved" if field == "status" else _TAMPER[field]
    ledger._conn.execute(
        f"UPDATE pending_actions SET {field} = ? WHERE id = ?", (value, held.id)
    )
    ledger._conn.commit()

    verdict = verify_receipts(ledger)
    assert not verdict.ok
    hits = [f for f in verdict.findings if f.subject == f"pending:{held.id}"]
    assert len(hits) == 1, verdict.render()
    assert hits[0].reason == "decision_differs_from_chain_entry"
    assert hits[0].fields == (field,), (
        f"mutating {field!r} alone was reported as {hits[0].fields}: the "
        "comparison is not field-precise, or another field moved with it"
    )


@pytest.mark.parametrize("field", OUTCOME_FIELDS)
def test_each_outcome_field_mutated_alone_is_detected(field, tmp_path):
    """Parametrised over the DERIVED outcome fields, including #120's
    structural pair: after a genuine execution, overwrite one column."""

    ledger = anchored(tmp_path)
    ctl, _spy, _ = fx.controller(ledger, route_high_risk=True)
    held = fx.hold(ctl, fx.action())
    assert ctl.approve(held.id, identity="human").executed
    assert verify_receipts(ledger).ok
    row = ledger.executions_for_pending(held.id)[0]

    ledger._conn.execute(
        f"UPDATE executions SET {field} = ? WHERE id = ?", (_TAMPER[field], row["id"])
    )
    ledger._conn.commit()

    verdict = verify_receipts(ledger)
    assert not verdict.ok
    hits = [f for f in verdict.findings if f.subject == f"execution:{row['id']}"]
    assert len(hits) == 1, verdict.render()
    assert hits[0].reason == "outcome_differs_from_chain_entry"
    assert hits[0].fields == (field,)


def test_the_tamper_table_covers_exactly_the_derived_fields():
    """The values above are keyed by name; a derived field with no tamper
    value would make its parametrised case fail on a KeyError — a red for the
    wrong reason. Pinned exact so the table cannot drift from the derivation."""

    assert set(_TAMPER) == set(DECISION_FIELDS) | set(OUTCOME_FIELDS)


# ---------------------------------------------------------------------------
# what can vary OUTSIDE the derivation — pinned exactly, not described
# ---------------------------------------------------------------------------

#: The ``pending_actions`` columns NOT on the decision record, each with the
#: reason it is outside. EXACT: a new column on the table that is neither here
#: nor on the record reddens the test below and forces the decision.
PENDING_COLUMNS_OUTSIDE_THE_RECEIPT = {
    "id": "the identity the receipt is keyed on; it is the subject, not a field",
    "subject_id": "hold-creation data, bound by the pinned authorization record's attempt/descriptor, not a decision",
    "risk_class": "hold-creation data; it decided whether to route, and routing already happened",
    "reason": "hold-creation data: the gate's routing reason, not the human's",
    "verdict": "promoted from the judgment JSON at creation; hold-creation data",
    "confidence": "promoted from the judgment JSON at creation; hold-creation data",
    "action": "bound by the pinned record's artifact_sha256 — a forged action refuses as descriptor_snapshot_mismatch (measured)",
    "judgment": "hold-creation data; the assessment it rests on is covered by the pinned record's coverage block",
    "authorization": "IS chained — under pending.hold, byte-equal, by _require_chain_binding",
    "created_at": "hold-creation data; the pinned record carries pinned_at",
    "execution_committed_at": "the at-most-once claim: a concurrency guard between honest drivers, not a receipt. Its role as the sole double-execution defence is CLOSED by the chained outcome (retry reads executed off the chain); its role as a mutex is not a receipt property. Named residual, G39",
}

#: The ``executions`` columns NOT on the outcome record, each with its reason.
EXECUTION_COLUMNS_OUTSIDE_THE_RECEIPT = {
    "id": "the identity the receipt is keyed on; it is the subject, not a field",
    "verdict": "promoted from the judgment JSON; what AUTHORIZED, not what HAPPENED. A legitimate backfill UPDATEs it (sqlite_ledger._backfill_executions), so chaining it would flag every backfilled row",
    "confidence": "as verdict",
    "authoritative": "as verdict",
    "judgment": "what the execution rested on, not its outcome; the pinned record's coverage block is the chained account of it",
    "unavailable": "derived from source at write time (int(source == 'unavailable')); source IS in the record, so this cannot vary independently without source also differing",
    "authorization": "the pinned record, chained under pending.hold for a hold-linked row. Named residual for auto-approved rows, G39",
}


def test_the_columns_outside_the_derivation_are_EXACTLY_the_named_ones():
    """No floor. The real table minus the derived record must equal the
    named-and-reasoned set — so the residual is a measurement, and a column
    nobody decided about cannot appear on either side unnoticed."""

    ledger = SqliteLedger(":memory:")
    pending_outside = set(columns(ledger, "pending_actions")) - set(DECISION_FIELDS)
    execution_outside = set(columns(ledger, "executions")) - set(OUTCOME_FIELDS)

    assert pending_outside == set(PENDING_COLUMNS_OUTSIDE_THE_RECEIPT), {
        "on the table, undecided": sorted(pending_outside - set(PENDING_COLUMNS_OUTSIDE_THE_RECEIPT)),
        "named here, not on the table": sorted(set(PENDING_COLUMNS_OUTSIDE_THE_RECEIPT) - pending_outside),
    }
    assert execution_outside == set(EXECUTION_COLUMNS_OUTSIDE_THE_RECEIPT), {
        "on the table, undecided": sorted(execution_outside - set(EXECUTION_COLUMNS_OUTSIDE_THE_RECEIPT)),
        "named here, not on the table": sorted(set(EXECUTION_COLUMNS_OUTSIDE_THE_RECEIPT) - execution_outside),
    }


def test_a_column_outside_the_receipt_is_NOT_detected_and_that_is_the_named_limit(tmp_path):
    """The limit as a passing test (doctrine #5). ``execution_committed_at``
    is outside the decision record by decision; mutating it alone is NOT a
    receipt finding. Asserted, so the residual cannot quietly be read as
    covered — and so that if it is ever brought inside, this test says so."""

    ledger = anchored(tmp_path)
    ctl, _spy, _ = fx.controller(ledger, route_high_risk=True)
    held = fx.hold(ctl, fx.action())
    assert ctl.approve(held.id, identity="human").executed
    assert verify_receipts(ledger).ok

    ledger._conn.execute(
        "UPDATE pending_actions SET execution_committed_at = NULL WHERE id = ?", (held.id,)
    )
    ledger._conn.commit()

    assert verify_receipts(ledger).ok, (
        "execution_committed_at is now inside the receipt; update the named "
        "residual in G39 and PENDING_COLUMNS_OUTSIDE_THE_RECEIPT together"
    )


# ---------------------------------------------------------------------------
# the paired positive for the derivation (doctrine #4)
# ---------------------------------------------------------------------------


def test_an_untouched_ledger_with_every_transition_verifies(tmp_path):
    """The positive control for the per-field negatives (doctrine #4). Every
    writer exercised — approve, reject, retry — on an honest ledger: the
    verifier reports every hold and execution matching. Without this, the
    parametrised negatives are consistent with a verifier that flags
    everything."""

    ledger = anchored(tmp_path)
    spy = fx.Spy(refuse=True)
    ctl, _, _ = fx.controller(ledger, route_high_risk=True, spy=spy)
    approved = fx.hold(ctl, fx.action("print('a')"))
    rejected = fx.hold(ctl, fx.action("print('b')"))
    ctl.approve(approved.id, identity="human")  # refused by the spy: retry-eligible
    ctl.reject(rejected.id, identity="human", reason="no")
    spy._refuse = False
    ctl.retry_execution(approved.id, identity="retrier")

    verdict = verify_receipts(ledger)
    assert verdict.ok, verdict.render()
    assert verdict.holds_checked == 2
    assert verdict.executions_checked == 2  # one refused, one executed


def test_the_hold_event_spelled_here_is_the_one_the_hold_writes():
    """``ledger/receipts.HOLD_EVENT`` mirrors ``policy/record.PINNED_HOLD_EVENT``
    rather than importing it, to keep ``ledger/`` below ``policy/`` in the
    import graph. Two spellings of one name are two chances to drift; this
    pins them equal, so the inverse walk keys on the event ``hold()`` really
    writes."""

    from prometheus_protocol.ledger.receipts import HOLD_EVENT
    from prometheus_protocol.policy.record import PINNED_HOLD_EVENT

    assert HOLD_EVENT == PINNED_HOLD_EVENT
