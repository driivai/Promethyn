"""F13 + F14: the human decision and the execution outcome, inside the chain.

WHAT THE AUDIT FOUND, reproduced at HEAD before anything here was written.
``resolve_pending_action`` (``ledger/sqlite_ledger.py:505``) stores approval
status, reviewer identity and decision time in mutable SQL columns, and
``_require_chain_binding`` (``execution/pending.py:973``) binds the
AUTHORIZATION record — not those columns. ``record_execution``
(``ledger/sqlite_ledger.py:647``) writes execution rows and chains nothing.

So, with an append-only anchor in place and the chain fully VALID:

  F13  create a genuine hold; UPDATE its row to ``approved`` with a forged
       reviewer and time; invoke retry — the executor runs, and
       ``verify_chain().ok`` is True before and after.

  F14  approve and execute a hold; UPDATE the row to ``executed=0`` with a
       replaced detail — the forged outcome is returned, chain still VALID.
       And one more UPDATE (null the at-most-once claim) lets retry run the
       executor a SECOND time: two side effects for one approval.

The chain is intact and truthful about what it covers. What it covered
excluded the human decision and the execution outcome — the two things a
receipt exists to establish. The adversary is database-write authority, which
is precisely the adversary an external witness is meant to constrain.

EVERY TEST BELOW ASSERTS THE FIXED BEHAVIOUR. Against the unfixed tree the
reproductions are RED; that observed red is recorded in the tracker entry, and
a fix without its reproduction would be a fix without a measurement.
"""

from __future__ import annotations

import json

import pytest

import test_execution_authorization_record as fx
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.ledger.tip_anchor import FileTipAnchor
from prometheus_protocol.policy.execution import ExecutionNotAuthorized

FORGED_AT = "2026-09-12T00:00:00+00:00"


def anchored(tmp_path) -> SqliteLedger:
    """A ledger with an APPEND-ONLY anchor: the brief's precondition, so that
    every "chain verifies" below is a verification against a witness, not a
    bare in-file chain talking to itself."""

    return SqliteLedger(
        tmp_path / "ledger.db", tip_anchor=FileTipAnchor(tmp_path / "tip.json")
    )


def forge_approval(ledger: SqliteLedger, pending_id: int, *, by: str = "forged-reviewer"):
    """The F13 write: the row says approved, and nothing else does."""

    ledger._conn.execute(
        "UPDATE pending_actions SET status = 'approved', decided_by = ?, "
        "decided_at = ?, decision_reason = 'forged' WHERE id = ?",
        (by, FORGED_AT, pending_id),
    )
    ledger._conn.commit()


def forge_outcome(ledger: SqliteLedger, pending_id: int) -> None:
    """The F14 write: the row now denies an execution that happened."""

    ledger._conn.execute(
        "UPDATE executions SET executed = 0, refused = 1, "
        "detail = 'forged: never ran' WHERE pending_id = ?",
        (pending_id,),
    )
    ledger._conn.commit()


def release_claim(ledger: SqliteLedger, pending_id: int) -> None:
    """The one extra write that turns F14 from a lie into a second side effect."""

    ledger._conn.execute(
        "UPDATE pending_actions SET execution_committed_at = NULL WHERE id = ?",
        (pending_id,),
    )
    ledger._conn.commit()


# ---------------------------------------------------------------------------
# PART 1 — the reproductions, permanent
# ---------------------------------------------------------------------------


def test_F13_a_forged_approval_in_the_row_does_NOT_let_retry_execute(tmp_path):
    """THE F13 REPRODUCTION.

    Asserts: the executor is never called; retry refuses with a typed reason
    that names the decision binding; the chain verifies before AND after —
    because the chain was never the thing that lied.
    """

    ledger = anchored(tmp_path)
    ctl, spy, _ = fx.controller(ledger, route_high_risk=True)
    held = fx.hold(ctl, fx.action())
    assert ledger.verify_chain().ok, "precondition: an anchored, valid chain"

    forge_approval(ledger, held.id)

    with pytest.raises(ExecutionNotAuthorized) as refused:
        ctl.retry_execution(held.id, identity="retrier")

    assert spy.calls == [], (
        "a forged approval reached the executor: the row's decision columns "
        "were trusted with nothing on the chain to vouch for them"
    )
    assert refused.value.reason == "decision_entry_missing"
    assert ledger.verify_chain().ok, (
        "the chain must STILL verify: the forgery never touched it, and a "
        "detection that broke the chain would be detecting the wrong thing"
    )


def test_F14_a_flipped_outcome_row_is_DETECTED_against_its_chained_counterpart(tmp_path):
    """THE F14 REPRODUCTION, half one: the lie is visible.

    Asserts: after a genuine execution, flipping ``executed`` and ``detail``
    in the row leaves the chain VALID — and the receipt verifier reports the
    row as differing from its chained outcome, naming the execution.
    """

    from prometheus_protocol.ledger.receipts import verify_receipts

    ledger = anchored(tmp_path)
    ctl, spy, _ = fx.controller(ledger, route_high_risk=True)
    held = fx.hold(ctl, fx.action())
    genuine = ctl.approve(held.id, identity="human")
    assert genuine.executed and len(spy.calls) == 1
    assert verify_receipts(ledger).ok, "precondition: an honest ledger verifies"

    forge_outcome(ledger, held.id)

    assert ledger.verify_chain().ok, "the chain itself is intact — that is the point"
    verdict = verify_receipts(ledger)
    assert not verdict.ok
    mismatched = [f for f in verdict.findings if f.reason == "outcome_differs_from_chain_entry"]
    assert len(mismatched) == 1, verdict.render()
    assert mismatched[0].subject == f"execution:{ledger.executions_for_pending(held.id)[0]['id']}"
    assert "executed" in mismatched[0].fields and "detail" in mismatched[0].fields


def test_F14_a_flipped_outcome_plus_a_released_claim_does_NOT_execute_twice(tmp_path):
    """THE F14 REPRODUCTION, half two: the ESCALATION, measured before fixing.

    With ``executed`` flipped and the at-most-once claim nulled, retry read the
    row, believed the hold had never executed, and ran the executor AGAIN —
    two execution rows, one approval, chain VALID throughout. Asserts: retry
    refuses because the chained outcome says the hold already executed.
    """

    ledger = anchored(tmp_path)
    ctl, spy, _ = fx.controller(ledger, route_high_risk=True)
    held = fx.hold(ctl, fx.action())
    ctl.approve(held.id, identity="human")
    assert len(spy.calls) == 1

    forge_outcome(ledger, held.id)
    release_claim(ledger, held.id)

    with pytest.raises(ExecutionNotAuthorized) as refused:
        ctl.retry_execution(held.id, identity="retrier")

    assert len(spy.calls) == 1, (
        f"DOUBLE EXECUTION: the executor ran {len(spy.calls)} times for one "
        "approval, because 'never executed' was read off a row and not the chain"
    )
    assert refused.value.reason == "outcome_differs_from_chain_entry"
    assert ledger.verify_chain().ok


# ---------------------------------------------------------------------------
# PART 2 — paired positives (doctrine #4): the negatives alone prove nothing
# ---------------------------------------------------------------------------


def test_a_genuine_approval_still_verifies_and_retry_still_works(tmp_path):
    """The positive control for the F13 negatives (doctrine #4). A real human
    approval, deferred, then retried: the decision is on the chain, the row
    matches it, and execution proceeds exactly once."""

    from prometheus_protocol.ledger.receipts import DECISION_EVENT, verify_receipts

    ledger = anchored(tmp_path)
    spy = fx.Spy(refuse=True)  # the first execution fail-closes, so retry is eligible
    ctl, _, _ = fx.controller(ledger, route_high_risk=True, spy=spy)
    held = fx.hold(ctl, fx.action())
    first = ctl.approve(held.id, identity="human", reason="looks right")
    assert first.refused and not first.executed

    decisions = [
        e for e in ledger.chained_events()
        if e["event"] == DECISION_EVENT and e["subject"] == f"pending:{held.id}"
    ]
    assert len(decisions) == 1
    payload = json.loads(decisions[0]["payload"])
    assert payload["status"] == "approved"
    assert payload["decided_by"] == "human"
    assert payload["decision_reason"] == "looks right"
    assert verify_receipts(ledger).ok

    spy._refuse = False
    second = ctl.retry_execution(held.id, identity="retrier")
    assert second.executed
    assert len(spy.calls) == 2  # one refused attempt, one real execution
    assert verify_receipts(ledger).ok


def test_a_genuine_execution_outcome_verifies_with_the_structural_pair(tmp_path):
    """The positive control for the F14 negatives (doctrine #4). A real
    execution: the outcome is on the chain, carries ``executed``, the detail
    AND the structural start signals (#120's ruling), and the row matches it
    field for field."""

    from prometheus_protocol.ledger.receipts import OUTCOME_EVENT, verify_receipts

    ledger = anchored(tmp_path)
    ctl, spy, _ = fx.controller(ledger, route_high_risk=True)
    held = fx.hold(ctl, fx.action())
    result = ctl.approve(held.id, identity="human")
    assert result.executed

    row = ledger.executions_for_pending(held.id)[0]
    outcomes = [
        e for e in ledger.chained_events()
        if e["event"] == OUTCOME_EVENT and e["subject"] == f"execution:{row['id']}"
    ]
    assert len(outcomes) == 1
    payload = json.loads(outcomes[0]["payload"])
    assert payload["executed"] is True
    assert payload["detail"] == row["detail"]
    assert payload["started_ok"] is True and payload["candidate_started"] is True
    assert row["started_ok"] is True and row["candidate_started"] is True
    assert verify_receipts(ledger).ok


# ---------------------------------------------------------------------------
# PART 3 — the independent verifier's entry point
# ---------------------------------------------------------------------------


def test_the_audit_cli_exits_2_when_a_row_disagrees_with_its_receipt(tmp_path, monkeypatch, capsys):
    """``audit --verify-chain`` is what an auditor runs. It must report the
    receipts alongside the hash walk and exit non-zero when the rows lie —
    otherwise F13's row would pass the only check an outsider is told to
    run. Positive first: an honest ledger exits 0 and prints both verdicts."""

    from test_execution_retry import _seed_pending
    from prometheus_protocol.cli.main import main

    db = str(tmp_path / "ledger.db")
    pid = _seed_pending(db, created_at="2026-07-01T00:00:00Z", subject="deploy/x", code="print('x')")
    monkeypatch.setenv("PROM_LEDGER_PATH", db)
    monkeypatch.setenv("PROM_PENDING_TTL", "0")
    assert main(["approve", str(pid), "--by", "human", "--no-exec"]) == 0
    capsys.readouterr()

    assert main(["audit", "--verify-chain"]) == 0
    out = capsys.readouterr().out
    assert "audit chain : chain valid" in out
    assert "receipts    : receipts valid" in out

    ledger = SqliteLedger(db)
    forge_approval(ledger, pid, by="someone-else")
    ledger.close()

    assert main(["audit", "--verify-chain"]) == 2
    out = capsys.readouterr().out
    assert "audit chain : chain valid" in out, "the chain is intact; only the row lies"
    assert "receipts INVALID" in out
    assert f"pending:{pid}: decision_differs_from_chain_entry on decided_by" in out


# ---------------------------------------------------------------------------
# PART 4 — the SERVICE's own comparison, on a row that differs from an entry
#
# The F13 reproduction refuses on "no entry at all". These two refuse on "an
# entry exists and the row no longer matches it" — the branch a comparison
# against ITSELF would pass (§7.5). Mutation S2 was GREEN until these existed,
# and that green was the proof gap, not evidence.
# ---------------------------------------------------------------------------


def test_F13_a_decision_altered_AFTER_a_genuine_approval_is_refused_at_retry(tmp_path):
    """Approve for real (chained), then overwrite the reviewer in the row.
    Retry must refuse on the DIFFERENCE, not on absence, and name the field."""

    ledger = anchored(tmp_path)
    spy = fx.Spy(refuse=True)  # fail-closed first execution: retry-eligible
    ctl, _, _ = fx.controller(ledger, route_high_risk=True, spy=spy)
    held = fx.hold(ctl, fx.action())
    ctl.approve(held.id, identity="human")
    spy._refuse = False

    ledger._conn.execute(
        "UPDATE pending_actions SET decided_by = 'someone-else' WHERE id = ?", (held.id,)
    )
    ledger._conn.commit()

    with pytest.raises(ExecutionNotAuthorized) as refused:
        ctl.retry_execution(held.id, identity="retrier")

    assert refused.value.reason == "decision_differs_from_chain_entry"
    assert "decided_by" in str(refused.value)
    assert len(spy.calls) == 1, "the altered decision reached the executor"
    assert ledger.verify_chain().ok


def test_F13_a_decided_hold_reset_to_pending_cannot_be_approved_again(tmp_path):
    """The re-approval attack: a hold rejected for real, its row reset to
    ``pending`` so a second human can approve it. The chain says rejected;
    approval must refuse on the difference before writing anything."""

    ledger = anchored(tmp_path)
    ctl, spy, _ = fx.controller(ledger, route_high_risk=True)
    held = fx.hold(ctl, fx.action())
    ctl.reject(held.id, identity="human", reason="no")

    ledger._conn.execute(
        "UPDATE pending_actions SET status = 'pending', decided_by = NULL, "
        "decided_at = NULL, decision_reason = NULL WHERE id = ?",
        (held.id,),
    )
    ledger._conn.commit()

    with pytest.raises(ExecutionNotAuthorized) as refused:
        ctl.approve(held.id, identity="second-human")

    assert refused.value.reason == "decision_differs_from_chain_entry"
    assert spy.calls == []
    # Nothing was written: the row is still the forged 'pending', and the
    # chain still ends at the genuine rejection.
    assert ledger.pending_action(held.id)["status"] == "pending"
    from prometheus_protocol.ledger.receipts import DECISION_EVENT
    last = [e for e in ledger.chained_events() if e["event"] == DECISION_EVENT][-1]
    assert json.loads(last["payload"])["status"] == "rejected"


# ---------------------------------------------------------------------------
# PART 5 — the inverse walk, and the programmatic verifier (review of #121)
#
# Two P1 findings on this PR, both confirmed by direct probe before a line was
# written. Retry discovered which receipts to check by walking ROWS, so a
# deleted or re-attributed row (plus a nulled claim) was a DOUBLE EXECUTION
# with the chain VALID — G42 had been filed as an orphaned-entry curiosity,
# and that severity was wrong. And ``verify_ledger_file``, the documented
# programmatic entry point, ran the hash walk alone and returned VALID over a
# forged outcome row while the CLI correctly exited 2.
# ---------------------------------------------------------------------------


def test_F14_a_DELETED_execution_row_does_NOT_let_retry_execute_twice(tmp_path):
    """Delete the row and null the claim. The chain still holds the receipt
    that says the hold executed; retry must refuse on the missing ROW."""

    ledger = anchored(tmp_path)
    ctl, spy, _ = fx.controller(ledger, route_high_risk=True)
    held = fx.hold(ctl, fx.action())
    assert ctl.approve(held.id, identity="human").executed

    ledger._conn.execute("DELETE FROM executions WHERE pending_id = ?", (held.id,))
    ledger._conn.commit()
    release_claim(ledger, held.id)

    with pytest.raises(ExecutionNotAuthorized) as refused:
        ctl.retry_execution(held.id, identity="retrier")

    assert len(spy.calls) == 1, "DOUBLE EXECUTION: the deleted row hid the receipt from retry"
    assert refused.value.reason == "execution_row_missing"
    assert ledger.verify_chain().ok


def test_F14_a_RE_ATTRIBUTED_execution_row_does_NOT_let_retry_execute_twice(tmp_path):
    """Point the row's ``pending_id`` at another hold and null the claim. The
    chained payload still names THIS hold; the row differs from it on
    ``pending_id``; retry must refuse on the difference."""

    ledger = anchored(tmp_path)
    ctl, spy, _ = fx.controller(ledger, route_high_risk=True)
    held = fx.hold(ctl, fx.action())
    assert ctl.approve(held.id, identity="human").executed

    ledger._conn.execute("UPDATE executions SET pending_id = 999 WHERE pending_id = ?", (held.id,))
    ledger._conn.commit()
    release_claim(ledger, held.id)

    with pytest.raises(ExecutionNotAuthorized) as refused:
        ctl.retry_execution(held.id, identity="retrier")

    assert len(spy.calls) == 1, "DOUBLE EXECUTION: the re-attributed row hid the receipt from retry"
    assert refused.value.reason == "outcome_differs_from_chain_entry"
    assert "pending_id" in str(refused.value)


def test_the_verifier_walks_entries_to_rows_a_deleted_execution_row_is_a_finding(tmp_path):
    """G42, closed. The orphaned receipt is reported, naming the execution."""

    from prometheus_protocol.ledger.receipts import verify_receipts

    ledger = anchored(tmp_path)
    ctl, _spy, _ = fx.controller(ledger, route_high_risk=True)
    held = fx.hold(ctl, fx.action())
    assert ctl.approve(held.id, identity="human").executed
    row_id = ledger.executions_for_pending(held.id)[0]["id"]

    ledger._conn.execute("DELETE FROM executions WHERE id = ?", (row_id,))
    ledger._conn.commit()

    verdict = verify_receipts(ledger)
    assert not verdict.ok
    assert [(f.subject, f.reason) for f in verdict.findings] == [
        (f"execution:{row_id}", "execution_row_missing")
    ]


def test_the_verifier_walks_entries_to_rows_a_deleted_HOLD_row_is_a_finding(tmp_path):
    """The other table. A deleted hold leaves its ``pending.hold`` and
    ``pending.decision`` entries orphaned; reported ONCE per subject."""

    from prometheus_protocol.ledger.receipts import verify_receipts

    ledger = anchored(tmp_path)
    ctl, _spy, _ = fx.controller(ledger, route_high_risk=True)
    held = fx.hold(ctl, fx.action())
    ctl.reject(held.id, identity="human", reason="no")

    ledger._conn.execute("DELETE FROM pending_actions WHERE id = ?", (held.id,))
    ledger._conn.commit()

    verdict = verify_receipts(ledger)
    assert not verdict.ok
    assert [(f.subject, f.reason) for f in verdict.findings] == [
        (f"pending:{held.id}", "hold_row_missing")
    ]
    assert verdict.holds_checked == 0


def test_verify_ledger_file_reports_receipt_failures_not_just_the_chain(tmp_path):
    """The documented programmatic entry point. A forged outcome row under an
    intact chain must come back NOT ok, with a status an auditor can branch
    on — and every field a ``ChainVerification`` consumer reads must still be
    there. Positive first."""

    from prometheus_protocol.ledger.sqlite_ledger import verify_ledger_file

    path, anchor = tmp_path / "ledger.db", FileTipAnchor(tmp_path / "tip.json")
    ledger = SqliteLedger(path, tip_anchor=anchor)
    ctl, _spy, _ = fx.controller(ledger, route_high_risk=True)
    held = fx.hold(ctl, fx.action())
    assert ctl.approve(held.id, identity="human").executed
    ledger.close()

    honest = verify_ledger_file(path, tip_anchor=anchor)
    assert honest.ok and honest.status == "valid"
    assert honest.chain.ok and honest.receipts.ok
    assert "chain valid" in honest.render() and "receipts valid" in honest.render()

    ledger = SqliteLedger(path, tip_anchor=anchor)
    forge_outcome(ledger, held.id)
    ledger.close()

    forged = verify_ledger_file(path, tip_anchor=anchor)
    assert not forged.ok
    assert forged.status == "receipts_invalid"
    assert forged.chain.ok, "the chain is intact; only the row lies"
    assert forged.broken_index is None and forged.length == forged.chain.length
    assert "outcome_differs_from_chain_entry" in forged.detail
    assert "receipts INVALID" in forged.render()


def test_verify_ledger_file_still_reports_a_broken_chain_first(tmp_path):
    """The chain's own failures keep their status: a rewritten entry is
    ``broken`` through the combined verdict, not hidden behind a receipts
    label, and the receipts are still reported alongside."""

    from prometheus_protocol.ledger.sqlite_ledger import verify_ledger_file
    from tests.support.chain_rewrite import rewrite_entry_and_rehash

    path, anchor = tmp_path / "ledger.db", FileTipAnchor(tmp_path / "tip.json")
    ledger = SqliteLedger(path, tip_anchor=anchor)
    ctl, _spy, _ = fx.controller(ledger, route_high_risk=True)
    held = fx.hold(ctl, fx.action())
    rewrite_entry_and_rehash(ledger, seq=1, payload={"forged": True})
    ledger.close()

    verdict = verify_ledger_file(path, tip_anchor=anchor)
    assert not verdict.ok and verdict.status == "broken"
    assert verdict.receipts.checked, "the chain was readable; receipts were still compared"


def test_verify_ledger_file_on_a_missing_file_is_NOT_VERIFIABLE_with_receipts_unchecked(tmp_path):
    """Couldn't-verify is not verified-clean, in both halves."""

    from prometheus_protocol.ledger.sqlite_ledger import verify_ledger_file

    verdict = verify_ledger_file(tmp_path / "absent.db")
    assert not verdict.ok and verdict.status == "not_verifiable"
    assert not verdict.receipts.checked and not verdict.receipts.ok
    assert "not checked" in verdict.render()
