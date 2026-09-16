"""Cross-context substitution against the decision receipt (F13 item 5).

Deletion asks "what if the receipt is not there". Substitution asks "what if
a VALID receipt is there, for the WRONG hold" — one hold's chained decision
swapped for another's. The chain stays self-consistent when every later hash
is recomputed (``tests/support/chain_rewrite.py``), so ``verify_chain()``
alone says VALID. What catches it, and where it stops, is stated here as
passing tests rather than implied.
"""

from __future__ import annotations

import json

import pytest

import test_execution_authorization_record as fx
from prometheus_protocol.ledger.receipts import DECISION_EVENT, verify_receipts
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.ledger.tip_anchor import FileTipAnchor
from prometheus_protocol.policy.execution import ExecutionNotAuthorized
from tests.support.chain_rewrite import rewrite_entry_and_rehash


def decision_entry(ledger: SqliteLedger, pending_id: int) -> dict:
    hits = [
        e for e in ledger.chained_events()
        if e["event"] == DECISION_EVENT and e["subject"] == f"pending:{pending_id}"
    ]
    assert len(hits) == 1, hits
    return hits[0]


def two_holds(ledger: SqliteLedger):
    """A approved (execution refused, so retry-eligible); B rejected by bob."""

    spy = fx.Spy(refuse=True)
    ctl, _, _ = fx.controller(ledger, route_high_risk=True, spy=spy)
    a = fx.hold(ctl, fx.action("print('a')"))
    b = fx.hold(ctl, fx.action("print('b')"))
    ctl.approve(a.id, identity="alice", reason="ship it")
    ctl.reject(b.id, identity="bob", reason="absolutely not")
    spy._refuse = False
    return ctl, spy, a, b


def test_a_decision_entry_swapped_for_another_holds_IS_detected_without_an_anchor(tmp_path):
    """Entry only. A's chained decision becomes B's (rejected, by bob), chain
    re-hashed to self-consistency. The chain says VALID; the receipts say A's
    row disagrees with its entry; retry refuses on the difference."""

    ledger = SqliteLedger(tmp_path / "ledger.db")  # no anchor, deliberately
    ctl, spy, a, b = two_holds(ledger)
    assert verify_receipts(ledger).ok

    stolen = json.loads(decision_entry(ledger, b.id)["payload"])
    rewrite_entry_and_rehash(ledger, seq=decision_entry(ledger, a.id)["seq"], payload=stolen)
    assert ledger.verify_chain().ok, "the rewrite must be self-consistent or this proves nothing"

    verdict = verify_receipts(ledger)
    assert not verdict.ok
    hit = [f for f in verdict.findings if f.subject == f"pending:{a.id}"]
    assert len(hit) == 1 and hit[0].reason == "decision_differs_from_chain_entry"
    assert {"status", "decided_by", "decision_reason"} <= set(hit[0].fields)

    with pytest.raises(ExecutionNotAuthorized) as refused:
        ctl.retry_execution(a.id, identity="retrier")
    assert refused.value.reason == "decision_differs_from_chain_entry"
    assert len(spy.calls) == 1, "the substituted decision reached the executor"


def test_the_named_limit_entry_AND_row_rewritten_together_is_NOT_detected_without_an_anchor(tmp_path):
    """The limit as a passing test (doctrine #5). The adversary swaps A's
    entry for B's AND rewrites A's row to match. Row equals entry; the chain
    is self-consistent; nothing in the ledger disagrees with anything. Without
    an anchor this is NOT detected — and what it buys is a DOWNGRADE: alice's
    approval now reads as bob's rejection, and retry refuses A as rejected.

    This is the authorization record's limit exactly
    (``test_the_named_limit_a_full_rewrite_is_NOT_detected_without_an_anchor_and_IS_with_one``),
    inherited by the decision receipt. An in-file chain cannot tell a
    consistent rewrite from history; only a witness outside the writer's
    authority can.
    """

    ledger = SqliteLedger(tmp_path / "ledger.db")
    ctl, spy, a, b = two_holds(ledger)

    stolen = json.loads(decision_entry(ledger, b.id)["payload"])
    rewrite_entry_and_rehash(ledger, seq=decision_entry(ledger, a.id)["seq"], payload=stolen)
    ledger._conn.execute(
        "UPDATE pending_actions SET status = ?, decided_by = ?, decided_at = ?, "
        "decision_reason = ? WHERE id = ?",
        (stolen["status"], stolen["decided_by"], stolen["decided_at"],
         stolen["decision_reason"], a.id),
    )
    ledger._conn.commit()

    assert ledger.verify_chain().ok
    assert verify_receipts(ledger).ok, "row equals entry: the receipt check has nothing to report"
    with pytest.raises(ValueError, match="rejected"):
        ctl.retry_execution(a.id, identity="retrier")
    assert len(spy.calls) == 1


def test_the_same_rewrite_IS_detected_with_an_append_only_anchor(tmp_path):
    """With a witness. Same double rewrite; the anchored tips no longer match
    the recomputed hashes, the chain is BROKEN, and retry refuses on the
    chain before it ever reads the row's decision."""

    ledger = SqliteLedger(tmp_path / "ledger.db", tip_anchor=FileTipAnchor(tmp_path / "tip.json"))
    ctl, spy, a, b = two_holds(ledger)

    stolen = json.loads(decision_entry(ledger, b.id)["payload"])
    rewrite_entry_and_rehash(ledger, seq=decision_entry(ledger, a.id)["seq"], payload=stolen)
    ledger._conn.execute(
        "UPDATE pending_actions SET status = ?, decided_by = ?, decided_at = ?, "
        "decision_reason = ? WHERE id = ?",
        (stolen["status"], stolen["decided_by"], stolen["decided_at"],
         stolen["decision_reason"], a.id),
    )
    ledger._conn.commit()

    chain = ledger.verify_chain()
    assert not chain.ok and chain.status == "broken", chain.render()
    assert verify_receipts(ledger).ok, (
        "the two checks are COMPLEMENTARY: rows equal entries, so receipts pass "
        "while the chain fails — an auditor needs both, and the CLI runs both"
    )
    with pytest.raises(ExecutionNotAuthorized) as refused:
        ctl.retry_execution(a.id, identity="retrier")
    assert refused.value.reason == "chain_did_not_verify"
    assert len(spy.calls) == 1


def test_the_subject_is_structural_so_an_entry_cannot_be_moved_between_holds(tmp_path):
    """The other substitution: not the payload but the SUBJECT — B's entry
    relabelled as A's. The subject is hashed into the entry, so relabelling
    without a full re-hash is BROKEN; with one, it is the payload case above
    (A's row differs from its now-duplicated entry, or B is left with none)."""

    ledger = SqliteLedger(tmp_path / "ledger.db")
    _ctl, _spy, a, b = two_holds(ledger)
    b_entry = decision_entry(ledger, b.id)

    ledger._conn.execute(
        "UPDATE audit_chain SET subject = ? WHERE seq = ?", (f"pending:{a.id}", b_entry["seq"])
    )
    ledger._conn.commit()

    chain = ledger.verify_chain()
    assert not chain.ok and chain.status == "broken"
    # And the receipts see it too, from both sides: B has no entry now, and
    # A has two of which the latest is B's.
    verdict = verify_receipts(ledger)
    reasons = {f.subject: f.reason for f in verdict.findings}
    assert reasons[f"pending:{b.id}"] == "decision_entry_missing"
    assert reasons[f"pending:{a.id}"] == "decision_differs_from_chain_entry"
