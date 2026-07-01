"""Shakeout characterisation for F6 (now resolved).

Judgment verdict/confidence were once only in the ledger's JSON ``evidence``
column and could not be filtered in SQL (F6). They are now promoted to
first-class, indexed, queryable columns alongside the JSON — which stays the
source of record — so an operator can WHERE-clause on confidence. This test
tripped when the column was added (as its predecessor instructed) and now
characterises the resolved behaviour. See ``docs/observability.md`` and
``docs/shakeout-report.md`` (F6).
"""

from __future__ import annotations

from prometheus_protocol.core.models import Attempt, Evidence, Judgment, Tier, Verdict
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger


def test_confidence_is_a_queryable_column_matching_the_json():
    ledger = SqliteLedger(":memory:")
    try:
        evidence = Evidence(
            passed=True, total=1, passed_count=1,
            verifier_id="subprocess-tests", verdict=Verdict.PASS, tier=Tier.HARD,
        )
        attempt = Attempt(
            task_id="t", split="train", entry_point="f", code="x", evidence=evidence,
            judgment=Judgment(Verdict.PASS, 0.95, authoritative=True),
        )
        ledger.record_attempt(attempt, cycle=1, kind="baseline")

        columns = [
            row[1]
            for row in ledger._conn.execute("PRAGMA table_info(attempts)").fetchall()
        ]
        assert "confidence" in columns and "verdict" in columns  # F6 resolved

        # It is now SQL-filterable directly...
        rows = ledger._conn.execute(
            "SELECT id FROM attempts WHERE confidence > 0.9"
        ).fetchall()
        assert len(rows) == 1

        # ...and the column equals the JSON, which stays the source of record.
        row = ledger.attempts()[0]
        assert row["confidence"] == 0.95
        assert row["evidence"]["judgment"]["confidence"] == 0.95
        assert row["verdict"] == row["evidence"]["judgment"]["verdict"] == "pass"
    finally:
        ledger.close()
