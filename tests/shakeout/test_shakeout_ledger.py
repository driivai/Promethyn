"""Shakeout characterisation for F6 (passing tripwire).

Judgment confidence/verdict live in the ledger's JSON ``evidence`` column, so
they cannot be filtered in SQL. This test documents the limitation and trips if
a first-class column is ever added (update it then). See
``docs/shakeout-report.md`` (F6).
"""

from __future__ import annotations

import sqlite3

import pytest

from prometheus_protocol.core.models import Attempt, Evidence, Judgment, Tier, Verdict
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger


def test_confidence_is_not_a_queryable_column_but_is_in_json():
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
        assert "confidence" not in columns  # known limitation (F6)
        with pytest.raises(sqlite3.OperationalError):
            ledger._conn.execute("SELECT id FROM attempts WHERE confidence > 0.9")

        # ...but it is recoverable by parsing the JSON evidence column.
        recovered = ledger.attempts()[0]["evidence"]["judgment"]["confidence"]
        assert recovered == 0.95
    finally:
        ledger.close()
