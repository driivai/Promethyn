"""Unit tests for the SQLite experience ledger."""

from __future__ import annotations

from prometheus_protocol.core.models import Attempt, Evidence
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger


def _attempt(passed: bool) -> Attempt:
    return Attempt(
        task_id="train/mean",
        split="train",
        entry_point="mean",
        code="def mean(xs): ...",
        evidence=Evidence(passed=passed, total=3, passed_count=3 if passed else 1),
        skills_used=("skill-empty-input",),
    )


def test_record_and_read_attempts():
    ledger = SqliteLedger(":memory:")
    try:
        ledger.record_attempt(_attempt(False), cycle=1, kind="train")
        ledger.record_attempt(_attempt(True), cycle=1, kind="heldout-after")
        rows = ledger.attempts()
        assert len(rows) == 2
        first = rows[0]
        assert first["task_id"] == "train/mean"
        assert first["passed"] is False
        assert first["skills_used"] == ["skill-empty-input"]
        assert first["evidence"]["total"] == 3
        assert rows[1]["passed"] is True
    finally:
        ledger.close()


def test_records_keep_insertion_order():
    ledger = SqliteLedger(":memory:")
    try:
        for _ in range(5):
            ledger.record_attempt(_attempt(True), cycle=1, kind="train")
        ids = [row["id"] for row in ledger.attempts()]
        assert ids == sorted(ids)
    finally:
        ledger.close()


def test_record_and_read_promotions():
    ledger = SqliteLedger(":memory:")
    try:
        ledger.record_promotion(
            skill_id="skill-empty-input",
            action="promote",
            cycle=1,
            rate_before=0.4,
            rate_after=1.0,
        )
        promotions = ledger.promotions()
        assert len(promotions) == 1
        assert promotions[0]["skill_id"] == "skill-empty-input"
        assert promotions[0]["action"] == "promote"
        assert promotions[0]["rate_after"] == 1.0
    finally:
        ledger.close()
