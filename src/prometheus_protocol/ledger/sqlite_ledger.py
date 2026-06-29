"""Experience ledger backed by SQLite.

The ledger is append-only by convention: callers record attempts and
promotions, and read them back in insertion order. That ordered history is
what makes a run auditable (you can see every proposal and every promotion)
and reversible (a promotion can be followed by a rollback record, and the
skill removed from the registry).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

from prometheus_protocol.core.interfaces import Ledger
from prometheus_protocol.core.models import Attempt

_SCHEMA = """
CREATE TABLE IF NOT EXISTS attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle        INTEGER NOT NULL,
    kind         TEXT    NOT NULL,
    task_id      TEXT    NOT NULL,
    split        TEXT    NOT NULL,
    entry_point  TEXT    NOT NULL,
    passed       INTEGER NOT NULL,
    total        INTEGER NOT NULL,
    passed_count INTEGER NOT NULL,
    skills_used  TEXT    NOT NULL,
    code         TEXT    NOT NULL,
    evidence     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS promotions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle       INTEGER NOT NULL,
    skill_id    TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    rate_before REAL    NOT NULL,
    rate_after  REAL    NOT NULL
);
"""


class SqliteLedger(Ledger):
    """SQLite-backed ledger. Pass ``":memory:"`` for an ephemeral instance."""

    def __init__(self, path: Path | str = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def record_attempt(self, attempt: Attempt, *, cycle: int, kind: str) -> int:
        evidence = dict(asdict(attempt.evidence))
        # Record the fused judgment (verdict + calibrated confidence) additively
        # inside the existing JSON column, so no table schema change is needed.
        if attempt.judgment is not None:
            evidence["judgment"] = {
                "verdict": attempt.judgment.verdict,
                "confidence": attempt.judgment.confidence,
            }
        cur = self._conn.execute(
            """
            INSERT INTO attempts (
                cycle, kind, task_id, split, entry_point,
                passed, total, passed_count, skills_used, code, evidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cycle,
                kind,
                attempt.task_id,
                attempt.split,
                attempt.entry_point,
                int(attempt.evidence.passed),
                attempt.evidence.total,
                attempt.evidence.passed_count,
                json.dumps(list(attempt.skills_used)),
                attempt.code,
                json.dumps(evidence),
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def record_promotion(
        self,
        *,
        skill_id: str,
        action: str,
        cycle: int,
        rate_before: float,
        rate_after: float,
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO promotions (cycle, skill_id, action, rate_before, rate_after)
            VALUES (?, ?, ?, ?, ?)
            """,
            (cycle, skill_id, action, rate_before, rate_after),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def attempts(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM attempts ORDER BY id").fetchall()
        return [self._attempt_row(row) for row in rows]

    def promotions(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM promotions ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _attempt_row(row: sqlite3.Row) -> dict:
        record = dict(row)
        record["passed"] = bool(record["passed"])
        record["skills_used"] = json.loads(record["skills_used"])
        record["evidence"] = json.loads(record["evidence"])
        return record
