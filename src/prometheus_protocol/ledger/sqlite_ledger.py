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

from prometheus_protocol.core.errors import StateError
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

CREATE TABLE IF NOT EXISTS pending_actions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id      TEXT    NOT NULL,
    risk_class      TEXT    NOT NULL,
    reason          TEXT    NOT NULL,
    verdict         TEXT    NOT NULL,
    confidence      REAL    NOT NULL,
    status          TEXT    NOT NULL,
    action          TEXT    NOT NULL,   -- JSON: the ExecutableAction payload
    judgment        TEXT    NOT NULL,   -- JSON: the Judgment it rests on
    created_at      TEXT    NOT NULL,
    decided_by      TEXT,
    decided_at      TEXT,
    decision_reason TEXT
);

CREATE TABLE IF NOT EXISTS executions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id  TEXT    NOT NULL,
    source      TEXT    NOT NULL,   -- how the decision reached the executor
    executed    INTEGER NOT NULL,
    refused     INTEGER NOT NULL,
    sandbox     TEXT    NOT NULL,
    exit_status INTEGER,
    detail      TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);
"""

# Terminal states a pending action can settle into. ``pending`` is the only
# non-terminal state; once decided it is never re-opened.
_PENDING_STATUS = "pending"


class SqliteLedger(Ledger):
    """SQLite-backed ledger. Pass ``":memory:"`` for an ephemeral instance."""

    def __init__(self, path: Path | str = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        try:
            conn.row_factory = sqlite3.Row
            conn.executescript(_SCHEMA)
            conn.commit()
        except sqlite3.DatabaseError as exc:
            conn.close()
            raise StateError(
                f"could not open experience ledger {self.path!r}: {exc}. "
                "The file may be corrupt or locked by another process; "
                "remove or repair it, then retry."
            ) from exc
        self._conn = conn

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

    # -- execution audit ---------------------------------------------------

    def record_pending_action(
        self,
        *,
        subject_id: str,
        risk_class: str,
        reason: str,
        verdict: str,
        confidence: float,
        action: dict,
        judgment: dict,
        created_at: str,
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO pending_actions (
                subject_id, risk_class, reason, verdict, confidence,
                status, action, judgment, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                subject_id,
                risk_class,
                reason,
                verdict,
                float(confidence),
                _PENDING_STATUS,
                json.dumps(action),
                json.dumps(judgment),
                created_at,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def resolve_pending_action(
        self,
        pending_id: int,
        *,
        status: str,
        decided_by: str,
        decided_at: str,
        decision_reason: str = "",
    ) -> None:
        # Only a still-pending action may be resolved; a decided one is never
        # re-opened, so a human decision cannot be silently overwritten.
        cur = self._conn.execute(
            """
            UPDATE pending_actions
               SET status = ?, decided_by = ?, decided_at = ?, decision_reason = ?
             WHERE id = ? AND status = ?
            """,
            (status, decided_by, decided_at, decision_reason, pending_id, _PENDING_STATUS),
        )
        self._conn.commit()
        if cur.rowcount != 1:
            raise StateError(
                f"cannot resolve pending action {pending_id}: it does not exist "
                "or has already been decided"
            )

    def pending_actions(self, *, status: str | None = None) -> list[dict]:
        if status is None:
            rows = self._conn.execute(
                "SELECT * FROM pending_actions ORDER BY id"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM pending_actions WHERE status = ? ORDER BY id",
                (status,),
            ).fetchall()
        return [self._pending_row(row) for row in rows]

    def pending_action(self, pending_id: int) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM pending_actions WHERE id = ?", (pending_id,)
        ).fetchone()
        return self._pending_row(row) if row is not None else None

    def record_execution(
        self,
        *,
        subject_id: str,
        source: str,
        executed: bool,
        refused: bool,
        sandbox_name: str,
        exit_status: int | None,
        detail: str,
        created_at: str,
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO executions (
                subject_id, source, executed, refused, sandbox,
                exit_status, detail, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                subject_id,
                source,
                int(executed),
                int(refused),
                sandbox_name,
                exit_status,
                detail,
                created_at,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def executions(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM executions ORDER BY id").fetchall()
        return [self._execution_row(row) for row in rows]

    def close(self) -> None:
        self._conn.close()

    @staticmethod
    def _attempt_row(row: sqlite3.Row) -> dict:
        record = dict(row)
        record["passed"] = bool(record["passed"])
        record["skills_used"] = json.loads(record["skills_used"])
        record["evidence"] = json.loads(record["evidence"])
        return record

    @staticmethod
    def _pending_row(row: sqlite3.Row) -> dict:
        record = dict(row)
        record["action"] = json.loads(record["action"])
        record["judgment"] = json.loads(record["judgment"])
        return record

    @staticmethod
    def _execution_row(row: sqlite3.Row) -> dict:
        record = dict(row)
        record["executed"] = bool(record["executed"])
        record["refused"] = bool(record["refused"])
        return record
