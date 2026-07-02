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
    evidence     TEXT    NOT NULL,
    -- Judgment promoted to queryable columns; the evidence JSON above stays the
    -- source of record. NULL when the attempt carried no fused judgment.
    verdict      TEXT,
    confidence   REAL
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
    decision_reason TEXT,
    -- Atomic at-most-once-execution guard, independent of the human decision:
    -- set when an execution for this hold is claimed (approve or retry), so two
    -- concurrent drivers cannot both execute. NULL = not yet executed; a
    -- fail-closed refusal releases it back to NULL so a retry can re-drive.
    execution_committed_at TEXT
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
    created_at  TEXT    NOT NULL,
    -- Judgment promoted to queryable columns; the judgment JSON is the source of
    -- record. NULL for rows written before observability (nothing to backfill).
    verdict       TEXT,
    confidence    REAL,
    authoritative INTEGER,
    judgment      TEXT,   -- JSON: the Judgment the executed action rested on
    -- The pending hold this execution resolves, when it came from one
    -- (human-approved or retried). NULL for auto-approved/blocked rows and for
    -- rows written before the link existed.
    pending_id    INTEGER
);
"""

# Terminal states a pending action can settle into. ``pending`` is the only
# non-terminal state; once decided it is never re-opened.
_PENDING_STATUS = "pending"

# Additive columns ensured on open (added to ledgers that predate them) so the
# write path can always populate them: the judgment columns promoted for
# querying, and the execution -> pending-hold link.
_ADDITIVE_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "attempts": [("verdict", "TEXT"), ("confidence", "REAL")],
    "executions": [
        ("verdict", "TEXT"),
        ("confidence", "REAL"),
        ("authoritative", "INTEGER"),
        ("judgment", "TEXT"),
        ("pending_id", "INTEGER"),
    ],
    "pending_actions": [("execution_committed_at", "TEXT")],
}

# Indexes for the range/equality audit queries.
_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_attempts_confidence   ON attempts(confidence);
CREATE INDEX IF NOT EXISTS idx_attempts_verdict      ON attempts(verdict);
CREATE INDEX IF NOT EXISTS idx_executions_confidence ON executions(confidence);
CREATE INDEX IF NOT EXISTS idx_executions_verdict    ON executions(verdict);
"""


def _load_json(text: str | None):
    """Best-effort JSON decode; returns ``None`` on empty or malformed input."""

    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _judgment_from_evidence(evidence_json: str | None) -> dict | None:
    """Extract ``{verdict, confidence}`` from an attempt's evidence JSON, or None."""

    evidence = _load_json(evidence_json)
    judgment = evidence.get("judgment") if isinstance(evidence, dict) else None
    if not isinstance(judgment, dict):
        return None
    if "verdict" not in judgment or "confidence" not in judgment:
        return None
    return judgment


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
            self._conn = conn
            # Forward, additive schema sync: add columns to ledgers that predate
            # them (judgment columns, the execution link, the execution claim)
            # and (re)create the indexes. Cheap and idempotent, so it is safe on
            # every open; the data backfill is separate (``backfill``). Guarded
            # with the open itself: on a read-only or unwritable existing ledger
            # the ALTER TABLEs raise here, and this must surface as the same
            # StateError (and close the connection), not a raw sqlite3 error.
            self.migration_added_columns = self._ensure_additive_columns()
        except sqlite3.DatabaseError as exc:
            conn.close()
            raise StateError(
                f"could not open experience ledger {self.path!r}: {exc}. "
                "The file may be corrupt, locked, or not writable; "
                "remove, repair, or grant write access, then retry."
            ) from exc

    def _ensure_additive_columns(self) -> list[str]:
        added: list[str] = []
        for table, columns in _ADDITIVE_COLUMNS.items():
            existing = {
                row["name"] for row in self._conn.execute(f"PRAGMA table_info({table})")
            }
            for name, decl in columns:
                if name not in existing:
                    # table/column names are internal constants, not user input.
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
                    added.append(f"{table}.{name}")
        self._conn.executescript(_INDEXES)
        self._conn.commit()
        return added

    def record_attempt(self, attempt: Attempt, *, cycle: int, kind: str) -> int:
        evidence = dict(asdict(attempt.evidence))
        # Record the fused judgment (verdict + calibrated confidence) additively
        # inside the existing JSON column, so no table schema change is needed.
        if attempt.judgment is not None:
            evidence["judgment"] = {
                "verdict": attempt.judgment.verdict,
                "confidence": attempt.judgment.confidence,
            }
        # Promote the same judgment to columns alongside the JSON — they are
        # written from one source, so they cannot diverge.
        verdict = attempt.judgment.verdict.value if attempt.judgment is not None else None
        confidence = attempt.judgment.confidence if attempt.judgment is not None else None
        cur = self._conn.execute(
            """
            INSERT INTO attempts (
                cycle, kind, task_id, split, entry_point,
                passed, total, passed_count, skills_used, code, evidence,
                verdict, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                verdict,
                confidence,
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

    def claim_pending_execution(self, pending_id: int, claimed_at: str) -> bool:
        """Atomically claim the right to execute a hold; True iff this call won.

        Sets ``execution_committed_at`` only when it was NULL, so at most one of
        any number of concurrent drivers (approve and/or retry) can proceed to
        the executor. Independent of the human decision: it never touches
        status/decided_*, so the recorded decision is untouched.
        """

        cur = self._conn.execute(
            "UPDATE pending_actions SET execution_committed_at = ? "
            "WHERE id = ? AND execution_committed_at IS NULL",
            (claimed_at, pending_id),
        )
        self._conn.commit()
        return cur.rowcount == 1

    def release_pending_execution(self, pending_id: int) -> None:
        """Release a claim taken by :meth:`claim_pending_execution`.

        Called only after a *refused* (fail-closed, no side-effect) execution,
        so the approved hold stays retry-eligible; a successful execution keeps
        its claim, marking the hold as having executed.
        """

        self._conn.execute(
            "UPDATE pending_actions SET execution_committed_at = NULL WHERE id = ?",
            (pending_id,),
        )
        self._conn.commit()

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
        judgment: dict | None = None,
        pending_id: int | None = None,
    ) -> int:
        # The judgment JSON is the source of record; verdict/confidence/
        # authoritative are promoted from it into queryable columns, from the
        # same object, so they cannot diverge.
        verdict = judgment.get("verdict") if judgment else None
        confidence = judgment.get("confidence") if judgment else None
        authoritative = (
            int(bool(judgment.get("authoritative"))) if judgment else None
        )
        cur = self._conn.execute(
            """
            INSERT INTO executions (
                subject_id, source, executed, refused, sandbox,
                exit_status, detail, created_at,
                verdict, confidence, authoritative, judgment, pending_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                verdict,
                confidence,
                authoritative,
                json.dumps(judgment) if judgment is not None else None,
                pending_id,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def executions(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM executions ORDER BY id").fetchall()
        return [self._execution_row(row) for row in rows]

    def executions_for_pending(self, pending_id: int) -> list[dict]:
        """Executions linked to one pending hold, in insertion order."""

        rows = self._conn.execute(
            "SELECT * FROM executions WHERE pending_id = ? ORDER BY id",
            (pending_id,),
        ).fetchall()
        return [self._execution_row(row) for row in rows]

    # -- audit queries (read-only) -----------------------------------------

    def executions_below_confidence(self, threshold: float) -> list[dict]:
        """Executed actions whose fused confidence is below ``threshold``."""

        rows = self._conn.execute(
            "SELECT * FROM executions "
            "WHERE executed = 1 AND confidence IS NOT NULL AND confidence < ? "
            "ORDER BY id",
            (float(threshold),),
        ).fetchall()
        return [self._execution_row(row) for row in rows]

    def authoritative_pass_below(self, threshold: float) -> list[dict]:
        """Executed authoritative-PASS actions with fused confidence below ``threshold``.

        The escalation blind spot: an authoritative PASS binds the verdict, so it
        is not escalated for low confidence, yet it may have run with weak fused
        confidence. This surfaces exactly those executed actions for review — it
        does not change what escalates (that stays gated to non-authoritative
        verdicts).
        """

        rows = self._conn.execute(
            "SELECT * FROM executions "
            "WHERE executed = 1 AND verdict = 'pass' AND authoritative = 1 "
            "AND confidence IS NOT NULL AND confidence < ? ORDER BY id",
            (float(threshold),),
        ).fetchall()
        return [self._execution_row(row) for row in rows]

    def human_decisions(self) -> list[dict]:
        """The decision log: pending actions a human or the sweep resolved."""

        rows = self._conn.execute(
            "SELECT * FROM pending_actions WHERE decided_by IS NOT NULL ORDER BY id"
        ).fetchall()
        return [self._pending_row(row) for row in rows]

    # -- backfill ----------------------------------------------------------

    def backfill(self) -> dict:
        """Fill judgment columns for historical rows from their JSON. Idempotent.

        Only rows whose columns are still NULL are touched, so re-running is a
        no-op. Rows with malformed or missing JSON are left NULL and counted,
        never fatal.
        """

        report = {
            "added_columns": list(self.migration_added_columns),
            "attempts": self._backfill_attempts(),
            "executions": self._backfill_executions(),
        }
        self._conn.commit()
        return report

    def _backfill_attempts(self) -> dict:
        rows = self._conn.execute(
            "SELECT id, evidence FROM attempts WHERE verdict IS NULL"
        ).fetchall()
        filled = skipped = 0
        for row in rows:
            judgment = _judgment_from_evidence(row["evidence"])
            if judgment is None:
                skipped += 1
                continue
            self._conn.execute(
                "UPDATE attempts SET verdict = ?, confidence = ? WHERE id = ?",
                (str(judgment["verdict"]), judgment["confidence"], row["id"]),
            )
            filled += 1
        return {"filled": filled, "skipped": skipped}

    def _backfill_executions(self) -> dict:
        rows = self._conn.execute(
            "SELECT id, judgment FROM executions "
            "WHERE verdict IS NULL AND judgment IS NOT NULL"
        ).fetchall()
        filled = skipped = 0
        for row in rows:
            judgment = _load_json(row["judgment"])
            if not isinstance(judgment, dict) or "verdict" not in judgment:
                skipped += 1
                continue
            self._conn.execute(
                "UPDATE executions "
                "SET verdict = ?, confidence = ?, authoritative = ? WHERE id = ?",
                (
                    str(judgment["verdict"]),
                    judgment.get("confidence"),
                    int(bool(judgment.get("authoritative"))),
                    row["id"],
                ),
            )
            filled += 1
        return {"filled": filled, "skipped": skipped}

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
        if record.get("authoritative") is not None:
            record["authoritative"] = bool(record["authoritative"])
        if record.get("judgment"):
            record["judgment"] = _load_json(record["judgment"])
        return record
