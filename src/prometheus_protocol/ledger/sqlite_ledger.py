"""Experience ledger backed by SQLite.

The ledger is append-only by convention: callers record attempts and
promotions, and read them back in insertion order. That ordered history is
what makes a run auditable (you can see every proposal and every promotion)
and reversible (a promotion can be followed by a rollback record, and the
skill removed from the registry).
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from dataclasses import asdict
from pathlib import Path

from prometheus_protocol.core.errors import StateError
from prometheus_protocol.core.interfaces import Ledger
from prometheus_protocol.core.models import (
    Attempt,
    Evidence,
    Unavailable,
    assert_never,
)
from prometheus_protocol.ledger.audit_chain import (
    GENESIS_ROOT,
    NOT_VERIFIABLE,
    ChainTip,
    ChainVerification,
    canonical_json,
    entry_hash,
    verify_rows,
)
from prometheus_protocol.ledger.receipts import (
    DECISION_EVENT,
    OUTCOME_EVENT,
    decision_subject,
    outcome_subject,
    project_decision,
    project_outcome,
)
from prometheus_protocol.ledger.tip_anchor import (
    AnchorUnavailable,
    TipAnchor,
    anchor_history,
)

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
    authorization   TEXT,               -- JSON: validated descriptor/assessment binding
    created_at      TEXT    NOT NULL,
    decided_by      TEXT,
    decided_at      TEXT,
    decision_reason TEXT,
    -- Atomic at-most-once-execution guard, independent of the human decision:
    -- set when an execution for this hold is claimed (approve or retry), so two
    -- concurrent drivers cannot both execute. NULL = not yet executed; a
    -- fail-closed refusal releases it back to NULL so a retry can re-drive.
    execution_committed_at TEXT,
    -- Set when a policy rotation voided a still-pending hold: a system
    -- transition (status 'invalidated'), separate from expiry, in flat columns
    -- so a sweep can find rotated-out holds without parsing the record.
    invalidated_at     TEXT,
    invalidated_reason TEXT
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
    pending_id    INTEGER,
    -- JSON: the versioned authorization record (policy/record.py) this outcome
    -- was decided under. For a human-approved or retried execution it is the
    -- hold's PINNED record. NULL for rows written before records existed.
    authorization TEXT
);

-- Workflow attribution for the governed orchestration layer (additive; the
-- single-proposer flow never writes here). One row per agent step in a
-- multi-step run, so "show every step in this workflow, which agent, at what
-- tier/confidence, what the gate decided, where a human was asked" is one
-- query. The step's action, if any, is authorized through the SAME gate and
-- recorded in `executions`; this table links to that hold by subject_id and
-- pending_id. It records grading and routing outcomes — it authorizes nothing.
CREATE TABLE IF NOT EXISTS workflow_steps (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id  TEXT    NOT NULL,
    step_id      TEXT    NOT NULL,
    agent_id     TEXT    NOT NULL,
    tier         TEXT    NOT NULL,   -- the tier the step's output was graded at
    verdict      TEXT    NOT NULL,
    confidence   REAL    NOT NULL,   -- this step's own graded confidence
    proposed_action INTEGER NOT NULL, -- 1 if the step proposed an executable action
    outcome      TEXT    NOT NULL,   -- approve / route / block / none (no action)
    subject_id   TEXT    NOT NULL,   -- links to executions.subject_id, when an action
    pending_id   INTEGER,            -- the human hold this step created, if routed
    created_at   TEXT    NOT NULL
);

-- Tamper-EVIDENT audit chain (see ledger/audit_chain.py). Each entry commits to
-- the prior entry's hash, so a retroactive edit/delete/reorder of an interior
-- entry breaks every later link and is caught by verify_chain(). The chokepoint's
-- authorization decisions (authorize / refuse / execute) write here. `seq` is the
-- chain position (1-based, contiguous); `payload` is canonical JSON.
CREATE TABLE IF NOT EXISTS audit_chain (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    seq        INTEGER NOT NULL UNIQUE,
    created_at TEXT    NOT NULL,
    event      TEXT    NOT NULL,
    subject    TEXT    NOT NULL,
    payload    TEXT    NOT NULL,   -- canonical JSON of the decision detail
    prev_hash  TEXT    NOT NULL,   -- prior entry's entry_hash (GENESIS_ROOT for seq 1)
    entry_hash TEXT    NOT NULL    -- sha256 over this entry's content AND prev_hash
);
"""


def _inserted_id(cur: sqlite3.Cursor) -> int:
    """The row id sqlite just assigned, or a refusal.

    ``Cursor.lastrowid`` is ``int | None`` because a cursor that did not INSERT
    has no row id. Every caller here has just executed one, so ``None`` would
    mean the write did not happen — which must say so, rather than being
    coerced by ``int(None)`` into a ``TypeError`` several frames away from the
    cause.
    """

    row_id = cur.lastrowid
    if row_id is None:  # pragma: no cover - an INSERT always assigns one
        raise StateError(
            "sqlite reported no row id for an insert that should have made one"
        )
    return row_id


# Terminal states a pending action can settle into. ``pending`` is the only
# non-terminal state; once decided it is never re-opened.
_PENDING_STATUS = "pending"
#: The two statuses the re-observation transition moves BETWEEN.
#:
#: SPELLED, NOT IMPORTED, and the reason is layering: ``PendingStatus`` lives in
#: ``execution/models.py``, which imports the policy seam, and a ledger that
#: imported the execution layer would invert the dependency the whole package
#: is arranged around — which is why ``_PENDING_STATUS`` above is a literal too.
#: What cannot be derived is the VALUE; what can be derived is the CHECK, so
#: ``tests/conformance/test_reobservation_branch_delete.py`` asserts these three
#: literals equal the enum members. That is the G26 answer applied here: three
#: copies that agree by hand are what a guard is for.
_APPROVED_STATUS = "approved"
_STATE_MOVED_STATUS = "state_moved_after_approval"

# Additive columns ensured on open (added to ledgers that predate them) so the
# write path can always populate them: the judgment columns promoted for
# querying, and the execution -> pending-hold link.
_ADDITIVE_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "attempts": [
        ("verdict", "TEXT"),
        ("confidence", "REAL"),
        # EX-1 discriminator, the same one the executions table carries: 1 when
        # this attempt's verifier could not RUN, so the NOT NULL count columns'
        # zeros are never mistaken for "ran and found nothing".
        ("unavailable", "INTEGER"),
    ],
    "executions": [
        ("verdict", "TEXT"),
        ("confidence", "REAL"),
        ("authoritative", "INTEGER"),
        ("judgment", "TEXT"),
        ("pending_id", "INTEGER"),
        # EX-1 discriminator: 1 when this row is a could-not-EXECUTE (an
        # authoritative verifier that could not run — an infra/policy fault),
        # forever distinct from a genuine ABSTAIN. Before EX-1 an infra-ABSTAIN
        # and a real abstention wrote byte-identical rows; this column, derived
        # from the recorded source, makes them permanently separable.
        ("unavailable", "INTEGER"),
        # The versioned authorization record the outcome was decided under.
        ("authorization", "TEXT"),
        # #120's structural start signals, carried as the executor measured
        # them and chained with the rest of the outcome (ledger/receipts.py).
        # NULL means no executor was invoked for this row at all — a blocked,
        # unavailable or pre-execution-refused row — which is a different fact
        # from 0 (invoked; isolation did not start).
        ("started_ok", "INTEGER"),
        ("candidate_started", "INTEGER"),
    ],
    "pending_actions": [
        ("execution_committed_at", "TEXT"),
        ("authorization", "TEXT"),
        # Policy-rotation invalidation, in flat columns.
        ("invalidated_at", "TEXT"),
        ("invalidated_reason", "TEXT"),
    ],
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

    @classmethod
    def private(
        cls, path: Path | str, *, tip_anchor: TipAnchor | None = None
    ) -> SqliteLedger:
        """Create trusted-zone storage; never chmod existing public user data."""
        if not os.fspath(path) or os.fspath(path) == ":memory:":
            raise ValueError("private ledger requires a filesystem path")
        location = Path(path).absolute()
        if location.is_symlink() or location.parent.is_symlink():
            raise ValueError("private ledger cannot use a symlink")
        location.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        cls.check_private_path(location, require_file=False)
        fd = os.open(
            location,
            os.O_RDWR | os.O_CREAT | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            cls.check_private_path(location)
            os.fsync(fd)
        finally:
            os.close(fd)
        return cls(location, tip_anchor=tip_anchor)

    @staticmethod
    def check_private_path(path: Path, *, require_file: bool = True) -> None:
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError("private ledger cannot use a symlink")
        parent = path.parent.stat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_mode & 0o077
            or parent.st_uid != os.geteuid()
        ):
            raise PermissionError(
                "authorization ledger parent must be private and owned by the gate"
            )
        if not require_file and not path.exists():
            return
        info = path.stat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
        ):
            raise PermissionError(
                "authorization ledger must be a private, singly linked gate-owned file"
            )

    def __init__(
        self,
        path: Path | str = ":memory:",
        *,
        tip_anchor: TipAnchor | None = None,
    ) -> None:
        self.path = str(path)
        # The out-of-band anchor that makes a genesis rewrite detectable.
        # Optional because an in-memory or throwaway ledger has nothing to
        # anchor against; where one is configured it is written after EVERY
        # chain append and consulted on EVERY verify, so an auditor cannot
        # forget to pass it. The production builder (runtime/factory.py
        # ``build_ledger``) supplies the configured target and warns when there
        # is none.
        self._tip_anchor = tip_anchor
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        try:
            conn.row_factory = sqlite3.Row
            # Wait (rather than immediately erroring) when another connection holds
            # the write lock, so concurrent appenders serialize instead of raising
            # "database is locked". Paired with the retry in record_chained.
            conn.execute("PRAGMA busy_timeout = 5000")
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
        # The pass/total/passed_count columns describe a check that RAN, and are
        # NOT NULL in the schema. An attempt whose verifier could not run has no
        # counts to report, and 0/0/0 alone would be indistinguishable from a
        # check that ran and found nothing — so the `unavailable` discriminator
        # says which it is, exactly as the executions table already does for
        # EX-1. The evidence JSON carries the Unavailable's verifier_id, tier and
        # reason; the discriminator is what makes the two permanently separable.
        outcome = attempt.evidence
        if isinstance(outcome, Unavailable):
            ran: Evidence | None = None
        elif isinstance(outcome, Evidence):
            ran = outcome
        else:
            assert_never(outcome)
        passed = int(ran.passed) if ran is not None else 0
        total = ran.total if ran is not None else 0
        passed_count = ran.passed_count if ran is not None else 0
        unavailable = 0 if ran is not None else 1
        # Record the fused judgment (verdict + calibrated confidence) additively
        # inside the existing JSON column, so no table schema change is needed.
        if attempt.judgment is not None:
            evidence["judgment"] = {
                "verdict": attempt.judgment.verdict,
                "confidence": attempt.judgment.confidence,
            }
        # Promote the same judgment to columns alongside the JSON — they are
        # written from one source, so they cannot diverge.
        verdict = (
            attempt.judgment.verdict.value if attempt.judgment is not None else None
        )
        confidence = (
            attempt.judgment.confidence if attempt.judgment is not None else None
        )
        cur = self._conn.execute(
            """
            INSERT INTO attempts (
                cycle, kind, task_id, split, entry_point,
                passed, total, passed_count, skills_used, code, evidence,
                verdict, confidence, unavailable
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cycle,
                kind,
                attempt.task_id,
                attempt.split,
                attempt.entry_point,
                passed,
                total,
                passed_count,
                json.dumps(list(attempt.skills_used)),
                attempt.code,
                json.dumps(evidence),
                verdict,
                confidence,
                unavailable,
            ),
        )
        self._conn.commit()
        return _inserted_id(cur)

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
        return _inserted_id(cur)

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
        authorization: dict | None = None,
        created_at: str,
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO pending_actions (
                subject_id, risk_class, reason, verdict, confidence,
                status, action, judgment, authorization, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                json.dumps(authorization) if authorization is not None else None,
                created_at,
            ),
        )
        self._conn.commit()
        return _inserted_id(cur)

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
            (
                status,
                decided_by,
                decided_at,
                decision_reason,
                pending_id,
                _PENDING_STATUS,
            ),
        )
        self._conn.commit()
        if cur.rowcount != 1:
            raise StateError(
                f"cannot resolve pending action {pending_id}: it does not exist "
                "or has already been decided"
            )
        # THE DECISION RECEIPT (F13). Chained AFTER the row commits, from the
        # row as stored, so the receipt is what a later reader will project —
        # never the arguments this call was handed. If this append raises (an
        # anchor that cannot be written), the row says decided and the chain
        # says nothing, and retry refuses it as ``decision_entry_missing``:
        # the fail-closed direction, and the same shape as a hold whose
        # ``pending.hold`` append failed.
        self._chain_decision(pending_id, at=decided_at)

    def invalidate_pending_action(
        self, pending_id: int, *, invalidated_at: str, reason: str
    ) -> bool:
        """Void a still-pending hold on a policy rotation; True iff it was pending.

        The same still-pending guard as ``resolve_pending_action``: a decided
        hold is never re-opened or rewritten by a rotation. The flat columns
        carry the same timestamp and reason as the audited transition.
        """

        cur = self._conn.execute(
            """
            UPDATE pending_actions
               SET status = ?, decided_by = ?, decided_at = ?, decision_reason = ?,
                   invalidated_at = ?, invalidated_reason = ?
             WHERE id = ? AND status = ?
            """,
            (
                "invalidated",
                "system:policy-rotation",
                invalidated_at,
                reason,
                invalidated_at,
                reason,
                pending_id,
                _PENDING_STATUS,
            ),
        )
        self._conn.commit()
        changed = cur.rowcount == 1
        if changed:
            # The receipt for a system transition, chained like a human one:
            # the row's status moved, and a reader of the row must be able to
            # find that move on the chain (F13 covers every writer, not only
            # approval — a forged ``invalidated`` on a real approval is a
            # denial of service with the same signature).
            self._chain_decision(pending_id, at=invalidated_at)
        return changed

    def mark_state_moved(self, pending_id: int, *, at: str, reason: str) -> bool:
        """Make an APPROVED hold terminal; True iff it was approved.

        The mirror image of the two guards above: they refuse to touch anything
        that is not still ``pending``, this refuses to touch anything that is
        not ``approved``. ``decided_by``/``decided_at``/``decision_reason`` are
        left exactly as the human wrote them — the approval was a correct
        decision on the state it was shown — and the flat invalidation columns
        carry when and why the hold stopped being executable, so a sweep can
        query it without parsing the record.
        """

        cur = self._conn.execute(
            """
            UPDATE pending_actions
               SET status = ?, invalidated_at = ?, invalidated_reason = ?
             WHERE id = ? AND status = ?
            """,
            (
                _STATE_MOVED_STATUS,
                at,
                reason,
                pending_id,
                _APPROVED_STATUS,
            ),
        )
        self._conn.commit()
        changed = cur.rowcount == 1
        if changed:
            # The one transition OUT of approved, receipted like the others.
            # ``decided_by``/``decided_at`` are unchanged by design and the
            # receipt restates them; only ``status`` and the invalidation
            # columns move, and the receipt says so.
            self._chain_decision(pending_id, at=at)
        return changed

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
        authorization: dict | None = None,
        started_ok: bool | None = None,
        candidate_started: bool | None = None,
    ) -> int:
        # The judgment JSON is the source of record; verdict/confidence/
        # authoritative are promoted from it into queryable columns, from the
        # same object, so they cannot diverge.
        verdict = judgment.get("verdict") if judgment else None
        confidence = judgment.get("confidence") if judgment else None
        authoritative = int(bool(judgment.get("authoritative"))) if judgment else None
        # EX-1: a could-not-EXECUTE row is marked distinctly (derived from the
        # source the controller records), so an infra/policy unavailability is
        # forever separable in the ledger from a genuine abstention — the two used
        # to write byte-identical rows, which is how the bug hid.
        unavailable = int(source == "unavailable")
        cur = self._conn.execute(
            """
            INSERT INTO executions (
                subject_id, source, executed, refused, sandbox,
                exit_status, detail, created_at,
                verdict, confidence, authoritative, judgment, pending_id, unavailable,
                authorization, started_ok, candidate_started
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                unavailable,
                json.dumps(authorization) if authorization is not None else None,
                None if started_ok is None else int(started_ok),
                None if candidate_started is None else int(candidate_started),
            ),
        )
        self._conn.commit()
        execution_id = _inserted_id(cur)
        # THE OUTCOME RECEIPT (F14). The row is read back and projected by
        # name (``ledger/receipts.py``), then chained under this execution's
        # identity in the same call — so an execution row cannot exist without
        # a receipt written from the same bytes, and a later rewrite of
        # ``executed`` or ``detail`` differs from it. Read back rather than
        # built from the arguments for the same reason as the decision
        # receipt: the receipt must be what a later projection of the
        # untouched row produces, through the same conversion, or the two can
        # drift on a type coercion and read as tampering that never happened.
        stored = self._conn.execute(
            "SELECT * FROM executions WHERE id = ?", (execution_id,)
        ).fetchone()
        self.record_chained(
            event=OUTCOME_EVENT,
            subject=outcome_subject(execution_id),
            payload=project_outcome(self._execution_row(stored)),
            created_at=created_at,
        )
        return execution_id

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

    # -- workflow attribution (additive; orchestration layer) --------------

    def record_workflow_step(
        self,
        *,
        workflow_id: str,
        step_id: str,
        agent_id: str,
        tier: str,
        verdict: str,
        confidence: float,
        proposed_action: bool,
        outcome: str,
        subject_id: str,
        pending_id: int | None,
        created_at: str,
    ) -> int:
        """Record one agent step of a governed workflow. Authorizes nothing.

        This is pure attribution: the step's grading (tier/verdict/confidence),
        whether it proposed an action, and what the shared gate decided. Any
        real execution is written by the executor into ``executions``; this row
        links to it by ``subject_id``/``pending_id``.
        """

        cur = self._conn.execute(
            """
            INSERT INTO workflow_steps (
                workflow_id, step_id, agent_id, tier, verdict, confidence,
                proposed_action, outcome, subject_id, pending_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                workflow_id,
                step_id,
                agent_id,
                tier,
                verdict,
                float(confidence),
                1 if proposed_action else 0,
                outcome,
                subject_id,
                pending_id,
                created_at,
            ),
        )
        self._conn.commit()
        return _inserted_id(cur)

    def workflow_steps(self, workflow_id: str) -> list[dict]:
        """Every recorded step of one workflow, in insertion order."""

        rows = self._conn.execute(
            "SELECT * FROM workflow_steps WHERE workflow_id = ? ORDER BY id",
            (workflow_id,),
        ).fetchall()
        return [
            {
                "id": row["id"],
                "workflow_id": row["workflow_id"],
                "step_id": row["step_id"],
                "agent_id": row["agent_id"],
                "tier": row["tier"],
                "verdict": row["verdict"],
                "confidence": row["confidence"],
                "proposed_action": bool(row["proposed_action"]),
                "outcome": row["outcome"],
                "subject_id": row["subject_id"],
                "pending_id": row["pending_id"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

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

    # -- tamper-evident audit chain ----------------------------------------

    def _chain_decision(self, pending_id: int, *, at: str) -> None:
        """Append the hold's decision columns to the chain, read back by name.

        ONE HELPER, CALLED BY EVERY WRITER of those columns after its UPDATE
        commits — ``resolve_pending_action``, ``invalidate_pending_action``,
        ``mark_state_moved``. The receipt is the row AS STORED, projected
        through the same ``DecisionRecord`` a verifier projects it through,
        so it is total over what those writers can change and equal to what a
        later reader will see. Three writers each spelling their own payload
        would be three chances for a column to reach one and miss another.
        """

        row = self.pending_action(pending_id)
        if row is None:
            raise StateError(
                f"pending action {pending_id} vanished before its decision "
                "could be chained"
            )
        self.record_chained(
            event=DECISION_EVENT,
            subject=decision_subject(pending_id),
            payload=project_decision(row),
            created_at=at,
        )

    def record_chained(
        self, *, event: str, subject: str, payload: dict, created_at: str
    ) -> int:
        """Append one decision to the hash chain and return its seq.

        Append-only in fact: the entry chains onto the CURRENT tip. The caller
        cannot supply ``prev_hash`` — the ledger reads the real tip itself — so a
        forged-prior-hash append is rejected by construction. Any later
        retroactive edit is caught by :meth:`verify_chain`.
        """

        payload_canonical = canonical_json(payload)
        # The tip read + insert is a read-modify-write, so a concurrent appender
        # on another connection could take the same seq; the UNIQUE(seq) column
        # then raises IntegrityError on the loser. Retry: re-read the (now newer)
        # tip and append the next contiguous seq, so the chain stays unbroken and
        # no raw sqlite error escapes. Bounded, then a clean StateError.
        for _attempt in range(16):
            row = self._conn.execute(
                "SELECT seq, entry_hash FROM audit_chain ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev_seq = row["seq"] if row is not None else 0
            prev_hash = row["entry_hash"] if row is not None else GENESIS_ROOT
            seq = prev_seq + 1
            digest = entry_hash(
                seq=seq,
                created_at=created_at,
                event=event,
                subject=subject,
                payload_canonical=payload_canonical,
                prev_hash=prev_hash,
            )
            try:
                self._conn.execute(
                    "INSERT INTO audit_chain (seq, created_at, event, subject, "
                    "payload, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        seq,
                        created_at,
                        event,
                        subject,
                        payload_canonical,
                        prev_hash,
                        digest,
                    ),
                )
                self._conn.commit()
                # Anchor AFTER the commit, so the anchored tip never names an
                # entry the ledger does not have. The reverse order would make a
                # crash between the two look like truncation; this order makes it
                # read as one honest, un-anchored extra entry.
                #
                # A failure here is NOT swallowed: the entry is committed, but an
                # un-anchored append is one a genesis rewrite could later hide, so
                # the caller must know the anchor is behind rather than discover
                # it during an incident. The chokepoint runner treats any
                # exception from this call as a failed append — a pre-execution
                # append that fails is a hard refusal (fail closed, DB untouched).
                if self._tip_anchor is not None:
                    self._tip_anchor.write(ChainTip(seq=seq, entry_hash=digest))
                return seq
            except sqlite3.IntegrityError:
                self._conn.rollback()  # another writer took this seq; re-read and retry
        raise StateError(
            "could not append to the audit chain: repeated seq collisions under "
            "concurrent writers"
        )

    def chained_events(self) -> list[dict]:
        """Every chain entry in insertion (id) order — the order verify walks."""

        rows = self._conn.execute("SELECT * FROM audit_chain ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def chain_tip(self) -> ChainTip | None:
        """The current tip, to be held out-of-band as a truncation anchor."""

        row = self._conn.execute(
            "SELECT seq, entry_hash FROM audit_chain ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return ChainTip(seq=row["seq"], entry_hash=row["entry_hash"]) if row else None

    @property
    def tip_anchor(self) -> TipAnchor | None:
        """The configured anchor target, if any — for the CLI and auditors."""

        return self._tip_anchor

    def verify_chain(
        self,
        *,
        expected_tip: ChainTip | None = None,
        expected_tips: list[ChainTip] | None = None,
    ) -> ChainVerification:
        """Walk and verify the audit chain (delegates to the standalone auditor).

        When this ledger was opened with a ``tip_anchor`` and no explicit tip is
        supplied, the anchor's whole history is used — so anchoring is
        *operational* rather than merely available, an auditor cannot silently
        verify without it, and every record the target holds is pinned, not just
        the newest (an append-only target's value is that history).

        Never returns ``VALID`` for a chain it could not actually check: a
        configured anchor that cannot be read, or a ledger whose rows cannot be
        loaded, is ``NOT_VERIFIABLE``. Couldn't-verify is not verified-clean.
        """

        if (
            expected_tip is None
            and expected_tips is None
            and self._tip_anchor is not None
        ):
            try:
                expected_tips = anchor_history(self._tip_anchor)
            except AnchorUnavailable as exc:
                return ChainVerification(
                    NOT_VERIFIABLE,
                    0,
                    None,
                    f"the configured tip anchor could not be read: {exc}",
                )
        try:
            rows = self.chained_events()
        except sqlite3.DatabaseError as exc:
            return ChainVerification(
                NOT_VERIFIABLE,
                0,
                None,
                f"the audit chain could not be read: {exc}",
            )
        return verify_rows(rows, expected_tip=expected_tip, expected_tips=expected_tips)

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
        if record.get("authorization"):
            record["authorization"] = json.loads(record["authorization"])
        return record

    @staticmethod
    def _execution_row(row: sqlite3.Row) -> dict:
        record = dict(row)
        record["executed"] = bool(record["executed"])
        record["refused"] = bool(record["refused"])
        if record.get("authoritative") is not None:
            record["authoritative"] = bool(record["authoritative"])
        if record.get("unavailable") is not None:
            record["unavailable"] = bool(record["unavailable"])
        # Three-valued on purpose: NULL stays None (no executor invoked), and
        # only a stored 0/1 becomes a bool. Coercing NULL to False would make
        # "nothing ran" and "isolation failed to start" the same bytes.
        for signal in ("started_ok", "candidate_started"):
            if record.get(signal) is not None:
                record[signal] = bool(record[signal])
        if record.get("judgment"):
            record["judgment"] = _load_json(record["judgment"])
        if record.get("authorization"):
            record["authorization"] = _load_json(record["authorization"])
        return record


def verify_ledger_file(
    path: Path | str,
    *,
    tip_anchor: TipAnchor | None = None,
    expected_tips: list[ChainTip] | None = None,
) -> ChainVerification:
    """Verify a ledger on disk and ALWAYS return a verdict, never raise.

    The auditor-facing entry point. :class:`SqliteLedger` raises
    :class:`StateError` when a file cannot be opened at all — correct fail-closed
    behaviour, and never a false ``VALID`` — but an auditor sweeping a set of
    ledgers wants one uniform answer per file. A file that is missing, is not a
    database, is truncated, or cannot be read comes back ``NOT_VERIFIABLE`` with
    the reason attached.

    Note the case an anchor exists for: a ledger file the adversary DELETED is
    recreated empty by SQLite, and an empty chain is internally consistent. With
    no anchor that reads as ``valid (0 entries)``; with one it is ``TRUNCATED``.
    Deletion is the cheapest attack on a ledger, and the anchor is what turns it
    from invisible into loud.
    """

    location = Path(os.fspath(path))
    if not location.exists():
        return ChainVerification(
            NOT_VERIFIABLE,
            0,
            None,
            f"no ledger file at {location}",
        )
    try:
        ledger = SqliteLedger(location, tip_anchor=tip_anchor)
    except (StateError, sqlite3.DatabaseError, OSError) as exc:
        return ChainVerification(
            NOT_VERIFIABLE,
            0,
            None,
            f"the ledger could not be opened: {exc}",
        )
    try:
        return ledger.verify_chain(expected_tips=expected_tips)
    finally:
        ledger.close()
