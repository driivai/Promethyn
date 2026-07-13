"""Audit observability: judgment columns, migration/backfill, and audit queries.

Additive observability over the existing chain — it records the same values into
queryable columns and reads them back. Nothing here changes what is decided or
executed (that parity is covered by the execution/bank/gate suites); these tests
cover the columns, the idempotent backfill, and the query correctness.
"""

from __future__ import annotations

import sqlite3

from prometheus_protocol.core.models import Attempt, Evidence, Judgment, Verdict
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.pending import _judgment_to_dict
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.core.models import ExecutableAction
from prometheus_protocol.swarm.executor import RecordingExecutor


def _attempt(judgment: Judgment | None) -> Attempt:
    return Attempt(
        task_id="t", split="train", entry_point="f", code="x",
        evidence=Evidence(passed=True, total=1, passed_count=1),
        judgment=judgment,
    )


def _exec(ledger: SqliteLedger, subject: str, *, executed: bool, judgment: dict) -> None:
    ledger.record_execution(
        subject_id=subject, source="auto-approved", executed=executed, refused=False,
        sandbox_name="namespace", exit_status=0 if executed else None, detail="",
        created_at="t", judgment=judgment,
    )


def _old_schema_db(path: str) -> None:
    """Create a ledger with the pre-observability schema (no judgment columns)."""

    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, cycle INTEGER, kind TEXT,
            task_id TEXT, split TEXT, entry_point TEXT, passed INTEGER, total INTEGER,
            passed_count INTEGER, skills_used TEXT, code TEXT, evidence TEXT);
        CREATE TABLE promotions (id INTEGER PRIMARY KEY, cycle INTEGER);
        CREATE TABLE pending_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, subject_id TEXT, risk_class TEXT,
            reason TEXT, verdict TEXT, confidence REAL, status TEXT, action TEXT,
            judgment TEXT, created_at TEXT, decided_by TEXT, decided_at TEXT,
            decision_reason TEXT);
        CREATE TABLE executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, subject_id TEXT, source TEXT,
            executed INTEGER, refused INTEGER, sandbox TEXT, exit_status INTEGER,
            detail TEXT, created_at TEXT);
        """
    )
    conn.commit()
    conn.close()


# -- column / JSON consistency (cannot diverge) -----------------------------


def test_attempt_columns_equal_the_evidence_json():
    ledger = SqliteLedger(":memory:")
    try:
        ledger.record_attempt(
            _attempt(Judgment(Verdict.PASS, 0.83, authoritative=True)), cycle=1, kind="k"
        )
        row = ledger.attempts()[0]
        assert row["verdict"] == row["evidence"]["judgment"]["verdict"] == "pass"
        assert row["confidence"] == row["evidence"]["judgment"]["confidence"] == 0.83
    finally:
        ledger.close()


def test_execution_columns_equal_the_judgment_json():
    ledger = SqliteLedger(":memory:")
    try:
        judgment = {"verdict": "pass", "confidence": 0.42, "authoritative": True}
        _exec(ledger, "s", executed=True, judgment=judgment)
        row = ledger.executions()[0]
        assert row["verdict"] == row["judgment"]["verdict"] == "pass"
        assert row["confidence"] == row["judgment"]["confidence"] == 0.42
        assert row["authoritative"] is True and row["judgment"]["authoritative"] is True
    finally:
        ledger.close()


def test_attempt_without_judgment_leaves_columns_null():
    ledger = SqliteLedger(":memory:")
    try:
        ledger.record_attempt(_attempt(None), cycle=1, kind="k")
        row = ledger.attempts()[0]
        assert row["verdict"] is None and row["confidence"] is None
    finally:
        ledger.close()


def test_unavailable_execution_is_forever_distinct_from_an_abstain():
    ledger = SqliteLedger(":memory:")
    try:
        # A could-not-EXECUTE row: the controller records source "unavailable"
        # with no judgment (there is no verdict to authorize on).
        ledger.record_execution(
            subject_id="s1", source="unavailable", executed=False, refused=True,
            sandbox_name="", exit_status=None, detail="sandbox did not start",
            created_at="t", judgment=None,
        )
        # A genuine policy block whose fused judgment ABSTAINed.
        ledger.record_execution(
            subject_id="s2", source="blocked", executed=False, refused=False,
            sandbox_name="", exit_status=None, detail="blocked",
            created_at="t",
            judgment={"verdict": "abstain", "confidence": 0.5, "authoritative": False},
        )
        rows = {r["subject_id"]: r for r in ledger.executions()}
        # The infra/policy unavailability is marked and carries no verdict; the
        # abstention is NOT unavailable and records verdict="abstain". These used
        # to be indistinguishable — the exact separation EX-1 exists to make.
        assert rows["s1"]["unavailable"] is True
        assert rows["s1"]["verdict"] is None
        assert rows["s2"]["unavailable"] is False
        assert rows["s2"]["verdict"] == "abstain"
    finally:
        ledger.close()


def test_confidence_and_verdict_columns_are_indexed():
    ledger = SqliteLedger(":memory:")
    try:
        names = {
            r[0] for r in ledger._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }
        assert {
            "idx_attempts_confidence", "idx_attempts_verdict",
            "idx_executions_confidence", "idx_executions_verdict",
        } <= names
    finally:
        ledger.close()


# -- controller populates the column (end to end) ---------------------------


def test_controller_execution_is_queryable_by_confidence():
    ledger = SqliteLedger(":memory:")
    controller = ExecutionController(
        gate=ActionGate(escalate_below=0.0, route_high_risk=False),  # no routing: auto-exec
        executor=RecordingExecutor(), ledger=ledger, clock=lambda: "t",
    )
    controller.submit(
        judgment=Judgment(Verdict.PASS, 0.44, authoritative=True),
        action=ExecutableAction(kind="python_code", code="print(1)"),
        subject_id="live",
    )
    below = ledger.executions_below_confidence(0.5)
    assert [r["subject_id"] for r in below] == ["live"]
    assert below[0]["confidence"] == 0.44


# -- migration / backfill ---------------------------------------------------


def test_opening_an_old_ledger_adds_the_columns(tmp_path):
    db = str(tmp_path / "old.db")
    _old_schema_db(db)
    ledger = SqliteLedger(db)
    try:
        assert set(ledger.migration_added_columns) == {
            "attempts.verdict", "attempts.confidence",
            "executions.verdict", "executions.confidence",
            "executions.authoritative", "executions.judgment",
            "executions.pending_id",
            # EX-1: the could-not-EXECUTE discriminator, added additively to old
            # ledgers so an infra/policy unavailability is forever separable from
            # a genuine abstention.
            "executions.unavailable",
            "pending_actions.execution_committed_at",
        }
        cols = {r["name"] for r in ledger._conn.execute("PRAGMA table_info(attempts)")}
        assert {"verdict", "confidence"} <= cols
        exec_cols = {r["name"] for r in ledger._conn.execute("PRAGMA table_info(executions)")}
        assert "unavailable" in exec_cols
    finally:
        ledger.close()


def test_backfill_fills_historical_rows_and_is_idempotent(tmp_path):
    import json

    db = str(tmp_path / "old.db")
    _old_schema_db(db)
    conn = sqlite3.connect(db)
    good = json.dumps({"total": 1, "judgment": {"verdict": "pass", "confidence": 0.55}})
    conn.execute(
        "INSERT INTO attempts (cycle,kind,task_id,split,entry_point,passed,total,"
        "passed_count,skills_used,code,evidence) VALUES (0,'k','t','train','f',1,1,1,'[]','',?)",
        (good,),
    )
    conn.commit()
    conn.close()

    ledger = SqliteLedger(db)
    try:
        report = ledger.backfill()
        assert report["attempts"] == {"filled": 1, "skipped": 0}
        assert ledger.attempts()[0]["confidence"] == 0.55
        # idempotent: a second run touches nothing
        assert ledger.backfill()["attempts"] == {"filled": 0, "skipped": 0}
    finally:
        ledger.close()


def test_backfill_leaves_malformed_or_missing_json_null_and_counts(tmp_path):
    import json

    db = str(tmp_path / "old.db")
    _old_schema_db(db)
    conn = sqlite3.connect(db)
    ins = (
        "INSERT INTO attempts (cycle,kind,task_id,split,entry_point,passed,total,"
        "passed_count,skills_used,code,evidence) VALUES (0,'k','t','train','f',1,1,1,'[]','',?)"
    )
    conn.execute(ins, ("{malformed json",))                 # unparseable -> skip
    conn.execute(ins, (json.dumps({"total": 1}),))          # valid, no judgment -> skip
    conn.commit()
    conn.close()

    ledger = SqliteLedger(db)
    try:
        report = ledger.backfill()
        assert report["attempts"] == {"filled": 0, "skipped": 2}  # counted, not fatal
        rows = {r[0]: r[1] for r in ledger._conn.execute("SELECT id, verdict FROM attempts")}
        assert rows[1] is None and rows[2] is None  # left NULL
    finally:
        ledger.close()


# -- query correctness ------------------------------------------------------


def _seed_executions(ledger: SqliteLedger) -> None:
    _exec(ledger, "hi", executed=True, judgment={"verdict": "pass", "confidence": 0.95, "authoritative": True})
    _exec(ledger, "lo", executed=True, judgment={"verdict": "pass", "confidence": 0.40, "authoritative": True})
    _exec(ledger, "lo-nonauth", executed=True, judgment={"verdict": "pass", "confidence": 0.30, "authoritative": False})
    _exec(ledger, "blocked", executed=False, judgment={"verdict": "fail", "confidence": 0.20, "authoritative": True})


def test_executions_below_confidence_returns_exactly_the_executed_low_rows():
    ledger = SqliteLedger(":memory:")
    try:
        _seed_executions(ledger)
        got = [r["subject_id"] for r in ledger.executions_below_confidence(0.5)]
        assert got == ["lo", "lo-nonauth"]           # executed & <0.5; not hi, not blocked
        # boundary: strictly less-than
        assert [r["subject_id"] for r in ledger.executions_below_confidence(0.40)] == ["lo-nonauth"]
        assert ledger.executions_below_confidence(0.30) == []
    finally:
        ledger.close()


def test_authoritative_pass_below_returns_only_authoritative_pass():
    ledger = SqliteLedger(":memory:")
    try:
        _seed_executions(ledger)
        got = [r["subject_id"] for r in ledger.authoritative_pass_below(0.5)]
        assert got == ["lo"]  # excludes lo-nonauth (non-authoritative) and blocked (not executed / FAIL)
    finally:
        ledger.close()


def test_human_decision_log_lists_resolved_holds():
    ledger = SqliteLedger(":memory:")
    try:
        for subject in ("p/keep", "p/approve", "p/expire"):
            ledger.record_pending_action(
                subject_id=subject, risk_class="low", reason="r", verdict="pass",
                confidence=0.6, action={"kind": "python_code", "code": "x", "entry_point": ""},
                judgment={"verdict": "pass", "confidence": 0.6, "authoritative": True},
                created_at="t0",
            )
        ledger.resolve_pending_action(2, status="approved", decided_by="will@driivai.com", decided_at="t1", decision_reason="ok")
        ledger.resolve_pending_action(3, status="expired", decided_by="system:sweep", decided_at="t2", decision_reason="expired after 1s TTL")
        log = ledger.human_decisions()
        assert [(r["id"], r["status"], r["decided_by"]) for r in log] == [
            (2, "approved", "will@driivai.com"),
            (3, "expired", "system:sweep"),
        ]  # the still-pending p/keep is not in the log
    finally:
        ledger.close()


# -- read-only --------------------------------------------------------------


def test_audit_queries_mutate_no_state():
    ledger = SqliteLedger(":memory:")
    try:
        _seed_executions(ledger)
        ledger.record_pending_action(
            subject_id="p", risk_class="low", reason="r", verdict="pass", confidence=0.6,
            action={"kind": "python_code", "code": "x", "entry_point": ""},
            judgment={"verdict": "pass", "confidence": 0.6, "authoritative": True}, created_at="t0",
        )

        def snapshot():
            return {
                t: ledger._conn.execute(f"SELECT * FROM {t} ORDER BY id").fetchall()
                for t in ("attempts", "executions", "pending_actions", "promotions")
            }

        before = snapshot()
        ledger.executions_below_confidence(0.5)
        ledger.authoritative_pass_below(0.5)
        ledger.human_decisions()
        after = snapshot()
        assert before == after  # the audit queries changed nothing
    finally:
        ledger.close()
