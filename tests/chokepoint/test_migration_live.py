"""Live end-to-end: the brokered runner applies a real migration to a real
PostgreSQL, exactly once, and refuses a replay against the live DB.

Gated on a configured database (``PROM_CHOKEPOINT_PG_DSN`` component env vars).
Without one it SKIPS locally, but under ``PROM_REQUIRE_PG=1`` (set in a CI that
provisions a DB) an absent DB FAILS — so this is never a silently-skipped guard.
"""

from __future__ import annotations

import dataclasses
import json
import multiprocessing
import os
import signal
import time
import uuid
from pathlib import Path

import psycopg
import pytest
from _pg_fault_proxy import DropCommitResponse

from prometheus_protocol.core.booleans import parse_env_bool
from prometheus_protocol.chokepoint import (
    AUDIT_OUTCOME_UNAVAILABLE,
    EXECUTION_BUSY,
    EXECUTION_COMMITTED,
    EXECUTION_NOT_ATTEMPTED,
    EXECUTION_UNKNOWN,
    RECEIPT_COMMITTED,
    RECEIPT_IN_PROGRESS,
    RECEIPT_NOT_FOUND,
    RECEIPT_UNAVAILABLE,
    RECONCILED_COMMITTED,
    RECONCILED_NOT_COMMITTED,
    RECONCILIATION_REQUIRED,
    REPLAY,
    ApprovalAuthority,
    BrokeredMigrationRunner,
    ConsumedApprovals,
    DbTarget,
    MigrationArtifact,
    ReceiptStatus,
    postgres_executor,
    postgres_receipt_lookup,
)
from prometheus_protocol.chokepoint.admission import ExecutionDeadline
from prometheus_protocol.chokepoint.runner import _receipt_text
from prometheus_protocol.core.models import Judgment, Verdict
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger

from tests.support.assessments import for_migration

_REQUIRE = parse_env_bool("PROM_REQUIRE_PG", os.environ.get("PROM_REQUIRE_PG"), default=False)


def _target_from_env() -> DbTarget | None:
    host = os.environ.get("PROM_CHOKEPOINT_PG_HOST")
    if not host:
        return None
    return DbTarget(
        host=host,
        port=int(os.environ.get("PROM_CHOKEPOINT_PG_PORT", "5432")),
        dbname=os.environ.get("PROM_CHOKEPOINT_PG_DB", "appdb"),
        user=os.environ.get("PROM_CHOKEPOINT_PG_USER", "migrator"),
        password=os.environ.get("PROM_CHOKEPOINT_PG_PASSWORD", ""),
        schema=os.environ.get("PROM_CHOKEPOINT_PG_SCHEMA", "public"),
    )


def _require_db() -> DbTarget:
    target = _target_from_env()
    if target is None:
        if _REQUIRE:
            pytest.fail("PROM_REQUIRE_PG=1 but PROM_CHOKEPOINT_PG_HOST is unset")
        pytest.skip("no configured PostgreSQL (set PROM_CHOKEPOINT_PG_HOST)")
    # pytest.fail/skip are NoReturn, so this is unreachable — but only a checker
    # that follows that through both branches knows it, and mypy 1.11 (the
    # declared floor) does not. Stating it costs nothing and makes the promise in
    # the signature true for every checker in the supported range.
    assert target is not None
    return target


def _connect(target: DbTarget):
    return psycopg.connect(
        host=target.host,
        port=target.port,
        dbname=target.dbname,
        user=target.user,
        password=target.resolve_password(),
        connect_timeout=10,
    )


def _scalar(target: DbTarget, query: str):
    with _connect(target) as connection, connection.cursor() as cursor:
        cursor.execute(query)
        row = cursor.fetchone()
    assert row is not None
    return row[0]


def _execute(target: DbTarget, query: str) -> None:
    with _connect(target) as connection, connection.cursor() as cursor:
        cursor.execute(query)


def _receipt_row(target: DbTarget, execution_id: str):
    """The receipt row, with its text columns normalized to ``str``.

    A driver may return a ``text`` column as ``str`` or as ``bytes``; comparing
    ``bytes`` to ``str`` is silently always-unequal, so these assertions would
    pass or fail on the local driver's whim rather than on the receipt's content.
    Normalizing here (the same rule the runner applies) makes the live checks
    representation-independent. The driver-agnostic unit proof of that rule is
    ``test_receipt_text_normalization.py``.
    """

    with _connect(target) as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT pg_catalog.to_regclass("
            "'promethyn_internal.migration_receipts')"
        )
        relation = cursor.fetchone()
        if relation is None or relation[0] is None:
            return None
        cursor.execute(
            "SELECT artifact_sha256, target_canonical, committed_at "
            "FROM promethyn_internal.migration_receipts "
            "WHERE execution_id = %s",
            (execution_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return (_receipt_text(row[0]), _receipt_text(row[1]), row[2])


def _delete_receipt(target: DbTarget, execution_id: str | None) -> None:
    if execution_id is None:
        return
    with _connect(target) as connection, connection.cursor() as cursor:
        cursor.execute("SELECT to_regclass('promethyn_internal.migration_receipts')")
        relation = cursor.fetchone()
        if relation is None or relation[0] is None:
            return
        cursor.execute(
            "DELETE FROM promethyn_internal.migration_receipts "
            "WHERE execution_id = %s",
            (execution_id,),
        )


class _FailOutcomeAudit:
    def __init__(self, ledger: SqliteLedger) -> None:
        self.ledger = ledger

    def record_chained(self, **event):
        if event["event"] == "execute_outcome":
            raise OSError("simulated termination before outcome audit")
        return self.ledger.record_chained(**event)

    def chained_events(self):
        return self.ledger.chained_events()

    def verify_chain(self):
        return self.ledger.verify_chain()


def _runner_and_approval(target: DbTarget, store_path, sql: str):
    authority = ApprovalAuthority()
    artifact = MigrationArtifact(sql)
    audit = SqliteLedger(Path(f"{store_path}.audit"))
    runner = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=ConsumedApprovals(store_path),
        executor=postgres_executor,
        audit=audit,
        clock=time.time,
    )
    judgment = Judgment(
        verdict=Verdict.PASS,
        confidence=1.0,
        authoritative=True,
        contributing=("hard-check",),
    )
    approval = authority.authorize(
        for_migration(judgment, artifact=artifact, target=target.identity),
        artifact=artifact, target=target.identity, now=time.time()
    )
    assert approval is not None
    return runner, artifact, approval, audit


def test_live_end_to_end_and_replay_refused(tmp_path):
    target = _require_db()
    # A uniquely-named table so the run is observable and the suite is re-runnable.
    tbl = f"chokepoint_probe_{int(time.time()*1000)}"
    runner, artifact, approval, audit = _runner_and_approval(
        target, tmp_path / "consumed.db", f"CREATE TABLE {tbl} (id int);"
    )

    try:
        # Legitimate path: the table does not exist yet, then does.
        assert _scalar(target, f"SELECT to_regclass('{tbl}') IS NULL") is True
        first = runner.execute(approval=approval, artifact=artifact)
        assert first.executed and not first.refused, first.detail
        assert _scalar(target, f"SELECT to_regclass('{tbl}') IS NOT NULL") is True

        # Replay the SAME approval: refused, and the DB is not touched again
        # (a second CREATE of the same table would ERROR — proof it never ran).
        second = runner.execute(approval=approval, artifact=artifact)
        assert second.refused and second.reason == REPLAY, second.detail
        assert _scalar(
            target, f"SELECT count(*) FROM pg_tables WHERE tablename='{tbl}'"
        ) == 1
    finally:
        _execute(target, f"DROP TABLE IF EXISTS {tbl}")
        runner.close()
        audit.close()


def test_live_executor_uses_exact_bound_schema(tmp_path):
    target = _require_db()
    suffix = int(time.time() * 1_000_000)
    schema = f"bound_schema_{suffix}"
    table = f"schema_probe_{suffix}"
    _execute(target, f"CREATE SCHEMA {schema}")
    bound_target = dataclasses.replace(target, schema=schema)
    runner, artifact, approval, audit = _runner_and_approval(
        bound_target,
        tmp_path / "schema.db",
        f"CREATE TABLE {table} (id int);",
    )

    try:
        result = runner.execute(approval=approval, artifact=artifact)
        assert result.executed, result.detail
        assert _scalar(
            target, f"SELECT to_regclass('{schema}.{table}') IS NOT NULL"
        ) is True
        assert _scalar(target, f"SELECT to_regclass('public.{table}') IS NULL") is True
    finally:
        _execute(target, f"DROP SCHEMA IF EXISTS {schema} CASCADE")
        runner.close()
        audit.close()


def test_live_executor_rolls_back_failed_migration(tmp_path):
    target = _require_db()
    table = f"rollback_probe_{int(time.time() * 1_000_000)}"
    runner, artifact, approval, audit = _runner_and_approval(
        target,
        tmp_path / "rollback.db",
        f"CREATE TABLE {table} (id int); SELECT 1 / 0;",
    )

    try:
        result = runner.execute(approval=approval, artifact=artifact)
        assert not result.executed and not result.refused
        assert result.reason == "migration_error"
        assert _scalar(target, f"SELECT to_regclass('{table}') IS NULL") is True
    finally:
        _execute(target, f"DROP TABLE IF EXISTS {table}")
        runner.close()
        audit.close()


def test_live_executor_does_not_interpret_psql_meta_commands(tmp_path):
    target = _require_db()
    table = f"meta_probe_{int(time.time() * 1_000_000)}"
    runner, artifact, approval, audit = _runner_and_approval(
        target,
        tmp_path / "meta.db",
        f"\\connect postgres\nCREATE TABLE {table} (id int);",
    )

    try:
        result = runner.execute(approval=approval, artifact=artifact)
        assert not result.executed and not result.refused
        assert result.reason == "migration_error"
        assert _scalar(target, f"SELECT to_regclass('{table}') IS NULL") is True
    finally:
        _execute(target, f"DROP TABLE IF EXISTS {table}")
        runner.close()
        audit.close()


def test_live_executor_rejects_transaction_control_before_migration(tmp_path):
    target = _require_db()
    table = f"transaction_escape_probe_{int(time.time() * 1_000_000)}"
    runner, artifact, approval, audit = _runner_and_approval(
        target,
        tmp_path / "transaction-escape.db",
        f"COMMIT; CREATE TABLE {table} (id int);",
    )

    try:
        result = runner.execute(approval=approval, artifact=artifact)
        assert not result.executed and result.reason == "migration_error"
        assert "transaction-control statements are forbidden" in result.detail
        assert result.execution_id is not None
        assert _receipt_row(target, result.execution_id) is None
        assert _scalar(target, f"SELECT to_regclass('{table}') IS NULL") is True
    finally:
        _execute(target, f"DROP TABLE IF EXISTS {table}")
        runner.close()
        audit.close()


def test_live_restart_reconciles_commit_from_transaction_receipt(tmp_path):
    target = _require_db()
    table = f"committed_receipt_probe_{int(time.time() * 1_000_000)}"
    audit_path = tmp_path / "committed-receipt-audit.db"
    consumed_path = tmp_path / "committed-receipt-consumed.db"
    ledger = SqliteLedger(audit_path)
    authority = ApprovalAuthority()
    artifact = MigrationArtifact(f"CREATE TABLE {table} (id int);")
    approval = authority.mint(
        artifact_sha256=artifact.sha256,
        target=target.identity,
        now=time.time(),
    )
    runner = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=ConsumedApprovals(consumed_path),
        executor=postgres_executor,
        audit=_FailOutcomeAudit(ledger),
        clock=time.time,
    )
    execution_id = None

    try:
        result = runner.execute(approval=approval, artifact=artifact)
        execution_id = result.execution_id
        assert result.executed and result.reason == AUDIT_OUTCOME_UNAVAILABLE
        assert execution_id is not None
        receipt = _receipt_row(target, execution_id)
        assert receipt is not None
        assert receipt[0] == artifact.sha256
        assert receipt[1] == target.identity.canonical
        assert _scalar(target, f"SELECT to_regclass('{table}') IS NOT NULL") is True
    finally:
        runner.close()
        ledger.close()

    reopened = SqliteLedger(audit_path)
    restarted = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=ConsumedApprovals(consumed_path),
        executor=postgres_executor,
        audit=reopened,
        clock=time.time,
    )
    try:
        report = restarted.reconcile_unfinished()
        assert len(report) == 1
        assert report[0].resolved and report[0].state == RECEIPT_COMMITTED
        outcome = reopened.chained_events()[-1]
        assert outcome["event"] == "execute_outcome"
        payload = json.loads(outcome["payload"])
        assert payload["reason"] == RECONCILED_COMMITTED
        assert payload["execution_id"] == execution_id
    finally:
        restarted.close()
        reopened.close()
        _execute(target, f"DROP TABLE IF EXISTS {table}")
        _delete_receipt(target, execution_id)


def test_live_restart_proves_failed_transaction_did_not_commit(tmp_path):
    target = _require_db()
    table = f"rolled_back_receipt_probe_{int(time.time() * 1_000_000)}"
    audit_path = tmp_path / "rolled-back-receipt-audit.db"
    consumed_path = tmp_path / "rolled-back-receipt-consumed.db"
    ledger = SqliteLedger(audit_path)
    authority = ApprovalAuthority()
    artifact = MigrationArtifact(
        f"CREATE TABLE {table} (id int); SELECT 1 / 0;"
    )
    approval = authority.mint(
        artifact_sha256=artifact.sha256,
        target=target.identity,
        now=time.time(),
    )
    runner = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=ConsumedApprovals(consumed_path),
        executor=postgres_executor,
        audit=_FailOutcomeAudit(ledger),
        clock=time.time,
    )
    execution_id = None

    try:
        result = runner.execute(approval=approval, artifact=artifact)
        execution_id = result.execution_id
        assert not result.executed and result.reason == AUDIT_OUTCOME_UNAVAILABLE
        assert execution_id is not None
        assert _receipt_row(target, execution_id) is None
        assert _scalar(target, f"SELECT to_regclass('{table}') IS NULL") is True
    finally:
        runner.close()
        ledger.close()

    reopened = SqliteLedger(audit_path)
    restarted = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=ConsumedApprovals(consumed_path),
        executor=postgres_executor,
        audit=reopened,
        clock=time.time,
    )
    try:
        report = restarted.reconcile_unfinished()
        assert len(report) == 1
        assert report[0].resolved and report[0].state == RECEIPT_NOT_FOUND
        outcome = reopened.chained_events()[-1]
        payload = json.loads(outcome["payload"])
        assert payload["reason"] == RECONCILED_NOT_COMMITTED
        assert payload["ok"] is False
    finally:
        restarted.close()
        reopened.close()
        _execute(target, f"DROP TABLE IF EXISTS {table}")


def test_live_lost_commit_response_remains_pending_until_receipt_recovery(tmp_path):
    target = _require_db()
    table = "lost_commit_" + uuid.uuid4().hex
    with DropCommitResponse(target) as proxy:
        bound = dataclasses.replace(target, host="127.0.0.1", port=proxy.port)
        store_path = tmp_path / "consumed.db"
        runner, artifact, approval, audit = _runner_and_approval(
            bound, store_path, f"CREATE TABLE {table} (id int); INSERT INTO {table} VALUES (1)"
        )
        authority = runner._authority
        execution_id = None
        restarted = None
        try:
            result = runner.execute(approval=approval, artifact=artifact)
            execution_id = result.execution_id
            assert proxy.dropped.wait(2), proxy.errors
            assert not proxy.errors
            assert result.reason == result.execution_state == EXECUTION_UNKNOWN
            assert not result.executed and not result.refused
            # The real PostgreSQL transaction committed, but its confirmation
            # never reached the production executor over the wire.
            assert _scalar(target, f"SELECT count(*) FROM {table}") == 1
            assert _receipt_row(target, execution_id) is not None
            assert [e["event"] for e in audit.chained_events()] == ["execute_intent", "execute_unknown"]
            runner.close()
            restarted = BrokeredMigrationRunner(
                authority=authority, target=bound, consumed=ConsumedApprovals(store_path),
                audit=audit, clock=time.time,
                receipt_lookup=lambda *a: ReceiptStatus(RECEIPT_UNAVAILABLE),
            )
            second_artifact = MigrationArtifact(f"INSERT INTO {table} VALUES (2)")
            second_approval = authority.mint(artifact_sha256=second_artifact.sha256,
                                             target=bound.identity, now=time.time())
            blocked = restarted.execute(approval=second_approval, artifact=second_artifact)
            assert blocked.reason == RECONCILIATION_REQUIRED
            assert _scalar(target, f"SELECT count(*) FROM {table}") == 1
            restarted._receipt_lookup = postgres_receipt_lookup
            report = restarted.reconcile_unfinished()
            assert len(report) == 1 and report[0].resolved and report[0].state == RECEIPT_COMMITTED
            assert restarted.execute(approval=approval, artifact=artifact).reason == REPLAY
            assert restarted.execute(approval=second_approval, artifact=second_artifact).executed
            assert _scalar(target, f"SELECT count(*) FROM {table}") == 2
        finally:
            runner.close()
            if restarted:
                restarted.close()
            audit.close()
            _execute(target, f"DROP TABLE IF EXISTS {table}")
            _delete_receipt(target, execution_id)


def _live_paused_owner(target, store_path, audit_path, approval, artifact, pipe, pause_after_intent):
    """Spawned runner using real PostgreSQL; pipe barriers carry no shared mutex."""
    ledger = SqliteLedger(audit_path)

    class Audit:
        def record_chained(self, **event):
            seq = ledger.record_chained(**event)
            if event["event"] == "execute_intent":
                pipe.send(event["payload"]["execution_id"])
                if pause_after_intent:
                    pipe.recv()
            return seq

        def chained_events(self):
            return ledger.chained_events()

        def verify_chain(self):
            return ledger.verify_chain()

    runner = BrokeredMigrationRunner(
        authority=ApprovalAuthority(key=b"live-recovery-authority-key-32-bytes"),
        target=target, consumed=ConsumedApprovals(store_path), audit=Audit(), clock=time.time,
    )
    try:
        pipe.send(runner.execute(approval=approval, artifact=artifact))
    finally:
        runner.close()
        ledger.close()
        pipe.close()


@pytest.mark.parametrize("terminate", [False, True])
def test_live_suspended_owner_cannot_be_declared_rolled_back(tmp_path, terminate):
    target = _require_db()
    table = "paused_owner_" + uuid.uuid4().hex
    authority = ApprovalAuthority(key=b"live-recovery-authority-key-32-bytes")
    artifact = MigrationArtifact(f"CREATE TABLE {table} (id int)")
    approval = authority.mint(artifact_sha256=artifact.sha256, target=target.identity, now=time.time())
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    store_path, audit_path = tmp_path / "store.db", tmp_path / "audit.db"
    process = context.Process(target=_live_paused_owner,
        args=(target, store_path, audit_path, approval, artifact, child, True))
    process.start()
    child.close()
    restarted = ledger = None
    execution_id = None
    stopped = False
    try:
        assert parent.poll(10), "runner did not publish intent"
        execution_id = parent.recv()
        os.kill(process.pid, signal.SIGSTOP)
        stopped = True
        ledger = SqliteLedger(audit_path)
        restarted = BrokeredMigrationRunner(authority=authority, target=target,
            consumed=ConsumedApprovals(store_path), audit=ledger, clock=time.time)
        report = restarted.reconcile_unfinished()
        assert len(report) == 1 and report[0].state == EXECUTION_BUSY and not report[0].resolved
        assert _scalar(target, f"SELECT to_regclass('{table}') IS NULL") is True
        assert not any(e["event"] == "execute_outcome" for e in ledger.chained_events())
        if terminate:
            process.kill()
            process.join(5)
            stopped = False
            report = restarted.reconcile_unfinished()
            assert len(report) == 1 and report[0].state == RECEIPT_NOT_FOUND and report[0].resolved
            assert restarted.execute(approval=approval, artifact=artifact).reason == REPLAY
        else:
            os.kill(process.pid, signal.SIGCONT)
            stopped = False
            parent.send("resume")
            assert parent.poll(15)
            assert parent.recv().executed
            process.join(5)
            assert process.exitcode == 0
            assert restarted.reconcile_unfinished() == ()
            assert _scalar(target, f"SELECT to_regclass('{table}') IS NOT NULL") is True
    finally:
        if stopped:
            os.kill(process.pid, signal.SIGCONT)
        if process.is_alive():
            process.kill()
        process.join(5)
        parent.close()
        if restarted:
            restarted.close()
        if ledger:
            ledger.close()
        _execute(target, f"DROP TABLE IF EXISTS {table}")
        _delete_receipt(target, execution_id)


def test_live_dead_client_with_active_transaction_stays_pending(tmp_path):
    target = _require_db()
    table = "active_owner_" + uuid.uuid4().hex
    authority = ApprovalAuthority(key=b"live-recovery-authority-key-32-bytes")
    artifact = MigrationArtifact(f"CREATE TABLE {table} (id int); SELECT pg_sleep(30)")
    approval = authority.mint(artifact_sha256=artifact.sha256, target=target.identity, now=time.time())
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    store_path, audit_path = tmp_path / "store.db", tmp_path / "audit.db"
    process = context.Process(target=_live_paused_owner,
        args=(target, store_path, audit_path, approval, artifact, child, False))
    process.start()
    child.close()
    restarted = ledger = None
    execution_id = backend_pid = None
    try:
        assert parent.poll(10)
        execution_id = parent.recv()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with _connect(target) as connection:
                row = connection.execute("SELECT pid FROM pg_stat_activity WHERE query = %s AND state='active'",
                                         (artifact.sql,)).fetchone()
            if row:
                backend_pid = row[0]
                break
            time.sleep(0.05)
        assert backend_pid is not None, "migration did not start in PostgreSQL"
        process.kill()
        process.join(5)
        ledger = SqliteLedger(audit_path)
        restarted = BrokeredMigrationRunner(authority=authority, target=target,
            consumed=ConsumedApprovals(store_path), audit=ledger, clock=time.time)
        report = restarted.reconcile_unfinished()
        assert len(report) == 1 and report[0].state == RECEIPT_IN_PROGRESS and not report[0].resolved
        with _connect(target) as connection:
            assert connection.execute("SELECT pg_terminate_backend(%s)", (backend_pid,)).fetchone()[0]
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            report = restarted.reconcile_unfinished()
            if report[0].resolved:
                break
            time.sleep(0.05)
        assert report[0].resolved and report[0].state == RECEIPT_NOT_FOUND
        assert _scalar(target, f"SELECT to_regclass('{table}') IS NULL") is True
    finally:
        if process.is_alive():
            process.kill()
        process.join(5)
        parent.close()
        if backend_pid is not None:
            with _connect(target) as connection:
                connection.execute("SELECT pg_terminate_backend(%s)", (backend_pid,))
        if restarted:
            restarted.close()
        if ledger:
            ledger.close()
        _execute(target, f"DROP TABLE IF EXISTS {table}")
        _delete_receipt(target, execution_id)


# ===========================================================================
# F7 boundary 2 — against a REAL PostgreSQL, not an injected driver
# ===========================================================================


def test_live_an_expired_approval_makes_no_privileged_database_contact(tmp_path):
    """POLICY (1), RULED: no privileged database contact after expiry.

    The unit tests for boundary 2a inject a fake driver. This one runs the real
    ``postgres_executor`` against the real server with a deadline that has
    already passed, and proves what the policy actually claims: no credential is
    resolved, no connection is opened, no lock is taken, no bootstrap DDL is
    written and no migration statement is sent.

    It FAILS rather than skips wherever PROM_REQUIRE_PG is set — ``_require_db``
    enforces that — because a security proof that skips is a void guard.
    """

    target = _require_db()
    resolved: list[str] = []

    class _Watched(DbTarget):
        def resolve_password(self) -> str:
            resolved.append("password")
            return super().resolve_password()

    watched = _Watched(
        target.host, target.port, target.dbname, target.user,
        target.password, schema=target.schema,
    )

    # A deadline that expired a minute ago, on the real clock.
    deadline = ExecutionDeadline.open(
        issued_at=time.time() - 120.0,
        expires_at=time.time() - 60.0,
        clock=time.time,
        uncertainty_s=0.0,
    )
    assert deadline.admit().admitted is False

    table = f"f7_must_not_exist_{int(time.time() * 1000)}"
    result = postgres_executor(
        f"CREATE TABLE {table} (id int);",
        watched,
        "a" * 64,
        "b" * 64,
        deadline=deadline,
    )

    assert result.state == EXECUTION_NOT_ATTEMPTED, result
    assert resolved == [], "a credential was resolved for an expired approval"

    # And the server agrees: the table does not exist.
    import psycopg

    with psycopg.connect(
        host=target.host, port=target.port, dbname=target.dbname,
        user=target.user, password=target.resolve_password(), connect_timeout=10,
    ) as connection, connection.cursor() as cursor:
        cursor.execute("SELECT pg_catalog.to_regclass(%s)", (table,))
        assert cursor.fetchone()[0] is None, "the migration ran after expiry"


def test_live_a_current_approval_still_executes(tmp_path):
    """The positive control for the test above: an executor that refused
    everything would pass it vacuously."""

    target = _require_db()
    table = f"f7_control_{int(time.time() * 1000)}"
    deadline = ExecutionDeadline.open(
        issued_at=time.time(),
        expires_at=time.time() + 90.0,
        clock=time.time,
    )
    result = postgres_executor(
        f"CREATE TABLE {table} (id int);", target, "c" * 64, "d" * 64,
        deadline=deadline,
    )
    assert result.state == EXECUTION_COMMITTED, result

    import psycopg

    with psycopg.connect(
        host=target.host, port=target.port, dbname=target.dbname,
        user=target.user, password=target.resolve_password(), connect_timeout=10,
    ) as connection, connection.cursor() as cursor:
        cursor.execute("SELECT pg_catalog.to_regclass(%s)", (table,))
        assert cursor.fetchone()[0] is not None
        cursor.execute(f"DROP TABLE {table}")
        connection.commit()
