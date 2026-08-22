"""Live end-to-end: the brokered runner applies a real migration to a real
PostgreSQL, exactly once, and refuses a replay against the live DB.

Gated on a configured database (``PROM_CHOKEPOINT_PG_DSN`` component env vars).
Without one it SKIPS locally, but under ``PROM_REQUIRE_PG=1`` (set in a CI that
provisions a DB) an absent DB FAILS — so this is never a silently-skipped guard.
"""

from __future__ import annotations

import dataclasses
import json
import os
import time
from pathlib import Path

import psycopg
import pytest

from prometheus_protocol.chokepoint import (
    AUDIT_OUTCOME_UNAVAILABLE,
    RECEIPT_COMMITTED,
    RECEIPT_NOT_FOUND,
    RECONCILED_COMMITTED,
    RECONCILED_NOT_COMMITTED,
    REPLAY,
    ApprovalAuthority,
    BrokeredMigrationRunner,
    ConsumedApprovals,
    DbTarget,
    MigrationArtifact,
    postgres_executor,
)
from prometheus_protocol.core.models import Judgment, Verdict
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger

_REQUIRE = (os.environ.get("PROM_REQUIRE_PG", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}


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
    return target


def _connect(target: DbTarget):
    return psycopg.connect(
        host=target.host,
        port=target.port,
        dbname=target.dbname,
        user=target.user,
        password=target.password,
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
        return cursor.fetchone()


def _delete_receipt(target: DbTarget, execution_id: str | None) -> None:
    if execution_id is None:
        return
    with _connect(target) as connection, connection.cursor() as cursor:
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
        judgment, artifact=artifact, target=target.identity, now=time.time()
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
