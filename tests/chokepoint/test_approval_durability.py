"""Replay and target binding survive real lifecycle/concurrency boundaries."""

from __future__ import annotations

import multiprocessing
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from prometheus_protocol.chokepoint import (
    AUDIT_OUTCOME_UNAVAILABLE,
    AUDIT_UNAVAILABLE,
    RECEIPT_COMMITTED,
    RECEIPT_CONFLICT,
    RECEIPT_IN_PROGRESS,
    RECEIPT_NOT_FOUND,
    REPLAY,
    STORE_UNAVAILABLE,
    TARGET_MISMATCH,
    Approval,
    ApprovalAuthority,
    BrokeredMigrationRunner,
    ConsumedApprovals,
    DbTarget,
    MigrationArtifact,
    MigrationRunnerConfig,
    ReceiptStatus,
    build_migration_runtime,
    postgres_executor,
    postgres_receipt_lookup,
)

_KEY = b"durability-test-key-is-32-bytes!!"


class _SpyExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def __call__(
        self,
        sql: str,
        target: DbTarget,
        execution_id: str,
        artifact_sha256: str,
    ) -> tuple[bool, str]:
        self.calls.append((sql, target.user))
        return True, "ok"


class _Audit:
    def __init__(self, *, fail_on: str | None = None) -> None:
        self.events: list[dict[str, object]] = []
        self.fail_on = fail_on
        self._lock = threading.Lock()

    def record_chained(self, **event) -> int:
        with self._lock:
            if event["event"] == self.fail_on:
                raise OSError("audit unavailable")
            seq = len(self.events) + 1
            self.events.append({"seq": seq, **event})
            return seq

    def chained_events(self) -> list[dict[str, object]]:
        with self._lock:
            return list(self.events)

    def verify_chain(self):
        return type("Verification", (), {"ok": True})()


def _no_receipt(execution_id, artifact_sha256, target):
    return ReceiptStatus(RECEIPT_NOT_FOUND)


def _target(*, user: str = "migrator", schema: str = "public") -> DbTarget:
    return DbTarget(
        host="db.internal",
        port=5432,
        dbname="appdb",
        user=user,
        password="rotatable-secret",
        schema=schema,
    )


def _approval(
    authority: ApprovalAuthority, target: DbTarget
) -> tuple[MigrationArtifact, Approval]:
    artifact = MigrationArtifact("ALTER TABLE orders ADD COLUMN reviewed bool;")
    approval = authority.mint(
        artifact_sha256=artifact.sha256,
        target=target.identity,
        now=1_000.0,
    )
    return artifact, approval


def _process_execute(
    path: str,
    approval: Approval,
    artifact: MigrationArtifact,
    target: DbTarget,
    start,
    results,
) -> None:
    """Spawn-safe worker: each process owns its connection to the same store."""

    store = ConsumedApprovals(path)
    try:
        runner = BrokeredMigrationRunner(
            authority=ApprovalAuthority(key=_KEY),
            target=target,
            consumed=store,
            executor=lambda sql, bound, execution_id, artifact_sha256: (True, "ok"),
            receipt_lookup=_no_receipt,
            audit=_Audit(),
            clock=lambda: 1_001.0,
        )
        start.wait(timeout=10)
        result = runner.execute(approval=approval, artifact=artifact)
        results.put((result.executed, result.refused, result.reason))
    finally:
        store.close()


def test_store_requires_a_durable_path():
    with pytest.raises(TypeError):
        ConsumedApprovals()  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="durable filesystem path"):
        ConsumedApprovals(":memory:")


def test_replay_is_refused_after_store_and_runner_restart(tmp_path):
    path = tmp_path / "consumed.db"
    authority = ApprovalAuthority(key=_KEY)
    target = _target()
    artifact, approval = _approval(authority, target)

    first_spy = _SpyExecutor()
    first_store = ConsumedApprovals(path)
    first_runner = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=first_store,
        executor=first_spy,
        receipt_lookup=_no_receipt,
        audit=_Audit(),
        clock=lambda: 1_001.0,
    )
    assert first_runner.execute(approval=approval, artifact=artifact).executed
    first_store.close()

    # New connection and new runner simulate a process/service restart while the
    # signed capability is still inside its validity window.
    second_spy = _SpyExecutor()
    second_store = ConsumedApprovals(path)
    try:
        second_runner = BrokeredMigrationRunner(
            authority=authority,
            target=target,
            consumed=second_store,
            executor=second_spy,
            receipt_lookup=_no_receipt,
            audit=_Audit(),
            clock=lambda: 1_002.0,
        )
        replay = second_runner.execute(approval=approval, artifact=artifact)
        assert replay.refused and replay.reason == REPLAY
        assert second_spy.calls == []
    finally:
        second_store.close()


def test_one_shared_store_serializes_thread_race(tmp_path):
    authority = ApprovalAuthority(key=_KEY)
    target = _target()
    artifact, approval = _approval(authority, target)
    spy = _SpyExecutor()
    store = ConsumedApprovals(tmp_path / "consumed.db")
    runner = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=store,
        executor=spy,
        receipt_lookup=_no_receipt,
        audit=_Audit(),
        clock=lambda: 1_001.0,
    )
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    lambda _: runner.execute(approval=approval, artifact=artifact),
                    range(2),
                )
            )
        assert sum(result.executed for result in results) == 1
        assert (
            sum(result.refused and result.reason == REPLAY for result in results) == 1
        )
        assert spy.calls == [(artifact.sql, target.user)]
    finally:
        store.close()


def test_independent_processes_cannot_both_spend_approval(tmp_path):
    path = str(tmp_path / "consumed.db")
    # Create the schema before racing independent connections against it.
    ConsumedApprovals(path).close()
    authority = ApprovalAuthority(key=_KEY)
    target = _target()
    artifact, approval = _approval(authority, target)

    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(
            target=_process_execute,
            args=(path, approval, artifact, target, start, results),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    start.set()
    outcomes = [results.get(timeout=15) for _ in processes]
    for process in processes:
        process.join(timeout=15)
        assert process.exitcode == 0

    assert sum(executed for executed, _, _ in outcomes) == 1
    assert sum(refused and reason == REPLAY for _, refused, reason in outcomes) == 1


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork is unavailable")
def test_inherited_store_reconnects_after_fork(tmp_path):
    authority = ApprovalAuthority(key=_KEY)
    target = _target()
    artifact, approval = _approval(authority, target)
    store = ConsumedApprovals(tmp_path / "fork.db")
    runner = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=store,
        executor=lambda sql, bound, execution_id, artifact_sha256: (True, "ok"),
        receipt_lookup=_no_receipt,
        audit=_Audit(),
        clock=lambda: 1_001.0,
    )
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            result = runner.execute(approval=approval, artifact=artifact)
            os.write(write_fd, result.reason.encode("ascii"))
        finally:
            os.close(write_fd)
            store.close()
        os._exit(0)

    os.close(write_fd)
    try:
        child_reason = os.read(read_fd, 100).decode("ascii")
        _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 0
        assert child_reason == "ok"
        replay = runner.execute(approval=approval, artifact=artifact)
        assert replay.refused and replay.reason == REPLAY
    finally:
        os.close(read_fd)
        store.close()


@pytest.mark.parametrize(
    ("runner_target", "changed_boundary"),
    [
        (_target(user="database_owner"), "user"),
        (_target(schema="billing"), "schema"),
    ],
)
def test_privilege_or_schema_change_invalidates_approval(
    tmp_path, runner_target: DbTarget, changed_boundary: str
):
    authority = ApprovalAuthority(key=_KEY)
    approved_target = _target(user="migrator", schema="public")
    artifact, approval = _approval(authority, approved_target)
    spy = _SpyExecutor()
    store = ConsumedApprovals(tmp_path / f"{changed_boundary}.db")
    try:
        runner = BrokeredMigrationRunner(
            authority=authority,
            target=runner_target,
            consumed=store,
            executor=spy,
            receipt_lookup=_no_receipt,
            audit=_Audit(),
            clock=lambda: 1_001.0,
        )
        result = runner.execute(approval=approval, artifact=artifact)
        assert result.refused and result.reason == TARGET_MISMATCH
        assert spy.calls == []
    finally:
        store.close()


def test_target_identity_is_canonical_and_excludes_only_password():
    original = _target()
    rotated = DbTarget(
        host=original.host,
        port=original.port,
        dbname=original.dbname,
        user=original.user,
        password="new-secret",
        schema=original.schema,
    )
    assert original.identity == rotated.identity
    assert original.identity.canonical == (
        '{"database":"appdb","host":"db.internal","port":5432,'
        '"schema":"public","user":"migrator"}'
    )
    assert "rotatable-secret" not in original.identity.canonical


def test_production_runtime_uses_stable_key_store_and_required_audit(tmp_path):
    target = _target()
    artifact = MigrationArtifact("SELECT 1;")
    config = MigrationRunnerConfig(
        target=target,
        signing_key=_KEY,
        approval_store_path=tmp_path / "production.db",
    )
    audit = _Audit()
    first = build_migration_runtime(
        config,
        audit=audit,
        executor=lambda sql, bound, execution_id, artifact_sha256: (True, "ok"),
        receipt_lookup=_no_receipt,
        clock=lambda: 1_001.0,
    )
    approval = first.authority.mint(
        artifact_sha256=artifact.sha256, target=target.identity, now=1_000.0
    )
    assert first.runner.execute(approval=approval, artifact=artifact).executed
    first.close()

    second = build_migration_runtime(
        config,
        audit=audit,
        executor=lambda sql, bound, execution_id, artifact_sha256: (True, "ok"),
        receipt_lookup=_no_receipt,
        clock=lambda: 1_002.0,
    )
    try:
        replay = second.runner.execute(approval=approval, artifact=artifact)
        assert replay.refused and replay.reason == REPLAY
        assert [event["event"] for event in audit.events] == [
            "execute_intent",
            "execute_outcome",
            "refuse",
        ]
    finally:
        second.close()

    with pytest.raises(ValueError, match="audit sink is required"):
        build_migration_runtime(config, audit=None)  # type: ignore[arg-type]


def test_production_config_rejects_weak_key_and_missing_store_path():
    with pytest.raises(ValueError, match="at least 32 bytes"):
        MigrationRunnerConfig(
            target=_target(), signing_key=b"too-short", approval_store_path="store.db"
        )
    with pytest.raises(ValueError, match="approval_store_path is required"):
        MigrationRunnerConfig(
            target=_target(), signing_key=_KEY, approval_store_path=""
        )


def test_runner_rejects_missing_audit_sink(tmp_path):
    store = ConsumedApprovals(tmp_path / "missing-audit.db")
    try:
        with pytest.raises(ValueError, match="audit sink is required"):
            BrokeredMigrationRunner(
                authority=ApprovalAuthority(key=_KEY),
                target=_target(),
                consumed=store,
                executor=_SpyExecutor(),
                receipt_lookup=_no_receipt,
                audit=None,  # type: ignore[arg-type]
                clock=lambda: 1_001.0,
            )
    finally:
        store.close()


def test_custom_executor_requires_matching_receipt_lookup(tmp_path):
    store = ConsumedApprovals(tmp_path / "missing-receipt-lookup.db")
    try:
        with pytest.raises(ValueError, match="requires a matching receipt lookup"):
            BrokeredMigrationRunner(
                authority=ApprovalAuthority(key=_KEY),
                target=_target(),
                consumed=store,
                executor=_SpyExecutor(),
                audit=_Audit(),
                clock=lambda: 1_001.0,
            )
    finally:
        store.close()


def test_store_unavailable_refuses_before_executor(tmp_path):
    authority = ApprovalAuthority(key=_KEY)
    target = _target()
    artifact, approval = _approval(authority, target)
    spy = _SpyExecutor()
    audit = _Audit()
    store = ConsumedApprovals(tmp_path / "closed.db")
    runner = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=store,
        executor=spy,
        receipt_lookup=_no_receipt,
        audit=audit,
        clock=lambda: 1_001.0,
    )
    store.close()

    result = runner.execute(approval=approval, artifact=artifact)

    assert result.refused and result.reason == STORE_UNAVAILABLE
    assert spy.calls == []
    assert audit.events[-1]["payload"]["reason"] == STORE_UNAVAILABLE


def test_execution_intent_audit_failure_refuses_before_executor(tmp_path):
    authority = ApprovalAuthority(key=_KEY)
    target = _target()
    artifact, approval = _approval(authority, target)
    spy = _SpyExecutor()
    audit = _Audit(fail_on="execute_intent")
    runner = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=ConsumedApprovals(tmp_path / "intent-failure.db"),
        executor=spy,
        receipt_lookup=_no_receipt,
        audit=audit,
        clock=lambda: 1_001.0,
    )

    result = runner.execute(approval=approval, artifact=artifact)

    assert result.refused and result.reason == AUDIT_UNAVAILABLE
    assert not result.executed and not result.audit_recorded
    assert spy.calls == []
    assert audit.events == []

    # The ambiguous approval remains spent; restoring the audit cannot make the
    # failed intent retryable as a fresh execution capability.
    audit.fail_on = None
    replay = runner.execute(approval=approval, artifact=artifact)
    assert replay.refused and replay.reason == REPLAY
    assert spy.calls == []


def test_outcome_audit_failure_returns_explicit_result_with_durable_intent(tmp_path):
    authority = ApprovalAuthority(key=_KEY)
    target = _target()
    artifact, approval = _approval(authority, target)
    spy = _SpyExecutor()
    audit = _Audit(fail_on="execute_outcome")
    runner = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=ConsumedApprovals(tmp_path / "outcome-failure.db"),
        executor=spy,
        receipt_lookup=_no_receipt,
        audit=audit,
        clock=lambda: 1_001.0,
    )

    result = runner.execute(approval=approval, artifact=artifact)

    assert result.executed and not result.refused
    assert result.reason == AUDIT_OUTCOME_UNAVAILABLE
    assert not result.audit_recorded
    assert spy.calls == [(artifact.sql, target.user)]
    assert [event["event"] for event in audit.events] == ["execute_intent"]
    assert "durable execution intent seq=1 exists" in result.detail


def test_store_rejects_unsafe_permissions_symlink_and_corruption(tmp_path):
    unsafe_parent = tmp_path / "unsafe"
    unsafe_parent.mkdir()
    unsafe_parent.chmod(0o777)
    with pytest.raises(PermissionError, match="group/world writable"):
        ConsumedApprovals(unsafe_parent / "consumed.db")

    source = tmp_path / "source.db"
    source.touch(mode=0o600)
    link = tmp_path / "link.db"
    link.symlink_to(source)
    with pytest.raises(ValueError, match="symlink"):
        ConsumedApprovals(link)

    exposed = tmp_path / "exposed.db"
    exposed.touch(mode=0o600)
    exposed.chmod(0o644)
    with pytest.raises(PermissionError, match="permissions must be 0600"):
        ConsumedApprovals(exposed)

    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"not a sqlite database")
    corrupt.chmod(0o600)
    with pytest.raises(sqlite3.DatabaseError):
        ConsumedApprovals(corrupt)


class _FakeCursor:
    def __init__(self, responses=()) -> None:
        self.calls: list[tuple[str, object, dict[str, object]]] = []
        self.responses = list(responses)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query, params=None, **kwargs):
        self.calls.append((query, params, kwargs))

    def fetchone(self):
        return self.responses.pop(0) if self.responses else None


class _FakeConnection:
    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor
        self.commits = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.commits += 1


class _FakePsycopg:
    class Error(Exception):
        pass

    def __init__(self, responses=()) -> None:
        self.cursor = _FakeCursor(responses)
        self.connection = _FakeConnection(self.cursor)
        self.connect_kwargs: dict[str, object] = {}

    def connect(self, **kwargs):
        self.connect_kwargs = kwargs
        return self.connection


@pytest.mark.parametrize("hostile_sql", [r"\! env", r"\connect otherdb", r"\copy t FROM PROGRAM 'id'"])
def test_driver_executor_treats_psql_meta_commands_only_as_sql(
    monkeypatch, hostile_sql: str
):
    driver = _FakePsycopg()
    monkeypatch.setattr(
        "prometheus_protocol.chokepoint.runner.import_module", lambda _: driver
    )
    target = _target(schema='billing, "private"')

    ok, detail = postgres_executor(
        hostile_sql, target, "a" * 64, "b" * 64
    )

    assert ok and detail == ""
    assert driver.connect_kwargs == {
        "host": target.host,
        "port": target.port,
        "dbname": target.dbname,
        "user": target.user,
        "password": target.password,
        "connect_timeout": 10,
        "autocommit": False,
    }
    assert driver.connection.commits == 1
    schema_query, schema_params, _ = next(
        call for call in driver.cursor.calls if "set_config('search_path'" in call[0]
    )
    assert "quote_ident(%s)" in schema_query
    assert schema_params == (target.schema,)
    artifact_query, _, artifact_kwargs = next(
        call for call in driver.cursor.calls if call[0] == hostile_sql
    )
    assert artifact_query == hostile_sql
    assert artifact_kwargs == {"prepare": False}
    receipt_query, receipt_params, _ = next(
        call
        for call in driver.cursor.calls
        if "INSERT INTO promethyn_internal.migration_receipts" in call[0]
    )
    assert "target_canonical" in receipt_query
    assert receipt_params == ("a" * 64, "b" * 64, target.identity.canonical)


@pytest.mark.parametrize(
    ("responses", "expected"),
    [
        ([(False,)], RECEIPT_IN_PROGRESS),
        ([(True,), (None,)], RECEIPT_NOT_FOUND),
        (
            [
                (True,),
                ("promethyn_internal.migration_receipts",),
                ("b" * 64, _target().identity.canonical, "2026-08-22T12:00:00Z"),
            ],
            RECEIPT_COMMITTED,
        ),
        (
            [
                (True,),
                ("promethyn_internal.migration_receipts",),
                ("wrong-hash", _target().identity.canonical, "2026-08-22T12:00:00Z"),
            ],
            RECEIPT_CONFLICT,
        ),
    ],
)
def test_receipt_lookup_distinguishes_every_recovery_state(
    monkeypatch, responses, expected
):
    driver = _FakePsycopg(responses)
    monkeypatch.setattr(
        "prometheus_protocol.chokepoint.runner.import_module", lambda _: driver
    )

    result = postgres_receipt_lookup("a" * 64, "b" * 64, _target())

    assert result.state == expected


@pytest.mark.parametrize(
    "sql",
    [
        "COMMIT; SELECT 1",
        "/* harmless */ ROLLBACK",
        "SELECT 1; -- boundary\nBEGIN; SELECT 2",
        "SAVEPOINT attacker_boundary",
    ],
)
def test_executor_rejects_transaction_control_before_connect(monkeypatch, sql):
    def must_not_import(_):
        raise AssertionError("driver import proves DB path was reached")

    monkeypatch.setattr(
        "prometheus_protocol.chokepoint.runner.import_module", must_not_import
    )

    ok, detail = postgres_executor(sql, _target(), "a" * 64, "b" * 64)

    assert not ok
    assert "transaction-control statements are forbidden" in detail


def test_driver_executor_fails_closed_when_driver_is_missing(monkeypatch):
    def unavailable(_):
        raise ImportError

    monkeypatch.setattr(
        "prometheus_protocol.chokepoint.runner.import_module", unavailable
    )
    ok, detail = postgres_executor("SELECT 1", _target(), "a" * 64, "b" * 64)
    assert not ok
    assert "unavailable" in detail


def test_driver_executor_reports_database_error(monkeypatch):
    driver = _FakePsycopg()

    def fail_connect(**kwargs):
        raise driver.Error("connection refused")

    driver.connect = fail_connect  # type: ignore[method-assign]
    monkeypatch.setattr(
        "prometheus_protocol.chokepoint.runner.import_module", lambda _: driver
    )
    ok, detail = postgres_executor("SELECT 1", _target(), "a" * 64, "b" * 64)
    assert not ok
    assert detail == "connection refused"
