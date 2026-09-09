"""F2/F3 regressions: uncertainty is pending; a live owner cannot be recovered."""

import json
import multiprocessing
import os
import signal
import threading

import pytest

from prometheus_protocol.chokepoint import (
    AUDIT_OUTCOME_UNAVAILABLE,
    EXECUTION_BUSY,
    EXECUTION_COMMITTED,
    EXECUTION_NOT_COMMITTED,
    EXECUTION_UNKNOWN,
    OWNER_UNVERIFIABLE,
    RECEIPT_COMMITTED,
    RECEIPT_NOT_FOUND,
    RECEIPT_UNAVAILABLE,
    RECONCILIATION_REQUIRED,
    REPLAY,
    STORE_UNAVAILABLE,
    ApprovalAuthority,
    BrokeredMigrationRunner,
    ConsumedApprovals,
    DbTarget,
    ExecutorResult,
    MigrationArtifact,
    ReceiptStatus,
    postgres_executor,
)
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger

KEY = b"recovery-test-key-32-bytes-minimum!"


def target():
    return DbTarget("localhost", 5432, "appdb", "migrator", "synthetic-secret")


def approved(sql="SELECT 1"):
    artifact = MigrationArtifact(sql)
    approval = ApprovalAuthority(key=KEY).mint(
        artifact_sha256=artifact.sha256,
        target=target().identity,
        now=1000,
    )
    return approval, artifact


def runner(path, audit, executor, lookup):
    return BrokeredMigrationRunner(
        authority=ApprovalAuthority(key=KEY),
        target=target(),
        consumed=ConsumedApprovals(path),
        executor=executor,
        receipt_lookup=lookup,
        audit=audit,
        clock=lambda: 1001,
    )


@pytest.mark.parametrize("kind", ["exception", "false", "typed", "malformed"])
def test_unknown_stays_pending_and_blocks_until_receipt_proves_commit(tmp_path, kind):
    ledger = SqliteLedger(tmp_path / "audit.db")
    calls, lookups = [], []
    available = False

    def executor(*args):
        calls.append(args)
        if kind == "exception":
            raise ConnectionError("COMMIT response lost")
        if kind == "false":
            return False, "connection lost"
        if kind == "malformed":
            return "truthy", "not a boolean"
        return ExecutorResult(EXECUTION_UNKNOWN)

    def lookup(*args):
        lookups.append(args)
        return ReceiptStatus(RECEIPT_COMMITTED if available else RECEIPT_UNAVAILABLE)

    first = runner(tmp_path / "store.db", ledger, executor, lookup)
    approval, artifact = approved()
    result = first.execute(approval=approval, artifact=artifact)
    assert not result.executed and not result.refused
    assert result.reason == result.execution_state == EXECUTION_UNKNOWN
    assert [e["event"] for e in ledger.chained_events()] == [
        "execute_intent",
        "execute_unknown",
    ]
    first.close()
    # New runner after restart still sees the pending intent, even though its
    # unknown event was durably recorded.
    second = runner(tmp_path / "store.db", ledger, executor, lookup)
    next_approval, next_artifact = approved("SELECT 2")
    blocked = second.execute(approval=next_approval, artifact=next_artifact)
    assert blocked.refused and blocked.reason == RECONCILIATION_REQUIRED
    assert len(calls) == 1 and len(lookups) == 1
    available = True
    report = second.reconcile_unfinished()
    assert (
        len(report) == 1 and report[0].resolved and report[0].state == RECEIPT_COMMITTED
    )
    assert second.reconcile_unfinished() == ()
    assert second.execute(approval=approval, artifact=artifact).reason == REPLAY
    # The approval refused during recovery was not consumed.
    assert (
        second.execute(approval=next_approval, artifact=next_artifact).reason
        == EXECUTION_UNKNOWN
    )
    assert len(calls) == 2
    second.close()
    ledger.close()


def test_legacy_false_outcome_is_revisited_but_stays_pending_until_the_operator_asserts(tmp_path):
    """A pre-upgrade false outcome is not terminal (F2), so its intent is
    revisited. But a pre-upgrade intent carries no owner identity, and since
    PROM-FIX-B no held lock is proof of a dead owner unless it is provably the
    owner's, so the revisit leaves it pending; the operator's assertion then
    lets the receipt speak, and the receipt proves COMMITTED."""

    ledger = SqliteLedger(tmp_path / "audit.db")
    payload = {
        "target": target().identity.canonical,
        "artifact_sha256": "b" * 64,
        "execution_id": "a" * 64,
    }
    ledger.record_chained(
        event="execute_intent", subject="x", payload=payload, created_at="1"
    )
    ledger.record_chained(
        event="execute_outcome",
        subject="x",
        payload={**payload, "intent_seq": 1, "ok": False, "reason": "migration_error"},
        created_at="2",
    )
    r = runner(
        tmp_path / "store.db",
        ledger,
        lambda *a: pytest.fail("must not execute"),
        lambda *a: ReceiptStatus(RECEIPT_COMMITTED),
    )
    pending = r.reconcile_unfinished()
    assert len(pending) == 1 and not pending[0].resolved
    assert pending[0].state == OWNER_UNVERIFIABLE
    report = r.reconcile_unfinished(assume_owner_dead=True)
    assert (
        len(report) == 1 and report[0].state == RECEIPT_COMMITTED and report[0].resolved
    )
    assert (
        json.loads(ledger.chained_events()[-1]["payload"])["execution_state"]
        == EXECUTION_COMMITTED
    )
    assert r.reconcile_unfinished() == ()
    r.close()
    ledger.close()


def test_confirmed_rollback_is_terminal(tmp_path):
    ledger = SqliteLedger(tmp_path / "audit.db")
    r = runner(
        tmp_path / "store.db",
        ledger,
        lambda *a: ExecutorResult(EXECUTION_NOT_COMMITTED, "rollback acknowledged"),
        lambda *a: pytest.fail("known rollback does not need a receipt lookup"),
    )
    approval, artifact = approved()
    result = r.execute(approval=approval, artifact=artifact)
    assert (
        result.reason == "migration_error"
        and result.execution_state == EXECUTION_NOT_COMMITTED
    )
    assert r.reconcile_unfinished() == ()
    r.close()
    ledger.close()


def test_unknown_event_audit_failure_does_not_resolve_intent(tmp_path):
    ledger = SqliteLedger(tmp_path / "audit.db")

    class Audit:
        def record_chained(self, **event):
            if event["event"] == "execute_unknown":
                raise OSError("audit unavailable after execution")
            return ledger.record_chained(**event)

        def chained_events(self):
            return ledger.chained_events()

        def verify_chain(self):
            return ledger.verify_chain()

    r = runner(
        tmp_path / "store.db",
        Audit(),
        lambda *a: ExecutorResult(EXECUTION_UNKNOWN),
        lambda *a: ReceiptStatus(RECEIPT_UNAVAILABLE),
    )
    approval, artifact = approved()
    result = r.execute(approval=approval, artifact=artifact)
    assert result.reason == AUDIT_OUTCOME_UNAVAILABLE
    assert result.execution_state == EXECUTION_UNKNOWN and not result.audit_recorded
    assert [e["event"] for e in ledger.chained_events()] == ["execute_intent"]
    assert not r.reconcile_unfinished()[0].resolved
    r.close()
    ledger.close()


class PauseAfterIntent:
    def __init__(self, ledger, entered, resume):
        self.ledger, self.entered, self.resume = ledger, entered, resume

    def record_chained(self, **event):
        seq = self.ledger.record_chained(**event)
        if event["event"] == "execute_intent":
            self.entered.set()
            assert self.resume.wait(15), "test owner was never resumed"
        return seq

    def verify_chain(self):
        return self.ledger.verify_chain()

    def chained_events(self):
        return self.ledger.chained_events()


def paused_owner(store_path, ledger_path, entered, resume, results):
    ledger = SqliteLedger(ledger_path)
    r = runner(
        store_path,
        PauseAfterIntent(ledger, entered, resume),
        lambda *a: (True, "committed"),
        lambda *a: ReceiptStatus(RECEIPT_NOT_FOUND),
    )
    approval, artifact = approved()
    try:
        results.put(r.execute(approval=approval, artifact=artifact))
    finally:
        r.close()
        ledger.close()


@pytest.mark.parametrize("terminate", [False, True])
def test_process_suspended_after_intent_cannot_be_reconciled(tmp_path, terminate):
    context = multiprocessing.get_context("spawn")
    entered, resume, results = context.Event(), context.Event(), context.Queue()
    store_path, audit_path = tmp_path / "store.db", tmp_path / "audit.db"
    owner = context.Process(
        target=paused_owner, args=(store_path, audit_path, entered, resume, results)
    )
    owner.start()
    stopped = False
    ledger = r = None
    try:
        assert entered.wait(10)
        os.kill(owner.pid, signal.SIGSTOP)
        stopped = True
        ledger = SqliteLedger(audit_path)
        r = runner(
            store_path,
            ledger,
            lambda *a: (True, "ok"),
            lambda *a: ReceiptStatus(RECEIPT_NOT_FOUND),
        )
        report = r.reconcile_unfinished()
        assert (
            len(report) == 1
            and not report[0].resolved
            and report[0].state == EXECUTION_BUSY
        )
        approval, artifact = approved("SELECT 2")
        assert (
            r.execute(approval=approval, artifact=artifact).reason
            == RECONCILIATION_REQUIRED
        )
        assert not any(e["event"] == "execute_outcome" for e in ledger.chained_events())
        if terminate:
            owner.kill()
            owner.join(5)
            stopped = False
            report = r.reconcile_unfinished()
            assert (
                len(report) == 1
                and report[0].resolved
                and report[0].state == RECEIPT_NOT_FOUND
            )
        else:
            os.kill(owner.pid, signal.SIGCONT)
            stopped = False
            resume.set()
            assert results.get(timeout=10).executed
            owner.join(5)
            assert owner.exitcode == 0
            assert r.reconcile_unfinished() == ()
        assert r.execute(approval=approval, artifact=artifact).executed
    finally:
        if stopped:
            os.kill(owner.pid, signal.SIGCONT)
        if owner.is_alive():
            resume.set()
            owner.terminate()
        owner.join(5)
        if r:
            r.close()
        if ledger:
            ledger.close()


def test_independent_threads_cannot_recover_a_live_owner(tmp_path):
    entered, resume = threading.Event(), threading.Event()
    ledger_path, store_path = tmp_path / "audit.db", tmp_path / "store.db"
    results = []

    def work():
        ledger = SqliteLedger(ledger_path)
        r = runner(
            store_path,
            PauseAfterIntent(ledger, entered, resume),
            lambda *a: (True, "ok"),
            lambda *a: ReceiptStatus(RECEIPT_NOT_FOUND),
        )
        approval, artifact = approved()
        try:
            results.append(r.execute(approval=approval, artifact=artifact))
        finally:
            r.close()
            ledger.close()

    thread = threading.Thread(target=work)
    thread.start()
    assert entered.wait(5)
    ledger = SqliteLedger(ledger_path)
    r = runner(
        store_path,
        ledger,
        lambda *a: pytest.fail("must not execute"),
        lambda *a: pytest.fail("must not look up a live owner's receipt"),
    )
    try:
        assert r.reconcile_unfinished()[0].state == EXECUTION_BUSY
    finally:
        resume.set()
        thread.join(5)
        r.close()
        ledger.close()
    assert not thread.is_alive() and results[0].executed


def test_a_store_with_a_second_name_refuses_execution(tmp_path):
    """The guard is the store's own inode (PROM-FIX-B); a store that gains a
    second name after construction is refused before use, and the refusal is
    STORE_UNAVAILABLE, never a lock that happens to be free."""

    ledger = SqliteLedger(tmp_path / "audit.db")
    r = runner(
        tmp_path / "store.db",
        ledger,
        lambda *a: pytest.fail("must not execute"),
        lambda *a: ReceiptStatus(RECEIPT_NOT_FOUND),
    )
    os.link(tmp_path / "store.db", tmp_path / "second-name.db")
    approval, artifact = approved()
    assert r.execute(approval=approval, artifact=artifact).reason == STORE_UNAVAILABLE
    assert not r.reconcile_unfinished()[0].resolved
    r.close()
    ledger.close()


@pytest.mark.parametrize(
    "failure,expected",
    [
        ("commit", EXECUTION_UNKNOWN),
        ("rollback", EXECUTION_UNKNOWN),
        ("statement", EXECUTION_NOT_COMMITTED),
        ("close", EXECUTION_COMMITTED),
    ],
)
def test_driver_proof_boundaries(monkeypatch, failure, expected):
    class DriverError(Exception):
        pass

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, query, *args, **kwargs):
            if query == "SELECT migration" and failure in {"statement", "rollback"}:
                raise DriverError("statement response lost")

        def fetchone(self):
            return None

    class Connection:
        commits = 0
        rollbacks = 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, *args):
            if failure == "close":
                raise DriverError("close failed after commit acknowledgment")
            if exc_type and failure == "commit":
                self.rollback()  # Cannot undo a COMMIT already sent.
            return False

        def cursor(self):
            return Cursor()

        def commit(self):
            self.commits += 1
            if self.commits == 2 and failure == "commit":
                raise DriverError("commit response lost")

        def rollback(self):
            self.rollbacks += 1
            if failure == "rollback":
                raise DriverError("rollback response lost")

    conn = Connection()
    driver = type("Driver", (), {"Error": DriverError, "connect": lambda **kw: conn})
    monkeypatch.setattr(
        "prometheus_protocol.chokepoint.runner.import_module", lambda name: driver
    )
    result = postgres_executor("SELECT migration", target(), "a" * 64, "b" * 64)
    assert result.state == expected
    if failure in {"rollback", "statement", "commit"}:
        assert conn.rollbacks == 1
