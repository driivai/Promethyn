"""Finding 2 (PROM-FIX-B part 2): the execution guard is keyed to the store's
identity, not its pathname.

The independent review reproduced this with real subprocesses, hard links,
SQLite and OS locks: two hard links to one consumed-store inode produced two
different companion lock paths (``original.db.execution.lock`` and
``alias.db.execution.lock``), both runners acquired their locks, and recovery
recorded ``not_committed`` for an owner that was still running. The lock
proved exclusion over a *path*, not over *the store*.

The guard is now an ``flock`` on a descriptor of the store's own inode, held
open for the store's lifetime. Every alias of the store — a hard link, a file
bind mount, a symlink — opens the same inode, and the kernel evaluates
``flock`` conflicts per inode across processes, so every alias resolves to one
lock object. A multiply linked store is refused at construction and before
every use besides, and each intent records the lock's identity so that "same
boot id and I hold a lock" only counts when it is provably the same lock.

The tests here reproduce the review's scenario, not a simplified one: the
owner is a real subprocess, the alias is a real hard link (and, under a mount
namespace, a real bind mount), and the recovering runner is given the alias
path. Positive controls prove an ordinary single-linked store still works.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import shutil
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

from tests.support.platform_gate import require_linux

from prometheus_protocol.chokepoint import (
    EXECUTION_BUSY,
    EXECUTION_COMMITTED,
    EXECUTION_UNKNOWN,
    OWNER_LEGACY,
    OWNER_LOCK_MISMATCH,
    OWNER_SAME_KERNEL,
    OWNER_UNVERIFIABLE,
    RECEIPT_NOT_FOUND,
    RECONCILED_NOT_COMMITTED,
    RECONCILIATION_REQUIRED,
    STORE_UNAVAILABLE,
    ApprovalAuthority,
    AuthorizationJournal,
    BrokeredMigrationRunner,
    ConsumedApprovals,
    DbTarget,
    ExecutorResult,
    MigrationArtifact,
    OwnerIdentity,
    ReceiptStatus,
    SubstratePolicy,
    assess_owner,
)
from prometheus_protocol.chokepoint import runner as runner_module
from prometheus_protocol.chokepoint.authorization_journal import AuthorizationUnavailable
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger

KEY = b"lock-identity-test-key-32-bytes!!!!"
HOST = OwnerIdentity(host="host-a", boot_id="boot-a", machine_id="machine-a", pid=1)


def target() -> DbTarget:
    return DbTarget("localhost", 5432, "appdb", "migrator", "synthetic-secret")


def approved(sql: str = "SELECT 1"):
    artifact = MigrationArtifact(sql)
    approval = ApprovalAuthority(key=KEY).mint(
        artifact_sha256=artifact.sha256, target=target().identity, now=1000
    )
    return approval, artifact


def make_runner(store_path, ledger, *, executor, lookup, identity=HOST, consumed=None):
    return BrokeredMigrationRunner(
        authority=ApprovalAuthority(key=KEY),
        target=target(),
        consumed=consumed if consumed is not None else ConsumedApprovals(store_path),
        executor=executor,
        receipt_lookup=lookup,
        audit=ledger,
        clock=lambda: 1001,
        identity=identity,
    )


def events(ledger):
    return [(e["event"], json.loads(e["payload"])) for e in ledger.chained_events()]


def identity_of(path) -> tuple[int, int]:
    info = os.stat(path)
    return info.st_dev, info.st_ino


# ---------------------------------------------------------------------------
# The owner: a real subprocess that holds the guard after its intent is durable
# ---------------------------------------------------------------------------


class _PauseAfterIntent:
    def __init__(self, ledger, entered, resume):
        self.ledger, self.entered, self.resume = ledger, entered, resume

    def record_chained(self, **event):
        seq = self.ledger.record_chained(**event)
        if event["event"] == "execute_intent":
            self.entered.set()
            assert self.resume.wait(30), "test owner was never resumed"
        return seq

    def verify_chain(self):
        return self.ledger.verify_chain()

    def chained_events(self):
        return self.ledger.chained_events()


def _owner_process(store_path, ledger_path, entered, resume, results):
    ledger = SqliteLedger(ledger_path)
    runner = make_runner(
        store_path, _PauseAfterIntent(ledger, entered, resume),
        executor=lambda *a: ExecutorResult(EXECUTION_COMMITTED, "committed"),
        lookup=lambda *a: ReceiptStatus(RECEIPT_NOT_FOUND),
    )
    approval, artifact = approved()
    try:
        result = runner.execute(approval=approval, artifact=artifact)
        results.put({"owner_executed": result.executed, "owner_state": result.execution_state})
    finally:
        runner.close()
        ledger.close()


@pytest.fixture
def live_owner(tmp_path):
    """Start the owner on ``original.db``, block it after its intent, and hand
    the test the paths while the owner is alive and holding the guard."""

    context = multiprocessing.get_context("spawn")
    entered, resume, results = context.Event(), context.Event(), context.Queue()
    store, audit = tmp_path / "original.db", tmp_path / "audit.db"
    owner = context.Process(target=_owner_process, args=(store, audit, entered, resume, results))
    owner.start()
    assert entered.wait(20), "the owner never recorded its intent"
    state = {"owner": owner, "store": store, "audit": audit, "resume": resume, "results": results}
    try:
        yield state
    finally:
        resume.set()
        owner.join(10)
        if owner.is_alive():
            owner.kill()
            owner.join(5)


# ---------------------------------------------------------------------------
# 1. The review's reproduction, failing closed
# ---------------------------------------------------------------------------


def test_review_reproduction_a_hard_link_alias_cannot_recover_a_live_owner(live_owner, monkeypatch):
    """Exactly the review's steps. The owner holds the guard on original.db and
    is alive. A second runner is given alias.db, a hard link to the same inode.
    Before: both locks acquired, recovery recorded not_committed while the
    owner ran. Now: the alias is the same lock object, so the recovering runner
    is BUSY; its executor is never called; no outcome is recorded for the
    owner's intent until the owner itself finishes."""

    store, audit = live_owner["store"], live_owner["audit"]
    alias = store.with_name("alias.db")
    os.link(store, alias)
    assert identity_of(store) == identity_of(alias), "same_store_inode must be True"
    assert live_owner["owner"].is_alive(), "child_alive must be True"

    # A runner on the alias with the link-count refusal switched off, so the
    # test reaches the lock itself rather than the refusal in front of it.
    monkeypatch.setattr(runner_module, "_singly_linked", lambda info: True)
    ledger = SqliteLedger(audit)
    calls: list[object] = []
    recovering = make_runner(
        alias, ledger,
        executor=lambda *a: calls.append(a),
        lookup=lambda *a: ReceiptStatus(RECEIPT_NOT_FOUND),
    )
    try:
        assert recovering._consumed.lock_id == f"{identity_of(store)[0]}:{identity_of(store)[1]}"
        report = recovering.reconcile_unfinished()
        assert len(report) == 1 and not report[0].resolved
        assert report[0].state in {EXECUTION_BUSY, OWNER_UNVERIFIABLE}
        assert report[0].state != RECEIPT_NOT_FOUND
        approval, artifact = approved("SELECT 2")
        blocked = recovering.execute(approval=approval, artifact=artifact)
        assert blocked.refused and blocked.reason == RECONCILIATION_REQUIRED
        assert calls == [], "the recovering runner's executor must never run"
        recorded = events(ledger)
        assert [name for name, _ in recorded] == ["execute_intent", "refuse"]
        assert not any(p.get("reason") == RECONCILED_NOT_COMMITTED for _, p in recorded)
        assert live_owner["owner"].is_alive()

        # With the refusal back on, the alias is not even usable as a store.
        monkeypatch.undo()
        again = recovering.execute(approval=approval, artifact=artifact)
        assert again.refused and again.reason == STORE_UNAVAILABLE
        assert calls == []
    finally:
        recovering.close()

    # The owner finishes on its own: the only terminal outcome is its commit.
    live_owner["resume"].set()
    outcome = live_owner["results"].get(timeout=20)
    assert outcome == {"owner_executed": True, "owner_state": EXECUTION_COMMITTED}
    live_owner["owner"].join(10)
    terminal = [p["execution_state"] for name, p in events(ledger) if name == "execute_outcome"]
    assert terminal == [EXECUTION_COMMITTED], terminal
    ledger.close()


def test_a_multiply_linked_store_is_refused_at_construction(tmp_path):
    store = tmp_path / "store.db"
    ConsumedApprovals(store).close()
    os.link(store, tmp_path / "alias.db")
    for path in (store, tmp_path / "alias.db"):
        with pytest.raises(ValueError, match="singly linked"):
            ConsumedApprovals(path)


def test_a_store_hard_linked_after_construction_is_caught_before_use(tmp_path):
    ledger = SqliteLedger(tmp_path / "audit.db")
    store = tmp_path / "store.db"
    runner = make_runner(
        store, ledger,
        executor=lambda *a: pytest.fail("must not execute"),
        lookup=lambda *a: ReceiptStatus(RECEIPT_NOT_FOUND),
    )
    alias = tmp_path / "alias.db"
    os.link(store, alias)
    approval, artifact = approved()
    result = runner.execute(approval=approval, artifact=artifact)
    assert result.refused and result.reason == STORE_UNAVAILABLE
    assert "MultiplyLinkedStore" in result.detail
    assert runner.reconcile_unfinished()[0].state == STORE_UNAVAILABLE
    with pytest.raises(runner_module._OwnershipUnavailable):
        with runner._consumed.execution_guard():
            pass
    # Positive control: remove the alias and the same store works again.
    os.unlink(alias)
    with runner._consumed.execution_guard() as owned:
        assert owned
    runner.close()
    ledger.close()


# ---------------------------------------------------------------------------
# 2. One inode, one lock: hard links, bind mounts, processes, threads
# ---------------------------------------------------------------------------


def test_aliased_stores_resolve_to_one_lock_object(tmp_path, monkeypatch):
    store = tmp_path / "store.db"
    original = ConsumedApprovals(store)
    os.link(store, tmp_path / "alias.db")
    monkeypatch.setattr(runner_module, "_singly_linked", lambda info: True)
    alias = ConsumedApprovals(tmp_path / "alias.db")
    try:
        assert original.lock_id == alias.lock_id
        with original.execution_guard() as owned:
            assert owned
            with alias.execution_guard() as other:
                assert other is False, "the alias must contend for the same lock"
        with alias.execution_guard() as other:
            assert other is True, "released by the original, acquirable by the alias"
    finally:
        original.close()
        alias.close()


def test_two_processes_on_one_store_contend_for_one_lock(tmp_path):
    store = tmp_path / "store.db"
    mine = ConsumedApprovals(store)
    probe = textwrap.dedent(
        """
        import json, sys
        from prometheus_protocol.chokepoint import ConsumedApprovals
        store = ConsumedApprovals(sys.argv[1])
        with store.execution_guard() as owned:
            print(json.dumps({"owned": owned, "lock_id": store.lock_id}))
        store.close()
        """
    )

    def other_process():
        out = subprocess.run([sys.executable, "-c", probe, str(store)], capture_output=True, text=True, timeout=60)
        assert out.returncode == 0, out.stderr
        return json.loads(out.stdout)

    try:
        with mine.execution_guard() as owned:
            assert owned
            assert other_process() == {"owned": False, "lock_id": mine.lock_id}
        assert other_process() == {"owned": True, "lock_id": mine.lock_id}
    finally:
        mine.close()


def test_two_threads_of_one_process_cannot_both_own(tmp_path):
    store = ConsumedApprovals(tmp_path / "store.db")
    held, release, seen = threading.Event(), threading.Event(), []

    def holder():
        with store.execution_guard() as owned:
            seen.append(("holder", owned))
            held.set()
            release.wait(10)

    thread = threading.Thread(target=holder)
    thread.start()
    try:
        assert held.wait(10)
        with store.execution_guard() as owned:
            seen.append(("second", owned))
    finally:
        release.set()
        thread.join(10)
        store.close()
    assert seen == [("holder", True), ("second", False)]


_BIND_MOUNT_PROBE = textwrap.dedent(
    """
    import json, os, subprocess, sys
    from prometheus_protocol.chokepoint import ConsumedApprovals
    root = sys.argv[1]
    original = os.path.join(root, "original.db")
    alias = os.path.join(root, "alias.db")
    first = ConsumedApprovals(original)
    fd = os.open(alias, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    subprocess.run(["mount", "--bind", original, alias], check=True)
    before = os.stat(alias)
    second = ConsumedApprovals(alias)   # nlink is 1: the link-count refusal does not fire
    with first.execution_guard() as owned:
        with second.execution_guard() as other:
            print(json.dumps({
                "same_inode": (os.stat(original).st_dev, os.stat(original).st_ino)
                              == (before.st_dev, before.st_ino),
                "nlink": before.st_nlink,
                "first_owned": owned,
                "alias_owned": other,
                "lock_ids_equal": first.lock_id == second.lock_id,
            }))
    first.close(); second.close()
    """
)


def test_a_file_bind_mount_alias_resolves_to_the_same_lock(tmp_path):
    """A bind mount aliases the store without increasing its link count, so the
    link-count refusal does not fire; only an inode-keyed lock excludes it.
    Runs in a private mount namespace (as root directly; otherwise through an
    unprivileged user namespace). Linux only, and it FAILS rather than skips
    where namespaces are unavailable: an unproven guard is not a proven one."""

    # FAILS under PROM_REQUIRE_LINUX=1 (CI) exactly as before; skips with the
    # reason on a developer machine off the declared platform.
    require_linux()
    command = ["unshare", "--mount", "--propagation", "private"]
    if os.geteuid() != 0:
        command = ["unshare", "--user", "--map-root-user", "--mount", "--propagation", "private"]
    command += [sys.executable, "-c", _BIND_MOUNT_PROBE, str(tmp_path)]
    run = subprocess.run(command, capture_output=True, text=True, timeout=120)
    assert run.returncode == 0, f"bind-mount probe failed:\n{run.stderr}"
    result = json.loads(run.stdout.strip().splitlines()[-1])
    assert result == {
        "same_inode": True, "nlink": 1, "first_owned": True, "alias_owned": False, "lock_ids_equal": True,
    }, result


# ---------------------------------------------------------------------------
# 3. The ownership inference: a held lock counts only if it is the same object
# ---------------------------------------------------------------------------


def test_same_boot_id_without_the_same_lock_is_not_established():
    recorded = {**HOST.as_payload(), "owner_lock_id": "8:100"}
    assert assess_owner(recorded, HOST, lock_id="8:100").basis == OWNER_SAME_KERNEL
    assert assess_owner(recorded, HOST, lock_id="8:100").established is True
    mismatch = assess_owner(recorded, HOST, lock_id="8:200")
    assert not mismatch.established and mismatch.basis == OWNER_LOCK_MISMATCH
    missing = assess_owner({**HOST.as_payload()}, HOST, lock_id="8:100")
    assert not missing.established and missing.basis == OWNER_LOCK_MISMATCH
    unknown = assess_owner(recorded, HOST, lock_id=None)
    assert not unknown.established and unknown.basis == OWNER_LOCK_MISMATCH


def test_a_legacy_intent_without_identity_is_never_established():
    legacy = assess_owner({"execution_id": "x", "artifact_sha256": "y"}, HOST, lock_id="8:100")
    assert not legacy.established and legacy.basis == OWNER_LEGACY


def test_the_intent_records_the_lock_identity_and_a_copied_store_cannot_recover_it(tmp_path):
    """The owner on store S leaves an UNKNOWN intent recording S's lock id. A
    runner on the same kernel using a byte-for-byte COPY of S holds a lock on
    a different inode: same boot id, a held lock, and still not the owner's
    lock. It must leave the intent pending; the operator's assertion resolves
    it and is recorded."""

    ledger = SqliteLedger(tmp_path / "audit.db")
    store = tmp_path / "store.db"
    owner = make_runner(
        store, ledger,
        executor=lambda *a: ExecutorResult(EXECUTION_UNKNOWN, "reply lost"),
        lookup=lambda *a: pytest.fail("the owner does not look up its own receipt"),
    )
    approval, artifact = approved()
    assert owner.execute(approval=approval, artifact=artifact).execution_state == EXECUTION_UNKNOWN
    intent = events(ledger)[0][1]
    assert intent["owner_lock_id"] == owner._consumed.lock_id
    owner.close()

    copy = tmp_path / "copy.db"
    shutil.copy(store, copy)
    os.chmod(copy, 0o600)
    lookups: list[object] = []

    def lookup(*args):
        lookups.append(args)
        return ReceiptStatus(RECEIPT_NOT_FOUND)

    other = make_runner(copy, ledger, executor=lambda *a: pytest.fail("must not execute"), lookup=lookup)
    try:
        assert other._consumed.lock_id != intent["owner_lock_id"]
        report = other.reconcile_unfinished()
        assert len(report) == 1 and not report[0].resolved and report[0].state == OWNER_UNVERIFIABLE
        assert "same object" in report[0].detail and lookups == []
        assert other.execute(approval=approved("SELECT 2")[0], artifact=approved("SELECT 2")[1]).reason == RECONCILIATION_REQUIRED
        forced = other.reconcile_unfinished(assume_owner_dead=True)
        assert forced[0].resolved and forced[0].state == RECEIPT_NOT_FOUND
        outcome = events(ledger)[-1][1]
        assert outcome["owner_override"] is True and outcome["owner_basis"] == OWNER_LOCK_MISMATCH
    finally:
        other.close()

    # Positive control: a runner on the ORIGINAL store, same kernel, same lock
    # object, is established and reconciles without any assertion.
    same = make_runner(store, ledger, executor=lambda *a: pytest.fail("must not execute"), lookup=lookup)
    try:
        assert same.reconcile_unfinished() == ()
    finally:
        same.close()
    ledger.close()


def test_positive_control_a_single_linked_store_recovers_its_own_dead_owner(tmp_path):
    ledger = SqliteLedger(tmp_path / "audit.db")
    store = tmp_path / "store.db"
    dead = make_runner(
        store, ledger,
        executor=lambda *a: ExecutorResult(EXECUTION_UNKNOWN, "reply lost"),
        lookup=lambda *a: ReceiptStatus(RECEIPT_NOT_FOUND),
    )
    approval, artifact = approved()
    dead.execute(approval=approval, artifact=artifact)
    dead.close()
    successor = make_runner(
        store, ledger,
        executor=lambda *a: ExecutorResult(EXECUTION_COMMITTED, "ok"),
        lookup=lambda *a: ReceiptStatus(RECEIPT_NOT_FOUND),
    )
    try:
        report = successor.reconcile_unfinished()
        assert len(report) == 1 and report[0].resolved and report[0].state == RECEIPT_NOT_FOUND
        assert events(ledger)[-1][1]["owner_basis"] == OWNER_SAME_KERNEL
        approval, artifact = approved("SELECT 2")
        assert successor.execute(approval=approval, artifact=artifact).executed
    finally:
        successor.close()
        ledger.close()


# ---------------------------------------------------------------------------
# 4. The authorization journal's store gets the same treatment
# ---------------------------------------------------------------------------


def test_the_authorization_journal_refuses_a_hard_linked_ledger_before_use(tmp_path):
    path = tmp_path / "authorization.db"
    audit = SqliteLedger.private(path)
    journal = AuthorizationJournal(audit, substrate_policy=SubstratePolicy())
    assert journal.records() == []
    os.link(path, tmp_path / "alias.db")
    with pytest.raises(AuthorizationUnavailable):
        journal.records()
    os.unlink(tmp_path / "alias.db")
    assert journal.records() == []
    audit.close()
