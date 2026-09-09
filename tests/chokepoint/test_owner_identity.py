"""F3 rework, part two: the multi-host race fails closed.

Two runners on two hosts that share a store or a ledger cannot be told apart
by the execution guard: host B's flock says nothing about host A. So every
intent now records its owner (host, kernel boot id, machine id, pid), and a
recovering runner that cannot establish the recorded owner is dead reports
``owner_unverifiable`` and leaves the intent pending. It never records
``reconciled_not_committed`` for an owner it could not place.

"Another host" is a runner constructed with a different ``OwnerIdentity`` on
this machine: the ledger and store are shared exactly as they would be over
a misdeployed mount, and the only thing that differs is what each runner
knows about itself. That is the whole of what the guard can see.
"""

from __future__ import annotations

import json
import logging
import os
import socket

import pytest

from prometheus_protocol.chokepoint import (
    EXECUTION_UNKNOWN,
    OWNER_FOREIGN,
    OWNER_LEGACY,
    OWNER_REBOOTED,
    OWNER_SAME_KERNEL,
    OWNER_UNVERIFIABLE,
    RECEIPT_NOT_FOUND,
    RECONCILED_NOT_COMMITTED,
    RECONCILIATION_REQUIRED,
    ApprovalAuthority,
    BrokeredMigrationRunner,
    ConsumedApprovals,
    DbTarget,
    ExecutorResult,
    MigrationArtifact,
    OwnerIdentity,
    ReceiptStatus,
    assess_owner,
    local_identity,
)
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger

KEY = b"owner-identity-test-key-32-bytes!!!"
RUNNER_LOGGER = "prometheus_protocol.chokepoint.runner"

HOST_A = OwnerIdentity(host="host-a", boot_id="boot-a", machine_id="machine-a", pid=101)
HOST_A_SAME_KERNEL = OwnerIdentity(host="container-on-a", boot_id="boot-a", machine_id=None, pid=202)
HOST_A_REBOOTED = OwnerIdentity(host="host-a", boot_id="boot-a-2", machine_id="machine-a", pid=303)
HOST_B = OwnerIdentity(host="host-b", boot_id="boot-b", machine_id="machine-b", pid=404)


def target() -> DbTarget:
    return DbTarget("localhost", 5432, "appdb", "migrator", "synthetic-secret")


def approved(sql: str = "SELECT 1"):
    artifact = MigrationArtifact(sql)
    approval = ApprovalAuthority(key=KEY).mint(
        artifact_sha256=artifact.sha256, target=target().identity, now=1000
    )
    return approval, artifact


def runner(tmp_path, ledger, identity, *, executor, lookup):
    return BrokeredMigrationRunner(
        authority=ApprovalAuthority(key=KEY),
        target=target(),
        consumed=ConsumedApprovals(tmp_path / "store.db"),
        executor=executor,
        receipt_lookup=lookup,
        audit=ledger,
        clock=lambda: 1001,
        identity=identity,
    )


def events(ledger):
    return [(e["event"], json.loads(e["payload"])) for e in ledger.chained_events()]


def leave_pending_intent(tmp_path, ledger, identity=HOST_A):
    """Host A executes, its executor loses the outcome: one pending intent."""

    owner = runner(
        tmp_path, ledger, identity,
        executor=lambda *a: ExecutorResult(EXECUTION_UNKNOWN, "COMMIT response lost"),
        lookup=lambda *a: pytest.fail("the owner does not look up its own receipt"),
    )
    approval, artifact = approved()
    result = owner.execute(approval=approval, artifact=artifact)
    owner.close()
    assert result.execution_state == EXECUTION_UNKNOWN
    return approval, artifact


# ---------------------------------------------------------------------------
# 1. Identity: read from the kernel and machine, recorded in the intent
# ---------------------------------------------------------------------------


def test_local_identity_reads_the_kernel_boot_id_and_machine_id(tmp_path):
    boot = tmp_path / "boot_id"
    boot.write_text("ed78d68d-3aa3-481c-84ab-c736418ffa17\n")
    machine = tmp_path / "machine-id"
    machine.write_text("0d0af05ee8fd4dc29275718f2ce4dff1\n")
    identity = local_identity(boot_id_path=str(boot), machine_id_paths=(str(tmp_path / "absent"), str(machine)))
    assert identity.boot_id == "ed78d68d-3aa3-481c-84ab-c736418ffa17"
    assert identity.machine_id == "0d0af05ee8fd4dc29275718f2ce4dff1"
    assert identity.host == socket.gethostname() and identity.pid == os.getpid()


@pytest.mark.parametrize("content", ["", "short", "not an id at all!!", "x" * 65])
def test_a_missing_or_malformed_id_is_none_never_a_placeholder(tmp_path, content):
    bad = tmp_path / "id"
    bad.write_text(content)
    identity = local_identity(boot_id_path=str(bad), machine_id_paths=(str(bad), str(tmp_path / "absent")))
    assert identity.boot_id is None and identity.machine_id is None


def test_the_intent_records_its_owner(tmp_path):
    ledger = SqliteLedger(tmp_path / "audit.db")
    leave_pending_intent(tmp_path, ledger, HOST_A)
    (_, intent), (_, unknown) = events(ledger)
    assert intent["owner_host"] == "host-a" and intent["owner_boot_id"] == "boot-a"
    assert intent["owner_machine_id"] == "machine-a" and intent["owner_pid"] == 101
    assert unknown["execution_state"] == EXECUTION_UNKNOWN
    ledger.close()


# ---------------------------------------------------------------------------
# 2. The assessment rules
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "recorded,local,established,basis",
    [
        (HOST_A, HOST_A, True, OWNER_SAME_KERNEL),
        (HOST_A, HOST_A_SAME_KERNEL, True, OWNER_SAME_KERNEL),   # another container, same kernel
        (HOST_A, HOST_A_REBOOTED, True, OWNER_REBOOTED),
        (HOST_A, HOST_B, False, OWNER_FOREIGN),
        (HOST_A, OwnerIdentity("host-a", "boot-x", "machine-b", 1), False, OWNER_FOREIGN),  # same name, other machine
        (HOST_A, OwnerIdentity("host-c", "boot-x", "machine-a", 1), False, OWNER_FOREIGN),  # same machine id, other name
        (OwnerIdentity("host-a", None, "machine-a", 1), OwnerIdentity("host-a", None, "machine-a", 2), True, OWNER_REBOOTED),
        (OwnerIdentity("host-a", None, None, 1), OwnerIdentity("host-a", None, None, 2), False, OWNER_FOREIGN),
    ],
    ids=["same-process", "same-kernel-other-container", "rebooted", "other-host",
         "same-name-other-machine", "same-machine-other-name", "no-boot-ids-same-machine", "nothing-to-compare"],
)
def test_assess_owner(recorded, local, established, basis):
    # Both runners hold the same lock object here (one store inode); the lock
    # identity's own rules are in test_lock_identity.py.
    payload = {**recorded.as_payload(), "owner_lock_id": "8:4242"}
    assessment = assess_owner(payload, local, lock_id="8:4242")
    assert assessment.established is established and assessment.basis == basis


def test_an_intent_without_identity_is_legacy_and_never_established():
    assessment = assess_owner({"execution_id": "x", "artifact_sha256": "y"}, HOST_B, lock_id="8:1")
    assert not assessment.established and assessment.basis == OWNER_LEGACY


# ---------------------------------------------------------------------------
# 3. The race, failing closed
# ---------------------------------------------------------------------------


def test_a_foreign_owner_is_never_declared_not_committed(tmp_path, caplog):
    """Host A leaves a pending intent. Host B, sharing the ledger and store,
    finds no receipt (A has not connected yet). Before this change B recorded
    reconciled_not_committed; now it cannot place A and leaves the intent."""

    caplog.set_level(logging.WARNING, logger=RUNNER_LOGGER)
    ledger = SqliteLedger(tmp_path / "audit.db")
    approval, artifact = leave_pending_intent(tmp_path, ledger, HOST_A)
    lookups: list[object] = []
    executions: list[object] = []

    def lookup(*args):
        lookups.append(args)
        return ReceiptStatus(RECEIPT_NOT_FOUND)

    host_b = runner(tmp_path, ledger, HOST_B, executor=lambda *a: executions.append(a), lookup=lookup)
    report = host_b.reconcile_unfinished()
    assert len(report) == 1 and not report[0].resolved
    assert report[0].state == OWNER_UNVERIFIABLE
    assert "host-a" in report[0].detail and "cannot be established" in report[0].detail
    assert lookups == [], "a receipt is not consulted for an owner that may still be about to write one"

    # The pending intent blocks new work on the target without spending its approval.
    next_approval, next_artifact = approved("SELECT 2")
    blocked = host_b.execute(approval=next_approval, artifact=next_artifact)
    assert blocked.refused and blocked.reason == RECONCILIATION_REQUIRED
    assert executions == []
    recorded = events(ledger)
    assert [event for event, _ in recorded] == ["execute_intent", "execute_unknown", "refuse"]
    assert recorded[-1][1]["reconciliation_state"] == OWNER_UNVERIFIABLE
    assert not any(payload.get("reason") == RECONCILED_NOT_COMMITTED for _, payload in recorded)
    host_b.close()

    # A runner on A's kernel holds the lock A would have needed: established.
    host_a_again = runner(tmp_path, ledger, HOST_A_SAME_KERNEL, executor=lambda *a: executions.append(a), lookup=lookup)
    report = host_a_again.reconcile_unfinished()
    assert len(report) == 1 and report[0].resolved and report[0].state == RECEIPT_NOT_FOUND
    outcome = events(ledger)[-1][1]
    assert outcome["reason"] == RECONCILED_NOT_COMMITTED and outcome["owner_basis"] == OWNER_SAME_KERNEL
    assert outcome["owner_override"] is False and outcome["reconciled_by_host"] == "container-on-a"
    assert host_a_again.execute(approval=next_approval, artifact=next_artifact).refused is False
    host_a_again.close()
    ledger.close()


def test_the_execution_path_cannot_assert_the_owner_dead(tmp_path):
    """Only an operator call carries assume_owner_dead; execute() never does,
    however many times it is retried."""

    ledger = SqliteLedger(tmp_path / "audit.db")
    leave_pending_intent(tmp_path, ledger, HOST_A)
    host_b = runner(
        tmp_path, ledger, HOST_B,
        executor=lambda *a: pytest.fail("must not execute"),
        lookup=lambda *a: ReceiptStatus(RECEIPT_NOT_FOUND),
    )
    for sql in ("SELECT 2", "SELECT 3"):
        approval, artifact = approved(sql)
        assert host_b.execute(approval=approval, artifact=artifact).reason == RECONCILIATION_REQUIRED
    assert all(r.state == OWNER_UNVERIFIABLE for r in host_b.reconcile_unfinished())
    host_b.close()
    ledger.close()


def test_the_operator_override_is_explicit_logged_and_recorded(tmp_path, caplog):
    caplog.set_level(logging.WARNING, logger=RUNNER_LOGGER)
    ledger = SqliteLedger(tmp_path / "audit.db")
    leave_pending_intent(tmp_path, ledger, HOST_A)
    host_b = runner(
        tmp_path, ledger, HOST_B,
        executor=lambda *a: pytest.fail("reconciliation never executes SQL"),
        lookup=lambda *a: ReceiptStatus(RECEIPT_NOT_FOUND),
    )
    assert host_b.reconcile_unfinished()[0].state == OWNER_UNVERIFIABLE
    report = host_b.reconcile_unfinished(assume_owner_dead=True)
    assert len(report) == 1 and report[0].resolved and report[0].state == RECEIPT_NOT_FOUND
    outcome = events(ledger)[-1][1]
    assert outcome["reason"] == RECONCILED_NOT_COMMITTED
    assert outcome["owner_override"] is True and outcome["owner_basis"] == OWNER_FOREIGN
    assert outcome["reconciled_by_host"] == "host-b"
    warned = [r.getMessage() for r in caplog.records if r.name == RUNNER_LOGGER and r.levelno == logging.WARNING]
    assert any("assume_owner_dead=True" in text and "host-a" in text for text in warned)
    assert host_b.reconcile_unfinished() == ()
    host_b.close()
    ledger.close()


def test_the_same_machine_after_a_reboot_is_established(tmp_path):
    ledger = SqliteLedger(tmp_path / "audit.db")
    leave_pending_intent(tmp_path, ledger, HOST_A)
    rebooted = runner(
        tmp_path, ledger, HOST_A_REBOOTED,
        executor=lambda *a: pytest.fail("must not execute"),
        lookup=lambda *a: ReceiptStatus(RECEIPT_NOT_FOUND),
    )
    report = rebooted.reconcile_unfinished()
    assert len(report) == 1 and report[0].resolved and report[0].state == RECEIPT_NOT_FOUND
    outcome = events(ledger)[-1][1]
    assert outcome["owner_basis"] == OWNER_REBOOTED and outcome["owner_override"] is False
    rebooted.close()
    ledger.close()


def test_a_legacy_intent_stays_pending_until_the_operator_asserts(tmp_path, caplog):
    """An intent with no owner identity says nothing about its owner, and the
    guard this runner holds says nothing about it either (PROM-FIX-B: no
    held lock is proof unless it is provably the owner's). It is left
    pending; only the operator's explicit assertion resolves it, recorded."""

    caplog.set_level(logging.WARNING, logger=RUNNER_LOGGER)
    ledger = SqliteLedger(tmp_path / "audit.db")
    ledger.record_chained(
        event="execute_intent", subject="x",
        payload={"target": target().identity.canonical, "artifact_sha256": "b" * 64, "execution_id": "a" * 64},
        created_at="1",
    )
    lookups: list[object] = []

    def lookup(*args):
        lookups.append(args)
        return ReceiptStatus(RECEIPT_NOT_FOUND)

    host_b = runner(tmp_path, ledger, HOST_B, executor=lambda *a: pytest.fail("must not execute"), lookup=lookup)
    report = host_b.reconcile_unfinished()
    assert len(report) == 1 and not report[0].resolved and report[0].state == OWNER_UNVERIFIABLE
    assert lookups == [] and not any(e == "execute_outcome" for e, _ in events(ledger))
    forced = host_b.reconcile_unfinished(assume_owner_dead=True)
    assert forced[0].resolved and forced[0].state == RECEIPT_NOT_FOUND
    outcome = events(ledger)[-1][1]
    assert outcome["owner_basis"] == OWNER_LEGACY and outcome["owner_override"] is True
    assert any("assume_owner_dead=True" in r.getMessage() for r in caplog.records if r.name == RUNNER_LOGGER)
    host_b.close()
    ledger.close()


def test_the_default_identity_is_this_host(tmp_path):
    ledger = SqliteLedger(tmp_path / "audit.db")
    r = BrokeredMigrationRunner(
        authority=ApprovalAuthority(key=KEY), target=target(),
        consumed=ConsumedApprovals(tmp_path / "store.db"),
        executor=lambda *a: ExecutorResult(EXECUTION_UNKNOWN), receipt_lookup=lambda *a: ReceiptStatus(RECEIPT_NOT_FOUND),
        audit=ledger, clock=lambda: 1001,
    )
    assert r.identity.host == socket.gethostname() and r.identity.pid == os.getpid()
    r.close()
    ledger.close()
