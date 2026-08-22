"""The tamper-evident audit chain: every tamper shape proven DETECTED (or its
limit honestly stated). Tampering is done via direct SQL on the ledger's own
connection — i.e. an adversary who reached the file, which is exactly the threat.
"""

from __future__ import annotations

import json
import threading

import pytest

from prometheus_protocol.chokepoint import (
    AUDIT_OUTCOME_UNAVAILABLE,
    RECEIPT_COMMITTED,
    RECEIPT_NOT_FOUND,
    RECEIPT_UNAVAILABLE,
    RECONCILED_COMMITTED,
    RECONCILED_NOT_COMMITTED,
    RECONCILIATION_REQUIRED,
    ApprovalAuthority,
    BrokeredMigrationRunner,
    ConsumedApprovals,
    DbTarget,
    MigrationArtifact,
    ReceiptStatus,
    execution_id_for,
)
from prometheus_protocol.core.models import Judgment, Verdict
from prometheus_protocol.ledger.audit_chain import (
    BROKEN,
    GENESIS_ROOT,
    NOT_VERIFIABLE,
    TRUNCATED,
    VALID,
    canonical_json,
    entry_hash,
    verify_rows,
)
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger


def _ledger_with(n: int) -> SqliteLedger:
    led = SqliteLedger(":memory:")
    for i in range(1, n + 1):
        led.record_chained(event="execute", subject="appdb@h:5432",
                           payload={"i": i, "reason": "ok"}, created_at=f"t{i}")
    return led


class _ReceiptBackend:
    """In-memory model of the executor's atomic database receipt."""

    def __init__(self, *, terminate: bool = False) -> None:
        self.terminate = terminate
        self.calls: list[str] = []
        self.receipts: dict[str, tuple[str, str]] = {}

    def __call__(
        self,
        sql: str,
        target: DbTarget,
        execution_id: str,
        artifact_sha256: str,
    ) -> tuple[bool, str]:
        self.calls.append(execution_id)
        if self.terminate:
            raise SystemExit("simulated process termination during transaction")
        self.receipts[execution_id] = (
            artifact_sha256,
            target.identity.canonical,
        )
        return True, "ok"

    def lookup(
        self, execution_id: str, artifact_sha256: str, target: DbTarget
    ) -> ReceiptStatus:
        receipt = self.receipts.get(execution_id)
        if receipt is None:
            return ReceiptStatus(RECEIPT_NOT_FOUND)
        if receipt != (artifact_sha256, target.identity.canonical):
            return ReceiptStatus("conflict")
        return ReceiptStatus(
            RECEIPT_COMMITTED,
            committed_at="2026-08-22T12:00:00+00:00",
        )


# -- happy + structure --------------------------------------------------------

def test_clean_chain_verifies():
    led = _ledger_with(5)
    result = led.verify_chain()
    assert result.ok and result.status == VALID and result.length == 5
    assert result.render() == "chain valid (5 entries)"


def test_first_entry_chains_onto_genesis_root():
    led = _ledger_with(1)
    row = led.chained_events()[0]
    assert row["prev_hash"] == GENESIS_ROOT
    assert row["seq"] == 1


def test_append_chains_onto_current_tip_by_construction():
    # The caller cannot supply prev_hash — each entry links to the real tip, so
    # a forged-prior-hash append is impossible through the API.
    led = _ledger_with(3)
    rows = led.chained_events()
    assert rows[1]["prev_hash"] == rows[0]["entry_hash"]
    assert rows[2]["prev_hash"] == rows[1]["entry_hash"]


# -- the six tamper shapes ----------------------------------------------------

def test_tamper_middle_edit_detected():
    led = _ledger_with(5)
    # Edit a field of a middle entry WITHOUT recomputing its hash.
    led._conn.execute("UPDATE audit_chain SET payload=? WHERE seq=3",
                      (json.dumps({"i": 999, "reason": "forged"}),))
    led._conn.commit()
    r = led.verify_chain()
    assert r.status == BROKEN and r.broken_index == 3
    assert "content edited" in r.detail


def test_tamper_middle_with_rehash_detected_at_next_link():
    # A smarter attacker edits entry 3 AND recomputes its hash to be
    # self-consistent — but cannot fix entry 4's prev_hash without rewriting the
    # rest, so it is caught at the next link.
    led = _ledger_with(5)
    rows = led.chained_events()
    forged_payload = canonical_json({"i": 999, "reason": "forged"})
    forged_hash = entry_hash(
        seq=3, created_at=rows[2]["created_at"], event=rows[2]["event"],
        subject=rows[2]["subject"], payload_canonical=forged_payload,
        prev_hash=rows[2]["prev_hash"],
    )
    led._conn.execute("UPDATE audit_chain SET payload=?, entry_hash=? WHERE seq=3",
                      (forged_payload, forged_hash))
    led._conn.commit()
    r = led.verify_chain()
    assert r.status == BROKEN and r.broken_index == 4
    assert "prev-hash mismatch" in r.detail


def test_delete_interior_entry_detected():
    led = _ledger_with(5)
    led._conn.execute("DELETE FROM audit_chain WHERE seq=3")
    led._conn.commit()
    r = led.verify_chain()
    assert r.status == BROKEN and r.broken_index == 4
    assert "discontinuity" in r.detail


def test_reorder_detected():
    led = _ledger_with(5)
    # Swap the content of entries 2 and 3 (keep the seq column) — a reorder.
    rows = {row["seq"]: row for row in led.chained_events()}
    a, b = rows[2], rows[3]
    for seq, src in ((2, b), (3, a)):
        led._conn.execute(
            "UPDATE audit_chain SET created_at=?, event=?, subject=?, payload=?, "
            "prev_hash=?, entry_hash=? WHERE seq=?",
            (src["created_at"], src["event"], src["subject"], src["payload"],
             src["prev_hash"], src["entry_hash"], seq),
        )
    led._conn.commit()
    r = led.verify_chain()
    assert r.status == BROKEN and r.broken_index == 2


def test_append_forgery_with_wrong_prev_detected():
    led = _ledger_with(3)
    # Bypass the API and insert seq 4 with a fabricated prev_hash.
    forged_prev = "00" * 32
    forged_hash = entry_hash(seq=4, created_at="t4", event="execute",
                             subject="x", payload_canonical="{}", prev_hash=forged_prev)
    led._conn.execute(
        "INSERT INTO audit_chain (seq, created_at, event, subject, payload, "
        "prev_hash, entry_hash) VALUES (4,'t4','execute','x','{}',?,?)",
        (forged_prev, forged_hash),
    )
    led._conn.commit()
    r = led.verify_chain()
    assert r.status == BROKEN and r.broken_index == 4
    assert "prev-hash mismatch" in r.detail


def test_truncation_is_undetectable_without_an_anchor():
    # Honest limit: a bare chain cannot detect pure tail-truncation — the
    # remaining prefix is a perfectly valid chain.
    led = _ledger_with(5)
    led._conn.execute("DELETE FROM audit_chain WHERE seq > 3")
    led._conn.commit()
    r = led.verify_chain()  # no anchor
    assert r.status == VALID and r.length == 3  # cannot tell 2 entries were lopped


def test_truncation_detected_with_anchor():
    led = _ledger_with(5)
    tip = led.chain_tip()  # held out-of-band by the auditor
    led._conn.execute("DELETE FROM audit_chain WHERE seq > 3")
    led._conn.commit()
    r = led.verify_chain(expected_tip=tip)
    assert r.status == TRUNCATED and "truncated" in r.detail


def test_rewritten_tip_detected_with_anchor():
    led = _ledger_with(3)
    tip = led.chain_tip()
    # Rewrite the tip entry's content and re-hash it self-consistently.
    rows = led.chained_events()
    forged_payload = canonical_json({"i": 3, "reason": "rewritten"})
    forged_hash = entry_hash(seq=3, created_at=rows[2]["created_at"],
                             event=rows[2]["event"], subject=rows[2]["subject"],
                             payload_canonical=forged_payload, prev_hash=rows[2]["prev_hash"])
    led._conn.execute("UPDATE audit_chain SET payload=?, entry_hash=? WHERE seq=3",
                      (forged_payload, forged_hash))
    led._conn.commit()
    r = led.verify_chain(expected_tip=tip)
    assert r.status == BROKEN and "anchored tip" in r.detail


# -- couldn't-verify is not verified-clean (EX-1 applied to the ledger) -------

def test_missing_field_is_not_verifiable_not_valid():
    # A raw-file attacker (or corruption) can produce a row the schema's NOT NULL
    # would forbid via the connection. The standalone auditor must report such a
    # row NOT_VERIFIABLE — never silently valid (the EX-1 distinction).
    led = _ledger_with(3)
    rows = led.chained_events()
    rows[1]["entry_hash"] = None  # a corrupt/missing hash the reader must not trust
    r = verify_rows(rows)
    assert r.status == NOT_VERIFIABLE and not r.ok
    # And the "never valid by default" guarantee: a clean run of the same rows IS valid.
    assert verify_rows(led.chained_events()).ok


def test_malformed_payload_is_not_verifiable():
    led = _ledger_with(3)
    led._conn.execute("UPDATE audit_chain SET payload=? WHERE seq=2", ("{not json",))
    led._conn.commit()
    r = led.verify_chain()
    assert r.status == NOT_VERIFIABLE and not r.ok


# -- regressions from the adversarial review (each was a real, confirmed defect) --

def test_bytewise_payload_edit_detected_even_if_it_reparses_equal():
    # A duplicate-key edit that json.loads normalizes (last-wins) back to the
    # original object. The hash must commit to the exact stored BYTES, so this is
    # caught — not read as VALID while chained_events() returns the forged bytes.
    led = _ledger_with(3)
    forged = '{"reason":"forged","reason":"ok","i":2}'  # reparses to {"i":2,"reason":"ok"}
    assert json.loads(forged) == json.loads('{"i":2,"reason":"ok"}')  # same object
    led._conn.execute("UPDATE audit_chain SET payload=? WHERE seq=2", (forged,))
    led._conn.commit()
    r = led.verify_chain()
    assert r.status == BROKEN and r.broken_index == 2 and "content edited" in r.detail


def test_honest_append_past_anchor_stays_valid():
    # The anchor is a point-in-time snapshot; legitimate appends grow the chain.
    led = _ledger_with(5)
    tip = led.chain_tip()  # seq 5
    for i in range(6, 9):
        led.record_chained(event="execute", subject="appdb@h:5432",
                           payload={"i": i, "reason": "ok"}, created_at=f"t{i}")
    r = led.verify_chain(expected_tip=tip)
    assert r.ok and r.length == 8  # anchor at seq 5 still matches; growth is fine


def test_full_rewrite_then_extend_detected_with_anchor():
    # A full rewrite that ALSO extends the chain past the anchored seq must not
    # slip through just by being longer than the anchor.
    led = _ledger_with(5)
    tip = led.chain_tip()  # seq 5, the honest tip hash
    led._conn.execute("DELETE FROM audit_chain")
    led._conn.commit()
    for i in range(1, 7):  # rebuild a self-consistent chain of length 6, all forged
        led.record_chained(event="execute", subject="FORGED",
                           payload={"i": i}, created_at=f"x{i}")
    r = led.verify_chain(expected_tip=tip)
    assert r.status == BROKEN and "anchored tip" in r.detail


def test_none_field_is_not_verifiable_not_a_crash():
    # A None created_at/event/subject (raw-file corruption) must report
    # NOT_VERIFIABLE, never raise AttributeError out of the auditor.
    led = _ledger_with(2)
    for field in ("created_at", "event", "subject"):
        rows = led.chained_events()
        rows[1][field] = None
        r = verify_rows(rows)  # must not raise
        assert r.status == NOT_VERIFIABLE and not r.ok, f"None {field} should be NOT_VERIFIABLE"


def test_concurrent_appends_serialize_into_one_valid_chain(tmp_path):
    # Two connections appending to the same ledger file concurrently must produce
    # one unbroken, contiguous chain — no raw sqlite error, no duplicate seq.
    path = str(tmp_path / "ledger.db")
    SqliteLedger(path).close()  # create the schema once
    barrier = threading.Barrier(2)
    errors: list[Exception] = []

    def worker(tag: str, k: int) -> None:
        led = SqliteLedger(path)
        try:
            barrier.wait()
            for i in range(k):
                led.record_chained(event="execute", subject=tag,
                                   payload={"i": i}, created_at=f"{tag}-{i}")
        except Exception as exc:  # noqa: BLE001 - any escaping error fails the test
            errors.append(exc)
        finally:
            led.close()

    threads = [threading.Thread(target=worker, args=("A", 25)),
               threading.Thread(target=worker, args=("B", 25))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"append raised under concurrency: {errors}"
    led = SqliteLedger(path)
    try:
        assert led.verify_chain().ok
        seqs = [e["seq"] for e in led.chained_events()]
        assert seqs == list(range(1, 51))  # 50 contiguous entries, no gaps/dupes
    finally:
        led.close()


# -- integration: the chokepoint's decisions ARE chained, and tamper is caught -

def test_chokepoint_decisions_are_chained_and_tamper_is_detected(tmp_path):
    led = SqliteLedger(":memory:")
    auth = ApprovalAuthority()
    target = DbTarget(host="127.0.0.1", port=5432, dbname="appdb",
                      user="migrator", password="secret")
    art = MigrationArtifact("CREATE TABLE t (id int);")

    class _Spy:
        def __call__(self, sql, tgt, execution_id, artifact_sha256):
            return True, "ok"

    t = [1000.0]
    runner = BrokeredMigrationRunner(
        authority=auth, target=target,
        consumed=ConsumedApprovals(tmp_path / "consumed.db"),
        executor=_Spy(),
        receipt_lookup=lambda execution_id, artifact_sha256, bound: ReceiptStatus(
            RECEIPT_NOT_FOUND
        ),
        audit=led, clock=lambda: t[0],
    )
    judgment = Judgment(verdict=Verdict.PASS, confidence=1.0, authoritative=True)
    approval = auth.authorize(judgment, artifact=art, target=target.identity, now=t[0])

    # The gate records mint; the runner records durable intent, outcome, then refusal.
    led.record_chained(event="authorize", subject=target.identity.canonical,
                      payload={"artifact_sha256": art.sha256}, created_at="t-mint")
    assert runner.execute(approval=approval, artifact=art).executed      # -> execute
    assert runner.execute(approval=approval, artifact=art).refused       # -> refuse (replay)

    events = [e["event"] for e in led.chained_events()]
    assert events == ["authorize", "execute_intent", "execute_outcome", "refuse"]
    outcome_payload = json.loads(led.chained_events()[2]["payload"])
    assert outcome_payload["intent_seq"] == 2
    assert led.verify_chain().ok

    # An adversary edits the "refuse" record to hide the replay attempt.
    led._conn.execute("UPDATE audit_chain SET event='execute' WHERE seq=4")
    led._conn.commit()
    r = led.verify_chain()
    assert r.status == BROKEN and r.broken_index == 4


def test_execution_intent_survives_restart_when_outcome_append_fails(tmp_path):
    path = tmp_path / "durable-audit.db"
    ledger = SqliteLedger(path)

    class _FailOutcome:
        def record_chained(self, **event):
            if event["event"] == "execute_outcome":
                raise OSError("simulated audit outage")
            return ledger.record_chained(**event)

        def chained_events(self):
            return ledger.chained_events()

        def verify_chain(self):
            return ledger.verify_chain()

    class _Spy:
        def __call__(self, sql, target, execution_id, artifact_sha256):
            return True, "ok"

    authority = ApprovalAuthority()
    target = DbTarget(
        host="127.0.0.1",
        port=5432,
        dbname="appdb",
        user="migrator",
        password="secret",
    )
    artifact = MigrationArtifact("CREATE TABLE durable_intent (id int);")
    approval = authority.mint(
        artifact_sha256=artifact.sha256, target=target.identity, now=1_000.0
    )
    runner = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=ConsumedApprovals(tmp_path / "durable-intent-consumed.db"),
        executor=_Spy(),
        receipt_lookup=lambda execution_id, artifact_sha256, bound: ReceiptStatus(
            RECEIPT_NOT_FOUND
        ),
        audit=_FailOutcome(),
        clock=lambda: 1_001.0,
    )

    result = runner.execute(approval=approval, artifact=artifact)
    assert result.executed and result.reason == AUDIT_OUTCOME_UNAVAILABLE
    runner.close()
    ledger.close()

    reopened = SqliteLedger(path)
    try:
        events = reopened.chained_events()
        assert [event["event"] for event in events] == ["execute_intent"]
        assert json.loads(events[0]["payload"])["artifact_sha256"] == artifact.sha256
        assert reopened.verify_chain().ok
    finally:
        reopened.close()


def test_execution_id_is_stable_and_bound_to_nonce_artifact_and_target():
    authority = ApprovalAuthority()
    target = DbTarget(
        host="db.internal",
        port=5432,
        dbname="appdb",
        user="migrator",
        password="secret",
    )
    artifact = MigrationArtifact("CREATE TABLE stable_id (id int);")
    approval = authority.mint(
        artifact_sha256=artifact.sha256,
        target=target.identity,
        now=1_000.0,
    )

    first = execution_id_for(
        approval=approval, artifact=artifact, target=target.identity
    )
    assert first == execution_id_for(
        approval=approval, artifact=artifact, target=target.identity
    )
    other_approval = authority.mint(
        artifact_sha256=artifact.sha256,
        target=target.identity,
        now=1_000.0,
    )
    assert first != execution_id_for(
        approval=other_approval, artifact=artifact, target=target.identity
    )


def test_restart_reconciles_committed_receipt_after_outcome_audit_failure(tmp_path):
    path = tmp_path / "committed-reconcile.db"
    ledger = SqliteLedger(path)

    class _FailOutcome:
        def record_chained(self, **event):
            if event["event"] == "execute_outcome":
                raise SystemExit("simulated termination before outcome audit")
            return ledger.record_chained(**event)

        def chained_events(self):
            return ledger.chained_events()

        def verify_chain(self):
            return ledger.verify_chain()

    authority = ApprovalAuthority()
    target = DbTarget(
        host="db.internal",
        port=5432,
        dbname="appdb",
        user="migrator",
        password="secret",
    )
    artifact = MigrationArtifact("CREATE TABLE committed_before_crash (id int);")
    approval = authority.mint(
        artifact_sha256=artifact.sha256,
        target=target.identity,
        now=1_000.0,
    )
    backend = _ReceiptBackend()
    runner = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=ConsumedApprovals(tmp_path / "committed-consumed.db"),
        executor=backend,
        receipt_lookup=backend.lookup,
        audit=_FailOutcome(),
        clock=lambda: 1_001.0,
    )
    with pytest.raises(SystemExit, match="termination before outcome audit"):
        runner.execute(approval=approval, artifact=artifact)
    execution_id = backend.calls[-1]
    assert execution_id in backend.receipts
    runner.close()
    ledger.close()

    reopened = SqliteLedger(path)
    restarted = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=ConsumedApprovals(tmp_path / "committed-consumed.db"),
        executor=backend,
        receipt_lookup=backend.lookup,
        audit=reopened,
        clock=lambda: 1_002.0,
    )
    try:
        report = restarted.reconcile_unfinished()
        assert len(report) == 1
        assert report[0].resolved and report[0].state == RECEIPT_COMMITTED
        events = reopened.chained_events()
        assert [event["event"] for event in events] == [
            "execute_intent",
            "execute_outcome",
        ]
        outcome = json.loads(events[-1]["payload"])
        assert outcome["execution_id"] == execution_id
        assert outcome["reason"] == RECONCILED_COMMITTED
        assert outcome["reconciled"] is True
    finally:
        restarted.close()
        reopened.close()


def test_restart_records_not_committed_after_termination_during_transaction(tmp_path):
    path = tmp_path / "terminated-reconcile.db"
    ledger = SqliteLedger(path)
    authority = ApprovalAuthority()
    target = DbTarget(
        host="db.internal",
        port=5432,
        dbname="appdb",
        user="migrator",
        password="secret",
    )
    artifact = MigrationArtifact("CREATE TABLE killed_transaction (id int);")
    approval = authority.mint(
        artifact_sha256=artifact.sha256,
        target=target.identity,
        now=1_000.0,
    )
    backend = _ReceiptBackend(terminate=True)
    runner = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=ConsumedApprovals(tmp_path / "terminated-consumed.db"),
        executor=backend,
        receipt_lookup=backend.lookup,
        audit=ledger,
        clock=lambda: 1_001.0,
    )
    with pytest.raises(SystemExit, match="simulated process termination"):
        runner.execute(approval=approval, artifact=artifact)
    runner.close()
    ledger.close()

    backend.terminate = False
    reopened = SqliteLedger(path)
    restarted = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=ConsumedApprovals(tmp_path / "terminated-consumed.db"),
        executor=backend,
        receipt_lookup=backend.lookup,
        audit=reopened,
        clock=lambda: 1_002.0,
    )
    try:
        report = restarted.reconcile_unfinished()
        assert len(report) == 1
        assert report[0].resolved and report[0].state == RECEIPT_NOT_FOUND
        outcome = json.loads(reopened.chained_events()[-1]["payload"])
        assert outcome["reason"] == RECONCILED_NOT_COMMITTED
        assert outcome["ok"] is False
    finally:
        restarted.close()
        reopened.close()


def test_restart_records_not_committed_after_termination_before_executor(tmp_path):
    path = tmp_path / "pre-executor-reconcile.db"
    ledger = SqliteLedger(path)

    class _TerminateAfterIntent:
        def record_chained(self, **event):
            seq = ledger.record_chained(**event)
            if event["event"] == "execute_intent":
                raise SystemExit("simulated termination after durable intent")
            return seq

        def chained_events(self):
            return ledger.chained_events()

        def verify_chain(self):
            return ledger.verify_chain()

    authority = ApprovalAuthority()
    target = DbTarget(
        host="db.internal",
        port=5432,
        dbname="appdb",
        user="migrator",
        password="secret",
    )
    artifact = MigrationArtifact("CREATE TABLE never_reached_executor (id int);")
    approval = authority.mint(
        artifact_sha256=artifact.sha256,
        target=target.identity,
        now=1_000.0,
    )
    backend = _ReceiptBackend()
    runner = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=ConsumedApprovals(tmp_path / "pre-executor-consumed.db"),
        executor=backend,
        receipt_lookup=backend.lookup,
        audit=_TerminateAfterIntent(),
        clock=lambda: 1_001.0,
    )
    with pytest.raises(SystemExit, match="termination after durable intent"):
        runner.execute(approval=approval, artifact=artifact)
    assert backend.calls == []
    runner.close()
    ledger.close()

    reopened = SqliteLedger(path)
    restarted = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=ConsumedApprovals(tmp_path / "pre-executor-consumed.db"),
        executor=backend,
        receipt_lookup=backend.lookup,
        audit=reopened,
        clock=lambda: 1_002.0,
    )
    try:
        report = restarted.reconcile_unfinished()
        assert len(report) == 1
        assert report[0].resolved and report[0].state == RECEIPT_NOT_FOUND
        outcome = json.loads(reopened.chained_events()[-1]["payload"])
        assert outcome["reason"] == RECONCILED_NOT_COMMITTED
    finally:
        restarted.close()
        reopened.close()


def test_unavailable_receipt_blocks_all_further_database_execution(tmp_path):
    ledger = SqliteLedger(tmp_path / "blocked-reconcile.db")
    authority = ApprovalAuthority()
    target = DbTarget(
        host="db.internal",
        port=5432,
        dbname="appdb",
        user="migrator",
        password="secret",
    )
    old_artifact = MigrationArtifact("CREATE TABLE unknown_outcome (id int);")
    old_approval = authority.mint(
        artifact_sha256=old_artifact.sha256,
        target=target.identity,
        now=1_000.0,
    )
    old_execution_id = execution_id_for(
        approval=old_approval,
        artifact=old_artifact,
        target=target.identity,
    )
    ledger.record_chained(
        event="execute_intent",
        subject=target.identity.canonical,
        payload={
            "phase": "execute_intent",
            "execution_id": old_execution_id,
            "artifact_sha256": old_artifact.sha256,
            "target": target.identity.canonical,
        },
        created_at="1001.0",
    )

    next_artifact = MigrationArtifact("CREATE TABLE must_not_run (id int);")
    next_approval = authority.mint(
        artifact_sha256=next_artifact.sha256,
        target=target.identity,
        now=1_001.0,
    )
    backend = _ReceiptBackend()
    receipt_state = [RECEIPT_UNAVAILABLE]
    runner = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=ConsumedApprovals(tmp_path / "blocked-consumed.db"),
        executor=backend,
        receipt_lookup=lambda execution_id, artifact_sha256, bound: ReceiptStatus(
            receipt_state[0], detail="database offline"
        ),
        audit=ledger,
        clock=lambda: 1_002.0,
    )
    try:
        result = runner.execute(approval=next_approval, artifact=next_artifact)
        assert result.refused and result.reason == RECONCILIATION_REQUIRED
        assert backend.calls == []

        # Recovery failure does not burn the new approval. Once the old intent
        # can be proven rolled back, the exact same capability may proceed.
        receipt_state[0] = RECEIPT_NOT_FOUND
        retry = runner.execute(approval=next_approval, artifact=next_artifact)
        assert retry.executed and not retry.refused
        assert len(backend.calls) == 1
        assert ledger.verify_chain().ok
    finally:
        runner.close()
        ledger.close()
