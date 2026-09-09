"""F11 checkpoint 2a: real disk + runtime proofs. None of these tests skip.

macOS uses the explicit substrate opt-out only for these persistence tests;
Linux CI uses the actual substrate probe. This is not an isolation proof.
"""

import hashlib
import json
import multiprocessing
import os
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from f11_support import authorization_context

from prometheus_protocol.chokepoint import (
    RECEIPT_NOT_FOUND,
    RECEIPT_UNAVAILABLE,
    Approval,
    DbTarget,
    KmsSigner,
    MemoryKms,
    MigrationArtifact,
    MigrationRunnerConfig,
    ReceiptStatus,
    approval_digest,
    build_migration_runtime,
)
from prometheus_protocol.chokepoint.authorization_journal import (
    AuthorizationUnavailable,
)
from prometheus_protocol.chokepoint.authorization_record import (
    DECISION_EVENT,
    SIGN_RESULT_EVENT,
    AuthorizationRecord,
    binding_preimage,
    canonical_record,
    strict_json,
)
from prometheus_protocol.chokepoint.signer import SignerTimeout
from prometheus_protocol.core.models import (
    Judgment,
    Tier,
    Unavailability,
    Unavailable,
    Verdict,
)
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.ledger.tip_anchor import FileTipAnchor

NOW = 1000.125
ARTIFACT = MigrationArtifact("CREATE TABLE approved (id integer);")
TARGET = DbTarget(
    host="db.internal", port=5432, dbname="appdb", user="migrator", password="db-secret"
)
PASS = Judgment(
    verdict=Verdict.PASS, confidence=1.0, authoritative=True, contributing=("hard",)
)


def runtime_at(
    path,
    *,
    kms=None,
    anchor=None,
    clock=lambda: NOW,
    executor=None,
    receipt_lookup=None,
):
    if kms is None:
        kms = MemoryKms(clock=clock)
        kms.create_key("approval-key")
        kms.grant_sign("approval-key", "runner")
    signer = KmsSigner(kms, key_id="approval-key")
    ledger = SqliteLedger.private(path / "audit.db", tip_anchor=anchor)
    calls = []
    runtime = build_migration_runtime(
        MigrationRunnerConfig(
            target=TARGET,
            approval_store_path=path / "consumed.db",
            signer=signer,
            allow_unverified_substrate=sys.platform != "linux",
        ),
        audit=ledger,
        authorization=authorization_context(signer),
        executor=executor or (lambda *args: calls.append(args) or (True, "committed")),
        receipt_lookup=(
            receipt_lookup
            if receipt_lookup is not None
            else lambda *args: ReceiptStatus(RECEIPT_NOT_FOUND)
        ),
        clock=clock,
        env={},
    )
    return runtime, ledger, kms, calls


@pytest.fixture
def live(tmp_path):
    runtime, ledger, kms, calls = runtime_at(tmp_path)
    yield runtime, ledger, kms, calls
    runtime.close()
    ledger.close()


def authorize(runtime, **kwargs):
    return runtime.authority.authorize(
        PASS, artifact=ARTIFACT, target=TARGET.identity, now=NOW, **kwargs
    )


def decisions(ledger):
    return [
        AuthorizationRecord.from_dict(strict_json(r["payload"]))
        for r in ledger.chained_events()
        if r["event"] == DECISION_EVENT
    ]


def test_runtime_records_before_sign(live, monkeypatch):
    runtime, ledger, kms, calls = live
    original = kms.sign

    def sign(key, digest, **kwargs):
        with sqlite3.connect(ledger.path) as disk:
            (payload,) = disk.execute(
                "SELECT payload FROM audit_chain WHERE event=?", (DECISION_EVENT,)
            ).fetchone()
        record = AuthorizationRecord.from_dict(strict_json(payload))
        assert record.recompute_approval_digest() == digest.hex()
        assert record.to_dict()["decision"] == "authorised"
        return original(key, digest, **kwargs)

    monkeypatch.setattr(kms, "sign", sign)
    approval = authorize(runtime)
    assert isinstance(approval, Approval)
    assert [r["event"] for r in ledger.chained_events()] == [
        DECISION_EVENT,
        SIGN_RESULT_EVENT,
    ]
    result = runtime.runner.execute(approval=approval, artifact=ARTIFACT)
    assert result.executed and len(calls) == 1
    for row in ledger.chained_events()[2:]:
        binding = strict_json(row["payload"])["approval_binding"]
        assert binding["issued_at"] == approval.issued_at.hex()
        assert binding["expires_at"] == approval.expires_at.hex()
        assert hashlib.sha256(binding_preimage(binding)).hexdigest() == approval_digest(
            approval
        )
    assert ledger.verify_chain().ok


def _disk_digest_process(path, output):
    # Spawned fresh interpreter, no Approval object / signer / live digest cache.
    with sqlite3.connect(path) as disk:
        (payload,) = disk.execute(
            "SELECT payload FROM audit_chain WHERE event=?", (DECISION_EVENT,)
        ).fetchone()
    record = AuthorizationRecord.from_dict(strict_json(payload))
    output.put(record.recompute_approval_digest())


def test_digest_recomputed_from_disk(live):
    runtime, ledger, _kms, _calls = live
    approval = authorize(runtime)
    expected = approval_digest(approval)
    runtime.close()
    ledger.close()
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    process = context.Process(target=_disk_digest_process, args=(ledger.path, output))
    process.start()
    try:
        assert output.get(timeout=20) == expected
        process.join(20)
        assert process.exitcode == 0
    finally:
        if process.is_alive():
            process.terminate()
            process.join(10)
        output.close()


@pytest.mark.parametrize(
    "judgment,reason",
    [
        (
            Judgment(verdict=Verdict.FAIL, confidence=1, authoritative=True),
            "verdict_fail",
        ),
        (
            Judgment(verdict=Verdict.PASS, confidence=1, authoritative=False),
            "non_authoritative",
        ),
        (None, "invalid_request"),
    ],
)
def test_runtime_persists_refusals(live, judgment, reason):
    runtime, ledger, kms, calls = live
    assert (
        runtime.authority.authorize(
            judgment, artifact=ARTIFACT, target=TARGET.identity, now=NOW
        )
        is None
    )
    value = decisions(ledger)[0].to_dict()
    assert value["decision"] == "refused" and value["reason"] == reason
    assert kms.sign_log() == () and calls == []


@pytest.mark.parametrize("ttl", [0, -1, float("nan"), float("inf"), True, 1e-300])
def test_invalid_expiry_is_recorded_without_signing(live, ttl):
    runtime, ledger, kms, calls = live
    assert authorize(runtime, ttl_seconds=ttl) is None
    assert decisions(ledger)[0].to_dict()["reason"] == "invalid_request"
    assert kms.sign_log() == () and calls == []


@pytest.mark.parametrize(
    "fault", ["raise", "false_receipt", "wrong_receipt", "after_commit"]
)
def test_record_failure_stops_real_runtime(live, monkeypatch, fault):
    runtime, _ledger, kms, calls = live
    original = SqliteLedger.record_chained
    invoked = []
    sign = kms.sign
    monkeypatch.setattr(
        kms, "sign", lambda *a, **kw: invoked.append(a) or sign(*a, **kw)
    )

    def append(self, **event):
        if event["event"] == DECISION_EVENT:
            if fault == "false_receipt":
                return True
            if fault == "wrong_receipt":
                return 999
            if fault == "after_commit":
                original(self, **event)
            raise OSError("SECRET-sink-error")
        return original(self, **event)

    monkeypatch.setattr(SqliteLedger, "record_chained", append)
    approval = None
    with pytest.raises(AuthorizationUnavailable) as error:
        approval = authorize(runtime)
        runtime.runner.execute(approval=approval, artifact=ARTIFACT)
    assert approval is None and invoked == [] and kms.sign_log() == () and calls == []
    assert "SECRET" not in str(error.value)


def test_anchor_failure_stops_sign_even_after_local_commit(tmp_path, monkeypatch):
    anchor = FileTipAnchor(tmp_path / "tip.json")
    runtime, ledger, kms, calls = runtime_at(tmp_path, anchor=anchor)
    try:
        monkeypatch.setattr(
            FileTipAnchor,
            "write",
            lambda self, tip: (_ for _ in ()).throw(OSError("failed")),
        )
        with pytest.raises(AuthorizationUnavailable):
            authorize(runtime)
        assert len(decisions(ledger)) == 1  # committed, but no acknowledged witness
        assert kms.sign_log() == () and calls == []
    finally:
        runtime.close()
        ledger.close()


def test_signed_result_failure_withholds_approval(live, monkeypatch):
    runtime, ledger, kms, calls = live
    original = SqliteLedger.record_chained

    def append(self, **event):
        if event["event"] == SIGN_RESULT_EVENT:
            raise OSError("failed")
        return original(self, **event)

    monkeypatch.setattr(SqliteLedger, "record_chained", append)
    with pytest.raises(AuthorizationUnavailable):
        authorize(runtime)
    assert len(decisions(ledger)) == 1 and len(kms.sign_log()) == 1 and calls == []


def test_lost_sign_reply_has_durable_decision(live, monkeypatch):
    runtime, ledger, kms, calls = live
    original = kms.sign

    def sign(*a, **kw):
        original(*a, **kw)
        from prometheus_protocol.chokepoint.signer import KmsTimeout

        raise KmsTimeout("lost reply")

    monkeypatch.setattr(kms, "sign", sign)
    with pytest.raises(SignerTimeout):
        authorize(runtime)
    assert len(kms.sign_log()) == 1
    assert decisions(ledger)[0].recompute_approval_digest() == kms.sign_log()[0].digest
    result = strict_json(ledger.chained_events()[-1]["payload"])
    assert result["state"] == "outcome_unknown" and result["approval"] is None
    assert calls == []


def test_no_production_mint_bypass(live):
    runtime, _ledger, kms, calls = live
    with pytest.raises(AuthorizationUnavailable, match="authorize"):
        runtime.authority.mint(
            artifact_sha256=ARTIFACT.sha256, target=TARGET.identity, now=NOW
        )
    assert kms.sign_log() == () and calls == []


def test_expiry_during_recording_never_signs(tmp_path, monkeypatch):
    now = [NOW]
    runtime, ledger, kms, calls = runtime_at(tmp_path, clock=lambda: now[0])
    original = runtime.authority.journal.record_decision

    def append(record):
        receipt = original(record)
        now[0] += 100
        return receipt

    monkeypatch.setattr(runtime.authority.journal, "record_decision", append)
    try:
        with pytest.raises(AuthorizationUnavailable, match="elapsed"):
            authorize(runtime)
        assert kms.sign_log() == () and calls == []
    finally:
        runtime.close()
        ledger.close()


def test_concurrent_threads_write_distinct_durable_decisions(live):
    runtime, ledger, kms, _calls = live
    with ThreadPoolExecutor(max_workers=4) as pool:
        approvals = list(pool.map(lambda _: authorize(runtime), range(12)))
    records = runtime.authority.journal.records()
    assert (
        len(records) == len(kms.sign_log()) == len({a.nonce for a in approvals}) == 12
    )
    assert {r.recompute_approval_digest() for r in records} == {
        approval_digest(a) for a in approvals
    }
    assert ledger.verify_chain().ok


def test_duplicate_decision_is_never_resigned(live, monkeypatch):
    runtime, ledger, kms, _calls = live
    authorize(runtime)
    record = decisions(ledger)[0]
    with pytest.raises(AuthorizationUnavailable, match="already recorded"):
        runtime.authority.journal.record_decision(record)
    assert len(kms.sign_log()) == 1


@pytest.mark.parametrize("placement", ["network", "unknown", "local"])
def test_private_storage_separately_mounted_file(tmp_path, monkeypatch, placement):
    from pathlib import Path
    from prometheus_protocol.chokepoint import authorization_journal as journal_module
    from prometheus_protocol.chokepoint.substrate import SubstratePolicy, classify_path
    from prometheus_protocol.core.errors import ConfigError

    ledger = SqliteLedger.private(tmp_path / "mounted.db")
    file = Path(ledger.path).absolute()
    fs = {"network": "nfs4", "unknown": "overlay", "local": "ext4"}[placement]
    table = f"10 10 8:1 / / rw - ext4 root rw\n20 10 0:20 /file {file} rw - {fs} source rw\n"
    queried = []
    def inspect(path):
        queried.append(path)
        assert path == file, "journal queried the parent instead of the existing file"
        return classify_path(str(path), table)
    monkeypatch.setattr(journal_module, "probe_file_substrate", inspect)
    try:
        if placement == "local":
            journal_module.AuthorizationJournal(ledger, substrate_policy=SubstratePolicy(require_verified=True))
        else:
            with pytest.raises(ConfigError):
                journal_module.AuthorizationJournal(ledger, substrate_policy=SubstratePolicy(require_verified=True))
        assert queried == [file]
    finally:
        ledger.close()


def test_private_storage_required(tmp_path):
    from prometheus_protocol.chokepoint.authorization_journal import (
        AuthorizationJournal,
    )
    from prometheus_protocol.chokepoint.substrate import SubstratePolicy

    ledger = SqliteLedger(":memory:")
    try:
        with pytest.raises(AuthorizationUnavailable):
            AuthorizationJournal(
                ledger, substrate_policy=SubstratePolicy(allow_unverified=True)
            )
    finally:
        ledger.close()
    ledger = SqliteLedger(tmp_path / "public.db")
    os.chmod(ledger.path, 0o644)
    try:
        with pytest.raises(PermissionError):
            AuthorizationJournal(
                ledger, substrate_policy=SubstratePolicy(allow_unverified=True)
            )
        assert os.stat(ledger.path).st_mode & 0o777 == 0o644
    finally:
        ledger.close()


@pytest.mark.parametrize(
    "field",
    ["issued_at", "expires_at", "artifact_sha256", "target", "requester", "signer"],
)
def test_record_tampering_is_rejected(live, field):
    runtime, ledger, _kms, _calls = live
    authorize(runtime)
    value = decisions(ledger)[0].to_dict()
    value[field] = None
    with pytest.raises((TypeError, ValueError)):
        AuthorizationRecord.from_dict(value)


def test_encoding_is_stable_and_snapshots_are_immutable(live):
    runtime, ledger, _kms, _calls = live
    authorize(runtime)
    record = decisions(ledger)[0]
    value = record.to_dict()
    value["target"]["schema"] = "changed"
    assert record.to_dict()["target"]["schema"] == "public"
    original = record.to_dict()
    assert (
        AuthorizationRecord.from_dict(dict(reversed(list(original.items())))) == record
    )
    with pytest.raises(ValueError, match="duplicate"):
        strict_json('{"a":1,"a":2}')
    with pytest.raises(ValueError):
        strict_json('{"a":NaN}')


def test_loader_rejects_tampered_ledger(live):
    runtime, ledger, _kms, _calls = live
    authorize(runtime)
    ledger._conn.execute("UPDATE audit_chain SET subject='changed' WHERE seq=1")
    ledger._conn.commit()
    with pytest.raises(AuthorizationUnavailable):
        runtime.authority.journal.records()


def test_unavailable_verifier_has_a_durable_refusal(live):
    runtime, ledger, kms, calls = live
    judgment = Unavailable(
        verifier_id="hard",
        tier=Tier.HARD,
        reason=Unavailability.INFRA_FAULT,
        detail="SECRET-adapter-message",
    )
    assert (
        runtime.authority.authorize(
            judgment, artifact=ARTIFACT, target=TARGET.identity, now=NOW
        )
        is None
    )
    value = decisions(ledger)[0].to_dict()
    assert value["reason"] == "verifier_unavailable"
    assert "SECRET" not in json.dumps(value) and kms.sign_log() == () and calls == []


def test_principal_change_after_record_blocks_sign(live, monkeypatch):
    runtime, ledger, kms, calls = live
    original = runtime.authority.journal.record_decision

    def append(record):
        receipt = original(record)
        runtime.authority.signer._principal = "different-principal"
        return receipt

    monkeypatch.setattr(runtime.authority.journal, "record_decision", append)
    with pytest.raises(AuthorizationUnavailable, match="caller"):
        authorize(runtime)
    assert len(decisions(ledger)) == 1 and kms.sign_log() == () and calls == []


def test_runtime_snapshots_caller_owned_context(tmp_path):
    from prometheus_protocol.chokepoint.signer import LocalHmacSigner

    signer = LocalHmacSigner(b"a" * 32)
    context = authorization_context(signer)
    ledger = SqliteLedger.private(tmp_path / "audit.db")
    runtime = build_migration_runtime(
        MigrationRunnerConfig(
            target=TARGET,
            approval_store_path=tmp_path / "consumed.db",
            signer=signer,
            allow_unverified_substrate=sys.platform != "linux",
        ),
        audit=ledger,
        authorization=context,
        clock=lambda: NOW,
        env={},
    )
    try:
        context.requester["subject"] = "other-requester"
        context.signer["caller_subject"] = "other-caller"
        authorize(runtime)
        assert decisions(ledger)[0].to_dict()["requester"]["subject"] == "requester"
        assert decisions(ledger)[0].to_dict()["signer"]["caller_subject"] == "runner"
    finally:
        runtime.close()
        ledger.close()


def _process_issuance(path, crash, output):
    from pathlib import Path

    from prometheus_protocol.chokepoint.signer import LocalHmacSigner

    path = Path(path)
    signer = LocalHmacSigner(b"p" * 32)
    ledger = SqliteLedger.private(path / "audit.db")
    runtime = build_migration_runtime(
        MigrationRunnerConfig(
            target=TARGET,
            approval_store_path=path / "consumed.db",
            signer=signer,
            allow_unverified_substrate=sys.platform != "linux",
        ),
        audit=ledger,
        authorization=authorization_context(signer),
        clock=lambda: NOW,
        env={},
    )
    if crash:
        append = runtime.authority.journal.record_decision

        def append_then_crash(record):
            append(record)
            os._exit(23)

        runtime.authority.journal.record_decision = append_then_crash
    try:
        approval = authorize(runtime)
        output.put(approval_digest(approval))
    finally:
        runtime.close()
        ledger.close()


def test_process_crash_after_durable_record_before_sign(tmp_path):
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    process = context.Process(
        target=_process_issuance, args=(str(tmp_path), True, output)
    )
    process.start()
    try:
        process.join(20)
        assert process.exitcode == 23
        ledger = SqliteLedger(tmp_path / "audit.db")
        try:
            assert [r["event"] for r in ledger.chained_events()] == [DECISION_EVENT]
            assert decisions(ledger)[0].to_dict()["decision"] == "authorised"
            assert ledger.verify_chain().ok
        finally:
            ledger.close()
    finally:
        if process.is_alive():
            process.terminate()
            process.join(10)
        output.close()


def test_multiprocess_issuance_has_no_lost_records(tmp_path):
    SqliteLedger.private(tmp_path / "audit.db").close()
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    processes = [
        context.Process(target=_process_issuance, args=(str(tmp_path), False, output))
        for _ in range(4)
    ]
    for process in processes:
        process.start()
    try:
        digests = {output.get(timeout=20) for _ in processes}
        for process in processes:
            process.join(20)
            assert process.exitcode == 0
        ledger = SqliteLedger(tmp_path / "audit.db")
        try:
            assert {r.recompute_approval_digest() for r in decisions(ledger)} == digests
            assert len(digests) == 4 and len(ledger.chained_events()) == 8
            assert ledger.verify_chain().ok
        finally:
            ledger.close()
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(10)
        output.close()


def encoding_vector():
    # Approval preimage assembled independently of the implementation encoder.
    components = [
        b"ab" * 32,
        b'{"database":"app","host":"db","port":5432,"schema":"public","user":"migrator"}',
        b"cd" * 16,
        b"-0x0.0p+0",
        b"0x1.0000000000000p+0",
    ]
    preimage = b"promethyn-approval-v2\0" + b"".join(
        len(c).to_bytes(8, "big") + c for c in components
    )
    return {
        "record_version": 1,
        "authorization_id": "01" * 16,
        "request_id": "02" * 16,
        "recorded_at": "-0x0.0p+0",
        "requester": {
            "identity_source": "local_os",
            "issuer": "host",
            "subject": "uid:1000",
        },
        "gate_identity": "gate",
        "policy_sha256": "ef" * 32,
        "decision": "authorised",
        "reason": "authoritative_pass",
        "artifact_sha256": "ab" * 32,
        "target": {
            "host": "db",
            "port": 5432,
            "database": "app",
            "user": "migrator",
            "schema": "public",
        },
        "nonce": "cd" * 16,
        "issued_at": "-0x0.0p+0",
        "expires_at": "0x1.0000000000000p+0",
        "approval_version": 3,
        "binding_version": 2,
        "scheme": "hmac-sha256",
        "approval_key_id": "test-key",
        "signer": {
            "backend": "local-hmac",
            "scope": "local",
            "key_resource": "test-key",
            "public_key_sha256": None,
            "caller_issuer": "host",
            "caller_subject": "uid:1000",
        },
        "approval_digest": hashlib.sha256(preimage).hexdigest(),
        "approval_preimage": preimage.hex(),
    }


def test_authorization_record_encoding_vectors():
    value = encoding_vector()
    record = AuthorizationRecord.create(value)
    assert len(canonical_record(value)) == 1027
    assert (
        record.record_hash
        == "227b86dea4374aa857daaee60c3d03f7433d3df49212acfe0f0a8df8dc461669"
    )
    assert record.recompute_approval_digest() == value["approval_digest"]
    assert record.to_dict()["issued_at"] == "-0x0.0p+0"
    other = encoding_vector()
    other["requester"].update(issuer="a", subject="b:c")
    value["requester"].update(issuer="a:b", subject="c")
    assert (
        AuthorizationRecord.create(value).record_hash
        != AuthorizationRecord.create(other).record_hash
    )
    value["gate_identity"], other["gate_identity"] = "é", "e\u0301"
    assert (
        AuthorizationRecord.create(value).record_hash
        != AuthorizationRecord.create(other).record_hash
    )


@pytest.mark.parametrize(
    "field,bad",
    [
        ("record_version", True),
        ("approval_version", 2),
        ("binding_version", 1),
        ("issued_at", "nan"),
        ("expires_at", "inf"),
        ("issued_at", "0x0p0"),
        ("scheme", "unknown"),
        ("approval_key_id", "space key"),
        ("nonce", "CD" * 16),
        ("artifact_sha256", "ab"),
        ("gate_identity", "x" * 4097),
        ("gate_identity", "\ud800"),
        ("approval_preimage", "00"),
        ("approval_digest", "00" * 32),
    ],
)
def test_invalid_record_fields_are_rejected(field, bad):
    value = encoding_vector()
    value[field] = bad
    with pytest.raises((ValueError, TypeError)):
        AuthorizationRecord.create(value)


@pytest.mark.parametrize(
    "field,bad",
    [("binding_version", 99), ("scheme", "none"), ("approval_key_id", " bad")],
)
def test_partial_refusals_do_not_bypass_schema_validation(field, bad):
    value = encoding_vector()
    value.update(
        decision="refused",
        reason="invalid_request",
        target=None,
        approval_digest=None,
        approval_preimage=None,
    )
    value[field] = bad
    with pytest.raises(ValueError):
        AuthorizationRecord.create(value)


def test_oversized_request_is_durably_refused(live):
    from prometheus_protocol.chokepoint import MigrationTarget

    runtime, ledger, kms, calls = live
    target = MigrationTarget("é" * 2048, 5432, "é" * 2048, "é" * 2048, "é" * 2048)
    assert (
        runtime.authority.authorize(PASS, artifact=ARTIFACT, target=target, now=NOW)
        is None
    )
    value = decisions(ledger)[0].to_dict()
    assert value["decision"] == "refused" and value["reason"] == "invalid_request"
    assert value["target"] is None and value["artifact_sha256"] == ARTIFACT.sha256
    assert kms.sign_log() == () and calls == []


@pytest.mark.parametrize("fault", ["orphan", "duplicate", "binding", "time"])
def test_loader_rejects_invalid_results_even_in_a_valid_chain(live, fault):
    runtime, ledger, _kms, _calls = live
    authorize(runtime)
    rows = ledger.chained_events()
    result = strict_json(rows[1]["payload"])
    if fault == "orphan":
        subject = "00" * 16
    else:
        subject = rows[1]["subject"]
    if fault in ("binding", "time"):
        # Build a valid chain with a semantically invalid result (not just a
        # broken chain hash). The reader must independently validate both.
        ledger._conn.execute("DELETE FROM audit_chain WHERE seq=2")
        ledger._conn.commit()
        if fault == "binding":
            result["approval"]["target"]["user"] = "someone-else"
        else:
            result["observed_at"] = (NOW + 1).hex()
    ledger.record_chained(
        event=SIGN_RESULT_EVENT, subject=subject, payload=result, created_at=NOW.hex()
    )
    assert ledger.verify_chain().ok
    with pytest.raises(AuthorizationUnavailable):
        runtime.authority.journal.records()


def test_required_anchor_is_acknowledged_before_sign(tmp_path, monkeypatch):
    from prometheus_protocol.ledger.anchor_targets import (
        MemoryObjectLockStore,
        ObjectLockTipAnchor,
    )
    from prometheus_protocol.ledger.tip_anchor import anchor_history

    anchor = ObjectLockTipAnchor(MemoryObjectLockStore(clock=lambda: NOW))
    runtime, ledger, kms, _calls = runtime_at(tmp_path, anchor=anchor)
    sign = kms.sign

    def checked_sign(*args, **kwargs):
        assert max(t.seq for t in anchor_history(anchor)) >= 1
        return sign(*args, **kwargs)

    monkeypatch.setattr(kms, "sign", checked_sign)
    try:
        assert authorize(runtime) is not None
        assert max(t.seq for t in anchor_history(anchor)) == 2
        assert len(runtime.authority.journal.records()) == 1
    finally:
        runtime.close()
        ledger.close()


@pytest.mark.parametrize("setting", ["context", "anchor"])
def test_production_requirements_cannot_be_silently_dropped(tmp_path, setting):
    from prometheus_protocol.chokepoint.signer import LocalHmacSigner
    from prometheus_protocol.core.config import Config
    from prometheus_protocol.core.errors import ConfigError

    signer = LocalHmacSigner(b"k" * 32)
    ledger = SqliteLedger.private(tmp_path / "audit.db")
    try:
        with pytest.raises((ConfigError, AuthorizationUnavailable)):
            build_migration_runtime(
                MigrationRunnerConfig(
                    target=TARGET,
                    signer=signer,
                    approval_store_path=tmp_path / "consumed.db",
                    allow_unverified_substrate=sys.platform != "linux",
                ),
                audit=ledger,
                authorization=None
                if setting == "context"
                else authorization_context(signer),
                settings=Config(require_ledger_anchor=False),
                env={"PROM_REQUIRE_LEDGER_ANCHOR": "1"} if setting == "anchor" else {},
            )
    finally:
        ledger.close()


def test_record_failure_leaves_database_untouched_with_positive_control(
    tmp_path, monkeypatch
):
    database = tmp_path / "protected.db"
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE changes (value TEXT)")
    executed = []

    def executor(*args):
        executed.append(args)
        with sqlite3.connect(database) as conn:
            conn.execute("INSERT INTO changes VALUES ('approved')")
        return True, "committed"

    runtime, ledger, kms, _calls = runtime_at(tmp_path, executor=executor)
    try:
        with monkeypatch.context() as patch:

            def fail(*args):
                raise AuthorizationUnavailable("cannot record")

            patch.setattr(runtime.authority.journal, "record_decision", fail)
            approval = None
            with pytest.raises(AuthorizationUnavailable):
                approval = authorize(runtime)
                runtime.runner.execute(approval=approval, artifact=ARTIFACT)
            assert approval is None and executed == [] and kms.sign_log() == ()
            with sqlite3.connect(database) as conn:
                assert conn.execute("SELECT COUNT(*) FROM changes").fetchone()[0] == 0
        approval = authorize(runtime)
        assert runtime.runner.execute(approval=approval, artifact=ARTIFACT).executed
        assert len(executed) == 1
        with sqlite3.connect(database) as conn:
            assert conn.execute("SELECT value FROM changes").fetchall() == [
                ("approved",)
            ]
    finally:
        runtime.close()
        ledger.close()


@pytest.mark.parametrize(
    "receipt_state",
    [
        pytest.param(RECEIPT_UNAVAILABLE, id="unavailable-remains-unresolved"),
        pytest.param(RECEIPT_NOT_FOUND, id="not-found-resolves-not-committed"),
    ],
)
def test_signed_decision_does_not_turn_unknown_execution_into_success(
    tmp_path, monkeypatch, receipt_state
):
    from prometheus_protocol.chokepoint import OwnerIdentity
    from prometheus_protocol.chokepoint.runner import (
        EXECUTION_NOT_COMMITTED,
        EXECUTION_UNKNOWN,
        RECONCILED_NOT_COMMITTED,
        ExecutorResult,
    )

    # Exercise receipt recovery on every OS, rather than accidentally passing
    # because a host without a boot ID stops early at owner_unverifiable.
    # Only ownership/receipt inputs are synthetic; persistence and recovery run.
    monkeypatch.setattr(
        "prometheus_protocol.chokepoint.runner.local_identity",
        lambda: OwnerIdentity("host", "test-boot", "test-machine", os.getpid()),
    )
    executions = []
    lookups = []

    def executor(*args):
        executions.append(args)
        return ExecutorResult(EXECUTION_UNKNOWN, "reply lost")

    def receipt_lookup(*args):
        lookups.append(args)
        return ReceiptStatus(receipt_state)

    runtime, ledger, kms, _calls = runtime_at(
        tmp_path, executor=executor, receipt_lookup=receipt_lookup
    )
    try:
        approval = authorize(runtime)
        result = runtime.runner.execute(approval=approval, artifact=ARTIFACT)
        assert not result.executed and result.execution_state == EXECUTION_UNKNOWN
        assert len(kms.sign_log()) == 1
        assert ledger.chained_events()[-1]["event"] == "execute_unknown"
        binding = strict_json(ledger.chained_events()[-1]["payload"])[
            "approval_binding"
        ]
        assert hashlib.sha256(binding_preimage(binding)).hexdigest() == approval_digest(
            approval
        )
        rows_before_recovery = ledger.chained_events()
        recovered = runtime.runner.reconcile_unfinished()
        assert len(recovered) == 1
        assert lookups == [(result.execution_id, ARTIFACT.sha256, TARGET)]
        assert recovered[0].state == receipt_state
        if receipt_state == RECEIPT_UNAVAILABLE:
            assert not recovered[0].resolved and not recovered[0].audit_recorded
            assert ledger.chained_events() == rows_before_recovery
        else:
            assert recovered[0].resolved and recovered[0].audit_recorded
            rows_after_recovery = ledger.chained_events()
            assert len(rows_after_recovery) == len(rows_before_recovery) + 1
            assert rows_after_recovery[-1]["event"] == "execute_outcome"
            outcome = strict_json(rows_after_recovery[-1]["payload"])
            assert outcome["ok"] is False
            assert outcome["execution_state"] == EXECUTION_NOT_COMMITTED
            assert outcome["reason"] == RECONCILED_NOT_COMMITTED
            assert outcome["approval_binding"] == binding
            assert runtime.runner.reconcile_unfinished() == ()
            assert len(lookups) == 1
        assert len(executions) == 1 and len(kms.sign_log()) == 1
        assert ledger.verify_chain().ok
    finally:
        runtime.close()
        ledger.close()


def test_permission_change_refuses_before_sign(live):
    runtime, ledger, kms, calls = live
    os.chmod(ledger.path, 0o644)
    try:
        with pytest.raises(AuthorizationUnavailable):
            authorize(runtime)
        assert kms.sign_log() == () and calls == []
    finally:
        os.chmod(ledger.path, 0o600)


@pytest.mark.parametrize(
    "binding_state",
    [
        "valid",
        "malformed",
        "legacy",
        "target-mismatch",
        "artifact-mismatch",
        "nonce-mismatch",
    ],
)
def test_recovery_preserves_binding_or_refuses_invalid_evidence(
    tmp_path, monkeypatch, binding_state
):
    from prometheus_protocol.chokepoint import OwnerIdentity
    from prometheus_protocol.chokepoint.runner import EXECUTION_UNKNOWN, ExecutorResult

    # Inject the ownership input only: this tests binding recovery, not the
    # host's boot-ID probe. Persistence, ledger and runner are the real path.
    monkeypatch.setattr(
        "prometheus_protocol.chokepoint.runner.local_identity",
        lambda: OwnerIdentity("host", "test-boot", "test-machine", os.getpid()),
    )
    runtime, ledger, _kms, _calls = runtime_at(
        tmp_path, executor=lambda *args: ExecutorResult(EXECUTION_UNKNOWN)
    )
    try:
        approval = authorize(runtime)
        assert (
            runtime.runner.execute(approval=approval, artifact=ARTIFACT).execution_state
            == EXECUTION_UNKNOWN
        )
        rows = ledger.chained_events()[2:]
        if binding_state != "valid":
            ledger._conn.execute("DELETE FROM audit_chain WHERE seq >= 3")
            ledger._conn.commit()
            for row in rows:
                payload = strict_json(row["payload"])
                if row["event"] == "execute_intent":
                    if binding_state == "legacy":
                        del payload["approval_binding"]
                    elif binding_state == "target-mismatch":
                        payload["approval_binding"]["target"]["user"] = "other-user"
                    elif binding_state == "artifact-mismatch":
                        payload["approval_binding"]["artifact_sha256"] = "00" * 32
                    elif binding_state == "nonce-mismatch":
                        payload["approval_binding"]["nonce"] = "00" * 16
                    else:
                        payload["approval_binding"]["issued_at"] = "nan"
                ledger.record_chained(
                    event=row["event"],
                    subject=row["subject"],
                    payload=payload,
                    created_at=row["created_at"],
                )
        assert ledger.verify_chain().ok
        result = runtime.runner.reconcile_unfinished()
        assert len(result) == 1
        if binding_state not in ("valid", "legacy"):
            assert not result[0].resolved and result[0].state == "invalid_intent"
            assert ledger.chained_events()[-1]["event"] == "execute_unknown"
        else:
            assert result[0].resolved
            binding = strict_json(ledger.chained_events()[-1]["payload"])[
                "approval_binding"
            ]
            if binding_state == "legacy":
                assert binding is None
            else:
                assert hashlib.sha256(
                    binding_preimage(binding)
                ).hexdigest() == approval_digest(approval)
    finally:
        runtime.close()
        ledger.close()
