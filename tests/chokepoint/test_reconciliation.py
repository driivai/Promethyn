"""F11 operational end-to-end proofs: real disk, real 2a issuance, 2b model.

No test skips. The 2a fixture's explicit Darwin substrate opt-out is for disk
tests only, not a claim of Linux isolation. No live cloud operations.
"""

import hashlib
import json
import multiprocessing
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace

import pytest
from test_authorization_record import ARTIFACT, NOW, PASS, TARGET, runtime_at

from prometheus_protocol.chokepoint.audit_source import (
    ABSENT_DIGEST,
    AuditScope,
    Caller,
    CoverageGap,
    DigestEvidence,
    Interval,
    SourceIssue,
)
from prometheus_protocol.chokepoint.audit_source_model import (
    MemorySignAudit,
    ModelClock,
    ModelFaults,
)
from prometheus_protocol.chokepoint.authorization_record import (
    AuthorizationRecord,
    strict_json,
)
from prometheus_protocol.chokepoint.reconcile_gate import GateCheckpoint, read_gate
from prometheus_protocol.chokepoint.reconciliation import (
    KeyPin,
    SettlingPolicy,
    decision_window,
    reconcile,
)
from prometheus_protocol.chokepoint.runner import EXECUTION_UNKNOWN, ExecutorResult
from prometheus_protocol.chokepoint.signer import SignerTimeout
from prometheus_protocol.cli.reconcile import (
    ExportAnchor,
    ExportSource,
    decode_source_export,
    encode_source_export,
    main,
)
from prometheus_protocol.ledger.anchor_targets import LogTipAnchor, MemoryAppendOnlyLog

NS = 1_000_000_000
POLICY = SettlingPolicy(1, 5, 300)
REQUEST = Interval(1000 * NS, 1001 * NS)


class Case:
    def __init__(self, path, profile="gcp_shaped", **runtime_options):
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = path
        self.scope = AuditScope(
            "model-gcp" if profile == "gcp_shaped" else "model-cloudtrail",
            "independent-history",
            "test-kms",
            "test-region",
            "approval-key",
        )
        self.clock = ModelClock(int(NOW * NS))
        self.model = MemorySignAudit(
            self.scope,
            profile=profile,
            clock=self.clock,
            signing_principals=("runner", "insider"),
        )
        self.admin = self.model.administrator()
        self.anchor = LogTipAnchor(MemoryAppendOnlyLog())
        self.runtime, self.ledger, _, self.calls = runtime_at(
            path,
            kms=self.model.signer(),
            anchor=self.anchor,
            clock=lambda: self.clock.now_ns() / NS,
            **runtime_options,
        )
        # A real anchored genesis even for a range containing no decisions.
        self.ledger.record_chained(
            event="audit_epoch",
            subject="test",
            payload={"version": 1},
            created_at=NOW.hex(),
        )
        self.pin = KeyPin(
            "approval-key",
            "model",
            "test-scope",
            hashlib.sha256(self.runtime.authority.signer.public_key_der).hexdigest(),
            "test-kms",
            "runner",
            "ECDSA_SHA_256",
            "model:service-observed-sign-input",
        )

    def issue(self, judgment=PASS):
        return self.runtime.authority.authorize(
            judgment,
            artifact=ARTIFACT,
            target=TARGET.identity,
            now=self.clock.now_ns() / NS,
        )

    def close(self):
        self.runtime.close()
        self.ledger.close()

    def checkpoint(self):
        rows = self.ledger.chained_events()
        return GateCheckpoint(
            rows[0]["entry_hash"],
            self.ledger.chain_tip(),
            Interval(0, self.clock.now_ns()),
            self.clock.now_ns(),
            "independent:test-gate-completeness",
        )

    def run(self, *, advance=True, **overrides):
        if advance and self.clock.now_ns() < 5000 * NS:
            self.clock.advance(5000 * NS - self.clock.now_ns())
        inputs = {
            "ledger_path": self.path / "audit.db",
            "checkpoint": self.checkpoint(),
            "anchor": self.anchor,
            "source": self.model.reader(),
            "scope": self.scope,
            "pin": self.pin,
            "requested": REQUEST,
            "policy": POLICY,
            "now": self.clock.now_ns(),
        }
        inputs.update(overrides)
        return reconcile(**inputs)


@pytest.fixture
def case(tmp_path):
    obj = Case(tmp_path)
    yield obj
    obj.close()


def records(case):
    return tuple(
        AuthorizationRecord.from_dict(strict_json(r["payload"]))
        for r in case.ledger.chained_events()
        if r["event"] == "authorization_decision"
    )


def mutate_source(case, transform):
    class Source:
        def read_sign_records(self, scope, start, end):
            return transform(case.model.reader().read_sign_records(scope, start, end))

    return Source()


def event_status(report):
    return [e["status"] for e in report.to_dict()["events"]]


def test_invoke_only_forgery_detected(case):
    case.model.signer("insider").sign("approval-key", b"x" * 32, principal="insider")
    report = case.run()
    assert event_status(report) == ["UNEXPLAINED"]
    assert report.to_dict()["forgery_signal"] and report.exit_code == 1


def test_normal_concurrent_batch_across_restart_zero_false_positives(case):
    with ThreadPoolExecutor(max_workers=6) as pool:
        approvals = list(pool.map(lambda _: case.issue(), range(18)))
    assert all(approvals)
    checkpoint_path = case.ledger.path
    case.runtime.close()
    case.ledger.close()
    # The reconciler reopens disk; no journal or live approval object passed.
    from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger

    case.ledger = SqliteLedger(checkpoint_path, tip_anchor=case.anchor)
    report = case.run()
    assert report.exit_code == 0
    assert event_status(report) == ["MATCHED"] * 18
    assert report.to_dict()["counts"] == {
        "MATCHED": 36,
        "UNEXPLAINED": 0,
        "UNWITNESSED": 0,
        "INDETERMINATE": 0,
    }
    assert not report.to_dict()["forgery_signal"]


def crash_before_sign(case, monkeypatch):
    def crash(_message):
        raise SystemExit("simulated pre-Sign crash")

    monkeypatch.setattr(case.runtime.authority.signer, "sign", crash)
    with pytest.raises(SystemExit):
        case.issue()
    assert len(records(case)) == 1 and not case.admin.history()


def test_pre_sign_crash_unwitnessed_not_forgery(case, monkeypatch):
    crash_before_sign(case, monkeypatch)
    report = case.run().to_dict()
    assert report["records"][0]["status"] == "UNWITNESSED"
    assert report["records"][0]["sign_result"] == "absent"
    assert not report["clean"] and not report["forgery_signal"]


def test_lost_successful_reply_still_matched_without_post_sign_result(
    case, monkeypatch
):
    case.admin.configure_faults(ModelFaults(lose_sign_reply=True))
    with pytest.raises(SignerTimeout):
        case.issue()
    assert case.run().exit_code == 0
    assert event_status(case.run()) == ["MATCHED"]


def test_crash_after_sign_before_result_still_matched(case, monkeypatch):
    monkeypatch.setattr(
        case.runtime.authority,
        "_result",
        lambda *a, **k: (_ for _ in ()).throw(SystemExit()),
    )
    with pytest.raises(SystemExit):
        case.issue()
    assert case.run().exit_code == 0
    assert case.run().to_dict()["records"][0]["sign_result"] == "absent"


@pytest.mark.parametrize("attest", [True, False])
def test_settling_boundary_requires_completeness(case, monkeypatch, attest):
    crash_before_sign(case, monkeypatch)
    window = decision_window(records(case)[0], POLICY)
    boundary = window.end + POLICY.settling
    case.clock.advance(boundary - 1 - case.clock.now_ns())
    before = case.run(advance=False).to_dict()
    assert before["records"][0]["status"] == "INDETERMINATE"
    assert before["records"][0]["reason"] == "settling"
    assert before["records"][0]["retry_after"] == boundary
    case.clock.advance(1)
    case.admin.set_coverage(attest=attest)
    after = case.run(advance=False).to_dict()
    assert after["records"][0]["status"] == (
        "UNWITNESSED" if attest else "INDETERMINATE"
    )
    assert not after["clean"]


@pytest.mark.parametrize(
    "failure",
    [
        "gap",
        "unreadable",
        "retention",
        "missing_page",
        "delay",
        "unattested",
        "exception",
    ],
)
def test_incomplete_source_never_empty_clean(case, failure):
    case.issue()
    if failure == "gap":
        case.admin.set_coverage(gaps=(CoverageGap(REQUEST, "logging-disabled"),))
    elif failure == "unreadable":
        case.admin.configure_faults(ModelFaults(reader_unavailable=True))
    elif failure == "retention":
        case.admin.set_coverage(retention_start=1100 * NS)
    elif failure == "missing_page":
        case.admin.configure_faults(ModelFaults(omit_page=0))
    elif failure == "delay":
        history = case.admin.history()
        case.admin.replace_history(
            tuple(replace(d, delivered_at=9000 * NS) for d in history)
        )
    elif failure == "unattested":
        case.admin.set_coverage(attest=False)
    source = case.model.reader()
    if failure == "exception":
        source = mutate_source(case, lambda _: (_ for _ in ()).throw(OSError("SECRET")))
    report = case.run(source=source)
    assert report.exit_code == 1
    assert report.to_dict()["records"][0]["status"] == "INDETERMINATE"
    assert "SECRET" not in report._json


def test_metadata_only_end_to_end_never_self_certifies(tmp_path):
    case = Case(tmp_path, "cloudtrail_shaped")
    try:
        approval = case.issue()
        report = case.run()
        assert approval and records(case)[0].recompute_approval_digest()
        assert event_status(report) == ["INDETERMINATE"]
        assert report.exit_code == 1 and "metadata_only" in report.to_dict()["problems"]
        assert report.to_dict()["records"][0]["status"] != "MATCHED"
    finally:
        case.close()


@pytest.mark.parametrize("field", ["digest", "principal", "algorithm", "time", "alias"])
def test_binding_mismatch_never_proximity_matches(case, field):
    case.issue()

    def transform(read):
        event = read.events[0]
        changes = {
            "digest": {
                "digest": DigestEvidence(
                    b"x" * 32, "observed", case.pin.digest_location
                )
            },
            "principal": {"caller": Caller("test-kms", "insider")},
            "algorithm": {"algorithm": "RSASSA_PSS_SHA_256"},
            "time": {"signed_at": 999 * NS},
            "alias": {
                "digest": DigestEvidence(
                    b"x" * 32, "observed", case.pin.digest_location
                ),
                "request_id": records(case)[0].authorization_id,
            },
        }
        return replace(read, events=(replace(event, **changes[field]),))

    # Request includes the early timestamp but it is outside admissible skew.
    report = case.run(
        source=mutate_source(case, transform), requested=Interval(998 * NS, 1001 * NS)
    )
    assert event_status(report) == ["UNEXPLAINED"]
    assert report.to_dict()["records"][0]["status"] == "UNWITNESSED"


def test_refused_decision_cannot_explain_sign(case, monkeypatch):
    # Record the SAME candidate binding as refused, then invoke directly. This
    # is stricter than testing a refusal with no candidate digest at all.
    journal = case.runtime.authority.journal
    original = journal.record_decision
    captured = []

    def refuse(record):
        value = record.to_dict()
        value.pop("authorization_record_hash")
        value.update(decision="refused", reason="verdict_fail")
        refused = AuthorizationRecord.create(value)
        original(refused)
        captured.append(refused)
        raise SystemExit()

    monkeypatch.setattr(journal, "record_decision", refuse)
    with pytest.raises(SystemExit):
        case.issue()
    case.model.signer().sign(
        "approval-key",
        bytes.fromhex(captured[0].recompute_approval_digest()),
        principal="runner",
    )
    report = case.run()
    assert event_status(report) == ["UNEXPLAINED"]
    assert report.to_dict()["refused_decisions"][0]["decision"] == "refused"


def test_exact_duplicates_one_event(case):
    case.issue()
    case.admin.duplicate_delivery(case.admin.history()[0].event_id)
    assert event_status(case.run()) == ["MATCHED"]


def test_excess_distinct_real_signs_unexplained(case):
    case.issue()
    digest = bytes.fromhex(records(case)[0].recompute_approval_digest())
    case.model.signer().sign("approval-key", digest, principal="runner")
    report = case.run().to_dict()
    assert sorted(e["status"] for e in report["events"]) == ["MATCHED", "UNEXPLAINED"]
    assert (
        next(e for e in report["events"] if e["status"] == "UNEXPLAINED")["reason"]
        == "excess_sign_attempts"
    )
    assert digest.hex() == records(case)[0].recompute_approval_digest()


def test_conflicting_source_identity_is_indeterminate(case):
    case.issue()
    source = mutate_source(
        case,
        lambda r: replace(
            r,
            events=(
                r.events[0],
                replace(r.events[0], caller=Caller("test-kms", "insider")),
            ),
        ),
    )
    report = case.run(source=source)
    assert event_status(report) == ["INDETERMINATE"]
    assert report.to_dict()["source_verification"]["state"] == "unusable"


@pytest.mark.parametrize("outcome", ["denied", "unknown"])
def test_denied_diagnostic_unknown_indeterminate(case, outcome):
    case.issue()
    source = mutate_source(
        case, lambda r: replace(r, events=(replace(r.events[0], outcome=outcome),))
    )
    report = case.run(source=source).to_dict()
    assert not report["forgery_signal"] and not report["clean"]
    if outcome == "denied":
        assert report["events"] == []
        assert report["denied_attempts"][0]["outcome"] == "denied"
        assert report["records"][0]["status"] == "UNWITNESSED"
    else:
        assert report["events"][0]["status"] == "INDETERMINATE"
        assert report["records"][0]["status"] == "INDETERMINATE"


def test_local_hmac_never_clean_external_result(case):
    pin = replace(
        case.pin, backend="local-hmac", scheme="hmac-sha256", public_key_sha256=None
    )
    report = case.run(pin=pin)
    assert report.exit_code == 1
    assert "no_independent_sign_source" in report.to_dict()["problems"]


def test_disk_tamper_chain_verified_before_typed_decode(case, monkeypatch):
    case.issue()
    from prometheus_protocol.chokepoint import reconcile_gate

    decoded = []
    monkeypatch.setattr(
        reconcile_gate, "_decode_rows", lambda rows: decoded.append(True)
    )
    with sqlite3.connect(case.path / "audit.db") as db:
        db.execute(
            "UPDATE audit_chain SET payload=payload || ' ' WHERE event='authorization_decision'"
        )
    report = case.run().to_dict()
    assert not decoded
    assert report["gate_verification"]["integrity_failure"]
    assert report["gate_verification"]["chain"] == "broken"
    assert report["events"][0]["status"] == "INDETERMINATE"


def test_stored_digest_corrupt_even_reanchored_never_trusted(case):
    case.issue()
    value = records(case)[0].to_dict()
    value["approval_digest"] = "ab" * 32
    case.ledger.record_chained(
        event="authorization_decision",
        subject=value["authorization_id"],
        payload=value,
        created_at=value["recorded_at"],
    )
    report = case.run().to_dict()
    assert report["gate_verification"]["chain"] == "valid"
    assert report["gate_verification"]["integrity_failure"]
    assert event_status(case.run()) == ["INDETERMINATE"]


def test_anchor_unavailable_never_decodes_or_matches(case, monkeypatch):
    case.issue()
    from prometheus_protocol.chokepoint import reconcile_gate

    monkeypatch.setattr(
        reconcile_gate,
        "_decode_rows",
        lambda rows: pytest.fail("decoded before anchor"),
    )
    assert event_status(case.run(anchor=None)) == ["INDETERMINATE"]


def test_gate_lookback_and_source_extension(case):
    case.issue()
    case.clock.advance(NS)
    case.model.signer().sign(
        "approval-key",
        bytes.fromhex(records(case)[0].recompute_approval_digest()),
        principal="runner",
    )
    # First delivery is removed to model one delayed start, not two attempts.
    case.admin.replace_history(case.admin.history()[1:])
    report = case.run(requested=Interval(1001 * NS, 1002 * NS)).to_dict()
    assert report["clean"] and report["events"][0]["status"] == "MATCHED"
    assert report["source_requested"]["start"] < report["requested"]["start"]
    assert report["source_requested"]["end"] > report["requested"]["end"]
    checkpoint = replace(
        case.checkpoint(), covered=Interval(1001 * NS, case.clock.now_ns())
    )
    short = case.run(checkpoint=checkpoint).to_dict()
    assert not short["clean"] and "gate_coverage_incomplete" in short["problems"]


def test_conflicting_identity_mapping_indeterminate(case):
    case.issue()
    report = case.run(pin=replace(case.pin, public_key_sha256="ab" * 32))
    assert event_status(report) == ["INDETERMINATE"]
    assert "conflicting_identity_mapping" in report.to_dict()["problems"]


def test_missing_legacy_history_is_not_empty_clean(case):
    case.ledger.record_chained(
        event="execute_intent",
        subject="legacy",
        payload={"approval_binding": None},
        created_at=NOW.hex(),
    )
    report = case.run().to_dict()
    assert "missing_legacy_history" in report["problems"] and not report["clean"]


def test_matched_sign_never_resolves_unknown_or_releases_nonce(tmp_path):
    case = Case(tmp_path, executor=lambda *args: ExecutorResult(EXECUTION_UNKNOWN))
    try:
        approval = case.issue()
        result = case.runtime.runner.execute(approval=approval, artifact=ARTIFACT)
        assert result.execution_state == EXECUTION_UNKNOWN
        before = case.ledger.chained_events()
        with sqlite3.connect(tmp_path / "consumed.db") as db:
            consumed_before = db.iterdump()
            consumed_before = list(consumed_before)
        report = case.run()
        assert report.exit_code == 0 and event_status(report) == ["MATCHED"]
        assert before == case.ledger.chained_events()
        with sqlite3.connect(tmp_path / "consumed.db") as db:
            assert consumed_before == list(db.iterdump())
        assert before[-1]["event"] == "execute_unknown"
    finally:
        case.close()


def test_controls_both_residual_honestly_not_detected(case):
    case.model.signer("insider").sign("approval-key", b"x" * 32, principal="insider")
    assert case.run().to_dict()["forgery_signal"]
    case.admin.replace_history(())
    case.admin.set_coverage(gaps=(), complete_through=case.clock.now_ns(), attest=True)
    report = case.run().to_dict()
    assert report["clean"] and not report["forgery_signal"]
    assert report["source_verification"]["coverage"]["gaps"] == []
    assert report["events"] == []


@pytest.mark.parametrize(
    "field",
    [
        "max_clock_skew_seconds",
        "record_ttl_seconds",
        "sign_attempt_seconds",
        "settle_seconds",
    ],
)
@pytest.mark.parametrize(
    "bad", [True, False, float("nan"), float("inf"), -float("inf"), -1, "5", None]
)
def test_numeric_policy_rejects_nonfinite_boolean_negative(field, bad):
    values = asdict(POLICY)
    values[field] = bad
    with pytest.raises((TypeError, ValueError)):
        SettlingPolicy(**values)


@pytest.mark.parametrize("field", ["sign_attempt_seconds", "settle_seconds"])
def test_positive_policy_cannot_be_disabled(field):
    values = asdict(POLICY)
    values[field] = 0
    with pytest.raises(ValueError):
        SettlingPolicy(**values)


def test_cli_versioned_json_secret_free_read_only(case, tmp_path, monkeypatch, capsys):
    from prometheus_protocol.cli import reconcile as cli

    approval = case.issue()
    case.run()
    export = encode_source_export(
        case.model.reader().read_sign_records(case.scope, 0, 4000 * NS)
    )
    source = tmp_path / "source.ndjson"
    source.write_bytes(export)
    anchor = tmp_path / "anchor.ndjson"
    anchor_raw = (
        "\n".join(json.dumps(asdict(t)) for t in case.anchor.history()) + "\n"
    ).encode()
    anchor.write_bytes(anchor_raw)
    config = {
        "version": 1,
        "scope": asdict(case.scope),
        "key_pin": asdict(case.pin),
        "policy": asdict(POLICY),
        "requested": asdict(REQUEST),
        "gate_checkpoint": asdict(case.checkpoint()),
        "anchor_sha256": hashlib.sha256(anchor_raw).hexdigest(),
        "source_sha256": hashlib.sha256(export).hexdigest(),
    }
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))
    monkeypatch.setattr(cli.time, "time_ns", case.clock.now_ns)
    paths = [
        source,
        anchor,
        config_path,
        tmp_path / "audit.db",
        tmp_path / "consumed.db",
    ]
    before = {p: p.read_bytes() for p in paths}
    arguments = [
        "--config",
        str(config_path),
        "--ledger",
        str(tmp_path / "audit.db"),
        "--anchor-history",
        str(anchor),
        "--source-evidence",
        str(source),
    ]
    assert main(arguments) == 0
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["schema_version"] == 1 and result["clean"]
    for secret in (
        approval.signature,
        approval.nonce,
        "db-secret",
        "approval_preimage",
        "approval_binding",
    ):
        assert secret not in output
    assert before == {p: p.read_bytes() for p in paths}
    source.write_bytes(export + b"SECRET")
    assert main(arguments) == 2
    assert "SECRET" not in capsys.readouterr().out
    source.write_bytes(export)
    for name in ("anchor_sha256", "source_sha256"):
        original = config[name]
        config[name] = None
        config_path.write_text(json.dumps(config))
        assert main(arguments) == 2  # null cannot turn off required hash pinning
        assert json.loads(capsys.readouterr().out)["status"] == "INDETERMINATE"
        config[name] = original
    config_path.write_text(json.dumps(config))
    assert main(arguments) == 0  # the restored, unmodified evidence still passes
    capsys.readouterr()


@pytest.mark.parametrize("change", ["absent", "local"])
def test_absent_or_locally_asserted_digest_not_matched(case, change):
    case.issue()
    source = mutate_source(
        case,
        lambda r: replace(
            r,
            events=(
                replace(
                    r.events[0],
                    digest=ABSENT_DIGEST
                    if change == "absent"
                    else replace(r.events[0].digest, location="local:gate-assertion"),
                ),
            ),
        ),
    )
    report = case.run(source=source).to_dict()
    assert report["events"][0]["status"] == "INDETERMINATE"
    assert report["records"][0]["status"] == "INDETERMINATE"


def test_useful_findings_retained_with_gap_elsewhere(case):
    case.model.signer("insider").sign("approval-key", b"x" * 32, principal="insider")
    source = mutate_source(
        case,
        lambda r: replace(
            r,
            coverage=replace(
                r.coverage,
                gaps=(
                    CoverageGap(
                        Interval(1000_800_000_000, 1000_900_000_000), "exclusion"
                    ),
                ),
            ),
        ),
    )
    report = case.run(source=source).to_dict()
    assert not report["clean"] and report["forgery_signal"]
    assert report["events"][0]["status"] == "UNEXPLAINED"
    assert "source_coverage_incomplete" in report["problems"]


def test_empty_range_must_be_settled_and_complete(case):
    report = case.run(advance=False).to_dict()
    assert not report["clean"] and "settling" in report["problems"]
    assert case.run().exit_code == 0


def test_export_preserves_missing_digest_and_coverage(case):
    case.issue()
    case.run()
    read = case.model.reader().read_sign_records(case.scope, 0, 4000 * NS)
    assert decode_source_export(encode_source_export(read)) == read
    cropped = ExportSource(read).read_sign_records(
        case.scope, REQUEST.start, REQUEST.end
    )
    assert cropped.coverage.requested == REQUEST and len(cropped.events) == 1
    assert ExportSource(read).read_sign_records(case.scope, 0, 5001 * NS).issues


def test_missing_disk_never_created(case):
    path = case.path / "missing.db"
    result = read_gate(path, case.checkpoint(), case.anchor)
    assert not result.ok and not path.exists()


@pytest.mark.parametrize(
    "change",
    [
        "no_attestation",
        "missing_pages",
        "frontier",
        "wrong_scope",
        "wrong_interval",
        "future_observation",
    ],
)
def test_source_contract_refusals(case, change):
    case.issue()

    def transform(read):
        c = read.coverage
        if change == "no_attestation":
            return replace(
                read,
                coverage=replace(c, completeness_evidence=None, complete_through=None),
            )
        if change == "missing_pages":
            return replace(read, coverage=replace(c, pages_exhausted=False))
        if change == "frontier":
            return replace(read, coverage=replace(c, complete_through=REQUEST.start))
        if change == "wrong_scope":
            wrong = replace(c.scope, region="wrong-region")
            return replace(
                read,
                coverage=replace(c, scope=wrong),
                events=tuple(replace(e, scope=wrong) for e in read.events),
            )
        if change == "wrong_interval":
            return replace(
                read, coverage=replace(c, requested=Interval(0, c.requested.end))
            )
        return replace(read, coverage=replace(c, observed_at=case.clock.now_ns() + NS))

    report = case.run(source=mutate_source(case, transform))
    assert report.exit_code == 1
    assert all(e["status"] != "MATCHED" for e in report.to_dict()["events"])
    assert report.to_dict()["records"][0]["status"] == "INDETERMINATE"


@pytest.mark.parametrize(
    "failure",
    ["stale_tip", "truncated", "unreadable_anchor", "unanchored", "future_checkpoint"],
)
def test_gate_checkpoint_refusals(case, failure):
    prior = case.checkpoint()
    case.issue()
    case.run()
    overrides = {}
    if failure == "stale_tip":
        overrides["checkpoint"] = replace(case.checkpoint(), tip=prior.tip)
    elif failure == "truncated":
        checkpoint = case.checkpoint()
        with sqlite3.connect(case.path / "audit.db") as db:
            db.execute("DELETE FROM audit_chain WHERE seq=?", (checkpoint.tip.seq,))
        overrides["checkpoint"] = checkpoint
    elif failure == "unreadable_anchor":

        class Missing:
            def history(self):
                raise OSError("DO-NOT-PRINT-SECRET")

        overrides["anchor"] = Missing()
    elif failure == "unanchored":

        class Old:
            def history(self):
                return [prior.tip]

        overrides["anchor"] = Old()
    else:
        overrides["checkpoint"] = replace(
            case.checkpoint(), observed_at=case.clock.now_ns() + NS
        )
    report = case.run(**overrides)
    assert report.exit_code == 1 and event_status(report) == ["INDETERMINATE"]
    assert "DO-NOT-PRINT-SECRET" not in report._json


def test_record_ttl_and_absence_window_not_shrunk(case, monkeypatch):
    crash_before_sign(case, monkeypatch)
    record = records(case)[0]
    value = record.to_dict()
    window = decision_window(record, POLICY)
    assert window.start == int(NOW * NS) - NS
    assert window.end == int((float.fromhex(value["expires_at"]) + 5 + 1) * NS)
    report = case.run(policy=replace(POLICY, record_ttl_seconds=89))
    assert report.exit_code == 1
    assert "record_time_policy_invalid" in report.to_dict()["problems"]


def test_disk_digest_is_recomputed_at_match_boundary(case, monkeypatch):
    case.issue()
    original = AuthorizationRecord.recompute_approval_digest
    called = []

    def recompute(self):
        called.append(self.authorization_id)
        return original(self)

    monkeypatch.setattr(AuthorizationRecord, "recompute_approval_digest", recompute)
    assert case.run().exit_code == 0
    assert len(called) >= 2  # selected projection AND actual independent match


@pytest.mark.parametrize("suffix", [b"\n", b"not-json\n", b'{"scope":{},"scope":{}}\n'])
def test_malformed_export_not_dropped(case, suffix):
    case.issue()
    case.run()
    raw = encode_source_export(
        case.model.reader().read_sign_records(case.scope, 0, 4000 * NS)
    )
    with pytest.raises((TypeError, ValueError)):
        decode_source_export(raw + suffix)


def test_distinct_ids_not_digest_deduplicated_at_consumer(case):
    case.issue()
    source = mutate_source(
        case,
        lambda r: replace(
            r,
            events=(
                r.events[0],
                r.events[0],
                replace(r.events[0], event_id="extra-id"),
            ),
        ),
    )
    report = case.run(source=source)
    assert len(report.to_dict()["events"]) == 2
    assert sorted(event_status(report)) == ["MATCHED", "UNEXPLAINED"]


def test_success_inside_settling_not_clean(case):
    case.issue()
    result = case.run(advance=False).to_dict()
    assert result["events"][0]["status"] == "INDETERMINATE"
    assert not result["clean"]


def test_success_at_absence_upper_bound_is_not_eligible(case):
    case.issue()
    upper = decision_window(records(case)[0], POLICY).end
    source = mutate_source(
        case, lambda r: replace(r, events=(replace(r.events[0], signed_at=upper),))
    )
    report = case.run(source=source, requested=Interval(REQUEST.start, upper + 1))
    assert event_status(report) == ["UNEXPLAINED"]


def test_empty_metadata_only_range_not_clean(tmp_path):
    obj = Case(tmp_path, "cloudtrail_shaped")
    try:
        assert obj.run().exit_code == 1
    finally:
        obj.close()


def test_real_aws_scope_cannot_upgrade_capability(case):
    case.issue()
    scope = replace(case.scope, provider="aws-cloudtrail")
    pin = replace(case.pin, backend="aws-kms")
    source = mutate_source(
        case,
        lambda r: replace(
            r,
            coverage=replace(r.coverage, scope=scope),
            events=tuple(replace(e, scope=scope) for e in r.events),
        ),
    )
    report = case.run(scope=scope, pin=pin, source=source).to_dict()
    assert "metadata_only" in report["problems"] and not report["clean"]


def test_lookback_not_just_extended_query(case):
    case.issue()
    initial = case.run().to_dict()
    start = initial["source_requested"]["start"]
    checkpoint = replace(
        case.checkpoint(), covered=Interval(start, case.clock.now_ns())
    )
    report = case.run(checkpoint=checkpoint).to_dict()
    assert "gate_coverage_incomplete" in report["problems"]


def test_export_conflict_outside_subquery_not_filtered_away(case):
    case.issue()
    case.run()
    read = case.model.reader().read_sign_records(case.scope, 0, 4000 * NS)
    conflict = replace(read.events[0], signed_at=2000 * NS)
    export = ExportSource(replace(read, events=(*read.events, conflict)))
    report = case.run(source=export)
    assert report.exit_code == 1 and event_status(report) == ["INDETERMINATE"]


def _fresh_process(inputs, output):
    output.put(reconcile(**inputs).to_dict())


def test_fresh_interpreter_reads_disk_and_independent_export(case):
    case.issue()
    case.run()
    inputs = {
        "ledger_path": case.path / "audit.db",
        "checkpoint": case.checkpoint(),
        "anchor": ExportAnchor(tuple(case.anchor.history())),
        "source": ExportSource(
            case.model.reader().read_sign_records(case.scope, 0, 4000 * NS)
        ),
        "scope": case.scope,
        "pin": case.pin,
        "requested": REQUEST,
        "policy": POLICY,
        "now": case.clock.now_ns(),
    }
    case.runtime.close()
    case.ledger.close()
    context = multiprocessing.get_context("spawn")
    output = context.Queue()
    process = context.Process(target=_fresh_process, args=(inputs, output))
    process.start()
    try:
        result = output.get(timeout=20)
        process.join(20)
        assert process.exitcode == 0 and result["clean"]
        assert result["events"][0]["status"] == "MATCHED"
    finally:
        if process.is_alive():
            process.terminate()
            process.join(10)
        output.close()


def test_lost_reply_no_event_needs_mature_complete_coverage(case):
    case.admin.configure_faults(ModelFaults(lose_sign_reply=True))
    with pytest.raises(SignerTimeout):
        case.issue()
    case.admin.replace_history(())
    immature = case.run(advance=False).to_dict()
    assert immature["records"][0]["status"] == "INDETERMINATE"
    mature = case.run().to_dict()
    assert mature["records"][0]["status"] == "UNWITNESSED"
    assert mature["records"][0]["sign_result"] == "outcome_unknown"
    assert not mature["forgery_signal"]
    case.admin.set_coverage(attest=False)
    assert case.run().to_dict()["records"][0]["status"] == "INDETERMINATE"


def test_native_gcp_normalizer_to_operational_match(case):
    # Provider-shaped export of an independently MODEL-observed input. This
    # composes the real normalizer and matcher, NOT a claim of live GCP evidence.
    from test_audit_source import GCP, gcp_event, key_export, wire

    from prometheus_protocol.chokepoint.audit_normalization import normalize_gcp_event

    identity = {
        **case.runtime.authority._context.signer,
        "backend": "gcp-kms",
        "scope": GCP.domain,
        "key_resource": GCP.key_resource,
        "caller_issuer": "cloudkms.googleapis.com",
    }
    case.runtime.authority._context = replace(
        case.runtime.authority._context, signer=identity
    )
    case.issue()
    pin = replace(
        case.pin,
        backend="gcp-kms",
        gate_scope=GCP.domain,
        caller_issuer="cloudkms.googleapis.com",
        algorithm="EC_SIGN_P256_SHA256",
        digest_location="protoPayload.request.digest.sha256:base64",
    )

    class NativeShapedSource:
        def read_sign_records(self, scope, start, end):
            assert scope == GCP
            independent = case.model.reader().read_sign_records(case.scope, start, end)
            events = []
            for observed in independent.events:
                raw = gcp_event(observed.digest.value)
                raw["timestamp"] = "1970-01-01T00:16:40.125000000Z"
                raw["protoPayload"]["authenticationInfo"]["principalSubject"] = "runner"
                events.append(
                    normalize_gcp_event(wire(raw), GCP, key_version=key_export())
                )
            return replace(
                independent,
                coverage=replace(independent.coverage, scope=GCP),
                events=tuple(events),
            )

    report = case.run(source=NativeShapedSource(), scope=GCP, pin=pin)
    assert report.exit_code == 0 and event_status(report) == ["MATCHED"]


def test_operator_cannot_enable_gate_asserted_digest(case):
    case.issue()
    source = mutate_source(
        case,
        lambda r: replace(
            r,
            events=(
                replace(
                    r.events[0],
                    digest=replace(r.events[0].digest, location="local:gate"),
                ),
            ),
        ),
    )
    report = case.run(
        source=source, pin=replace(case.pin, digest_location="local:gate")
    )
    assert event_status(report) == ["INDETERMINATE"]
    assert "unsupported_digest_provenance" in report.to_dict()["problems"]


def test_source_diagnostics_and_references_do_not_echo_secrets(case):
    case.issue()
    secret = "signing-key-or-bearer-token:SECRET"
    source = mutate_source(
        case,
        lambda r: replace(
            r,
            issues=(SourceIssue(secret),),
            coverage=replace(
                r.coverage,
                completeness_evidence=secret,
                gaps=(CoverageGap(REQUEST, secret),),
            ),
        ),
    )
    report = case.run(source=source)
    assert report.exit_code == 1 and secret not in report._json


def test_gate_size_bound_refuses_without_truncation(case):
    case.ledger.record_chained(
        event="test", subject="x" * 140_000, payload={}, created_at=NOW.hex()
    )
    report = case.run()
    assert report.exit_code == 1
    assert "gate_read_unavailable" in report.to_dict()["problems"]
