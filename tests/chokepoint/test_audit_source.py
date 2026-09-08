"""F11 2b: input semantics only. No reconciler verdicts, live calls, or skips."""

import base64
import dataclasses
import inspect
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from prometheus_protocol.chokepoint.audit_normalization import (
    GcpKeyVersion,
    MalformedEvent,
    decode_json,
    native_coverage,
    normalize_aws_event,
    normalize_gcp_event,
    normalize_pkcs11_event,
    timestamp_ns,
    unavailable_pkcs11_read,
)
from prometheus_protocol.chokepoint.audit_source import (
    ABSENT_DIGEST,
    AuditPage,
    AuditScope,
    Coverage,
    CoverageGap,
    DigestEvidence,
    Interval,
    PagedSignAuditSource,
    ReadLimits,
)
from prometheus_protocol.chokepoint.audit_source_model import (
    Delivery,
    MemorySignAudit,
    ModelClock,
    ModelFaults,
)
from prometheus_protocol.chokepoint.signer import KmsAccessDenied, KmsTimeout

DIGEST = bytes(range(32))
OTHER = b"x" * 32
AWS_KEY = "arn:aws:kms:us-west-2:111122223333:key/12345678-1234-1234-1234-123456789012"
AWS = AuditScope(
    "aws-cloudtrail", "trail-account-region", "111122223333", "us-west-2", AWS_KEY
)
GCP_KEY = "projects/project-a/locations/us-west1/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1"
GCP = AuditScope(
    "gcp-audit",
    "projects/project-a/logs/cloudaudit.googleapis.com%2Fdata_access",
    "project-a",
    "us-west1",
    GCP_KEY,
)
STAMP = "2026-09-08T00:00:00.123456789Z"
AT = timestamp_ns(STAMP)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def aws_event():
    # AWS's documented Sign shape, synthetic identities; NOT a live capture.
    return {
        "eventVersion": "1.08",
        "eventSource": "kms.amazonaws.com",
        "eventName": "Sign",
        "eventTime": STAMP,
        "awsRegion": AWS.region,
        "recipientAccountId": AWS.domain,
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDASYNTHE1",
            "arn": "arn:aws:iam::111122223333:user/runner",
            "accountId": AWS.domain,
        },
        "requestParameters": {
            "keyId": AWS_KEY,
            "messageType": "DIGEST",
            "signingAlgorithm": "ECDSA_SHA_256",
        },
        "responseElements": None,
        "eventID": "aws-event-1",
        "requestID": "aws-request-1",
        "resources": [
            {"accountId": AWS.domain, "type": "AWS::KMS::Key", "ARN": AWS_KEY}
        ],
    }


def gcp_event(digest=DIGEST):
    return {
        "logName": GCP.source_id,
        "insertId": "gcp-event-1",
        "timestamp": STAMP,
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "cloudkms.googleapis.com",
            "methodName": "AsymmetricSign",
            "resourceName": GCP_KEY,
            "authenticationInfo": {
                "principalEmail": "runner@project-a.iam.gserviceaccount.com"
            },
            "request": {
                "name": GCP_KEY,
                "digest": {"sha256": base64.b64encode(digest).decode()},
            },
            "status": {"code": 0},
        },
    }


def key_export():
    return GcpKeyVersion.from_public_key_export(
        wire({"name": GCP_KEY, "algorithm": "EC_SIGN_P256_SHA256"})
    )


def model(profile="gcp_shaped", **reader_options):
    clock = ModelClock(100)
    scope = AuditScope(
        "model-gcp" if profile == "gcp_shaped" else "model-cloudtrail",
        "model-history",
        "test-account",
        "test-region",
        "approval-key",
    )
    factory = MemorySignAudit(scope, profile=profile, clock=clock)
    return (
        factory,
        clock,
        scope,
        factory.signer(),
        factory.reader(**reader_options),
        factory.administrator(),
    )


def invoke(signer, scope, digest=DIGEST):
    return signer.sign(scope.key_resource, digest, principal="runner")


@pytest.mark.parametrize("profile", ["gcp_shaped", "cloudtrail_shaped"])
def test_profiles_observed_digest_or_explicit_absence(profile):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

    _factory, clock, scope, signer, reader, admin = model(profile)
    signature = invoke(signer, scope)
    assert signature and signer.get_public_key(scope.key_resource)
    public = serialization.load_der_public_key(
        signer.get_public_key(scope.key_resource)
    )
    public.verify(signature, DIGEST, ec.ECDSA(Prehashed(hashes.SHA256())))
    clock.advance(100)
    result = reader.read_sign_records(scope, 0, 200)
    assert result.state == "complete" and len(result.events) == 1
    event = result.events[0]
    if profile == "cloudtrail_shaped":
        assert event.digest == ABSENT_DIGEST and event.capability == "metadata_only"
        assert result.coverage.capability == "metadata_only"
        assert all(decode_json(d.raw)["digest"] is None for d in admin.history())
    else:
        assert event.digest.value == DIGEST and event.digest.provenance == "observed"
        assert event.capability == result.coverage.capability == "digest_bound"
    assert event.caller.subject == "runner" and event.signed_at == 100
    assert event.outcome == "success" and event.scope == scope


def test_metadata_only_cannot_self_certify_from_persisted_gate(tmp_path):
    from test_authorization_record import NOW, authorize, decisions, runtime_at

    _factory, clock, scope, signer, reader, admin = model("cloudtrail_shaped")
    clock.advance(int(NOW * 1_000_000_000) - clock.now_ns())
    runtime, ledger, _kms, _calls = runtime_at(tmp_path, kms=signer)
    try:
        approval = authorize(runtime)
        gate = decisions(ledger)[0].to_dict()
        assert approval is not None and gate["approval_digest"]
        clock.advance(100)
        report = reader.read_sign_records(scope, 0, clock.now_ns())
        assert report.state == "complete" and report.events[0].digest == ABSENT_DIGEST
        assert gate["approval_digest"].encode() not in admin.history()[0].raw
        with pytest.raises(TypeError):
            reader.read_sign_records(scope, 0, clock.now_ns(), gate_record=gate)
    finally:
        runtime.close()
        ledger.close()


def test_metadata_profile_rejects_administrator_digest_injection():
    _factory, clock, scope, signer, reader, admin = model("cloudtrail_shaped")
    invoke(signer, scope)
    old = admin.history()[0]
    forged = decode_json(old.raw)
    forged.update(digest=DIGEST.hex(), provenance="observed")
    admin.replace_history((dataclasses.replace(old, raw=wire(forged)),))
    clock.advance(100)
    result = reader.read_sign_records(scope, 0, 200)
    assert result.state == "incomplete" and result.events == ()
    assert result.issues[0].reason == "malformed_event"


@pytest.mark.parametrize(
    "value,provenance,location",
    [
        (None, "observed", "gate"),
        (DIGEST, "inferred", "gate"),
        (DIGEST, "observed", None),
        (bytearray(DIGEST), "observed", "source"),
        (b"short", "observed", "source"),
        (None, "absent", "gate"),
    ],
)
def test_digest_provenance_cannot_describe_inferred_bytes(value, provenance, location):
    with pytest.raises(ValueError):
        DigestEvidence(value, provenance, location)


def test_all_pages_and_empty_complete_range():
    _f, clock, scope, signer, reader, _a = model(page_size=1)
    for _ in range(4):
        invoke(signer, scope)
    clock.advance(100)
    result = reader.read_sign_records(scope, 0, 200)
    assert result.state == "complete" and len(result.events) == 4
    assert result.coverage.pages_exhausted and result.coverage.source_attested
    empty = reader.read_sign_records(scope, 0, 99)
    assert empty.state == "complete" and empty.events == ()


@pytest.mark.parametrize("omitted", [0, 1, 2])
def test_omitted_page_is_incomplete(omitted):
    _f, clock, scope, signer, reader, admin = model(page_size=1)
    for _ in range(3):
        invoke(signer, scope)
    clock.advance(100)
    admin.configure_faults(ModelFaults(omit_page=omitted))
    result = reader.read_sign_records(scope, 0, 200)
    assert result.state == "incomplete" and not result.coverage.pages_exhausted
    assert result.issues[0].reason == "page_unavailable_or_malformed"


def test_every_page_is_not_source_completeness():
    _f, clock, scope, signer, reader, admin = model()
    invoke(signer, scope)
    clock.advance(100)
    admin.set_coverage(attest=False)
    result = reader.read_sign_records(scope, 0, 200)
    assert result.coverage.pages_exhausted and not result.coverage.source_attested
    assert result.coverage.complete_through is None and result.state == "incomplete"


def test_retention_boundary_and_reported_gap():
    _f, clock, scope, signer, reader, admin = model()
    invoke(signer, scope)
    clock.advance(100)
    admin.set_coverage(
        retention_start=110, gaps=(CoverageGap(Interval(150, 170), "logging_disabled"),)
    )
    result = reader.read_sign_records(scope, 0, 200)
    assert result.state == "incomplete" and result.events == ()
    assert result.coverage.covered == Interval(110, 200)
    assert result.coverage.gaps == (
        CoverageGap(Interval(0, 110), "retention"),
        CoverageGap(Interval(150, 170), "logging_disabled"),
    )


def test_duplicates_collapse_by_source_id_not_digest():
    _f, clock, scope, signer, reader, admin = model(page_size=1)
    invoke(signer, scope)
    admin.duplicate_delivery(admin.history()[0].event_id)
    invoke(signer, scope)  # same digest, distinct Sign operation
    clock.advance(100)
    result = reader.read_sign_records(scope, 0, 200)
    assert result.state == "complete" and len(result.events) == 2
    assert result.events[0].event_id != result.events[1].event_id
    assert result.events[0].digest == result.events[1].digest


def test_conflicting_duplicate_payload_makes_source_unusable():
    _f, clock, scope, signer, reader, admin = model(page_size=1)
    invoke(signer, scope)
    original = admin.history()[0]
    conflict = decode_json(original.raw)
    conflict["digest"] = OTHER.hex()
    admin.replace_history((original, dataclasses.replace(original, raw=wire(conflict))))
    clock.advance(100)
    result = reader.read_sign_records(scope, 0, 200)
    assert result.state == "unusable"
    assert result.issues[0].reason == "conflicting_event_id"


def test_delayed_delivery_limits_complete_through():
    _f, clock, scope, signer, reader, admin = model()
    admin.configure_faults(ModelFaults(delivery_delay_ns=100))
    invoke(signer, scope)
    clock.advance(50)
    pending = reader.read_sign_records(scope, 0, 101)
    assert pending.events == () and pending.coverage.complete_through == 100
    assert pending.coverage.pages_exhausted and pending.state == "incomplete"
    clock.advance(50)
    delivered = reader.read_sign_records(scope, 0, 101)
    assert delivered.state == "complete" and len(delivered.events) == 1


@pytest.mark.parametrize("profile", ["gcp_shaped", "cloudtrail_shaped"])
def test_lost_and_late_sign_replies_do_not_erase_success(profile):
    _f, clock, scope, signer, reader, admin = model(profile)
    admin.configure_faults(ModelFaults(lose_sign_reply=True, sign_reply_delay_ns=100))
    with pytest.raises(KmsTimeout):
        invoke(signer, scope)
    assert clock.now_ns() == 200
    result = reader.read_sign_records(scope, 0, 200)
    assert result.state == "complete" and result.events[0].outcome == "success"
    assert len(result.events) == 1 and result.events[0].signed_at == 100


def test_reader_and_signer_have_no_administrator_operations():
    factory, clock, scope, signer, reader, admin = model()
    assert {n for n in dir(reader) if not n.startswith("_")} == {"read_sign_records"}
    assert {n for n in dir(signer) if not n.startswith("_")} == {
        "sign",
        "get_public_key",
    }
    invoke(signer, scope)
    before = admin.history()
    clock.advance(100)
    result = reader.read_sign_records(scope, 0, 200)
    assert admin.history() == before
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.events[0].outcome = "denied"
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.coverage.pages_exhausted = False
    with pytest.raises(KmsAccessDenied):
        factory.signer("attacker").sign(scope.key_resource, DIGEST, principal="runner")


def test_denied_attempt_retained_and_unknown_caller_not_filtered():
    factory, clock, scope, _signer, reader, _admin = model()
    with pytest.raises(KmsAccessDenied):
        factory.signer("unknown-caller").sign(
            scope.key_resource, DIGEST, principal="unknown-caller"
        )
    clock.advance(100)
    result = reader.read_sign_records(scope, 0, 200)
    assert result.state == "complete" and len(result.events) == 1
    assert (
        result.events[0].outcome == "denied"
        and result.events[0].caller.subject == "unknown-caller"
    )


def test_administrator_controls_both_residual_is_clean_looking():
    _f, clock, scope, signer, reader, admin = model()
    invoke(signer, scope)  # direct Sign, no gate involved
    clock.advance(100)
    assert len(reader.read_sign_records(scope, 0, 200).events) == 1
    admin.set_coverage(gaps=(CoverageGap(Interval(90, 110), "excluded"),))
    admin.replace_history(())
    admin.set_coverage(retention_start=0, gaps=(), complete_through=200)
    erased = reader.read_sign_records(scope, 0, 200)
    assert erased.state == "complete" and erased.events == ()
    assert erased.coverage.gaps == () and erased.issues == ()
    # No synthetic tombstone/counter/gap: control of both defeats this witness.


@pytest.mark.parametrize(
    "fault", [ModelFaults(reader_unavailable=True), ModelFaults(read_reply_delay_ns=10)]
)
def test_read_failures_and_late_replies_are_not_empty_clean_history(fault):
    _f, clock, scope, signer, reader, admin = model(limits=ReadLimits(duration_ns=10))
    invoke(signer, scope)
    clock.advance(100)
    admin.configure_faults(fault)
    result = reader.read_sign_records(scope, 0, 200)
    assert (
        result.state == "incomplete"
        and result.issues
        and not result.coverage.pages_exhausted
    )


@pytest.mark.parametrize(
    "limits", [ReadLimits(pages=1), ReadLimits(records=1), ReadLimits(bytes=1)]
)
def test_response_limits_preserve_incompleteness(limits):
    _f, clock, scope, signer, reader, _admin = model(page_size=1, limits=limits)
    invoke(signer, scope)
    invoke(signer, scope)
    clock.advance(100)
    result = reader.read_sign_records(scope, 0, 200)
    assert result.state == "incomplete" and result.issues


def test_malformed_row_is_retained_as_failure_not_dropped():
    _f, clock, scope, signer, reader, admin = model(page_size=1)
    invoke(signer, scope)
    original = admin.history()[0]
    admin.replace_history((original, Delivery(b"not JSON", 100, 100, "bad-row")))
    clock.advance(100)
    result = reader.read_sign_records(scope, 0, 200)
    assert result.state == "incomplete" and len(result.events) == 1
    assert result.issues[0].reason == "malformed_event" and result.issues[0].page == 1


def test_model_threaded_signatures_remain_distinct():
    _f, clock, scope, signer, reader, _admin = model()
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(pool.map(lambda _: invoke(signer, scope), range(12)))
    clock.advance(100)
    result = reader.read_sign_records(scope, 0, 200)
    assert result.state == "complete" and len({e.event_id for e in result.events}) == 12


def test_aws_mapping_is_metadata_only_even_for_digest_message_type():
    event = normalize_aws_event(wire(aws_event()), AWS)
    assert event.capability == "metadata_only" and event.digest == ABSENT_DIGEST
    assert event.message_type == "DIGEST" and event.request_id == "aws-request-1"
    assert event.signed_at == AT and event.scope.key_resource == AWS_KEY


@pytest.mark.parametrize("location", ["top", "request", "response"])
def test_aws_shaped_event_cannot_become_digest_bearing(location):
    event = aws_event()
    if location == "top":
        event["digest"] = DIGEST.hex()
    elif location == "request":
        event["requestParameters"]["digest"] = DIGEST.hex()
    else:
        event["responseElements"] = {"digest": DIGEST.hex()}
    with pytest.raises(ValueError):
        normalize_aws_event(wire(event), AWS)


@pytest.mark.parametrize(
    "error,outcome",
    [
        (None, "success"),
        ("AccessDeniedException", "denied"),
        ("ThrottlingException", "unknown"),
    ],
)
def test_aws_outcomes(error, outcome):
    event = aws_event()
    if error:
        event["errorCode"] = error
    assert normalize_aws_event(wire(event), AWS).outcome == outcome


def test_gcp_base64_digest_and_independently_pinned_algorithm():
    event = normalize_gcp_event(wire(gcp_event()), GCP, key_export())
    assert event.digest.value == DIGEST and event.digest.provenance == "observed"
    assert event.digest.location == "protoPayload.request.digest.sha256:base64"
    assert event.algorithm == "EC_SIGN_P256_SHA256"
    assert event.algorithm_provenance.startswith("pinned:GetPublicKey:")
    assert event.outcome == "success" and event.signed_at == AT


@pytest.mark.parametrize(
    "encoded",
    [
        DIGEST.hex(),
        "!!!",
        "",
        base64.b64encode(b"short").decode(),
        base64.b64encode(DIGEST).decode() + "=",
        base64.b64encode(DIGEST).decode().rstrip("="),
        base64.b64encode(DIGEST).decode()[:-2] + "9=",  # nonzero unused pad bits
    ],
)
def test_gcp_encoding_rejects_hex_and_noncanonical_base64(encoded):
    event = gcp_event()
    event["protoPayload"]["request"]["digest"]["sha256"] = encoded
    with pytest.raises(ValueError):
        normalize_gcp_event(wire(event), GCP, key_export())


def test_gcp_missing_digest_stays_absent_and_missing_outcome_unknown():
    event = gcp_event()
    del event["protoPayload"]["request"]["digest"]
    del event["protoPayload"]["status"]
    normalized = normalize_gcp_event(wire(event), GCP, key_export())
    assert (
        normalized.digest == ABSENT_DIGEST and normalized.capability == "metadata_only"
    )
    assert normalized.outcome == "unknown"


def test_copied_correlation_alias_does_not_replace_observed_digest():
    legitimate, attacker = gcp_event(), gcp_event(OTHER)
    for event in (legitimate, attacker):
        event["protoPayload"]["request"]["caller_provided_context"] = {
            "authorization_id": "copied-alias",
            "digest": DIGEST.hex(),
        }
        event["protoPayload"]["metadata"] = {
            "entries": {"caller_provided_context": "copied-alias"}
        }
    honest = normalize_gcp_event(wire(legitimate), GCP, key_export())
    hostile = normalize_gcp_event(wire(attacker), GCP, key_export())
    assert honest.digest.value == DIGEST and hostile.digest.value == OTHER
    assert honest.digest != hostile.digest  # no matching algorithm implemented in 2b


@pytest.mark.parametrize(
    "method",
    [
        "google.cloud.kms.v1.KeyManagementService.AsymmetricSign",
        "asymmetricSign",
        "Sign",
        "",
        None,
    ],
)
def test_gcp_unknown_method_formats_fail_closed(method):
    event = gcp_event()
    event["protoPayload"]["methodName"] = method
    with pytest.raises(ValueError):
        normalize_gcp_event(wire(event), GCP, key_export())


@pytest.mark.parametrize(
    "field", ["resourceName", "authenticationInfo", "request", "@type"]
)
def test_gcp_missing_identity_fields_fail_closed(field):
    event = gcp_event()
    del event["protoPayload"][field]
    with pytest.raises(ValueError):
        normalize_gcp_event(wire(event), GCP, key_export())


@pytest.mark.parametrize("provider", ["aws", "gcp"])
def test_provider_scope_mismatch_fails_closed(provider):
    if provider == "aws":
        with pytest.raises(ValueError):
            normalize_aws_event(
                wire(aws_event()), dataclasses.replace(AWS, region="us-east-1")
            )
    else:
        with pytest.raises(ValueError):
            normalize_gcp_event(
                wire(gcp_event()),
                dataclasses.replace(GCP, key_resource=GCP_KEY[:-1] + "2"),
                key_export(),
            )


def test_pkcs11_cannot_fabricate_an_audit_capability():
    scope = AuditScope("pkcs11", "vendor-not-specified", "device", "rack", "object-id")
    with pytest.raises(MalformedEvent):
        normalize_pkcs11_event(wire({"digest": DIGEST.hex(), "success": True}), scope)
    result = unavailable_pkcs11_read(scope, 0, 100, observed_at=200)
    assert result.state == "incomplete" and result.events == ()
    assert (
        result.coverage.capability == "metadata_only"
        and not result.coverage.source_attested
    )


@pytest.mark.parametrize(
    "raw",
    [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b"[]", b"\xff", b"x" * 65537],
)
def test_wire_decode_rejects_ambiguous_and_unbounded_events(raw):
    with pytest.raises(ValueError):
        decode_json(raw)


@pytest.mark.parametrize(
    "bad", [True, False, -1, float("nan"), float("inf"), 1.0, 2**63]
)
def test_interval_rejects_invalid_times(bad):
    with pytest.raises(ValueError):
        Interval(bad, 2**63 - 1)


def test_timestamp_does_not_collapse_nanoseconds():
    assert timestamp_ns("2026-09-08T00:00:00.123456790Z") == AT + 1


def test_gcp_event_identity_includes_nanosecond_timestamp():
    first = normalize_gcp_event(wire(gcp_event()), GCP, key_export())
    raw = gcp_event()
    raw["timestamp"] = "2026-09-08T00:00:00.123456790Z"
    second = normalize_gcp_event(wire(raw), GCP, key_export())
    assert first.event_id != second.event_id
    raw["timestamp"] = STAMP
    raw["protoPayload"]["request"]["digest"]["sha256"] = base64.b64encode(
        OTHER
    ).decode()
    conflict = normalize_gcp_event(wire(raw), GCP, key_export())
    assert conflict.event_id == first.event_id and conflict != first


def test_port_has_no_gate_or_reconciliation_dependency():
    from prometheus_protocol.chokepoint import (
        audit_normalization,
        audit_source,
        audit_source_model,
    )

    for module in (audit_source, audit_source_model, audit_normalization):
        source = inspect.getsource(module)
        assert "import boto" not in source and "from google.cloud" not in source
        assert "import authorization_record" not in source
        assert "from prometheus_protocol.chokepoint.authorization_record" not in source
    assert list(
        inspect.signature(PagedSignAuditSource.read_sign_records).parameters
    ) == ["self", "scope", "start", "end"]


class StaticPages:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def read_page(self, scope, interval, token, deadline_ns):
        self.calls.append((scope, interval, token, deadline_ns))
        return self.pages[0 if token is None else int(token)]


def native_reader(pages, normalize=normalize_aws_event):
    return PagedSignAuditSource(
        pages,
        normalize,
        "metadata_only",
        utc_ns=lambda: AT + 100,
        monotonic_ns=lambda: 0,
    )


def test_native_pages_exhausted_do_not_attest_asynchronous_delivery():
    coverage = native_coverage(AWS, AT - 100, AT + 100, observed_at=AT + 100)
    pages = StaticPages(
        (
            AuditPage((), "1", 0, "snapshot", coverage),
            AuditPage((wire(aws_event()),), None, 1, "snapshot", coverage),
        )
    )
    result = native_reader(pages).read_sign_records(AWS, AT - 100, AT + 100)
    assert len(pages.calls) == 2 and len(result.events) == 1
    assert result.coverage.pages_exhausted and result.state == "incomplete"
    assert (
        not result.coverage.source_attested and result.coverage.complete_through is None
    )


def test_aws_lookup_ninety_day_retention_and_unknown_gcp_retention():
    day = 86400 * 1_000_000_000
    coverage = native_coverage(AWS, AT - 91 * day, AT, observed_at=AT)
    assert coverage.covered == Interval(AT - 90 * day, AT)
    assert coverage.gaps == (
        CoverageGap(Interval(AT - 91 * day, AT - 90 * day), "retention"),
    )
    assert coverage.capability == "metadata_only" and coverage.complete_through is None
    gcp = native_coverage(GCP, AT - day, AT, observed_at=AT)
    assert gcp.covered is None and not gcp.source_attested


@pytest.mark.parametrize(
    "fault", ["loop", "ordinal", "snapshot", "coverage", "malformed", "bounds"]
)
def test_native_page_sequence_and_row_failures_cannot_look_complete(fault):
    coverage = Coverage(
        AWS,
        Interval(AT - 100, AT + 100),
        Interval(AT - 100, AT + 100),
        AT + 100,
        (),
        AT + 100,
        "metadata_only",
        "test-only:complete-source",
    )
    first = AuditPage((), "1", 0, "snapshot", coverage)
    second = AuditPage((wire(aws_event()),), None, 1, "snapshot", coverage)
    if fault == "loop":
        second = dataclasses.replace(second, next_token="1")
    elif fault == "ordinal":
        second = dataclasses.replace(second, ordinal=2)
    elif fault == "snapshot":
        second = dataclasses.replace(second, snapshot_id="different")
    elif fault == "coverage":
        second = dataclasses.replace(
            second, coverage=dataclasses.replace(coverage, complete_through=AT)
        )
    elif fault == "malformed":
        second = dataclasses.replace(second, records=(b"{}",))
    else:
        event = aws_event()
        event["eventTime"] = "2026-09-09T00:00:00Z"
        second = dataclasses.replace(second, records=(wire(event),))
    result = native_reader(StaticPages((first, second))).read_sign_records(
        AWS, AT - 100, AT + 100
    )
    assert result.state == "incomplete" and result.issues
    assert not result.coverage.pages_exhausted


def test_normalizer_finishing_after_deadline_does_not_pass():
    clock = ModelClock(0)
    coverage = native_coverage(AWS, AT - 100, AT + 100, observed_at=AT + 100)
    pages = StaticPages(
        (AuditPage((wire(aws_event()),), None, 0, "snapshot", coverage),)
    )

    def slow_normalize(raw, scope):
        clock.advance(11)
        return normalize_aws_event(raw, scope)

    source = PagedSignAuditSource(
        pages,
        slow_normalize,
        "metadata_only",
        ReadLimits(duration_ns=10),
        utc_ns=lambda: AT + 100,
        monotonic_ns=clock.now_ns,
    )
    result = source.read_sign_records(AWS, AT - 100, AT + 100)
    assert result.events == () and result.issues[0].reason == "deadline"
    assert not result.coverage.pages_exhausted


@pytest.mark.parametrize(
    "field,value",
    [
        ("pages_exhausted", 1),
        ("complete_through", AT + 101),
        ("completeness_evidence", None),
        ("gaps", []),
    ],
)
def test_coverage_rejects_mutable_or_unattested_assertions(field, value):
    coverage = Coverage(
        AWS,
        Interval(AT - 100, AT + 100),
        Interval(AT - 100, AT + 100),
        AT + 100,
        (),
        AT + 100,
        "metadata_only",
        "test-only",
    )
    with pytest.raises(ValueError):
        dataclasses.replace(coverage, **{field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("pages", 0),
        ("records", True),
        ("bytes", -1),
        ("duration_ns", float("nan")),
        ("pages", 1025),
    ],
)
def test_read_limits_reject_invalid_configuration(field, value):
    with pytest.raises(ValueError):
        ReadLimits(**{field: value})


@pytest.mark.parametrize(
    "code,outcome", [(0, "success"), (7, "denied"), (4, "unknown")]
)
def test_gcp_explicit_status_mapping(code, outcome):
    event = gcp_event()
    event["protoPayload"]["status"] = {"code": code}
    assert normalize_gcp_event(wire(event), GCP, key_export()).outcome == outcome


def test_gcp_algorithm_export_cannot_follow_another_key_or_unknown_algorithm():
    other = GcpKeyVersion.from_public_key_export(
        wire({"name": GCP_KEY[:-1] + "2", "algorithm": "EC_SIGN_P256_SHA256"})
    )
    with pytest.raises(ValueError):
        normalize_gcp_event(wire(gcp_event()), GCP, other)
    with pytest.raises(ValueError):
        GcpKeyVersion.from_public_key_export(
            wire({"name": GCP_KEY, "algorithm": "guess"})
        )


def test_aws_alias_is_not_immutable_identity():
    event = aws_event()
    event["requestParameters"]["keyId"] = "alias/copied-correlation"
    assert normalize_aws_event(wire(event), AWS).scope.key_resource == AWS_KEY
    event["resources"][0]["ARN"] = (
        "arn:aws:kms:us-west-2:111122223333:alias/copied-correlation"
    )
    with pytest.raises(ValueError):
        normalize_aws_event(wire(event), AWS)
