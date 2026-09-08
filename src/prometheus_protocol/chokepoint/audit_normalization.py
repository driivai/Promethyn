"""Offline, version-pinned provider mappings; no SDK or network calls.

Unsupported/redacted identities and unknown schema fields raise MalformedEvent.
The page collector retains that failure as incomplete input. Digests are never
accepted from correlation labels, gate records, key names or response wrappers.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from prometheus_protocol.chokepoint.audit_source import (
    ABSENT_DIGEST,
    MAX_RECORD_BYTES,
    AuditScope,
    Caller,
    Capability,
    Coverage,
    CoverageGap,
    DigestEvidence,
    Interval,
    Outcome,
    SignEvent,
    SignRead,
    SourceIssue,
    nanoseconds,
    text_field,
)


class MalformedEvent(ValueError):
    """Unsupported or malformed source evidence; never silently dropped."""


def native_coverage(
    scope: AuditScope,
    start: int,
    end: int,
    *,
    observed_at: int,
    retained_since: int | None = None,
    gaps: tuple[CoverageGap, ...] = (),
) -> Coverage:
    """Native LookupEvents/entries.list evidence: NEVER a completeness attestation.

    AWS LookupEvents has a known 90-day boundary. GCP needs a separately
    established retention configuration; unknown retention means no coverage
    claim. Archives/vendor exports require separately validated adapters.
    """
    requested = Interval(start, end)
    nanoseconds(observed_at)
    boundary: int | None
    capability: Capability
    if scope.provider == "aws-cloudtrail":
        boundary = max(0, observed_at - 90 * 86400 * 1_000_000_000)
        if retained_since is not None:
            boundary = max(boundary, nanoseconds(retained_since))
        capability = "metadata_only"
    elif scope.provider == "gcp-audit":
        boundary = None if retained_since is None else nanoseconds(retained_since)
        capability = "digest_bound"
    else:
        raise ValueError("no supported native audit coverage mapping")
    covered = None
    if boundary is not None:
        a, b = max(start, boundary), min(end, observed_at)
        covered = Interval(a, b) if a < b else None
        if start < min(end, boundary):
            gaps = (
                CoverageGap(Interval(start, min(end, boundary)), "retention"),
                *gaps,
            )
    return Coverage(
        scope, requested, covered, None, gaps, observed_at, capability, None
    )


def fields(
    value: object, required: set[str], optional: set[str] | None = None
) -> dict[str, Any]:
    if (
        type(value) is not dict
        or not required <= value.keys()
        or value.keys() - required - (optional or set())
    ):
        raise MalformedEvent("unknown or missing source fields")
    return value


def decode_json(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_RECORD_BYTES:
        raise MalformedEvent("invalid event size")

    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise MalformedEvent("duplicate JSON field")
            out[key] = value
        return out

    def constant(_value):
        raise MalformedEvent("non-finite JSON number")

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant
        )
    except (ValueError, UnicodeError, RecursionError):
        raise MalformedEvent("malformed source JSON") from None
    if type(value) is not dict:
        raise MalformedEvent("source event is not an object")
    return value


def timestamp_ns(value: object) -> int:
    """Pin RFC3339 UTC Z; preserve all nine fractional digits, not microseconds."""
    if type(value) is not str:
        raise MalformedEvent("timestamp absent")
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z", value
    )
    if match is None:
        raise MalformedEvent("unsupported timestamp encoding")
    try:
        dt = datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        delta = dt - epoch
        return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + int(
            (match[2] or "").ljust(9, "0")
        )
    except ValueError:
        raise MalformedEvent("invalid timestamp") from None


_AWS_KEY = re.compile(
    r"arn:(aws|aws-us-gov|aws-cn):kms:([a-z0-9-]+):(\d{12}):key/([a-zA-Z0-9-]+)"
)
_GCP_KEY = re.compile(
    r"projects/([^/]+)/locations/([^/]+)/keyRings/([^/]+)/cryptoKeys/([^/]+)/cryptoKeyVersions/([1-9][0-9]*)"
)


def normalize_aws_event(raw: bytes, scope: AuditScope) -> SignEvent:
    """CloudTrailEvent JSON (not the LookupEvents envelope), metadata ONLY."""
    e = fields(
        decode_json(raw),
        {
            "eventVersion",
            "userIdentity",
            "eventTime",
            "eventSource",
            "eventName",
            "awsRegion",
            "requestParameters",
            "responseElements",
            "requestID",
            "eventID",
            "resources",
            "recipientAccountId",
        },
        {
            "sourceIPAddress",
            "userAgent",
            "readOnly",
            "eventType",
            "managementEvent",
            "eventCategory",
            "errorCode",
            "errorMessage",
            "sharedEventID",
            "vpcEndpointId",
            "vpcEndpointAccountId",
            "tlsDetails",
            "additionalEventData",
        },
    )
    if (
        scope.provider != "aws-cloudtrail"
        or e["eventSource"] != "kms.amazonaws.com"
        or e["eventName"] != "Sign"
    ):
        raise MalformedEvent("wrong AWS service/method")
    if (
        e["eventVersion"] not in ("1.08", "1.09")
        or e["awsRegion"] != scope.region
        or e["recipientAccountId"] != scope.domain
    ):
        raise MalformedEvent("unsupported AWS version or scope")
    key = _AWS_KEY.fullmatch(scope.key_resource)
    if key is None or key[2] != scope.region or key[3] != scope.domain:
        raise MalformedEvent("immutable AWS key scope required")
    resources = e["resources"]
    if type(resources) is not list or len(resources) != 1:
        raise MalformedEvent("ambiguous AWS key resource")
    resource = fields(resources[0], {"accountId", "type", "ARN"})
    if resource != {
        "accountId": scope.domain,
        "type": "AWS::KMS::Key",
        "ARN": scope.key_resource,
    }:
        raise MalformedEvent("AWS key resource mismatch")
    request = fields(
        e["requestParameters"], {"keyId", "messageType", "signingAlgorithm"}
    )
    key_id = text_field(request["keyId"])
    if key_id not in (scope.key_resource, key[4]) and not key_id.startswith("alias/"):
        raise MalformedEvent("AWS requested key mismatch")
    if request["messageType"] not in ("RAW", "DIGEST"):
        raise MalformedEvent("unknown AWS message type")
    if request["signingAlgorithm"] not in (
        "ECDSA_SHA_256",
        "ECDSA_SHA_384",
        "ECDSA_SHA_512",
        "RSASSA_PKCS1_V1_5_SHA_256",
        "RSASSA_PKCS1_V1_5_SHA_384",
        "RSASSA_PKCS1_V1_5_SHA_512",
        "RSASSA_PSS_SHA_256",
        "RSASSA_PSS_SHA_384",
        "RSASSA_PSS_SHA_512",
    ):
        raise MalformedEvent("unknown AWS algorithm")
    identity = fields(
        e["userIdentity"],
        {"type", "principalId", "arn", "accountId"},
        {"accessKeyId", "userName", "sessionContext", "invokedBy"},
    )
    if identity["type"] not in ("IAMUser", "AssumedRole"):
        raise MalformedEvent("unsupported AWS caller type")
    principal = text_field(identity["principalId"])
    arn = text_field(identity["arn"])
    account = text_field(identity["accountId"])
    if (
        not re.fullmatch(r"\d{12}", account)
        or not arn.startswith(f"arn:{key[1]}:")
        or f":{account}:" not in arn
    ):
        raise MalformedEvent("AWS authenticated caller mismatch")
    if e["responseElements"] is not None:
        raise MalformedEvent("unexpected AWS Sign response evidence")
    error = e.get("errorCode")
    outcome: Outcome
    if error is None:
        if "errorMessage" in e:
            raise MalformedEvent("AWS error missing code")
        outcome = "success"
    elif text_field(error) in (
        "AccessDenied",
        "AccessDeniedException",
        "KMS.AccessDeniedException",
    ):
        outcome = "denied"
    else:
        outcome = "unknown"
    # ARN is retained along with principalId: a reusable role/user name alone
    # is not the complete authenticated identity in the source.
    return SignEvent(
        scope,
        text_field(e["eventID"]),
        Caller(arn, principal),
        timestamp_ns(e["eventTime"]),
        outcome,
        request["signingAlgorithm"],
        "observed:requestParameters.signingAlgorithm",
        ABSENT_DIGEST,
        text_field(e["requestID"]),
        request["messageType"],
    )


@dataclass(frozen=True, slots=True)
class GcpKeyVersion:
    resource: str
    algorithm: str
    evidence_sha256: str

    @classmethod
    def from_public_key_export(cls, raw: bytes) -> GcpKeyVersion:
        """Separately trusted GetPublicKey export; NOT supplied by a gate row."""
        data = fields(
            decode_json(raw),
            {"name", "algorithm"},
            {"pem", "pemCrc32c", "protectionLevel", "publicKey"},
        )
        if (
            _GCP_KEY.fullmatch(text_field(data["name"])) is None
            or data["algorithm"] != "EC_SIGN_P256_SHA256"
        ):
            raise MalformedEvent("unsupported GCP immutable key/algorithm")
        return cls(data["name"], data["algorithm"], hashlib.sha256(raw).hexdigest())

    def __post_init__(self) -> None:
        if (
            _GCP_KEY.fullmatch(self.resource) is None
            or self.algorithm != "EC_SIGN_P256_SHA256"
            or not re.fullmatch(r"[0-9a-f]{64}", self.evidence_sha256)
        ):
            raise MalformedEvent("invalid pinned GCP version evidence")


def normalize_gcp_event(
    raw: bytes, scope: AuditScope, key_version: GcpKeyVersion
) -> SignEvent:
    e = fields(
        decode_json(raw),
        {"logName", "insertId", "timestamp", "protoPayload"},
        {
            "resource",
            "severity",
            "receiveTimestamp",
            "labels",
            "trace",
            "spanId",
            "operation",
        },
    )
    p = fields(
        e["protoPayload"],
        {
            "@type",
            "serviceName",
            "methodName",
            "resourceName",
            "authenticationInfo",
            "request",
        },
        {
            "status",
            "authorizationInfo",
            "requestMetadata",
            "response",
            "metadata",
            "numResponseItems",
        },
    )
    key = _GCP_KEY.fullmatch(scope.key_resource)
    if (
        scope.provider != "gcp-audit"
        or key is None
        or key[1] != scope.domain
        or key[2] != scope.region
    ):
        raise MalformedEvent("wrong GCP key scope")
    if (
        e["logName"] != scope.source_id
        or e["logName"]
        != f"projects/{scope.domain}/logs/cloudaudit.googleapis.com%2Fdata_access"
    ):
        raise MalformedEvent("wrong GCP log scope")
    if (
        p["@type"] != "type.googleapis.com/google.cloud.audit.AuditLog"
        or p["serviceName"] != "cloudkms.googleapis.com"
        or p["methodName"] != "AsymmetricSign"
    ):
        raise MalformedEvent("unknown GCP service/method format")
    if (
        p["resourceName"] != scope.key_resource
        or key_version.resource != scope.key_resource
    ):
        raise MalformedEvent("GCP version mismatch")
    request = fields(
        p["request"],
        {"name"},
        {"@type", "digest", "digestCrc32c", "caller_provided_context"},
    )
    if request["name"] != scope.key_resource:
        raise MalformedEvent("GCP requested version mismatch")
    if (
        "@type" in request
        and request["@type"]
        != "type.googleapis.com/google.cloud.kms.v1.AsymmetricSignRequest"
    ):
        raise MalformedEvent("unknown GCP request type")
    auth = fields(
        p["authenticationInfo"],
        {"principalEmail"},
        {
            "principalSubject",
            "serviceAccountKeyName",
            "serviceAccountDelegationInfo",
            "authoritySelector",
        },
    )
    caller = text_field(auth.get("principalSubject", auth["principalEmail"]))
    text_field(auth["principalEmail"])
    digest = ABSENT_DIGEST
    if "digest" in request:
        d = fields(request["digest"], {"sha256"})
        encoded = text_field(d["sha256"])
        try:
            value = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise MalformedEvent("invalid base64 digest") from None
        if len(value) != 32 or base64.b64encode(value).decode("ascii") != encoded:
            raise MalformedEvent("noncanonical SHA-256 base64 digest")
        digest = DigestEvidence(
            value, "observed", "protoPayload.request.digest.sha256:base64"
        )
    outcome: Outcome = "unknown"
    if "status" in p:
        status = fields(p["status"], {"code"}, {"message", "details"})
        if type(status["code"]) is not int or not 0 <= status["code"] <= 16:
            raise MalformedEvent("invalid GCP status")
        outcome = (
            "success"
            if status["code"] == 0
            else "denied"
            if status["code"] == 7
            else "unknown"
        )
    signed_at = timestamp_ns(e["timestamp"])
    # LogEntry duplicate identity includes timestamp and insertId within the
    # project/log scope; insertId alone must not collapse distinct timestamps.
    event_id = "gcp:" + json.dumps(
        [signed_at, text_field(e["insertId"])], separators=(",", ":")
    )
    return SignEvent(
        scope,
        event_id,
        Caller("cloudkms.googleapis.com", caller),
        signed_at,
        outcome,
        key_version.algorithm,
        "pinned:GetPublicKey:" + key_version.evidence_sha256,
        digest,
    )


def normalize_pkcs11_event(_raw: bytes, _scope: AuditScope) -> SignEvent:
    raise MalformedEvent(
        "no portable PKCS#11 audit-read schema; vendor evidence required"
    )


def unavailable_pkcs11_read(
    scope: AuditScope, start: int, end: int, *, observed_at: int
) -> SignRead:
    return SignRead(
        (),
        Coverage(
            scope,
            Interval(start, end),
            None,
            None,
            (),
            observed_at,
            "metadata_only",
            None,
        ),
        (SourceIssue("no_portable_audit_source"),),
    )
