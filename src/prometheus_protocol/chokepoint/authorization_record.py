"""F11's pinned authorization record. No signing, I/O or credentials here."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass

from prometheus_protocol.chokepoint.approval import (
    APPROVAL_VERSION,
    Approval,
    MigrationTarget,
    _canonical,
)
from prometheus_protocol.chokepoint.signer import SCHEMES

MAX_RECORD_BYTES = 65536
DECISION_EVENT = "authorization_decision"
SIGN_RESULT_EVENT = "authorization_sign_result"
DOMAIN = b"promethyn-authorization-record-v1\x00"
FIELDS = (
    "record_version",
    "authorization_id",
    "request_id",
    "recorded_at",
    "requester",
    "gate_identity",
    "policy_sha256",
    "decision",
    "reason",
    "artifact_sha256",
    "target",
    "nonce",
    "issued_at",
    "expires_at",
    "approval_version",
    "binding_version",
    "scheme",
    "approval_key_id",
    "signer",
    "approval_digest",
    "approval_preimage",
)
REQUESTER_FIELDS = ("identity_source", "issuer", "subject")
SIGNER_FIELDS = (
    "backend",
    "scope",
    "key_resource",
    "public_key_sha256",
    "caller_issuer",
    "caller_subject",
)
TARGET_FIELDS = ("host", "port", "database", "user", "schema")
REASONS = frozenset(
    (
        "authoritative_pass",
        "verdict_fail",
        "verifier_unavailable",
        "non_authoritative",
        "invalid_request",
        "requester_unavailable",
        "security_configuration_unavailable",
    )
)


def strict_json(value: str) -> dict:
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate record field")
            result[key] = item
        return result

    def constant(_):
        raise ValueError("non-finite JSON number")

    if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_RECORD_BYTES:
        raise ValueError("record exceeds size limit")
    result = json.loads(value, object_pairs_hook=pairs, parse_constant=constant)
    if not isinstance(result, dict):
        raise TypeError("record must be an object")
    return result


def exact_fields(value: object, fields) -> dict:
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError("missing or unknown record fields")
    return value


def text(value: object, *, empty: bool = False, maximum: int = 4096) -> bytes:
    if not isinstance(value, str) or (not empty and not value):
        raise ValueError("invalid record text")
    encoded = value.encode("utf-8", errors="strict")
    if len(encoded) > maximum:
        raise ValueError("record text exceeds size limit")
    return encoded


def hex_bytes(value: object, size: int | None = None) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise ValueError("invalid record hex")
    if size is not None and len(value) != size * 2:
        raise ValueError("invalid record hex length")
    if len(value) > MAX_RECORD_BYTES * 2:
        raise ValueError("record hex exceeds size limit")
    raw = bytes.fromhex(value)
    if raw.hex() != value:
        raise ValueError("noncanonical record hex")
    return raw


def u64(value: object) -> bytes:
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError("invalid unsigned record integer")
    return value.to_bytes(8, "big")


def finite_time(value: object) -> float:
    if not isinstance(value, (int, float)) or type(value) not in (int, float):
        raise ValueError("invalid time")
    try:
        result = float(value)
    except OverflowError:
        raise ValueError("invalid time") from None
    if not math.isfinite(result):
        raise ValueError("non-finite time")
    return result


def read_time(value: object) -> float:
    if not isinstance(value, str):
        raise TypeError("invalid record time")
    text(value, maximum=32)
    result = float.fromhex(value)
    if not math.isfinite(result) or result.hex() != value:
        raise ValueError("noncanonical record time")
    return result


def lp(value: bytes) -> bytes:
    return u64(len(value)) + value


def requester_bytes(value: object) -> bytes:
    item = exact_fields(value, REQUESTER_FIELDS)
    if item["identity_source"] not in ("local_os", "authenticated_service", "unknown"):
        raise ValueError("invalid requester source")
    unknown = item["identity_source"] == "unknown"
    if unknown and (item["issuer"] != "" or item["subject"] != ""):
        raise ValueError("unknown requester must not invent an identity")
    return b"".join(lp(text(item[k], empty=unknown)) for k in REQUESTER_FIELDS)


def signer_bytes(value: object) -> bytes:
    item = exact_fields(value, SIGNER_FIELDS)
    if item["backend"] not in ("model", "aws-kms", "gcp-kms", "pkcs11", "local-hmac"):
        raise ValueError("invalid signer backend")
    result = b""
    for key in SIGNER_FIELDS:
        if key == "public_key_sha256":
            if item[key] is None:
                if item["backend"] != "local-hmac":
                    raise ValueError("external signer requires pinned public key")
                encoded = b"\x00"
            else:
                if item["backend"] == "local-hmac":
                    raise ValueError("HMAC has no public key")
                encoded = b"\x01" + lp(hex_bytes(item[key], 32))
        else:
            encoded = text(item[key])
        result += lp(encoded)
    return result


def target_bytes(value: object) -> bytes:
    item = exact_fields(value, TARGET_FIELDS)
    MigrationTarget.from_dict(item)
    return b"".join(
        lp(u64(item[k]) if k == "port" else text(item[k])) for k in TARGET_FIELDS
    )


def binding_fields(approval: Approval) -> dict:
    """Reconstructable binding, without the bearer signature. Validate first."""
    checked = Approval.from_dict(approval.to_dict())
    return {
        "artifact_sha256": checked.artifact_sha256,
        "target": checked.target.to_dict(),
        "nonce": checked.nonce,
        "issued_at": checked.issued_at.hex(),
        "expires_at": checked.expires_at.hex(),
        "approval_version": checked.version,
        "binding_version": 2,
        "scheme": checked.scheme,
        "approval_key_id": checked.key_id,
    }


BINDING_FIELDS = (
    "artifact_sha256",
    "target",
    "nonce",
    "issued_at",
    "expires_at",
    "approval_version",
    "binding_version",
    "scheme",
    "approval_key_id",
)


def binding_preimage(value: Mapping) -> bytes:
    hex_bytes(value["artifact_sha256"], 32)
    hex_bytes(value["nonce"], 16)
    target_bytes(value["target"])
    for key, expected in (
        ("approval_version", APPROVAL_VERSION),
        ("binding_version", 2),
    ):
        u64(value[key])
        if value[key] != expected:
            raise ValueError("unsupported approval binding version")
    if value["scheme"] not in SCHEMES:
        raise ValueError("invalid signature scheme")
    key_bytes = text(value["approval_key_id"], maximum=128)
    if any(c < 0x21 or c > 0x7E for c in key_bytes):
        raise ValueError("invalid approval key id")
    issued, expires = read_time(value["issued_at"]), read_time(value["expires_at"])
    if expires <= issued:
        raise ValueError("expiry must follow issuance")
    return _canonical(
        value["artifact_sha256"],
        MigrationTarget.from_dict(value["target"]),
        value["nonce"],
        issued,
        expires,
    )


def execution_evidence(approval: Approval) -> dict:
    try:
        binding = binding_fields(approval)
        binding_preimage(binding)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return {"approval_binding": None}
    return {"approval_binding": binding}


def recovered_evidence(payload: dict) -> dict:
    value = payload.get("approval_binding")
    if value is None:
        return {"approval_binding": None}  # Legacy intent, not reconstructed evidence.
    exact_fields(value, BINDING_FIELDS)
    binding_preimage(value)
    target = MigrationTarget.from_dict(value["target"]).canonical
    if (
        payload.get("artifact_sha256") != value["artifact_sha256"]
        or payload.get("target") != target
    ):
        raise ValueError("approval binding disagrees with execution intent")
    # Pin against runner.execution_id_for in the production recovery proof.
    # The signed nonce must explain this receipt, not some other execution.
    material = json.dumps(
        {
            "artifact_sha256": value["artifact_sha256"],
            "approval_nonce": value["nonce"],
            "target": target,
            "version": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    expected = hashlib.sha256(b"promethyn-execution\x00" + material).hexdigest()
    if payload.get("execution_id") != expected:
        raise ValueError("approval binding disagrees with execution identity")
    return {"approval_binding": value}


def canonical_record(value: dict) -> bytes:
    exact_fields(value, FIELDS)
    u64(value["record_version"])
    if value["record_version"] != 1:
        raise ValueError("unsupported authorization record version")
    if (
        value["decision"] not in ("authorised", "refused")
        or value["reason"] not in REASONS
    ):
        raise ValueError("invalid authorization decision")
    authorised = value["decision"] == "authorised"
    if authorised != (value["reason"] == "authoritative_pass"):
        raise ValueError("decision/reason disagreement")
    result = DOMAIN
    for i, name in enumerate(FIELDS):
        item = value[name]
        optional = i >= 9
        if item is None and optional:
            if authorised:
                raise ValueError("authorised record has absent binding")
            encoded = b"\x00"
        else:
            if name in ("record_version", "approval_version", "binding_version"):
                encoded = u64(item)
                expected = {
                    "record_version": 1,
                    "approval_version": APPROVAL_VERSION,
                    "binding_version": 2,
                }[name]
                if item != expected:
                    raise ValueError("unsupported record or binding version")
            elif name in ("authorization_id", "request_id", "nonce"):
                encoded = hex_bytes(item, 16)
            elif name in ("artifact_sha256", "policy_sha256", "approval_digest"):
                encoded = hex_bytes(item, 32)
            elif name == "approval_preimage":
                encoded = hex_bytes(item)
            elif name in ("recorded_at", "issued_at", "expires_at"):
                read_time(item)
                encoded = text(item)
            elif name == "target":
                encoded = target_bytes(item)
            elif name == "requester":
                encoded = requester_bytes(item)
            elif name == "signer":
                encoded = signer_bytes(item)
            elif name == "scheme":
                if item not in SCHEMES:
                    raise ValueError("invalid signature scheme")
                encoded = text(item)
            elif name == "approval_key_id":
                encoded = text(item, maximum=128)
                if any(c < 0x21 or c > 0x7E for c in encoded):
                    raise ValueError("invalid approval key id")
            else:
                encoded = text(item)
            if optional:
                encoded = b"\x01" + lp(encoded)
        result += lp(encoded)
    if len(result) > MAX_RECORD_BYTES:
        raise ValueError("record exceeds size limit")
    if authorised and value["requester"]["identity_source"] == "unknown":
        raise ValueError("unknown requester cannot be authorised")
    if all(value[k] is not None for k in BINDING_FIELDS):
        preimage = binding_preimage(value)
        if value["approval_preimage"] != preimage.hex():
            raise ValueError("approval preimage disagrees with structured fields")
        if value["approval_digest"] != hashlib.sha256(preimage).hexdigest():
            raise ValueError("approval digest disagrees with recomputation")
    elif value["approval_digest"] is not None or value["approval_preimage"] is not None:
        raise ValueError("incomplete binding cannot assert a digest")
    return result


@dataclass(frozen=True, repr=False)
class AuthorizationRecord:
    """An immutable canonical snapshot; callers only receive fresh decoded copies."""

    _json: str

    def __post_init__(self) -> None:
        value = strict_json(self._json)
        exact_fields(value, (*FIELDS, "authorization_record_hash"))
        claimed = value.pop("authorization_record_hash")
        hex_bytes(claimed, 32)
        if hashlib.sha256(canonical_record(value)).hexdigest() != claimed:
            raise ValueError("authorization record hash mismatch")
        expected = json.dumps(
            {**value, "authorization_record_hash": claimed},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        if self._json != expected:
            raise ValueError("noncanonical authorization JSON")

    @classmethod
    def create(cls, value: dict) -> AuthorizationRecord:
        digest = hashlib.sha256(canonical_record(value)).hexdigest()
        return cls(
            json.dumps(
                {**value, "authorization_record_hash": digest},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        )

    @classmethod
    def from_dict(cls, value: dict) -> AuthorizationRecord:
        return cls(
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        )

    def to_dict(self) -> dict:
        return strict_json(self._json)

    @property
    def record_hash(self) -> str:
        return self.to_dict()["authorization_record_hash"]

    @property
    def authorization_id(self) -> str:
        return self.to_dict()["authorization_id"]

    def recompute_approval_digest(self) -> str:
        value = self.to_dict()
        return hashlib.sha256(binding_preimage(value)).hexdigest()

    def __repr__(self) -> str:
        return f"AuthorizationRecord(id={self.authorization_id!r})"


@dataclass(frozen=True)
class AuthorizationContext:
    """Trusted deployment inputs, snapshotted before issuance; never agent data."""

    gate_identity: str
    policy_sha256: str
    requester: dict
    signer: dict

    def snapshot(self) -> AuthorizationContext:
        # Copy via canonical serialization: the caller cannot mutate nested
        # configuration between recording and signing.
        text(self.gate_identity)
        hex_bytes(self.policy_sha256, 32)
        requester_bytes(self.requester)
        signer_bytes(self.signer)
        # Reserve space for a bounded refusal even if the request is oversized.
        if (
            len(
                json.dumps(
                    [
                        self.gate_identity,
                        self.policy_sha256,
                        self.requester,
                        self.signer,
                    ]
                ).encode("utf-8")
            )
            > 16384
        ):
            raise ValueError("authorization context exceeds size limit")
        return AuthorizationContext(
            self.gate_identity,
            self.policy_sha256,
            json.loads(json.dumps(self.requester)),
            json.loads(json.dumps(self.signer)),
        )


def validate_sign_result(payload: dict, record: AuthorizationRecord) -> None:
    exact_fields(
        payload,
        (
            "version",
            "authorization_id",
            "authorization_record_hash",
            "observed_at",
            "state",
            "reason",
            "provider_request_id",
            "approval",
        ),
    )
    if type(payload["version"]) is not int or payload["version"] != 1:
        raise ValueError("invalid sign result version")
    read_time(payload["observed_at"])
    value = record.to_dict()
    if (
        value["decision"] != "authorised"
        or payload["authorization_id"] != record.authorization_id
        or payload["authorization_record_hash"] != record.record_hash
    ):
        raise ValueError("sign result does not bind an authorised decision")
    reasons = {
        "signed": ("signature_verified",),
        "denied": ("signer_denied",),
        "malformed": ("signer_malformed",),
        "outcome_unknown": ("signer_outcome_unknown",),
        "unavailable": (
            "signer_unavailable",
            "expired_before_sign",
            "signer_identity_changed",
        ),
    }
    if (
        payload["state"] not in reasons
        or payload["reason"] not in reasons[payload["state"]]
    ):
        raise ValueError("invalid sign result state/reason")
    if payload["provider_request_id"] is not None:
        text(payload["provider_request_id"])
    if payload["state"] == "signed":
        binding = binding_fields(Approval.from_dict(payload["approval"]))
        if binding != {k: value[k] for k in BINDING_FIELDS}:
            raise ValueError("signed envelope does not match recorded binding")
    elif payload["approval"] is not None:
        raise ValueError("unsuccessful result cannot carry an approval")
