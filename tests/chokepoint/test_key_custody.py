"""PIH-2 — external key custody: forgery becomes witnessed, not silent.

The documented residual over every approval was root: whoever can read the
runner's memory reads the HMAC key and mints approvals nobody ever sees. PIH-2
moves signing to a KMS / HSM whose private key never exists on the host. It
does not stop root — it makes root ask the KMS, and the KMS writes it down.

Doctrine, so the tests can be read against it:

* **Detection, not prevention.** An insider holding the Sign-invoke permission
  gets a valid signature. The residual is a passing test, with the log entry
  it leaves as the point.
* **Couldn't-sign is not signed.** Every way the KMS can fail — unreachable,
  denied, timed out, malformed — raises a distinct ``SignerUnavailable`` and
  mints nothing, end to end through the chokepoint runner: DB untouched,
  executor never called. There is no path to a local key.
* **Proven, not asserted.** Unextractability is checked by walking the port's
  surface and the objects' attributes against the real private scalar
  obtained through the model's only reference to it — a positive control, so
  the negative assertions mean something.
* **Nothing skips.** The KMS is modelled in memory with the medium's exact
  semantics; every test runs on every CI runner.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import pickle
import re
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from f11_support import authorization_context

from prometheus_protocol.chokepoint import (
    ARTIFACT_MISMATCH,
    EXPIRED,
    EXTERNAL_SIGNER_REQUIRED_ENV,
    INVALID_SIGNATURE,
    RECEIPT_NOT_FOUND,
    REPLAY,
    TARGET_MISMATCH,
    Approval,
    ApprovalAuthority,
    DbTarget,
    KmsAccessDenied,
    KmsPort,
    KmsSigner,
    LocalHmacSigner,
    MemoryKms,
    MigrationArtifact,
    MigrationRunnerConfig,
    MigrationTarget,
    PublicKeyVerifier,
    ReceiptStatus,
    SignerCapabilityAbsent,
    SignerDenied,
    SignerMalformed,
    SignerTimeout,
    SignerUnavailable,
    SignerUnreachable,
    approval_digest,
    build_migration_runtime,
    unexplained_records,
    unwitnessed_digests,
)
from prometheus_protocol.chokepoint.approval import _canonical
from prometheus_protocol.chokepoint.authorization_journal import (
    AuthorizationUnavailable,
)
from prometheus_protocol.core.config import SECURITY_FIELDS, Config
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.core.models import Judgment, Verdict
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger

REPO = Path(__file__).resolve().parents[2]
KEY_ID = "prod/approvals"
RUNNER = "runner"
NOW = 1_000.0

#: SHA-256 of the v2 canonical bytes for a fixed input, computed on main before
#: PIH-2 touched anything. The signature primitive moved; the bytes it seals
#: did not, and this pins that.
V2_BINDING_GOLDEN = "e102b99d833531a353e14dcd05891ddf73b3d5652ab711ed24c9a38bfaa163bc"


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


class _SpyExecutor:
    """Records every DB touch. A refusal must leave ``calls`` empty."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, sql, target, execution_id, artifact_sha256):
        self.calls.append(sql)
        return True, "spy applied"


class _Audit:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def record_chained(self, **event) -> int:
        self.events.append(event)
        return len(self.events)

    def chained_events(self):
        return list(self.events)

    def verify_chain(self):
        return type("Verification", (), {"ok": True})()


def _kms() -> MemoryKms:
    kms = MemoryKms(clock=lambda: NOW)
    kms.create_key(KEY_ID)
    kms.grant_sign(KEY_ID, RUNNER)
    return kms


def _db_target() -> DbTarget:
    return DbTarget(host="127.0.0.1", port=5432, dbname="appdb", user="migrator", password="s")


def _target() -> MigrationTarget:
    return _db_target().identity


def _artifact(sql: str = "CREATE TABLE witnessed (id int);") -> MigrationArtifact:
    return MigrationArtifact(sql)


def _pass() -> Judgment:
    return Judgment(
        verdict=Verdict.PASS, confidence=1.0, authoritative=True, contributing=("hard",)
    )


def _runtime(tmp_path, signer, *, executor=None, require=False, env=None, settings=None):
    return build_migration_runtime(
        MigrationRunnerConfig(
            target=_db_target(),
            approval_store_path=tmp_path / "consumed.db",
            signer=signer,
            require_external_signer=require,
            allow_unverified_substrate=sys.platform != "linux",
        ),
        audit=SqliteLedger.private(tmp_path / "authorization.db"),
        authorization=authorization_context(signer),
        executor=executor if executor is not None else _SpyExecutor(),
        receipt_lookup=lambda execution_id, artifact_sha256, bound: ReceiptStatus(RECEIPT_NOT_FOUND),
        clock=lambda: NOW + 1,
        env=env if env is not None else {},
        settings=settings,
    )


def _private_scalar(kms: MemoryKms, key_id: str = KEY_ID) -> bytes:
    """The test's oracle: the real private key, reached through the ONE
    reference the model keeps (a closure cell). Nothing on the port gets here."""

    closure = kms._signers[key_id].__closure__
    assert closure, "the model no longer holds the key in a closure; update the oracle"
    for cell in closure:
        value = cell.cell_contents
        if isinstance(value, ec.EllipticCurvePrivateKey):
            return value.private_numbers().private_value.to_bytes(32, "big")
    raise AssertionError("no private key found in the closure")


def _walk(value, seen=None):
    """Every object reachable through attributes and containers."""

    seen = set() if seen is None else seen
    if id(value) in seen:
        return
    seen.add(id(value))
    yield value
    children = []
    if hasattr(value, "__dict__"):
        children.extend(vars(value).values())
    if isinstance(value, dict):
        children.extend(value.keys())
        children.extend(value.values())
    elif isinstance(value, (list, tuple, set, frozenset)):
        children.extend(value)
    for child in children:
        yield from _walk(child, seen)


def _contains_private_material(root, scalar: bytes) -> list[str]:
    found = []
    for item in _walk(root):
        if isinstance(item, ec.EllipticCurvePrivateKey):
            found.append("a private key object")
        if isinstance(item, (bytes, bytearray)) and scalar in bytes(item):
            found.append("the private scalar as bytes")
        if isinstance(item, str) and scalar.hex() in item:
            found.append("the private scalar as hex")
    return found


# ===========================================================================
# 1. Round trip, binding unchanged, the scheme
# ===========================================================================


def test_sign_and_verify_round_trip_through_the_kms(tmp_path):
    kms = _kms()
    executor = _SpyExecutor()
    runtime = _runtime(tmp_path, KmsSigner(kms, key_id=KEY_ID), executor=executor)
    artifact = _artifact()
    approval = runtime.authority.authorize(_pass(), artifact=artifact, target=_target(), now=NOW)
    assert approval is not None
    assert approval.scheme == "ecdsa-p256-sha256" and approval.key_id == KEY_ID
    assert runtime.authority.verify(approval, artifact=artifact, target=_target(), now=NOW + 1).ok

    result = runtime.runner.execute(approval=approval, artifact=artifact)
    assert result.executed and executor.calls == [artifact.sql]
    runtime.close()


def test_every_binding_still_blocks_with_the_external_signer(tmp_path, monkeypatch):
    """Only the primitive moved: artifact, target, expiry and single use are
    the same checks, proven by the same refusals, DB untouched each time."""

    kms = _kms()
    executor = _SpyExecutor()
    runtime = _runtime(tmp_path, KmsSigner(kms, key_id=KEY_ID), executor=executor)
    authority, runner = runtime.authority, runtime.runner
    artifact = _artifact()

    swapped = runner.execute(
        approval=authority.authorize(_pass(), artifact=artifact, target=_target(), now=NOW),
        artifact=_artifact("DROP TABLE users;"),
    )
    assert swapped.refused and swapped.reason == ARTIFACT_MISMATCH

    other = dataclasses.replace(_target(), dbname="otherdb")
    wrong_target = runner.execute(
        approval=authority.authorize(_pass(), artifact=artifact, target=other, now=NOW),
        artifact=artifact,
    )
    assert wrong_target.refused and wrong_target.reason == TARGET_MISMATCH

    stale = authority.authorize(_pass(), artifact=artifact, target=_target(), now=NOW)
    with monkeypatch.context() as m:
        m.setattr(runner, "_clock", lambda: NOW + 1000)
        expired = runner.execute(approval=stale, artifact=artifact)
    assert expired.refused and expired.reason == EXPIRED

    assert executor.calls == [], "a refusal reached the database"

    approval = authority.authorize(_pass(), artifact=artifact, target=_target(), now=NOW)
    assert runner.execute(approval=approval, artifact=artifact).executed
    replay = runner.execute(approval=approval, artifact=artifact)
    assert replay.refused and replay.reason == REPLAY
    assert executor.calls == [artifact.sql], "the replay reached the database"
    runtime.close()


def test_the_binding_is_the_v2_binding_unchanged():
    target = MigrationTarget(host="db.internal", port=5432, dbname="appdb", user="migrator", schema="public")
    sealed = _canonical("ab" * 32, target, "cd" * 16, 1000.0, 1090.0)
    assert len(sealed) == 288
    assert hashlib.sha256(sealed).hexdigest() == V2_BINDING_GOLDEN
    assert sealed.startswith(b"promethyn-approval-v2\x00")

    # The envelope names the primitive; the bound fields are exactly the v2 five.
    kms = _kms()
    approval = ApprovalAuthority(signer=KmsSigner(kms, key_id=KEY_ID)).mint(
        artifact_sha256="ab" * 32, target=target, now=1000.0, ttl_seconds=90.0
    )
    assert set(approval.to_dict()) == {
        "version", "artifact_sha256", "target", "nonce", "issued_at", "expires_at",
        "scheme", "key_id", "signature",
    }
    assert approval_digest(approval) == hashlib.sha256(
        _canonical(approval.artifact_sha256, target, approval.nonce, 1000.0, 1090.0)
    ).hexdigest()


def test_the_scheme_is_ecdsa_p256_sha256_over_the_canonical_digest():
    kms = _kms()
    signer = KmsSigner(kms, key_id=KEY_ID)
    approval = ApprovalAuthority(signer=signer).mint(
        artifact_sha256="ab" * 32, target=_target(), now=NOW
    )
    signature = bytes.fromhex(approval.signature)
    r, s = decode_dss_signature(signature)  # DER, as every KMS returns it
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    assert 0 < r < order and 0 < s < order
    public = serialization.load_der_public_key(signer.public_key_der)
    assert isinstance(public, ec.EllipticCurvePublicKey) and isinstance(public.curve, ec.SECP256R1)
    assert signer.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
    # What the KMS signed is the SHA-256 of the canonical bytes, and it says so.
    assert kms.sign_log()[-1].digest == approval_digest(approval)


@pytest.mark.parametrize(
    "field, value",
    [
        ("artifact_sha256", "ff" * 32),
        ("nonce", "00" * 16),
        ("issued_at", NOW - 1),
        ("expires_at", NOW + 1000),
        ("key_id", "prod/other"),
        ("scheme", "hmac-sha256"),
        ("signature", "ab" * 70),
    ],
)
def test_a_tampered_field_fails_the_signature(field, value):
    kms = _kms()
    authority = ApprovalAuthority(signer=KmsSigner(kms, key_id=KEY_ID))
    artifact = _artifact()
    approval = authority.mint(artifact_sha256=artifact.sha256, target=_target(), now=NOW)
    tampered = dataclasses.replace(approval, **{field: value})
    result = authority.verify(tampered, artifact=artifact, target=_target(), now=NOW + 1)
    assert not result.ok and result.reason == INVALID_SIGNATURE, (field, result)


def test_a_tampered_target_fails_the_signature():
    kms = _kms()
    authority = ApprovalAuthority(signer=KmsSigner(kms, key_id=KEY_ID))
    artifact = _artifact()
    approval = authority.mint(artifact_sha256=artifact.sha256, target=_target(), now=NOW)
    other = dataclasses.replace(approval, target=dataclasses.replace(_target(), schema="hostile"))
    result = authority.verify(other, artifact=artifact, target=other.target, now=NOW + 1)
    assert not result.ok and result.reason == INVALID_SIGNATURE


def test_schemes_and_keys_do_not_cross():
    kms = _kms()
    kms.create_key("prod/other")
    kms.grant_sign("prod/other", RUNNER)
    artifact = _artifact()
    local = ApprovalAuthority(key=b"k" * 32)
    kms_a = ApprovalAuthority(signer=KmsSigner(kms, key_id=KEY_ID))
    kms_b = ApprovalAuthority(signer=KmsSigner(kms, key_id="prod/other"))

    from_local = local.mint(artifact_sha256=artifact.sha256, target=_target(), now=NOW)
    from_a = kms_a.mint(artifact_sha256=artifact.sha256, target=_target(), now=NOW)
    assert from_local.scheme == "hmac-sha256" and from_a.scheme == "ecdsa-p256-sha256"

    assert not kms_a.verify(from_local, artifact=artifact, target=_target(), now=NOW + 1).ok
    assert not local.verify(from_a, artifact=artifact, target=_target(), now=NOW + 1).ok
    assert not kms_b.verify(from_a, artifact=artifact, target=_target(), now=NOW + 1).ok
    assert kms_a.verify(from_a, artifact=artifact, target=_target(), now=NOW + 1).ok
    assert local.verify(from_local, artifact=artifact, target=_target(), now=NOW + 1).ok


def test_the_envelope_survives_the_wire_and_rejects_what_it_should():
    kms = _kms()
    for authority in (ApprovalAuthority(signer=KmsSigner(kms, key_id=KEY_ID)), ApprovalAuthority(key=b"k" * 32)):
        approval = authority.mint(artifact_sha256="ab" * 32, target=_target(), now=NOW)
        assert Approval.from_json(approval.to_json()) == approval

    base = ApprovalAuthority(signer=KmsSigner(kms, key_id=KEY_ID)).mint(
        artifact_sha256="ab" * 32, target=_target(), now=NOW
    ).to_dict()
    for bad in (
        {"scheme": "rsa-pss"},
        {"key_id": ""},
        {"key_id": "with\ttab"},
        {"key_id": "x" * 129},
        {"signature": "abc"},
        {"signature": "zz" * 40},
        {"scheme": "hmac-sha256", "signature": "ab" * 70},
        {"version": 2},
    ):
        with pytest.raises((ValueError, TypeError)):
            Approval.from_dict({**base, **bad})
    with pytest.raises(ValueError):
        Approval.from_dict({k: v for k, v in base.items() if k != "key_id"})


# ===========================================================================
# 2. Unextractability, proven against the real scalar
# ===========================================================================


def test_no_port_operation_returns_key_material():
    kms = _kms()
    scalar = _private_scalar(kms)
    # Positive control: the oracle IS the key the KMS signs with — its public
    # point matches the public key the port hands out.
    derived = ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1()).public_key()
    assert derived.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) == kms.get_public_key(KEY_ID)

    signature = kms.sign(KEY_ID, hashlib.sha256(b"message").digest(), principal=RUNNER)
    public = kms.get_public_key(KEY_ID)
    for name, value in (("sign", signature), ("get_public_key", public)):
        assert isinstance(value, bytes), name
        assert scalar not in value and scalar.hex().encode() not in value, name
    # There is no third operation on the port.
    assert {n for n in vars(KmsPort).get("__protocol_attrs__", set()) if not n.startswith("_")} <= {"sign", "get_public_key"} or True
    port_methods = {name for name in dir(KmsPort) if not name.startswith("_")}
    assert port_methods == {"sign", "get_public_key"}


def test_the_model_and_the_signer_hold_no_private_material_in_their_attributes():
    kms = _kms()
    scalar = _private_scalar(kms)
    signer = KmsSigner(kms, key_id=KEY_ID)
    authority = ApprovalAuthority(signer=signer)
    authority.mint(artifact_sha256="ab" * 32, target=_target(), now=NOW)

    # Attribute walk: the only reference to the key is inside a closure, which
    # is not an attribute of anything and not reachable through the port.
    assert _contains_private_material(vars(kms), scalar) == []
    assert _contains_private_material(signer, scalar) == []
    assert _contains_private_material(authority, scalar) == []
    for rendered in (repr(kms), repr(signer), repr(authority), signer.public_key_pem):
        assert scalar.hex() not in rendered
    with pytest.raises(TypeError):
        pickle.dumps(kms)  # a KMS cannot be serialized: its keys do not leave it


def test_the_kms_surface_has_no_export_and_no_erase():
    kms = _kms()
    public = {name for name in dir(kms) if not name.startswith("_")}
    assert public == {
        "create_key", "grant_sign", "revoke_sign", "can_sign",
        "sign", "get_public_key", "sign_log", "fault",
    }
    assert not [n for n in public if re.search(r"export|extract|private|secret", n)]
    assert not [n for n in public if re.search(r"clear|delete|erase|reset|purge|truncate|remove", n)]


# ===========================================================================
# 3. The verify side holds no signing material
# ===========================================================================


def test_verification_uses_the_public_key_and_never_the_kms():
    kms = _kms()
    signer = KmsSigner(kms, key_id=KEY_ID)
    artifact = _artifact()
    approval = ApprovalAuthority(signer=signer).mint(
        artifact_sha256=artifact.sha256, target=_target(), now=NOW
    )
    verifier = PublicKeyVerifier(signer.public_key_pem, key_id=KEY_ID)
    verify_only = ApprovalAuthority(signer=verifier)
    assert verify_only.external is True
    assert _contains_private_material(verifier, _private_scalar(kms)) == []
    assert not [v for v in _walk(verify_only) if isinstance(v, LocalHmacSigner)]

    log_before = kms.sign_log()
    kms.fault = "unreachable"  # the KMS is gone; verification does not notice
    assert verify_only.verify(approval, artifact=artifact, target=_target(), now=NOW + 1).ok
    assert signer.verify(_canonical(approval.artifact_sha256, _target(), approval.nonce, approval.issued_at, approval.expires_at), bytes.fromhex(approval.signature))
    assert kms.sign_log() == log_before, "verification made a KMS request"


def test_a_verify_only_host_cannot_mint_but_can_execute_what_the_gate_signed(tmp_path):
    """The split-role deployment: the gate signs through the KMS, the runner
    holds the public key only. A runner host compromise yields no signing
    capability at all — there is nothing there to steal or to invoke."""

    kms = _kms()
    gate = ApprovalAuthority(signer=KmsSigner(kms, key_id=KEY_ID))
    verifier = PublicKeyVerifier(gate.signer.public_key_der, key_id=KEY_ID)
    executor = _SpyExecutor()
    runtime = _runtime(tmp_path, verifier, executor=executor)

    with pytest.raises(SignerCapabilityAbsent):
        runtime.authority.authorize(_pass(), artifact=_artifact(), target=_target(), now=NOW)
    with pytest.raises(SignerCapabilityAbsent):
        runtime.authority.mint(artifact_sha256="ab" * 32, target=_target(), now=NOW)
    assert executor.calls == []

    artifact = _artifact()
    approval = gate.authorize(_pass(), artifact=artifact, target=_target(), now=NOW)
    assert runtime.runner.execute(approval=approval, artifact=artifact).executed
    assert executor.calls == [artifact.sql]
    runtime.close()


# ===========================================================================
# 4. The witness: every Sign is a record the host cannot erase
# ===========================================================================


def test_every_sign_appends_a_record_the_auditor_can_match():
    kms = _kms()
    authority = ApprovalAuthority(signer=KmsSigner(kms, key_id=KEY_ID))
    approvals = [
        authority.mint(artifact_sha256=f"{i:02x}" * 32, target=_target(), now=NOW) for i in range(3)
    ]
    log = kms.sign_log()
    assert [record.index for record in log] == [0, 1, 2]
    assert [record.digest for record in log] == [approval_digest(a) for a in approvals]
    assert all(record.principal == RUNNER and record.outcome == "signed" for record in log)
    assert all(record.key_id == KEY_ID for record in log)
    assert unwitnessed_digests([approval_digest(a) for a in approvals], log) == []
    assert unexplained_records(log, [approval_digest(a) for a in approvals]) == []


def test_a_denied_attempt_is_a_record_too():
    kms = _kms()
    with pytest.raises(KmsAccessDenied):
        kms.sign(KEY_ID, hashlib.sha256(b"x").digest(), principal="insider")
    (record,) = kms.sign_log()
    assert record.principal == "insider" and record.outcome == "denied"
    assert unexplained_records(kms.sign_log(), []) == [record]


def test_the_log_is_append_only_and_a_copy():
    kms = _kms()
    kms.sign(KEY_ID, hashlib.sha256(b"x").digest(), principal=RUNNER)
    log = kms.sign_log()
    assert isinstance(log, tuple)
    assert kms.sign_log() == log
    with pytest.raises(AttributeError):
        log.append(None)


def test_an_approval_the_kms_never_signed_is_unwitnessed():
    """A valid-looking approval with no Sign record means the key exists
    somewhere other than the KMS, or the log was tampered with. Either is the
    alarm this reconciliation exists to raise."""

    kms = _kms()
    local = ApprovalAuthority(key=b"k" * 32).mint(artifact_sha256="ab" * 32, target=_target(), now=NOW)
    assert unwitnessed_digests([approval_digest(local)], kms.sign_log()) == [approval_digest(local)]


# ===========================================================================
# 5. Fail-closed: couldn't-sign is not signed — end to end
# ===========================================================================


@pytest.mark.parametrize(
    "fault, expected",
    [
        ("unreachable", SignerUnreachable),
        ("timeout", SignerTimeout),
        ("garbage", SignerMalformed),
        ("denied", SignerDenied),
    ],
)
def test_a_kms_failure_mints_nothing_and_the_db_is_untouched(tmp_path, fault, expected):
    kms = _kms()
    executor = _SpyExecutor()
    runtime = _runtime(tmp_path, KmsSigner(kms, key_id=KEY_ID), executor=executor)
    if fault == "denied":
        kms.revoke_sign(KEY_ID, RUNNER)
    else:
        kms.fault = fault

    artifact = _artifact()
    with pytest.raises(expected) as raised:
        runtime.authority.authorize(_pass(), artifact=artifact, target=_target(), now=NOW)
    assert isinstance(raised.value, SignerUnavailable) and raised.value.kind == expected.kind
    with pytest.raises(AuthorizationUnavailable, match="authorize"):
        runtime.authority.mint(artifact_sha256=artifact.sha256, target=_target(), now=NOW)
    assert executor.calls == [], "the migration ran with no approval"

    # A failure the KMS never saw leaves no record; one it refused, or answered
    # badly, does — the trail is the medium's, not this code's.
    if fault in ("unreachable", "timeout"):
        assert kms.sign_log() == ()
    else:
        assert kms.sign_log()[-1].outcome == ("denied" if fault == "denied" else "signed")
    runtime.close()


@pytest.mark.parametrize(
    "fault, expected",
    [("unreachable", SignerUnreachable), ("timeout", SignerTimeout), ("garbage", SignerMalformed)],
)
def test_a_kms_failure_at_construction_refuses_the_signer(fault, expected):
    kms = _kms()
    kms.fault = fault
    with pytest.raises(expected):
        KmsSigner(kms, key_id=KEY_ID)


def test_a_signature_by_the_wrong_key_is_a_malformed_answer():
    """A KMS that answers with a valid signature by some OTHER key is refused:
    the answer is checked under the configured key's public key before use."""

    kms = _kms()
    kms.create_key("prod/other")
    kms.grant_sign("prod/other", RUNNER)

    class _Swapped:
        def sign(self, key_id, digest, *, principal):
            return kms.sign("prod/other", digest, principal=principal)

        def get_public_key(self, key_id):
            return kms.get_public_key(key_id)

    signer = KmsSigner(_Swapped(), key_id=KEY_ID)
    with pytest.raises(SignerMalformed):
        signer.sign(b"message")


def test_end_to_end_a_forgery_under_a_kms_config_is_refused_and_the_path_recovers(tmp_path):
    kms = _kms()
    executor = _SpyExecutor()
    runtime = _runtime(tmp_path, KmsSigner(kms, key_id=KEY_ID), executor=executor)
    artifact = _artifact("DROP TABLE users;")

    # The insider cannot read a key, so they forge with one of their own.
    forged = ApprovalAuthority(key=b"i" * 32).mint(
        artifact_sha256=artifact.sha256, target=_target(), now=NOW
    )
    forged = dataclasses.replace(forged, scheme="ecdsa-p256-sha256", key_id=KEY_ID, signature="ab" * 70)
    result = runtime.runner.execute(approval=forged, artifact=artifact)
    assert result.refused and result.reason == INVALID_SIGNATURE
    assert executor.calls == []

    # KMS down: nothing minted, nothing executed.
    kms.fault = "unreachable"
    with pytest.raises(SignerUnreachable):
        runtime.authority.authorize(_pass(), artifact=_artifact(), target=_target(), now=NOW)
    assert executor.calls == []

    # KMS back: the path is live, so the refusals above were not a dead path.
    kms.fault = None
    good = _artifact()
    approval = runtime.authority.authorize(_pass(), artifact=good, target=_target(), now=NOW)
    assert runtime.runner.execute(approval=approval, artifact=good).executed
    assert executor.calls == [good.sql]
    runtime.close()


def test_no_silent_fallback_to_a_local_key(tmp_path, monkeypatch):
    calls: list[bytes] = []
    original = LocalHmacSigner.sign

    def _spy(self, message):
        calls.append(message)
        return original(self, message)

    monkeypatch.setattr(LocalHmacSigner, "sign", _spy)

    kms = _kms()
    runtime = _runtime(tmp_path, KmsSigner(kms, key_id=KEY_ID))
    runtime.authority.authorize(_pass(), artifact=_artifact(), target=_target(), now=NOW)
    kms.fault = "unreachable"
    with pytest.raises(SignerUnreachable):
        runtime.authority.authorize(_pass(), artifact=_artifact(), target=_target(), now=NOW)
    assert calls == [], "a local HMAC signer was used under a KMS configuration"
    assert not [v for v in _walk(runtime.authority) if isinstance(v, LocalHmacSigner)]
    assert isinstance(runtime.authority.signer, KmsSigner)
    runtime.close()

    kms.fault = None
    with pytest.raises(ValueError, match="exactly one"):
        MigrationRunnerConfig(
            target=_db_target(), approval_store_path=tmp_path / "c.db",
            signing_key=b"k" * 32, signer=KmsSigner(kms, key_id=KEY_ID),
        )
    with pytest.raises(ValueError, match="exactly one"):
        MigrationRunnerConfig(target=_db_target(), approval_store_path=tmp_path / "c.db")


# ===========================================================================
# 6. THE RESIDUAL — witnessed, not prevented, as a passing test
# ===========================================================================


def test_an_insider_with_sign_invoke_gets_a_valid_signature_AND_is_logged(tmp_path):
    """Stated as a passing test because it is the residual, not a defect.

    The KMS signs for whoever holds the invoke permission. An insider who
    holds it mints an approval for hostile SQL and the runner executes it —
    NOT prevented. What the insider cannot do is make that silent: the KMS
    log carries their principal and the digest of exactly that approval, and
    the auditor's reconciliation flags it against the ledger. Stopping them
    outright takes a second party (PIH-3, buyer-gated).
    """

    kms = _kms()
    kms.grant_sign(KEY_ID, "insider")  # the deployment's policy let them
    executor = _SpyExecutor()
    runtime = _runtime(tmp_path, KmsSigner(kms, key_id=KEY_ID), executor=executor)

    legitimate = runtime.authority.authorize(_pass(), artifact=_artifact(), target=_target(), now=NOW)
    hostile = _artifact("DROP TABLE users;")
    insider = ApprovalAuthority(signer=KmsSigner(kms, key_id=KEY_ID, principal="insider"))
    forged = insider.mint(artifact_sha256=hostile.sha256, target=_target(), now=NOW)

    result = runtime.runner.execute(approval=forged, artifact=hostile)
    assert result.executed and executor.calls == [hostile.sql], (
        "this documents the residual: an insider holding kms:Sign is not stopped"
    )

    # Witnessed: the record names them and the exact approval.
    flagged = unexplained_records(kms.sign_log(), [approval_digest(legitimate)])
    assert len(flagged) == 1
    assert flagged[0].principal == "insider" and flagged[0].digest == approval_digest(forged)
    assert flagged[0].outcome == "signed"
    runtime.close()


def test_an_insider_without_sign_invoke_is_denied_and_the_attempt_is_logged():
    kms = _kms()
    insider = ApprovalAuthority(signer=KmsSigner(kms, key_id=KEY_ID, principal="insider"))
    with pytest.raises(SignerDenied):
        insider.mint(artifact_sha256="ab" * 32, target=_target(), now=NOW)
    (record,) = kms.sign_log()
    assert record.principal == "insider" and record.outcome == "denied"


def test_the_invoke_holder_cannot_administer_the_key():
    """Separation of duties, which the deployment's access policy must
    reproduce: whoever may invoke Sign may not grant Sign or create keys."""

    kms = _kms()
    for principal in (RUNNER, "insider"):
        with pytest.raises(KmsAccessDenied):
            kms.grant_sign(KEY_ID, "insider", by=principal)
        with pytest.raises(KmsAccessDenied):
            kms.create_key("prod/rogue", by=principal)
    assert not kms.can_sign(KEY_ID, "insider")


# ===========================================================================
# 7. The requirement: honoured or refused, the OR of its sources
# ===========================================================================


def test_signers_are_labelled():
    kms = _kms()
    local = LocalHmacSigner(b"k" * 32)
    assert local.external is False and local.key_id.startswith("hmac:")
    assert (b"k" * 32).hex() not in local.key_id and "kkkk" not in repr(local)
    assert KmsSigner(kms, key_id=KEY_ID).external is True
    assert PublicKeyVerifier(kms.get_public_key(KEY_ID), key_id=KEY_ID).external is True
    assert ApprovalAuthority(key=b"k" * 32).external is False


def test_the_requirement_refuses_a_local_key_as_cannot_be_honoured(tmp_path):
    with pytest.raises(ConfigError, match="cannot be honoured"):
        MigrationRunnerConfig(
            target=_db_target(), approval_store_path=tmp_path / "c.db",
            signing_key=b"k" * 32, require_external_signer=True,
        )
    local = MigrationRunnerConfig(
        target=_db_target(), approval_store_path=tmp_path / "c.db", signing_key=b"k" * 32,
        allow_unverified_substrate=sys.platform != "linux",
    )
    common = dict(audit=SqliteLedger.private(tmp_path / "authorization.db"), executor=_SpyExecutor(), clock=lambda: NOW,
                  receipt_lookup=lambda *a: ReceiptStatus(RECEIPT_NOT_FOUND))
    # The environment alone raises the requirement …
    with pytest.raises(ConfigError, match="required"):
        build_migration_runtime(local, env={EXTERNAL_SIGNER_REQUIRED_ENV: "1"}, **common)
    # … and so does the runtime Config.
    with pytest.raises(ConfigError, match="required"):
        build_migration_runtime(local, env={}, settings=Config(require_external_signer=True), **common)
    # With an external signer the requirement is met.
    kms = _kms()
    signer = KmsSigner(kms, key_id=KEY_ID)
    runtime = build_migration_runtime(
        MigrationRunnerConfig(
            target=_db_target(), approval_store_path=tmp_path / "d.db",
            signer=signer, require_external_signer=True,
            allow_unverified_substrate=sys.platform != "linux",
        ),
        authorization=authorization_context(signer),
        env={EXTERNAL_SIGNER_REQUIRED_ENV: "1"}, settings=Config(require_external_signer=True), **common,
    )
    assert runtime.authority.external
    runtime.close()


def test_the_requirement_is_a_declared_security_field():
    assert "require_external_signer" in SECURITY_FIELDS
    assert Config().require_external_signer is False
    assert Config.from_env({"PROM_REQUIRE_EXTERNAL_SIGNER": "1"}).require_external_signer is True


def test_a_local_signer_is_warned_about_as_non_protecting(tmp_path, caplog):
    local = MigrationRunnerConfig(
        target=_db_target(), approval_store_path=tmp_path / "c.db", signing_key=b"k" * 32,
        allow_unverified_substrate=sys.platform != "linux",
    )
    with caplog.at_level(logging.WARNING, logger="prometheus_protocol.chokepoint.runner"):
        runtime = build_migration_runtime(
            local, audit=SqliteLedger.private(tmp_path / "authorization.db"), executor=_SpyExecutor(), clock=lambda: NOW,
            authorization=authorization_context(LocalHmacSigner(b"k" * 32)),
            receipt_lookup=lambda *a: ReceiptStatus(RECEIPT_NOT_FOUND), env={},
        )
    runtime.close()
    assert any("NON-PROTECTING" in record.message for record in caplog.records)
    assert not any((b"k" * 32).hex() in record.message for record in caplog.records)

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="prometheus_protocol.chokepoint.runner"):
        _runtime(tmp_path, KmsSigner(_kms(), key_id=KEY_ID)).close()
    assert not [r for r in caplog.records if "NON-PROTECTING" in r.message]


# ===========================================================================
# 8. The docs say what the code does — and what it does not
# ===========================================================================


def test_the_docs_state_detection_not_prevention_and_the_residual():
    threat = (REPO / "docs" / "threat-model.md").read_text(encoding="utf-8")
    custody = (REPO / "docs" / "key-custody.md").read_text(encoding="utf-8")
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    lower_threat, lower_custody = threat.lower(), custody.lower()

    assert "PIH-2" in threat and "key-custody.md" in threat
    assert "detection, not prevention" in lower_threat and "detection, not prevention" in lower_custody
    assert "kms:sign" in lower_custody or "sign-invoke" in lower_custody
    assert "non-protecting" in lower_custody and "non-protecting" in lower_threat
    assert "access policy" in lower_custody and "administer" in lower_custody
    assert "test_an_insider_with_sign_invoke_gets_a_valid_signature_and_is_logged" in lower_custody
    assert "ecdsa" in lower_custody and "p-256" in lower_custody
    for call in ("GetPublicKey", "asymmetricSign", "C_Sign", "GenerateMac"):
        assert call in custody, f"the KMS mapping must name {call}"
    assert "prom_require_external_signer" in lower_custody
    assert "cryptography" in pyproject
    for text in (threat, custody):
        for overclaim in ("cannot be forged", "impossible to forge", "prevents forgery", "tamper-proof."):
            assert overclaim not in text.lower(), f"overclaim: {overclaim!r}"
