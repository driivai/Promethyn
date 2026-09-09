"""PIH-4a: a silent security-config downgrade is detectable by an external
witness — and the two things this does NOT prove are proven too.

Every test here is a property. The decisive one is
``test_one_declared_config_resolving_weaker_produces_a_different_digest``: if
the digest were taken over what ``Config`` *says*, an operator whose posture
silently resolved to something weaker would publish an unchanged digest and the
attestation would miss exactly the downgrade it exists to catch.

The honest limits are passing tests, not caveats: a deliberately weak posture
attests ATTESTED (configuration correctness is not covered), binary integrity is
not covered at all, and an insider who controls both the running config and the
published target is not detected. Nothing here is uncrackable.
"""

from __future__ import annotations

from typing import Any

import ast
import dataclasses
import json
import subprocess
import sys
from pathlib import Path

import pytest

from prometheus_protocol.attestation import (
    ATTESTED,
    CONFIG_ATTESTATION_REQUIRED_ENV,
    MISMATCH,
    NOT_VERIFIABLE,
    POSTURE_FIELDS,
    TARGET_FILE,
    TARGET_LOG,
    TARGET_WORM,
    AttestationRecord,
    AttestationUnavailable,
    ConfigAttestor,
    LocalFileAttestationTarget,
    LogAttestationTarget,
    ObjectStoreAttestationTarget,
    ResolvedPosture,
    attestation_target_for,
    build_attestation_target,
    build_config_attestor,
    config_attestation_required,
    posture_digest,
    posture_preimage,
    resolve_posture,
    verify_attestation,
)
from prometheus_protocol.attestation import attest as attest_module
from prometheus_protocol.attestation import posture as posture_module
from prometheus_protocol.chokepoint.kms_model import MemoryKms
from prometheus_protocol.chokepoint.signer import (
    KmsSigner,
    LocalHmacSigner,
    PublicKeyVerifier,
    SignerUnavailable,
)
from prometheus_protocol.core.anchor_spec import parse_anchor_spec
from prometheus_protocol.core.config import SECURITY_FIELDS, Config
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.ledger.anchor_targets import (
    MemoryAppendOnlyLog,
    MemoryObjectLockStore,
)
from prometheus_protocol.sandbox.container import ContainerSandbox
from prometheus_protocol.sandbox.namespace import NamespaceSandbox

KEY = bytes.fromhex("a1" * 32)


def signer():
    return LocalHmacSigner(KEY)


def a_posture(**overrides: Any) -> ResolvedPosture:
    """A fixed, fully specified posture. Never resolved from this host, so the
    digest assertions below are about the encoding, not about the runner.

    ``**overrides`` is heterogeneous by construction — each key is a different
    field type — so ``dict[str, Any]`` states what the base holds rather than
    letting the join collapse to a type no field accepts. Every field is still
    checked against its own annotation at the ResolvedPosture call.
    """

    base: dict[str, Any] = dict(
        sandbox_adapter="namespace",
        sandbox_isolating=True,
        digest_pin_active=False,
        provider="mock",
        tls_required=True,
        anchor_required=True,
        anchor_target_class=TARGET_WORM,
        anchor_append_only=True,
        signer_scheme="ecdsa-p256-sha256",
        signer_external=True,
        signer_key_id="kms:alias/approvals",
        substrate_require_verified=True,
        substrate_allow_unverified=False,
        substrate_verdict="safe",
        substrate_fs_type="ext4",
        attestation_required=True,
        attestation_target_class=TARGET_LOG,
        attestation_target_external=True,
        verifier_timeout_s=5.0,
        verifier_memory_mb=256,
        verifier_cpu_seconds=5,
        verifier_max_processes=64,
        request_timeout_s=30.0,
        provider_max_response_bytes=4 * 1024 * 1024,
        max_role_calls=16,
        pending_ttl_seconds=86_400,
        gate_threshold=0.0,
        escalate_below=0.75,
        ledger_anchor_retention_days=3650,
    )
    base.update(overrides)
    return ResolvedPosture(**base)


def availability(monkeypatch, *, namespace: bool, container: bool) -> None:
    monkeypatch.setattr(NamespaceSandbox, "available", classmethod(lambda cls: namespace))
    monkeypatch.setattr(ContainerSandbox, "available", classmethod(lambda cls: container))


# ===========================================================================
# 1. The digest: deterministic, and no collision on the covered surface
# ===========================================================================


def test_the_digest_is_deterministic_for_one_posture():
    assert posture_digest(a_posture()) == posture_digest(a_posture())
    assert len(posture_digest(a_posture())) == 64


def test_the_digest_is_byte_identical_in_another_process():
    """A digest that depended on hash seeds, dict order or memory addresses
    would be useless as an external record. Proven by a real subprocess, not by
    calling the function twice in this one."""

    program = (
        "import json,sys;"
        "sys.path.insert(0, 'tests');"
        "from conformance.test_config_attestation import a_posture;"
        "from prometheus_protocol.attestation import posture_digest, posture_preimage;"
        "print(json.dumps([posture_digest(a_posture()), posture_preimage(a_posture()).hex()]))"
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True, text=True, timeout=120,
        cwd=str(Path(__file__).resolve().parents[2]),
        env={"PYTHONHASHSEED": "1", "PATH": "/usr/bin:/bin"},
    )
    assert result.returncode == 0, result.stderr
    digest, preimage = json.loads(result.stdout.strip().splitlines()[-1])
    assert digest == posture_digest(a_posture())
    assert preimage == posture_preimage(a_posture()).hex()


#: One materially different value per covered field. Flipping any one of them
#: is a different security posture and must be a different digest.
_FLIPS: dict[str, object] = {
    "sandbox_adapter": "unsafe",
    "sandbox_isolating": False,
    "digest_pin_active": True,
    "provider": "remote",
    "tls_required": False,
    "anchor_required": False,
    "anchor_target_class": TARGET_FILE,
    "anchor_append_only": False,
    "signer_scheme": "hmac-sha256",
    "signer_external": False,
    "signer_key_id": "hmac:0123456789abcdef",
    "substrate_require_verified": False,
    "substrate_allow_unverified": True,
    "substrate_verdict": "unknown",
    "substrate_fs_type": None,
    "attestation_required": False,
    "attestation_target_class": TARGET_FILE,
    "attestation_target_external": False,
    "verifier_timeout_s": 5.000000000000001,
    "verifier_memory_mb": 257,
    "verifier_cpu_seconds": 6,
    "verifier_max_processes": 65,
    "request_timeout_s": 31.0,
    "provider_max_response_bytes": 4 * 1024 * 1024 + 1,
    "max_role_calls": 17,
    "pending_ttl_seconds": 0,
    "gate_threshold": 0.5,
    "escalate_below": 0.0,
    "ledger_anchor_retention_days": 1,
}


@pytest.mark.parametrize("field", sorted(_FLIPS))
def test_changing_any_covered_field_changes_the_digest(field):
    assert posture_digest(a_posture(**{field: _FLIPS[field]})) != posture_digest(a_posture())


def test_no_two_covered_postures_share_a_digest():
    """Pairwise, not just against the base: a digest that collided between two
    flips would let one downgrade masquerade as another."""

    digests = {posture_digest(a_posture())} | {
        posture_digest(a_posture(**{name: value})) for name, value in _FLIPS.items()
    }
    assert len(digests) == len(_FLIPS) + 1


def test_every_posture_field_is_covered_by_the_digest_and_by_a_flip():
    """The void-guard check: a field added to the posture but left out of
    POSTURE_FIELDS would be attested by nothing, silently."""

    declared = tuple(f.name for f in dataclasses.fields(ResolvedPosture))
    assert POSTURE_FIELDS == declared, "POSTURE_FIELDS drifted from the posture"
    assert set(_FLIPS) == set(declared), "a covered field has no flip test"


#: The canonical encoding, pinned as a known answer. Any change to the domain
#: separator, the field order, the committed field count, the per-field name
#: commitment, the length prefixes or the type tags moves this — which is the
#: point: an encoding that can drift silently is two digests for one posture.
#: Change it only with a deliberate version bump of the domain separator.
GOLDEN_DIGEST = "4b910cb267b7ec16ea5e60ff77a63531891e7de419e797e35c1bd701cc4864e7"
GOLDEN_PREIMAGE_BYTES = 1216


def test_the_canonical_encoding_matches_its_pinned_known_answer():
    assert posture_digest(a_posture()) == GOLDEN_DIGEST
    assert len(posture_preimage(a_posture())) == GOLDEN_PREIMAGE_BYTES
    # And the preimage is reconstructible by hand from the documented rule, so
    # an auditor does not have to trust the function that produced it.
    expected = bytearray(b"prom-config-posture-v1\x00")
    expected += len(POSTURE_FIELDS).to_bytes(8, "big")
    for name in POSTURE_FIELDS:
        field = name.encode("ascii")
        value = posture_module.encode_value(getattr(a_posture(), name))
        expected += len(field).to_bytes(8, "big") + field
        expected += len(value).to_bytes(8, "big") + value
    assert bytes(expected) == posture_preimage(a_posture())


def test_the_encoding_is_typed_and_length_prefixed():
    """Ambiguous encoding means two postures with one digest. The type tag is
    what keeps True, 1 and "1" apart; the length prefix is what stops a value
    from impersonating a field boundary."""

    assert posture_module.encode_value(True) != posture_module.encode_value(1)
    assert posture_module.encode_value(1) != posture_module.encode_value("1")
    assert posture_module.encode_value(None) != posture_module.encode_value("")
    # A value containing the next field's name cannot shift the boundary.
    shifted = a_posture(sandbox_adapter="namespace\x00sandbox_isolating")
    assert posture_digest(shifted) != posture_digest(a_posture())
    preimage = posture_preimage(a_posture())
    assert preimage.startswith(b"prom-config-posture-v1\x00")
    assert len(POSTURE_FIELDS).to_bytes(8, "big") in preimage[:40]
    with pytest.raises(TypeError):
        posture_module.encode_value(["not", "encodable"])
    with pytest.raises(ValueError):
        posture_module.encode_value(float("nan"))


# ===========================================================================
# 2. Resolved, not declared — the test that decides whether this works
# ===========================================================================


def test_one_declared_config_resolving_weaker_produces_a_different_digest(monkeypatch, tmp_path):
    """The Attacker-5 lesson, as a test.

    ONE declared Config — byte-identical, ``sandbox="auto"``, the default
    hardened intent — resolved on three hosts. Where an isolating adapter
    exists it resolves to one; where none does it resolves to the NullSandbox
    that refuses to run code; where none does and the operator opted into the
    unsafe runner it resolves to running untrusted code with no isolation at
    all. Those are three different security postures, and they produce three
    different digests.

    The control is the point: the declared configuration is EQUAL in all three,
    so a digest taken over the declared config would have been identical and the
    downgrade would have been attested as if nothing had changed.
    """

    config = Config(ledger_path=tmp_path / "l.db", sandbox="auto")
    key = signer()

    availability(monkeypatch, namespace=True, container=False)
    isolating = resolve_posture(config, signer=key, env={})

    availability(monkeypatch, namespace=False, container=False)
    refusing = resolve_posture(config, signer=key, env={})

    unsafe = resolve_posture(config, signer=key, env={"PROM_ALLOW_UNSAFE_EXEC": "1"})

    # What actually resolved, on the same declared configuration. (The null
    # adapter reports isolating=True because refusing to run IS the safe
    # answer; it is a different posture all the same, and the adapter name is
    # what says so — which is why the digest covers both.)
    assert isolating.sandbox_adapter == "namespace" and isolating.sandbox_isolating
    assert refusing.sandbox_adapter == "null"
    assert unsafe.sandbox_adapter == "unsafe" and not unsafe.sandbox_isolating

    digests = {posture_digest(p) for p in (isolating, refusing, unsafe)}
    assert len(digests) == 3, "a weaker resolution produced the same digest"

    # The control: hashing the DECLARED config would have missed all of it.
    declared = dataclasses.asdict(config)
    assert declared == dataclasses.asdict(config)
    assert json.dumps(declared, default=str, sort_keys=True) == json.dumps(
        dataclasses.asdict(config), default=str, sort_keys=True
    ), "the declared configuration is identical across all three resolutions"


def test_a_required_anchor_resolving_to_the_non_protecting_file_is_a_different_posture(tmp_path):
    """The same lesson on the ledger witness: an anchor is configured either
    way, so 'an anchor is set' is unchanged — what differs is the resolved
    target class, and that is what the digest records."""

    worm = Config(ledger_path=tmp_path / "l.db", ledger_anchor=f"worm://{tmp_path}/w")
    local = Config(ledger_path=tmp_path / "l.db", ledger_anchor=f"file://{tmp_path}/tip.json")
    key = signer()
    strong = resolve_posture(worm, signer=key, env={})
    weak = resolve_posture(local, signer=key, env={})
    assert (strong.anchor_target_class, strong.anchor_append_only) == (TARGET_WORM, True)
    assert (weak.anchor_target_class, weak.anchor_append_only) == (TARGET_FILE, False)
    assert posture_digest(strong) != posture_digest(weak)


def test_the_signer_actually_in_use_is_what_is_recorded(tmp_path):
    """Custody is resolved, not declared: the same Config with a local key and
    with an external one are different postures."""

    config = Config(ledger_path=tmp_path / "l.db")
    kms = MemoryKms()
    kms.create_key("alias/approvals")
    kms.grant_sign("alias/approvals", "runner", by="key-admin")
    external = KmsSigner(kms, key_id="alias/approvals")
    local = resolve_posture(config, signer=signer(), env={})
    remote = resolve_posture(config, signer=external, env={})
    assert local.signer_external is False and remote.signer_external is True
    assert posture_digest(local) != posture_digest(remote)


# ===========================================================================
# 3. Sign with PIH-2's signer, publish to PIH-1's targets
# ===========================================================================


def attestor_on(target, *, key=None, required=False, posture=None):
    """``state`` is the live posture and the clock, both settable by the test:
    a posture change or the passage of time is what these tests drive."""

    state = {"posture": posture if posture is not None else a_posture(), "now": 1_000.0}
    return state, ConfigAttestor(
        target=target,
        signer=key if key is not None else signer(),
        resolve=lambda: state["posture"],
        required=required,
        interval_s=60.0,
        clock=lambda: state["now"],
    )


def test_the_attestation_is_signed_by_the_pih2_signer_and_verifies_by_public_key():
    """Production custody end to end: the digest is sealed by a key that never
    exists on this host, and checked by a verifier that holds only the public
    key and cannot mint."""

    kms = MemoryKms()
    kms.create_key("alias/approvals")
    kms.grant_sign("alias/approvals", "runner", by="key-admin")
    external = KmsSigner(kms, key_id="alias/approvals")
    store = MemoryObjectLockStore()
    target = ObjectStoreAttestationTarget(store)
    _, attestor = attestor_on(target, key=external)
    record = attestor.attest()
    assert record is not None and record.scheme == "ecdsa-p256-sha256"

    verifier = PublicKeyVerifier(external.public_key_der, key_id="alias/approvals")
    result = verify_attestation(target=target, verifier=verifier, resolve=a_posture)
    assert (result.status, result.ok) == (ATTESTED, True)
    # The verifying host cannot mint one of its own.
    with pytest.raises(SignerUnavailable):
        verifier.sign(b"anything")


@pytest.mark.parametrize("build", [
    lambda: ObjectStoreAttestationTarget(MemoryObjectLockStore()),
    lambda: LogAttestationTarget(MemoryAppendOnlyLog()),
])
def test_both_external_targets_are_the_pih1_ports(build):
    """No new medium: the object-lock store and the append-only log are the
    same ports, and the same in-memory references, PIH-1 anchors tips to."""

    target = build()
    _, attestor = attestor_on(target)
    record = attestor.attest()
    assert record is not None and target.external is True
    assert [r.digest for r in target.records()] == [record.digest]


def test_the_local_file_target_is_marked_non_protecting(tmp_path):
    target = LocalFileAttestationTarget(tmp_path / "posture.json")
    assert target.external is False and target.kind == TARGET_FILE
    _, attestor = attestor_on(target)
    assert attestor.attest() is not None
    assert target.records()[0].digest == posture_digest(a_posture())


def test_the_target_builder_dispatches_the_same_three_kinds(tmp_path):
    kinds = {
        f"file://{tmp_path}/p.json": TARGET_FILE,
        f"worm://{tmp_path}/w": TARGET_WORM,
        "https://witness.example/attestations": TARGET_LOG,
    }
    for spec_text, kind in kinds.items():
        target = build_attestation_target(parse_anchor_spec(spec_text, name="t"))
        assert target.kind == kind
        assert target.external is (kind != TARGET_FILE)


def test_there_is_no_second_signing_or_publishing_path():
    """Drift check, on the source. The attestation package must not implement
    signing primitives of its own, nor reach the network itself: it composes
    PIH-2's signer port and PIH-1's target ports."""

    package = Path(attest_module.__file__).parent
    banned = {"hmac", "urllib", "http", "requests", "socket", "ssl"}
    for path in package.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            assert not (set(names) & banned), f"{path.name} imports {names}: a second path"
    # And it defines no signing primitive of its own: the only sign() reached
    # is the injected port's.
    source = (package / "attest.py").read_text(encoding="utf-8")
    assert "ApprovalSigner" in source
    assert "self._signer.sign(" in source, "signing goes through the injected port"
    for path in package.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        defined = [
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "sign"
        ]
        assert defined == [], f"{path.name} defines its own sign(): a second path"


# ===========================================================================
# 4. Startup and cadence, and the publish-failure decision
# ===========================================================================


def test_attestation_happens_at_startup_and_then_on_the_cadence():
    target = LogAttestationTarget(MemoryAppendOnlyLog())
    state, attestor = attestor_on(target)
    assert attestor.attest_if_due() is not None          # startup, always
    state["now"] += 10.0
    assert attestor.attest_if_due() is None              # inside the interval
    state["now"] += 60.0
    assert attestor.attest_if_due() is not None          # the interval elapsed
    assert len(target.records()) == 2


def test_a_posture_change_mid_run_produces_a_new_digest_on_the_record():
    """The point of the cadence: a downgrade after startup reaches the external
    record, so the witness sees the change rather than only the first posture."""

    target = LogAttestationTarget(MemoryAppendOnlyLog())
    state, attestor = attestor_on(target)
    first = attestor.attest_if_due()
    state["posture"] = a_posture(sandbox_adapter="unsafe", sandbox_isolating=False)
    state["now"] += 61.0
    second = attestor.attest_if_due()
    assert first is not None and second is not None and first.digest != second.digest
    assert [r.digest for r in target.records()] == [first.digest, second.digest]


class _RefusingTarget:
    kind = TARGET_LOG
    external = True

    def publish(self, record):
        raise AttestationUnavailable("the witness is unreachable")

    def records(self):
        return []


def test_a_failed_publish_is_fail_closed_under_the_requirement():
    """The decision, stated in the module docstring and enforced here: a
    posture that cannot be attested is refused, because being unable to attest
    a downgrade is itself the signal."""

    _, attestor = attestor_on(_RefusingTarget(), required=True)
    with pytest.raises(AttestationUnavailable, match="required and it could not be published"):
        attestor.attest()


def test_a_failed_publish_is_a_loud_error_without_the_requirement(caplog):
    """And never swallowed: without the requirement the runtime continues, but
    the operator is told at ERROR that the posture is on no external record."""

    _, attestor = attestor_on(_RefusingTarget(), required=False)
    with caplog.at_level("ERROR"):
        assert attestor.attest() is None
    assert "NOT on any external record" in caplog.text


def test_a_target_failing_in_an_undeclared_way_follows_the_same_policy(caplog):
    """The decision is the requirement's, not the exception type's: a target
    that raises something it never declared is still fail-closed when required
    and still loud when not."""

    class _Exploding:
        kind, external = TARGET_LOG, True

        def publish(self, record):
            raise RuntimeError("the witness returned something unexpected")

        def records(self):
            return []

    _, required = attestor_on(_Exploding(), required=True)
    with pytest.raises(AttestationUnavailable, match="RuntimeError"):
        required.attest()
    _, optional = attestor_on(_Exploding(), required=False)
    with caplog.at_level("ERROR"):
        assert optional.attest() is None
    assert "NOT on any external record" in caplog.text


def test_a_signer_that_cannot_sign_is_never_attested_anyway():
    class _Broken:
        scheme, key_id, external = "ecdsa-p256-sha256", "kms:x", True

        def sign(self, message):
            raise SignerUnavailable("the KMS is unreachable")

        def verify(self, message, signature):
            return False

    target = LogAttestationTarget(MemoryAppendOnlyLog())
    _, attestor = attestor_on(target, key=_Broken(), required=True)
    with pytest.raises(AttestationUnavailable, match="could not sign"):
        attestor.attest()
    assert target.records() == []


# ===========================================================================
# 5. Verify: MISMATCH is the catch, NOT_VERIFIABLE is never ATTESTED
# ===========================================================================


def test_a_silent_flip_of_a_security_setting_is_reported_as_mismatch():
    target = LogAttestationTarget(MemoryAppendOnlyLog())
    state, attestor = attestor_on(target)
    attestor.attest()
    # The downgrade: isolation quietly turned off after the posture was signed.
    state["posture"] = a_posture(sandbox_isolating=False)
    result = verify_attestation(
        target=target, verifier=signer(), resolve=lambda: state["posture"]
    )
    assert result.status == MISMATCH and not result.ok
    assert result.published_digest != result.live_digest


@pytest.mark.parametrize("mangle,why", [
    (lambda r: AttestationRecord(r.digest, r.created_at, r.key_id, r.scheme, b"\x00" * 32),
     "a forged signature"),
    (lambda r: AttestationRecord("b" * 64, r.created_at, r.key_id, r.scheme, r.signature),
     "a digest swapped under a real signature"),
    (lambda r: AttestationRecord(r.digest, r.created_at, "other-key", r.scheme, r.signature),
     "a record replayed as another key's"),
])
def test_a_tampered_record_is_not_verifiable_never_attested(mangle, why):
    log = MemoryAppendOnlyLog()
    target = LogAttestationTarget(log)
    _, attestor = attestor_on(target)
    record = attestor.attest()
    assert record is not None
    log.operator_rewrite([mangle(record).encode()])
    result = verify_attestation(target=target, verifier=signer(), resolve=a_posture)
    assert result.status == NOT_VERIFIABLE, why
    assert not result.ok


@pytest.mark.parametrize("body", [b"", b"not json", b"[]", b'{"digest": "short"}'])
def test_an_unreadable_published_record_is_not_verifiable(body):
    log = MemoryAppendOnlyLog()
    log.operator_rewrite([body])
    result = verify_attestation(
        target=LogAttestationTarget(log), verifier=signer(), resolve=a_posture
    )
    assert result.status == NOT_VERIFIABLE and not result.ok


def test_nothing_published_is_not_verifiable_not_attested():
    result = verify_attestation(
        target=LogAttestationTarget(MemoryAppendOnlyLog()),
        verifier=signer(),
        resolve=a_posture,
    )
    assert result.status == NOT_VERIFIABLE


def test_a_live_posture_that_cannot_be_computed_is_not_verifiable():
    """Couldn't-verify is never attested-clean: a host where resolution refuses
    (a sandbox requirement that cannot be honoured, an unreadable mount table)
    reports NOT_VERIFIABLE, not ATTESTED and not MISMATCH."""

    target = LogAttestationTarget(MemoryAppendOnlyLog())
    _, attestor = attestor_on(target)
    attestor.attest()

    def refuse():
        raise ConfigError("require_digest_pin cannot be honoured here")

    result = verify_attestation(target=target, verifier=signer(), resolve=refuse)
    assert result.status == NOT_VERIFIABLE and "could not be resolved" in result.detail


def test_the_projection_carries_no_secret():
    posture = a_posture()
    text = json.dumps(posture.projection(), default=str)
    assert KEY.hex() not in text and "a1a1a1" not in text
    assert "token" not in text and "api_key" not in text
    # The key identifier is a non-secret fingerprint, and it IS there.
    assert "kms:alias/approvals" in text


# ===========================================================================
# 6. The honest limits, and the residual — passing tests, not caveats
# ===========================================================================


def test_honest_limit_a_deliberately_weak_posture_still_attests():
    """ATTESTED means "this is the posture that is running, signed". It does
    NOT mean the posture is safe. A configuration with no isolation, no TLS
    requirement, a local key and a non-protecting witness attests exactly as
    well as a hardened one — so nobody may read ATTESTED as a safety verdict."""

    weak = a_posture(
        sandbox_adapter="unsafe",
        sandbox_isolating=False,
        digest_pin_active=False,
        tls_required=False,
        anchor_required=False,
        anchor_target_class=TARGET_FILE,
        anchor_append_only=False,
        signer_scheme="hmac-sha256",
        signer_external=False,
        signer_key_id="hmac:0123456789abcdef",
        substrate_require_verified=False,
        substrate_allow_unverified=True,
        substrate_verdict="unknown",
    )
    target = LogAttestationTarget(MemoryAppendOnlyLog())
    _, attestor = attestor_on(target, posture=weak)
    assert attestor.attest() is not None
    result = verify_attestation(target=target, verifier=signer(), resolve=lambda: weak)
    assert result.status == ATTESTED, "a weak posture attests; correctness is not covered"


def test_honest_limit_binary_integrity_is_not_covered(monkeypatch):
    """Nothing here measures the running code. The same posture on modified
    code produces the same digest — that is full measured-boot attestation
    (PIH-4b), deferred and platform-gated, and it is not claimed here."""

    before = posture_digest(a_posture())

    # Stand in for a modified binary: replace a function in the running package.
    monkeypatch.setattr(
        attest_module, "signed_message", lambda **kw: b"a different implementation"
    )
    assert posture_digest(a_posture()) == before, "the digest is blind to the code, by design"

    # And no field even claims to cover it, so the limit cannot drift silently.
    measurement = [n for n in POSTURE_FIELDS if any(
        word in n for word in ("binary", "measure", "pcr", "boot", "image_hash")
    )]
    assert measurement == [], f"a measurement-shaped field appeared: {measurement}"
    assert "binary" in attest_module.__doc__.lower() or "binary" in (
        posture_module.__doc__ or ""
    ).lower()


def test_residual_an_insider_who_controls_both_is_not_detected():
    """The PIH-1 attacker-controls-the-anchor pattern, restated for postures.

    An insider who can change the running configuration AND write the published
    target simply re-attests the weakened posture. Verification then says
    ATTESTED and MISMATCH never fires. This is not detected, it is stated: the
    control is worth exactly what the separation between the config host and the
    witness is worth.
    """

    log = MemoryAppendOnlyLog()
    target = LogAttestationTarget(log)
    state, attestor = attestor_on(target)
    attestor.attest()
    honest = posture_digest(a_posture())

    # The insider downgrades the posture and re-publishes under the same key.
    state["posture"] = a_posture(sandbox_isolating=False, signer_external=False)
    attestor.attest()

    result = verify_attestation(
        target=target, verifier=signer(), resolve=lambda: state["posture"]
    )
    assert result.status == ATTESTED, "controlling both config and target is undetected"
    assert result.published_digest != honest


# ===========================================================================
# 7. The configuration surface
# ===========================================================================


def test_the_requirement_is_declared_and_consumed():
    assert "require_config_attestation" in SECURITY_FIELDS
    assert "config_attestation_target" in SECURITY_FIELDS
    assert Config().require_config_attestation is False
    assert Config().config_attestation_target is None


@pytest.mark.parametrize("value,expected", [
    ("1", True), ("true", True), ("YES", True), ("on", True),
    ("0", False), ("false", False), ("no", False), ("off", False),
])
def test_the_requirement_is_read_through_the_strict_parser(value, expected):
    assert config_attestation_required({CONFIG_ATTESTATION_REQUIRED_ENV: value}) is expected
    assert config_attestation_required({}) is False


@pytest.mark.parametrize("value", ["tru", "y", "t", "enabled", "", "  ", "2"])
def test_a_misspelled_requirement_is_refused_not_read_as_false(value):
    """F9: a present but unrecognised value is a ConfigError, never a silent
    False that would leave the requirement off while it looks on."""

    with pytest.raises(ConfigError, match="not a boolean"):
        config_attestation_required({CONFIG_ATTESTATION_REQUIRED_ENV: value})
    with pytest.raises(ConfigError, match="not a boolean"):
        Config.from_env({CONFIG_ATTESTATION_REQUIRED_ENV: value})


def test_a_local_only_target_is_refused_under_the_requirement(tmp_path):
    """Same reasoning as the local ledger anchor: an insider who changes the
    config rewrites the local record in the same breath."""

    with pytest.raises(ConfigError, match="rewrites the record of it in the same breath"):
        Config(ledger_path=tmp_path / "l.db",
               config_attestation_target=f"file://{tmp_path}/p.json",
               require_config_attestation=True)
    # And at the runtime half, which is the one the environment variable reaches.
    config = Config(ledger_path=tmp_path / "l.db",
                    config_attestation_target=f"file://{tmp_path}/p.json")
    with pytest.raises(ConfigError, match="cannot be honoured"):
        attestation_target_for(config, env={CONFIG_ATTESTATION_REQUIRED_ENV: "1"})
    # Without the requirement it is allowed, and warned about.
    assert attestation_target_for(config, env={}).external is False


def test_the_requirement_with_no_target_is_refused(tmp_path):
    with pytest.raises(ConfigError, match="no config_attestation_target"):
        Config(ledger_path=tmp_path / "l.db", require_config_attestation=True)
    config = Config(ledger_path=tmp_path / "l.db")
    with pytest.raises(ConfigError, match="no target is configured"):
        attestation_target_for(config, env={CONFIG_ATTESTATION_REQUIRED_ENV: "1"})


def test_the_attestor_builds_from_config_and_publishes(tmp_path):
    config = Config(
        ledger_path=tmp_path / "l.db",
        config_attestation_target=f"worm://{tmp_path}/witness",
        require_config_attestation=True,
    )
    attestor = build_config_attestor(config, signer=signer(), env={})
    assert attestor is not None and attestor.required is True
    record = attestor.attest()
    assert record is not None and attestor.last_digest == record.digest
    published = attestation_target_for(config, env={}).records()
    assert [r.digest for r in published] == [record.digest]


def test_startup_attestation_publishes_before_the_first_cadence_tick(tmp_path):
    """The startup half is one call: by the time it returns, the posture this
    process is running is on the external record."""

    from prometheus_protocol.attestation import attest_at_startup

    config = Config(
        ledger_path=tmp_path / "l.db",
        config_attestation_target=f"worm://{tmp_path}/witness",
        require_config_attestation=True,
    )
    attestor = attest_at_startup(config, signer=signer(), env={})
    assert attestor is not None and attestor.last_digest is not None
    published = attestation_target_for(config, env={}).records()
    assert [r.digest for r in published] == [attestor.last_digest]
    # And under the requirement, a startup that cannot attest stops there. The
    # unwritable target is a plain file where the record directory must go, so
    # this fails locally and deterministically rather than over the network.
    (tmp_path / "occupied").write_text("not a directory")
    broken = Config(
        ledger_path=tmp_path / "l.db",
        config_attestation_target=f"worm://{tmp_path}/occupied",
        require_config_attestation=True,
    )
    with pytest.raises(AttestationUnavailable, match="required and it could not be published"):
        attest_at_startup(broken, signer=signer(), env={})


def test_no_target_configured_means_no_attestor(tmp_path):
    config = Config(ledger_path=tmp_path / "l.db")
    assert build_config_attestor(config, signer=signer(), env={}) is None


def test_a_signer_is_required_rather_than_generated_per_process(tmp_path):
    """A per-process key would give every process a different custody posture,
    so the next process could never verify the last one's attestation."""

    from prometheus_protocol.attestation.runtime import resolve_attestation_signer

    config = Config(ledger_path=tmp_path / "l.db")
    with pytest.raises(ConfigError, match="unverifiable by the next one"):
        resolve_attestation_signer(config, env={})
    assert resolve_attestation_signer(config, signing_key=KEY, env={}).key_id == signer().key_id


def test_the_external_signer_requirement_reaches_attestations(tmp_path):
    """PIH-2's policy applies here because PIH-2's resolver is what decides it:
    under require_external_signer a local key is refused for attestations too."""

    from prometheus_protocol.attestation.runtime import resolve_attestation_signer

    config = Config(ledger_path=tmp_path / "l.db", require_external_signer=True)
    with pytest.raises(ConfigError, match="external approval signer is required"):
        resolve_attestation_signer(config, signing_key=KEY, env={})
