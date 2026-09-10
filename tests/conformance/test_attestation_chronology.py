"""P-1: equal-time attestations must not be ordered by digest.

THE REVIEW'S SCENARIO, reproduced twice. ``created_at`` is
``int(clock() * 1e9)``. Equal values occur under a frozen or injected clock,
under a wall clock whose real resolution is coarser than a nanosecond, when the
clock repeats or steps back, and for two publications inside ``time.time()``'s
effective resolution. ``DirectoryObjectStore.list_keys()`` then sorts
lexicographically, so with equal stamps the tiebreaker is the first sixteen hex
characters of the DIGEST — which has no relation to publication order. And
``verify_attestation`` took ``records[-1]`` as the newest.

Two consequences, both asserted below against the real store:

* **the ordering case** — publish a HIGH-digest record first and a LOW-digest
  record second at the same stamp; the listing returns them low-then-high, so
  the old verifier compared against the OLDER record and reported MISMATCH
  against the posture that was genuinely current;
* **the rollback case, which is worse** — publish A then B at the same stamp;
  if A sorts after B the verifier ALWAYS picks A, so returning the runtime to A
  later reports ATTESTED while the newest publication was B.

The fix taken is option (b): verification REFUSES the ambiguity. Scoped to the
WORM/object-store target, because the log-backed target's append index is
assigned by the medium and preserves publication order — the tests at the end
assert that scoping in both directions.
"""

from __future__ import annotations

from typing import Any

import pytest

from prometheus_protocol.attestation.attest import (
    ATTESTED,
    MISMATCH,
    NOT_VERIFIABLE,
    AttestationRecord,
    ConfigAttestor,
    LogAttestationTarget,
    ObjectStoreAttestationTarget,
    newest_record,
    verify_attestation,
)
from prometheus_protocol.attestation.posture import (
    TARGET_LOG,
    TARGET_WORM,
    ResolvedPosture,
    posture_digest,
)
from prometheus_protocol.chokepoint.signer import LocalHmacSigner
from prometheus_protocol.ledger.anchor_targets import (
    DirectoryObjectStore,
    MemoryAppendOnlyLog,
)

KEY = b"p1-attestation-chronology-key-32"

#: One frozen instant. Every record below is created at exactly this stamp,
#: which is the condition the whole finding turns on.
FROZEN = 1_700_000_000.0


def _signer() -> LocalHmacSigner:
    return LocalHmacSigner(KEY)


def _posture(**overrides: Any) -> ResolvedPosture:
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


def _record_for(posture: ResolvedPosture, *, created_at: str) -> AttestationRecord:
    """A genuinely signed record for ``posture`` at a chosen stamp."""

    digest = posture_digest(posture)
    signer = _signer()
    record = AttestationRecord(
        digest=digest,
        created_at=created_at,
        key_id=signer.key_id,
        scheme=signer.scheme,
        signature=b"",
    )
    return AttestationRecord(
        digest=digest,
        created_at=created_at,
        key_id=signer.key_id,
        scheme=signer.scheme,
        signature=signer.sign(record.message),
    )


def _two_postures_ordered_by_digest() -> tuple[ResolvedPosture, ResolvedPosture]:
    """Two real postures, returned (high digest, low digest).

    Searching for them rather than hard-coding: the digest is over the posture's
    canonical form, so a change to that form would silently invert a hard-coded
    pair and quietly stop testing the thing this file is about.
    """

    candidates = [
        _posture(sandbox_adapter=f"container-{n}") for n in range(64)
    ]
    ranked = sorted(candidates, key=lambda p: posture_digest(p)[:16])
    return ranked[-1], ranked[0]


@pytest.fixture
def store(tmp_path):
    return DirectoryObjectStore(tmp_path / "worm")


# ---------------------------------------------------------------------------
# 1. the ordering case
# ---------------------------------------------------------------------------


def test_equal_time_records_come_back_out_of_publication_order(store):
    """The precondition, asserted before anything is claimed about the fix.

    If this stopped being true the tests below would pass vacuously.
    """

    high, low = _two_postures_ordered_by_digest()
    stamp = f"{int(FROZEN * 1_000_000_000)}"
    target = ObjectStoreAttestationTarget(store)

    target.publish(_record_for(high, created_at=stamp))  # published FIRST
    target.publish(_record_for(low, created_at=stamp))   # published SECOND

    digests = [record.digest for record in target.records()]
    assert digests == [posture_digest(low), posture_digest(high)], (
        "the store no longer reorders equal-time records by digest; re-derive "
        "this test against whatever it does now"
    )
    assert digests[-1] != posture_digest(low), (
        "records[-1] is not the record published last — the premise of P-1"
    )


def test_the_verifier_refuses_rather_than_comparing_against_the_older_record(store):
    """The review's first reproduction. Previously: MISMATCH against the posture
    that is genuinely current. Now: NOT_VERIFIABLE, naming the ambiguity."""

    high, low = _two_postures_ordered_by_digest()
    stamp = f"{int(FROZEN * 1_000_000_000)}"
    target = ObjectStoreAttestationTarget(store)
    target.publish(_record_for(high, created_at=stamp))
    target.publish(_record_for(low, created_at=stamp))

    result = verify_attestation(
        target=target,
        verifier=_signer(),
        resolve=lambda: low,  # the posture genuinely in force
    )

    assert result.status == NOT_VERIFIABLE
    assert result.status != MISMATCH, (
        "reporting MISMATCH here would accuse the running host of a downgrade "
        "on the strength of a digest sort order"
    )
    assert "share the newest timestamp" in result.detail


# ---------------------------------------------------------------------------
# 2. the rollback case — the worse one
# ---------------------------------------------------------------------------


def test_a_rollback_to_an_older_posture_is_not_reported_as_attested(store):
    """Publish A, then B, at the same instant, with A sorting AFTER B.

    The old verifier always picked A, so returning the runtime to A later
    reported ATTESTED while the newest publication was B — a silent downgrade
    wearing a green light, which is the exact failure attestation exists to
    catch.
    """

    posture_a, posture_b = _two_postures_ordered_by_digest()  # A sorts after B
    stamp = f"{int(FROZEN * 1_000_000_000)}"
    target = ObjectStoreAttestationTarget(store)
    target.publish(_record_for(posture_a, created_at=stamp))  # A first
    target.publish(_record_for(posture_b, created_at=stamp))  # B second, NEWEST

    # The runtime is rolled back to A. Under the old code: records[-1] is A
    # (it sorts last), the digest matches, ATTESTED.
    result = verify_attestation(
        target=target, verifier=_signer(), resolve=lambda: posture_a
    )

    assert result.status != ATTESTED, (
        "a rollback to a superseded posture was reported as attested"
    )
    assert result.status == NOT_VERIFIABLE
    assert "cannot be established" in result.detail


def test_the_rollback_case_is_green_when_the_stamps_differ(store):
    """The positive control. A verifier that refused everything would pass the
    test above without proving anything, so the SAME two postures, published at
    DISTINCT stamps, must verify normally."""

    posture_a, posture_b = _two_postures_ordered_by_digest()
    target = ObjectStoreAttestationTarget(store)
    target.publish(_record_for(posture_a, created_at=f"{int(FROZEN * 1e9)}"))
    target.publish(_record_for(posture_b, created_at=f"{int(FROZEN * 1e9) + 1}"))

    assert verify_attestation(
        target=target, verifier=_signer(), resolve=lambda: posture_b
    ).status == ATTESTED
    # And the rollback IS caught, rather than refused, when order is knowable.
    assert verify_attestation(
        target=target, verifier=_signer(), resolve=lambda: posture_a
    ).status == MISMATCH


# ---------------------------------------------------------------------------
# 3. the rule itself
# ---------------------------------------------------------------------------


def test_newest_record_refuses_only_a_genuine_ambiguity():
    high, low = _two_postures_ordered_by_digest()
    a = _record_for(high, created_at="100")
    b = _record_for(low, created_at="100")
    c = _record_for(high, created_at="200")

    # Two distinct records at the newest stamp: refused.
    record, why = newest_record([a, b])
    assert record is None and "share the newest timestamp" in why

    # A duplicate stamp FURTHER BACK does not decide what is current.
    record, why = newest_record([a, b, c])
    assert record is not None and record.digest == c.digest and why == ""

    # Byte-identical republication is idempotent by design, not an ambiguity.
    record, why = newest_record([a, _record_for(high, created_at="100")])
    assert record is not None and record.digest == a.digest


def test_a_single_record_is_never_ambiguous():
    high, _ = _two_postures_ordered_by_digest()
    record, why = newest_record([_record_for(high, created_at="1")])
    assert record is not None and why == ""


def test_the_refusal_names_what_a_reader_must_do():
    high, low = _two_postures_ordered_by_digest()
    _, why = newest_record(
        [_record_for(high, created_at="7"), _record_for(low, created_at="7")]
    )
    assert "Publish a fresh attestation" in why
    assert "coin toss" in why


# ---------------------------------------------------------------------------
# 4. the scope: the log target is NOT affected, and says so structurally
# ---------------------------------------------------------------------------


def test_the_log_target_declares_its_order_authoritative():
    assert LogAttestationTarget(MemoryAppendOnlyLog()).ordered is True


def test_the_object_store_target_declares_its_order_derived(store):
    assert ObjectStoreAttestationTarget(store).ordered is False


def test_equal_time_records_on_the_log_target_still_verify():
    """The log assigns the append index, so publication order survives an equal
    ``created_at`` and there is no ambiguity to refuse. Refusing here would have
    broken a target that was never affected — which is why the fix is scoped by
    a DECLARED property rather than applied everywhere."""

    posture_a, posture_b = _two_postures_ordered_by_digest()
    target = LogAttestationTarget(MemoryAppendOnlyLog())
    stamp = f"{int(FROZEN * 1_000_000_000)}"
    target.publish(_record_for(posture_a, created_at=stamp))
    target.publish(_record_for(posture_b, created_at=stamp))

    assert [r.digest for r in target.records()] == [
        posture_digest(posture_a),
        posture_digest(posture_b),
    ], "the log no longer preserves publication order"
    assert verify_attestation(
        target=target, verifier=_signer(), resolve=lambda: posture_b
    ).status == ATTESTED
    # The rollback to A is a MISMATCH here — detected, not refused, because the
    # medium can say which came last.
    assert verify_attestation(
        target=target, verifier=_signer(), resolve=lambda: posture_a
    ).status == MISMATCH


def test_a_target_that_does_not_declare_order_is_treated_as_unordered():
    """The safe default: an undeclared target gets the refusal, not the trust."""

    posture_a, posture_b = _two_postures_ordered_by_digest()
    stamp = f"{int(FROZEN * 1_000_000_000)}"
    records = [
        _record_for(posture_a, created_at=stamp),
        _record_for(posture_b, created_at=stamp),
    ]

    class _Undeclared:
        kind = "undeclared"
        external = True

        def publish(self, record: AttestationRecord) -> None:  # pragma: no cover
            raise NotImplementedError

        def records(self) -> list[AttestationRecord]:
            return list(records)

    assert not hasattr(_Undeclared, "ordered")
    result = verify_attestation(
        target=_Undeclared(), verifier=_signer(), resolve=lambda: posture_b
    )
    assert result.status == NOT_VERIFIABLE


# ---------------------------------------------------------------------------
# 5. the corrected claims
# ---------------------------------------------------------------------------


def test_the_docstrings_no_longer_claim_a_chronology_they_cannot_keep():
    """attest.py:195-196 said records come back "oldest first"; :199-206 said
    "lexical order is chronological". The second is true only while created_at
    is unique, and the first followed from it."""

    from prometheus_protocol.attestation.attest import AttestationTarget

    protocol_doc = AttestationTarget.records.__doc__ or ""
    assert "ORDER IS NOT GUARANTEED TO BE CHRONOLOGICAL" in protocol_doc
    # The phrase survives only inside the correction that retracts it.
    assert 'used to\n        say "oldest first" as though it were' in protocol_doc
    assert "must therefore not take ``records()[-1]``" in protocol_doc

    store_doc = ObjectStoreAttestationTarget.__doc__ or ""
    assert "lexical order is chronological" not in store_doc
    assert "true only while ``created_at`` is UNIQUE" in store_doc


def test_the_rejected_fixes_are_named_so_they_are_not_tried_again():
    """Widening the key or keeping the whole digest does not close it — the
    collision is in created_at. Nor does a finer clock: it establishes nothing
    across processes, restarts, regressions or an injected clock."""

    store_doc = ObjectStoreAttestationTarget.__doc__ or ""
    assert "_KEY_WIDTH" in store_doc
    assert "injected clock" in store_doc


def test_the_attestor_still_publishes_and_verifies_end_to_end(store, tmp_path):
    """A whole-path control: the real attestor over the real store."""

    state = {"posture": _posture(), "now": FROZEN}
    target = ObjectStoreAttestationTarget(store)
    attestor = ConfigAttestor(
        target=target,
        signer=_signer(),
        resolve=lambda: state["posture"],
        required=False,
        interval_s=60.0,
        clock=lambda: state["now"],
    )
    attestor.attest()
    assert verify_attestation(
        target=target, verifier=_signer(), resolve=lambda: state["posture"]
    ).status == ATTESTED
