"""The security posture that is ACTUALLY ACTIVE, and its digest.

PIH-4a's near-term slice of Defense 4: make a silent security-config downgrade
detectable by an external witness, the same shape as PIH-1 (the ledger anchor)
and PIH-2 (the KMS signer). What is attested is **what posture is running**.

The load-bearing distinction, and the Attacker-5 lesson: this hashes the
**resolved** posture, never the declared :class:`~prometheus_protocol.core.config.Config`.
A flag can be set and still resolve to something weaker — ``sandbox="auto"``
resolves to the namespace adapter on one host and to a :class:`NullSandbox` (or,
with the opt-in, the unsafe runner) on another; an anchor can be configured and
resolve to the non-protecting local file. If the digest hashed what Config
*says*, those deployments would produce an identical digest and the attestation
would miss exactly the downgrade it exists to catch. So every field below is
read from the object that is actually live, and
``tests/conformance/test_config_attestation.py`` proves one declared Config
produces different digests under different resolutions.

**Canonical encoding, pinned.** Ambiguous encoding means two digests for one
posture, which is the void-guard shape, so this uses the same discipline as the
audit chain's entry hash and the authorization record::

    digest = sha256( DOMAIN
                     || u64_be(len(POSTURE_FIELDS))
                     || for each field, in POSTURE_FIELDS order:
                            lp(name) || lp(tag || value) )

where ``lp(x) = u64_be(len(x)) || x`` length-prefixes every variable field (so
no field boundary can be forged by embedding a delimiter), the field COUNT is
committed (so adding or removing a field changes the digest), the order is the
pinned :data:`POSTURE_FIELDS` tuple rather than any dict iteration order, and
every value carries a one-byte type tag so ``True``, ``1`` and ``"1"`` cannot
encode alike. Floats are their exact IEEE-754 big-endian bytes: a cap of 5.0 and
one of 5.000000000000001 are different postures and hash differently.

**What this does NOT cover**, stated here because it is stated in the docs and
pinned by passing tests:

* **Binary integrity.** Nothing here measures the running code. A modified
  interpreter, library or this very module produces the same digest for the
  same posture. That is full measured-boot attestation (PIH-4b), deferred and
  platform-gated.
* **Configuration correctness.** A deliberately weak posture attests exactly as
  well as a strong one. ``ATTESTED`` means "this is the posture that is
  running, signed by the key you pinned" — never "this posture is safe".
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, fields

_DOMAIN = b"prom-config-posture-v1\x00"

_TAG_NONE = b"n"
_TAG_BOOL = b"b"
_TAG_INT = b"i"
_TAG_FLOAT = b"f"
_TAG_STR = b"s"

#: Anchor/attestation target classes, resolved. ``file`` is the non-protecting
#: local one: an insider who changes the config rewrites it in the same breath.
TARGET_NONE = "none"
TARGET_FILE = "file"
TARGET_WORM = "worm"
TARGET_LOG = "log"


@dataclass(frozen=True)
class ResolvedPosture:
    """What is live, field by field — not what was asked for.

    Every value here is read from a resolved object (the built sandbox, the
    built anchor, the resolved signer, the probed substrate) or is a numeric
    bound already in force. Nothing on this record is a restatement of intent.
    """

    # -- what actually executes untrusted code -----------------------------
    #: The live adapter's own name: namespace / container / unsafe / null.
    sandbox_adapter: str
    #: The live adapter's own answer, not the requested one.
    sandbox_isolating: bool
    #: Digest pinning as the built adapter reports it, not as requested.
    digest_pin_active: bool

    # -- the network boundary ----------------------------------------------
    provider: str
    #: https:// enforced for credentialed endpoints (the loopback opt-out off).
    tls_required: bool

    # -- the ledger's external witness (PIH-1) ------------------------------
    anchor_required: bool
    #: The resolved target class, so a required anchor that resolved to the
    #: non-protecting local file is a different posture from a worm:// one.
    anchor_target_class: str
    #: The resolved target's own ``append_only``: the protecting distinction.
    anchor_append_only: bool

    # -- approval key custody (PIH-2) ---------------------------------------
    signer_scheme: str
    #: True only when the private key never exists on this host.
    signer_external: bool
    #: The non-secret key identifier. Never key material.
    signer_key_id: str

    # -- the execution guard's substrate ------------------------------------
    substrate_require_verified: bool
    substrate_allow_unverified: bool
    #: The classification OUTCOME (safe / unsafe / unknown), not the policy.
    substrate_verdict: str
    substrate_fs_type: str | None

    # -- this attestation's own posture -------------------------------------
    attestation_required: bool
    attestation_target_class: str
    attestation_target_external: bool

    # -- the numeric caps in effect -----------------------------------------
    verifier_timeout_s: float
    verifier_memory_mb: int
    verifier_cpu_seconds: int
    verifier_max_processes: int
    request_timeout_s: float
    provider_max_response_bytes: int
    max_role_calls: int
    pending_ttl_seconds: int
    gate_threshold: float
    escalate_below: float
    ledger_anchor_retention_days: int

    def projection(self) -> dict[str, object]:
        """The posture as plain data for an operator or a machine reader.

        Every field here is already non-secret by construction — the signer's
        key id is a fingerprint, never key material, and no credential, token
        or endpoint is on the record at all.
        """

        return {field.name: getattr(self, field.name) for field in fields(self)}


#: The pinned field order the digest commits to. Explicit rather than derived
#: from ``dataclasses.fields`` at hash time, so a reordering is a visible source
#: change; a test asserts the two agree, which is what stops a field being added
#: to the posture and silently left out of the digest.
POSTURE_FIELDS: tuple[str, ...] = (
    "sandbox_adapter",
    "sandbox_isolating",
    "digest_pin_active",
    "provider",
    "tls_required",
    "anchor_required",
    "anchor_target_class",
    "anchor_append_only",
    "signer_scheme",
    "signer_external",
    "signer_key_id",
    "substrate_require_verified",
    "substrate_allow_unverified",
    "substrate_verdict",
    "substrate_fs_type",
    "attestation_required",
    "attestation_target_class",
    "attestation_target_external",
    "verifier_timeout_s",
    "verifier_memory_mb",
    "verifier_cpu_seconds",
    "verifier_max_processes",
    "request_timeout_s",
    "provider_max_response_bytes",
    "max_role_calls",
    "pending_ttl_seconds",
    "gate_threshold",
    "escalate_below",
    "ledger_anchor_retention_days",
)


def _lp(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def encode_value(value: object) -> bytes:
    """One unambiguous encoding per value, type tag first.

    The tag is what stops ``True``/``1``/``"1"`` — three different postures —
    from sharing a preimage. An unsupported type raises rather than being
    stringified: a silently stringified value is an encoding nobody pinned.
    """

    if value is None:
        return _TAG_NONE
    if isinstance(value, bool):  # before int: bool is a subclass of int
        return _TAG_BOOL + (b"\x01" if value else b"\x00")
    if isinstance(value, int):
        return _TAG_INT + int(value).to_bytes(8, "big", signed=True)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("a non-finite posture value has no canonical encoding")
        return _TAG_FLOAT + struct.pack(">d", value)
    if isinstance(value, str):
        return _TAG_STR + value.encode("utf-8")
    raise TypeError(f"no canonical encoding for {type(value).__name__} in a posture")


def posture_preimage(posture: ResolvedPosture) -> bytes:
    """The exact bytes the digest is taken over. Public so an auditor can
    recompute the digest by hand rather than trusting this function."""

    parts = [_DOMAIN, len(POSTURE_FIELDS).to_bytes(8, "big")]
    for name in POSTURE_FIELDS:
        parts.append(_lp(name.encode("ascii")))
        parts.append(_lp(encode_value(getattr(posture, name))))
    return b"".join(parts)


def posture_digest(posture: ResolvedPosture) -> str:
    """The SHA-256 of :func:`posture_preimage`, hex. Deterministic across
    processes and hosts for one resolved posture."""

    return hashlib.sha256(posture_preimage(posture)).hexdigest()
