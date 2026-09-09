"""Signed config digests: which security posture is actually running (PIH-4a).

The near-term slice of Defense 4, composed from the two seams that already
exist — PIH-2's signer for sealing and PIH-1's external targets for publishing.
It makes a silent security-config downgrade **detectable by an external
witness**. It does not prove the binary is unmodified (PIH-4b, deferred), and
it does not prove the configuration is correct: a signed weak posture attests
exactly as well as a strong one. Both limits are in the module docstrings, in
``docs/threat-model.md`` §4, and pinned by passing tests.
"""

from prometheus_protocol.attestation.attest import (
    ATTESTED,
    MISMATCH,
    NOT_VERIFIABLE,
    AttestationRecord,
    AttestationTarget,
    AttestationUnavailable,
    AttestationVerification,
    ConfigAttestor,
    LocalFileAttestationTarget,
    LogAttestationTarget,
    ObjectStoreAttestationTarget,
    build_attestation_target,
    decode_record,
    signed_message,
    verify_attestation,
)
from prometheus_protocol.attestation.posture import (
    POSTURE_FIELDS,
    TARGET_FILE,
    TARGET_LOG,
    TARGET_NONE,
    TARGET_WORM,
    ResolvedPosture,
    posture_digest,
    posture_preimage,
)
from prometheus_protocol.attestation.runtime import (
    CONFIG_ATTESTATION_REQUIRED_ENV,
    attest_at_startup,
    attestation_target_for,
    build_config_attestor,
    config_attestation_required,
    resolve_posture,
)

__all__ = [
    "ATTESTED",
    "CONFIG_ATTESTATION_REQUIRED_ENV",
    "MISMATCH",
    "NOT_VERIFIABLE",
    "POSTURE_FIELDS",
    "TARGET_FILE",
    "TARGET_LOG",
    "TARGET_NONE",
    "TARGET_WORM",
    "AttestationRecord",
    "AttestationTarget",
    "AttestationUnavailable",
    "AttestationVerification",
    "ConfigAttestor",
    "LocalFileAttestationTarget",
    "LogAttestationTarget",
    "ObjectStoreAttestationTarget",
    "ResolvedPosture",
    "attest_at_startup",
    "attestation_target_for",
    "build_attestation_target",
    "build_config_attestor",
    "config_attestation_required",
    "decode_record",
    "posture_digest",
    "posture_preimage",
    "resolve_posture",
    "signed_message",
    "verify_attestation",
]
