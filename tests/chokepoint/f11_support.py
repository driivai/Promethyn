"""Explicit, non-secret deployment identities for the issuance fixtures."""

import hashlib

from prometheus_protocol.chokepoint.authorization_record import AuthorizationContext


def authorization_context(signer):
    public = getattr(signer, "public_key_der", None)
    return AuthorizationContext(
        gate_identity="test-gate",
        policy_sha256=hashlib.sha256(
            b"test-policy: authoritative PASS only"
        ).hexdigest(),
        requester={
            "identity_source": "authenticated_service",
            "issuer": "test-auth",
            "subject": "requester",
        },
        signer={
            "backend": "model" if signer.external else "local-hmac",
            "scope": "test-scope",
            "key_resource": signer.key_id,
            "public_key_sha256": hashlib.sha256(public).hexdigest() if public else None,
            "caller_issuer": "test-kms",
            "caller_subject": getattr(signer, "principal", "runner"),
        },
    )
