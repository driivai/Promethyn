"""Approval signing behind a port: a local key for development, or an external
KMS / HSM whose key never exists on this host.

PROM-HARDEN-MAX left one residual standing over every approval: root on the
runner host reads the HMAC key out of the runner's memory and mints any
approval it likes, silently. Attacker 1 and 2 never reach the key; root does.
PIH-2 does not claim to stop root. It moves the key somewhere root cannot
read it — a KMS or HSM that signs on request and never returns key material —
so that forging an approval requires *asking the KMS to sign*. Invoke holders
still obtain valid signatures. F11 reconciliation detects unexplained signing
only with independently trusted digest-bound audit history and complete
coverage. Native AWS CloudTrail is metadata-only and cannot supply that
detection; GCP can expose the digest; PKCS#11 needs vendor evidence. Controlling
Sign and audit administration can erase the witness. See ``docs/key-custody.md``.

The port is small on purpose:

* :class:`LocalHmacSigner` — the key is bytes in this process. **Non-protecting
  against a host-level insider**: whoever can read the process can read the
  key. Development only; the runtime warns, and the requirement refuses it.
* :class:`KmsSigner` — signs through a :class:`KmsPort` (``sign``,
  ``get_public_key``), neither of which can return key material. Verification
  uses the public key fetched once at construction, so the verify side holds
  nothing a forger could use and needs no KMS call.
* :class:`PublicKeyVerifier` — a verify-only signer for a host that should
  never be able to mint: it holds the public key and nothing else.

**Scheme.** ECDSA over NIST P-256 with SHA-256, DER-encoded signatures, the
message being the approval's existing canonical bytes (the binding is
unchanged; only the primitive that seals it moved). Chosen because it is the
one signing scheme every target offers: AWS KMS ``ECC_NIST_P256`` /
``ECDSA_SHA_256``, GCP Cloud KMS ``EC_SIGN_P256_SHA256``, PKCS#11 ``CKM_ECDSA``
over a P-256 key. Ed25519 would rule out AWS KMS and older HSMs; RSA buys
nothing here; keeping HMAC inside the KMS (``GenerateMac``/``VerifyMac``) would
make every *verification* a KMS call, coupling the execute path to KMS
availability and leaving the verifier holding a credential. A public key is
not a secret: it can be pinned, published and handed to an auditor.

**Fail-closed.** A KMS that is unreachable, denies the call, times out, or
answers with something that is not a valid signature under its own public key
raises a :class:`SignerUnavailable` subclass and mints nothing. Couldn't-sign
is not signed — the ``Unavailable`` discipline applied to signing. There is no
path from a configured :class:`KmsSigner` to a local key.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Protocol

HMAC_SHA256 = "hmac-sha256"
ECDSA_P256_SHA256 = "ecdsa-p256-sha256"
SCHEMES = (HMAC_SHA256, ECDSA_P256_SHA256)

_FINGERPRINT_DOMAIN = b"promethyn-key-id\x00"


# ---------------------------------------------------------------------------
# Errors: distinct, never a silent default
# ---------------------------------------------------------------------------


class SignerUnavailable(RuntimeError):
    """The signer could not sign. No approval is minted; the caller learns why.

    Distinct from a refusal (``verify`` saying no) and from a bad judgment
    (``authorize`` returning ``None``): the check could not run, and that must
    never be read as either "signed" or "not authorised".
    """

    kind = "unavailable"


class SignerUnreachable(SignerUnavailable):
    """The KMS could not be reached."""

    kind = "unreachable"


class SignerDenied(SignerUnavailable):
    """The KMS refused this principal the Sign operation on this key."""

    kind = "denied"


class SignerTimeout(SignerUnavailable):
    """The KMS did not answer within the deadline."""

    kind = "timeout"


class SignerMalformed(SignerUnavailable):
    """The KMS answered with something that is not a valid signature or key."""

    kind = "malformed"


class SignerCapabilityAbsent(SignerUnavailable):
    """This host holds a public key only and cannot mint."""

    kind = "no-signing-capability"


# ---------------------------------------------------------------------------
# The port
# ---------------------------------------------------------------------------


class ApprovalSigner(Protocol):
    """Seals and checks the canonical bytes of an approval."""

    #: One of :data:`SCHEMES`; bound into the approval envelope.
    scheme: str
    #: A non-secret identifier for the key; bound into the approval envelope.
    key_id: str
    #: True when the private key never exists on this host.
    external: bool

    def sign(self, message: bytes) -> bytes:
        """Raises :class:`SignerUnavailable` rather than returning anything else."""

    def verify(self, message: bytes, signature: bytes) -> bool:
        """False for any signature that does not verify; never raises for one."""


def key_fingerprint(key: bytes) -> str:
    """A non-secret identifier for a symmetric key: a domain-separated hash
    prefix. Preimage resistance means it reveals nothing usable about the key;
    it lets an operator tell which key an approval was minted under."""

    return "hmac:" + hashlib.sha256(_FINGERPRINT_DOMAIN + key).hexdigest()[:16]


class LocalHmacSigner:
    """HMAC-SHA256 with a key held in this process.

    **Non-protecting against a host-level insider.** Anyone who can read this
    process — root, a debugger, a core dump — reads the key and mints
    approvals with no record anywhere. It exists for development and for the
    tests that record what it is worth; the runtime warns when it is the
    configured signer and ``require_external_signer`` refuses it.
    """

    scheme = HMAC_SHA256
    external = False

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key if key is not None else os.urandom(32)
        if not isinstance(self._key, bytes) or len(self._key) < 32:
            raise ValueError("approval signing key must be at least 32 bytes")
        self.key_id = key_fingerprint(self._key)

    def sign(self, message: bytes) -> bytes:
        return hmac.new(self._key, message, hashlib.sha256).digest()

    def verify(self, message: bytes, signature: bytes) -> bool:
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != 32:
            return False
        return hmac.compare_digest(self.sign(message), bytes(signature))

    def __repr__(self) -> str:
        return f"LocalHmacSigner(key_id={self.key_id!r})"


# ---------------------------------------------------------------------------
# The KMS port and the signer over it
# ---------------------------------------------------------------------------


class KmsError(RuntimeError):
    """The KMS refused or failed an operation."""


class KmsUnreachable(KmsError):
    """No answer from the KMS endpoint."""


class KmsAccessDenied(KmsError):
    """The calling principal lacks the Sign permission on the key."""


class KmsTimeout(KmsError):
    """The KMS did not answer within the deadline."""


class KmsPort(Protocol):
    """The two operations a signer needs from a KMS / HSM. Neither returns key
    material — a real adapter that could is not an adapter for this port.

    Mapping, call by call (``docs/key-custody.md`` has the full table):

    * ``sign`` → AWS KMS ``Sign(KeyId, Message=<digest>, MessageType=DIGEST,
      SigningAlgorithm=ECDSA_SHA_256)``; GCP ``asymmetricSign(name,
      digest={sha256: <digest>})``; PKCS#11 ``C_SignInit(CKM_ECDSA)`` +
      ``C_Sign(<digest>)`` with the raw ``r||s`` re-encoded as DER.
    * ``get_public_key`` → AWS ``GetPublicKey`` (``PublicKey`` is SPKI DER);
      GCP ``getPublicKey`` (PEM, decoded to DER); PKCS#11
      ``C_GetAttributeValue(CKA_EC_POINT, CKA_EC_PARAMS)`` assembled into SPKI.

    ``principal`` names the credential the call is made under; a real adapter
    ignores it (the credential is the client's), the in-memory model uses it
    to enforce and record who asked.
    """

    def sign(self, key_id: str, digest: bytes, *, principal: str) -> bytes:
        """A DER-encoded ECDSA signature over ``digest`` (32 bytes, SHA-256)."""

    def get_public_key(self, key_id: str) -> bytes:
        """The public key as SubjectPublicKeyInfo DER."""


def _crypto():
    """The asymmetric primitives, imported where they are used.

    ``cryptography`` is a declared dependency; the import is deferred so the
    package imports without it and the KMS path refuses loudly rather than
    the whole chokepoint failing to import.
    """

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            Prehashed,
            decode_dss_signature,
            encode_dss_signature,
        )
    except ImportError as exc:  # pragma: no cover - the dependency is declared
        raise SignerUnavailable(
            "the external signer needs the 'cryptography' package, which is not "
            "installed; refusing rather than falling back to a local key"
        ) from exc
    return InvalidSignature, hashes, serialization, ec, Prehashed, decode_dss_signature, encode_dss_signature


def digest_of(message: bytes) -> bytes:
    """What is actually sent to the KMS: the SHA-256 of the canonical bytes."""

    return hashlib.sha256(message).digest()


class _EcdsaP256Verifier:
    """Verification with a P-256 public key held as SPKI DER. Shared by the
    signer and the verify-only host; holds no private material by
    construction."""

    scheme = ECDSA_P256_SHA256
    external = True

    def _load_public(self, spki: bytes, *, where: str) -> None:
        _, _, serialization, ec, _, _, _ = _crypto()
        if not isinstance(spki, (bytes, bytearray)) or not spki:
            raise SignerMalformed(f"{where} returned no public key")
        try:
            public = serialization.load_der_public_key(bytes(spki))
        except (ValueError, TypeError) as exc:
            raise SignerMalformed(f"{where} returned an unreadable public key: {exc}") from exc
        except Exception as exc:  # noqa: BLE001 - UnsupportedAlgorithm and friends
            raise SignerMalformed(f"{where} returned an unsupported public key: {exc}") from exc
        if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(
            public.curve, ec.SECP256R1
        ):
            raise SignerMalformed(f"{where} returned a key that is not P-256")
        self._public = public
        self._spki = bytes(spki)

    @property
    def public_key_der(self) -> bytes:
        return self._spki

    @property
    def public_key_pem(self) -> str:
        _, _, serialization, _, _, _, _ = _crypto()
        return self._public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

    def verify(self, message: bytes, signature: bytes) -> bool:
        InvalidSignature, hashes, _, ec, Prehashed, decode, encode = _crypto()
        if not isinstance(signature, (bytes, bytearray)) or not signature:
            return False
        signature = bytes(signature)
        try:
            r, s = decode(signature)
        except ValueError:
            return False
        # Strict DER only: an alternative encoding of the same (r, s) is not
        # the signature the KMS produced and is refused.
        if encode(r, s) != signature:
            return False
        try:
            self._public.verify(
                signature, digest_of(message), ec.ECDSA(Prehashed(hashes.SHA256()))
            )
        except InvalidSignature:
            return False
        return True


class KmsSigner(_EcdsaP256Verifier):
    """Signs through a :class:`KmsPort`; the private key never exists here.

    The public key is fetched once at construction and cached, so verification
    never contacts the KMS: a verify-side outage cannot happen, and a
    verify-side credential does not exist. Construction itself fails closed —
    no reachable, well-formed public key, no signer.
    """

    def __init__(self, kms: KmsPort, *, key_id: str, principal: str = "runner") -> None:
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("KmsSigner needs a key_id")
        self._kms = kms
        self.key_id = key_id
        self._principal = principal
        try:
            spki = kms.get_public_key(key_id)
        except KmsError as exc:
            raise _unavailable(exc, f"fetching the public key for {key_id!r}") from exc
        self._load_public(spki, where=f"KMS key {key_id!r}")

    @property
    def principal(self) -> str:
        """Configured credential identity; real adapters must bind it honestly."""
        return self._principal

    def sign(self, message: bytes) -> bytes:
        digest = digest_of(message)
        try:
            signature = self._kms.sign(self.key_id, digest, principal=self._principal)
        except KmsError as exc:
            raise _unavailable(exc, f"signing with {self.key_id!r}") from exc
        # The answer is checked under the KMS's own public key before it is
        # used: a KMS that returns garbage — or a signature by some other key —
        # is a malformed answer, not an approval.
        if not isinstance(signature, (bytes, bytearray)) or not self.verify(message, signature):
            raise SignerMalformed(
                f"the KMS returned something that does not verify as a signature "
                f"by {self.key_id!r} under its own public key; no approval is minted"
            )
        return bytes(signature)

    def __repr__(self) -> str:
        return f"KmsSigner(key_id={self.key_id!r}, principal={self._principal!r})"


class PublicKeyVerifier(_EcdsaP256Verifier):
    """A host that can check approvals and can never mint one.

    Holds the public key and nothing else. ``sign`` raises
    :class:`SignerCapabilityAbsent`: the absence of signing capability on the
    execute side is the point, not a limitation.
    """

    def __init__(self, public_key: bytes | str, *, key_id: str) -> None:
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("PublicKeyVerifier needs a key_id")
        self.key_id = key_id
        # A separate local for the decoded form: rebinding the parameter left it
        # typed `bytes | str` for the rest of the function, so the DER handed on
        # below was only accidentally a `bytes`.
        spki: bytes
        if isinstance(public_key, str):
            _, _, serialization, _, _, _, _ = _crypto()
            try:
                loaded = serialization.load_pem_public_key(public_key.encode("ascii"))
                spki = loaded.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            except (ValueError, TypeError, UnicodeEncodeError) as exc:
                raise SignerMalformed(f"unreadable public key PEM: {exc}") from exc
        else:
            spki = public_key
        self._load_public(spki, where="the pinned public key")

    def sign(self, message: bytes) -> bytes:
        raise SignerCapabilityAbsent(
            f"this host holds only the public key for {self.key_id!r} and cannot "
            "mint an approval"
        )

    def __repr__(self) -> str:
        return f"PublicKeyVerifier(key_id={self.key_id!r})"


def _unavailable(exc: KmsError, doing: str) -> SignerUnavailable:
    if isinstance(exc, KmsAccessDenied):
        return SignerDenied(f"the KMS denied {doing}: {exc}")
    if isinstance(exc, KmsTimeout):
        return SignerTimeout(f"the KMS timed out {doing}: {exc}")
    if isinstance(exc, KmsUnreachable):
        return SignerUnreachable(f"the KMS was unreachable {doing}: {exc}")
    return SignerUnavailable(f"the KMS failed {doing}: {exc}")
