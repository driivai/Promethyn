"""A KMS / HSM in memory, with the real medium's semantics.

No cloud KMS SDK is bundled, for the reason PIH-1 gave for buckets: a signer
adapter the CI cannot exercise against a real KMS is a guard nobody has seen
work. What ships instead is the medium's *semantics*, faithfully, so the
signer logic is proven against them and a real adapter has a documented
contract to be proven against (``docs/key-custody.md``):

* **Unextractability.** A key is generated inside :meth:`MemoryKms.create_key`
  and held only inside a signing closure. No attribute of the model is a
  private key, no port operation returns one, and the model cannot be
  serialized. A test walks the surface and checks, rather than a comment
  asserting it.
* **Per-request logging.** Every ``sign`` call — granted or denied — appends
  a :class:`SignRequest` to a log that has no removal operation at all. It
  stands in for the KMS-side audit trail (CloudTrail, Cloud Audit Logs, the
  HSM's audit log) that a host insider cannot reach.
* **Separation of duties.** Creating a key and granting ``Sign`` are the key
  administrator's operations and require an administrator principal; the
  signing credential can sign and nothing else. That is the access-policy
  artifact a deployment must reproduce.
* **An adversary surface.** ``fault`` makes the KMS unreachable, slow, or
  broken; ``grant_sign``/``revoke_sign`` model the invoke permission, so the
  residual — an insider *with* invoke permission gets a valid signature, and
  is logged — is a test rather than a sentence.

The model is the reference; the tests run against it on every CI runner.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Iterable

from prometheus_protocol.chokepoint.signer import (
    KmsAccessDenied,
    KmsError,
    KmsTimeout,
    KmsUnreachable,
    _crypto,
)

SIGNED = "signed"
DENIED = "denied"


@dataclass(frozen=True)
class SignRequest:
    """One entry of the KMS-side sign log: who asked which key to sign what."""

    index: int
    key_id: str
    principal: str
    digest: str
    at: float
    outcome: str


class MemoryKms:
    """See the module docstring. Administration and the port are both here,
    because a real KMS exposes both — under different permissions."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        administrators: Iterable[str] = ("key-admin",),
    ) -> None:
        # Signing closures: the private key object is referenced by the
        # closure and by nothing else. ``vars(self)`` never holds a key.
        self._signers: dict[str, Callable[[bytes], bytes]] = {}
        self._public: dict[str, bytes] = {}
        self._invoke: dict[str, set[str]] = {}
        self._administrators = frozenset(administrators)
        self._log: list[SignRequest] = []
        self._clock = clock
        #: The adversary / fault surface: ``None``, ``"unreachable"``,
        #: ``"timeout"`` or ``"garbage"`` (answers, but not with a signature).
        self.fault: str | None = None

    # -- administration: the key administrator's role, not the signer's -----

    def _require_admin(self, by: str) -> None:
        if by not in self._administrators:
            raise KmsAccessDenied(
                f"{by!r} may not administer keys: only {sorted(self._administrators)} may"
            )

    def create_key(self, key_id: str, *, by: str = "key-admin") -> str:
        """Generate a P-256 key inside the KMS. Returns the id, never the key."""

        self._require_admin(by)
        if key_id in self._signers:
            raise KmsError(f"key {key_id!r} already exists")
        _, hashes, serialization, ec, Prehashed, _, _ = _crypto()
        private = ec.generate_private_key(ec.SECP256R1())

        def sign(digest: bytes) -> bytes:
            return private.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))

        self._signers[key_id] = sign
        self._public[key_id] = private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self._invoke[key_id] = set()
        # ``private`` is a local: it goes out of scope here, and the closure
        # above holds the only remaining reference.
        return key_id

    def grant_sign(self, key_id: str, principal: str, *, by: str = "key-admin") -> None:
        """Let ``principal`` invoke Sign on ``key_id``. An administrator's act."""

        self._require_admin(by)
        self._invoke[self._known(key_id)].add(principal)

    def revoke_sign(self, key_id: str, principal: str, *, by: str = "key-admin") -> None:
        self._require_admin(by)
        self._invoke[self._known(key_id)].discard(principal)

    def can_sign(self, key_id: str, principal: str) -> bool:
        return principal in self._invoke.get(key_id, set())

    def _known(self, key_id: str) -> str:
        if key_id not in self._signers:
            raise KmsError(f"no such key {key_id!r}")
        return key_id

    # -- the port: what a caller holding a credential can do ----------------

    def _reachable(self) -> None:
        if self.fault == "unreachable":
            raise KmsUnreachable("connection refused")
        if self.fault == "timeout":
            raise KmsTimeout("no answer within the deadline")

    def sign(self, key_id: str, digest: bytes, *, principal: str) -> bytes:
        self._reachable()
        self._known(key_id)
        if not isinstance(digest, (bytes, bytearray)) or len(digest) != 32:
            raise KmsError("digest must be exactly 32 bytes for ECDSA_SHA_256")
        digest_hex = bytes(digest).hex()
        if not self.can_sign(key_id, principal):
            # A denied attempt is an event too: the real audit trail records it,
            # and so does this one.
            self._append(key_id, principal, digest_hex, DENIED)
            raise KmsAccessDenied(f"{principal!r} may not invoke Sign on {key_id!r}")
        self._append(key_id, principal, digest_hex, SIGNED)
        if self.fault == "garbage":
            return b"\x30\x06\x02\x01\x01\x02\x01\x01"  # a DER pair that signs nothing
        return self._signers[key_id](bytes(digest))

    def get_public_key(self, key_id: str) -> bytes:
        self._reachable()
        self._known(key_id)
        if self.fault == "garbage":
            return b"not a public key"
        return self._public[key_id]

    # -- the audit trail: append-only, with no operation that removes --------

    def _append(self, key_id: str, principal: str, digest: str, outcome: str) -> None:
        self._log.append(
            SignRequest(
                index=len(self._log),
                key_id=key_id,
                principal=principal,
                digest=digest,
                at=self._clock(),
                outcome=outcome,
            )
        )

    def sign_log(self) -> tuple[SignRequest, ...]:
        """Every sign request ever made, in order. A copy: the log itself is
        not reachable through the port, and nothing here removes an entry."""

        return tuple(self._log)

    def __reduce__(self):
        raise TypeError("a KMS cannot be serialized: its keys do not leave it")


# ---------------------------------------------------------------------------
# The auditor's reconciliation: approvals against the sign log
# ---------------------------------------------------------------------------


def unwitnessed_digests(digests: Iterable[str], log: Iterable[SignRequest]) -> list[str]:
    """Approval digests with no ``signed`` record in the log.

    With an external signer every valid approval is exactly one Sign request,
    so a valid approval whose digest is absent from the KMS log means either
    the log was tampered with or the key exists somewhere other than the KMS —
    both alarms.
    """

    signed = {record.digest for record in log if record.outcome == SIGNED}
    return [digest for digest in digests if digest not in signed]


def unexplained_records(log: Iterable[SignRequest], digests: Iterable[str]) -> list[SignRequest]:
    """``signed`` records whose digest matches no approval the ledger knows.

    For a digest-bound log — this model's, or a GCP Data Access log carrying
    the observed digest — this is the forgery signal: a Sign request that no
    authorised approval accounts for was made by someone holding the invoke
    permission for their own purposes. A metadata-only trail cannot feed this
    comparison at all: native AWS CloudTrail records no digest, so there the
    operational reconciler answers INDETERMINATE, not detection
    (``docs/key-custody.md``). Denied attempts are listed too — an attempt is
    an event.
    """

    known = set(digests)
    return [
        record
        for record in log
        if record.outcome == DENIED or record.digest not in known
    ]
