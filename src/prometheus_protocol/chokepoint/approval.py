"""Artifact-bound, single-use, short-lived migration approvals — the signed capability.

An approval is a *capability*: possession of a valid one authorizes exactly one
execution of exactly one migration artifact against exactly one target, within a
short window. It is bound by construction, not by convention:

* **artifact binding** — it carries the SHA-256 of the exact migration SQL; the
  runner re-hashes what it is about to execute and refuses on mismatch (a *swap*
  of a different artifact under a valid approval fails);
* **target binding** — it names the exact target; use against another target
  fails;
* **expiry** — it carries an absolute expiry; past it, it fails;
* **unforgeability** — every field is sealed by a signature over the canonical
  bytes, made by an :class:`~prometheus_protocol.chokepoint.signer.ApprovalSigner`:
  HMAC-SHA256 with a runner-zone key (development), or ECDSA P-256 through an
  external KMS / HSM whose private key never exists on the host (PIH-2,
  ``docs/key-custody.md``). The agent zone never holds either (see
  ``docs/chokepoint-threat-model.md`` §4.3), so an agent cannot mint or alter an
  approval: any tampered field or hand-crafted signature fails verification.
  That unreachability is a property of the sandbox, not of this module, and it is
  proven rather than assumed: ``tests/chokepoint/test_agent_zone_containment.py``
  plants the local key in the runner's environment and sweeps for it from inside
  the agent context by every path it has. Until PROM-HARDEN-MAX the sandbox
  inherited the runner's environment wholesale, so an agent could simply read
  ``PROM_CHOKEPOINT_KEY`` and mint its own approvals — everything below is
  downstream of a key the attacker would already have held. Root on the host
  could always read that key; with the external signer, root must ask the KMS
  to sign, and the KMS records the request. Detection, not prevention.

Single use (replay protection) is *stateful* and therefore NOT a property of this
pure module — it is enforced by the runner's atomic consumed-nonce claim
(``runner.py``). ``verify`` here is deliberately side-effect free so it can be
called freely; the nonce it carries is what the runner spends exactly once.

Authorization is fail-closed: :meth:`ApprovalAuthority.authorize` mints an
approval **only** for an authoritative ``PASS`` judgment. An ``Unavailable`` (a
verifier that could not run), a ``FAIL``, or a non-authoritative verdict yields
``None`` — no capability, so nothing downstream can execute.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import stat
import string
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - import cycle: policy imports core.models
    from prometheus_protocol.policy.assessment import PolicyAssessment

from prometheus_protocol.chokepoint.signer import (
    HMAC_SHA256,
    SCHEMES,
    ApprovalSigner,
    LocalHmacSigner,
)
from prometheus_protocol.core.models import Judgment, Unavailable, Verdict
from prometheus_protocol.policy.snapshot import ACTION_DATABASE_MIGRATE

#: Default approval lifetime. The window clocks *mint → execute* — an automated
#: hop once a migration has been authorized — NOT human deliberation, which
#: happens before minting. 90s is ample for that hop and short enough that a
#: captured approval is stale before it is useful.
DEFAULT_TTL_SECONDS = 90.0
#: The envelope version. v3 (PIH-2) names the scheme and key the signature was
#: made with; the *binding* — the canonical bytes the signature seals — is the
#: v2 binding unchanged, and a test pins its digest.
APPROVAL_VERSION = 3
#: Bounds on the envelope's signature field, in hex characters: an HMAC is
#: exactly 64; a DER-encoded P-256 ECDSA signature is 140–144. Anything outside
#: is not a signature this module would ever produce.
_SIGNATURE_HEX_MIN = 64
_SIGNATURE_HEX_MAX = 256
_KEY_ID_MAX = 128


@dataclass(frozen=True)
class MigrationTarget:
    """The complete, credential-independent identity of a migration target.

    An approval binds to all fields that can change the authority or namespace
    in which SQL executes.  The password is deliberately absent: rotating a
    credential must not invalidate an otherwise identical approval, while
    changing the database principal or schema must.

    ``canonical`` is a deterministic JSON representation used by the approval
    MAC and audit records.  A structured, length-prefixed approval encoding
    keeps field boundaries unambiguous even when identifiers contain punctuation.
    """

    host: str
    port: int
    dbname: str
    user: str
    schema: str

    def __post_init__(self) -> None:
        for name in ("host", "dbname", "user", "schema"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"migration target {name} must be a non-empty string")
            if value != value.strip():
                raise ValueError(f"migration target {name} cannot have outer whitespace")
            if "\x00" in value:
                raise ValueError(f"migration target {name} cannot contain NUL")
        if not isinstance(self.port, int) or isinstance(self.port, bool):
            raise TypeError("migration target port must be an integer")
        if not 1 <= self.port <= 65_535:
            raise ValueError("migration target port must be between 1 and 65535")

    @property
    def canonical(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

    def to_dict(self) -> dict[str, str | int]:
        return {
            "database": self.dbname,
            "host": self.host,
            "port": self.port,
            "schema": self.schema,
            "user": self.user,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> MigrationTarget:
        expected = {"database", "host", "port", "schema", "user"}
        if set(value) != expected:
            raise ValueError("migration target has missing or unknown fields")
        port = value["port"]
        if not isinstance(port, int) or isinstance(port, bool):
            raise TypeError("migration target port must be an integer")
        strings: dict[str, str] = {}
        for key in ("database", "host", "schema", "user"):
            item = value[key]
            if not isinstance(item, str):
                raise TypeError(f"migration target {key} must be a string")
            strings[key] = item
        return cls(
            host=strings["host"],
            port=port,
            dbname=strings["database"],
            user=strings["user"],
            schema=strings["schema"],
        )

    def __str__(self) -> str:
        return self.canonical


def artifact_hash(sql: str) -> str:
    """The content hash an approval binds to: SHA-256 of the migration SQL bytes."""

    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


#: Refuse absurdly large migration files rather than reading them into memory.
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class ArtifactSource:
    """Where an artifact's bytes came from, captured from the very descriptor
    they were read through — so it describes the file that was actually read,
    not whatever now answers to that path."""

    path: str
    device: int
    inode: int
    size: int


@dataclass(frozen=True)
class MigrationArtifact:
    """The exact thing to be executed. Its identity is the hash of its content.

    The content lives *here*, as bytes already read, and :attr:`sha256` hashes
    that same in-memory string — so there is no window between hashing and
    executing in which a path could be made to mean something else. A migration
    normally starts life as a file, and the moment a file *path* is what gets
    carried to execution, a local adversary only has to rewrite it in between:
    approved artifact hashed, hostile artifact run, the approval still valid for
    a hash nobody re-checks. :meth:`from_path` is the safe ingestion point, and
    ``source`` is excluded from equality so an artifact read from disk still
    compares equal to the same SQL constructed in memory.
    """

    sql: str
    source: ArtifactSource | None = field(default=None, compare=False)

    @property
    def sha256(self) -> str:
        return artifact_hash(self.sql)

    @classmethod
    def from_path(cls, path: str | os.PathLike[str]) -> MigrationArtifact:
        """Read a migration file ONCE and keep its bytes.

        Everything is done through a single descriptor: opened ``O_NOFOLLOW`` so
        a symlink swapped in at the path cannot redirect the read, checked to be
        a regular file (a FIFO would block forever, a device would not be a
        migration), then read and ``fstat``-ed through that same descriptor. What
        gets hashed is what got read; a later rewrite of the path — in place or by
        rename — cannot reach the returned artifact.
        """

        # O_NONBLOCK is load-bearing, not tidiness: opening a FIFO read-only
        # BLOCKS until a writer appears, and the regular-file check below happens
        # after the open — too late to help. A migration path an adversary can
        # replace with a named pipe would hang the runner indefinitely, holding
        # a spent approval and an unreconciled intent. With O_NONBLOCK the open
        # returns at once (or fails), and the check then refuses it. For a
        # regular file the flag has no effect.
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("migration artifact must be a regular file")
            if info.st_size > MAX_ARTIFACT_BYTES:
                raise ValueError(
                    f"migration artifact is larger than {MAX_ARTIFACT_BYTES} bytes"
                )
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARTIFACT_BYTES:
                    raise ValueError(
                        f"migration artifact is larger than {MAX_ARTIFACT_BYTES} bytes"
                    )
                chunks.append(chunk)
        finally:
            os.close(descriptor)
        raw = b"".join(chunks)
        try:
            sql = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("migration artifact is not valid UTF-8") from exc
        return cls(
            sql=sql,
            source=ArtifactSource(
                path=os.fspath(path),
                device=info.st_dev,
                inode=info.st_ino,
                size=total,
            ),
        )

    def source_still_matches(self) -> bool | None:
        """Whether the originating file still holds the bytes this artifact was
        built from. ``None`` when the artifact did not come from a file.

        Purely **evidence**: execution never depends on it, because the content is
        already held. It answers "was the file tampered with after we read it?",
        which is worth recording in the audit trail even though the answer cannot
        change what runs.
        """

        if self.source is None:
            return None
        try:
            replacement = MigrationArtifact.from_path(self.source.path)
        except (OSError, ValueError):
            return False
        return hmac.compare_digest(replacement.sha256, self.sha256)


@dataclass(frozen=True)
class Approval:
    """A signed, single-use capability to run one artifact against one target.

    The bound fields — artifact, target, nonce, issuance, expiry — are sealed
    by ``signature``, made with ``scheme`` under the key named by ``key_id``
    (an HMAC over a runner-zone key, or an ECDSA signature by an external KMS).
    It is inert data — it authorizes nothing until
    :meth:`ApprovalAuthority.verify` accepts it and the runner spends its
    ``nonce``.
    """

    artifact_sha256: str
    target: MigrationTarget
    nonce: str
    issued_at: float
    expires_at: float
    scheme: str
    key_id: str
    signature: str
    version: int = APPROVAL_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "artifact_sha256": self.artifact_sha256,
            "target": self.target.to_dict(),
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "scheme": self.scheme,
            "key_id": self.key_id,
            "signature": self.signature,
        }

    def to_json(self) -> str:
        """Serialize with a stable, versioned wire representation."""

        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> Approval:
        expected = {
            "version",
            "artifact_sha256",
            "target",
            "nonce",
            "issued_at",
            "expires_at",
            "scheme",
            "key_id",
            "signature",
        }
        if set(value) != expected:
            raise ValueError("approval has missing or unknown fields")
        version = value["version"]
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version != APPROVAL_VERSION
        ):
            raise ValueError(f"unsupported approval version {value['version']!r}")
        target = value["target"]
        if not isinstance(target, Mapping):
            raise TypeError("approval target must be an object")
        artifact_sha256 = _required_hex(
            value["artifact_sha256"], name="artifact_sha256", length=64
        )
        nonce = _required_hex(value["nonce"], name="nonce", length=32)
        scheme = _required_scheme(value["scheme"])
        key_id = _required_key_id(value["key_id"])
        signature = _required_signature_hex(value["signature"], scheme=scheme)
        issued_at = _required_finite_number(value["issued_at"], name="issued_at")
        expires_at = _required_finite_number(value["expires_at"], name="expires_at")
        if expires_at <= issued_at:
            raise ValueError("approval expiry must be after issuance")
        return cls(
            artifact_sha256=artifact_sha256,
            target=MigrationTarget.from_dict(target),
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
            scheme=scheme,
            key_id=key_id,
            signature=signature,
        )

    @classmethod
    def from_json(cls, value: str) -> Approval:
        """Parse an approval without accepting duplicate or non-object JSON."""

        def reject_duplicate_keys(
            pairs: list[tuple[str, object]],
        ) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError(f"duplicate approval field {key!r}")
                result[key] = item
            return result

        parsed = json.loads(value, object_pairs_hook=reject_duplicate_keys)
        if not isinstance(parsed, Mapping):
            raise TypeError("approval JSON must contain an object")
        return cls.from_dict(parsed)


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of verifying an approval. ``ok`` is True only when every bound
    field checks out; otherwise ``reason`` names the first failure (fail-closed)."""

    ok: bool
    reason: str = ""


# Refusal reasons (stable identifiers a caller/ledger can key on).
INVALID_SIGNATURE = "invalid_signature"
ARTIFACT_MISMATCH = "artifact_mismatch"
TARGET_MISMATCH = "target_mismatch"
EXPIRED = "expired"
INVALID_TIME = "invalid_time"
OK = "ok"


def _required_hex(value: object, *, name: str, length: int) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(character not in string.hexdigits for character in value)
    ):
        raise ValueError(f"approval {name} must be {length} hexadecimal characters")
    return value.lower()


def _required_finite_number(value: object, *, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"approval {name} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"approval {name} must be finite")
    return result


def _required_scheme(value: object) -> str:
    if not isinstance(value, str) or value not in SCHEMES:
        raise ValueError(f"approval scheme must be one of {', '.join(SCHEMES)}")
    return value


def _required_key_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _KEY_ID_MAX
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise ValueError(
            f"approval key_id must be 1-{_KEY_ID_MAX} printable ASCII characters"
        )
    return value


def _required_signature_hex(value: object, *, scheme: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) % 2
        or not _SIGNATURE_HEX_MIN <= len(value) <= _SIGNATURE_HEX_MAX
        or any(character not in string.hexdigits for character in value)
    ):
        raise ValueError("approval signature must be an even-length hexadecimal string")
    if scheme == HMAC_SHA256 and len(value) != 64:
        raise ValueError("an hmac-sha256 approval signature must be 64 hexadecimal characters")
    return value.lower()


def approval_digest(approval: Approval) -> str:
    """The SHA-256 (hex) of the bytes an approval's signature seals — the value
    an external KMS logs for each Sign request, so an auditor can match every
    approval to its record (``kms_model.unwitnessed_digests``)."""

    return hashlib.sha256(
        _canonical(
            approval.artifact_sha256,
            approval.target,
            approval.nonce,
            approval.issued_at,
            approval.expires_at,
        )
    ).hexdigest()


def _length_prefix(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return len(encoded).to_bytes(8, "big") + encoded


def _canonical(
    artifact_sha256: str,
    target: MigrationTarget,
    nonce: str,
    issued_at: float,
    expires_at: float,
) -> bytes:
    # Versioned and length-prefixed so there is no delimiter-splicing ambiguity.
    # A v2 approval intentionally cannot verify under the older, partial target
    # identity: changing the binding format is a security boundary change.
    fields = (
        artifact_sha256,
        target.canonical,
        nonce,
        issued_at.hex(),
        expires_at.hex(),
    )
    return b"promethyn-approval-v2\x00" + b"".join(
        _length_prefix(field) for field in fields
    )


class ApprovalAuthority:
    """Mints and verifies approvals through an :class:`ApprovalSigner`.

    With the default local signer the key lives only where the authority is
    constructed — the gate and the runner, both in the trusted zone. It is never
    written to the agent's workspace, never placed in an artifact, never handed
    to the agent. Default is a fresh 32-byte random key; a runner may instead
    pass a key sourced from its own environment (``PROM_CHOKEPOINT_KEY``) so
    gate and runner share one. That key is readable by root on the host, which
    is the residual the external signer answers: pass ``signer=KmsSigner(…)``
    and no private key exists on the host at all (``docs/key-custody.md``).
    """

    def __init__(
        self, *, key: bytes | None = None, signer: ApprovalSigner | None = None
    ) -> None:
        if signer is not None and key is not None:
            raise ValueError("pass a signing key or a signer, not both")
        if signer is None:
            signer = LocalHmacSigner(key if key is not None else os.urandom(32))
        self._signer = signer

    @property
    def signer(self) -> ApprovalSigner:
        return self._signer

    @property
    def external(self) -> bool:
        """True when no private key exists on this host."""

        return bool(self._signer.external)

    def __repr__(self) -> str:
        return (
            f"ApprovalAuthority(scheme={self._signer.scheme!r}, "
            f"key_id={self._signer.key_id!r}, external={self.external})"
        )

    def _sign(
        self,
        artifact_sha256: str,
        target: MigrationTarget,
        nonce: str,
        issued_at: float,
        expires_at: float,
    ) -> str:
        """Seal the canonical bytes. Raises ``SignerUnavailable`` — never
        returns a placeholder — when the signer cannot sign."""

        return self._signer.sign(
            _canonical(artifact_sha256, target, nonce, issued_at, expires_at)
        ).hex()

    def mint(
        self,
        *,
        artifact_sha256: str,
        target: MigrationTarget,
        now: float,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
    ) -> Approval:
        """Mint a bound, signed, single-use approval. Prefer :meth:`authorize`,
        which will not mint without an authoritative PASS."""

        checked_hash = _required_hex(
            artifact_sha256, name="artifact_sha256", length=64
        )
        if not isinstance(target, MigrationTarget):
            raise TypeError("approval target must be a MigrationTarget")
        now = _required_finite_number(now, name="issued_at")
        ttl_seconds = _required_finite_number(ttl_seconds, name="ttl_seconds")
        if ttl_seconds <= 0:
            raise ValueError("approval ttl_seconds must be greater than zero")
        nonce = secrets.token_hex(16)
        expires_at = now + ttl_seconds
        if not math.isfinite(expires_at):
            raise ValueError("approval expires_at must be finite")
        signature = self._sign(checked_hash, target, nonce, now, expires_at)
        return Approval(
            artifact_sha256=checked_hash,
            target=target,
            nonce=nonce,
            issued_at=now,
            expires_at=expires_at,
            scheme=self._signer.scheme,
            key_id=self._signer.key_id,
            signature=signature,
            version=APPROVAL_VERSION,
        )

    def authorize(
        self,
        assessment: "PolicyAssessment",
        *,
        artifact: MigrationArtifact,
        target: MigrationTarget,
        now: float,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
    ) -> Approval | None:
        """Mint an approval ONLY for an authoritative PASS — else ``None``.

        Fail-closed by construction: an ``Unavailable`` (a check that could not
        run), a ``FAIL``, or a non-authoritative verdict produces no capability,
        so the migration cannot execute. Mirrors ``gate.authorization.ActionGate``
        semantics for the migration action. A signer that cannot sign raises
        ``SignerUnavailable`` — distinct from ``None``, because "could not sign"
        must never be read as "not authorised" or as "signed".

        PHASE-1.2b — THE FOURTH AUTHORIZATION SURFACE, and the one the sprint
        brief did not name. This minted a signed, single-use capability to run a
        migration against a privileged database principal from a raw
        authoritative ``Judgment``: the most consequential action class in the
        system was reachable without a policy ever being resolved. It now takes a
        :class:`~prometheus_protocol.policy.assessment.PolicyAssessment`, and an
        unbound judgment raises rather than minting.

        The assessment must also be bound to THIS artifact and target. A
        capability is minted for one artifact against one principal; an
        assessment resolved for a different one is evidence about a different
        action, and accepting it would let a policy evaluation of a harmless
        migration authorize a destructive one.
        """

        from prometheus_protocol.policy.assessment import require_assessment

        checked = require_assessment(
            assessment, surface="ApprovalAuthority.authorize"
        )
        judgment = checked.outcome
        if isinstance(judgment, Unavailable):
            return None
        if judgment.verdict != Verdict.PASS or not judgment.authoritative:
            return None
        if checked.action_class != ACTION_DATABASE_MIGRATE:
            return None
        if not hmac.compare_digest(checked.artifact_sha256, artifact.sha256):
            return None
        if not hmac.compare_digest(checked.target_canonical, target.canonical):
            return None
        return self.mint(
            artifact_sha256=artifact.sha256,
            target=target,
            now=now,
            ttl_seconds=ttl_seconds,
        )

    def verify(
        self,
        approval: Approval,
        *,
        artifact: MigrationArtifact,
        target: MigrationTarget,
        now: float,
    ) -> VerifyResult:
        """Stateless verification of every bound field, fail-closed.

        Order matters: the signature is checked FIRST, so a tampered field can
        never be trusted to route the later checks. Single-use is not checked
        here — the runner spends the nonce atomically.
        """

        if (
            not isinstance(approval.version, int)
            or isinstance(approval.version, bool)
            or approval.version != APPROVAL_VERSION
        ):
            return VerifyResult(False, INVALID_SIGNATURE)
        if not isinstance(approval.target, MigrationTarget):
            return VerifyResult(False, INVALID_SIGNATURE)
        if not isinstance(target, MigrationTarget):
            return VerifyResult(False, TARGET_MISMATCH)
        try:
            artifact_sha256 = _required_hex(
                approval.artifact_sha256, name="artifact_sha256", length=64
            )
            nonce = _required_hex(approval.nonce, name="nonce", length=32)
            scheme = _required_scheme(approval.scheme)
            key_id = _required_key_id(approval.key_id)
            signature = bytes.fromhex(
                _required_signature_hex(approval.signature, scheme=scheme)
            )
        except (TypeError, ValueError):
            return VerifyResult(False, INVALID_SIGNATURE)
        # The envelope must name THIS authority's scheme and key: a signature
        # under some other key, or another scheme, is not one to try.
        if scheme != self._signer.scheme or not hmac.compare_digest(
            key_id, self._signer.key_id
        ):
            return VerifyResult(False, INVALID_SIGNATURE)
        try:
            checked_now = _required_finite_number(now, name="now")
            issued_at = _required_finite_number(
                approval.issued_at, name="issued_at"
            )
            expires_at = _required_finite_number(
                approval.expires_at, name="expires_at"
            )
        except (TypeError, ValueError):
            return VerifyResult(False, INVALID_TIME)
        if expires_at <= issued_at:
            return VerifyResult(False, INVALID_TIME)
        sealed = _canonical(artifact_sha256, approval.target, nonce, issued_at, expires_at)
        if not self._signer.verify(sealed, signature):
            return VerifyResult(False, INVALID_SIGNATURE)
        if not hmac.compare_digest(artifact_sha256, artifact.sha256):
            return VerifyResult(False, ARTIFACT_MISMATCH)
        if not hmac.compare_digest(approval.target.canonical, target.canonical):
            return VerifyResult(False, TARGET_MISMATCH)
        if checked_now < issued_at:
            return VerifyResult(False, INVALID_TIME)
        if checked_now >= expires_at:
            return VerifyResult(False, EXPIRED)
        return VerifyResult(True, OK)
