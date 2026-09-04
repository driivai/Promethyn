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
* **unforgeability** — every field is covered by an HMAC-SHA256 over a
  runner-zone secret key. The agent zone never holds that key (see
  ``docs/chokepoint-threat-model.md`` §4.3), so an agent cannot mint or alter an
  approval: any tampered field or hand-crafted MAC fails ``hmac.compare_digest``.
  That unreachability is a property of the sandbox, not of this module, and it is
  proven rather than assumed: ``tests/chokepoint/test_agent_zone_containment.py``
  plants this key in the runner's environment and sweeps for it from inside the
  agent context by every path it has. Until PROM-HARDEN-MAX the sandbox inherited
  the runner's environment wholesale, so an agent could simply read
  ``PROM_CHOKEPOINT_KEY`` and mint its own approvals — everything below is
  downstream of a key the attacker would already have held.

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
import string
from collections.abc import Mapping
from dataclasses import dataclass

from prometheus_protocol.core.models import Judgment, Unavailable, Verdict

#: Default approval lifetime. The window clocks *mint → execute* — an automated
#: hop once a migration has been authorized — NOT human deliberation, which
#: happens before minting. 90s is ample for that hop and short enough that a
#: captured approval is stale before it is useful.
DEFAULT_TTL_SECONDS = 90.0
APPROVAL_VERSION = 2


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


@dataclass(frozen=True)
class MigrationArtifact:
    """The exact thing to be executed. Its identity is the hash of its content."""

    sql: str

    @property
    def sha256(self) -> str:
        return artifact_hash(self.sql)


@dataclass(frozen=True)
class Approval:
    """A signed, single-use capability to run one artifact against one target.

    All fields except ``mac`` are covered by ``mac``; the ``mac`` is an
    HMAC-SHA256 over them keyed by a runner-zone secret. It is inert data — it
    authorizes nothing until :meth:`ApprovalAuthority.verify` accepts it and the
    runner spends its ``nonce``.
    """

    artifact_sha256: str
    target: MigrationTarget
    nonce: str
    issued_at: float
    expires_at: float
    mac: str
    version: int = APPROVAL_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "artifact_sha256": self.artifact_sha256,
            "target": self.target.to_dict(),
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "mac": self.mac,
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
            "mac",
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
        mac = _required_hex(value["mac"], name="mac", length=64)
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
            mac=mac,
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
    """Holds the runner-zone signing key; mints and verifies approvals.

    The key lives only where an ``ApprovalAuthority`` is constructed — the gate
    and the runner, both in the trusted zone. It is never written to the agent's
    workspace, never placed in an artifact, never handed to the agent. Default is
    a fresh 32-byte random key; a runner may instead pass a key sourced from its
    own environment (``PROM_CHOKEPOINT_KEY``) so gate and runner share one.
    """

    def __init__(self, *, key: bytes | None = None) -> None:
        self._key = key if key is not None else os.urandom(32)
        if not isinstance(self._key, bytes) or len(self._key) < 32:
            raise ValueError("approval signing key must be at least 32 bytes")

    def _mac(
        self,
        artifact_sha256: str,
        target: MigrationTarget,
        nonce: str,
        issued_at: float,
        expires_at: float,
    ) -> str:
        return hmac.new(
            self._key,
            _canonical(artifact_sha256, target, nonce, issued_at, expires_at),
            hashlib.sha256,
        ).hexdigest()

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
        mac = self._mac(checked_hash, target, nonce, now, expires_at)
        return Approval(
            artifact_sha256=checked_hash,
            target=target,
            nonce=nonce,
            issued_at=now,
            expires_at=expires_at,
            mac=mac,
            version=APPROVAL_VERSION,
        )

    def authorize(
        self,
        judgment: Judgment | Unavailable,
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
        semantics for the migration action.
        """

        if isinstance(judgment, Unavailable):
            return None
        if judgment.verdict != Verdict.PASS or not judgment.authoritative:
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
            mac = _required_hex(approval.mac, name="mac", length=64)
        except (TypeError, ValueError):
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
        expected = self._mac(
            artifact_sha256,
            approval.target,
            nonce,
            issued_at,
            expires_at,
        )
        if not hmac.compare_digest(expected, mac):
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
