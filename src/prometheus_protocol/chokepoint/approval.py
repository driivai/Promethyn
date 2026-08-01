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
import os
import secrets
from dataclasses import dataclass

from prometheus_protocol.core.models import Judgment, Unavailable, Verdict

#: Default approval lifetime. The window clocks *mint → execute* — an automated
#: hop once a migration has been authorized — NOT human deliberation, which
#: happens before minting. 90s is ample for that hop and short enough that a
#: captured approval is stale before it is useful.
DEFAULT_TTL_SECONDS = 90.0


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
    target: str
    nonce: str
    issued_at: float
    expires_at: float
    mac: str


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
OK = "ok"


def _canonical(artifact_sha256: str, target: str, nonce: str,
               issued_at: float, expires_at: float) -> bytes:
    # A fixed, unambiguous serialization of every bound field. Delimited by a
    # byte that cannot appear in the hex/float fields, so no field-splicing
    # ambiguity is possible.
    return (
        f"{artifact_sha256}|{target}|{nonce}|{issued_at:.6f}|{expires_at:.6f}"
    ).encode("utf-8")


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
        if len(self._key) < 16:
            raise ValueError("approval signing key must be at least 16 bytes")

    def _mac(self, artifact_sha256: str, target: str, nonce: str,
             issued_at: float, expires_at: float) -> str:
        return hmac.new(
            self._key,
            _canonical(artifact_sha256, target, nonce, issued_at, expires_at),
            hashlib.sha256,
        ).hexdigest()

    def mint(self, *, artifact_sha256: str, target: str, now: float,
             ttl_seconds: float = DEFAULT_TTL_SECONDS) -> Approval:
        """Mint a bound, signed, single-use approval. Prefer :meth:`authorize`,
        which will not mint without an authoritative PASS."""

        nonce = secrets.token_hex(16)
        expires_at = now + ttl_seconds
        mac = self._mac(artifact_sha256, target, nonce, now, expires_at)
        return Approval(
            artifact_sha256=artifact_sha256, target=target, nonce=nonce,
            issued_at=now, expires_at=expires_at, mac=mac,
        )

    def authorize(
        self,
        judgment: Judgment | Unavailable,
        *,
        artifact: MigrationArtifact,
        target: str,
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
            artifact_sha256=artifact.sha256, target=target, now=now,
            ttl_seconds=ttl_seconds,
        )

    def verify(
        self,
        approval: Approval,
        *,
        artifact: MigrationArtifact,
        target: str,
        now: float,
    ) -> VerifyResult:
        """Stateless verification of every bound field, fail-closed.

        Order matters: the signature is checked FIRST, so a tampered field can
        never be trusted to route the later checks. Single-use is not checked
        here — the runner spends the nonce atomically.
        """

        expected = self._mac(
            approval.artifact_sha256, approval.target, approval.nonce,
            approval.issued_at, approval.expires_at,
        )
        if not hmac.compare_digest(expected, approval.mac):
            return VerifyResult(False, INVALID_SIGNATURE)
        if not hmac.compare_digest(approval.artifact_sha256, artifact.sha256):
            return VerifyResult(False, ARTIFACT_MISMATCH)
        if approval.target != target:
            return VerifyResult(False, TARGET_MISMATCH)
        if now > approval.expires_at:
            return VerifyResult(False, EXPIRED)
        return VerifyResult(True, OK)
