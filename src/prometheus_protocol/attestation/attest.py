"""Sign the posture digest with PIH-2's signer; publish it to PIH-1's target.

Neither half is new machinery. Signing goes through the same
:class:`~prometheus_protocol.chokepoint.signer.ApprovalSigner` port PIH-2 built
for approvals — ``LocalHmacSigner`` in development, ``KmsSigner`` in production,
so in production the attestation is sealed by the same key that never exists on
this host — and verification goes through the same
:class:`~prometheus_protocol.chokepoint.signer.PublicKeyVerifier`, which holds a
public key and nothing a forger could use. Publishing goes to the same external
media PIH-1 anchors ledger tips to: the :class:`ObjectStore` port (a WORM mount
or an object-locked bucket) and the :class:`AppendOnlyLog` port (a log run by
another party), with the same concrete stores. A second signing path or a
second publish path would be drift, and there is neither.

**The local target is NON-PROTECTING**, for exactly PIH-1's reason: an insider
who changes the running config rewrites the local record in the same breath, so
the witness is inside the authority it is supposed to witness. It exists for
development, the runtime warns, and ``require_config_attestation`` refuses it.

**Publish failure is not swallowed.** Under the requirement it is fail-closed —
an unattestable posture is refused, because a security downgrade that cannot be
attested is itself the signal this control exists to raise, and the repository's
rule is that a requested security property which cannot be honoured is refused
rather than degraded (the same shape as a required ledger anchor). Without the
requirement it is a loud ERROR and the runtime continues: attestation is then an
optional witness, and turning an optional witness's outage into a hard
availability failure would be a worse trade than saying so at ERROR. Which of
the two applies is decided by the requirement alone, never by the error.

No background thread does this. A thread that publishes on a cadence and
swallows what it catches is precisely the void-guard shape — the control would
appear present and report nothing — so the cadence is a method the caller drives
(:meth:`ConfigAttestor.attest_if_due`) and every failure reaches that caller.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from prometheus_protocol.attestation.posture import (
    TARGET_FILE,
    TARGET_LOG,
    TARGET_WORM,
    ResolvedPosture,
    posture_digest,
)
from prometheus_protocol.chokepoint.signer import (
    ApprovalSigner,
    SignerUnavailable,
)
from prometheus_protocol.core.anchor_spec import (
    ANCHOR_FILE,
    ANCHOR_LOG,
    ANCHOR_WORM,
    AnchorSpec,
)
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.ledger.anchor_targets import (
    DEFAULT_RETENTION_S,
    AppendOnlyLog,
    DirectoryObjectStore,
    ObjectExists,
    ObjectStore,
    ObjectStoreError,
)
from prometheus_protocol.ledger.audit_chain import canonical_json

_LOG = logging.getLogger(__name__)

_DOMAIN = b"prom-config-attestation-v1\x00"
_KEY_WIDTH = 20
_MAX_RECORD_BYTES = 4096

#: Verification statuses. ATTESTED and MISMATCH are conclusions; NOT_VERIFIABLE
#: is the EX-1 distinction — the check could not run, and couldn't-verify is
#: never attested-clean.
ATTESTED = "attested"
MISMATCH = "mismatch"
NOT_VERIFIABLE = "not_verifiable"


class AttestationUnavailable(RuntimeError):
    """The posture could not be attested. Never a silent pass."""


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------


def _lp(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def signed_message(*, digest: str, created_at: str, key_id: str, scheme: str) -> bytes:
    """What the signature actually covers.

    The key id and scheme are inside the signature, so a record cannot be
    replayed as if it had been sealed by a different key or primitive.
    """

    return b"".join((
        _DOMAIN,
        _lp(digest.encode("ascii")),
        _lp(created_at.encode("ascii")),
        _lp(key_id.encode("utf-8")),
        _lp(scheme.encode("ascii")),
    ))


@dataclass(frozen=True)
class AttestationRecord:
    """One signed statement: at this time, this host was running this posture."""

    digest: str
    created_at: str
    key_id: str
    scheme: str
    signature: bytes

    @property
    def message(self) -> bytes:
        return signed_message(
            digest=self.digest,
            created_at=self.created_at,
            key_id=self.key_id,
            scheme=self.scheme,
        )

    def encode(self) -> bytes:
        return canonical_json({
            "digest": self.digest,
            "created_at": self.created_at,
            "key_id": self.key_id,
            "scheme": self.scheme,
            "signature": self.signature.hex(),
        }).encode("utf-8")


def decode_record(body: bytes, *, where: str) -> AttestationRecord:
    """Strictly. A record that cannot be read is unreadable, never ignored."""

    import json

    if not isinstance(body, (bytes, bytearray)) or not body:
        raise AttestationUnavailable(f"{where}: empty attestation record")
    if len(body) > _MAX_RECORD_BYTES:
        raise AttestationUnavailable(f"{where}: attestation record is implausibly large")
    try:
        payload = json.loads(bytes(body).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise AttestationUnavailable(f"{where}: unreadable attestation record: {exc}") from exc
    if not isinstance(payload, dict):
        raise AttestationUnavailable(f"{where}: attestation record is not an object")
    fields = {}
    for name in ("digest", "created_at", "key_id", "scheme", "signature"):
        value = payload.get(name)
        if not isinstance(value, str) or not value:
            raise AttestationUnavailable(f"{where}: attestation record has no {name}")
        fields[name] = value
    try:
        signature = bytes.fromhex(fields["signature"])
    except ValueError as exc:
        raise AttestationUnavailable(f"{where}: unreadable signature: {exc}") from exc
    if len(fields["digest"]) != 64 or any(c not in "0123456789abcdef" for c in fields["digest"]):
        raise AttestationUnavailable(f"{where}: attestation record has no posture digest")
    return AttestationRecord(
        digest=fields["digest"],
        created_at=fields["created_at"],
        key_id=fields["key_id"],
        scheme=fields["scheme"],
        signature=signature,
    )


# ---------------------------------------------------------------------------
# The targets — the PIH-1 ports, carrying attestation records
# ---------------------------------------------------------------------------


class AttestationTarget(Protocol):
    """Where signed postures are published. ``external`` is False for the local
    file, which is inside the authority it would have to witness."""

    kind: str
    external: bool

    def publish(self, record: AttestationRecord) -> None:
        """Write one record. Raises on any failure; never silently drops one."""

    def records(self) -> list[AttestationRecord]:
        """Every published record this target holds, oldest first."""


class ObjectStoreAttestationTarget:
    """One immutable object per attestation, on PIH-1's :class:`ObjectStore`.

    Keyed by a zero-padded creation time so lexical order is chronological, and
    written with ``put_if_absent`` under retention: this code never overwrites
    or deletes a record, and on a compliance-mode bucket or a WORM mount the
    medium refuses it to everyone else too. Re-publishing an identical record
    (a restart with an unchanged posture in the same instant) is idempotent.
    """

    kind = TARGET_WORM
    external = True

    def __init__(
        self,
        store: ObjectStore,
        *,
        # Flat, with no separator: DirectoryObjectStore lists a directory's own
        # entries by name, so a prefix containing "/" would write records into a
        # subdirectory the listing never reads — published and invisible.
        prefix: str = "attestation-",
        retain_for_s: float = DEFAULT_RETENTION_S,
    ) -> None:
        self._store = store
        self._prefix = prefix
        self._retain_for_s = retain_for_s

    def _key(self, record: AttestationRecord) -> str:
        stamp = record.created_at.rjust(_KEY_WIDTH, "0")[-_KEY_WIDTH:]
        return f"{self._prefix}{stamp}-{record.digest[:16]}.json"

    def publish(self, record: AttestationRecord) -> None:
        body = record.encode()
        try:
            self._store.put_if_absent(self._key(record), body, retain_for_s=self._retain_for_s)
        except ObjectExists:
            existing = self._store.versions(self._key(record))
            if body in existing:
                return
            raise AttestationUnavailable(
                "a different attestation already holds this record's position"
            )
        except ObjectStoreError as exc:
            raise AttestationUnavailable(f"could not publish the attestation: {exc}") from exc

    def records(self) -> list[AttestationRecord]:
        try:
            keys = self._store.list_keys(self._prefix)
            bodies = [(key, body) for key in keys for body in self._store.versions(key)]
        except ObjectStoreError as exc:
            raise AttestationUnavailable(f"could not read the attestations: {exc}") from exc
        return [decode_record(body, where=key) for key, body in bodies]


class LogAttestationTarget:
    """One appended record per attestation, on PIH-1's :class:`AppendOnlyLog`.

    Protecting exactly when the log is run by a party the config-writing
    adversary is not; the same statement, and the same trust boundary, as the
    ledger's append-only anchor (``docs/threat-model.md`` §3.4).
    """

    kind = TARGET_LOG
    external = True

    def __init__(self, log: AppendOnlyLog) -> None:
        self._log = log

    def publish(self, record: AttestationRecord) -> None:
        body = record.encode()
        try:
            index = self._log.append(body)
        except Exception as exc:  # noqa: BLE001 - the log is an external boundary
            raise AttestationUnavailable(f"could not publish the attestation: {exc}") from exc
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise AttestationUnavailable("the attestation log returned no valid append index")

    def records(self) -> list[AttestationRecord]:
        try:
            entries = self._log.entries()
        except Exception as exc:  # noqa: BLE001
            raise AttestationUnavailable(f"could not read the attestations: {exc}") from exc
        return [
            decode_record(body, where=f"attestation-log#{index}")
            for index, body in enumerate(entries)
        ]


class LocalFileAttestationTarget:
    """One local file, rewritten in place. **NON-PROTECTING.**

    Exactly PIH-1's ``file://`` anchor and exactly its reasoning: whoever can
    change the running configuration can rewrite this file in the same breath,
    so the record proves nothing against the adversary it exists for.
    Development only; ``require_config_attestation`` refuses it.
    """

    kind = TARGET_FILE
    external = False

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def publish(self, record: AttestationRecord) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_bytes(record.encode())
        except OSError as exc:
            raise AttestationUnavailable(f"could not publish the attestation: {exc}") from exc

    def records(self) -> list[AttestationRecord]:
        try:
            body = self.path.read_bytes()
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise AttestationUnavailable(f"could not read the attestation: {exc}") from exc
        return [decode_record(body, where=str(self.path))]


def build_attestation_target(
    spec: AnchorSpec,
    *,
    token: str | None = None,
    retain_for_s: float = DEFAULT_RETENTION_S,
    timeout_s: float = 10.0,
    allow_insecure_loopback: bool = False,
) -> AttestationTarget:
    """The target a parsed spec names — the same three kinds, the same stores.

    Dispatch mirrors ``ledger.anchor_targets.build_tip_anchor`` and reuses its
    concrete media (``DirectoryObjectStore``, ``HttpAppendOnlyLog``) rather than
    introducing a second way to reach an external witness.
    """

    if spec.kind == ANCHOR_FILE:
        return LocalFileAttestationTarget(spec.target)
    if spec.kind == ANCHOR_WORM:
        return ObjectStoreAttestationTarget(
            DirectoryObjectStore(spec.target), retain_for_s=retain_for_s
        )
    if spec.kind == ANCHOR_LOG:
        from prometheus_protocol.ledger.anchor_http import HttpAppendOnlyLog

        return LogAttestationTarget(
            HttpAppendOnlyLog(
                spec.target,
                token=token,
                timeout_s=timeout_s,
                allow_insecure_loopback=allow_insecure_loopback,
            )
        )
    raise ConfigError(f"unknown config attestation target kind {spec.kind!r}")


# ---------------------------------------------------------------------------
# Attesting, at startup and on a cadence
# ---------------------------------------------------------------------------


class ConfigAttestor:
    """Computes the live posture, signs its digest, publishes it.

    ``resolve`` is called every time, so a posture change mid-run produces a new
    digest the external record notices; it is a callable rather than a captured
    value for exactly that reason.
    """

    def __init__(
        self,
        *,
        target: AttestationTarget,
        signer: ApprovalSigner,
        resolve: Callable[[], ResolvedPosture],
        required: bool,
        interval_s: float = 3600.0,
        clock: Callable[[], float] = time.time,
        log: logging.Logger = _LOG,
    ) -> None:
        if interval_s <= 0:
            raise ConfigError("config attestation interval must be positive")
        self._target = target
        self._signer = signer
        self._resolve = resolve
        self._required = bool(required)
        self._interval_s = float(interval_s)
        self._clock = clock
        self._log = log
        self._last_at: float | None = None
        #: The last digest published, for an operator asking what is on record.
        self.last_digest: str | None = None

    @property
    def required(self) -> bool:
        return self._required

    def _fail(self, detail: str, exc: Exception | None = None) -> None:
        if self._required:
            raise AttestationUnavailable(
                f"config attestation is required and {detail}. A security posture "
                "that cannot be attested is itself the signal this control exists "
                "to raise, so the runtime refuses rather than continuing "
                "unattested. Fix the target or the signer, or withdraw "
                "require_config_attestation."
            ) from exc
        self._log.error(
            "config attestation FAILED and %s: the running security posture is "
            "NOT on any external record, so a downgrade from here would not be "
            "detectable. Set require_config_attestation to make this refuse "
            "instead of continue.",
            detail,
        )

    def attest(self) -> AttestationRecord | None:
        """Compute, sign and publish once.

        Returns the record on success. On failure it raises
        :class:`AttestationUnavailable` under the requirement, and returns
        ``None`` after an ERROR without it — never silently.
        """

        try:
            posture = self._resolve()
        except Exception as exc:  # noqa: BLE001 - resolution touches the whole host
            self._fail(f"the live posture could not be resolved ({type(exc).__name__}: {exc})", exc)
            return None
        digest = posture_digest(posture)
        created_at = f"{int(self._clock() * 1_000_000_000)}"
        message = signed_message(
            digest=digest,
            created_at=created_at,
            key_id=getattr(self._signer, "key_id", ""),
            scheme=getattr(self._signer, "scheme", ""),
        )
        try:
            signature = self._signer.sign(message)
        except SignerUnavailable as exc:
            self._fail(f"the signer could not sign it ({exc})", exc)
            return None
        record = AttestationRecord(
            digest=digest,
            created_at=created_at,
            key_id=getattr(self._signer, "key_id", ""),
            scheme=getattr(self._signer, "scheme", ""),
            signature=signature,
        )
        try:
            self._target.publish(record)
        except AttestationUnavailable as exc:
            self._fail(f"it could not be published ({exc})", exc)
            return None
        except Exception as exc:  # noqa: BLE001 - the target is an external boundary
            # A target that fails in a way it did not declare still goes through
            # the same policy: fail-closed under the requirement, loud otherwise.
            # Letting an undeclared error type escape would make the decision
            # depend on which exception a target happened to raise.
            self._fail(f"it could not be published ({type(exc).__name__}: {exc})", exc)
            return None
        self._last_at = self._clock()
        self.last_digest = digest
        self._log.info(
            "config posture attested: digest=%s target=%s(external=%s) key=%s",
            digest,
            self._target.kind,
            self._target.external,
            record.key_id,
        )
        return record

    def attest_if_due(self, now: float | None = None) -> AttestationRecord | None:
        """The cadence, driven by the caller. Publishes when the interval has
        elapsed (and at the first call), otherwise does nothing."""

        moment = self._clock() if now is None else now
        if self._last_at is not None and moment - self._last_at < self._interval_s:
            return None
        return self.attest()


# ---------------------------------------------------------------------------
# Verifying
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttestationVerification:
    """The verdict. ``ok`` is True only for ATTESTED: a posture that could not
    be checked is never reported as one that was."""

    status: str
    detail: str
    live_digest: str | None = None
    published_digest: str | None = None
    key_id: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == ATTESTED

    def projection(self) -> dict[str, object]:
        """Machine-readable, and carrying no secret: a posture digest, a
        non-secret key id, and a status."""

        return {
            "status": self.status,
            "ok": self.ok,
            "detail": self.detail,
            "live_digest": self.live_digest,
            "published_digest": self.published_digest,
            "key_id": self.key_id,
        }


def verify_attestation(
    *,
    target: AttestationTarget,
    verifier: ApprovalSigner,
    resolve: Callable[[], ResolvedPosture],
) -> AttestationVerification:
    """Does the running posture match what was published, and was that signed?

    ``verifier`` holds a public key and no secret in production (PIH-2's
    :class:`PublicKeyVerifier`), so this can run on a host that could never mint
    an attestation of its own.

    * signature valid AND digest equals the live resolved posture → ATTESTED
    * signature valid AND digest differs → MISMATCH, the silent-downgrade catch
    * signature invalid, no readable record, or the live posture cannot be
      computed → NOT_VERIFIABLE, which is never ATTESTED
    """

    try:
        records = target.records()
    except AttestationUnavailable as exc:
        return AttestationVerification(NOT_VERIFIABLE, f"the published attestation could not be read: {exc}")
    except Exception as exc:  # noqa: BLE001 - the target is an external boundary
        return AttestationVerification(
            NOT_VERIFIABLE, f"the published attestation could not be read: {type(exc).__name__}: {exc}"
        )
    if not records:
        return AttestationVerification(NOT_VERIFIABLE, "no attestation has been published")
    record = records[-1]
    if not verifier.verify(record.message, record.signature):
        return AttestationVerification(
            NOT_VERIFIABLE,
            "the published attestation is not signed by the pinned key; it "
            "establishes nothing about the running posture",
            published_digest=record.digest,
            key_id=record.key_id,
        )
    try:
        live = posture_digest(resolve())
    except Exception as exc:  # noqa: BLE001 - resolution touches the whole host
        return AttestationVerification(
            NOT_VERIFIABLE,
            f"the live posture could not be resolved ({type(exc).__name__}: {exc}), "
            "so it cannot be compared with the signed one",
            published_digest=record.digest,
            key_id=record.key_id,
        )
    if live != record.digest:
        return AttestationVerification(
            MISMATCH,
            "the running security posture is NOT the one on the external record: "
            "a setting changed since it was attested",
            live_digest=live,
            published_digest=record.digest,
            key_id=record.key_id,
        )
    return AttestationVerification(
        ATTESTED,
        "the running security posture matches the signed external record",
        live_digest=live,
        published_digest=record.digest,
        key_id=record.key_id,
    )
