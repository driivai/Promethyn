"""Faithful *semantics* model: no cloud SDK, no deployed-cloud claim.

The factory is trusted test-harness authority. Hand out separate capability
objects, never the factory: signer, read-only reader, audit administrator.
Python object privacy is NOT a process/security boundary against introspection.
The metadata-only medium never stores a digest or signature in its history.
"""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Literal

from prometheus_protocol.chokepoint.audit_normalization import decode_json, fields
from prometheus_protocol.chokepoint.audit_source import (
    ABSENT_DIGEST,
    DEFAULT_READ_LIMITS,
    AuditPage,
    AuditScope,
    Caller,
    Capability,
    Coverage,
    CoverageGap,
    DigestEvidence,
    Interval,
    ReadLimits,
    SignEvent,
    SignRead,
    collect_sign_records,
    nanoseconds,
    text_field,
)
from prometheus_protocol.chokepoint.signer import (
    KmsAccessDenied,
    KmsError,
    KmsTimeout,
    _crypto,
)


class ModelClock:
    def __init__(self, now_ns: int) -> None:
        self._now = nanoseconds(now_ns)

    def now_ns(self) -> int:
        return self._now

    def advance(self, duration_ns: int) -> None:
        self._now = nanoseconds(self._now + nanoseconds(duration_ns))


def _encode(event: SignEvent) -> bytes:
    return json.dumps(
        {
            "scope": asdict(event.scope),
            "event_id": event.event_id,
            "caller": asdict(event.caller),
            "signed_at": event.signed_at,
            "outcome": event.outcome,
            "algorithm": event.algorithm,
            "digest": None if event.digest.value is None else event.digest.value.hex(),
            "provenance": event.digest.provenance,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def normalize_model_event(
    raw: bytes, scope: AuditScope, profile: Capability
) -> SignEvent:
    d = fields(
        decode_json(raw),
        {
            "scope",
            "event_id",
            "caller",
            "signed_at",
            "outcome",
            "algorithm",
            "digest",
            "provenance",
        },
    )
    if d["scope"] != asdict(scope):
        raise ValueError("model scope mismatch")
    caller = fields(d["caller"], {"issuer", "subject"})
    if profile == "metadata_only":
        if d["digest"] is not None or d["provenance"] != "absent":
            raise ValueError("metadata-only model cannot expose a digest")
        digest = ABSENT_DIGEST
    else:
        if type(d["digest"]) is not str or len(d["digest"]) != 64:
            raise ValueError("model digest absent/invalid")
        value = bytes.fromhex(d["digest"])
        if value.hex() != d["digest"]:
            raise ValueError("noncanonical model digest")
        digest = DigestEvidence(
            value, d["provenance"], "model:service-observed-sign-input"
        )
    return SignEvent(
        scope,
        d["event_id"],
        Caller(**caller),
        d["signed_at"],
        d["outcome"],
        d["algorithm"],
        "model:fixed-P256-key",
        digest,
    )


@dataclass(frozen=True, slots=True)
class ModelSigner:
    _sign: Callable[[str, bytes, str], bytes]
    _public_key: Callable[[str], bytes]

    def sign(self, key_id: str, digest: bytes, *, principal: str) -> bytes:
        return self._sign(key_id, digest, principal)

    def get_public_key(self, key_id: str) -> bytes:
        return self._public_key(key_id)


@dataclass(frozen=True, slots=True)
class ModelAuditReader:
    _read: Callable[[AuditScope, int, int], SignRead]

    def read_sign_records(self, scope: AuditScope, start: int, end: int) -> SignRead:
        return self._read(scope, start, end)


@dataclass(frozen=True, slots=True)
class Delivery:
    raw: bytes
    signed_at: int
    delivered_at: int
    event_id: str

    def __post_init__(self) -> None:
        if type(self.raw) is not bytes:
            raise ValueError("mutable delivery")
        if nanoseconds(self.delivered_at) < nanoseconds(self.signed_at):
            raise ValueError("delivery precedes sign")
        text_field(self.event_id)


@dataclass(frozen=True, slots=True)
class ModelFaults:
    delivery_delay_ns: int = 0
    read_reply_delay_ns: int = 0
    sign_reply_delay_ns: int = 0
    lose_sign_reply: bool = False
    reader_unavailable: bool = False
    omit_page: int | None = None

    def __post_init__(self) -> None:
        for value in (
            self.delivery_delay_ns,
            self.read_reply_delay_ns,
            self.sign_reply_delay_ns,
        ):
            nanoseconds(value)
        if (
            type(self.lose_sign_reply) is not bool
            or type(self.reader_unavailable) is not bool
        ):
            raise ValueError("invalid fault flag")
        if self.omit_page is not None:
            nanoseconds(self.omit_page)


class _Medium:
    def __init__(
        self,
        scope: AuditScope,
        profile: Capability,
        clock: ModelClock,
        invoke: tuple[str, ...],
    ):
        self.scope, self.profile, self.clock, self.invoke = (
            scope,
            profile,
            clock,
            frozenset(invoke),
        )
        self.lock = threading.RLock()
        self.history: list[Delivery] = []
        self.retention_start = 0
        self.gaps: tuple[CoverageGap, ...] = ()
        self.frontier_override: int | None = None
        self.attest = True
        self.faults = ModelFaults()
        _, hashes, serialization, ec, Prehashed, _, _ = _crypto()
        private = ec.generate_private_key(ec.SECP256R1())
        self.seal: Callable[[bytes], bytes] = lambda digest: private.sign(
            digest, ec.ECDSA(Prehashed(hashes.SHA256()))
        )
        self.public = private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign(self, key: str, digest: bytes, claimed: str, authenticated: str) -> bytes:
        if key != self.scope.key_resource or claimed != authenticated:
            raise KmsAccessDenied("caller/key outside bound signing capability")
        if type(digest) is not bytes or len(digest) != 32:
            raise KmsError("expected 32-byte digest")
        with self.lock:
            signed_at = self.clock.now_ns()
            allowed = authenticated in self.invoke
            signature = self.seal(digest) if allowed else b""
            evidence = (
                DigestEvidence(digest, "observed", "model:service-observed-sign-input")
                if self.profile == "digest_bound"
                else ABSENT_DIGEST
            )
            event = SignEvent(
                self.scope,
                str(uuid.uuid4()),
                Caller(self.scope.domain, authenticated),
                signed_at,
                "success" if allowed else "denied",
                "ECDSA_SHA_256",
                "model:fixed-P256-key",
                evidence,
            )
            self.history.append(
                Delivery(
                    _encode(event),
                    signed_at,
                    nanoseconds(signed_at + self.faults.delivery_delay_ns),
                    event.event_id,
                )
            )
            if not allowed:
                raise KmsAccessDenied("Sign permission denied")
            self.clock.advance(self.faults.sign_reply_delay_ns)
            if self.faults.lose_sign_reply:
                raise KmsTimeout("successful Sign reply lost")
            return signature

    def public_key(self, key: str) -> bytes:
        if key != self.scope.key_resource:
            raise KmsAccessDenied("key outside bound signing capability")
        return self.public

    def read(
        self,
        scope: AuditScope,
        start: int,
        end: int,
        page_size: int,
        limits: ReadLimits,
    ) -> SignRead:
        requested = Interval(start, end)
        with self.lock:
            now = self.clock.now_ns()
            faults = self.faults
            gaps = []
            if start < min(end, self.retention_start):
                gaps.append(
                    CoverageGap(
                        Interval(start, min(end, self.retention_start)), "retention"
                    )
                )
            for gap in self.gaps:
                a, b = max(start, gap.interval.start), min(end, gap.interval.end)
                if a < b:
                    gaps.append(CoverageGap(Interval(a, b), gap.reason))
            eligible = tuple(
                d
                for d in self.history
                if max(start, self.retention_start) <= d.signed_at < end
            )
            visible = tuple(
                d.raw
                for d in eligible
                if d.delivered_at <= now
                and not any(
                    g.interval.start <= d.signed_at < g.interval.end for g in gaps
                )
            )
            frontier = min(
                [now]
                + [d.signed_at for d in eligible if d.delivered_at > now]
                + [g.interval.start for g in gaps]
            )
            if self.frontier_override is not None:
                frontier = self.frontier_override
            a, b = max(start, self.retention_start), min(end, now)
            coverage = Coverage(
                scope,
                requested,
                Interval(a, b) if a < b else None,
                frontier if self.attest else None,
                tuple(gaps),
                now,
                self.profile,
                "model:source-completeness-assertion" if self.attest else None,
            )
            snapshot = str(uuid.uuid4())

        class Pages:
            def read_page(_self, requested_scope, interval, token, deadline_ns):
                if (
                    faults.reader_unavailable
                    or scope != self.scope
                    or requested_scope != scope
                    or interval != requested
                ):
                    raise OSError("model reader unavailable or out of scope")
                self.clock.advance(faults.read_reply_delay_ns)
                index = 0 if token is None else int(token)
                if faults.omit_page == index:
                    index += 1
                offset = index * page_size
                next_token = (
                    str(index + 1) if offset + page_size < len(visible) else None
                )
                return AuditPage(
                    visible[offset : offset + page_size],
                    next_token,
                    index,
                    snapshot,
                    coverage,
                )

        return collect_sign_records(
            Pages(),
            lambda raw, s: normalize_model_event(raw, s, self.profile),
            scope,
            start,
            end,
            capability=self.profile,
            observed_at=now,
            limits=limits,
            monotonic_ns=self.clock.now_ns,
        )


@dataclass(frozen=True, slots=True)
class ModelAuditAdministrator:
    """History AND assertions are mutable for this adversary, not for Sign."""

    _medium: _Medium

    def history(self) -> tuple[Delivery, ...]:
        with self._medium.lock:
            return tuple(self._medium.history)

    def configure_faults(self, faults: ModelFaults) -> None:
        if type(faults) is not ModelFaults:
            raise ValueError("invalid faults")
        with self._medium.lock:
            self._medium.faults = faults

    def set_coverage(
        self,
        *,
        retention_start: int = 0,
        gaps: tuple[CoverageGap, ...] = (),
        complete_through: int | None = None,
        attest: bool = True,
    ) -> None:
        nanoseconds(retention_start)
        if (
            type(gaps) is not tuple
            or any(type(g) is not CoverageGap for g in gaps)
            or type(attest) is not bool
        ):
            raise ValueError("invalid coverage configuration")
        if complete_through is not None:
            nanoseconds(complete_through)
        with self._medium.lock:
            self._medium.retention_start, self._medium.gaps = retention_start, gaps
            self._medium.frontier_override, self._medium.attest = (
                complete_through,
                attest,
            )

    def replace_history(self, deliveries: tuple[Delivery, ...]) -> None:
        if type(deliveries) is not tuple or any(
            type(d) is not Delivery for d in deliveries
        ):
            raise ValueError("invalid replacement history")
        with self._medium.lock:
            # Raw malformed/injected records may enter the adversarial medium;
            # the reader must reject them, not make them binding evidence.
            self._medium.history = list(deliveries)

    def duplicate_delivery(self, event_id: str) -> None:
        with self._medium.lock:
            delivery = next(d for d in self._medium.history if d.event_id == event_id)
            self._medium.history.append(delivery)


class MemorySignAudit:
    """Trusted harness factory, not a capability handed to the adversary."""

    def __init__(
        self,
        scope: AuditScope,
        *,
        profile: Literal["gcp_shaped", "cloudtrail_shaped"],
        clock: ModelClock,
        signing_principals: tuple[str, ...] = ("runner",),
    ) -> None:
        if profile not in ("gcp_shaped", "cloudtrail_shaped"):
            raise ValueError("unknown model profile")
        expected_provider = (
            "model-gcp" if profile == "gcp_shaped" else "model-cloudtrail"
        )
        if scope.provider != expected_provider:
            raise ValueError("model must not impersonate a deployed provider")
        self._medium = _Medium(
            scope,
            "digest_bound" if profile == "gcp_shaped" else "metadata_only",
            clock,
            signing_principals,
        )

    def signer(self, authenticated_principal: str = "runner") -> ModelSigner:
        text_field(authenticated_principal)
        medium = self._medium
        return ModelSigner(
            lambda key, digest, claimed: medium.sign(
                key, digest, claimed, authenticated_principal
            ),
            medium.public_key,
        )

    def reader(
        self, *, page_size: int = 100, limits: ReadLimits = DEFAULT_READ_LIMITS
    ) -> ModelAuditReader:
        if type(page_size) is not int or not 1 <= page_size <= 1000:
            raise ValueError("invalid page size")
        return ModelAuditReader(
            lambda scope, start, end: self._medium.read(
                scope, start, end, page_size, limits
            )
        )

    def administrator(self) -> ModelAuditAdministrator:
        return ModelAuditAdministrator(self._medium)
