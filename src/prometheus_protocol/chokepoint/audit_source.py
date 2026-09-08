"""Read-only signing-history input, NOT a reconciler or an authenticity oracle.

Intervals are half-open UTC epoch nanoseconds. Exhausting pages is separate
from a source's completeness assertion. Assertions are evidence supplied by
the source, not facts independently established by this library.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Literal, Protocol

Capability = Literal["digest_bound", "metadata_only"]
Outcome = Literal["success", "denied", "unknown"]
MAX_RECORD_BYTES = 65_536


def text_field(value: object) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 4096:
        raise ValueError("invalid text field")
    if any(ord(c) < 32 for c in value):
        raise ValueError("control character in text field")
    return value


def nanoseconds(value: object) -> int:
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ValueError("expected nonnegative signed-64-bit nanoseconds")
    return value


def capability_field(value: object) -> Capability:
    if value == "digest_bound":
        return "digest_bound"
    if value == "metadata_only":
        return "metadata_only"
    raise ValueError("unknown capability")


@dataclass(frozen=True, slots=True)
class Interval:
    start: int
    end: int

    def __post_init__(self) -> None:
        if nanoseconds(self.start) >= nanoseconds(self.end):
            raise ValueError("interval must be nonempty")


@dataclass(frozen=True, slots=True)
class AuditScope:
    provider: str
    source_id: str
    domain: str
    region: str
    key_resource: str

    def __post_init__(self) -> None:
        for value in (
            self.provider,
            self.source_id,
            self.domain,
            self.region,
            self.key_resource,
        ):
            text_field(value)


@dataclass(frozen=True, slots=True)
class Caller:
    issuer: str
    subject: str

    def __post_init__(self) -> None:
        text_field(self.issuer)
        text_field(self.subject)


@dataclass(frozen=True, slots=True)
class DigestEvidence:
    value: bytes | None
    provenance: Literal["observed", "absent"]
    location: str | None

    def __post_init__(self) -> None:
        if self.value is None:
            if self.provenance != "absent" or self.location is not None:
                raise ValueError("absent digest cannot carry an inferred binding")
        elif (
            type(self.value) is not bytes
            or len(self.value) != 32
            or self.provenance != "observed"
            or self.location is None
        ):
            raise ValueError("digest requires 32 observed bytes and provenance")
        else:
            text_field(self.location)

    @property
    def capability(self) -> Capability:
        return "metadata_only" if self.value is None else "digest_bound"


ABSENT_DIGEST = DigestEvidence(None, "absent", None)


@dataclass(frozen=True, slots=True)
class SignEvent:
    scope: AuditScope
    event_id: str
    caller: Caller
    signed_at: int
    outcome: Outcome
    algorithm: str
    algorithm_provenance: str
    digest: DigestEvidence
    request_id: str | None = None
    message_type: str | None = None

    def __post_init__(self) -> None:
        if type(self.scope) is not AuditScope or type(self.caller) is not Caller:
            raise ValueError("invalid event identity")
        if type(self.digest) is not DigestEvidence:
            raise ValueError("invalid digest evidence")
        text_field(self.event_id)
        nanoseconds(self.signed_at)
        if self.outcome not in ("success", "denied", "unknown"):
            raise ValueError("unknown sign outcome")
        text_field(self.algorithm)
        text_field(self.algorithm_provenance)
        for value in (self.request_id, self.message_type):
            if value is not None:
                text_field(value)

    @property
    def capability(self) -> Capability:
        return self.digest.capability


@dataclass(frozen=True, slots=True)
class CoverageGap:
    interval: Interval
    reason: str

    def __post_init__(self) -> None:
        if type(self.interval) is not Interval:
            raise ValueError("invalid gap interval")
        text_field(self.reason)


@dataclass(frozen=True, slots=True)
class Coverage:
    scope: AuditScope
    requested: Interval
    covered: Interval | None
    complete_through: int | None
    gaps: tuple[CoverageGap, ...]
    observed_at: int
    capability: Capability
    # Nonempty only when the SOURCE asserts completeness, with a named basis.
    # Native AWS/GCP page responses alone MUST leave this absent.
    completeness_evidence: str | None
    pages_exhausted: bool = False

    def __post_init__(self) -> None:
        if type(self.scope) is not AuditScope or type(self.requested) is not Interval:
            raise ValueError("invalid coverage scope/interval")
        nanoseconds(self.observed_at)
        capability_field(self.capability)
        if type(self.pages_exhausted) is not bool or type(self.gaps) is not tuple:
            raise ValueError("mutable/invalid coverage")
        if self.covered is not None and (
            type(self.covered) is not Interval
            or not (
                self.requested.start
                <= self.covered.start
                < self.covered.end
                <= min(self.requested.end, self.observed_at)
            )
        ):
            raise ValueError("covered interval exceeds query or observation")
        for gap in self.gaps:
            if type(gap) is not CoverageGap or not (
                self.requested.start
                <= gap.interval.start
                < gap.interval.end
                <= self.requested.end
            ):
                raise ValueError("gap outside query")
        if self.completeness_evidence is not None:
            text_field(self.completeness_evidence)
        if self.complete_through is not None:
            nanoseconds(self.complete_through)
            if (
                self.completeness_evidence is None
                or self.complete_through > self.observed_at
            ):
                raise ValueError("unattested/future completeness frontier")

    @property
    def source_attested(self) -> bool:
        return self.completeness_evidence is not None


@dataclass(frozen=True, slots=True)
class SourceIssue:
    reason: str
    page: int | None = None
    row: int | None = None

    def __post_init__(self) -> None:
        text_field(self.reason)
        for value in (self.page, self.row):
            if value is not None:
                nanoseconds(value)


@dataclass(frozen=True, slots=True)
class SignRead:
    events: tuple[SignEvent, ...]
    coverage: Coverage
    issues: tuple[SourceIssue, ...] = ()

    def __post_init__(self) -> None:
        if type(self.events) is not tuple or type(self.issues) is not tuple:
            raise ValueError("read results must be immutable")
        if type(self.coverage) is not Coverage:
            raise ValueError("invalid coverage")
        if any(
            type(e) is not SignEvent or e.scope != self.coverage.scope
            for e in self.events
        ):
            raise ValueError("event outside read scope")
        if any(type(i) is not SourceIssue for i in self.issues):
            raise ValueError("invalid source issue")
        if self.coverage.capability == "metadata_only" and any(
            e.digest.value is not None for e in self.events
        ):
            raise ValueError("metadata-only source cannot yield a digest")

    @property
    def state(self) -> Literal["complete", "incomplete", "unusable"]:
        """Input completeness only; never an authorization/reconciliation verdict."""
        if any(i.reason == "conflicting_event_id" for i in self.issues):
            return "unusable"
        c = self.coverage
        if (
            self.issues
            or not c.pages_exhausted
            or not c.source_attested
            or c.covered != c.requested
            or c.gaps
            or c.complete_through is None
            or c.complete_through < c.requested.end
        ):
            return "incomplete"
        return "complete"


class SignAuditSource(Protocol):
    def read_sign_records(self, scope: AuditScope, start: int, end: int) -> SignRead:
        """Read normalized events and coverage. No mutation operations."""


@dataclass(frozen=True, slots=True)
class AuditPage:
    records: tuple[bytes, ...]
    next_token: str | None
    ordinal: int
    snapshot_id: str
    coverage: Coverage


class PageSource(Protocol):
    def read_page(
        self, scope: AuditScope, interval: Interval, token: str | None, deadline_ns: int
    ) -> AuditPage:
        """Adapter must honor the absolute monotonic deadline, including I/O.

        The collector rejects late replies but cannot preempt a blocked adapter.
        Native page metadata does not itself constitute a completeness witness.
        """


@dataclass(frozen=True, slots=True)
class ReadLimits:
    pages: int = 64
    records: int = 10_000
    bytes: int = 4 * 1024 * 1024
    duration_ns: int = 3_000_000_000

    def __post_init__(self) -> None:
        for value in (self.pages, self.records, self.bytes, self.duration_ns):
            if nanoseconds(value) == 0:
                raise ValueError("limits must be positive")
        if self.pages > 1024 or self.records > 100_000 or self.bytes > 64 * 1024 * 1024:
            raise ValueError("read limits exceed hard ceiling")


DEFAULT_READ_LIMITS = ReadLimits()
Normalizer = Callable[[bytes, AuditScope], SignEvent]


@dataclass(frozen=True, slots=True)
class PagedSignAuditSource:
    """Read-only composition for a separately provided, deadline-bound adapter."""

    pages: PageSource
    normalize: Normalizer
    capability: Capability
    limits: ReadLimits = DEFAULT_READ_LIMITS
    utc_ns: Callable[[], int] = time.time_ns
    monotonic_ns: Callable[[], int] = time.monotonic_ns

    def read_sign_records(self, scope: AuditScope, start: int, end: int) -> SignRead:
        return collect_sign_records(
            self.pages,
            self.normalize,
            scope,
            start,
            end,
            capability=self.capability,
            observed_at=self.utc_ns(),
            limits=self.limits,
            monotonic_ns=self.monotonic_ns,
        )


def collect_sign_records(
    source: PageSource,
    normalize: Normalizer,
    scope: AuditScope,
    start: int,
    end: int,
    *,
    capability: Capability,
    observed_at: int,
    limits: ReadLimits = DEFAULT_READ_LIMITS,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
) -> SignRead:
    """Bounded all-page reader. Errors retain diagnostics, never shorten silently.

    The adapter is trusted to describe its scope/sequence honestly. A source
    administrator rewriting history AND its assertions can still conceal it.
    """
    interval = Interval(start, end)
    coverage = Coverage(scope, interval, None, None, (), observed_at, capability, None)
    events: dict[str, SignEvent] = {}
    issues: list[SourceIssue] = []
    token: str | None = None
    tokens: set[str] = set()
    snapshot: str | None = None
    byte_count = row_count = 0
    deadline = nanoseconds(monotonic_ns()) + limits.duration_ns
    for ordinal in range(limits.pages):
        if monotonic_ns() >= deadline:
            issues.append(SourceIssue("deadline", ordinal))
            break
        try:
            page = source.read_page(scope, interval, token, deadline)
            if monotonic_ns() >= deadline:
                issues.append(SourceIssue("late_reply", ordinal))
                break
            if type(page) is not AuditPage or type(page.records) is not tuple:
                raise ValueError("invalid page")
            if type(page.ordinal) is not int or page.ordinal != ordinal:
                raise ValueError("missing/reordered page")
            text_field(page.snapshot_id)
            if page.next_token is not None:
                text_field(page.next_token)
            if type(page.coverage) is not Coverage or (
                page.coverage.scope != scope
                or page.coverage.requested != interval
                or page.coverage.capability != capability
                or page.coverage.pages_exhausted
                or page.coverage.observed_at > observed_at
            ):
                raise ValueError("invalid page coverage")
            if snapshot is None:
                snapshot, coverage = page.snapshot_id, page.coverage
            elif page.snapshot_id != snapshot or page.coverage != coverage:
                raise ValueError("incoherent pagination")
        except Exception:  # noqa: BLE001 - source boundary: failed read is incomplete
            issues.append(SourceIssue("page_unavailable_or_malformed", ordinal))
            break
        for row, raw in enumerate(page.records):
            row_count += 1
            if type(raw) is not bytes:
                issues.append(SourceIssue("malformed_event", ordinal, row))
                break
            byte_count += len(raw)
            if (
                len(raw) > MAX_RECORD_BYTES
                or byte_count > limits.bytes
                or row_count > limits.records
            ):
                issues.append(SourceIssue("response_limit", ordinal, row))
                break
            if monotonic_ns() >= deadline:
                issues.append(SourceIssue("deadline", ordinal, row))
                break
            try:
                event = normalize(raw, scope)
                if monotonic_ns() >= deadline:
                    issues.append(SourceIssue("deadline", ordinal, row))
                    break
                if type(event) is not SignEvent or event.scope != scope:
                    raise ValueError("normalizer changed scope")
                if (
                    not start <= event.signed_at < end
                    or event.signed_at > coverage.observed_at
                ):
                    raise ValueError("event outside interval")
                if capability == "metadata_only" and event.digest.value is not None:
                    raise ValueError("metadata-only digest injection")
                old = events.get(event.event_id)
                if old is not None and old != event:
                    issues.append(SourceIssue("conflicting_event_id", ordinal, row))
                    break
                events[event.event_id] = event
            except Exception:  # noqa: BLE001 - unparseable row is incomplete, never dropped
                issues.append(SourceIssue("malformed_event", ordinal, row))
                break
        if issues:
            break
        if page.next_token is None:
            coverage = replace(coverage, pages_exhausted=True)
            break
        if page.next_token in tokens:
            issues.append(SourceIssue("pagination_loop", ordinal))
            break
        tokens.add(page.next_token)
        token = page.next_token
    else:
        issues.append(SourceIssue("page_limit"))
    return SignRead(tuple(events.values()), coverage, tuple(issues))
