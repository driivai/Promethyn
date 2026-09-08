"""F11 retrospective signing reconciliation. Never execute, sign, or recover.

The four outcomes are about Sign evidence, NOT approval delivery or database
state. Trusted inputs include auditor pins and both history coverage assertions.
"""

from __future__ import annotations

import hashlib
import json
from bisect import bisect_left
from dataclasses import asdict, dataclass
from fractions import Fraction
from pathlib import Path
from typing import cast

from prometheus_protocol.chokepoint.audit_source import (
    AuditScope,
    Coverage,
    Interval,
    SignAuditSource,
    SignEvent,
    SignRead,
    nanoseconds,
    text_field,
)
from prometheus_protocol.chokepoint.authorization_record import (
    AuthorizationRecord,
    hex_bytes,
    read_time,
)
from prometheus_protocol.chokepoint.reconcile_gate import (
    AnchorReader,
    GateCheckpoint,
    read_gate,
)
from prometheus_protocol.core.validation import require_non_negative, require_positive

NS = 1_000_000_000
SOURCE_REASONS = frozenset(
    (
        "deadline",
        "late_reply",
        "page_unavailable_or_malformed",
        "malformed_event",
        "response_limit",
        "conflicting_event_id",
        "pagination_loop",
        "page_limit",
        "event_outside_query",
        "source_read_unavailable",
        "export_does_not_cover_query",
        "event_outside_export_query",
        "capability_unavailable",
    )
)
LIMITATIONS = (
    "Retrospective Sign evidence, not prevention, approval delivery, execution or human intent.",
    "Metadata-only sources cannot detect digest-bound forgery; no independent source exists for local HMAC.",
    "Gate completeness, source completeness, identity pins and the auditor must be independently trusted.",
    "Control of Sign and audit administration can erase unauthorized signing without a detectable gap.",
    "A compromised gate that appends dishonest authorised decisions can produce matching histories.",
    "No live provider adapter is validated by model or offline-export results.",
)


def _ceil(value: Fraction) -> int:
    return -(-value.numerator // value.denominator)


def _seconds(value: float) -> Fraction:
    return Fraction(value) * NS


@dataclass(frozen=True, slots=True)
class SettlingPolicy:
    # No guessed production clock bound or signing deadline.
    max_clock_skew_seconds: float
    sign_attempt_seconds: float
    record_ttl_seconds: float
    settle_seconds: float = 900

    def __post_init__(self) -> None:
        for name in (
            "max_clock_skew_seconds",
            "record_ttl_seconds",
            "settle_seconds",
            "sign_attempt_seconds",
        ):
            validate = (
                require_positive
                if name in ("settle_seconds", "sign_attempt_seconds")
                else require_non_negative
            )
            number = validate(getattr(self, name), name=name)
            nanoseconds(_ceil(_seconds(number)))
            object.__setattr__(self, name, number)

    @property
    def skew(self) -> int:
        return _ceil(_seconds(self.max_clock_skew_seconds))

    @property
    def lookback(self) -> int:
        return (
            _ceil(
                _seconds(self.record_ttl_seconds) + _seconds(self.sign_attempt_seconds)
            )
            + self.skew
        )

    @property
    def settling(self) -> int:
        return _ceil(_seconds(self.settle_seconds))


@dataclass(frozen=True, slots=True)
class KeyPin:
    """Auditor-owned one-to-one mapping, not values selected by a gate row."""

    approval_key_id: str
    backend: str
    gate_scope: str
    public_key_sha256: str | None
    caller_issuer: str
    caller_subject: str
    algorithm: str
    digest_location: str
    scheme: str = "ecdsa-p256-sha256"

    def __post_init__(self) -> None:
        for name in (
            "approval_key_id",
            "backend",
            "gate_scope",
            "caller_issuer",
            "caller_subject",
            "algorithm",
            "digest_location",
            "scheme",
        ):
            text_field(getattr(self, name))
        if self.backend not in ("model", "gcp-kms", "aws-kms", "pkcs11", "local-hmac"):
            raise ValueError("unknown key backend")
        if self.backend == "local-hmac":
            if self.public_key_sha256 is not None or self.scheme != "hmac-sha256":
                raise ValueError("invalid HMAC pin")
        else:
            hex_bytes(self.public_key_sha256, 32)
            if self.scheme != "ecdsa-p256-sha256":
                raise ValueError("unsupported pinned scheme")


def decision_window(record: AuthorizationRecord, policy: SettlingPolicy) -> Interval:
    value = record.to_dict()
    issued, expires = read_time(value["issued_at"]), read_time(value["expires_at"])
    if issued < 0:
        raise ValueError("negative issuance time")
    if Fraction(expires) - Fraction(issued) > Fraction(policy.record_ttl_seconds):
        raise ValueError("record TTL exceeds pinned bound")
    start = _seconds(issued) - policy.skew
    end = _seconds(expires) + _seconds(policy.sign_attempt_seconds) + policy.skew
    return Interval(max(0, start.numerator // start.denominator), _ceil(end))


def _contains(outer: Interval, inner: Interval) -> bool:
    return outer.start <= inner.start and inner.end <= outer.end


def _reference(value: str | None) -> str | None:
    # Evidence references can be signed URLs or free-form adapter diagnostics.
    # Retain a lookup fingerprint, never blindly echo a bearer URL/exception.
    return (
        "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
        if value is not None
        else None
    )


def _coverage_report(coverage: Coverage) -> dict:
    result = asdict(coverage)
    result["completeness_evidence"] = _reference(coverage.completeness_evidence)
    for gap in result["gaps"]:
        reason = gap["reason"]
        if reason not in ("retention", "logging-disabled", "exclusion"):
            gap["reason"] = "source_gap"
            gap["evidence_reference"] = _reference(reason)
    return result


def _overlaps(a: Interval, b: Interval) -> bool:
    return a.start < b.end and b.start < a.end


def _identity(record: AuthorizationRecord, scope: AuditScope, pin: KeyPin) -> bool:
    value = record.to_dict()
    signer = value["signer"]
    return (
        signer
        == {
            "backend": pin.backend,
            "scope": pin.gate_scope,
            "key_resource": scope.key_resource,
            "public_key_sha256": pin.public_key_sha256,
            "caller_issuer": pin.caller_issuer,
            "caller_subject": pin.caller_subject,
        }
        and value["approval_key_id"] == pin.approval_key_id
        and value["scheme"] == pin.scheme
    )


def _compatible(
    event: SignEvent, record: AuthorizationRecord, window: Interval, pin: KeyPin
) -> bool:
    return (
        record.to_dict()["decision"] == "authorised"
        and event.digest.provenance == "observed"
        and event.digest.location == pin.digest_location
        and event.digest.value is not None
        and event.digest.value.hex() == record.recompute_approval_digest()
        and event.caller.issuer == pin.caller_issuer
        and event.caller.subject == pin.caller_subject
        and event.algorithm == pin.algorithm
        and window.start <= event.signed_at < window.end
    )


def _coverage_ok(source: SignRead, interval: Interval, now: int) -> bool:
    c = source.coverage
    return (
        not source.issues
        and c.pages_exhausted
        and c.source_attested
        and c.observed_at <= now
        and c.covered is not None
        and _contains(c.covered, interval)
        and c.complete_through is not None
        and c.complete_through >= interval.end
        and not any(_overlaps(g.interval, interval) for g in c.gaps)
    )


def _checked_source(
    source: SignAuditSource, scope: AuditScope, interval: Interval, now: int
) -> SignRead:
    # A port implementation may not use 2b's collector. Enforce identity and
    # duplicate rules again at the consuming boundary, preserving useful rows.
    from prometheus_protocol.chokepoint.audit_source import SourceIssue

    try:
        result = source.read_sign_records(scope, interval.start, interval.end)
        if (
            type(result) is not SignRead
            or result.coverage.scope != scope
            or result.coverage.requested != interval
            or len(result.events) > 10_000
            or len(result.issues) > 10_000
        ):
            raise ValueError("wrong source query")
        unique: dict[str, SignEvent] = {}
        issues = list(result.issues)
        for event in result.events:
            if not interval.start <= event.signed_at < interval.end:
                issues.append(SourceIssue("event_outside_query"))
                continue
            if event.event_id in unique and unique[event.event_id] != event:
                issues.append(SourceIssue("conflicting_event_id"))
            unique[event.event_id] = event
        if len(unique) > 10_000:
            raise ValueError("source exceeds event bound")
        return SignRead(tuple(unique.values()), result.coverage, tuple(issues))
    except Exception:  # noqa: BLE001 - external reader exception cannot yield empty clean history
        return SignRead(
            (),
            Coverage(scope, interval, None, None, (), now, "metadata_only", None),
            (SourceIssue("source_read_unavailable"),),
        )


@dataclass(frozen=True, slots=True)
class ReconciliationReport:
    _json: str

    def to_dict(self) -> dict:
        return json.loads(self._json)

    @property
    def exit_code(self) -> int:
        return 0 if self.to_dict()["clean"] else 1


def reconcile(
    *,
    ledger_path: Path,
    checkpoint: GateCheckpoint,
    anchor: AnchorReader | None,
    source: SignAuditSource,
    scope: AuditScope,
    pin: KeyPin,
    requested: Interval,
    policy: SettlingPolicy,
    now: int,
) -> ReconciliationReport:
    """Only reads the 2a ledger and 2b source. Does not accept cached decisions."""
    nanoseconds(now)
    gate = read_gate(ledger_path, checkpoint, anchor)
    problems = list(gate.issues)
    if checkpoint.observed_at > now:
        problems.append("future_gate_checkpoint")
    if pin.backend == "local-hmac":
        problems.append("no_independent_sign_source")
    provider_backends = {
        "model-gcp": "model",
        "model-cloudtrail": "model",
        "aws-cloudtrail": "aws-kms",
        "gcp-audit": "gcp-kms",
        "pkcs11": "pkcs11",
    }
    if (
        pin.backend != "local-hmac"
        and provider_backends.get(scope.provider) != pin.backend
    ):
        problems.append("conflicting_identity_mapping")
    native_locations = {
        "gcp-audit": "protoPayload.request.digest.sha256:base64",
        "model-gcp": "model:service-observed-sign-input",
    }
    if (
        scope.provider in native_locations
        and pin.digest_location != native_locations[scope.provider]
    ):
        problems.append("unsupported_digest_provenance")
    selected: list[tuple[AuthorizationRecord, Interval]] = []
    refusals = []
    for record in gate.records:
        value = record.to_dict()
        signer = value["signer"]
        if value["decision"] == "refused":
            t = _seconds(read_time(value["recorded_at"]))
            if requested.start <= t < requested.end:
                refusals.append(
                    {
                        "authorization_id": record.authorization_id,
                        "decision": "refused",
                        "reason": value["reason"],
                        "forgery_signal": False,
                    }
                )
            continue
        # Pin conflicts for the same key or envelope ID cannot be filtered away.
        if (
            signer["key_resource"] != scope.key_resource
            and value["approval_key_id"] != pin.approval_key_id
        ):
            continue
        try:
            window = decision_window(record, policy)
            if _overlaps(window, requested):
                selected.append((record, window))
                if not _identity(record, scope, pin):
                    problems.append("conflicting_identity_mapping")
        except (TypeError, ValueError, OverflowError):
            problems.append("record_time_policy_invalid")
    extended = Interval(
        min([requested.start] + [w.start for _, w in selected]),
        max([requested.end] + [w.end for _, w in selected]),
    )
    try:
        required_gate = Interval(
            max(0, extended.start - policy.lookback),
            nanoseconds(extended.end + policy.skew),
        )
    except ValueError:
        required_gate = extended
        problems.append("gate_interval_overflow")
    if not _contains(checkpoint.covered, required_gate):
        problems.append("gate_coverage_incomplete")
    evidence = _checked_source(source, scope, extended, now)
    global_source_failure = bool(evidence.issues) or evidence.coverage.observed_at > now
    if global_source_failure:
        problems.append("source_incomplete")
    if evidence.coverage.capability != "digest_bound" or scope.provider in (
        "aws-cloudtrail",
        "model-cloudtrail",
    ):
        problems.append("metadata_only")
    if not _coverage_ok(evidence, extended, now):
        problems.append("source_coverage_incomplete")
    range_retry = requested.end + policy.settling
    if now < range_retry:
        problems.append("settling")
    fatal = not gate.ok or any(
        p in problems
        for p in (
            "future_gate_checkpoint",
            "no_independent_sign_source",
            "conflicting_identity_mapping",
            "record_time_policy_invalid",
            "gate_interval_overflow",
            "gate_coverage_incomplete",
            "source_incomplete",
            "metadata_only",
            "unsupported_digest_provenance",
        )
    )
    records = []
    events = []
    denied = []
    used: set[str] = set()
    by_digest: dict[str, list[tuple[AuthorizationRecord, Interval]]] = {}
    for record, window in selected:
        by_digest.setdefault(record.recompute_approval_digest(), []).append(
            (record, window)
        )
    uncertain_times = sorted(
        e.signed_at
        for e in evidence.events
        if e.outcome == "unknown"
        or (
            e.outcome == "success"
            and (
                e.capability != "digest_bound"
                or e.digest.location != pin.digest_location
            )
        )
    )
    lifecycle = dict(gate.lifecycle)
    # Stable allocation is accounting only; when identical sign inputs repeat,
    # the report explicitly declines to identify which attempt was malicious.
    for event in sorted(evidence.events, key=lambda e: (e.signed_at, e.event_id)):
        in_requested = requested.start <= event.signed_at < requested.end
        if not in_requested and (
            event.digest.value is None or event.digest.value.hex() not in by_digest
        ):
            continue
        row = {
            "event_id": event.event_id,
            "signed_at": event.signed_at,
            "outcome": event.outcome,
            "forgery_signal": False,
            "caller": asdict(event.caller),
            "algorithm": event.algorithm,
            "observed_digest_sha256": event.digest.value.hex()
            if event.digest.value is not None
            else None,
            "digest_provenance": event.digest.provenance,
            "digest_location": event.digest.location
            if event.digest.location == pin.digest_location
            else None,
        }
        if event.outcome == "denied":
            denied.append({**row, "reason": "sign_denied"})
            continue
        candidates = [
            (r, w)
            for r, w in by_digest.get(
                event.digest.value.hex() if event.digest.value is not None else "", []
            )
            if _compatible(event, r, w, pin)
        ]
        row["candidate_authorization_ids"] = [r.authorization_id for r, _ in candidates]
        successful = event.outcome == "success"
        event_interval = Interval(event.signed_at, event.signed_at + 1)
        affected = candidates[0][1] if candidates else event_interval
        retry = max(range_retry, affected.end + policy.settling)
        if (
            fatal
            or not successful
            or event.capability != "digest_bound"
            or event.digest.location != pin.digest_location
        ):
            row.update(
                status="INDETERMINATE",
                reason=(
                    "unknown_sign_outcome"
                    if not successful
                    else "insufficient_evidence"
                ),
            )
        elif now < retry:
            row.update(status="INDETERMINATE", reason="settling", retry_after=retry)
        elif not _coverage_ok(evidence, affected, now):
            row.update(status="INDETERMINATE", reason="source_coverage_incomplete")
        else:
            eligible = [r for r, _ in candidates if r.authorization_id not in used]
            if eligible:
                record = eligible[0]
                used.add(record.authorization_id)
                row.update(
                    status="MATCHED",
                    reason="independent_digest_match",
                    authorization_id=record.authorization_id,
                )
            else:
                row.update(
                    status="UNEXPLAINED",
                    reason="excess_sign_attempts"
                    if candidates
                    else "no_eligible_authorization",
                    forgery_signal=True,
                )
                if candidates:
                    row["attribution"] = (
                        "accounting_excess_not_identified_malicious_attempt"
                    )
        events.append(row)
    for record, window in selected:
        uncertain_index = bisect_left(uncertain_times, window.start)
        retry = max(range_retry, window.end + policy.settling)
        row = {
            "authorization_id": record.authorization_id,
            "record_hash": record.record_hash,
            "decision": "authorised",
            "forgery_signal": False,
            "required_interval": asdict(window),
            "sign_result": lifecycle.get(record.authorization_id, "absent"),
        }
        if fatal:
            row.update(status="INDETERMINATE", reason="insufficient_evidence")
        elif now < retry:
            row.update(status="INDETERMINATE", reason="settling", retry_after=retry)
        elif not _coverage_ok(evidence, window, now):
            row.update(status="INDETERMINATE", reason="source_coverage_incomplete")
        elif record.authorization_id in used:
            row.update(status="MATCHED", reason="independent_digest_match")
        elif (
            uncertain_index < len(uncertain_times)
            and uncertain_times[uncertain_index] < window.end
        ):
            row.update(status="INDETERMINATE", reason="insufficient_correlation")
        else:
            row.update(status="UNWITNESSED", reason="no_successful_sign_witness")
        records.append(row)
    counts = {
        s: sum(row["status"] == s for row in records + events)
        for s in ("MATCHED", "UNWITNESSED", "UNEXPLAINED", "INDETERMINATE")
    }
    clean = not problems and not any(
        counts[s] for s in ("UNWITNESSED", "UNEXPLAINED", "INDETERMINATE")
    )
    result = {
        "schema_version": 1,
        "clean": clean,
        "status": "CHECKED" if clean else "NON_CLEAN",
        "scope": asdict(scope),
        "requested": asdict(requested),
        "source_requested": asdict(extended),
        "settling_policy": asdict(policy),
        "observed_at": now,
        "retry_after": max(
            [range_retry]
            + [cast(int, r.get("retry_after", 0)) for r in records + events]
        )
        if "settling" in problems or any("retry_after" in r for r in records + events)
        else None,
        "gate_verification": {
            "chain": gate.chain,
            "anchor": gate.anchor,
            "integrity_failure": gate.integrity_failure,
            "checkpoint": {
                **asdict(checkpoint),
                "evidence": _reference(checkpoint.evidence),
            },
            "required_interval": asdict(required_gate),
            "issues": list(gate.issues),
        },
        "source_verification": {
            "state": evidence.state,
            "coverage": _coverage_report(evidence.coverage),
            "issues": [
                {
                    "reason": i.reason
                    if i.reason in SOURCE_REASONS
                    else "source_issue",
                    "page": i.page,
                    "row": i.row,
                }
                for i in evidence.issues
            ],
        },
        "records": records,
        "events": events,
        "refused_decisions": refusals,
        "denied_attempts": denied,
        "counts": counts,
        "record_counts": {s: sum(r["status"] == s for r in records) for s in counts},
        "event_counts": {s: sum(e["status"] == s for e in events) for s in counts},
        "record_count": len(records),
        "event_count": len(events),
        "denied_count": len(denied),
        "forgery_signal": any(e["forgery_signal"] for e in events),
        "problems": sorted(set(problems)),
        "limitations": list(LIMITATIONS),
    }
    # Explicit projection above: no arbitrary ledger/source payload, signature,
    # nonce, signed envelope, artifact content or exception text is serialized.
    return ReconciliationReport(json.dumps(result, sort_keys=True, allow_nan=False))
