"""Read-only F11 operator command over independently obtained evidence exports.

The auditor owns config/pins. File hashes pin transfer bytes, NOT their origin
or completeness. The operator must authenticate both witnesses out-of-band.
No cloud SDK, credential, dynamic plugin loading, or live signing is used here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path

from prometheus_protocol.chokepoint.audit_source import (
    AuditScope,
    Caller,
    Coverage,
    CoverageGap,
    DigestEvidence,
    Interval,
    SignEvent,
    SignRead,
    SourceIssue,
)
from prometheus_protocol.chokepoint.authorization_record import (
    exact_fields,
    hex_bytes,
    strict_json,
)
from prometheus_protocol.chokepoint.reconcile_gate import GateCheckpoint
from prometheus_protocol.chokepoint.reconciliation import (
    KeyPin,
    SettlingPolicy,
    reconcile,
)
from prometheus_protocol.ledger.audit_chain import ChainTip


def _object(cls, value: object) -> dict:
    return dict(exact_fields(value, [f.name for f in fields(cls)]))


def _read(path: Path, maximum: int, expected_hash: str | None = None) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("evidence exceeds limit")
    if expected_hash is not None:
        hex_bytes(expected_hash, 32)
        if hashlib.sha256(raw).hexdigest() != expected_hash:
            raise ValueError("evidence transfer hash mismatch")
    return raw


def encode_source_export(read: SignRead) -> bytes:
    """Versioned NDJSON: one coverage/issues header, then one event per line.

    This is a transfer encoding of the 2b port, not an alternative audit source.
    It does not upgrade a capability or attest anything the reader did not.
    """
    header = {
        "version": 1,
        "coverage": asdict(read.coverage),
        "issues": [asdict(i) for i in read.issues],
    }
    lines = [json.dumps(header, sort_keys=True)]
    for event in read.events:
        value = asdict(event)
        value["digest"]["value"] = (
            event.digest.value.hex() if event.digest.value is not None else None
        )
        lines.append(json.dumps(value, sort_keys=True))
    return ("\n".join(lines) + "\n").encode("utf-8")


def decode_source_export(raw: bytes) -> SignRead:
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("source export exceeds limit")
    lines = raw.decode("utf-8").splitlines()
    if not 1 <= len(lines) <= 10_001 or any(not line for line in lines):
        raise ValueError("invalid export framing")
    header = exact_fields(strict_json(lines[0]), ("version", "coverage", "issues"))
    if type(header["version"]) is not int or header["version"] != 1:
        raise ValueError("unknown source export version")
    c = _object(Coverage, header["coverage"])
    c["scope"] = AuditScope(**_object(AuditScope, c["scope"]))
    c["requested"] = Interval(**_object(Interval, c["requested"]))
    if c["covered"] is not None:
        c["covered"] = Interval(**_object(Interval, c["covered"]))
    gaps = []
    for gap in c["gaps"]:
        g = _object(CoverageGap, gap)
        gaps.append(
            CoverageGap(Interval(**_object(Interval, g["interval"])), g["reason"])
        )
    c["gaps"] = tuple(gaps)
    events = []
    for line in lines[1:]:
        e = _object(SignEvent, strict_json(line))
        e["scope"] = AuditScope(**_object(AuditScope, e["scope"]))
        e["caller"] = Caller(**_object(Caller, e["caller"]))
        d = _object(DigestEvidence, e["digest"])
        if d["value"] is not None:
            d["value"] = hex_bytes(d["value"], 32)
        e["digest"] = DigestEvidence(**d)
        events.append(SignEvent(**e))
    return SignRead(
        tuple(events),
        Coverage(**c),
        tuple(SourceIssue(**_object(SourceIssue, i)) for i in header["issues"]),
    )


@dataclass(frozen=True, slots=True)
class ExportSource:
    read: SignRead

    def read_sign_records(self, scope: AuditScope, start: int, end: int) -> SignRead:
        query = Interval(start, end)
        c = self.read.coverage
        issues = list(self.read.issues)
        identities: dict[str, SignEvent] = {}
        for event in self.read.events:
            if event.event_id in identities and identities[event.event_id] != event:
                issues.append(SourceIssue("conflicting_event_id"))
            identities[event.event_id] = event
        if scope != c.scope:
            raise ValueError("export scope mismatch")
        if not c.requested.start <= start < end <= c.requested.end:
            issues.append(SourceIssue("export_does_not_cover_query"))

        def clip(interval):
            a, b = max(start, interval.start), min(end, interval.end)
            return Interval(a, b) if a < b else None

        gaps = []
        for gap in c.gaps:
            interval = clip(gap.interval)
            if interval is not None:
                gaps.append(CoverageGap(interval, gap.reason))
        coverage = replace(
            c,
            requested=query,
            covered=clip(c.covered) if c.covered else None,
            gaps=tuple(gaps),
        )
        # Validate BEFORE selection: an invalid original row cannot disappear
        # just because this particular subquery would have filtered it away.
        if any(
            not c.requested.start <= e.signed_at < c.requested.end
            for e in self.read.events
        ):
            issues.append(SourceIssue("event_outside_export_query"))
        return SignRead(
            tuple(e for e in self.read.events if start <= e.signed_at < end),
            coverage,
            tuple(issues),
        )


@dataclass(frozen=True, slots=True)
class ExportAnchor:
    tips: tuple[ChainTip, ...]

    def history(self) -> list[ChainTip]:
        return list(self.tips)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only F11 reconciliation; trusted independent exports required"
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--anchor-history", type=Path, required=True)
    parser.add_argument("--source-evidence", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        config = exact_fields(
            strict_json(_read(args.config, 65_536).decode("utf-8")),
            (
                "version",
                "scope",
                "key_pin",
                "policy",
                "requested",
                "gate_checkpoint",
                "anchor_sha256",
                "source_sha256",
            ),
        )
        if type(config["version"]) is not int or config["version"] != 1:
            raise ValueError("unsupported config version")
        hex_bytes(config["anchor_sha256"], 32)
        hex_bytes(config["source_sha256"], 32)
        checkpoint = _object(GateCheckpoint, config["gate_checkpoint"])
        checkpoint["tip"] = ChainTip(**_object(ChainTip, checkpoint["tip"]))
        checkpoint["covered"] = Interval(**_object(Interval, checkpoint["covered"]))
        anchor_raw = _read(
            args.anchor_history, 16 * 1024 * 1024, config["anchor_sha256"]
        )
        tips = tuple(
            ChainTip(**_object(ChainTip, strict_json(line)))
            for line in anchor_raw.decode("utf-8").splitlines()
        )
        source_raw = _read(
            args.source_evidence, 4 * 1024 * 1024, config["source_sha256"]
        )
        report = reconcile(
            ledger_path=args.ledger,
            checkpoint=GateCheckpoint(**checkpoint),
            anchor=ExportAnchor(tips),
            source=ExportSource(decode_source_export(source_raw)),
            scope=AuditScope(**_object(AuditScope, config["scope"])),
            pin=KeyPin(**_object(KeyPin, config["key_pin"])),
            policy=SettlingPolicy(**_object(SettlingPolicy, config["policy"])),
            requested=Interval(**_object(Interval, config["requested"])),
            now=time.time_ns(),
        )
        print(json.dumps(report.to_dict(), sort_keys=True, allow_nan=False))
        return report.exit_code
    except Exception:  # noqa: BLE001 - includes parser/I/O/dependency failures; never echo bearer data
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "clean": False,
                    "status": "INDETERMINATE",
                    "reason": "invalid_or_unreadable_evidence",
                    "forgery_signal": False,
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
