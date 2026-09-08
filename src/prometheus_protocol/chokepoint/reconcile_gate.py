"""Read-only, anchored disk snapshots for F11. No issuance or recovery API.

The checkpoint is supplied by the independent auditor, NOT derived from a
ledger timestamp. It attests complete gate history for an interval at an exact
tip. A chain alone cannot make that assertion. Trust/retention remains external.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from prometheus_protocol.chokepoint.audit_source import (
    Interval,
    nanoseconds,
    text_field,
)
from prometheus_protocol.chokepoint.authorization_journal import AuthorizationJournal
from prometheus_protocol.chokepoint.authorization_record import (
    SIGN_RESULT_EVENT,
    AuthorizationRecord,
    binding_preimage,
    hex_bytes,
    strict_json,
)
from prometheus_protocol.ledger.audit_chain import ChainTip, verify_rows


class AnchorReader(Protocol):
    """Read capability only; no write method is requested by this consumer."""

    def history(self) -> list[ChainTip]: ...


@dataclass(frozen=True, slots=True)
class GateCheckpoint:
    ledger_id: str
    tip: ChainTip
    covered: Interval
    observed_at: int
    evidence: str

    def __post_init__(self) -> None:
        hex_bytes(self.ledger_id, 32)
        if (
            type(self.tip) is not ChainTip
            or type(self.tip.seq) is not int
            or self.tip.seq < 1
        ):
            raise ValueError("invalid gate checkpoint tip")
        hex_bytes(self.tip.entry_hash, 32)
        if type(self.covered) is not Interval or self.covered.end > nanoseconds(
            self.observed_at
        ):
            raise ValueError("invalid gate coverage")
        text_field(self.evidence)


@dataclass(frozen=True, slots=True)
class GateRead:
    records: tuple[AuthorizationRecord, ...]
    lifecycle: tuple[tuple[str, str], ...]
    checkpoint: GateCheckpoint
    chain: str
    anchor: str
    issues: tuple[str, ...]
    integrity_failure: bool = False

    @property
    def ok(self) -> bool:
        return self.chain == "valid" and self.anchor == "verified" and not self.issues


def _decode_rows(
    rows: list[dict],
) -> tuple[tuple[AuthorizationRecord, ...], tuple[tuple[str, str], ...]]:
    # Reuse the production 2a decoder, uniqueness and sign-result reference
    # checks. It reconstructs the preimage, approval digest AND record hash.
    records = tuple(AuthorizationJournal._decisions(rows))
    lifecycle = []
    for row in rows:
        if row["event"] == SIGN_RESULT_EVENT:
            payload = strict_json(row["payload"])
            lifecycle.append((row["subject"], payload["state"]))
        elif row["event"].startswith(("execute", "execution")):
            payload = strict_json(row["payload"])
            binding = payload.get("approval_binding")
            if binding is None:
                raise LookupError("missing legacy history")
            # Imported full bindings need not have a decision: an invoke-only
            # forged approval is precisely such a case. Never invent one here.
            binding_preimage(binding)
    return records, tuple(lifecycle)


def read_gate(
    path: Path, checkpoint: GateCheckpoint, anchor: AnchorReader | None
) -> GateRead:
    """One SQLite read transaction, raw chain+anchor BEFORE typed decoding.

    Bounds are refusal limits, not truncation. No SqliteLedger constructor:
    that constructor performs schema migrations. mode=ro never creates a DB;
    SQLite may require existing WAL/SHM access for a live database snapshot.
    """
    chain, anchor_state = "not_verified", "not_verified"
    connection = None
    try:
        connection = sqlite3.connect(
            path.absolute().as_uri() + "?mode=ro", uri=True, timeout=3
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        deadline = time.monotonic() + 3
        connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        connection.execute("BEGIN")
        schema = connection.execute(
            "SELECT type FROM sqlite_master WHERE name='audit_chain'"
        ).fetchone()
        if schema is None or schema[0] != "table":
            raise ValueError("missing audit table")
        count, size, largest = connection.execute(
            "SELECT count(*), coalesce(sum(n),0), coalesce(max(n),0) FROM "
            "(SELECT coalesce(length(CAST(payload AS BLOB)),0) + coalesce(length(CAST(created_at AS BLOB)),0) "
            "+ coalesce(length(CAST(event AS BLOB)),0) + coalesce(length(CAST(subject AS BLOB)),0) "
            "+ coalesce(length(CAST(prev_hash AS BLOB)),0) + coalesce(length(CAST(entry_hash AS BLOB)),0) "
            "AS n FROM audit_chain)"
        ).fetchone()
        if count > 100_000 or size > 64 * 1024 * 1024 or largest > 131_072:
            raise ValueError("gate snapshot exceeds bounds")
        rows = [
            dict(row)
            for row in connection.execute(
                "SELECT seq,created_at,event,subject,payload,prev_hash,entry_hash FROM audit_chain ORDER BY id"
            )
        ]
        if anchor is None:
            return GateRead(
                (), (), checkpoint, chain, "missing", ("anchor_unavailable",)
            )
        tips = anchor.history()
        if type(tips) is not list or not tips or len(tips) > 100_000:
            raise ValueError("missing/oversized anchor history")
        for tip in tips:
            if type(tip) is not ChainTip or type(tip.seq) is not int or tip.seq < 1:
                raise ValueError("invalid anchor tip")
            hex_bytes(tip.entry_hash, 32)
        verification = verify_rows(rows, expected_tips=[*tips, checkpoint.tip])
        chain = verification.status
        if not verification.ok:
            return GateRead(
                (), (), checkpoint, chain, "mismatch", ("gate_integrity_failure",), True
            )
        if (
            not rows
            or rows[0]["entry_hash"] != checkpoint.ledger_id
            or rows[-1]["seq"] != checkpoint.tip.seq
            or rows[-1]["entry_hash"] != checkpoint.tip.entry_hash
            or checkpoint.tip not in tips
        ):
            return GateRead(
                (), (), checkpoint, chain, "unanchored", ("gate_checkpoint_mismatch",)
            )
        anchor_state = "verified"
        try:
            records, lifecycle = _decode_rows(rows)
        except LookupError:
            return GateRead(
                (), (), checkpoint, chain, anchor_state, ("missing_legacy_history",)
            )
        except Exception:  # noqa: BLE001 - corrupt typed evidence never becomes an explanation
            return GateRead(
                (),
                (),
                checkpoint,
                chain,
                anchor_state,
                ("gate_integrity_failure",),
                True,
            )
        return GateRead(records, lifecycle, checkpoint, chain, anchor_state, ())
    except Exception:  # noqa: BLE001 - read boundary; never disclose SQLite/anchor exception text
        return GateRead(
            (), (), checkpoint, chain, anchor_state, ("gate_read_unavailable",)
        )
    finally:
        if connection is not None:
            connection.close()
