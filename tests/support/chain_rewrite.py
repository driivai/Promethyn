"""Rewrite one audit-chain entry and re-hash everything after it — the attack
the in-file chain cannot see without an external anchor.

Test support for the named limit in ``docs/ledger-integrity.md`` §"What this
DOES and DOES NOT protect against": an adversary who can rewrite EVERY row
recomputes a wholly self-consistent chain. The pending service's chain binding
inherits that limit exactly, and the passing test that records it needs the
rewrite to be real — every recomputed hash valid on its own terms — or the
"NOT detected" it asserts would be asserting nothing.
"""

from __future__ import annotations

from prometheus_protocol.ledger.audit_chain import canonical_json, entry_hash
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger


def rewrite_entry_and_rehash(ledger: SqliteLedger, *, seq: int, payload: dict) -> None:
    """Replace entry ``seq``'s payload and recompute its hash and every later
    entry's ``prev_hash``/``entry_hash``, so ``verify_chain()`` reads VALID."""

    rows = sorted(ledger.chained_events(), key=lambda row: row["seq"])
    prev_hash: str | None = None
    for row in rows:
        if row["seq"] < seq:
            prev_hash = row["entry_hash"]
            continue
        canonical = canonical_json(payload) if row["seq"] == seq else row["payload"]
        if prev_hash is None:
            prev_hash = row["prev_hash"]
        digest = entry_hash(
            seq=row["seq"],
            created_at=row["created_at"],
            event=row["event"],
            subject=row["subject"],
            payload_canonical=canonical,
            prev_hash=prev_hash,
        )
        ledger._conn.execute(
            "UPDATE audit_chain SET payload = ?, prev_hash = ?, entry_hash = ? WHERE seq = ?",
            (canonical, prev_hash, digest, row["seq"]),
        )
        prev_hash = digest
    ledger._conn.commit()
