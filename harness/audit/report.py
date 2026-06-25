"""Reconstruct an auditable summary from a ledger.

Auditability is a protocol invariant: from the ledger alone you can recover
what was attempted, what passed, and what was promoted. This module turns the
raw records into a compact summary.
"""

from __future__ import annotations

from prometheus_protocol.core.interfaces import Ledger


def audit_ledger(ledger: Ledger) -> dict:
    """Summarise attempts and promotions recorded in ``ledger``."""

    attempts = ledger.attempts()
    promotions = ledger.promotions()

    by_kind: dict[str, dict[str, int]] = {}
    for attempt in attempts:
        bucket = by_kind.setdefault(attempt["kind"], {"total": 0, "passed": 0})
        bucket["total"] += 1
        bucket["passed"] += int(attempt["passed"])

    return {
        "attempts": len(attempts),
        "promotions": [
            {
                "cycle": promotion["cycle"],
                "skill_id": promotion["skill_id"],
                "action": promotion["action"],
                "rate_before": promotion["rate_before"],
                "rate_after": promotion["rate_after"],
            }
            for promotion in promotions
        ],
        "by_kind": by_kind,
    }
