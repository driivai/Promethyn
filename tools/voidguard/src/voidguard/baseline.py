"""Baseline (ratchet) support: acknowledge existing findings, fail only on new.

Without this no repo with existing debt can adopt the scanner, and every repo
has existing debt.
"""

from __future__ import annotations

import json
from pathlib import Path

from .model import Finding


def load(path: str | Path) -> set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    data = json.loads(p.read_text(encoding="utf-8"))
    return set(data.get("fingerprints", []))


def save(path: str | Path, findings: list[Finding]) -> None:
    data = {
        "voidguard-baseline": 1,
        "comment": "acknowledged findings; the scanner fails only on NEW ones. "
                   "Each entry is sha256(rule|guard|mechanism)[:16].",
        "fingerprints": sorted({f.fingerprint() for f in findings}),
    }
    Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def split(findings: list[Finding], known: set[str]) -> tuple[list[Finding], int]:
    """(new_findings, suppressed_count)."""

    fresh = [f for f in findings if f.fingerprint() not in known]
    return fresh, len(findings) - len(fresh)
