"""Finding model: every claim carries its evidence.

A finding without its enumerated search set is itself an unverified claim, and
this is a tool about unverified claims — so the model makes the evidence field
structurally mandatory, not a docstring convention.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

VOID = "VOID"
WARN = "WARN"
UNKNOWN = "UNKNOWN"

VERDICTS = (VOID, WARN, UNKNOWN)

#: Ordering for --fail-on thresholds (most severe first).
SEVERITY = {VOID: 3, WARN: 2, UNKNOWN: 1}


@dataclass
class Evidence:
    """What was searched and what was found. Mandatory on every finding."""

    summary: str
    searched: list[str] = field(default_factory=list)
    found: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"summary": self.summary, "searched": self.searched, "found": self.found}


@dataclass
class Finding:
    rule: str          # e.g. "R1a"
    vg_class: int      # 1..4
    verdict: str       # VOID | WARN | UNKNOWN
    guard: str         # what is guarded (file::name or path:line)
    mechanism: str     # how the guard is gated
    evidence: Evidence
    question: str      # the one question, answered
    fix: str
    id: str = ""       # assigned at render time: VG-<class>-<n>

    def fingerprint(self) -> str:
        """Stable identity for baselining: rule + guard + mechanism.

        Deliberately excludes line numbers and verdicts so a file edit above the
        guard, or a verdict downgrade, does not silently re-open an acknowledged
        finding under a new identity.
        """

        raw = f"{self.rule}|{self.guard}|{self.mechanism}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule": self.rule,
            "class": self.vg_class,
            "verdict": self.verdict,
            "guard": self.guard,
            "mechanism": self.mechanism,
            "evidence": self.evidence.to_dict(),
            "question": self.question,
            "fix": self.fix,
            "fingerprint": self.fingerprint(),
        }


@dataclass
class ScanResult:
    root: str
    findings: list[Finding]
    notes: list[str] = field(default_factory=list)  # scanner-level caveats

    def counts(self) -> dict:
        out = {v: 0 for v in VERDICTS}
        for f in self.findings:
            out[f.verdict] += 1
        return out

    def to_dict(self) -> dict:
        return {
            "voidguard": 1,
            "root": self.root,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
        }
