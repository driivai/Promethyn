"""Run every rule; assign stable, ordered finding ids."""

from __future__ import annotations

from . import rules_class1, rules_class2, rules_class3, rules_class4
from .model import ScanResult
from .repo import Repo


def scan(root: str, *, schedule_probe=None) -> ScanResult:
    repo = Repo(root)
    findings = []
    findings.extend(rules_class1.scan(repo))
    findings.extend(rules_class2.scan(repo))
    findings.extend(rules_class3.scan(repo))
    findings.extend(rules_class4.scan(repo, schedule_probe=schedule_probe))

    findings.sort(key=lambda f: (f.vg_class, f.rule, f.guard, f.mechanism))
    counters = {1: 0, 2: 0, 3: 0, 4: 0}
    for f in findings:
        counters[f.vg_class] += 1
        f.id = f"VG-{f.vg_class}-{counters[f.vg_class]:03d}"
    return ScanResult(root=str(repo.root), findings=findings, notes=list(repo.notes))
