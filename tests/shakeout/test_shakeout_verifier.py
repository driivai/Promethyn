"""Shakeout repro for F3 — RED BY DESIGN.

A task with no test cases cannot be verified, yet the runner returns FAIL (a
confident failure) rather than ABSTAIN. See ``docs/shakeout-report.md`` (F3).
"""

from __future__ import annotations

import pytest

from prometheus_protocol.core.models import Task, Verdict
from prometheus_protocol.verifier.runner import SubprocessVerifier


@pytest.mark.xfail(
    strict=True,
    reason="F3: an empty-cases task returns FAIL; 'cannot verify' should be "
    "ABSTAIN so it is not counted as a real failure or mined by the forge",
)
def test_empty_cases_task_abstains():
    task = Task(id="t/f", entry_point="f", prompt="x", split="train", cases=())
    evidence = SubprocessVerifier(memory_mb=0).verify(
        code="def f(x):\n    return x\n", task=task
    )
    assert evidence.verdict == Verdict.ABSTAIN
