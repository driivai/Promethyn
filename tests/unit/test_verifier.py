"""Unit tests for the subprocess verifier."""

from __future__ import annotations

from prometheus_protocol.core.models import Case, Task, Tier, Verdict
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.runner import SubprocessVerifier


def _task(entry_point: str, cases, split: str = "train") -> Task:
    return Task(
        id=f"t/{entry_point}",
        entry_point=entry_point,
        prompt="x",
        split=split,
        cases=tuple(cases),
    )


def test_passing_solution():
    verifier = SubprocessVerifier(memory_mb=0)
    task = _task("inc", [Case(args=(1,), expected=2), Case(args=(5,), expected=6)])
    evidence = verifier.verify(code="def inc(n):\n    return n + 1\n", task=task)
    assert evidence.passed
    assert evidence.passed_count == 2
    assert evidence.total == 2


def test_wrong_output_fails():
    verifier = SubprocessVerifier(memory_mb=0)
    task = _task("inc", [Case(args=(1,), expected=2)])
    evidence = verifier.verify(code="def inc(n):\n    return n + 99\n", task=task)
    assert not evidence.passed
    assert evidence.passed_count == 0
    assert evidence.failures


def test_runtime_exception_is_a_failure_not_a_crash():
    verifier = SubprocessVerifier(memory_mb=0)
    task = _task("boom", [Case(args=([],), expected=1)])
    evidence = verifier.verify(code="def boom(xs):\n    return xs[0]\n", task=task)
    assert not evidence.passed
    assert any("IndexError" in f for f in evidence.failures)


def test_missing_entry_point_is_a_failure():
    verifier = SubprocessVerifier(memory_mb=0)
    task = _task("expected_name", [Case(args=(1,), expected=1)])
    evidence = verifier.verify(code="def other_name(n):\n    return n\n", task=task)
    assert not evidence.passed


def test_syntax_error_is_reported_as_import_error():
    verifier = SubprocessVerifier(memory_mb=0)
    task = _task("f", [Case(args=(1,), expected=1)])
    evidence = verifier.verify(code="def f(n)\n    return n\n", task=task)
    assert not evidence.passed
    assert any("import error" in f for f in evidence.failures)


def test_timeout_is_flagged():
    verifier = SubprocessVerifier(timeout_s=1.0, cpu_seconds=5, memory_mb=0)
    task = _task("spin", [Case(args=(1,), expected=1)])
    evidence = verifier.verify(
        code="def spin(n):\n    while True:\n        pass\n", task=task
    )
    assert not evidence.passed
    assert evidence.timed_out


def test_memory_limit_contains_a_large_allocation():
    # Generous enough to start the interpreter, far too small for the alloc.
    verifier = SubprocessVerifier(timeout_s=10.0, memory_mb=200)
    task = _task("hog", [Case(args=(1,), expected=1)])
    evidence = verifier.verify(
        code="def hog(n):\n    big = bytearray(400 * 1024 * 1024)\n    return len(big)\n",
        task=task,
    )
    assert not evidence.passed


# -- tier-tagged evidence ---------------------------------------------------


def test_emits_tier_tagged_evidence_on_pass():
    verifier = SubprocessVerifier(memory_mb=0)
    task = _task("inc", [Case(args=(1,), expected=2)])
    evidence = verifier.verify(code="def inc(n):\n    return n + 1\n", task=task)
    assert evidence.verdict == Verdict.PASS
    assert evidence.tier == Tier.HARD
    assert evidence.verifier_id == "subprocess-tests"
    assert evidence.latency_ms is not None and evidence.latency_ms >= 0.0


def test_emits_fail_verdict_when_tests_fail():
    verifier = SubprocessVerifier(memory_mb=0)
    task = _task("inc", [Case(args=(1,), expected=2)])
    evidence = verifier.verify(code="def inc(n):\n    return 0\n", task=task)
    assert evidence.verdict == Verdict.FAIL
    assert evidence.tier == Tier.HARD


def test_abstains_on_timeout():
    # An infrastructure failure (the check could not run) is ABSTAIN, not FAIL.
    verifier = SubprocessVerifier(timeout_s=1.0, cpu_seconds=5, memory_mb=0)
    task = _task("spin", [Case(args=(1,), expected=1)])
    evidence = verifier.verify(
        code="def spin(n):\n    while True:\n        pass\n", task=task
    )
    assert evidence.verdict == Verdict.ABSTAIN
    assert evidence.timed_out is True
    assert not evidence.passed


def test_bank_judges_runner_evidence_with_hard_confidence():
    verifier = SubprocessVerifier(memory_mb=0)
    bank = VerifierBank()
    bank.register(verifier.verifier_id, verifier.tier)

    task = _task("inc", [Case(args=(1,), expected=2)])
    passing = verifier.verify(code="def inc(n):\n    return n + 1\n", task=task)
    judgment = bank.judge([passing])
    assert judgment.verdict == passing.verdict == Verdict.PASS
    assert judgment.authoritative is True
    assert 0.90 < judgment.confidence < 1.0

    failing = verifier.verify(code="def inc(n):\n    return 0\n", task=task)
    fail_judgment = bank.judge([failing])
    assert fail_judgment.verdict == failing.verdict == Verdict.FAIL
    assert 0.90 < fail_judgment.confidence < 1.0
