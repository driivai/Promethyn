"""Conformance: routing verification through the bank changes no outcomes.

Wiring the verifier bank into the loop must be behaviour-preserving for the
existing single hard verifier: every task's pass/fail is identical to the raw
subprocess result, and the held-out pass rate is unchanged. ABSTAIN (an
infrastructure failure) counts as not-a-pass and never pollutes calibration.
"""

from __future__ import annotations

from prometheus_protocol._examples.python_functions import (
    build_benchmark,
    build_solution_book,
)
from prometheus_protocol.core.models import Evidence, Tier, Verdict
from prometheus_protocol.provider.mock import MockProvider
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.runner import SubprocessVerifier
from prometheus_protocol.verifier.trust import sample_count

SUBPROCESS_ID = "subprocess-tests"


def test_bank_mediated_verdict_matches_raw_pass_fail_per_task():
    benchmark = build_benchmark()
    provider = MockProvider(build_solution_book())
    verifier = SubprocessVerifier(memory_mb=0)
    bank = VerifierBank()
    bank.register(verifier.verifier_id, verifier.tier)

    saw_pass = saw_fail = False
    for task in benchmark.tasks:
        code = provider.propose_solution(
            prompt=task.prompt, entry_point=task.entry_point, skills=()
        )
        evidence = verifier.verify(code=code, task=task)
        judgment = bank.judge([evidence])
        # A lone hard verifier must not change the verdict.
        assert (judgment.verdict == Verdict.PASS) == evidence.passed
        saw_pass = saw_pass or evidence.passed
        saw_fail = saw_fail or not evidence.passed

    # The benchmark exercises both branches at baseline.
    assert saw_pass and saw_fail


def test_heldout_pass_rate_unchanged(orchestrator, benchmark):
    # Bank-mediated baseline still 40%, and one cycle still reaches 100%.
    assert orchestrator.baseline(benchmark.heldout).pass_rate == 0.4
    cycle = orchestrator.run_cycle(benchmark.train, benchmark.heldout, cycle=1)
    assert cycle.post_heldout_rate == 1.0


def test_abstain_is_not_a_pass_and_does_not_calibrate():
    bank = VerifierBank()
    bank.register(SUBPROCESS_ID, Tier.HARD)
    before = bank._store.get(SUBPROCESS_ID)

    abstain = Evidence(
        passed=False,
        total=1,
        passed_count=0,
        verifier_id=SUBPROCESS_ID,
        verdict=Verdict.ABSTAIN,
        tier=Tier.HARD,
    )
    judgment = bank.judge([abstain])

    assert judgment.verdict != Verdict.PASS
    after = bank._store.get(SUBPROCESS_ID)
    assert sample_count(after) == 0
    assert after == before  # trust untouched by an ABSTAIN


def test_judgment_is_deterministic_and_ignores_latency():
    def evidence(latency_ms: float) -> Evidence:
        return Evidence(
            passed=True,
            total=1,
            passed_count=1,
            verifier_id=SUBPROCESS_ID,
            verdict=Verdict.PASS,
            tier=Tier.HARD,
            cost=latency_ms / 1000.0,
            latency_ms=latency_ms,
        )

    def judge(latency_ms: float):
        bank = VerifierBank()
        bank.register(SUBPROCESS_ID, Tier.HARD)
        return bank.judge([evidence(latency_ms)])

    # Identical inputs -> identical judgment; latency does not affect it.
    assert judge(5.0) == judge(5.0)
    assert judge(5.0) == judge(5000.0)
