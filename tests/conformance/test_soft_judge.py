"""Conformance: the soft verifier reuses I6/I7 and stays behaviour-preserving.

A soft (model-judged) verdict never flips the authoritative hard verdict
(I6), an un-audited soft verifier carries ~zero weight until calibrated (I7),
and enabling the soft verifier changes confidence but never a pass/fail
outcome (parity). Constructed SOFT evidence mirrors what ``ModelJudgeVerifier``
emits (tier SOFT, verifier_id "model-judge").
"""

from __future__ import annotations

import pytest

from prometheus_protocol.core.models import Evidence, Tier, Verdict
from prometheus_protocol.verifier import trust
from prometheus_protocol.verifier.bank import VerifierBank

HARD = "subprocess-tests"
SOFT = "model-judge"


def ev(vid: str, verdict: Verdict, tier: Tier) -> Evidence:
    return Evidence(
        passed=(verdict == Verdict.PASS),
        total=1,
        passed_count=1 if verdict == Verdict.PASS else 0,
        verifier_id=vid,
        verdict=verdict,
        tier=tier,
    )


def _calibrated_soft_stats(rounds: int = 30) -> trust.TrustStats:
    bank = VerifierBank()
    bank.register(HARD, Tier.HARD)
    bank.register(SOFT, Tier.SOFT)
    for i in range(rounds):
        verdict = Verdict.PASS if i % 2 == 0 else Verdict.FAIL
        bank.judge([ev(HARD, verdict, Tier.HARD), ev(SOFT, verdict, Tier.SOFT)])
    return bank._store.get(SOFT)


def _bank_with_soft(stats: trust.TrustStats | None) -> VerifierBank:
    bank = VerifierBank()
    bank.register(HARD, Tier.HARD)
    if stats is None:
        bank.register(SOFT, Tier.SOFT)
    else:
        bank._store.put(SOFT, stats)
    return bank


# -- I6: authoritative dominance --------------------------------------------


def test_i6_soft_does_not_flip_hard_pass():
    judgment = VerifierBank().judge(
        [ev(HARD, Verdict.PASS, Tier.HARD), ev(SOFT, Verdict.FAIL, Tier.SOFT)]
    )
    assert judgment.verdict == Verdict.PASS
    assert judgment.authoritative is True
    assert judgment.contributing == (HARD,)


def test_i6_soft_does_not_flip_hard_fail():
    judgment = VerifierBank().judge(
        [ev(HARD, Verdict.FAIL, Tier.HARD), ev(SOFT, Verdict.PASS, Tier.SOFT)]
    )
    assert judgment.verdict == Verdict.FAIL
    assert judgment.authoritative is True


# -- I7: earned weight + informative confidence -----------------------------


def test_i7_unaudited_soft_moves_confidence_negligibly():
    hard_only = VerifierBank()
    hard_only.register(HARD, Tier.HARD)
    c_hard = hard_only.judge([ev(HARD, Verdict.PASS, Tier.HARD)]).confidence

    c_fresh = _bank_with_soft(None).judge(
        [ev(HARD, Verdict.PASS, Tier.HARD), ev(SOFT, Verdict.PASS, Tier.SOFT)]
    ).confidence
    assert c_fresh == pytest.approx(c_hard)


def test_calibrated_soft_makes_confidence_informative():
    stats = _calibrated_soft_stats()
    assert trust.youden(stats) > 0.8

    hard_only = VerifierBank()
    hard_only.register(HARD, Tier.HARD)
    c_hard = hard_only.judge([ev(HARD, Verdict.PASS, Tier.HARD)]).confidence

    agree = _bank_with_soft(stats).judge(
        [ev(HARD, Verdict.PASS, Tier.HARD), ev(SOFT, Verdict.PASS, Tier.SOFT)]
    )
    disagree = _bank_with_soft(stats).judge(
        [ev(HARD, Verdict.PASS, Tier.HARD), ev(SOFT, Verdict.FAIL, Tier.SOFT)]
    )

    # Agreement raises confidence above hard-alone; disagreement lowers it...
    assert agree.confidence > c_hard
    assert disagree.confidence < agree.confidence
    # ...but the hard verdict still stands (disagreement surfaced, not obeyed).
    assert disagree.verdict == Verdict.PASS


def test_abstain_does_not_calibrate_the_soft_verifier():
    bank = VerifierBank()
    bank.register(HARD, Tier.HARD)
    bank.register(SOFT, Tier.SOFT)
    bank.judge([ev(HARD, Verdict.PASS, Tier.HARD), ev(SOFT, Verdict.ABSTAIN, Tier.SOFT)])
    assert trust.sample_count(bank._store.get(SOFT)) == 0


def test_determinism_identical_inputs_identical_judgment():
    def run():
        bank = VerifierBank()
        bank.register(HARD, Tier.HARD)
        bank.register(SOFT, Tier.SOFT)
        return bank.judge(
            [ev(HARD, Verdict.PASS, Tier.HARD), ev(SOFT, Verdict.FAIL, Tier.SOFT)]
        )

    assert run() == run()


# -- Parity: enabling the soft verifier changes no pass/fail outcome --------


def test_parity_enabling_judge_preserves_verdicts(tmp_path):
    from prometheus_protocol import Config, build_orchestrator
    from prometheus_protocol._examples.python_functions import build_benchmark

    benchmark = build_benchmark()

    def outcomes(enable: bool, sub: str):
        config = Config(
            registry_dir=tmp_path / sub,
            ledger_path=":memory:",
            verifier_memory_mb=0,
            enable_model_judge=enable,
        )
        report = build_orchestrator(config).baseline(benchmark.tasks)
        return {o.task_id: o.passed for o in report.outcomes}, report.rate_for("heldout")

    off, off_rate = outcomes(False, "off")
    on, on_rate = outcomes(True, "on")
    # Every task's pass/fail is identical; the held-out rate is unchanged.
    assert on == off
    assert on_rate == off_rate == 0.4
