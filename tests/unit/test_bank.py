"""Unit tests for the verifier bank: fusion, calibration, escalation, ranking."""

from __future__ import annotations

import pytest

from prometheus_protocol.core.models import Evidence, Judgment, Tier, Verdict
from prometheus_protocol.verifier import trust
from prometheus_protocol.verifier.bank import VerifierBank


def ev(vid: str, verdict: Verdict, tier: Tier, *, cost=None, latency_ms=None) -> Evidence:
    return Evidence(
        passed=(verdict == Verdict.PASS),
        total=1,
        passed_count=1 if verdict == Verdict.PASS else 0,
        verifier_id=vid,
        verdict=verdict,
        tier=tier,
        cost=cost,
        latency_ms=latency_ms,
    )


def test_single_hard_pass_is_authoritative_and_confident():
    bank = VerifierBank()
    bank.register("h", Tier.HARD)
    judgment = bank.judge([ev("h", Verdict.PASS, Tier.HARD)])
    assert judgment.verdict == Verdict.PASS
    assert judgment.authoritative is True
    assert judgment.conflict is False
    assert 0.90 < judgment.confidence < 1.0


def test_two_agreeing_hard_beats_one():
    one = VerifierBank().judge([ev("h1", Verdict.PASS, Tier.HARD)])
    two = VerifierBank().judge(
        [ev("h1", Verdict.PASS, Tier.HARD), ev("h2", Verdict.PASS, Tier.HARD)]
    )
    assert two.confidence > one.confidence


def test_human_overrides_hard_and_calibrates_it():
    bank = VerifierBank()
    judgment = bank.judge(
        [ev("h", Verdict.PASS, Tier.HARD), ev("u", Verdict.FAIL, Tier.HUMAN)]
    )
    assert judgment.verdict == Verdict.FAIL
    assert judgment.authoritative is True
    assert judgment.conflict is True
    assert judgment.contributing == ("u",)
    # The human reference recorded one false-positive against the hard verifier.
    assert bank._store.get("h").fp == 1


def test_advisory_abstain_is_dropped():
    bank = VerifierBank()
    bank.register("s", Tier.SOFT)
    judgment = bank.judge(
        [ev("h", Verdict.PASS, Tier.HARD), ev("s", Verdict.ABSTAIN, Tier.SOFT)]
    )
    assert judgment.verdict == Verdict.PASS
    # An abstaining verifier records no calibration sample.
    assert trust.sample_count(bank._store.get("s")) == 0


def test_no_usable_evidence_abstains():
    judgment = VerifierBank().judge([ev("s", Verdict.ABSTAIN, Tier.SOFT)])
    assert judgment.verdict == Verdict.ABSTAIN
    assert judgment.confidence == pytest.approx(0.5)
    assert judgment.authoritative is False


def test_auto_register_uses_evidence_tier():
    bank = VerifierBank()
    bank.judge([ev("h", Verdict.PASS, Tier.HARD)])
    assert bank._store.get("h").tier == Tier.HARD


def test_missing_tier_is_rejected():
    bank = VerifierBank()
    bad = Evidence(passed=True, total=1, passed_count=1,
                   verifier_id="x", verdict=Verdict.PASS, tier=None)
    with pytest.raises(ValueError):
        bank.judge([bad])


def test_tier_mismatch_is_rejected():
    # A verifier's tier is fixed; reporting it under a different tier is an error.
    bank = VerifierBank()
    bank.register("v", Tier.HARD)
    with pytest.raises(ValueError):
        bank.judge([ev("v", Verdict.PASS, Tier.SOFT)])

    # Same in the other direction, after an auto-registration as SOFT.
    other = VerifierBank()
    other.judge([ev("w", Verdict.PASS, Tier.SOFT)])
    with pytest.raises(ValueError):
        other.judge([ev("w", Verdict.PASS, Tier.HARD)])


def test_registered_tier_is_the_source_of_truth():
    # Evidence may omit the tier for a known verifier; the stored tier governs
    # both classification and the prior (no divergence between the two).
    bank = VerifierBank()
    bank.register("h", Tier.HARD)
    tierless = Evidence(passed=True, total=1, passed_count=1,
                        verifier_id="h", verdict=Verdict.PASS, tier=None)
    judgment = bank.judge([tierless])
    assert judgment.authoritative is True
    assert 0.90 < judgment.confidence < 1.0


def test_needs_escalation():
    bank = VerifierBank(escalate_below=0.75)
    low = Judgment(Verdict.PASS, 0.5, authoritative=False)
    high = Judgment(Verdict.PASS, 0.9, authoritative=False)
    authoritative = Judgment(Verdict.PASS, 0.5, authoritative=True)
    assert bank.needs_escalation(low) is True
    assert bank.needs_escalation(high) is False
    # Authoritative judgments are binding and never escalate.
    assert bank.needs_escalation(authoritative) is False


def test_rank_orders_calibrated_above_unaudited():
    bank = VerifierBank()
    bank.register("h", Tier.HARD)
    bank.register("s_cal", Tier.SOFT)
    bank.register("s_raw", Tier.SOFT)
    for i in range(6):
        verdict = Verdict.PASS if i % 2 == 0 else Verdict.FAIL
        bank.judge([ev("h", verdict, Tier.HARD), ev("s_cal", verdict, Tier.SOFT)])
    order = [entry.verifier_id for entry in bank.rank()]
    assert order.index("s_cal") < order.index("s_raw")


def test_rank_breaks_ties_by_cost_then_latency():
    bank = VerifierBank()
    bank.register("cheap", Tier.SOFT)
    bank.register("dear", Tier.SOFT)
    # Same (zero) reliability; cost decides.
    bank.judge([ev("cheap", Verdict.ABSTAIN, Tier.SOFT, cost=1.0)])
    bank.judge([ev("dear", Verdict.ABSTAIN, Tier.SOFT, cost=9.0)])
    order = [entry.verifier_id for entry in bank.rank()]
    assert order.index("cheap") < order.index("dear")
