"""Conformance: verifier-trust invariants.

These pin two formal claims from ``spec/invariants.md``:

  I6. A soft-tier verdict can never override a hard-tier verdict; it may only
      inform calibration.
  I7. An un-audited verifier carries zero aggregation weight until calibrated
      against trusted references.

plus determinism of fusion and the "trust is earned" property.
"""

from __future__ import annotations

import pytest

from prometheus_protocol.core.models import Evidence, Tier, Verdict
from prometheus_protocol.verifier import trust
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.store import InMemoryTrustStore
from prometheus_protocol.verifier.trust import TrustStats


def ev(vid: str, verdict: Verdict, tier: Tier) -> Evidence:
    return Evidence(
        passed=(verdict == Verdict.PASS),
        total=1,
        passed_count=1 if verdict == Verdict.PASS else 0,
        verifier_id=vid,
        verdict=verdict,
        tier=tier,
    )


def test_i6_soft_cannot_override_hard():
    bank = VerifierBank()
    judgment = bank.judge(
        [ev("h", Verdict.PASS, Tier.HARD), ev("s", Verdict.FAIL, Tier.SOFT)]
    )
    # The hard verdict stands; the soft FAIL does not flip it.
    assert judgment.verdict == Verdict.PASS
    assert judgment.authoritative is True
    assert judgment.contributing == ("h",)
    # The soft verdict served only as calibration: exactly one sample recorded.
    assert trust.sample_count(bank._store.get("s")) == 1


def test_i7_unaudited_verifier_has_zero_weight():
    # An un-audited soft verifier contributes a log-LR of exactly zero...
    cold = TrustStats(verifier_id="s", tier=Tier.SOFT)
    assert trust.log_lr(cold, Verdict.PASS) == 0.0

    # ...so judging on it alone yields the neutral prior and no authority.
    bank = VerifierBank()
    bank.register("s", Tier.SOFT)
    judgment = bank.judge([ev("s", Verdict.PASS, Tier.SOFT)])
    assert judgment.confidence == pytest.approx(0.5)
    assert judgment.authoritative is False


def test_trust_is_earned_through_calibration():
    bank = VerifierBank()
    bank.register("h", Tier.HARD)
    bank.register("s", Tier.SOFT)

    # 25 correct agreements with hard labels, alternating PASS/FAIL.
    for i in range(25):
        verdict = Verdict.PASS if i % 2 == 0 else Verdict.FAIL
        bank.judge([ev("h", verdict, Tier.HARD), ev("s", verdict, Tier.SOFT)])

    assert trust.youden(bank._store.get("s")) > 0.8

    # The now-trusted soft verifier can carry an advisory-only judgment above
    # the escalation threshold on its own.
    advisory = bank.judge([ev("s", Verdict.PASS, Tier.SOFT)])
    assert advisory.authoritative is False
    assert advisory.confidence > bank.escalate_below
    assert bank.needs_escalation(advisory) is False


def test_determinism_identical_inputs_identical_judgment():
    def run() -> object:
        bank = VerifierBank(InMemoryTrustStore())
        bank.register("h", Tier.HARD)
        bank.register("s", Tier.SOFT)
        return bank.judge(
            [ev("h", Verdict.PASS, Tier.HARD), ev("s", Verdict.FAIL, Tier.SOFT)]
        )

    assert run() == run()
