"""Unit tests for the calibrated trust model (pure math)."""

from __future__ import annotations

import pytest

from prometheus_protocol.core.models import Tier, Verdict
from prometheus_protocol.verifier import trust
from prometheus_protocol.verifier.trust import TrustStats


def _stats(tier: Tier, **counts) -> TrustStats:
    return TrustStats(verifier_id="v", tier=tier, **counts)


def test_cold_start_reliabilities():
    assert trust.tpr(_stats(Tier.HARD)) == pytest.approx(0.95)
    assert trust.tnr(_stats(Tier.HARD)) == pytest.approx(0.95)
    assert trust.tpr(_stats(Tier.HUMAN)) == pytest.approx(0.98)
    assert trust.tpr(_stats(Tier.SOFT)) == pytest.approx(0.5)
    assert trust.tpr(_stats(Tier.CONSISTENCY)) == pytest.approx(0.5)


def test_cold_start_youden():
    assert trust.youden(_stats(Tier.HARD)) == pytest.approx(0.9)
    assert trust.youden(_stats(Tier.HUMAN)) == pytest.approx(0.96)
    # An un-audited soft verifier has exactly zero reliability.
    assert trust.youden(_stats(Tier.SOFT)) == 0.0


def test_updated_confusion_rules():
    base = _stats(Tier.SOFT)
    assert trust.updated(base, predicted=Verdict.PASS, actual=Verdict.PASS).tp == 1
    assert trust.updated(base, predicted=Verdict.FAIL, actual=Verdict.PASS).fn == 1
    assert trust.updated(base, predicted=Verdict.FAIL, actual=Verdict.FAIL).tn == 1
    assert trust.updated(base, predicted=Verdict.PASS, actual=Verdict.FAIL).fp == 1


def test_abstain_never_updates():
    base = _stats(Tier.SOFT, tp=2, fp=1)
    assert trust.updated(base, predicted=Verdict.ABSTAIN, actual=Verdict.PASS) == base
    assert trust.updated(base, predicted=Verdict.PASS, actual=Verdict.ABSTAIN) == base


def test_sample_count():
    assert trust.sample_count(_stats(Tier.SOFT, tp=3, fn=1, tn=2, fp=4)) == 10


def test_log_lr_signs_and_zero():
    hard = _stats(Tier.HARD)
    assert trust.log_lr(hard, Verdict.PASS) > 0.0
    assert trust.log_lr(hard, Verdict.FAIL) < 0.0
    assert trust.log_lr(hard, Verdict.ABSTAIN) == 0.0
    # An un-audited soft verifier contributes nothing either way.
    soft = _stats(Tier.SOFT)
    assert trust.log_lr(soft, Verdict.PASS) == 0.0
    assert trust.log_lr(soft, Verdict.FAIL) == 0.0


def test_log_lr_is_finite_under_extreme_counts():
    # Clamping keeps the ratio finite even when one outcome never happened.
    lopsided = _stats(Tier.SOFT, tp=10_000, tn=10_000)
    assert trust.log_lr(lopsided, Verdict.PASS) == pytest.approx(
        -trust.log_lr(lopsided, Verdict.FAIL)
    )
    assert abs(trust.log_lr(lopsided, Verdict.PASS)) < 50.0
