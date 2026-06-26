"""Unit tests for trust-weighted evidence fusion (pure math)."""

from __future__ import annotations

import pytest

from prometheus_protocol.core.models import Tier, Verdict
from prometheus_protocol.verifier import aggregate
from prometheus_protocol.verifier.trust import TrustStats


def _hard(**counts) -> TrustStats:
    return TrustStats(verifier_id="h", tier=Tier.HARD, **counts)


def test_fuse_no_contributions_is_neutral():
    verdict, confidence = aggregate.fuse([])
    assert verdict == Verdict.PASS
    assert confidence == pytest.approx(0.5)


def test_fuse_single_hard_pass():
    verdict, confidence = aggregate.fuse([(_hard(), Verdict.PASS)])
    assert verdict == Verdict.PASS
    assert confidence == pytest.approx(0.95)


def test_fuse_single_hard_fail():
    verdict, confidence = aggregate.fuse([(_hard(), Verdict.FAIL)])
    assert verdict == Verdict.FAIL
    assert confidence == pytest.approx(0.95)


def test_agreement_increases_confidence():
    one = aggregate.fuse([(_hard(), Verdict.PASS)])[1]
    two = aggregate.fuse([(_hard(), Verdict.PASS), (_hard(), Verdict.PASS)])[1]
    assert two > one


def test_sigmoid_is_stable_for_large_inputs():
    # Must not overflow for large magnitudes.
    assert aggregate.sigmoid(1000.0) == pytest.approx(1.0)
    assert aggregate.sigmoid(-1000.0) == pytest.approx(0.0)
    assert aggregate.sigmoid(0.0) == pytest.approx(0.5)


def test_total_log_odds_sums_contributions():
    single = aggregate.total_log_odds([(_hard(), Verdict.PASS)])
    double = aggregate.total_log_odds(
        [(_hard(), Verdict.PASS), (_hard(), Verdict.PASS)]
    )
    assert double == pytest.approx(2 * single)
