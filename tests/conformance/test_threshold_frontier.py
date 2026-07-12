"""Conformance: the post-hoc θ-sweep is correct, monotone, and needs no model.

The threshold lever is a pure recomputation over stored baseline records; these
tests verify the recomputation arithmetic against hand-computed values, prove the
frontier is monotone (false-PASS can only fall as coverage falls — the property
that makes the abstention trade visible by construction), round-trip the
persistence format, and reproduce the scripted grounding-v2 θ=0.80 headline.
Zero model calls anywhere.
"""

from __future__ import annotations

import json

from prometheus_protocol.benchmarks.judge_eval import JudgedRow
from prometheus_protocol.benchmarks.threshold_frontier import (
    THETAS,
    load_records,
    persist_records,
    record_from_row,
    sweep,
    trade_at,
)
from prometheus_protocol.core.models import Verdict

P, F = Verdict.PASS, Verdict.FAIL

# Hand-checkable records: two false-PASS (hi/mid conf), two correct PASS (hi/mid),
# one correct FAIL.
_RECORDS = [
    {"item_id": "a", "verdict": "pass", "confidence": 0.9, "gold": "fail", "tier": "soft"},
    {"item_id": "b", "verdict": "pass", "confidence": 0.6, "gold": "fail", "tier": "soft"},
    {"item_id": "c", "verdict": "pass", "confidence": 0.9, "gold": "pass", "tier": "soft"},
    {"item_id": "d", "verdict": "pass", "confidence": 0.6, "gold": "pass", "tier": "soft"},
    {"item_id": "e", "verdict": "fail", "confidence": 0.9, "gold": "fail", "tier": "soft"},
]


def _pt(theta):
    return next(p for p in sweep(_RECORDS, [theta]))


def test_theta_grid_is_050_to_095_step_005():
    assert THETAS[0] == 0.50 and THETAS[-1] == 0.95
    assert all(abs((THETAS[i + 1] - THETAS[i]) - 0.05) < 1e-9 for i in range(len(THETAS) - 1))


def test_recompute_at_theta_070_matches_hand_computed():
    # θ=0.70: b(0.6) and d(0.6) PASSes fall to ABSTAIN; a,c stay PASS; e stays FAIL.
    p = _pt(0.70)
    assert (p.coverage.num, p.coverage.den) == (3, 5)       # a,c,e decided
    assert (p.false_pass.num, p.false_pass.den) == (1, 2)   # a PASS of {a,e} gold-neg decided
    assert (p.false_fail.num, p.false_fail.den) == (0, 1)   # c of {c} gold-pos decided
    assert (p.withheld_correct, p.withheld_false_pass) == (1, 1)  # d correct, b false


def test_recompute_at_theta_050_accepts_all_passes():
    p = _pt(0.50)
    assert (p.coverage.num, p.coverage.den) == (5, 5)
    assert (p.false_pass.num, p.false_pass.den) == (2, 3)   # a,b of {a,b,e}
    assert (p.withheld_correct, p.withheld_false_pass) == (0, 0)


def test_recompute_at_theta_095_withholds_all_hi_conf_passes():
    p = _pt(0.95)
    assert (p.coverage.num, p.coverage.den) == (1, 5)       # only e (FAIL) survives
    assert (p.false_pass.num, p.false_pass.den) == (0, 1)
    assert (p.withheld_correct, p.withheld_false_pass) == (2, 2)


def test_frontier_is_monotone_false_pass_falls_only_as_coverage_falls():
    points = sweep(_RECORDS)
    covs = [p.coverage.num for p in points]
    fps = [p.false_pass.num for p in points]
    assert covs == sorted(covs, reverse=True), "coverage must be non-increasing in θ"
    assert fps == sorted(fps, reverse=True), "false-PASS must be non-increasing in θ"


def test_persist_round_trip(tmp_path):
    rows = [
        JudgedRow(item_id="x", actor_model="-", reference=F, judged=P, confidence=0.9),
        JudgedRow(item_id="y", actor_model="-", reference=P, judged=F, confidence=None),
    ]
    path = str(tmp_path / "baseline.json")
    persist_records(rows, path, set_name="s", arm="correlated")
    loaded = load_records(path)
    assert loaded["set"] == "s" and loaded["arm"] == "correlated"
    assert loaded["records"][0] == record_from_row(rows[0])
    assert loaded["records"][1]["confidence"] is None  # unstated survives round-trip


def test_scripted_grounding_v2_theta_080_reproduces_the_3_for_2_trade():
    """The reproducible headline: on scripted grounding-v2, θ=0.80 moves false-PASS
    3/44 -> 1/42 while withholding 3 correct PASSes to catch 2 false ones."""

    from prometheus_protocol.benchmarks.threshold_frontier import _scripted_grounding_v2_records

    records, _, _ = _scripted_grounding_v2_records()
    points = sweep(records)
    base = next(p for p in points if p.theta == 0.50)
    at80 = next(p for p in points if p.theta == 0.80)
    assert (base.false_pass.num, base.false_pass.den) == (3, 44)
    assert (at80.false_pass.num, at80.false_pass.den) == (1, 42)
    assert (at80.withheld_correct, at80.withheld_false_pass) == (3, 2)
    assert "3 correct PASS(es) withheld to catch 2 false-PASS(es)" in trade_at(points, 0.80)
