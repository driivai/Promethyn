"""Conformance: the SOFT-lever report never emits a rate without its denominator.

The abstention trap is only impossible to miss if false-PASS is never shown
without the coverage and denominator next to it. These tests fail the build if a
rate is rendered as a bare percentage, if the JSON emits a rate as a bare float
instead of a {num, den} object, or if a thin denominator drops its rule-of-three
ceiling. The count arithmetic is fixture-verified against hand-computed values.
"""

from __future__ import annotations

import re

from prometheus_protocol.benchmarks.judge_eval import JudgedRow
from prometheus_protocol.benchmarks.soft_calibration_report import (
    Rate,
    render_block,
    summarize,
)
from prometheus_protocol.core.models import Verdict

P, F, A = Verdict.PASS, Verdict.FAIL, Verdict.ABSTAIN


def _row(item_id, reference, judged, conf=None):
    return JudgedRow(item_id=item_id, actor_model="-", reference=reference,
                     judged=judged, confidence=conf)


# A hand-checkable fixture set:
#   r1 ref FAIL  judged PASS  -> false-PASS
#   r2 ref FAIL  judged FAIL  -> correct negative
#   r3 ref PASS  judged PASS  -> correct positive
#   r4 ref PASS  judged FAIL  -> false-FAIL
#   r5 ref FAIL  judged ABSTAIN -> referenced but not decided (abstain)
#   r6 ref ABSTAIN judged PASS  -> no ground truth (excluded entirely)
_ROWS = [
    _row("r1", F, P, 0.9),
    _row("r2", F, F, 0.8),
    _row("r3", P, P, 0.7),
    _row("r4", P, F, 0.6),
    _row("r5", F, A),
    _row("r6", A, P, 0.9),
]


def _summary():
    return summarize(_ROWS, set_name="fixture", arm="scripted", lever="baseline",
                     model_calls=6)


def test_summarize_matches_hand_counts():
    s = _summary()
    assert (s.items_total, s.items_scored) == (5, 4)   # r1..r5 referenced; r1..r4 decided
    assert (s.judge_pass, s.judge_fail, s.abstain) == (2, 2, 1)
    assert (s.coverage.num, s.coverage.den) == (4, 5)
    assert (s.false_pass.num, s.false_pass.den) == (1, 2)   # r1 of {r1,r2} decided gold-neg
    assert (s.false_fail.num, s.false_fail.den) == (1, 2)   # r4 of {r3,r4} decided gold-pos
    assert (s.agreement.num, s.agreement.den) == (2, 4)     # r2, r3 agree
    assert s.model_calls == 6


def test_no_rendered_rate_is_a_bare_percentage():
    """Every line that shows a percentage must also show its n/d denominator."""

    block = render_block(_summary())
    offenders = [
        line for line in block.splitlines()
        if "%" in line and not re.search(r"\d+\s*/\s*\d+", line)
    ]
    assert offenders == [], f"rate(s) emitted without a denominator: {offenders}"


def test_json_rates_are_num_den_objects_not_bare_floats():
    s = _summary()
    j = s.as_json()
    for key in ("coverage", "false_PASS", "false_FAIL", "agreement"):
        assert isinstance(j[key], dict), f"{key} must be an object, not a bare rate"
        assert "num" in j[key] and "den" in j[key], f"{key} missing num/den"


def test_thin_denominator_carries_rule_of_three_ceiling():
    # false_PASS/false_FAIL here have denominator 2 (< 20) -> ceiling present.
    s = _summary()
    assert s.false_pass.den < 20
    assert s.false_pass.render().count("rule-of-three") == 1
    assert s.as_json()["false_PASS"]["rule_of_three_ceiling"] is not None
    # a fat denominator (>= 20) does not print the ceiling
    fat = Rate(0, 45)
    assert "rule-of-three" not in fat.render()
    assert fat.as_json()["rule_of_three_ceiling"] is None


def test_zero_denominator_renders_dash_never_a_fake_zero():
    assert Rate(0, 0).render().endswith("= -")
    assert Rate(0, 0).as_json()["rate"] is None
