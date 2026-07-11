"""Candidate chain-composition rules — HYPOTHESES to be measured, not answers.

The orchestration runtime records each step's own confidence and reports a
chain-level number computed as the **minimum** along the realised path — an
explicit conservative *placeholder* (``docs/orchestration.md``), never claimed
to be a principled composition.

This module gathers several *candidate* rules for turning per-step confidences
(and their tiers) into a single chain-level number. They exist to be **measured**
against real chain outcomes (``benchmarks/chain_eval.py``,
``docs/composition-study.md``) — which rule, if any, predicts whether a chain
was actually correct. None of them is asserted to be sound; the measurement
decides, and the measured finding governs whether the runtime's placeholder is
ever replaced.

**These functions cannot authorize anything.** Each is a pure map
``(confidences, tiers) -> float`` in ``[0, 1]``. This module imports nothing
from the gate, the executor, or the controller, and holds no capability. A
composed number is a *summary for a human*, never an input the gate reads: the
gate decides on each action's own judgment, one action at a time. A high
composed confidence therefore can only ever make a halt decision *more*
conservative (route/hold sooner); it can never lift a block or grant execution.
That property is enforced by construction (nothing here touches the gate) and
tested (``tests/conformance/test_composition.py``).
"""

from __future__ import annotations

from math import prod
from typing import Callable, Sequence

from prometheus_protocol.core.models import Tier

# A composition rule: per-step confidences + per-step tiers -> chain number.
CompositionRule = Callable[[Sequence[float], Sequence[Tier]], float]

# The worst per-domain SOFT false-PASS rate measured live (grounding-v2,
# correlated arm: 5/45 = 11.1%; see docs/judge-quality.md). A SOFT step's PASS
# is, at best, this-much-less-than-certain, so a tier-aware rule refuses to let
# a SOFT step push chain confidence above the measured SOFT reliability ceiling.
# Directional (single run, small N) and used only to make composition MORE
# conservative — never less.
SOFT_FALSE_PASS_CEILING = 0.111
SOFT_RELIABILITY_CEILING = 1.0 - SOFT_FALSE_PASS_CEILING  # ~0.889

# A small per-extra-step penalty for the weakest-link-with-length rule: each
# additional dependent step is another place an unmeasured error can enter, so
# a longer chain is discounted below its weakest graded step.
LENGTH_PENALTY_PER_STEP = 0.02


def _check(confidences: Sequence[float], tiers: Sequence[Tier]) -> None:
    if len(confidences) != len(tiers):
        raise ValueError(
            f"confidences ({len(confidences)}) and tiers ({len(tiers)}) "
            "must be the same length"
        )
    for c in confidences:
        if not (0.0 <= c <= 1.0):
            raise ValueError(f"confidence {c!r} outside [0, 1]")


def min_rule(confidences: Sequence[float], tiers: Sequence[Tier]) -> float:
    """The current placeholder: the chain is only as strong as its weakest step.

    Conservative and never over-states trust, but discriminates poorly — one
    weak step floors the whole chain regardless of the others.
    """

    _check(confidences, tiers)
    return min(confidences) if confidences else 0.0


def product_rule(confidences: Sequence[float], tiers: Sequence[Tier]) -> float:
    """Independence assumption: multiply per-step confidences.

    Exactly calibrated *iff* per-step correctness is independent and each
    confidence is a true per-step correctness probability — an assumption
    dependent workflow steps generally violate. Decays fast with chain length.
    """

    _check(confidences, tiers)
    return prod(confidences) if confidences else 0.0


def mean_rule(confidences: Sequence[float], tiers: Sequence[Tier]) -> float:
    """Arithmetic mean. Included precisely because it is *dangerous*: it averages
    a weak link away, so a chain with one confidently-wrong step can still score
    high. Measured to expose that failure mode, not recommended."""

    _check(confidences, tiers)
    return sum(confidences) / len(confidences) if confidences else 0.0


def tier_weighted_rule(confidences: Sequence[float], tiers: Sequence[Tier]) -> float:
    """Tier-aware: cap each SOFT step at the measured SOFT reliability ceiling,
    then take the product.

    Encodes two measured facts: an authoritative (HARD/HUMAN) PASS is reliable
    (~0% false-PASS live), while a SOFT PASS cannot be trusted above the measured
    SOFT reliability ceiling however confident the advisor sounds. Only ever
    lowers a SOFT step's contribution; never raises anything.
    """

    _check(confidences, tiers)
    if not confidences:
        return 0.0
    adjusted = [
        c if tier in (Tier.HARD, Tier.HUMAN) else min(c, SOFT_RELIABILITY_CEILING)
        for c, tier in zip(confidences, tiers)
    ]
    return prod(adjusted)


def weakest_link_length_rule(
    confidences: Sequence[float], tiers: Sequence[Tier]
) -> float:
    """Weakest link, discounted for length: ``min - penalty * (N - 1)``.

    Keeps min's conservatism but adds a small penalty for each extra dependent
    step, so a longer chain is trusted less than a short one with the same
    weakest step. Floored at 0.
    """

    _check(confidences, tiers)
    if not confidences:
        return 0.0
    base = min(confidences)
    penalty = LENGTH_PENALTY_PER_STEP * (len(confidences) - 1)
    return max(0.0, base - penalty)


#: The candidate rules, by name — the hypotheses the measurement evaluates.
RULES: dict[str, CompositionRule] = {
    "min": min_rule,
    "product": product_rule,
    "mean": mean_rule,
    "tier_weighted": tier_weighted_rule,
    "weakest_link_length": weakest_link_length_rule,
}


__all__ = [
    "CompositionRule",
    "RULES",
    "min_rule",
    "product_rule",
    "mean_rule",
    "tier_weighted_rule",
    "weakest_link_length_rule",
    "SOFT_FALSE_PASS_CEILING",
    "SOFT_RELIABILITY_CEILING",
    "LENGTH_PENALTY_PER_STEP",
]
