"""Trust-weighted evidence fusion — pure and deterministic.

Each verifier's report contributes a log-likelihood ratio toward PASS (see
:mod:`prometheus_protocol.verifier.trust`). With a neutral prior (log-odds 0)
the contributions add up, and the total log-odds is mapped back to a
probability of PASS.

    log_odds = sum(per-report log-LR)
    p_pass   = sigmoid(log_odds)
    verdict  = PASS if p_pass >= 0.5 else FAIL
    confidence = p_pass if PASS else 1 - p_pass
"""

from __future__ import annotations

import math
from typing import Iterable, Sequence

from prometheus_protocol.core.models import Verdict
from prometheus_protocol.verifier.trust import TrustStats, log_lr

# A pairing of a verifier's calibration stats with the verdict it reported.
Contribution = tuple[TrustStats, Verdict]


def total_log_odds(contributions: Iterable[Contribution]) -> float:
    """Sum the per-report log-likelihood ratios (prior log-odds is 0)."""

    return math.fsum(log_lr(stats, report) for stats, report in contributions)


def sigmoid(x: float) -> float:
    """Numerically stable logistic function."""

    if x >= 0.0:
        return 1.0 / (1.0 + math.exp(-x))
    z = math.exp(x)
    return z / (1.0 + z)


def p_pass(log_odds: float) -> float:
    """Probability of PASS for the given log-odds."""

    return sigmoid(log_odds)


def fuse(contributions: Sequence[Contribution]) -> tuple[Verdict, float]:
    """Fuse contributions into a verdict and a confidence in [0, 1].

    With no contributions the result is the neutral prior: PASS at confidence
    0.5 (callers that need an explicit "no evidence" outcome handle that before
    calling here).
    """

    probability = p_pass(total_log_odds(contributions))
    if probability >= 0.5:
        return Verdict.PASS, probability
    return Verdict.FAIL, 1.0 - probability
