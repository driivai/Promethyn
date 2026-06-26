"""Calibrated trust model for verifiers — pure and deterministic, no I/O.

Each verifier accumulates a confusion matrix against trusted reference labels:

    actual PASS, predicted PASS -> tp        actual PASS, predicted FAIL -> fn
    actual FAIL, predicted FAIL -> tn        actual FAIL, predicted PASS -> fp

Any ABSTAIN (predicted or actual) updates nothing.

From those counts and a tier-dependent Beta prior we estimate the verifier's
sensitivity (TPR) and specificity (TNR). The prior makes authoritative tiers
trusted by construction at cold start while soft tiers must earn trust:

    HARD        -> Beta(19, 1)  cold-start reliability 0.95
    HUMAN       -> Beta(49, 1)  cold-start reliability 0.98
    SOFT        -> Beta(1, 1)   cold-start reliability 0.5  (zero evidence)
    CONSISTENCY -> Beta(1, 1)   cold-start reliability 0.5  (zero evidence)

The same prior is applied to both TPR and TNR. Reliability for ranking is the
Youden index ``J = TPR + TNR - 1`` in [-1, 1]; it is 0 for an un-audited soft
verifier, so such a verifier carries no aggregation weight until calibrated.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, replace

from prometheus_protocol.core.models import Tier, Verdict

# Probabilities are clamped away from 0 and 1 so log-likelihood ratios stay
# finite even with extreme counts.
_CLAMP_LO = 1e-6
_CLAMP_HI = 1.0 - 1e-6

# Tier-dependent Beta(alpha, beta) priors, applied to both TPR and TNR.
TIER_PRIORS: dict[Tier, tuple[int, int]] = {
    Tier.HARD: (19, 1),
    Tier.HUMAN: (49, 1),
    Tier.SOFT: (1, 1),
    Tier.CONSISTENCY: (1, 1),
}


@dataclass(frozen=True)
class TrustStats:
    """Persisted calibration state for one verifier.

    Holds the verifier's tier (which selects the prior) and its confusion
    counts against trusted references. This is the unit a :class:`TrustStore`
    stores and returns.
    """

    verifier_id: str
    tier: Tier
    tp: int = 0
    fn: int = 0
    tn: int = 0
    fp: int = 0


def prior_for(tier: Tier) -> tuple[int, int]:
    """Return the ``(alpha, beta)`` Beta prior for ``tier``."""

    return TIER_PRIORS.get(tier, (1, 1))


def _clamp(value: float) -> float:
    return min(max(value, _CLAMP_LO), _CLAMP_HI)


def sample_count(stats: TrustStats) -> int:
    """Number of calibration samples recorded so far."""

    return stats.tp + stats.fn + stats.tn + stats.fp


def tpr(stats: TrustStats) -> float:
    """Estimated sensitivity P(predict PASS | actual PASS), clamped."""

    alpha, beta = prior_for(stats.tier)
    return _clamp((stats.tp + alpha) / (stats.tp + stats.fn + alpha + beta))


def tnr(stats: TrustStats) -> float:
    """Estimated specificity P(predict FAIL | actual FAIL), clamped."""

    alpha, beta = prior_for(stats.tier)
    return _clamp((stats.tn + alpha) / (stats.tn + stats.fp + alpha + beta))


def youden(stats: TrustStats) -> float:
    """Reliability scalar ``TPR + TNR - 1`` in [-1, 1] (0 = no information)."""

    return tpr(stats) + tnr(stats) - 1.0


def log_lr(stats: TrustStats, report: Verdict) -> float:
    """Log-likelihood ratio toward PASS contributed by one report.

    ABSTAIN contributes nothing (0.0). A PASS report weighs in by
    ``log(TPR / (1 - TNR))``; a FAIL report by ``log((1 - TPR) / TNR)``.
    """

    if report == Verdict.ABSTAIN:
        return 0.0
    sensitivity = tpr(stats)
    specificity = tnr(stats)
    if report == Verdict.PASS:
        return math.log(sensitivity / (1.0 - specificity))
    return math.log((1.0 - sensitivity) / specificity)


def updated(stats: TrustStats, *, predicted: Verdict, actual: Verdict) -> TrustStats:
    """Return new stats after one calibration sample.

    ``predicted`` is the verifier's verdict; ``actual`` is the trusted
    reference verdict. Any ABSTAIN on either side is a no-op.
    """

    if predicted == Verdict.ABSTAIN or actual == Verdict.ABSTAIN:
        return stats
    if actual == Verdict.PASS:
        if predicted == Verdict.PASS:
            return replace(stats, tp=stats.tp + 1)
        return replace(stats, fn=stats.fn + 1)
    # actual == FAIL
    if predicted == Verdict.FAIL:
        return replace(stats, tn=stats.tn + 1)
    return replace(stats, fp=stats.fp + 1)
