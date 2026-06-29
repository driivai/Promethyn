"""Verifier bank: fuse many verdicts into one judgment and rank verifiers.

The bank depends only on a :class:`TrustStore` port (injected) and the pure
trust/aggregation math. It never lets an advisory verdict override an
authoritative one — soft verdicts are calibration signal only — and it teaches
lower-trust verifiers by comparing them against the authoritative reference.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence

from prometheus_protocol.core.models import (
    AUTHORITATIVE_TIERS,
    Evidence,
    Judgment,
    Tier,
    Verdict,
)
from prometheus_protocol.verifier.aggregate import fuse, p_pass, total_log_odds
from prometheus_protocol.verifier.store import InMemoryTrustStore, TrustStore
from prometheus_protocol.verifier.trust import (
    TrustStats,
    sample_count,
    updated,
    youden,
)


@dataclass(frozen=True)
class RankEntry:
    """One verifier's standing in the trust ranking."""

    verifier_id: str
    tier: Tier
    youden: float
    samples: int
    mean_cost: float | None
    mean_latency_ms: float | None


class VerifierBank:
    """Registers verifiers, fuses their evidence, and ranks them by trust."""

    def __init__(
        self,
        store: TrustStore | None = None,
        *,
        escalate_below: float = 0.75,
    ) -> None:
        self._store: TrustStore = store if store is not None else InMemoryTrustStore()
        self.escalate_below = escalate_below
        # Ephemeral running means of observed cost/latency, used only to break
        # ties in rank(); not part of the persisted trust state.
        self._cost_sum: dict[str, float] = {}
        self._cost_n: dict[str, int] = {}
        self._latency_sum: dict[str, float] = {}
        self._latency_n: dict[str, int] = {}

    # -- registration ------------------------------------------------------

    def register(self, verifier_id: str, tier: Tier) -> None:
        """Register a verifier so its tier prior applies. Idempotent."""

        if self._store.get(verifier_id) is None:
            self._store.put(verifier_id, TrustStats(verifier_id=verifier_id, tier=tier))

    def _ensure_stats(self, evidence: Evidence) -> TrustStats:
        """Return the persisted stats for an evidence's verifier.

        A verifier's tier is intrinsic and fixed once known. The persisted
        ``stats.tier`` is the single source of truth used for both
        classification and the prior; evidence only seeds the tier when the
        verifier is first seen. If evidence reports a tier that contradicts the
        stored one, that is a caller error and is rejected loudly rather than
        silently mis-weighted.
        """

        stats = self._store.get(evidence.verifier_id)
        if stats is not None:
            if evidence.tier is not None and evidence.tier != stats.tier:
                raise ValueError(
                    f"verifier {evidence.verifier_id!r} is tier "
                    f"{stats.tier.value!r} but its evidence claims tier "
                    f"{evidence.tier.value!r}; a verifier's tier is fixed"
                )
            return stats
        if evidence.tier is None:
            raise ValueError(
                f"evidence from {evidence.verifier_id!r} has no tier; register "
                "the verifier or set Evidence.tier before judging"
            )
        stats = TrustStats(verifier_id=evidence.verifier_id, tier=evidence.tier)
        self._store.put(evidence.verifier_id, stats)
        return stats

    def _observe(self, evidence: Evidence) -> None:
        vid = evidence.verifier_id
        if evidence.cost is not None:
            self._cost_sum[vid] = self._cost_sum.get(vid, 0.0) + evidence.cost
            self._cost_n[vid] = self._cost_n.get(vid, 0) + 1
        if evidence.latency_ms is not None:
            self._latency_sum[vid] = self._latency_sum.get(vid, 0.0) + evidence.latency_ms
            self._latency_n[vid] = self._latency_n.get(vid, 0) + 1

    # -- judging -----------------------------------------------------------

    def judge(self, evidence: Sequence[Evidence]) -> Judgment:
        for item in evidence:
            self._observe(item)

        # Resolve each non-abstaining report to its verifier's persisted stats.
        # Classification and the prior both read the stored tier, so they can
        # never disagree.
        usable: list[tuple[Evidence, TrustStats]] = []
        for item in evidence:
            if item.verdict == Verdict.ABSTAIN:
                continue
            usable.append((item, self._ensure_stats(item)))

        if not usable:
            return Judgment(
                verdict=Verdict.ABSTAIN,
                confidence=0.5,
                authoritative=False,
            )

        authoritative = [pair for pair in usable if pair[1].tier in AUTHORITATIVE_TIERS]
        advisory = [pair for pair in usable if pair[1].tier not in AUTHORITATIVE_TIERS]

        if authoritative:
            return self._authoritative_judgment(authoritative, advisory)
        return self._advisory_judgment(advisory)

    def _authoritative_judgment(
        self,
        authoritative: list[tuple[Evidence, TrustStats]],
        advisory: list[tuple[Evidence, TrustStats]],
    ) -> Judgment:
        has_human = any(stats.tier == Tier.HUMAN for _, stats in authoritative)
        ref_tier = Tier.HUMAN if has_human else Tier.HARD
        reference = [(e, s) for (e, s) in authoritative if s.tier == ref_tier]
        # Every non-reference verifier: lower-tier authoritative ones and all
        # advisory ones. These are calibrated against the reference and inform
        # confidence, but never the verdict.
        others = [(e, s) for (e, s) in authoritative if s.tier != ref_tier] + advisory

        # The verdict is decided by the authoritative reference alone — an
        # advisory verdict can never override it (I6).
        ref_contributions = [(s, e.verdict) for (e, s) in reference]
        ref_verdict, _ = fuse(ref_contributions)

        # Confidence additionally reflects every non-reference verifier, each
        # weighted by the trust it has earned: an agreeing advisor raises
        # confidence, a dissenting one lowers it, while the verdict stays put.
        # An un-audited verifier contributes a log-LR of ~0 (I7), so it moves
        # confidence negligibly until it has earned weight through calibration.
        all_contributions = ref_contributions + [(s, e.verdict) for (e, s) in others]
        probability = p_pass(total_log_odds(all_contributions))
        confidence = probability if ref_verdict == Verdict.PASS else 1.0 - probability

        # Calibrate each non-reference verifier against the reference verdict.
        for e, s in others:
            self._store.put(
                e.verifier_id,
                updated(s, predicted=e.verdict, actual=ref_verdict),
            )

        conflict = any(e.verdict != ref_verdict for e, _ in authoritative)
        return Judgment(
            verdict=ref_verdict,
            confidence=confidence,
            authoritative=True,
            contributing=tuple(e.verifier_id for e, _ in reference),
            conflict=conflict,
        )

    def _advisory_judgment(
        self, advisory: list[tuple[Evidence, TrustStats]]
    ) -> Judgment:
        # No authoritative reference is available, so we report the fused
        # advisory verdict but record no calibration (there is no ground truth).
        contributions = [(s, e.verdict) for (e, s) in advisory]
        verdict, confidence = fuse(contributions)
        return Judgment(
            verdict=verdict,
            confidence=confidence,
            authoritative=False,
            contributing=tuple(e.verifier_id for e, _ in advisory),
            conflict=False,
        )

    # -- escalation and ranking -------------------------------------------

    def needs_escalation(self, judgment: Judgment) -> bool:
        """True when a non-authoritative judgment is too uncertain to trust."""

        return (not judgment.authoritative) and (
            judgment.confidence < self.escalate_below
        )

    def rank(self) -> list[RankEntry]:
        """Rank verifiers: highest reliability first.

        Ordered by Youden index descending, then sample count descending, then
        lower mean cost and lower mean latency, then id for stability.
        Un-audited verifiers (Youden near 0) fall to the bottom.
        """

        entries = [
            RankEntry(
                verifier_id=vid,
                tier=stats.tier,
                youden=youden(stats),
                samples=sample_count(stats),
                mean_cost=self._mean(self._cost_sum, self._cost_n, vid),
                mean_latency_ms=self._mean(self._latency_sum, self._latency_n, vid),
            )
            for vid, stats in self._store.all().items()
        ]
        entries.sort(
            key=lambda e: (
                -e.youden,
                -e.samples,
                math.inf if e.mean_cost is None else e.mean_cost,
                math.inf if e.mean_latency_ms is None else e.mean_latency_ms,
                e.verifier_id,
            )
        )
        return entries

    @staticmethod
    def _mean(
        sums: dict[str, float], counts: dict[str, int], vid: str
    ) -> float | None:
        n = counts.get(vid, 0)
        return None if n == 0 else sums[vid] / n
