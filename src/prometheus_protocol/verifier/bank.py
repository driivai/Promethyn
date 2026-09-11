"""Verifier bank: fuse many verdicts into one judgment and rank verifiers.

The bank depends only on a :class:`TrustStore` port (injected) and the pure
trust/aggregation math. It never lets an advisory verdict override an
authoritative one — soft verdicts are calibration signal only — and it teaches
lower-trust verifiers by comparing them against the authoritative reference.

PHASE-1.2a — COVERAGE IS VALIDATED BEFORE FUSION.

:meth:`VerifierBank.judge` answers "given these results, what is the verdict".
It cannot answer "is there a result MISSING", and it never could: nothing told it
what was owed. An independent review reproduced the consequence twice — a
passing structural check standing in for an executable check that never ran, and
a HARD PASS beside a HARD Unavailable returning an authoritative PASS with the
outage kept only as metadata. The second is INTENTIONAL behaviour for two
redundant HARD verifiers where either suffices; the bank simply could not tell
redundant from required, because nothing told it.

:meth:`VerifierBank.judge_covered` is the entry point that can. It takes the
resolved :class:`~prometheus_protocol.policy.snapshot.BoundRequirements` and
results bound to it, validates coverage against the policy FIRST, and only then
fuses. Fusion behaviour for what survives is unchanged — this adds a gate in
front of it, it does not re-tune it.

``judge`` remains, unchanged, for the paths that have not migrated. That is an
EXPOSURE and it is named rather than implied: a caller that goes on using
``judge`` gets the old semantics and the policy layer is not consulted. Closing
it means a raw ``Judgment(PASS, authoritative=True)`` must stop being sufficient
for production authorization, which is a breaking interface change and the next
sprint's subject.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Sequence

from prometheus_protocol.core.validation import require_unit_interval
from prometheus_protocol.core.models import (
    AUTHORITATIVE_TIERS,
    Evidence,
    Judgment,
    Tier,
    Unavailability,
    Unavailable,
    Verdict,
    partition_outcomes,
)
from prometheus_protocol.verifier.aggregate import fuse, p_pass, total_log_odds
from prometheus_protocol.verifier.store import InMemoryTrustStore, TrustStore
from prometheus_protocol.verifier.trust import (
    TrustStats,
    sample_count,
    updated,
    youden,
)

if TYPE_CHECKING:  # pragma: no cover - import cycle: policy imports core.models
    from prometheus_protocol.policy.assessment import PolicyAssessment
    from prometheus_protocol.policy.coverage import BoundResult
    from prometheus_protocol.policy.profile import VerificationPolicy
    from prometheus_protocol.policy.snapshot import BoundRequirements


@dataclass(frozen=True)
class RankEntry:
    """One verifier's standing in the trust ranking."""

    verifier_id: str
    tier: Tier
    youden: float
    samples: int
    mean_cost: float | None
    mean_latency_ms: float | None


def _merge_unavailable(items: list[Unavailable]) -> Unavailable:
    """The bank's single could-not-execute outcome from authoritative verifiers
    that could not run. One is reported as-is; several are summarised, keeping
    POLICY_REFUSAL only when *every* one was a deliberate refusal (otherwise the
    conservative INFRA_FAULT)."""

    if len(items) == 1:
        return items[0]
    all_policy = all(u.reason == Unavailability.POLICY_REFUSAL for u in items)
    reason = Unavailability.POLICY_REFUSAL if all_policy else Unavailability.INFRA_FAULT
    ids = ", ".join(u.verifier_id for u in items)
    return Unavailable(
        verifier_id=items[0].verifier_id,
        tier=items[0].tier,
        reason=reason,
        detail=f"{len(items)} authoritative verifiers could not execute ({ids})",
    )


class VerifierBank:
    """Registers verifiers, fuses their evidence, and ranks them by trust."""

    def __init__(
        self,
        store: TrustStore | None = None,
        *,
        escalate_below: float = 0.75,
        policy_supplier: "Callable[[], VerificationPolicy] | None" = None,
    ) -> None:
        self._store: TrustStore = store if store is not None else InMemoryTrustStore()
        self.escalate_below = require_unit_interval(
            escalate_below, name="escalate_below"
        )
        self._policy_supplier = policy_supplier
        # Ephemeral running means of observed cost/latency, used only to break
        # ties in rank(); not part of the persisted trust state.
        self._cost_sum: dict[str, float] = {}
        self._cost_n: dict[str, int] = {}
        self._latency_sum: dict[str, float] = {}
        self._latency_n: dict[str, int] = {}

    def bind_policy_supplier(self, supplier: "Callable[[], VerificationPolicy]") -> None:
        """Bind the trusted selected-policy source before the first assessment."""

        if self._policy_supplier is not None:
            raise ValueError("VerifierBank policy supplier is already bound")
        self._policy_supplier = supplier

    @property
    def has_policy_supplier(self) -> bool:
        return self._policy_supplier is not None

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

    def assess(
        self,
        snapshot: "BoundRequirements",
        results: "Sequence[BoundResult]",
    ) -> "PolicyAssessment":
        """The ONLY way to obtain something an authorization surface will read.

        PHASE-1.2b. ``judge_covered`` answers "what is the verdict, given the
        policy" and returns a ``Judgment | Unavailable`` — which is exactly what
        a caller with no policy at all could also produce, and that
        indistinguishability was the bypass. This wraps the same validated
        outcome in a :class:`~prometheus_protocol.policy.assessment.PolicyAssessment`
        bound to the snapshot, and the gate, the execution controller, the action
        gateway and the migration approval authority now accept nothing else.

        Nothing about the decision changes here. ``judge_covered`` does the
        work; this attaches the binding that proves the work happened, so a raw
        verdict is not merely rejected downstream but has no parameter to arrive
        through.
        """

        from prometheus_protocol.policy.assessment import mint
        from prometheus_protocol.policy.execution import ExecutionNotAuthorized
        from prometheus_protocol.policy.resolver import resolve
        from prometheus_protocol.policy.snapshot import snapshot_digest

        if self._policy_supplier is None:
            raise ExecutionNotAuthorized(
                "VerifierBank requires the selected-policy supplier before minting"
            )
        policy = self._policy_supplier()
        expected = resolve(
            policy,
            artifact_sha256=snapshot.artifact_sha256,
            target_canonical=snapshot.target_canonical,
            action_class=snapshot.action_class,
            attempt_id=snapshot.attempt_id,
        )
        if snapshot_digest(expected) != snapshot_digest(snapshot):
            raise ExecutionNotAuthorized(
                "snapshot differs from requirements re-resolved from selected policy"
            )

        return mint(expected, self.judge_covered(expected, results))

    def judge_covered(
        self,
        snapshot: "BoundRequirements",
        results: "Sequence[BoundResult]",
    ) -> Judgment | Unavailable:
        """Validate required coverage against the policy, THEN fuse.

        This is the authorization-capable entry point. The order is the whole
        point and is not an optimisation: fusion over an incomplete result set
        produces a confident answer to a question nobody was owed an answer to.

        What comes back, by row of the enforcement table:

        * **satisfied** — fusion proceeds over the validated results, and the
          returned :class:`Judgment` is exactly what ``judge`` would have
          produced for those results. Advisory and soft-tier behaviour is
          untouched.
        * **the required check FAILED** — an authoritative
          ``Judgment(FAIL)``. A failure is a real answer, not an outage, and
          reporting it as unavailable would lose that the check ran and said no.
        * **anything else** — an :class:`Unavailable`. Abstained, incomplete,
          invalid evidence and ambiguity are all "there is no satisfactory
          result for a required check", which is a could-not-verify, and EX-1
          says a could-not-verify is never a verdict.

        ``INFRA_FAULT`` vs ``POLICY_REFUSAL`` follows the meaning already fixed
        in ``core/models.py``: an incomplete coverage is a fault to repair, while
        an abstention, invalid evidence or an ambiguity is the policy layer
        deliberately declining to treat what it has as sufficient.
        """

        from prometheus_protocol.policy.coverage import (
            REFUSED_INCOMPLETE,
            REFUSED_UNSATISFACTORY,
            CoverageRefused,
            validate_coverage,
        )

        outcome = validate_coverage(snapshot, tuple(results))
        if isinstance(outcome, CoverageRefused):
            if outcome.reason == REFUSED_UNSATISFACTORY:
                return Judgment(
                    verdict=Verdict.FAIL,
                    confidence=1.0,
                    authoritative=True,
                    contributing=(outcome.check_id,),
                )
            reason = (
                Unavailability.INFRA_FAULT
                if outcome.reason == REFUSED_INCOMPLETE
                else Unavailability.POLICY_REFUSAL
            )
            return Unavailable(
                verifier_id="policy-coverage",
                tier=Tier.HARD,
                reason=reason,
                detail=f"{outcome.reason} check={outcome.check_id} {outcome.detail}".strip(),
            )

        # Coverage holds. Only now does anything get fused, and it is fused by
        # the SAME code path every other caller uses — a second aggregator here
        # would be the defect this sprint exists to remove, wearing a fix.
        return self.judge(outcome.graded)

    def judge(
        self, evidence: Sequence[Evidence | Unavailable]
    ) -> Judgment | Unavailable:
        # An Unavailable is NOT evidence: it is a verifier that could not execute,
        # and it must never be aggregated into a verdict. Separate it out by TYPE
        # before anything reads a ``.verdict`` — so no Unavailable can ever enter
        # the fusion below, by construction rather than by a forgotten guard.
        # Partitioned exhaustively rather than by two complementary
        # comprehensions. The comprehensions produced exactly these two lists
        # today, so nothing about aggregation changes here (that is Phase 1.2) —
        # but a filter drops anything that is neither member with no diagnostic,
        # and this is the one place where a dropped outcome would silently leave
        # a fusion. A third member now fails the build instead.
        graded, unavailable = partition_outcomes(evidence)

        for item in graded:
            self._observe(item)

        # Resolve each non-abstaining report to its verifier's persisted stats.
        # Classification and the prior both read the stored tier, so they can
        # never disagree.
        usable: list[tuple[Evidence, TrustStats]] = []
        for item in graded:
            if item.verdict == Verdict.ABSTAIN:
                continue
            usable.append((item, self._ensure_stats(item)))

        authoritative = [pair for pair in usable if pair[1].tier in AUTHORITATIVE_TIERS]
        advisory = [pair for pair in usable if pair[1].tier not in AUTHORITATIVE_TIERS]
        auth_unavailable = [u for u in unavailable if u.tier in AUTHORITATIVE_TIERS]

        if authoritative:
            # Authoritative truth is available; it decides the verdict. But an
            # authoritative verifier that could NOT execute alongside it is NOT
            # simply absent — it is an operational fault every time, and a sibling
            # covering for it does not make the non-execution a non-event. Carry it
            # on the Judgment (never drop it here) so a could-not-run HARD/HUMAN
            # verifier stays visible downstream, exactly like an unavailable that
            # stood alone. The verdict is still A's; only B's silence is refused.
            return self._authoritative_judgment(
                authoritative, advisory, unavailable=tuple(auth_unavailable)
            )
        if auth_unavailable:
            # No authoritative verdict is available AND an authoritative verifier
            # could not execute. Report the could-not-execute — never fall through
            # to a SOFT advisory verdict, which would silently stand in for a
            # HARD/HUMAN check that never ran (the exact defect EX-1 fixes). The
            # caller halts / routes to a human; it is never a pass, fail, or
            # abstention.
            return _merge_unavailable(auth_unavailable)
        if advisory:
            return self._advisory_judgment(advisory)
        # Nothing to go on: every report abstained, and no authoritative verifier
        # was unavailable. A genuine "no opinion".
        return Judgment(
            verdict=Verdict.ABSTAIN,
            confidence=0.5,
            authoritative=False,
        )

    def _authoritative_judgment(
        self,
        authoritative: list[tuple[Evidence, TrustStats]],
        advisory: list[tuple[Evidence, TrustStats]],
        *,
        unavailable: tuple[Unavailable, ...] = (),
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
        # ``decided`` states the __post_init__ guarantee that every constructed
        # Evidence carries a verdict, so the fusion calls below take a plain
        # ``Verdict``. This replaces the four ratcheted ``# type: ignore[arg-type]``
        # the EX-1 mypy baseline left here: the field is ``Verdict | None`` because
        # that is the CONSTRUCTOR's contract, and the ignores were standing in for
        # an invariant the type could not express. Nothing is defaulted — an
        # Evidence that somehow escaped __post_init__ raises rather than being
        # fused as a verdict nobody reached.
        ref_contributions = [(s, e.decided) for (e, s) in reference]
        ref_verdict, _ = fuse(ref_contributions)

        # Confidence additionally reflects every non-reference verifier, each
        # weighted by the trust it has earned: an agreeing advisor raises
        # confidence, a dissenting one lowers it, while the verdict stays put.
        # An un-audited verifier contributes a log-LR of ~0 (I7), so it moves
        # confidence negligibly until it has earned weight through calibration.
        all_contributions = ref_contributions + [(s, e.decided) for (e, s) in others]
        probability = p_pass(total_log_odds(all_contributions))
        confidence = probability if ref_verdict == Verdict.PASS else 1.0 - probability

        # Calibrate each non-reference verifier against the reference verdict.
        for e, s in others:
            self._store.put(
                e.verifier_id,
                updated(s, predicted=e.decided, actual=ref_verdict),
            )

        conflict = any(e.verdict != ref_verdict for e, _ in authoritative)
        return Judgment(
            verdict=ref_verdict,
            confidence=confidence,
            authoritative=True,
            contributing=tuple(e.verifier_id for e, _ in reference),
            conflict=conflict,
            unavailable=unavailable,
        )

    def _advisory_judgment(
        self, advisory: list[tuple[Evidence, TrustStats]]
    ) -> Judgment:
        # No authoritative reference is available, so we report the fused
        # advisory verdict but record no calibration (there is no ground truth).
        contributions = [(s, e.decided) for (e, s) in advisory]
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
