"""Action-authorization gate.

Where ``PromotionGate`` decides whether to keep a skill, ``ActionGate`` decides
whether a judged proposal may be executed. It lives in the gate package and
reuses ``GateDecision``; it does not fork the gate.

Only verified, authoritative truth above a risk-dependent confidence bar may
authorize an action — this is the judge side of the wall.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Mapping

from prometheus_protocol.core.models import (
    ExecutableAction,
    Judgment,
    Unavailable,
    Verdict,
)

if TYPE_CHECKING:  # pragma: no cover - import cycle: policy imports core.models
    from prometheus_protocol.policy.assessment import PolicyAssessment
from prometheus_protocol.gate.promotion import (
    OUTCOME_APPROVE,
    OUTCOME_BLOCK,
    OUTCOME_ROUTE,
    GateDecision,
)

# A could-not-execute authorization outcome, kept here (not in the frozen
# promotion module) as a distinct terminal state. An authoritative verifier
# could not run, so there is no verdict to authorize on: it NEVER approves
# (``approved`` stays False, so the wall is unchanged) and it is deliberately
# neither ``block`` (which would misreport a harness fault as a policy denial)
# nor ``route`` (which means "a PASS too uncertain to auto-approve"). It routes
# to a human hold and is recorded distinctly, so an unavailable is forever
# separable in the ledger from an ordinary denial or a genuine abstention.
OUTCOME_UNAVAILABLE = "unavailable"

# Minimum confidence required to authorize an action, by risk class. A higher
# risk demands a more confident judgment.
_DEFAULT_MIN_CONFIDENCE: dict[str, float] = {
    "low": 0.0,
    "medium": 0.75,
    "high": 0.9,
}


class ActionGate:
    """Authorizes an action from a single judgment.

    Routing is opt-in and additive. Constructed bare (``ActionGate()``) the gate
    is a pure binary authorizer, exactly as before: an authoritative PASS at or
    above the risk floor is approved, everything else is blocked. When
    ``escalate_below`` and/or ``route_high_risk`` are supplied, it additionally
    *routes* — an authoritative PASS that is too uncertain, below the floor, or
    high-risk is neither approved nor blocked but held for a human. Routing never
    changes verdict semantics or the load-bearing ``approved`` field: a routed
    or blocked decision is always ``approved=False`` and cannot reach execution.
    """

    def __init__(
        self,
        *,
        min_confidence: Mapping[str, float] | None = None,
        escalate_below: float | None = None,
        route_high_risk: bool = False,
    ) -> None:
        self._min_confidence = dict(
            _DEFAULT_MIN_CONFIDENCE if min_confidence is None else min_confidence
        )
        self._escalate_below = escalate_below
        self._route_high_risk = route_high_risk

    def decide(
        self,
        assessment: "PolicyAssessment",
        *,
        risk_class: str = "low",
        subject_id: str = "",
        action: ExecutableAction | None = None,
    ) -> GateDecision:
        """Authorize an action from a POLICY-EVALUATED, ACTION-BOUND assessment.

        PHASE-1.2b — this parameter used to be a ``Judgment``. It is not one
        anymore, and that is the whole change: a raw authoritative verdict says
        what the evidence showed and can say nothing about whether a policy
        required that evidence, so a gate that reads one is enforcing a policy it
        never consulted. There is no longer a parameter through which an unbound
        judgment can arrive; presenting one raises
        :class:`~prometheus_protocol.policy.assessment.UnboundAuthorization`
        rather than returning an unapproved decision, because a falsy return is
        something a caller could read as a policy denial.

        WHAT THIS METHOD READS, AND WHAT IT IGNORES. It reads
        ``assessment.outcome``. It reads nothing else. ``action`` is carried into
        the returned decision and is never compared with
        ``assessment.artifact_sha256`` or ``assessment.action_class``, and
        ``snapshot_digest`` is not compared with anything at all. Measured
        consequences, both reproduced in ``tests/conformance/``: an assessment
        resolved for artifact A returns ``approved=True`` for an action running
        unrelated code B, and an assessment whose ``action_class`` is
        ``sandbox.execute`` returns ``approved=True`` for a
        ``git_delete_branch`` action. The parameter type is therefore a proof
        that SOME policy was evaluated, not a proof it was evaluated for THIS
        action. ``docs/execution-descriptor.md`` is the seam that closes it.
        """

        from prometheus_protocol.policy.assessment import require_assessment

        judgment = require_assessment(assessment, surface="ActionGate.decide").outcome
        if isinstance(judgment, Unavailable):
            # An authoritative verifier could NOT execute: there is no verdict to
            # authorize on. Never approve; route to a human hold via the distinct
            # terminal outcome above — never a silent block, and never a pass.
            return GateDecision(
                approved=False,
                subject_id=subject_id,
                judgment=None,
                reason=(
                    f"unavailable: an authoritative check could not execute "
                    f"({judgment.reason.value}: {judgment.detail}); routed to a human"
                ),
                outcome=OUTCOME_UNAVAILABLE,
                action=action,
            )
        floor = self._min_confidence.get(risk_class, 0.0)
        outcome = self._outcome(judgment, risk_class=risk_class, floor=floor)
        return GateDecision(
            approved=(outcome == OUTCOME_APPROVE),
            subject_id=subject_id,
            judgment=judgment,
            reason=_reason(judgment, risk_class, floor, outcome),
            outcome=outcome,
            action=action,
        )

    def _routing_enabled(self) -> bool:
        return self._escalate_below is not None or self._route_high_risk

    def _outcome(self, judgment: Judgment, *, risk_class: str, floor: float) -> str:
        passes = judgment.verdict == Verdict.PASS and judgment.authoritative
        # A non-PASS or non-authoritative judgment is always blocked: a human is
        # never asked to rubber-stamp a failure or an ungrounded claim.
        if not passes:
            return OUTCOME_BLOCK
        # An authoritative PASS below the risk floor is not auto-authorizable.
        # With routing on it is held for a human; otherwise it is the legacy
        # confidence denial (blocked).
        if judgment.confidence < floor:
            return OUTCOME_ROUTE if self._routing_enabled() else OUTCOME_BLOCK
        # At/above the floor: high risk always halts for a human when routing is
        # on, and so does a confidence below the escalation bar.
        if self._route_high_risk and risk_class == "high":
            return OUTCOME_ROUTE
        if self._escalate_below is not None and judgment.confidence < self._escalate_below:
            return OUTCOME_ROUTE
        return OUTCOME_APPROVE


def _reason(
    judgment: Judgment, risk_class: str, floor: float, outcome: str
) -> str:
    if outcome == OUTCOME_APPROVE:
        return (
            f"authorized: {judgment.verdict.value} verdict, authoritative, "
            f"confidence {judgment.confidence:.2f} >= {floor:.2f} ({risk_class} risk)"
        )
    if outcome == OUTCOME_ROUTE:
        return (
            f"routed to a human: {judgment.verdict.value} verdict, "
            f"confidence {judgment.confidence:.2f} ({risk_class} risk) needs review"
        )
    if judgment.verdict != Verdict.PASS:
        return f"blocked: verdict is {judgment.verdict.value}, not pass"
    if not judgment.authoritative:
        return "blocked: judgment is not authoritative"
    return (
        f"blocked: confidence {judgment.confidence:.2f} below the {risk_class} "
        f"risk floor {floor:.2f}"
    )
