"""Action-authorization gate.

Where ``PromotionGate`` decides whether to keep a skill, ``ActionGate`` decides
whether a judged proposal may be executed. It lives in the gate package and
reuses ``GateDecision``; it does not fork the gate.

Only verified, authoritative truth above a risk-dependent confidence bar may
authorize an action — this is the judge side of the wall.
"""

from __future__ import annotations

from typing import Mapping

from prometheus_protocol.core.models import Judgment, Verdict
from prometheus_protocol.gate.promotion import GateDecision

# Minimum confidence required to authorize an action, by risk class. A higher
# risk demands a more confident judgment.
_DEFAULT_MIN_CONFIDENCE: dict[str, float] = {
    "low": 0.0,
    "medium": 0.75,
    "high": 0.9,
}


class ActionGate:
    """Authorizes an action from a single judgment."""

    def __init__(self, *, min_confidence: Mapping[str, float] | None = None) -> None:
        self._min_confidence = dict(
            _DEFAULT_MIN_CONFIDENCE if min_confidence is None else min_confidence
        )

    def decide(
        self,
        judgment: Judgment,
        *,
        risk_class: str = "low",
        subject_id: str = "",
    ) -> GateDecision:
        floor = self._min_confidence.get(risk_class, 0.0)
        approved = (
            judgment.verdict == Verdict.PASS
            and judgment.authoritative
            and judgment.confidence >= floor
        )
        return GateDecision(
            approved=approved,
            subject_id=subject_id,
            judgment=judgment,
            reason=_reason(judgment, risk_class, floor, approved),
        )


def _reason(
    judgment: Judgment, risk_class: str, floor: float, approved: bool
) -> str:
    if approved:
        return (
            f"authorized: {judgment.verdict.value} verdict, authoritative, "
            f"confidence {judgment.confidence:.2f} >= {floor:.2f} ({risk_class} risk)"
        )
    if judgment.verdict != Verdict.PASS:
        return f"denied: verdict is {judgment.verdict.value}, not pass"
    if not judgment.authoritative:
        return "denied: judgment is not authoritative"
    return (
        f"denied: confidence {judgment.confidence:.2f} below the {risk_class} "
        f"risk floor {floor:.2f}"
    )
