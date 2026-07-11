"""Tier-tagged inter-agent messages — the piece that stops silent compounding.

When one agent step's output is handed to a dependent step, it is NOT handed
over as a trusted fact. It is handed over as an :class:`AgentMessage`: a
graded proposal that carries *who* produced it, *at what tier* it was graded
(HARD/SOFT/…), *with what confidence and verdict*, and a content hash for
provenance. A downstream agent receives "step A claims X, tier=SOFT,
confidence=0.6" — never "X is true".

This is enforced structurally, not by discipline: a dependent step's inputs
are typed ``tuple[AgentMessage, ...]``, and an ``AgentMessage`` cannot be
constructed without a real :class:`Tier` and a :class:`Verdict` — there is no
constructor that yields a bare, untiered assertion. So the ONLY thing that can
travel agent-to-agent is a claim that already wears its own grading. An error
in an upstream step arrives downstream visibly discounted, not laundered into
fact.

The message carries a *per-step* confidence, not a composed chain confidence:
composing confidence across dependent steps is an unsolved problem and is left
to the orchestrator to record (conservatively) and to a future sprint to
solve. See ``docs/orchestration.md``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from prometheus_protocol.core.models import Judgment, Tier, Verdict


def content_hash(text: str) -> str:
    """Deterministic provenance hash for a message's content."""

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AgentMessage:
    """A graded claim passed from one workflow step to its dependents.

    Every field that makes it a *claim rather than a fact* is required: the
    grading ``tier``, the ``verdict``, and the ``confidence`` have no defaults,
    so a message cannot exist without them. Construct these through
    :meth:`graded` in the runtime, which sources the grade from the verifier
    bank — never from the proposing agent itself.
    """

    workflow_id: str
    from_step: str
    from_agent: str
    content: str
    tier: Tier
    verdict: Verdict
    confidence: float
    provenance: str

    def __post_init__(self) -> None:
        # The structural guarantee: no message without a genuine tier + verdict.
        if not isinstance(self.tier, Tier):
            raise TypeError(
                "AgentMessage.tier must be a Tier — an inter-agent message "
                "cannot be an untiered assertion of fact"
            )
        if not isinstance(self.verdict, Verdict):
            raise TypeError("AgentMessage.verdict must be a Verdict")
        if not (0.0 <= float(self.confidence) <= 1.0):
            raise ValueError("AgentMessage.confidence must be in [0, 1]")

    @classmethod
    def graded(
        cls,
        *,
        workflow_id: str,
        from_step: str,
        from_agent: str,
        content: str,
        tier: Tier,
        judgment: Judgment,
    ) -> "AgentMessage":
        """Build a message from an authoritative-or-advisory bank judgment.

        The runtime uses this after the verifier bank has graded the step's
        output, so the tier and confidence a downstream agent sees are the
        bank's, not the proposing agent's self-report.
        """

        return cls(
            workflow_id=workflow_id,
            from_step=from_step,
            from_agent=from_agent,
            content=content,
            tier=tier,
            verdict=judgment.verdict,
            confidence=judgment.confidence,
            provenance=content_hash(content),
        )

    def summary(self) -> str:
        """One-line human rendering: who claimed what, at what tier/confidence."""

        return (
            f"{self.from_step}/{self.from_agent} claims "
            f"[{self.tier.value} · {self.verdict.value} · {self.confidence:.2f}]: "
            f"{self.content!r}"
        )
