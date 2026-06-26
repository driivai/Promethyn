"""Swarm roles: the proposer side.

Roles receive only the ``TaskPacket`` and a proposer-side ``ProposerContext``
(the packet plus the proposals produced so far). They never see held-out task
labels or verifier internals — that is the firewall, preserved by the type of
the input. Roles only ever return ``Proposal`` objects; they assert no truth.

``Skeptic`` and ``PolicyReviewer`` are mandatory and non-removable; the
framework injects them (see ``synthesis``).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Mapping, Sequence

from prometheus_protocol.swarm.models import (
    KIND_CRITIQUE,
    KIND_HYPOTHESIS,
    KIND_PROPOSED_ACTION,
    FalsificationCheck,
    Proposal,
    Provenance,
    TaskPacket,
    content_hash,
)


@dataclass(frozen=True)
class ProposerContext:
    """Everything the proposer side is allowed to see. No judged artifacts."""

    packet: TaskPacket
    proposals: tuple[Proposal, ...] = ()
    notes: Mapping[str, str] = field(default_factory=dict)


class Role(ABC):
    """A proposer. Produces proposals; never a judgment or a decision."""

    id: str = "role"
    kind: str = KIND_HYPOTHESIS
    mandatory: bool = False

    @abstractmethod
    def propose(self, packet: TaskPacket, context: ProposerContext) -> list[Proposal]:
        raise NotImplementedError


def _make_proposal(
    role_id: str,
    kind: str,
    content: str,
    rationale: str,
    *,
    inputs: Sequence[str] = (),
    checks: Sequence[FalsificationCheck] = (),
) -> Proposal:
    digest = content_hash(content)
    return Proposal(
        id=f"{role_id}/{kind}/{digest[:8]}",
        role_id=role_id,
        kind=kind,
        content=content,
        rationale=rationale,
        provenance=Provenance(content_hash=digest, inputs=tuple(inputs)),
        falsification_checks=tuple(checks),
    )


# --------------------------------------------------------------------------
# Simple deterministic optional roles.
# --------------------------------------------------------------------------


class PlannerRole(Role):
    id = "planner"
    kind = KIND_PROPOSED_ACTION

    def propose(self, packet: TaskPacket, context: ProposerContext) -> list[Proposal]:
        content = f"Take the next step toward: {packet.goal}"
        rationale = (
            "Advances the stated goal directly while respecting the declared "
            f"constraints ({', '.join(packet.constraints) or 'none'})."
        )
        return [_make_proposal(self.id, KIND_PROPOSED_ACTION, content, rationale)]


class AnalystRole(Role):
    id = "analyst"
    kind = KIND_HYPOTHESIS

    def propose(self, packet: TaskPacket, context: ProposerContext) -> list[Proposal]:
        content = f"The goal is reachable within the given budget: {packet.goal}"
        rationale = "A working hypothesis derived from the packet goal and budget."
        return [_make_proposal(self.id, KIND_HYPOTHESIS, content, rationale)]


def default_optional_roles() -> list[Role]:
    return [PlannerRole(), AnalystRole()]


# --------------------------------------------------------------------------
# Mandatory, non-removable roles.
# --------------------------------------------------------------------------


class Skeptic(Role):
    """Attaches falsification checks to every non-critique proposal."""

    id = "skeptic"
    kind = KIND_CRITIQUE
    mandatory = True

    def propose(self, packet: TaskPacket, context: ProposerContext) -> list[Proposal]:
        critiques: list[Proposal] = []
        for proposal in context.proposals:
            if proposal.kind == KIND_CRITIQUE:
                continue
            checks = (
                FalsificationCheck(
                    id=f"falsify/{proposal.id}/content",
                    description="proposal must have content",
                    predicate="non_empty_content",
                ),
                FalsificationCheck(
                    id=f"falsify/{proposal.id}/rationale",
                    description="proposal must state a rationale",
                    predicate="states_rationale",
                ),
            )
            content = f"Critique of {proposal.id}: attach falsification checks."
            rationale = (
                "A proposal that cannot survive concrete falsification checks is "
                "unsound."
            )
            critiques.append(
                _make_proposal(
                    self.id,
                    KIND_CRITIQUE,
                    content,
                    rationale,
                    inputs=(proposal.id,),
                    checks=checks,
                )
            )
        return critiques


class PolicyReviewer(Role):
    """Attaches a policy check to every proposed action."""

    id = "policy-reviewer"
    kind = KIND_CRITIQUE
    mandatory = True

    def propose(self, packet: TaskPacket, context: ProposerContext) -> list[Proposal]:
        critiques: list[Proposal] = []
        for proposal in context.proposals:
            if proposal.kind != KIND_PROPOSED_ACTION:
                continue
            checks = (
                FalsificationCheck(
                    id=f"policy/{proposal.id}",
                    description="proposed action must be policy-compliant",
                    predicate="policy_compliant",
                ),
            )
            content = f"Policy review of {proposal.id}."
            rationale = (
                "Proposed actions must satisfy policy before they may be "
                "authorized."
            )
            critiques.append(
                _make_proposal(
                    self.id,
                    KIND_CRITIQUE,
                    content,
                    rationale,
                    inputs=(proposal.id,),
                    checks=checks,
                )
            )
        return critiques
