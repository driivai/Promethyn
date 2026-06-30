"""Swarm roles: the proposer side, now reasoning via the model provider.

Roles receive only the ``TaskPacket`` and a proposer-side ``ProposerContext``
(the packet plus the proposals produced so far). They never see held-out task
labels or verifier internals — that is the firewall, preserved by the type of
the input (INV-SWARM-6). Roles only ever return ``Proposal`` objects; they
assert no truth.

Reasoning is model-backed: a role builds a role-specific prompt from the packet
and proposer-side context only, calls the provider, and validates the reply
into typed proposals. A malformed or unparseable reply (or a missing provider)
yields NO proposal — a role degrades gracefully and never lets an unvalidated
object cross the wall. The provider is injected at construction, so the
``propose(packet, context)`` signature is unchanged.

``Skeptic`` and ``PolicyReviewer`` are mandatory and non-removable; the
framework injects them (see ``synthesis``). The Skeptic keeps its cheap
structural checks and, in the code domain, additionally asks the model for
executable falsification cases that the HARD subprocess verifier runs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Mapping, Sequence

from prometheus_protocol.core.interfaces import Provider
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
from prometheus_protocol.swarm.prompts import (
    build_reasoning_prompt,
    build_skeptic_prompt,
    parse_cases,
    parse_reasoning,
)


@dataclass(frozen=True)
class ProposerContext:
    """Everything the proposer side is allowed to see. No judged artifacts."""

    packet: TaskPacket
    proposals: tuple[Proposal, ...] = ()
    notes: Mapping[str, str] = field(default_factory=dict)


class Role(ABC):
    """A proposer. Produces proposals; never a judgment or a decision.

    A model-backed role holds an injected ``provider`` and calls it inside
    ``propose``. ``provider`` may be ``None`` (no model wired): the role then
    produces no proposal rather than a placeholder.
    """

    id: str = "role"
    kind: str = KIND_HYPOTHESIS
    mandatory: bool = False

    def __init__(self, provider: Provider | None = None) -> None:
        self.provider = provider

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


def _packet_input(packet: TaskPacket) -> str:
    return f"packet:{content_hash(packet.goal)[:12]}"


def _safe_generate(
    provider: Provider, *, prompt: str, system: str | None
) -> str | None:
    """Call the provider, returning ``None`` on any failure (degrade, never crash)."""

    try:
        text = provider.generate(prompt=prompt, system=system)
    except Exception:
        return None
    return text if isinstance(text, str) else None


def _reason(role: Role, packet: TaskPacket) -> list[Proposal]:
    """Build a reasoning proposal from a model reply, or none if malformed."""

    if role.provider is None:
        return []
    system, user = build_reasoning_prompt(role.id, packet)
    text = _safe_generate(role.provider, prompt=user, system=system)
    if text is None:
        return []
    parsed = parse_reasoning(text)
    if parsed is None:
        return []  # malformed reply: no proposal crosses the wall
    content, rationale = parsed
    return [
        _make_proposal(
            role.id, role.kind, content, rationale, inputs=(_packet_input(packet),)
        )
    ]


# --------------------------------------------------------------------------
# Model-backed optional roles.
# --------------------------------------------------------------------------


class PlannerRole(Role):
    """Proposes the next action. In the code domain it proposes candidate code."""

    id = "planner"
    kind = KIND_PROPOSED_ACTION

    def propose(self, packet: TaskPacket, context: ProposerContext) -> list[Proposal]:
        if self.provider is None:
            return []
        if packet.entry_point:
            # Code domain: reuse the actor's code-generation method.
            try:
                code = self.provider.propose_solution(
                    prompt=packet.goal, entry_point=packet.entry_point
                )
            except Exception:
                return []
            if not isinstance(code, str) or not code.strip():
                return []
            rationale = f"Candidate implementation of {packet.entry_point}()."
            return [
                _make_proposal(
                    self.id,
                    KIND_PROPOSED_ACTION,
                    code,
                    rationale,
                    inputs=(_packet_input(packet),),
                )
            ]
        return _reason(self, packet)


class AnalystRole(Role):
    """States a testable hypothesis about the task."""

    id = "analyst"
    kind = KIND_HYPOTHESIS

    def propose(self, packet: TaskPacket, context: ProposerContext) -> list[Proposal]:
        return _reason(self, packet)


def default_optional_roles(provider: Provider | None = None) -> list[Role]:
    return [PlannerRole(provider), AnalystRole(provider)]


# --------------------------------------------------------------------------
# Mandatory, non-removable roles.
# --------------------------------------------------------------------------


def _structural_checks(proposal: Proposal) -> tuple[FalsificationCheck, ...]:
    """Cheap, deterministic checks every primary proposal must survive."""

    return (
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


class Skeptic(Role):
    """Attaches falsification checks to every non-critique proposal.

    Always attaches cheap structural checks. In the code domain it additionally
    asks the model for executable input/output cases and attaches them as an
    executable check, so an action's veto is wired to real verification.
    """

    id = "skeptic"
    kind = KIND_CRITIQUE
    mandatory = True

    def propose(self, packet: TaskPacket, context: ProposerContext) -> list[Proposal]:
        critiques: list[Proposal] = []
        for proposal in context.proposals:
            if proposal.kind == KIND_CRITIQUE:
                continue
            checks: list[FalsificationCheck] = list(_structural_checks(proposal))
            executable = self._executable_check(packet, proposal)
            if executable is not None:
                checks.append(executable)
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

    def _executable_check(
        self, packet: TaskPacket, proposal: Proposal
    ) -> FalsificationCheck | None:
        # Executable cases only apply to a code action in a code-domain task.
        if (
            self.provider is None
            or not packet.entry_point
            or proposal.kind != KIND_PROPOSED_ACTION
        ):
            return None
        system, user = build_skeptic_prompt(packet, proposal)
        text = _safe_generate(self.provider, prompt=user, system=system)
        if text is None:
            return None
        cases = parse_cases(text)
        if not cases:
            return None  # nothing runnable: structural checks still apply
        return FalsificationCheck(
            id=f"falsify/{proposal.id}/cases",
            description=f"candidate must satisfy {len(cases)} skeptic case(s)",
            predicate="executable_cases",
            entry_point=packet.entry_point,
            cases=tuple(cases),
        )


class PolicyReviewer(Role):
    """Attaches a deterministic policy check to every proposed action.

    Policy compliance is a rule, not a model opinion, so this check stays
    deterministic (it does not call the provider).
    """

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
