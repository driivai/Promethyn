"""Role prompt builders and reply parsers for the proposer side.

Roles turn a ``TaskPacket`` plus proposer-side context into a provider request,
and parse the reply into typed proposal material. These functions are pure (no
I/O): a role calls the provider with the strings built here and validates the
result with the parsers here. Parsing is strict — an unparseable reply yields
``None`` / no cases, so a malformed model reply never becomes a proposal that
crosses the wall.

Roles receive only the packet and proposer-side context, never held-out task
labels or verifier internals (INV-SWARM-6).
"""

from __future__ import annotations

import json
from typing import Sequence

from prometheus_protocol.core.models import Case
from prometheus_protocol.swarm.models import Proposal, TaskPacket

# Reply markers the roles ask the model to use and the parsers read back.
_CONTENT = "CONTENT:"
_RATIONALE = "RATIONALE:"
_CASE = "CASE:"

REASONING_SYSTEM = {
    "planner": (
        "You are the planner role of a reasoning swarm. Propose the single next "
        "action that best advances the goal while respecting the constraints. "
        "You assert no truth; a separate verifier judges you."
    ),
    "analyst": (
        "You are the analyst role of a reasoning swarm. State one clear, testable "
        "hypothesis about the task. You assert no truth; a separate verifier "
        "judges you."
    ),
}

_REASONING_FORMAT = (
    "Reply in exactly two lines and nothing else:\n"
    f"{_CONTENT} <one concise line>\n"
    f"{_RATIONALE} <one concise line>"
)

SKEPTIC_SYSTEM = (
    "You are the skeptic role of a reasoning swarm. Given a candidate that "
    "implements a function, propose concrete input/output test cases that would "
    "expose it as wrong. You assert no verdict; the cases are run by an "
    "independent verifier."
)


def _task_framing(packet: TaskPacket) -> str:
    lines = [f"Goal: {packet.goal}"]
    if packet.context:
        lines.append(f"Context: {packet.context}")
    if packet.constraints:
        lines.append("Constraints: " + "; ".join(packet.constraints))
    if packet.entry_point:
        lines.append(f"Function to implement: {packet.entry_point}")
    return "\n".join(lines)


def build_reasoning_prompt(role_id: str, packet: TaskPacket) -> tuple[str, str]:
    """Return ``(system, user)`` for a reasoning role (planner / analyst)."""

    system = REASONING_SYSTEM.get(role_id, REASONING_SYSTEM["analyst"])
    user = f"{_task_framing(packet)}\n\n{_REASONING_FORMAT}"
    return system, user


def build_skeptic_prompt(packet: TaskPacket, target: Proposal) -> tuple[str, str]:
    """Return ``(system, user)`` asking for executable falsification cases."""

    user = (
        f"{_task_framing(packet)}\n\n"
        f"Candidate implementation of {packet.entry_point}:\n{target.content}\n\n"
        "Propose input/output cases that a correct implementation must satisfy. "
        "Reply one case per line and nothing else, JSON on each side:\n"
        f"{_CASE} [arg1, arg2, ...] -> <expected>"
    )
    return SKEPTIC_SYSTEM, user


def _field(text: str, marker: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped[: len(marker)].upper() == marker:
            return stripped[len(marker):].strip()
    return ""


def parse_reasoning(text: str) -> tuple[str, str] | None:
    """Parse a reasoning reply into ``(content, rationale)`` or ``None``.

    Both fields must be present and non-empty; anything else is malformed and
    yields no proposal.
    """

    content = _field(text, _CONTENT)
    rationale = _field(text, _RATIONALE)
    if not content or not rationale:
        return None
    return content, rationale


def parse_cases(text: str) -> list[Case]:
    """Parse ``CASE: [args] -> expected`` lines into :class:`Case` objects.

    Each side is JSON. Malformed lines are skipped; ``args`` must be a JSON
    list. An empty result means no runnable case (the executable check ABSTAINs).
    """

    cases: list[Case] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line[: len(_CASE)].upper() != _CASE or "->" not in line:
            continue
        left, _, right = line[len(_CASE):].partition("->")
        try:
            args = json.loads(left.strip())
            expected = json.loads(right.strip())
        except (ValueError, TypeError):
            continue
        if not isinstance(args, list):
            continue
        cases.append(Case(args=tuple(args), expected=expected))
    return cases


def case_descriptions(cases: Sequence[Case]) -> str:
    return ", ".join(f"{c.args!r}->{c.expected!r}" for c in cases)
