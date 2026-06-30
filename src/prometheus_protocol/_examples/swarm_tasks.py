"""Deterministic, offline swarm reasoning fixtures.

Mirrors the role/skeptic prompts with scripted replies so a swarm run is fully
reproducible against the mock provider — roles reason, the skeptic emits
executable cases — with no network or API key. With a real remote provider the
same roles reason for real; this module only supplies the offline simulation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Sequence

from prometheus_protocol.provider.mock import MockProvider, MockSolution
from prometheus_protocol.swarm.models import TaskPacket
from prometheus_protocol.swarm.prompts import REASONING_SYSTEM, SKEPTIC_SYSTEM

_ENTRY_POINT = re.compile(r"Function to implement:\s*([A-Za-z_]\w*)")


@dataclass(frozen=True)
class CodeTask:
    """An offline code-domain task: a goal, candidate code, and skeptic cases."""

    entry_point: str
    goal: str
    code: str
    cases: tuple[tuple[tuple, object], ...]

    def packet(self, *, budget: int = 5, risk_class: str = "low") -> TaskPacket:
        return TaskPacket(
            goal=self.goal,
            budget=budget,
            risk_class=risk_class,
            entry_point=self.entry_point,
        )


class _SwarmResponder:
    """Scripted generation: role from the system prompt, cases from the book."""

    def __init__(self, cases_by_entry_point: dict[str, tuple]) -> None:
        self._cases = dict(cases_by_entry_point)

    def __call__(self, prompt: str, system: str | None) -> str:
        if system == SKEPTIC_SYSTEM:
            match = _ENTRY_POINT.search(prompt)
            cases = self._cases.get(match.group(1), ()) if match else ()
            return "\n".join(
                f"CASE: {json.dumps(list(args))} -> {json.dumps(expected)}"
                for args, expected in cases
            )
        if system == REASONING_SYSTEM["planner"]:
            return (
                "CONTENT: Take the next concrete step toward the goal.\n"
                "RATIONALE: It advances the goal within the budget and constraints."
            )
        if system == REASONING_SYSTEM["analyst"]:
            return (
                "CONTENT: The goal is reachable within the stated budget.\n"
                "RATIONALE: Derived from the goal and constraints in the packet."
            )
        return ""


def build_swarm_provider(code_tasks: Sequence[CodeTask] = ()) -> MockProvider:
    """A mock provider scripted for swarm roles (reasoning + executable cases)."""

    book = {t.entry_point: MockSolution(baseline=t.code, improved=t.code) for t in code_tasks}
    cases = {t.entry_point: t.cases for t in code_tasks}
    return MockProvider(book=book, responder=_SwarmResponder(cases))


def correct_code_task() -> CodeTask:
    """A correct candidate that satisfies the skeptic's cases (gets approved)."""

    return CodeTask(
        entry_point="add",
        goal="Implement add(a, b) returning the sum of two integers.",
        code="def add(a, b):\n    return a + b\n",
        cases=(((1, 2), 3), ((0, 0), 0), ((-1, 5), 4)),
    )


def buggy_code_task() -> CodeTask:
    """A buggy candidate that fails a skeptic case (cannot be approved)."""

    return CodeTask(
        entry_point="add",
        goal="Implement add(a, b) returning the sum of two integers.",
        code="def add(a, b):\n    return a - b\n",  # wrong: subtracts
        cases=(((1, 2), 3), ((0, 0), 0)),
    )
