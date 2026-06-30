"""Deterministic, offline provider used as the default.

HONEST DESCRIPTION: ``MockProvider`` is a SIMULATION of a model in the loop,
not a model. It carries a small "solution book" that maps each known entry
point to two canned implementations: a *baseline* that overlooks an edge
case, and an *improved* one that handles it. The provider returns the
improved implementation only when a retrieved skill is relevant to the prompt
(one of the skill's triggers appears in the prompt text).

This reproduces, deterministically and without any network or API key, the
property the runtime is built to exploit: that a relevant retrieved skill
makes a better solution reachable. It exercises the plumbing end to end; it
says nothing about the quality of any real model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

from prometheus_protocol.core.interfaces import Provider
from prometheus_protocol.core.models import Skill

# A deterministic stand-in for open-ended generation. Given (prompt, system) it
# returns scripted text, so swarm reasoning roles produce reproducible proposals
# offline. ``None`` means "no scripted generation" (generation returns "").
Responder = Callable[[str, "str | None"], str]


@dataclass(frozen=True)
class MockSolution:
    """Two canned implementations for one entry point."""

    baseline: str
    improved: str


SolutionBook = Mapping[str, MockSolution]


class MockProvider(Provider):
    """Offline simulation of a proposer. See module docstring."""

    def __init__(
        self,
        book: SolutionBook | None = None,
        *,
        responder: Responder | None = None,
    ) -> None:
        self._book: dict[str, MockSolution] = dict(book or {})
        self._responder = responder

    def propose_solution(
        self,
        *,
        prompt: str,
        entry_point: str,
        skills: Sequence[Skill] = (),
    ) -> str:
        solution = self._book.get(entry_point)
        if solution is None:
            return _stub(entry_point)
        if _has_relevant_skill(prompt, skills):
            return solution.improved
        return solution.baseline

    def generate(self, *, prompt: str, system: str | None = None) -> str:
        # Deterministic, offline generation for swarm reasoning roles. Without a
        # responder there is no scripted output, so generation is empty (a role
        # then produces no proposal — graceful degradation).
        if self._responder is None:
            return ""
        return self._responder(prompt, system)


def _has_relevant_skill(prompt: str, skills: Sequence[Skill]) -> bool:
    text = prompt.lower()
    for skill in skills:
        for trigger in skill.triggers:
            if trigger and trigger.lower() in text:
                return True
    return False


def _stub(entry_point: str) -> str:
    return f"def {entry_point}(*args, **kwargs):\n    raise NotImplementedError\n"
