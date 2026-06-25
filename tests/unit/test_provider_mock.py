"""Unit tests for the simulated provider.

These pin the simulation's contract: a relevant retrieved skill (one whose
trigger appears in the prompt) unlocks the improved implementation; otherwise
the baseline is returned.
"""

from __future__ import annotations

from prometheus_protocol.core.models import Skill
from prometheus_protocol.provider.mock import MockProvider, MockSolution

BOOK = {
    "f": MockSolution(
        baseline="def f(xs):\n    return xs[0]\n",
        improved="def f(xs):\n    return None if not xs else xs[0]\n",
    )
}


def test_baseline_when_no_skills():
    provider = MockProvider(BOOK)
    code = provider.propose_solution(
        prompt="first element, or None if empty", entry_point="f", skills=()
    )
    assert code == BOOK["f"].baseline


def test_improved_when_relevant_skill_present():
    provider = MockProvider(BOOK)
    skill = Skill(id="s", title="t", body="b", triggers=("empty",))
    code = provider.propose_solution(
        prompt="first element, or None if empty", entry_point="f", skills=[skill]
    )
    assert code == BOOK["f"].improved


def test_skill_irrelevant_to_prompt_is_ignored():
    provider = MockProvider(BOOK)
    skill = Skill(id="s", title="t", body="b", triggers=("empty",))
    code = provider.propose_solution(
        prompt="return the first element", entry_point="f", skills=[skill]
    )
    assert code == BOOK["f"].baseline


def test_unknown_entry_point_returns_stub():
    provider = MockProvider(BOOK)
    code = provider.propose_solution(prompt="x", entry_point="ghost", skills=())
    assert "ghost" in code
    assert "NotImplementedError" in code
