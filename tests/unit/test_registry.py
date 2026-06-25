"""Unit tests for the markdown skill registry."""

from __future__ import annotations

from prometheus_protocol.core.models import Skill
from prometheus_protocol.registry.markdown_registry import (
    MarkdownSkillRegistry,
    markdown_to_skill,
    skill_to_markdown,
)


def _skill() -> Skill:
    return Skill(
        id="skill-empty-input",
        title="Guard against empty input",
        body="# Guard\n\nCheck for empty sequences.",
        triggers=("empty",),
        tags=("empty-input",),
        source="forge",
    )


def test_markdown_round_trip():
    skill = _skill()
    restored = markdown_to_skill(skill_to_markdown(skill))
    assert restored == skill


def test_add_get_all_and_remove(tmp_path):
    registry = MarkdownSkillRegistry(tmp_path)
    skill = _skill()
    registry.add(skill)
    assert registry.get(skill.id) == skill
    assert registry.all() == [skill]
    assert (tmp_path / "skill-empty-input.md").exists()

    registry.remove(skill.id)
    assert registry.get(skill.id) is None
    assert registry.all() == []
    # Removing a missing skill is a no-op, not an error.
    registry.remove(skill.id)


def test_retrieve_matches_on_trigger(tmp_path):
    registry = MarkdownSkillRegistry(tmp_path)
    registry.add(_skill())
    assert [s.id for s in registry.retrieve("return the mean of an empty list")] == [
        "skill-empty-input"
    ]
    assert registry.retrieve("return the sum of two numbers") == []


def test_retrieve_respects_k(tmp_path):
    registry = MarkdownSkillRegistry(tmp_path)
    for i in range(3):
        registry.add(
            Skill(id=f"s{i}", title="t", body="b", triggers=("alpha",), tags=())
        )
    assert len(registry.retrieve("alpha alpha", k=2)) == 2
