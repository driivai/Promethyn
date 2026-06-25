"""Skill registry backed by a folder of markdown documents.

Each skill is a single ``.md`` file with a small key/value header fenced by
``---`` lines, followed by the markdown body. The format is deliberately
plain text: skills are meant to be read, reviewed, and edited by humans, and
to diff cleanly in version control.
"""

from __future__ import annotations

from pathlib import Path

from prometheus_protocol.core.interfaces import Registry
from prometheus_protocol.core.models import Skill

_FENCE = "---"


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def skill_to_markdown(skill: Skill) -> str:
    header = [
        _FENCE,
        f"id: {skill.id}",
        f"title: {skill.title}",
        f"triggers: {', '.join(skill.triggers)}",
        f"tags: {', '.join(skill.tags)}",
        f"source: {skill.source}",
        _FENCE,
        "",
    ]
    body = skill.body.rstrip("\n")
    return "\n".join(header) + body + "\n"


def markdown_to_skill(text: str) -> Skill:
    lines = text.splitlines()
    if not lines or lines[0].strip() != _FENCE:
        raise ValueError("skill document is missing its header fence")
    meta: dict[str, str] = {}
    cursor = 1  # index into header lines (note: a text cursor, not a vendor)
    while cursor < len(lines) and lines[cursor].strip() != _FENCE:
        key, _, value = lines[cursor].partition(":")
        meta[key.strip()] = value.strip()
        cursor += 1
    body = "\n".join(lines[cursor + 1:]).strip("\n")
    return Skill(
        id=meta.get("id", ""),
        title=meta.get("title", ""),
        body=body,
        triggers=_split_csv(meta.get("triggers", "")),
        tags=_split_csv(meta.get("tags", "")),
        source=meta.get("source", ""),
    )


class MarkdownSkillRegistry(Registry):
    """A registry that persists skills as markdown files under ``root``."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, skill_id: str) -> Path:
        return self.root / f"{skill_id}.md"

    def add(self, skill: Skill) -> None:
        self._path(skill.id).write_text(skill_to_markdown(skill), encoding="utf-8")

    def remove(self, skill_id: str) -> None:
        self._path(skill_id).unlink(missing_ok=True)

    def get(self, skill_id: str) -> Skill | None:
        path = self._path(skill_id)
        if not path.exists():
            return None
        return markdown_to_skill(path.read_text(encoding="utf-8"))

    def all(self) -> list[Skill]:
        skills = [
            markdown_to_skill(path.read_text(encoding="utf-8"))
            for path in sorted(self.root.glob("*.md"))
        ]
        return skills

    def retrieve(self, query: str, *, k: int = 5) -> list[Skill]:
        """Return up to ``k`` skills relevant to ``query``, best first.

        Relevance is a simple, deterministic keyword score: how many of a
        skill's triggers and tags appear in the lowercased query. Ties break
        on skill id so results are stable across runs.
        """

        haystack = query.lower()
        scored: list[tuple[int, str, Skill]] = []
        for skill in self.all():
            keywords = set(skill.triggers) | set(skill.tags)
            score = sum(1 for kw in keywords if kw and kw.lower() in haystack)
            if score > 0:
                scored.append((score, skill.id, skill))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [skill for _, _, skill in scored[:k]]
