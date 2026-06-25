"""Lesson miner and skill forge — the proposer of new skills.

The forge looks at attempts that *failed* and distils them into reusable
skills. It is deliberately simple and deterministic: failures are grouped by
the failure cluster recorded on each task, and each cluster yields one skill
built from a known lesson template. A richer forge could ask a provider to
author the skill prose; this one keeps the loop reproducible and offline.

The forge only ever sees training failures. That is half of the held-out
firewall (the gate enforces the other half), and it is checked here in code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from prometheus_protocol.core.models import SPLIT_TRAIN, Attempt, Skill, Task


@dataclass(frozen=True)
class _Lesson:
    title: str
    triggers: tuple[str, ...]
    guidance: str


# Known clusters map to curated lessons. Unknown clusters fall back to a
# generic template (see ``_fallback``), so the forge degrades gracefully.
_CLUSTER_LESSONS: dict[str, _Lesson] = {
    "empty-input": _Lesson(
        title="Guard against empty input",
        triggers=("empty",),
        guidance=(
            "Before indexing into or aggregating over a sequence, check whether "
            "it is empty. Return a well-defined default (for example 0, None, or "
            "an empty container) rather than letting an index error or an "
            "arithmetic error from a zero-length input escape."
        ),
    ),
}


class LessonForge:
    """Mines failing attempts into candidate skills."""

    def __init__(self, lessons: Mapping[str, _Lesson] | None = None) -> None:
        self._lessons = dict(_CLUSTER_LESSONS if lessons is None else lessons)

    def mine(
        self,
        failures: Sequence[Attempt],
        tasks_by_id: Mapping[str, Task],
    ) -> list[Skill]:
        # Held-out firewall (forge side): the forge must never learn from
        # anything but training failures.
        leaked = sorted({a.task_id for a in failures if a.split != SPLIT_TRAIN})
        if leaked:
            raise ValueError(
                "forge received non-training attempts, violating the held-out "
                f"firewall: {', '.join(leaked)}"
            )

        clusters: dict[str, list[Task]] = {}
        for attempt in failures:
            task = tasks_by_id.get(attempt.task_id)
            if task is None or task.cluster is None:
                continue
            clusters.setdefault(task.cluster, []).append(task)

        skills: list[Skill] = []
        for cluster in sorted(clusters):
            tasks = sorted(clusters[cluster], key=lambda t: t.id)
            lesson = self._lessons.get(cluster) or _fallback(cluster)
            skills.append(
                Skill(
                    id=f"skill-{cluster}",
                    title=lesson.title,
                    body=_render(lesson, cluster, tasks),
                    triggers=lesson.triggers,
                    tags=(cluster,),
                    source="forge",
                )
            )
        return skills


def _fallback(cluster: str) -> _Lesson:
    keyword = cluster.split("-", 1)[0]
    return _Lesson(
        title=f"Lesson for the {cluster} cluster",
        triggers=(keyword,),
        guidance=(
            f"Several training tasks in the {cluster!r} cluster failed for a "
            "shared reason. Review the failing cases and handle that condition "
            "explicitly before returning."
        ),
    )


def _render(lesson: _Lesson, cluster: str, tasks: Sequence[Task]) -> str:
    motivating = "\n".join(
        f"- `{task.entry_point}` ({task.id})" for task in tasks
    )
    return (
        f"# {lesson.title}\n\n"
        f"Mined from failing training tasks in the `{cluster}` cluster:\n\n"
        f"{motivating}\n\n"
        "## Guidance\n\n"
        f"{lesson.guidance}\n"
    )
