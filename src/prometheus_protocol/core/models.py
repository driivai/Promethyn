"""Immutable data structures shared across the runtime.

These types are intentionally small, hashable where practical, and free of
behaviour. Behaviour lives in the service modules (verifier, registry, forge,
gate, runtime); the models are the wire format that flows between them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Allowed values for ``Task.split``. The whole safety story of the protocol
# rests on these two partitions never mixing (see ``gate`` and ``spec``).
SPLIT_TRAIN = "train"
SPLIT_HELDOUT = "heldout"
SPLITS = (SPLIT_TRAIN, SPLIT_HELDOUT)


@dataclass(frozen=True)
class Case:
    """A single hidden input/output expectation for a task.

    ``args`` is the positional argument tuple handed to the candidate
    function; ``expected`` is the value it must return. Cases are *hidden*:
    they are handed to the verifier, never to the model provider.
    """

    args: tuple[Any, ...]
    expected: Any


@dataclass(frozen=True)
class Task:
    """A unit of work the runtime tries to solve.

    ``prompt`` and ``entry_point`` are the only fields exposed to a provider.
    ``cases`` and ``cluster`` are evaluation-side metadata and must not leak
    into a proposal request.
    """

    id: str
    entry_point: str
    prompt: str
    split: str
    cases: tuple[Case, ...]
    cluster: str | None = None

    def __post_init__(self) -> None:
        if self.split not in SPLITS:
            raise ValueError(
                f"task {self.id!r} has unknown split {self.split!r}; "
                f"expected one of {SPLITS}"
            )


@dataclass(frozen=True)
class Skill:
    """A reusable lesson, stored on disk as a markdown document.

    ``triggers`` are lowercase keywords that, when present in a task prompt,
    mark the skill as relevant. ``tags`` group related skills (typically by
    the failure cluster that produced them).
    """

    id: str
    title: str
    body: str
    triggers: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    source: str = ""


@dataclass(frozen=True)
class Evidence:
    """The hard pass/fail outcome produced by the verifier for one attempt."""

    passed: bool
    total: int
    passed_count: int
    failures: tuple[str, ...] = ()
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    timed_out: bool = False


@dataclass(frozen=True)
class Attempt:
    """One proposal evaluated against one task, with its evidence.

    ``skills_used`` records which skills were in context when the proposal was
    produced; this is what makes ablation and audit possible after the fact.
    """

    task_id: str
    split: str
    entry_point: str
    code: str
    evidence: Evidence
    skills_used: tuple[str, ...] = field(default_factory=tuple)
