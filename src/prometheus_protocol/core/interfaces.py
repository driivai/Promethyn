"""Abstract service boundaries for the runtime.

Each abstract base class below is a seam in the system. Concrete
implementations live in their own packages so that the contract and the
implementation can evolve independently. The public API re-exports these so
downstream code can program against the interfaces, not the implementations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Sequence

from prometheus_protocol.core.models import Attempt, Evidence, Skill, Task


class Provider(ABC):
    """The model boundary.

    A provider turns a task prompt (plus any retrieved skills) into candidate
    source code. It is deliberately blind to hidden test cases: only the
    prompt, the required entry point, and the retrieved skills are passed in.
    """

    @abstractmethod
    def propose_solution(
        self,
        *,
        prompt: str,
        entry_point: str,
        skills: Sequence[Skill] = (),
    ) -> str:
        """Return source code defining a function named ``entry_point``."""
        raise NotImplementedError


class Verifier(ABC):
    """Runs candidate code against a task's hidden cases and returns evidence."""

    @abstractmethod
    def verify(self, *, code: str, task: Task) -> Evidence:
        raise NotImplementedError


class Registry(ABC):
    """Stores skills and retrieves the ones relevant to a query."""

    @abstractmethod
    def add(self, skill: Skill) -> None:
        raise NotImplementedError

    @abstractmethod
    def remove(self, skill_id: str) -> None:
        """Remove a skill. Removal must be possible so promotion is reversible."""
        raise NotImplementedError

    @abstractmethod
    def get(self, skill_id: str) -> Skill | None:
        raise NotImplementedError

    @abstractmethod
    def all(self) -> list[Skill]:
        raise NotImplementedError

    @abstractmethod
    def retrieve(self, query: str, *, k: int = 5) -> list[Skill]:
        raise NotImplementedError


class Gate(ABC):
    """Decides whether a candidate skill earns promotion.

    Implementations must enforce the held-out firewall: the task ids the forge
    learned from must never intersect the task ids the gate scores against.
    """

    @abstractmethod
    def evaluate(
        self,
        *,
        candidate: Skill,
        train_ids: Sequence[str],
        heldout_tasks: Sequence[Task],
        score_fn,
        rate_before: float,
    ):
        raise NotImplementedError


class Ledger(ABC):
    """Append-only record of attempts and promotions.

    The ledger is what makes the runtime auditable and reversible: every
    attempt and every promotion is written down, in order, and can be read
    back.
    """

    @abstractmethod
    def record_attempt(self, attempt: Attempt, *, cycle: int, kind: str) -> int:
        raise NotImplementedError

    @abstractmethod
    def record_promotion(
        self,
        *,
        skill_id: str,
        action: str,
        cycle: int,
        rate_before: float,
        rate_after: float,
    ) -> int:
        raise NotImplementedError

    @abstractmethod
    def attempts(self) -> list[dict]:
        raise NotImplementedError

    @abstractmethod
    def promotions(self) -> list[dict]:
        raise NotImplementedError
