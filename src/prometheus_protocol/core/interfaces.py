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

    def assess(self, *, prompt: str, system: str | None = None) -> str:
        """Return a free-form completion for an advisory assessment.

        Optional capability used by advisory judges (for example the
        model-judge verifier) that ask the model to grade an outcome rather
        than to propose one. The default raises ``NotImplementedError``;
        providers that can issue such a request override it. A judge treats an
        unsupported provider as "no opinion" (ABSTAIN).
        """
        raise NotImplementedError("this provider does not support assessment")

    def generate(self, *, prompt: str, system: str | None = None) -> str:
        """Return a free-form completion for open-ended reasoning.

        Optional capability used by swarm reasoning roles to produce a typed
        proposal (a hypothesis, option, forecast, critique, or — for non-code
        domains — an action) from a role-specific prompt. The default raises
        ``NotImplementedError``; providers that can issue such a request
        override it. A role treats an unsupported provider, or any failure, as
        "no proposal" (it degrades gracefully and never crosses the wall with an
        unvalidated object).
        """
        raise NotImplementedError("this provider does not support generation")


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

    # -- execution audit (live-execution: pending human holds + executions) ---
    #
    # The execution subsystem records its full chain here so the halt-and-route
    # decision, the human's approve/reject, and every executed action are all
    # re-readable from the ledger alone (INV-EXEC-4).

    @abstractmethod
    def record_pending_action(
        self,
        *,
        subject_id: str,
        risk_class: str,
        reason: str,
        verdict: str,
        confidence: float,
        action: dict,
        judgment: dict,
        created_at: str,
    ) -> int:
        """Record a routed action awaiting a human decision; return its id."""
        raise NotImplementedError

    @abstractmethod
    def resolve_pending_action(
        self,
        pending_id: int,
        *,
        status: str,
        decided_by: str,
        decided_at: str,
        decision_reason: str = "",
    ) -> None:
        """Record a human's approve/reject (or an expiry) for a pending action."""
        raise NotImplementedError

    @abstractmethod
    def claim_pending_execution(self, pending_id: int, claimed_at: str) -> bool:
        """Atomically claim the right to execute a hold; True iff this call won.

        The at-most-once-execution guard: only one of any number of concurrent
        drivers (approve and/or retry) may proceed to the executor. It must not
        touch the human decision record.
        """
        raise NotImplementedError

    @abstractmethod
    def release_pending_execution(self, pending_id: int) -> None:
        """Release a claim after a refused (no-side-effect) execution."""
        raise NotImplementedError

    @abstractmethod
    def pending_actions(self, *, status: str | None = None) -> list[dict]:
        """Return pending actions in insertion order, optionally filtered."""
        raise NotImplementedError

    @abstractmethod
    def pending_action(self, pending_id: int) -> dict | None:
        """Return one pending action by id, or ``None`` if there is no such id."""
        raise NotImplementedError

    @abstractmethod
    def record_execution(
        self,
        *,
        subject_id: str,
        source: str,
        executed: bool,
        refused: bool,
        sandbox_name: str,
        exit_status: int | None,
        detail: str,
        created_at: str,
        judgment: dict | None = None,
        pending_id: int | None = None,
    ) -> int:
        """Record one executor outcome (executed, refused, or blocked).

        ``judgment`` is the fused Judgment the action rested on; it is stored as
        JSON and promoted to queryable verdict/confidence columns.
        ``pending_id`` links the outcome to the pending hold it resolves, when
        it came from one — it is what makes "this approved hold has never
        executed" answerable from the ledger alone.
        """
        raise NotImplementedError

    @abstractmethod
    def executions(self) -> list[dict]:
        """Return recorded executions in insertion order."""
        raise NotImplementedError

    @abstractmethod
    def executions_for_pending(self, pending_id: int) -> list[dict]:
        """Return executions linked to one pending hold, in insertion order."""
        raise NotImplementedError

    # -- audit queries (additive observability; read-only) --------------------

    @abstractmethod
    def executions_below_confidence(self, threshold: float) -> list[dict]:
        """Executed actions whose fused confidence is below ``threshold``."""
        raise NotImplementedError

    @abstractmethod
    def authoritative_pass_below(self, threshold: float) -> list[dict]:
        """Executed authoritative-PASS actions with fused confidence below ``threshold``."""
        raise NotImplementedError

    @abstractmethod
    def human_decisions(self) -> list[dict]:
        """The decision log: pending actions a human or the sweep resolved."""
        raise NotImplementedError

    @abstractmethod
    def backfill(self) -> dict:
        """Idempotently fill judgment columns for historical rows from their JSON."""
        raise NotImplementedError
