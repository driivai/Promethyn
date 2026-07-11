"""The workflow topology: a small DAG of agent steps.

A :class:`Workflow` is a set of :class:`AgentStep`s and their dependencies —
which prior steps' (tier-tagged) outputs each step consumes. It is validated
(unique ids, dependencies exist, no cycles) and produces a **deterministic**
execution order.

The proposer/judge wall is preserved *inside* every step. A step's
:class:`Agent` may only **propose** (`AgentProposal`: content and, optionally,
one executable action) — it produces no verdict, no confidence, no approval.
An independent :class:`StepGrader` (a verifier-shaped port, satisfied by the
real domain verifiers) grades the proposal into tier-tagged
:class:`~prometheus_protocol.core.models.Evidence`. The runtime, not the agent,
turns that into the grade a downstream step sees.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from prometheus_protocol.core.models import Evidence, ExecutableAction
from prometheus_protocol.orchestration.messages import AgentMessage


@dataclass(frozen=True)
class AgentProposal:
    """What an agent produces: a claim, and at most one action to authorize.

    Proposer-side only. It carries no tier, no confidence, and no approval —
    those come from grading (the ``StepGrader``) and the gate, never the agent.
    ``action`` is the single executable action the step wants taken, if any; it
    is routed to the SAME gate every other action goes through. ``risk_class``
    is the step's declared risk for that action.
    """

    content: str
    action: ExecutableAction | None = None
    risk_class: str = "low"


@runtime_checkable
class Agent(Protocol):
    """The proposer at one step. It may only propose.

    ``agent_id`` names it for the audit trail. ``propose`` sees the step's task
    and the tier-tagged messages from its dependencies — never a bare fact.
    """

    agent_id: str

    def propose(self, task: str, inputs: tuple[AgentMessage, ...]) -> AgentProposal: ...


@runtime_checkable
class StepGrader(Protocol):
    """The judge at one step: grades a proposal into tier-tagged Evidence.

    Independent of the agent (the wall, inside the step). Satisfied by the real
    domain verifiers via a thin adapter, or by a deterministic grader for the
    offline demo. It returns Evidence; it never authorizes anything.
    """

    def grade(self, proposal: AgentProposal, inputs: tuple[AgentMessage, ...]) -> Evidence: ...


@dataclass(frozen=True)
class AgentStep:
    """One node of the workflow DAG."""

    step_id: str
    agent: Agent
    grader: StepGrader
    task: str
    depends_on: tuple[str, ...] = ()


class WorkflowError(ValueError):
    """A malformed workflow: unknown dependency, duplicate id, or a cycle."""


@dataclass(frozen=True)
class Workflow:
    """A validated DAG of agent steps with a deterministic execution order."""

    steps: tuple[AgentStep, ...]
    workflow_id: str = "workflow"
    _by_id: dict[str, AgentStep] = field(default_factory=dict, compare=False, repr=False)

    def __post_init__(self) -> None:
        by_id: dict[str, AgentStep] = {}
        for step in self.steps:
            if step.step_id in by_id:
                raise WorkflowError(f"duplicate step id {step.step_id!r}")
            by_id[step.step_id] = step
        for step in self.steps:
            for dep in step.depends_on:
                if dep not in by_id:
                    raise WorkflowError(
                        f"step {step.step_id!r} depends on unknown step {dep!r}"
                    )
                if dep == step.step_id:
                    raise WorkflowError(f"step {step.step_id!r} depends on itself")
        object.__setattr__(self, "_by_id", by_id)
        # Validate acyclicity by computing the order eagerly.
        self.order()

    def step(self, step_id: str) -> AgentStep:
        return self._by_id[step_id]

    def order(self) -> tuple[AgentStep, ...]:
        """Deterministic topological order (Kahn's algorithm, ids as tiebreak).

        Ties between ready steps break on ``step_id`` so a given workflow always
        runs in exactly one order — reproducible audit trails.
        """

        indegree = {s.step_id: len(s.depends_on) for s in self.steps}
        dependents: dict[str, list[str]] = {s.step_id: [] for s in self.steps}
        for s in self.steps:
            for dep in s.depends_on:
                dependents[dep].append(s.step_id)

        ready = sorted(sid for sid, d in indegree.items() if d == 0)
        ordered: list[AgentStep] = []
        while ready:
            sid = ready.pop(0)
            ordered.append(self._by_id[sid])
            for child in dependents[sid]:
                indegree[child] -= 1
                if indegree[child] == 0:
                    # keep `ready` sorted for determinism
                    ready.append(child)
                    ready.sort()
        if len(ordered) != len(self.steps):
            remaining = sorted(set(self._by_id) - {s.step_id for s in ordered})
            raise WorkflowError(f"workflow has a cycle among steps: {remaining}")
        return tuple(ordered)
