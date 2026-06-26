"""Executor: the wall's enforcement point.

``Executor.execute`` accepts ONLY a ``GateDecision`` — there is no method that
takes a ``Proposal`` or a ``TestPlan``. Nothing reaches execution that the gate
did not approve. The provided ``RecordingExecutor`` is a no-op recorder: this
sprint has no real tool side-effects.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from prometheus_protocol.gate.promotion import GateDecision
from prometheus_protocol.swarm.models import ExecutionResult


class Executor(ABC):
    """Acts on an approved gate decision and returns a result."""

    @abstractmethod
    def execute(self, decision: GateDecision) -> ExecutionResult:
        raise NotImplementedError


class RecordingExecutor(Executor):
    """A no-op executor that records the approved decisions it was given."""

    def __init__(self) -> None:
        self.executed: list[GateDecision] = []

    def execute(self, decision: GateDecision) -> ExecutionResult:
        # The wall: only a gate-produced decision may cross into execution.
        if not isinstance(decision, GateDecision):
            raise TypeError(
                "Executor.execute accepts only a GateDecision; a proposal or "
                "test plan cannot be executed"
            )
        if not decision.approved:
            raise ValueError("refusing to execute an unapproved gate decision")
        self.executed.append(decision)
        return ExecutionResult(
            executed=True,
            subject_id=decision.subject_id,
            detail="recorded (no-op; no real side-effects)",
        )
