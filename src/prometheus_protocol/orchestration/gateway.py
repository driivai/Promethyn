"""The orchestrator's ONLY door to action — and it is a one-way door.

The defining invariant of this layer: the orchestrator can sequence agents and
pass their outputs, but it has **no path to execute**. Every action any agent
proposes is submitted to the SAME gate every other action goes through; the
gate decides. The orchestrator cannot approve, cannot bypass, cannot reach the
executor.

That is enforced by *type* at the API level: an :class:`ActionGateway` wraps a
single ``submit`` callable — the existing :meth:`ExecutionController.submit` —
and exposes exactly one method, ``route_action``, which delegates to it. The
gateway and the runtime carry **no** ``execute``, ``approve``, ``gate``, or
``executor`` member; the orchestrator's whole vocabulary for touching the
world is ``route_action``, and it always ends at the gate. Just as the git
tool cannot ``push`` because push is not one of its operations, the
orchestrator cannot execute or approve because those operations are not on the
objects it holds. Human approval of a held action stays with whoever holds the
controller (the operator), never with the orchestrator.

HONEST CAVEAT (documented, not papered over): this is capability safety *in
Python*, so it is airtight only up to introspection. Because ``submit`` is a
bound method, ``gateway._submit.__self__`` is the controller, and a caller who
deliberately reaches through the object model could touch its human verbs —
exactly as ``git_tool._sandbox`` is reachable in principle. Two things bound
that caveat: it takes a deliberate ``__self__``/``__closure__`` escape, never
any capability the orchestration API offers; and even then the **gate is not
bypassable** — ``approve`` only executes an action the gate already *routed*
(a pending hold), never one it *blocked*, so no path lets the orchestrator run
what the gate refused. A process/capability boundary (a follow-up) is what
would close the introspection gap entirely; the gate-in-the-loop guarantee
holds today regardless.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from prometheus_protocol.core.models import ExecutableAction
from prometheus_protocol.execution.controller import SubmitOutcome

if TYPE_CHECKING:  # pragma: no cover - import cycle: policy imports core.models
    from prometheus_protocol.policy.assessment import PolicyAssessment


class SubmitFn(Protocol):
    """The one capability the gateway is granted: submit an action for judging."""

    def __call__(
        self,
        *,
        assessment: "PolicyAssessment",
        action: ExecutableAction,
        risk_class: str = "low",
        subject_id: str = "",
    ) -> SubmitOutcome: ...


class ActionGateway:
    """A submit-only adapter over the execution pipeline. Authorizes nothing.

    Construct it with ``ActionGateway(controller.submit)``. The gateway keeps
    only that bound callable — not the controller — so even reaching into its
    internals finds no approve/execute/gate handle. ``route_action`` is the
    orchestrator's entire vocabulary for touching the world, and it always ends
    at the gate.
    """

    def __init__(self, submit: SubmitFn) -> None:
        # A bound callable, not the controller. There is deliberately no
        # `_controller`, `_gate`, or `_executor` attribute to reach through.
        self._submit = submit

    def route_action(
        self,
        *,
        assessment: "PolicyAssessment",
        action: ExecutableAction,
        risk_class: str = "low",
        subject_id: str = "",
    ) -> SubmitOutcome:
        """Submit a proposed action for authorization; return what the gate did.

        The gate — not this gateway and not the orchestrator — approves,
        routes to a human, or blocks. The gateway only carries the proposal in.

        PHASE-1.2b — what it carries is a policy-evaluated, action-bound
        assessment. The gateway still authorizes nothing and still reads
        nothing off what it carries; the change is that there is no ``judgment=``
        keyword left for an unbound verdict to enter through.
        """

        return self._submit(
            assessment=assessment,
            action=action,
            risk_class=risk_class,
            subject_id=subject_id,
        )
