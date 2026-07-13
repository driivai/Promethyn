"""The workflow runtime: advance the DAG, grade, route, record — never execute.

For each step in the workflow's deterministic order the runtime:

1. gathers the tier-tagged :class:`AgentMessage`s from the step's dependencies
   (never bare facts);
2. asks the step's agent to **propose** (content + at most one action);
3. asks the step's **independent grader** to grade the proposal into tier-tagged
   Evidence, then fuses it through the EXISTING verifier bank into a judgment
   (tier + confidence + verdict) — the wall, inside the step;
4. if the proposal carries an action, submits it through the ``ActionGateway``
   — i.e. the existing gate. The gate approves (executes now), routes to a
   human (a pending hold), or blocks. The runtime never executes;
5. wraps the step's output as a tier-tagged message for its dependents; and
6. records the step in the workflow ledger.

The runtime holds a bank (to grade), a gateway (its only door to action), and a
ledger port (to record). It has no executor, no gate, no controller, and no
`execute`/`approve` method. Its authority to change the world is exactly the
gateway's ``route_action`` — which always ends at the gate.

**Chain confidence is a labelled placeholder.** Composing per-step confidences
into a joint chain confidence (A@0.8 feeding B@0.7) is an unsolved problem;
inventing a formula and calling it sound would be dishonest. The runtime
records each step's own confidence, and reports a chain-level number computed
as the **minimum** of the confidences along the realised path — the most
conservative defensible summary, used only to make "the chain is only as strong
as its weakest graded step" visible. It is NOT a solution; see
``docs/orchestration.md`` for the open problem.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol

from prometheus_protocol.core.models import Tier, Unavailable, Verdict
from prometheus_protocol.gate.authorization import OUTCOME_UNAVAILABLE
from prometheus_protocol.gate.promotion import (
    OUTCOME_APPROVE,
    OUTCOME_BLOCK,
    OUTCOME_ROUTE,
)
from prometheus_protocol.orchestration.gateway import ActionGateway
from prometheus_protocol.orchestration.messages import AgentMessage
from prometheus_protocol.orchestration.workflow import AgentStep, Workflow
from prometheus_protocol.verifier.bank import VerifierBank

_OUTCOME_NONE = "none"  # the step proposed no action


class WorkflowLedgerPort(Protocol):
    """The narrow ledger surface the runtime needs. Records; authorizes nothing.

    Satisfied by the concrete ``SqliteLedger`` (additive ``workflow_steps``
    table). Declared here so the runtime depends on recording, not on the whole
    ledger.
    """

    def record_workflow_step(
        self,
        *,
        workflow_id: str,
        step_id: str,
        agent_id: str,
        tier: str,
        verdict: str,
        confidence: float,
        proposed_action: bool,
        outcome: str,
        subject_id: str,
        pending_id: int | None,
        created_at: str,
    ) -> int: ...


@dataclass(frozen=True)
class StepRecord:
    """The in-memory result of running one step (mirrors the ledger row).

    ``verdict``/``confidence``/``tier``/``message`` are ``None`` when the step did
    not produce a graded result: ``unavailable`` is True when the step's own
    authoritative grader could not execute, and ``halted`` is True when the step
    was skipped because a dependency was unavailable (a cascade). Such a step
    emits NO downstream message — nothing may compound on a check that did not
    run — so its ``message`` is None and dependents cannot fire."""

    step_id: str
    agent_id: str
    tier: Tier | None
    verdict: Verdict | None
    confidence: float | None
    proposed_action: bool
    outcome: str
    subject_id: str
    pending_id: int | None
    message: AgentMessage | None
    unavailable: bool = False
    halted: bool = False


@dataclass(frozen=True)
class WorkflowRun:
    """The outcome of advancing a whole workflow."""

    workflow_id: str
    steps: tuple[StepRecord, ...]
    #: Conservative PLACEHOLDER — the minimum step confidence along the run, not
    #: a principled chain confidence. See the module docstring.
    chain_confidence_placeholder: float
    messages: dict[str, AgentMessage] = field(default_factory=dict)

    @property
    def executed_subject_ids(self) -> tuple[str, ...]:
        return tuple(s.subject_id for s in self.steps if s.outcome == OUTCOME_APPROVE)

    @property
    def held_subject_ids(self) -> tuple[str, ...]:
        return tuple(s.subject_id for s in self.steps if s.outcome == OUTCOME_ROUTE)

    @property
    def unavailable_step_ids(self) -> tuple[str, ...]:
        """Steps that could not be graded — their own grader was unavailable, or a
        dependency was (a cascade halt). Visible at the run level, not only in the
        ledger, so a caller can see exactly which branch could not run."""

        return tuple(s.step_id for s in self.steps if s.unavailable or s.halted)


class WorkflowRuntime:
    """Sequences agents through the DAG. Has no authority to execute."""

    def __init__(
        self,
        *,
        bank: VerifierBank,
        gateway: ActionGateway,
        ledger: WorkflowLedgerPort,
        clock: Callable[[], str] | None = None,
    ) -> None:
        # Grade (bank), the one door to action (gateway), record (ledger).
        # Deliberately NO executor, NO gate, NO controller reference.
        self._bank = bank
        self._gateway = gateway
        self._ledger = ledger
        self._clock = clock or _utc_now_iso

    def run(self, workflow: Workflow) -> WorkflowRun:
        messages: dict[str, AgentMessage] = {}
        records: list[StepRecord] = []
        confidences: list[float] = []
        halted: set[str] = set()  # step_ids whose branch could not be graded

        for step in workflow.order():
            # (0) Cascade halt: a dependent NEVER fires on an absent input. If any
            #     dependency's branch was unavailable (halted, emitting no message),
            #     halt this step too — checked HERE, at decision time, before it
            #     proposes. The strict ``messages[dep]`` lookup below would KeyError
            #     on an absent message regardless (fail-closed); this makes the halt
            #     graceful so independent sibling branches still run.
            halted_deps = [dep for dep in step.depends_on if dep in halted]
            if halted_deps:
                halted.add(step.step_id)
                records.append(self._halt_record(
                    step, workflow, tier=None, proposed_action=False,
                    subject_id="", unavailable=False, halted=True,
                ))
                continue

            inputs = tuple(messages[dep] for dep in step.depends_on)

            # (1) propose — proposer side only, no verdict/confidence.
            proposal = step.agent.propose(step.task, inputs)

            # (2) grade — the independent judge, fused through the bank (reuse).
            evidence = step.grader.grade(proposal, inputs)
            judgment = self._bank.judge([evidence])

            # (2a) The step's own authoritative grader COULD NOT EXECUTE. Halt this
            #      branch: emit NO downstream message (a SOFT verdict must never
            #      stand in for a HARD check that never ran) and do NOT route the
            #      ungraded action (an ungraded action is never authorized). Record
            #      it distinctly and cascade to dependents. After this, ``judgment``
            #      is narrowed to a real Judgment for the rest of the loop.
            if isinstance(judgment, Unavailable):
                halted.add(step.step_id)
                subject_id = f"{workflow.workflow_id}:{step.step_id}"
                records.append(self._halt_record(
                    step, workflow, tier=judgment.tier,
                    proposed_action=proposal.action is not None,
                    subject_id=subject_id if proposal.action is not None else "",
                    unavailable=True, halted=False,
                ))
                continue

            tier = evidence.tier if evidence.tier is not None else Tier.SOFT

            # (3) route any action through the SAME gate. The runtime never
            #     executes; the gate decides approve / route-to-human / block.
            subject_id = f"{workflow.workflow_id}:{step.step_id}"
            outcome = _OUTCOME_NONE
            pending_id: int | None = None
            if proposal.action is not None:
                submit = self._gateway.route_action(
                    judgment=judgment,
                    action=proposal.action,
                    risk_class=proposal.risk_class,
                    subject_id=subject_id,
                )
                outcome = submit.outcome
                if submit.pending is not None:
                    pending_id = submit.pending.id

            # (4) wrap the output as a tier-tagged message for dependents.
            message = AgentMessage.graded(
                workflow_id=workflow.workflow_id,
                from_step=step.step_id,
                from_agent=step.agent.agent_id,
                content=proposal.content,
                tier=tier,
                judgment=judgment,
            )
            messages[step.step_id] = message
            confidences.append(judgment.confidence)

            # (5) record the step for the workflow audit trail.
            self._ledger.record_workflow_step(
                workflow_id=workflow.workflow_id,
                step_id=step.step_id,
                agent_id=step.agent.agent_id,
                tier=tier.value,
                verdict=judgment.verdict.value,
                confidence=judgment.confidence,
                proposed_action=proposal.action is not None,
                outcome=outcome,
                subject_id=subject_id if proposal.action is not None else "",
                pending_id=pending_id,
                created_at=self._clock(),
            )
            records.append(StepRecord(
                step_id=step.step_id,
                agent_id=step.agent.agent_id,
                tier=tier,
                verdict=judgment.verdict,
                confidence=judgment.confidence,
                proposed_action=proposal.action is not None,
                outcome=outcome,
                subject_id=subject_id if proposal.action is not None else "",
                pending_id=pending_id,
                message=message,
            ))

        chain = min(confidences) if confidences else 0.0  # PLACEHOLDER (see docstring)
        return WorkflowRun(
            workflow_id=workflow.workflow_id,
            steps=tuple(records),
            chain_confidence_placeholder=chain,
            messages=messages,
        )

    def _halt_record(
        self,
        step: AgentStep,
        workflow: Workflow,
        *,
        tier: Tier | None,
        proposed_action: bool,
        subject_id: str,
        unavailable: bool,
        halted: bool,
    ) -> StepRecord:
        """Record a branch that halted — its own grader could not execute
        (``unavailable``), or a dependency's did (``halted``, a cascade). It emits
        no message and authorizes no action; the workflow ledger row marks it
        ``verdict='unavailable'`` / ``outcome=OUTCOME_UNAVAILABLE`` so it is forever
        distinct from a graded pass/fail/abstain in the audit trail."""

        self._ledger.record_workflow_step(
            workflow_id=workflow.workflow_id,
            step_id=step.step_id,
            agent_id=step.agent.agent_id,
            tier=tier.value if tier is not None else "",
            verdict="unavailable",
            confidence=0.0,
            proposed_action=proposed_action,
            outcome=OUTCOME_UNAVAILABLE,
            subject_id=subject_id,
            pending_id=None,
            created_at=self._clock(),
        )
        return StepRecord(
            step_id=step.step_id,
            agent_id=step.agent.agent_id,
            tier=tier,
            verdict=None,
            confidence=None,
            proposed_action=proposed_action,
            outcome=OUTCOME_UNAVAILABLE,
            subject_id=subject_id,
            pending_id=None,
            message=None,
            unavailable=unavailable,
            halted=halted,
        )


def _utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "WorkflowRuntime",
    "WorkflowRun",
    "StepRecord",
    "WorkflowLedgerPort",
    "OUTCOME_APPROVE",
    "OUTCOME_ROUTE",
    "OUTCOME_BLOCK",
]
