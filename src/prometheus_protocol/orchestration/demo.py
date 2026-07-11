"""A runnable multi-step workflow, governed end to end.

Three agents cooperate on one job through the REAL chain — the verifier bank,
the action gate, the execution controller, the sandbox executor, and the
ledger — with nothing forked for orchestration:

* **plan** (SOFT): a reasoning step. Graded soft, so its output travels
  downstream as a SOFT, advisory claim — never a fact.
* **implement** (HARD): consumes the plan's tier-tagged message, proposes a
  small computation to run, and is graded HARD. Its action clears the gate and
  executes in the sandbox.
* **export** (HARD, high-risk): proposes a higher-risk action. Even though it
  passes and is authoritative, high risk means the gate ROUTES it to a human —
  the workflow halts that branch for review. The operator then approves it
  through the existing controller (not the orchestrator).

Finally the workflow ledger is queried: every step, which agent, at what tier,
what the gate decided, and where a human was asked — one query. The model is
frozen and offline (scripted agents); the grading, gate decisions, sandboxed
execution, and ledger rows are all real.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from prometheus_protocol.core.models import (
    ACTION_PYTHON_CODE,
    Evidence,
    ExecutableAction,
    Tier,
    Verdict,
)
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.executor import SandboxExecutor
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.orchestration.gateway import ActionGateway
from prometheus_protocol.orchestration.messages import AgentMessage
from prometheus_protocol.orchestration.runtime import WorkflowRuntime
from prometheus_protocol.orchestration.workflow import (
    AgentProposal,
    AgentStep,
    Workflow,
)
from prometheus_protocol.sandbox import NamespaceSandbox
from prometheus_protocol.verifier.bank import VerifierBank

_PLAN_GRADER = "plan-review"
_IMPL_GRADER = "impl-check"


@dataclass
class ScriptedAgent:
    """A deterministic proposer: fixed content, and an optional action."""

    agent_id: str
    content: str
    action: ExecutableAction | None = None
    risk_class: str = "low"

    def propose(self, task: str, inputs: tuple[AgentMessage, ...]) -> AgentProposal:
        return AgentProposal(
            content=self.content, action=self.action, risk_class=self.risk_class
        )


@dataclass
class ScriptedGrader:
    """A deterministic judge: returns fixed tier-tagged Evidence.

    Stands in for a real domain verifier (the extension surface conforms those)
    so the demo runs offline. A soft grader emits SOFT evidence; the hard
    grader emits HARD (authoritative) evidence.
    """

    verifier_id: str
    tier: Tier
    passed: bool = True

    def grade(self, proposal: AgentProposal, inputs: tuple[AgentMessage, ...]) -> Evidence:
        return Evidence(
            passed=self.passed,
            total=1,
            passed_count=1 if self.passed else 0,
            verifier_id=self.verifier_id,
            verdict=Verdict.PASS if self.passed else Verdict.FAIL,
            tier=self.tier,
        )


def _print_action(label: str) -> ExecutableAction:
    return ExecutableAction(kind=ACTION_PYTHON_CODE, code=f"print({label!r})")


def build_workflow() -> Workflow:
    plan = AgentStep(
        step_id="plan",
        agent=ScriptedAgent("planner", "sum the first three primes: 2 + 3 + 5"),
        grader=ScriptedGrader(_PLAN_GRADER, Tier.SOFT),
        task="Draft an approach.",
    )
    implement = AgentStep(
        step_id="implement",
        agent=ScriptedAgent(
            "implementer", "computed 2 + 3 + 5 = 10",
            action=_print_action("2 + 3 + 5 = 10"), risk_class="medium",
        ),
        grader=ScriptedGrader(_IMPL_GRADER, Tier.HARD),
        task="Carry out the plan.",
        depends_on=("plan",),
    )
    export = AgentStep(
        step_id="export",
        agent=ScriptedAgent(
            "exporter", "export the result to the shared record",
            action=_print_action("EXPORT: 10"), risk_class="high",
        ),
        grader=ScriptedGrader(_IMPL_GRADER, Tier.HARD),
        task="Publish the result (high-risk).",
        depends_on=("implement",),
    )
    return Workflow(steps=(plan, implement, export), workflow_id="demo-wf-1")


def run_demo(*, out: Callable[[str], None] = print) -> dict:
    ledger = SqliteLedger(":memory:")
    controller = ExecutionController(
        gate=ActionGate(escalate_below=0.75, route_high_risk=True),
        executor=SandboxExecutor(),
        ledger=ledger,
    )
    # The orchestrator receives ONLY a submit-only gateway — no controller, no
    # gate, no executor. Its whole vocabulary for acting is route_action.
    runtime = WorkflowRuntime(
        bank=VerifierBank(),
        gateway=ActionGateway(controller.submit),
        ledger=ledger,
    )

    workflow = build_workflow()
    out(f"=== workflow {workflow.workflow_id}: "
        f"{' -> '.join(s.step_id for s in workflow.order())} ===")
    run = runtime.run(workflow)

    for rec in run.steps:
        out(f"[step] {rec.step_id} ({rec.agent_id}): "
            f"tier={rec.tier.value} confidence={rec.confidence:.2f} "
            f"-> {rec.outcome.upper()}"
            + (f" (held #{rec.pending_id} for a human)" if rec.pending_id else ""))
    out("")
    out("[messages] what each downstream step actually received (never a bare fact):")
    for step in workflow.order():
        for dep in step.depends_on:
            out(f"  {step.step_id} <- {run.messages[dep].summary()}")
    out("")
    out(f"[chain] conservative placeholder confidence (min of steps) = "
        f"{run.chain_confidence_placeholder:.2f}  "
        f"— NOT a principled composition (see docs/orchestration.md)")

    # The high-risk export was held; the operator approves it through the
    # existing controller (the orchestrator cannot).
    held = [r for r in run.steps if r.pending_id is not None]
    for rec in held:
        out("")
        out(f"[human] operator reviews held step {rec.step_id} "
            f"(pending #{rec.pending_id}) and approves it:")
        result = controller.approve(rec.pending_id, identity="demo-operator",
                                    reason="reviewed and accepted")
        out(f"[human]   executed in sandbox '{result.sandbox_name}' "
            f"(exit {result.exit_status}); output {result.stdout.strip()!r}")

    out("")
    out("=== workflow audit (one query: ledger.workflow_steps) ===")
    steps = ledger.workflow_steps(workflow.workflow_id)
    for row in steps:
        out(f"[audit] {row['step_id']}/{row['agent_id']}: "
            f"tier={row['tier']} verdict={row['verdict']} "
            f"conf={row['confidence']:.2f} action={row['proposed_action']} "
            f"outcome={row['outcome']}"
            + (f" pending#{row['pending_id']}" if row['pending_id'] else ""))
    execs = ledger.executions()
    executed = sum(1 for e in execs if e["executed"])
    out(f"[audit] executions recorded: {len(execs)} "
        f"(executed {executed}, held/blocked {len(execs) - executed})")

    return {
        "steps": len(run.steps),
        "held": [r.step_id for r in held],
        "executed": executed,
        "workflow_steps": steps,
        "chain_placeholder": run.chain_confidence_placeholder,
    }


def main(argv=None) -> int:
    import argparse

    argparse.ArgumentParser(
        prog="python -m prometheus_protocol.orchestration.demo",
        description="A governed multi-step workflow through the real Hearth.",
    ).parse_args(argv)
    if not NamespaceSandbox.available():
        print("[demo] the namespace isolation runtime is unavailable; the "
              "approved actions cannot run sandboxed, so the demo refuses to run.")
        return 1
    summary = run_demo()
    ok = (
        summary["steps"] == 3
        and summary["held"] == ["export"]
        and summary["executed"] == 2  # implement (auto) + export (after approval)
    )
    print("[demo] " + ("governed workflow closed: tier-tagged messages, one "
                       "action approved, one high-risk action held for a human, "
                       "full per-step audit" if ok else "UNEXPECTED OUTCOME"))
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover - exercised via main() in tests
    raise SystemExit(main())
