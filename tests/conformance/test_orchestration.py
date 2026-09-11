"""Conformance: the governed orchestration layer upholds the Hearth's rules.

Five load-bearing properties, each enforced by construction and tested:

1. the orchestrator has NO authority to execute — its only door to action is a
   submit-only gateway that always ends at the gate; a soft-only (non-
   authoritative) claim cannot execute;
2. errors cannot silently compound — a downstream agent receives tier-tagged
   messages, never a bare asserted fact, and a message cannot exist untiered;
3. the human backstop holds across a workflow — a high-risk step routes to a
   human and executes nothing until approved (INV-EXEC-3);
4. a multi-step run is auditable per step (workflow_id/agent_id/tier/outcome);
5. the Hearth is byte-identical to main — the layer is a contained module.

The behavioural checks that execute an action need the isolation runtime
(skip without it, FAIL under PROM_REQUIRE_SANDBOX=1); the structural, message,
and audit checks need no runtime.
"""

from __future__ import annotations

import os

import pytest

from hearth_ledger import (
    ORCHESTRATION_FILES,
    UNSANCTIONED_MESSAGE,
    unsanctioned_changes,
)

from prometheus_protocol.core.booleans import parse_env_bool
from prometheus_protocol.core.models import (
    ACTION_PYTHON_CODE,
    ExecutableAction,
    Tier,
    Verdict,
)
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.executor import SandboxExecutor
from prometheus_protocol.gate.authorization import ActionGate, OUTCOME_UNAVAILABLE
from prometheus_protocol.policy.execution import ExecutionAuthorizer
from prometheus_protocol.gate.promotion import OUTCOME_ROUTE
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.orchestration import (
    ActionGateway,
    AgentMessage,
    AgentProposal,
    AgentStep,
    Workflow,
    WorkflowError,
    WorkflowRuntime,
)
from prometheus_protocol.orchestration.demo import ScriptedAgent, ScriptedGrader
from prometheus_protocol.sandbox import NamespaceSandbox
from prometheus_protocol.verifier.bank import VerifierBank

from tests.support.assessments import workflow_policy

_REQUIRE = parse_env_bool(
    "PROM_REQUIRE_SANDBOX", os.environ.get("PROM_REQUIRE_SANDBOX"), default=False
)


def _require_runtime() -> None:
    if not NamespaceSandbox.available():
        reason = (
            "namespace isolation runtime (unprivileged user namespaces) unavailable"
        )
        if _REQUIRE:
            pytest.fail(f"PROM_REQUIRE_SANDBOX=1 but {reason}")
        pytest.skip(reason)


def _print_action(label: str) -> ExecutableAction:
    return ExecutableAction(kind=ACTION_PYTHON_CODE, code=f"print({label!r})")


def _controller(
    ledger: SqliteLedger, *, route_high_risk: bool = True, policy=None
) -> ExecutionController:
    from prometheus_protocol.policy.profile import DEFAULT_PROFILE_ID, load_profile

    selected = policy if policy is not None else load_profile(DEFAULT_PROFILE_ID)
    return ExecutionController(
        gate=ActionGate(
            target_canonical="sandbox://workflow",
            escalate_below=0.75,
            route_high_risk=route_high_risk,
            authorizer=ExecutionAuthorizer(lambda: selected),
        ),
        executor=SandboxExecutor(),
        ledger=ledger,
    )


# --------------------------------------------------------------------------
# 1. the orchestrator has no execute authority
# --------------------------------------------------------------------------


def test_gateway_exposes_only_route_action():
    gw = ActionGateway(lambda **kw: None)
    public = {n for n in dir(gw) if not n.startswith("__")}
    # The one capability, and its single stored callable — nothing else.
    assert public == {"route_action", "_submit"}
    for forbidden in (
        "approve",
        "reject",
        "execute",
        "_execute",
        "gate",
        "_gate",
        "executor",
        "_executor",
        "controller",
        "_controller",
    ):
        assert not hasattr(gw, forbidden), forbidden


def test_runtime_has_no_executor_gate_or_execute_path():
    rt = WorkflowRuntime(
        bank=VerifierBank(),
        gateway=ActionGateway(lambda **kw: None),
        ledger=SqliteLedger(":memory:"),
        policy=workflow_policy("plan-review", "impl-check"),
    )
    for forbidden in (
        "execute",
        "_execute",
        "approve",
        "_executor",
        "executor",
        "_gate",
        "gate",
        "_controller",
        "controller",
    ):
        assert not hasattr(rt, forbidden), forbidden
    # Its only authority-bearing collaborator is the gateway.
    assert hasattr(rt, "_gateway") and isinstance(rt._gateway, ActionGateway)


def test_soft_only_claim_cannot_execute():
    """A soft-only step that proposes an action cannot execute.

    CHECKPOINT 3 MOVED WHERE THIS IS REFUSED, and the comment this replaces was
    wrong to arrange otherwise. PHASE-1.2b permitted the soft grader on purpose,
    so that the GATE would be what refused and the test kept exercising "a SOFT
    verdict never authorizes at the gate". But a policy naming an advisory
    implementation as permitted is now itself the defect: under R3 permitted
    implementations are interchangeable, so that policy asserted a soft grader
    could satisfy a requirement. Coverage refuses it, one decision earlier.

    The gate-level property is NOT lost — it is asserted directly, against the
    gate, in ``test_soft_levers.py::test_soft_stays_soft_no_lever_grants_authority``.
    Testing it through a workflow only worked by writing a policy the system now
    correctly rejects.
    """

    ledger = SqliteLedger(":memory:")
    policy = workflow_policy("soft-grader")
    bank = VerifierBank()
    bank.register("soft-grader", Tier.SOFT)
    runtime = WorkflowRuntime(
        bank=bank,
        gateway=ActionGateway(_controller(ledger, policy=policy).submit),
        ledger=ledger,
        policy=policy,
    )
    wf = Workflow(
        workflow_id="soft-wf",
        steps=(
            AgentStep(
                step_id="s1",
                agent=ScriptedAgent(
                    "a1", "do the thing", action=_print_action("x"), risk_class="low"
                ),
                grader=ScriptedGrader("soft-grader", Tier.SOFT),
                task="t",
            ),
        ),
    )
    run = runtime.run(wf)
    assert run.steps[0].outcome == OUTCOME_UNAVAILABLE
    assert run.executed_subject_ids == ()
    assert all(not e["executed"] for e in ledger.executions())


# --------------------------------------------------------------------------
# 2. no silent compounding: tier-tagged messages, never bare facts
# --------------------------------------------------------------------------


def test_agent_message_cannot_be_untiered():
    good = AgentMessage(
        workflow_id="w",
        from_step="a",
        from_agent="ag",
        content="c",
        tier=Tier.SOFT,
        verdict=Verdict.PASS,
        confidence=0.5,
        provenance="p",
    )
    assert good.tier is Tier.SOFT
    with pytest.raises(TypeError):
        AgentMessage(
            workflow_id="w",
            from_step="a",
            from_agent="ag",
            content="c",
            tier="soft",
            verdict=Verdict.PASS,
            confidence=0.5,
            provenance="p",
        )
    with pytest.raises(TypeError):
        AgentMessage(
            workflow_id="w",
            from_step="a",
            from_agent="ag",
            content="c",
            tier=Tier.SOFT,
            verdict="pass",
            confidence=0.5,
            provenance="p",
        )


def test_downstream_agent_receives_tier_tagged_messages_not_facts():
    """The runtime hands a dependent agent tuple[AgentMessage], each carrying a
    tier/verdict/confidence — a bare asserted fact cannot travel agent-to-agent."""

    captured: dict[str, tuple] = {}

    class CapturingAgent:
        agent_id = "capture"

        def propose(self, task, inputs):
            captured["inputs"] = inputs
            return AgentProposal(content="downstream output")

    ledger = SqliteLedger(":memory:")
    runtime = WorkflowRuntime(
        bank=VerifierBank(),
        gateway=ActionGateway(_controller(ledger).submit),
        ledger=ledger,
        policy=workflow_policy("plan-review", "impl-check"),
    )
    wf = Workflow(
        workflow_id="msg-wf",
        steps=(
            AgentStep(
                "up",
                ScriptedAgent("up-agent", "upstream claim"),
                ScriptedGrader("g-soft", Tier.SOFT),
                task="t",
            ),
            AgentStep(
                "down",
                CapturingAgent(),
                ScriptedGrader("g-soft2", Tier.SOFT),
                task="t",
                depends_on=("up",),
            ),
        ),
    )
    runtime.run(wf)

    inputs = captured["inputs"]
    assert isinstance(inputs, tuple) and len(inputs) == 1
    msg = inputs[0]
    assert isinstance(msg, AgentMessage)  # not a str, not a bare fact
    assert isinstance(msg.tier, Tier)  # it wears its grading
    assert isinstance(msg.verdict, Verdict)
    assert 0.0 <= msg.confidence <= 1.0
    assert msg.from_step == "up" and msg.content == "upstream claim"


# --------------------------------------------------------------------------
# 3. the human backstop holds across a workflow
# --------------------------------------------------------------------------


def test_human_backstop_holds_in_a_workflow():
    _require_runtime()
    from prometheus_protocol.orchestration.demo import build_workflow

    ledger = SqliteLedger(":memory:")
    policy = workflow_policy("plan-review", "impl-check")
    controller = _controller(ledger, policy=policy)
    runtime = WorkflowRuntime(
        bank=VerifierBank(),
        gateway=ActionGateway(controller.submit),
        ledger=ledger,
        policy=policy,
    )
    run = runtime.run(build_workflow())

    export = next(r for r in run.steps if r.step_id == "export")
    assert export.outcome == OUTCOME_ROUTE and export.pending_id is not None
    # Before approval: only the auto-approved `implement` executed; the held
    # high-risk action has run nothing.
    assert sum(1 for e in ledger.executions() if e["executed"]) == 1
    assert not ledger.executions_for_pending(export.pending_id)

    # The operator approves through the CONTROLLER (the orchestrator cannot).
    result = controller.approve(export.pending_id, identity="op", reason="ok")
    assert result.executed
    assert sum(1 for e in ledger.executions() if e["executed"]) == 2


# --------------------------------------------------------------------------
# 4. the workflow is auditable per step
# --------------------------------------------------------------------------


def test_workflow_run_is_auditable_per_step():
    ledger = SqliteLedger(":memory:")
    runtime = WorkflowRuntime(
        bank=VerifierBank(),
        gateway=ActionGateway(_controller(ledger).submit),
        ledger=ledger,
        policy=workflow_policy("plan-review", "impl-check"),
    )
    wf = Workflow(
        workflow_id="audit-wf",
        steps=(
            AgentStep(
                "a",
                ScriptedAgent("agent-a", "claim a"),
                ScriptedGrader("g", Tier.SOFT),
                task="t",
            ),
            AgentStep(
                "b",
                ScriptedAgent("agent-b", "claim b"),
                ScriptedGrader("h", Tier.HARD),
                task="t",
                depends_on=("a",),
            ),
        ),
    )
    runtime.run(wf)
    rows = ledger.workflow_steps("audit-wf")
    assert [r["step_id"] for r in rows] == ["a", "b"]
    assert [r["agent_id"] for r in rows] == ["agent-a", "agent-b"]
    assert [r["tier"] for r in rows] == ["soft", "hard"]
    assert ledger.workflow_steps("no-such-wf") == []  # scoped by workflow_id


# --------------------------------------------------------------------------
# DAG validation (unit-ish; no runtime)
# --------------------------------------------------------------------------


def test_workflow_dag_order_is_deterministic_and_validated():
    steps = (
        AgentStep(
            "c",
            ScriptedAgent("c", "c"),
            ScriptedGrader("g", Tier.SOFT),
            task="t",
            depends_on=("a", "b"),
        ),
        AgentStep(
            "a", ScriptedAgent("a", "a"), ScriptedGrader("g", Tier.SOFT), task="t"
        ),
        AgentStep(
            "b", ScriptedAgent("b", "b"), ScriptedGrader("g", Tier.SOFT), task="t"
        ),
    )
    order = [s.step_id for s in Workflow(steps=steps).order()]
    assert order == ["a", "b", "c"]  # topo, ties broken by id

    with pytest.raises(WorkflowError):  # unknown dependency
        Workflow(
            steps=(
                AgentStep(
                    "x",
                    ScriptedAgent("x", "x"),
                    ScriptedGrader("g", Tier.SOFT),
                    task="t",
                    depends_on=("missing",),
                ),
            )
        )
    with pytest.raises(WorkflowError):  # cycle
        Workflow(
            steps=(
                AgentStep(
                    "p",
                    ScriptedAgent("p", "p"),
                    ScriptedGrader("g", Tier.SOFT),
                    task="t",
                    depends_on=("q",),
                ),
                AgentStep(
                    "q",
                    ScriptedAgent("q", "q"),
                    ScriptedGrader("g", Tier.SOFT),
                    task="t",
                    depends_on=("p",),
                ),
            )
        )
    with pytest.raises(WorkflowError):  # duplicate id
        Workflow(
            steps=(
                AgentStep(
                    "d",
                    ScriptedAgent("d", "d"),
                    ScriptedGrader("g", Tier.SOFT),
                    task="t",
                ),
                AgentStep(
                    "d",
                    ScriptedAgent("d2", "d2"),
                    ScriptedGrader("g", Tier.SOFT),
                    task="t",
                ),
            )
        )


# --------------------------------------------------------------------------
# 5. the Hearth is the sanctioned CONTENT (not a diff against a branch)
# --------------------------------------------------------------------------

_HEARTH_FILES = ORCHESTRATION_FILES


def test_hearth_is_the_sanctioned_content():
    """The orchestration layer is a contained module: it changes no Hearth-core
    file (bank, both gates, executor, controller, pending, forge, core models
    and interfaces). The SQLite ledger is extended additively and is
    intentionally not in this set.

    THE COMPARISON REFERENCE IS THE LEDGER, NOT A BRANCH. This used to run
    ``git diff --name-only origin/main`` and reject changed paths outside a
    permitted set. Two defects, both closed here:

    * the permitted set was over PATHS, so a file sanctioned once — including
      ``gate/authorization.py`` — was sanctioned FOREVER, and every later edit
      to it was invisible rather than allowed;
    * on main the diff against ``origin/main`` is empty, so after each merge the
      guard asserted nothing at all.

    Hashing the files on disk fixes both: any edit to any frozen file fails until
    its digest is updated deliberately, and the assertion holds identically on a
    branch, on main, in a worktree and in a fresh clone. The ``skipif origin/main
    is unresolvable`` marker is gone with the git dependency — it was how these
    guards silently stopped running under a shallow checkout.
    """

    unsanctioned = unsanctioned_changes(_HEARTH_FILES)
    assert unsanctioned == [], UNSANCTIONED_MESSAGE + "\n" + "\n".join(unsanctioned)
