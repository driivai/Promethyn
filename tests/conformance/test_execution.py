"""Phase 2 conformance: INV-EXEC-1..4 — turning execution on, safely.

INV-EXEC-1 sandbox mandatory (fail-closed); INV-EXEC-2 approved-only;
INV-EXEC-3 the human halt (load-bearing); INV-EXEC-4 audit completeness.

The fail-closed refusals, the approved-only wall, the human halt, and the audit
chain need no isolation runtime and always run. The positive "it really executed
inside isolation" assertions require the namespace sandbox: they SKIP when the
runtime is absent, but FAIL instead when PROM_REQUIRE_SANDBOX=1 (CI), so green
there always means execution was proven under real isolation, not skipped.
"""

from __future__ import annotations

import os

import pytest

from prometheus_protocol.core.models import (
    ACTION_PYTHON_CODE,
    ExecutableAction,
    Judgment,
    Verdict,
)
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.executor import SandboxExecutor
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import OUTCOME_ROUTE, GateDecision
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.sandbox import NamespaceSandbox
from prometheus_protocol.sandbox.unsafe import NullSandbox, UnsafeLocalSandbox
from prometheus_protocol.swarm.executor import Executor
from prometheus_protocol.swarm.models import (
    ExecutionResult,
    Proposal,
    Provenance,
    TestPlan,
    content_hash,
)

_REQUIRE = (os.environ.get("PROM_REQUIRE_SANDBOX", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}
_CLOCK = "2026-07-01T00:00:00Z"
_PASS_HIGH = Judgment(verdict=Verdict.PASS, confidence=0.99, authoritative=True)
_PASS_LOW = Judgment(verdict=Verdict.PASS, confidence=0.60, authoritative=True)
_FAIL = Judgment(verdict=Verdict.FAIL, confidence=0.99, authoritative=True)


def _isolating_sandbox() -> NamespaceSandbox:
    if not NamespaceSandbox.available():
        reason = "namespace isolation runtime (unprivileged user namespaces) unavailable"
        if _REQUIRE:
            pytest.fail(f"PROM_REQUIRE_SANDBOX=1 but {reason}")
        pytest.skip(reason)
    return NamespaceSandbox()


class _SpyExecutor(Executor):
    """Records every decision that crosses into execution, without side effects.

    Honours the same wall as the real executor, so it can stand in wherever the
    property under test is the *control flow* (did execution happen at all?)
    rather than the sandboxed side-effect.
    """

    def __init__(self) -> None:
        self.calls: list[GateDecision] = []

    def execute(self, decision: GateDecision) -> ExecutionResult:
        if not isinstance(decision, GateDecision):
            raise TypeError("Executor.execute accepts only a GateDecision")
        if not decision.approved:
            raise ValueError("refusing to execute an unapproved gate decision")
        self.calls.append(decision)
        return ExecutionResult(executed=True, subject_id=decision.subject_id, detail="spy")


def _action(code: str = "print('MARK')") -> ExecutableAction:
    return ExecutableAction(kind=ACTION_PYTHON_CODE, code=code)


def _approved(code: str = "print('RAN')") -> GateDecision:
    return GateDecision(
        approved=True, subject_id="s", action=_action(code), outcome="approve"
    )


def _controller(executor: Executor) -> ExecutionController:
    return ExecutionController(
        gate=ActionGate(escalate_below=0.75, route_high_risk=True),
        executor=executor,
        ledger=SqliteLedger(":memory:"),
        clock=lambda: _CLOCK,
    )


# -- INV-EXEC-1: the sandbox is mandatory for execution (fail-closed) -------


def test_inv_exec_1_refuses_when_no_isolating_sandbox():
    # NullSandbox: isolation cannot start -> refuse; the action did not run.
    r_null = SandboxExecutor(sandbox=NullSandbox()).execute(_approved())
    assert r_null.refused and not r_null.executed and not r_null.started_ok

    # The unsafe runner (isolating=False) is refused BEFORE it can run anything:
    # execution must never degrade to running in the clear.
    r_unsafe = SandboxExecutor(sandbox=UnsafeLocalSandbox()).execute(_approved())
    assert r_unsafe.refused and not r_unsafe.executed
    assert "RAN" not in r_unsafe.stdout  # it never ran unsandboxed


def test_inv_exec_1_executes_inside_isolation():
    sandbox = _isolating_sandbox()
    result = SandboxExecutor(sandbox=sandbox).execute(_approved("print('INSIDE-SANDBOX')"))
    assert result.executed and not result.refused
    assert result.sandbox_name == sandbox.name and result.exit_status == 0
    assert "INSIDE-SANDBOX" in result.stdout


def test_inv_exec_1_network_is_denied_during_execution():
    sandbox = _isolating_sandbox()
    code = (
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 80), 2); print('NET-REACHED')\n"
        "except OSError:\n"
        "    print('NET-DENIED')\n"
    )
    result = SandboxExecutor(sandbox=sandbox).execute(_approved(code))
    assert result.executed
    assert "NET-DENIED" in result.stdout and "NET-REACHED" not in result.stdout


# -- INV-EXEC-2: the executor accepts only an approved GateDecision ---------


def test_inv_exec_2_executor_accepts_only_approved_gate_decision():
    ex = SandboxExecutor(sandbox=NullSandbox())
    proposal = Proposal(
        id="p", role_id="r", kind="proposed_action", content="c", rationale="r",
        provenance=Provenance(content_hash=content_hash("c")),
    )
    with pytest.raises(TypeError):
        ex.execute(proposal)  # a raw proposal cannot be executed
    with pytest.raises(TypeError):
        ex.execute(TestPlan(entries=()))  # nor a test plan
    with pytest.raises(ValueError):
        # a blocked / unapproved decision cannot be executed
        ex.execute(GateDecision(approved=False, subject_id="s", action=_action(), outcome="block"))


def test_inv_exec_2_a_pending_action_cannot_reach_the_executor():
    spy = _SpyExecutor()
    controller = _controller(spy)
    outcome = controller.submit(
        judgment=_PASS_LOW, action=_action(), risk_class="low", subject_id="s"
    )
    assert outcome.outcome == OUTCOME_ROUTE
    assert spy.calls == []  # a held action never reached execution


# -- INV-EXEC-3: the human halt (load-bearing) -----------------------------


def test_inv_exec_3_no_execution_without_a_recorded_human_approval():
    spy = _SpyExecutor()
    controller = _controller(spy)
    held = controller.submit(judgment=_PASS_LOW, action=_action(), subject_id="s").pending
    assert spy.calls == []  # routed: nothing executed

    controller.approve(held.id, identity="will@driivai.com", reason="ok")
    assert len(spy.calls) == 1  # executes only after the recorded approval

    row = controller.pending.get(held.id)
    assert row.status.value == "approved"
    assert row.human_decision.identity == "will@driivai.com"


def test_inv_exec_3_a_rejected_action_never_executes():
    spy = _SpyExecutor()
    controller = _controller(spy)
    held = controller.submit(judgment=_PASS_LOW, action=_action(), subject_id="s").pending
    controller.reject(held.id, identity="will@driivai.com", reason="no")
    assert spy.calls == []


def test_inv_exec_3_high_risk_halts_even_at_high_confidence():
    spy = _SpyExecutor()
    controller = _controller(spy)
    outcome = controller.submit(
        judgment=_PASS_HIGH, action=_action(), risk_class="high", subject_id="s"
    )
    assert outcome.outcome == OUTCOME_ROUTE and spy.calls == []


# -- INV-EXEC-4: every execution and human decision is auditable -----------


def test_inv_exec_4_execution_chain_is_re_readable_from_the_ledger():
    ledger = SqliteLedger(":memory:")
    controller = ExecutionController(
        gate=ActionGate(escalate_below=0.75, route_high_risk=True),
        executor=_SpyExecutor(),
        ledger=ledger,
        clock=lambda: _CLOCK,
    )
    controller.submit(judgment=_PASS_HIGH, action=_action(), subject_id="s/auto")
    held = controller.submit(judgment=_PASS_LOW, action=_action(), subject_id="s/hold").pending
    controller.approve(held.id, identity="will@driivai.com")
    controller.submit(judgment=_FAIL, action=_action(), subject_id="s/block")

    execs = ledger.executions()
    assert [e["source"] for e in execs] == ["auto-approved", "human-approved", "blocked"]
    # The human decision is queryable end to end.
    resolved = ledger.pending_action(held.id)
    assert resolved["status"] == "approved" and resolved["decided_by"] == "will@driivai.com"
    # Nothing happened off-ledger: one pending row, three execution rows.
    assert len(ledger.pending_actions()) == 1 and len(execs) == 3
