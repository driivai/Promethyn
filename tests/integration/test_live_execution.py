"""Milestone: one real code-domain task, executed for real, end to end.

A real solution is graded by the HARD subprocess verifier (through the sandbox),
the bank turns that evidence into a judgment, and the execution controller acts
on it:

  * an approved, high-confidence, low-risk action EXECUTES inside the sandbox;
  * the same action at high risk HALTS for a human and only executes after a
    recorded approval;
  * a failing solution is BLOCKED and never executes.

Every path is written to the ledger. This is the proof that execution is on and
safe. It requires the isolation runtime: it SKIPs without it, but FAILS under
PROM_REQUIRE_SANDBOX=1 (CI), so a green CI proves the milestone under real
isolation.
"""

from __future__ import annotations

import os

import pytest

from prometheus_protocol.core.models import (
    ACTION_PYTHON_CODE,
    Case,
    ExecutableAction,
    Task,
    Verdict,
)
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.executor import SandboxExecutor
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import (
    OUTCOME_APPROVE,
    OUTCOME_BLOCK,
    OUTCOME_ROUTE,
)
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.sandbox import NamespaceSandbox
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.runner import SubprocessVerifier
from prometheus_protocol.verifier.store import InMemoryTrustStore

_REQUIRE = (os.environ.get("PROM_REQUIRE_SANDBOX", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}

_TASK = Task(
    id="live/add",
    entry_point="add",
    prompt="",
    split="train",
    cases=(Case((2, 3), 5), Case((0, 0), 0), Case((-1, 1), 0)),
)
_GOOD = "def add(a, b):\n    return a + b\n"
_BAD = "def add(a, b):\n    return a - b\n"
# The action prints a marker so the test can prove the code really ran in-sandbox.
_ACTION_CODE = _GOOD + "\nif __name__ == '__main__':\n    print('add(2,3)=', add(2, 3))\n"


def _require_sandbox() -> None:
    if not NamespaceSandbox.available():
        reason = "namespace isolation runtime (unprivileged user namespaces) unavailable"
        if _REQUIRE:
            pytest.fail(f"PROM_REQUIRE_SANDBOX=1 but {reason}")
        pytest.skip(reason)


def _judge(code: str):
    """Real HARD verification of ``code`` -> a fused bank judgment."""

    verifier = SubprocessVerifier(memory_mb=0, sandbox=NamespaceSandbox())
    bank = VerifierBank(InMemoryTrustStore())
    bank.register(verifier.verifier_id, verifier.tier)
    return bank.judge([verifier.verify(code=code, task=_TASK)])


def test_milestone_live_execution_end_to_end():
    _require_sandbox()
    ledger = SqliteLedger(":memory:")
    controller = ExecutionController(
        gate=ActionGate(escalate_below=0.75, route_high_risk=True),
        executor=SandboxExecutor(sandbox=NamespaceSandbox()),
        ledger=ledger,
        clock=lambda: "2026-07-01T00:00:00Z",
    )
    action = ExecutableAction(kind=ACTION_PYTHON_CODE, code=_ACTION_CODE, entry_point="add")

    # The correct solution earns an authoritative PASS at full confidence.
    good = _judge(_GOOD)
    assert good.verdict == Verdict.PASS and good.authoritative

    # 1. APPROVED, high-confidence, low-risk -> EXECUTES inside the sandbox.
    approved = controller.submit(
        judgment=good, action=action, risk_class="low", subject_id="live/ok"
    )
    assert approved.outcome == OUTCOME_APPROVE
    assert approved.execution.executed and approved.execution.sandbox_name == "namespace"
    assert approved.execution.exit_status == 0
    assert "add(2,3)= 5" in approved.execution.stdout

    # 2. The SAME action at HIGH risk HALTS for a human, then executes on approval.
    held = controller.submit(
        judgment=good, action=action, risk_class="high", subject_id="live/hold"
    )
    assert held.outcome == OUTCOME_ROUTE and held.execution is None
    result = controller.approve(
        held.pending.id, identity="will@driivai.com", reason="reviewed"
    )
    assert result.executed and "add(2,3)= 5" in result.stdout

    # 3. A FAILING solution is BLOCKED and never executes.
    bad = _judge(_BAD)
    assert bad.verdict == Verdict.FAIL
    blocked = controller.submit(
        judgment=bad, action=action, risk_class="low", subject_id="live/bad"
    )
    assert blocked.outcome == OUTCOME_BLOCK and blocked.execution is None

    # Audit: all three paths are recorded, re-readable end to end.
    execs = ledger.executions()
    assert [e["source"] for e in execs] == ["auto-approved", "human-approved", "blocked"]
    assert ledger.pending_action(held.pending.id)["decided_by"] == "will@driivai.com"
    assert len(ledger.pending_actions()) == 1
