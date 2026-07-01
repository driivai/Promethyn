"""Hardening the halt: pending-action expiry and the approve->execute loop.

Two gaps live execution left open: holds never expired, and CLI approval did not
execute. These cover the fix without weakening any INV-EXEC guarantee — nothing
low-confidence auto-executes, and execution still runs only through the gated,
sandboxed, fail-closed path.

The expiry, stale-approval, and fail-closed cases need no isolation runtime and
always run. The positive "approval really executes in the sandbox" cases run
under the namespace runtime: they SKIP when it is absent but FAIL under
PROM_REQUIRE_SANDBOX=1, so a green CI proves them under real isolation.
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
from prometheus_protocol.execution.models import PendingStatus
from prometheus_protocol.execution.pending import PendingActionService
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import GateDecision
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.sandbox import NamespaceSandbox
from prometheus_protocol.sandbox.unsafe import NullSandbox
from prometheus_protocol.swarm.executor import Executor
from prometheus_protocol.swarm.models import ExecutionResult

_REQUIRE = (os.environ.get("PROM_REQUIRE_SANDBOX", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}
_T0 = "2026-07-01T00:00:00Z"
_T0_PLUS_200 = "2026-07-01T00:03:20Z"  # +200 seconds
_LOW = Judgment(verdict=Verdict.PASS, confidence=0.60, authoritative=True)


class _Clock:
    """A settable clock: advancing ``now`` models time passing between calls."""

    def __init__(self, now: str) -> None:
        self.now = now

    def __call__(self) -> str:
        return self.now


class _SpyExecutor(Executor):
    """Records every decision that crosses into execution, without side effects."""

    def __init__(self) -> None:
        self.calls: list[GateDecision] = []

    def execute(self, decision: GateDecision) -> ExecutionResult:
        if not isinstance(decision, GateDecision):
            raise TypeError("Executor.execute accepts only a GateDecision")
        if not decision.approved:
            raise ValueError("refusing to execute an unapproved gate decision")
        self.calls.append(decision)
        return ExecutionResult(executed=True, subject_id=decision.subject_id, detail="spy")


def _action(code: str = "print('mark')") -> ExecutableAction:
    return ExecutableAction(kind=ACTION_PYTHON_CODE, code=code)


def _harness(*, ttl: int, clock: _Clock, executor: Executor | None = None):
    ledger = SqliteLedger(":memory:")
    executor = executor if executor is not None else _SpyExecutor()
    controller = ExecutionController(
        gate=ActionGate(escalate_below=0.75, route_high_risk=True),
        executor=executor,
        ledger=ledger,
        clock=clock,
        ttl_seconds=ttl,
    )
    return controller, ledger, executor


def _isolating_sandbox() -> NamespaceSandbox:
    if not NamespaceSandbox.available():
        reason = "namespace isolation runtime (unprivileged user namespaces) unavailable"
        if _REQUIRE:
            pytest.fail(f"PROM_REQUIRE_SANDBOX=1 but {reason}")
        pytest.skip(reason)
    return NamespaceSandbox()


# -- expiry via sweep -------------------------------------------------------


def test_sweep_expires_lapsed_pending_and_audits_the_transition():
    clock = _Clock(_T0)
    controller, ledger, spy = _harness(ttl=100, clock=clock)
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending

    clock.now = _T0_PLUS_200  # time passes beyond the 100s TTL
    expired = controller.sweep()

    assert [p.id for p in expired] == [held.id]
    assert controller.pending.get(held.id).status == PendingStatus.EXPIRED
    assert spy.calls == []  # expiry never executes anything
    # The transition is fully audited in the ledger.
    row = ledger.pending_action(held.id)
    assert row["status"] == "expired"
    assert row["decided_by"] == "system:sweep"
    assert "TTL" in row["decision_reason"]
    assert row["decided_at"] == _T0_PLUS_200


def test_sweep_is_idempotent():
    clock = _Clock(_T0)
    controller, _ledger, _spy = _harness(ttl=100, clock=clock)
    controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    clock.now = _T0_PLUS_200
    assert len(controller.sweep()) == 1
    assert controller.sweep() == []  # already expired: a no-op


def test_ttl_zero_disables_expiry():
    clock = _Clock("2020-01-01T00:00:00Z")
    controller, _ledger, spy = _harness(ttl=0, clock=clock)
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    clock.now = "2030-01-01T00:00:00Z"  # ten years later
    assert controller.sweep() == []
    assert controller.pending.get(held.id).status == PendingStatus.PENDING
    # and it remains approvable
    controller.approve(held.id, identity="will@driivai.com")
    assert len(spy.calls) == 1


# -- expiry blocks approval / execution -------------------------------------


def test_expired_action_cannot_be_approved_or_executed():
    clock = _Clock(_T0)
    controller, _ledger, spy = _harness(ttl=100, clock=clock)
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    clock.now = _T0_PLUS_200
    controller.sweep()  # -> EXPIRED

    with pytest.raises(ValueError):
        controller.approve(held.id, identity="will@driivai.com")
    assert spy.calls == []  # an expired hold never executes


def test_stale_approval_is_refused_even_without_a_sweep():
    """The load-bearing race: a hold lapses but no sweep has run yet."""

    clock = _Clock(_T0)
    controller, _ledger, spy = _harness(ttl=100, clock=clock)
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending

    clock.now = _T0_PLUS_200  # past TTL; sweep has NOT run
    with pytest.raises(ValueError, match="expired"):
        controller.approve(held.id, identity="will@driivai.com")

    assert spy.calls == []  # the stale approval did not execute
    # approval expired it on the spot, audited
    assert controller.pending.get(held.id).status == PendingStatus.EXPIRED


def test_already_resolved_action_cannot_be_re_approved():
    clock = _Clock(_T0)
    controller, _ledger, spy = _harness(ttl=0, clock=clock)
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    controller.approve(held.id, identity="will@driivai.com")
    with pytest.raises(ValueError):
        controller.approve(held.id, identity="someone-else")
    with pytest.raises(ValueError):
        controller.reject(held.id, identity="someone-else")
    assert len(spy.calls) == 1  # only the first, legitimate approval ran


# -- INV-EXEC-3 preserved: no new auto-execution path -----------------------


def test_expiry_does_not_create_an_auto_execution_path():
    clock = _Clock(_T0)
    controller, _ledger, spy = _harness(ttl=100, clock=clock)
    # A low-confidence action still routes and holds — never auto-executes.
    outcome = controller.submit(judgment=_LOW, action=_action(), subject_id="s")
    assert outcome.pending is not None and outcome.execution is None
    assert spy.calls == []


# -- approve -> execute through the sandbox ---------------------------------


def test_approve_executes_through_the_sandbox():
    sandbox = _isolating_sandbox()
    clock = _Clock(_T0)
    controller, ledger, _ = _harness(
        ttl=0, clock=clock, executor=SandboxExecutor(sandbox=sandbox)
    )
    held = controller.submit(
        judgment=_LOW, action=_action("print('APPROVED-AND-RAN')"), subject_id="s"
    ).pending

    result = controller.approve(held.id, identity="will@driivai.com", reason="ok")
    assert result.executed and not result.refused
    assert result.sandbox_name == sandbox.name and "APPROVED-AND-RAN" in result.stdout
    # audited as a human-approved execution
    execs = ledger.executions()
    assert [e["source"] for e in execs] == ["human-approved"]
    assert execs[0]["executed"] is True


def test_approve_fails_closed_without_an_isolating_sandbox():
    clock = _Clock(_T0)
    # NullSandbox: isolation cannot start. Approval records; execution refuses.
    controller, ledger, _ = _harness(
        ttl=0, clock=clock, executor=SandboxExecutor(sandbox=NullSandbox())
    )
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending

    result = controller.approve(held.id, identity="will@driivai.com")
    assert result.refused and not result.executed  # fail-closed, not degraded
    # The approval is recorded, and the refusal is recorded — nothing ran unsandboxed.
    assert controller.pending.get(held.id).status == PendingStatus.APPROVED
    execs = ledger.executions()
    assert len(execs) == 1 and execs[0]["refused"] is True and execs[0]["executed"] is False


# -- CLI: sweep, expired-refuses, and record-only ---------------------------


def _seed_pending(ledger_path: str, *, created_at: str, subject: str, code: str) -> int:
    ledger = SqliteLedger(ledger_path)
    service = PendingActionService(ledger, clock=lambda: created_at, ttl_seconds=999_999)
    decision = ActionGate(escalate_below=0.75, route_high_risk=True).decide(
        _LOW, risk_class="low", subject_id=subject, action=_action(code)
    )
    held = service.hold(decision, risk_class="low")
    ledger.close()
    return held.id


def test_cli_sweep_expires_then_approve_refuses(tmp_path, monkeypatch, capsys):
    from prometheus_protocol.cli.main import main

    db = str(tmp_path / "ledger.db")
    pid = _seed_pending(db, created_at="2020-01-01T00:00:00Z", subject="deploy/old", code="print('x')")
    monkeypatch.setenv("PROM_LEDGER_PATH", db)
    monkeypatch.setenv("PROM_PENDING_TTL", "1")

    assert main(["sweep"]) == 0
    assert "1 pending action(s) expired" in capsys.readouterr().out
    # An expired hold cannot be approved and does not execute.
    assert main(["approve", str(pid), "--by", "will@driivai.com"]) == 1
    assert "expired" in capsys.readouterr().err
    assert SqliteLedger(db).executions() == []  # nothing ran


def test_cli_approve_no_exec_records_only(tmp_path, monkeypatch, capsys):
    from prometheus_protocol.cli.main import main

    db = str(tmp_path / "ledger.db")
    pid = _seed_pending(db, created_at="2026-07-01T00:00:00Z", subject="deploy/x", code="print('x')")
    monkeypatch.setenv("PROM_LEDGER_PATH", db)
    monkeypatch.setenv("PROM_PENDING_TTL", "0")  # disable expiry for a stable id

    assert main(["approve", str(pid), "--by", "will@driivai.com", "--no-exec"]) == 0
    assert "recorded, not executed" in capsys.readouterr().out
    ledger = SqliteLedger(db)
    assert ledger.pending_action(pid)["status"] == "approved"
    assert ledger.executions() == []  # --no-exec did not run anything


def test_cli_approve_executes_through_the_sandbox(tmp_path, monkeypatch, capsys):
    _isolating_sandbox()  # gate: needs the isolation runtime
    from prometheus_protocol.cli.main import main

    db = str(tmp_path / "ledger.db")
    pid = _seed_pending(
        db, created_at="2026-07-01T00:00:00Z", subject="deploy/ok", code="print('CLI-RAN')"
    )
    monkeypatch.setenv("PROM_LEDGER_PATH", db)
    monkeypatch.setenv("PROM_PENDING_TTL", "0")

    assert main(["approve", str(pid), "--by", "will@driivai.com"]) == 0
    assert "executed in sandbox" in capsys.readouterr().out
    execs = SqliteLedger(db).executions()
    assert len(execs) == 1 and execs[0]["source"] == "human-approved" and execs[0]["executed"] is True
