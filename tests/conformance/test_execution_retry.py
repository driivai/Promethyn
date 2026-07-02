"""The retry verb: re-driving an approved-but-never-executed hold, narrowly.

An action approved while the sandbox was unavailable fail-closes (INV-EXEC-1)
and used to sit `approved`-but-never-executed with no path forward, because a
decided hold is not re-approvable (by design — that stays true). `retry-execution`
closes the gap without loosening anything: it is valid ONLY for an approved hold
that has never successfully executed, it re-drives the SAME gated, sandboxed,
fail-closed controller path, it never touches the human decision record, and
every attempt — eligible or not — is recorded.

The retry window reuses the existing TTL semantics: a retry is accepted only
within `ttl_seconds` of the recorded approval, exactly as a pending hold is
approvable only within `ttl_seconds` of its creation; `ttl_seconds <= 0`
disables both.

The state-machine and audit cases need no isolation runtime and always run. The
positive "retry really executes in the sandbox" case runs under the namespace
runtime: it SKIPs when absent but FAILs under PROM_REQUIRE_SANDBOX=1.
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
_LOW = Judgment(verdict=Verdict.PASS, confidence=0.60, authoritative=True)


class _Clock:
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


def _controller(ledger, *, executor: Executor, clock: _Clock, ttl: int = 0):
    return ExecutionController(
        gate=ActionGate(escalate_below=0.75, route_high_risk=True),
        executor=executor,
        ledger=ledger,
        clock=clock,
        ttl_seconds=ttl,
    )


def _isolating_sandbox() -> NamespaceSandbox:
    if not NamespaceSandbox.available():
        reason = "namespace isolation runtime (unprivileged user namespaces) unavailable"
        if _REQUIRE:
            pytest.fail(f"PROM_REQUIRE_SANDBOX=1 but {reason}")
        pytest.skip(reason)
    return NamespaceSandbox()


def _decision_record(ledger, pending_id: int) -> tuple:
    row = ledger.pending_action(pending_id)
    return (
        row["status"],
        row["decided_by"],
        row["decided_at"],
        row["decision_reason"],
    )


# -- the eligible state: approved, execution refused or deferred -------------


def test_retry_executes_an_approval_refused_by_a_missing_sandbox():
    ledger = SqliteLedger(":memory:")
    clock = _Clock(_T0)
    # The outage: approval fail-closes because no isolating sandbox is available.
    outage = _controller(
        ledger, executor=SandboxExecutor(sandbox=NullSandbox()), clock=clock
    )
    held = outage.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    refused = outage.approve(held.id, identity="will@driivai.com", reason="ok")
    assert refused.refused and not refused.executed
    decided_before = _decision_record(ledger, held.id)

    # The sandbox is back (a fresh controller over the same ledger, as after a
    # restart): the retry re-drives execution through the same gated path.
    spy = _SpyExecutor()
    recovered = _controller(ledger, executor=spy, clock=clock)
    result = recovered.retry_execution(held.id, identity="will@driivai.com")

    assert result.executed and not result.refused
    assert len(spy.calls) == 1 and spy.calls[0].approved
    execs = ledger.executions()
    assert [e["source"] for e in execs] == ["human-approved", "human-approved-retry"]
    assert execs[0]["refused"] is True and execs[1]["executed"] is True
    assert execs[1]["pending_id"] == held.id
    # The human decision record is untouched by the retry.
    assert _decision_record(ledger, held.id) == decided_before
    assert ledger.pending_action(held.id)["status"] == "approved"


def test_retry_executes_a_deferred_no_exec_approval():
    ledger = SqliteLedger(":memory:")
    clock = _Clock(_T0)
    spy = _SpyExecutor()
    controller = _controller(ledger, executor=spy, clock=clock)
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    # Deferred: the approval is recorded, execution deliberately not driven.
    controller.pending.approve(held.id, identity="will@driivai.com")
    assert ledger.executions() == []

    result = controller.retry_execution(held.id, identity="will@driivai.com")
    assert result.executed and len(spy.calls) == 1
    assert ledger.executions()[0]["source"] == "human-approved-retry"


def test_retry_fail_closes_again_when_the_sandbox_is_still_missing():
    ledger = SqliteLedger(":memory:")
    clock = _Clock(_T0)
    controller = _controller(
        ledger, executor=SandboxExecutor(sandbox=NullSandbox()), clock=clock
    )
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    controller.approve(held.id, identity="will@driivai.com")

    result = controller.retry_execution(held.id, identity="will@driivai.com")
    assert result.refused and not result.executed  # fail-closed, not degraded
    execs = ledger.executions()
    assert [e["source"] for e in execs] == ["human-approved", "human-approved-retry"]
    assert all(e["refused"] for e in execs) and all(not e["executed"] for e in execs)
    # A refused retry consumes nothing: the hold is still retry-eligible.
    again = controller.retry_execution(held.id, identity="will@driivai.com")
    assert again.refused and len(ledger.executions()) == 3


# -- ineligible states are refused, recorded, and execute nothing ------------


def test_retry_is_refused_for_a_still_pending_hold():
    ledger = SqliteLedger(":memory:")
    spy = _SpyExecutor()
    controller = _controller(ledger, executor=spy, clock=_Clock(_T0))
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending

    with pytest.raises(ValueError, match="still pending"):
        controller.retry_execution(held.id, identity="will@driivai.com")
    assert spy.calls == []  # the halt is not bypassable
    execs = ledger.executions()
    assert [e["source"] for e in execs] == ["retry-refused"]
    assert execs[0]["pending_id"] == held.id and not execs[0]["executed"]
    assert ledger.pending_action(held.id)["status"] == "pending"


def test_retry_is_refused_for_a_rejected_hold():
    ledger = SqliteLedger(":memory:")
    spy = _SpyExecutor()
    controller = _controller(ledger, executor=spy, clock=_Clock(_T0))
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    controller.reject(held.id, identity="will@driivai.com", reason="no")
    decided_before = _decision_record(ledger, held.id)

    with pytest.raises(ValueError, match="rejected"):
        controller.retry_execution(held.id, identity="will@driivai.com")
    assert spy.calls == []
    assert ledger.executions()[-1]["source"] == "retry-refused"
    assert _decision_record(ledger, held.id) == decided_before


def test_retry_is_refused_for_an_expired_hold():
    ledger = SqliteLedger(":memory:")
    spy = _SpyExecutor()
    clock = _Clock(_T0)
    controller = _controller(ledger, executor=spy, clock=clock, ttl=100)
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    clock.now = "2026-07-01T00:03:20Z"  # +200s: past the TTL
    controller.sweep()
    assert ledger.pending_action(held.id)["status"] == "expired"

    with pytest.raises(ValueError, match="expired"):
        controller.retry_execution(held.id, identity="will@driivai.com")
    assert spy.calls == []
    assert ledger.executions()[-1]["source"] == "retry-refused"


def test_retry_is_refused_for_an_already_executed_hold():
    ledger = SqliteLedger(":memory:")
    spy = _SpyExecutor()
    controller = _controller(ledger, executor=spy, clock=_Clock(_T0))
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    controller.approve(held.id, identity="will@driivai.com")  # executed (spy)
    assert len(spy.calls) == 1

    with pytest.raises(ValueError, match="already executed"):
        controller.retry_execution(held.id, identity="will@driivai.com")
    assert len(spy.calls) == 1  # it did not run a second time
    assert ledger.executions()[-1]["source"] == "retry-refused"


def test_a_successful_retry_cannot_itself_be_retried():
    """Non-amplification: a retry that executes is as terminal as an approval —
    a second retry sees the executed retry row and is refused."""

    ledger = SqliteLedger(":memory:")
    spy = _SpyExecutor()
    controller = _controller(ledger, executor=spy, clock=_Clock(_T0))
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    controller.pending.approve(held.id, identity="will@driivai.com")  # deferred
    assert controller.retry_execution(held.id, identity="will@driivai.com").executed
    assert len(spy.calls) == 1

    with pytest.raises(ValueError, match="already executed"):
        controller.retry_execution(held.id, identity="will@driivai.com")
    assert len(spy.calls) == 1  # the executed retry is terminal too


# -- at-most-once execution under concurrency (atomic claim) -----------------


def test_a_claimed_hold_cannot_be_double_executed_by_a_retry():
    """The TOCTOU guard: if another driver has claimed the execution (its
    side-effect in flight), a racing retry passes its read-only eligibility
    check but is refused by the atomic claim — it never reaches the executor."""

    ledger = SqliteLedger(":memory:")
    spy = _SpyExecutor()
    controller = _controller(ledger, executor=spy, clock=_Clock(_T0))
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    controller.pending.approve(held.id, identity="will@driivai.com")  # deferred

    # Simulate a concurrent driver that has already claimed the execution.
    assert ledger.claim_pending_execution(held.id, _T0) is True

    result = controller.retry_execution(held.id, identity="will@driivai.com")
    assert result.refused and not result.executed
    assert spy.calls == []  # the racing retry never ran the action
    assert "already in progress or has completed" in result.detail
    assert ledger.executions()[-1]["source"] == "human-approved-retry"
    assert ledger.executions()[-1]["refused"] is True


def test_second_concurrent_approve_cannot_double_execute():
    """Before this guard the approve path was atomic via the status transition;
    the claim keeps at-most-once even when the status is already approved."""

    ledger = SqliteLedger(":memory:")
    spy = _SpyExecutor()
    controller = _controller(ledger, executor=spy, clock=_Clock(_T0))
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    controller.approve(held.id, identity="will@driivai.com")  # executed, claim held
    assert len(spy.calls) == 1
    # The claim survived the successful execution, so no further execution can
    # be driven for this hold by any path.
    assert ledger.claim_pending_execution(held.id, _T0) is False


def test_a_refused_execution_releases_the_claim_for_retry():
    ledger = SqliteLedger(":memory:")
    clock = _Clock(_T0)
    controller = _controller(
        ledger, executor=SandboxExecutor(sandbox=NullSandbox()), clock=clock
    )
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    assert controller.approve(held.id, identity="will@driivai.com").refused
    # The fail-closed refusal released the claim, so the hold is claimable again
    # (which is what lets a retry re-drive it once the sandbox is back).
    assert ledger.pending_action(held.id)["execution_committed_at"] is None


def test_retry_is_refused_for_an_unknown_id_and_records_nothing():
    ledger = SqliteLedger(":memory:")
    controller = _controller(ledger, executor=_SpyExecutor(), clock=_Clock(_T0))
    with pytest.raises(KeyError):
        controller.retry_execution(999, identity="will@driivai.com")
    assert ledger.executions() == []  # nothing to audit for a nonexistent hold


def test_retry_is_conservative_about_unlinked_legacy_executions():
    """A pre-link executed approval for the same subject blocks the retry:
    'never executed' must be provable, and on doubt the retry refuses."""

    ledger = SqliteLedger(":memory:")
    spy = _SpyExecutor()
    controller = _controller(ledger, executor=spy, clock=_Clock(_T0))
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    controller.pending.approve(held.id, identity="will@driivai.com")
    # A legacy row: executed, human-approved, no pending link.
    ledger.record_execution(
        subject_id="s", source="human-approved", executed=True, refused=False,
        sandbox_name="namespace", exit_status=0, detail="legacy", created_at=_T0,
    )

    with pytest.raises(ValueError, match="cannot be proven"):
        controller.retry_execution(held.id, identity="will@driivai.com")
    assert spy.calls == []


# -- the retry window: TTL semantics respected --------------------------------


def test_retry_window_lapses_with_the_ttl_and_leaves_the_decision_untouched():
    ledger = SqliteLedger(":memory:")
    spy = _SpyExecutor()
    clock = _Clock(_T0)
    controller = _controller(ledger, executor=spy, clock=clock, ttl=100)
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    controller.pending.approve(held.id, identity="will@driivai.com")  # deferred
    decided_before = _decision_record(ledger, held.id)

    clock.now = "2026-07-01T00:03:20Z"  # +200s: past the approval's TTL window
    with pytest.raises(ValueError, match="retry window"):
        controller.retry_execution(held.id, identity="will@driivai.com")
    assert spy.calls == []
    assert ledger.executions()[-1]["source"] == "retry-refused"
    # The window refuses execution; it never rewrites the decision record.
    assert _decision_record(ledger, held.id) == decided_before
    assert ledger.pending_action(held.id)["status"] == "approved"


def test_ttl_zero_disables_the_retry_window():
    ledger = SqliteLedger(":memory:")
    spy = _SpyExecutor()
    clock = _Clock("2020-01-01T00:00:00Z")
    controller = _controller(ledger, executor=spy, clock=clock, ttl=0)
    held = controller.submit(judgment=_LOW, action=_action(), subject_id="s").pending
    controller.pending.approve(held.id, identity="will@driivai.com")

    clock.now = "2030-01-01T00:00:00Z"  # ten years later
    result = controller.retry_execution(held.id, identity="will@driivai.com")
    assert result.executed and len(spy.calls) == 1


# -- retry really executes in the sandbox (isolation runtime required) -------


def test_retry_executes_through_the_real_sandbox_after_an_outage():
    sandbox = _isolating_sandbox()
    ledger = SqliteLedger(":memory:")
    clock = _Clock(_T0)
    outage = _controller(
        ledger, executor=SandboxExecutor(sandbox=NullSandbox()), clock=clock
    )
    held = outage.submit(
        judgment=_LOW, action=_action("print('RETRIED-AND-RAN')"), subject_id="s"
    ).pending
    assert outage.approve(held.id, identity="will@driivai.com").refused

    recovered = _controller(
        ledger, executor=SandboxExecutor(sandbox=sandbox), clock=clock
    )
    result = recovered.retry_execution(held.id, identity="will@driivai.com")
    assert result.executed and "RETRIED-AND-RAN" in result.stdout
    assert result.sandbox_name == sandbox.name and result.exit_status == 0


# -- CLI ----------------------------------------------------------------------


def _seed_pending(ledger_path: str, *, created_at: str, subject: str, code: str) -> int:
    ledger = SqliteLedger(ledger_path)
    service = PendingActionService(ledger, clock=lambda: created_at, ttl_seconds=999_999)
    decision = ActionGate(escalate_below=0.75, route_high_risk=True).decide(
        _LOW, risk_class="low", subject_id=subject, action=_action(code)
    )
    held = service.hold(decision, risk_class="low")
    ledger.close()
    return held.id


def test_cli_retry_execution_runs_a_deferred_approval(tmp_path, monkeypatch, capsys):
    _isolating_sandbox()  # gate: needs the isolation runtime
    from prometheus_protocol.cli.main import main

    db = str(tmp_path / "ledger.db")
    pid = _seed_pending(
        db, created_at="2026-07-01T00:00:00Z", subject="deploy/x", code="print('x')"
    )
    monkeypatch.setenv("PROM_LEDGER_PATH", db)
    monkeypatch.setenv("PROM_PENDING_TTL", "0")

    assert main(["approve", str(pid), "--by", "will@driivai.com", "--no-exec"]) == 0
    capsys.readouterr()
    assert main(["retry-execution", str(pid), "--by", "will@driivai.com"]) == 0
    assert "executed in sandbox" in capsys.readouterr().out
    execs = SqliteLedger(db).executions()
    assert len(execs) == 1 and execs[0]["source"] == "human-approved-retry"
    assert execs[0]["executed"] is True and execs[0]["pending_id"] == pid


def test_cli_retry_execution_refuses_a_pending_hold(tmp_path, monkeypatch, capsys):
    from prometheus_protocol.cli.main import main

    db = str(tmp_path / "ledger.db")
    pid = _seed_pending(
        db, created_at="2026-07-01T00:00:00Z", subject="deploy/x", code="print('x')"
    )
    monkeypatch.setenv("PROM_LEDGER_PATH", db)
    monkeypatch.setenv("PROM_PENDING_TTL", "0")

    assert main(["retry-execution", str(pid), "--by", "will@driivai.com"]) == 1
    assert "still pending" in capsys.readouterr().err
    ledger = SqliteLedger(db)
    assert ledger.pending_action(pid)["status"] == "pending"
    assert [e["source"] for e in ledger.executions()] == ["retry-refused"]


def test_cli_retry_execution_unknown_id(tmp_path, monkeypatch, capsys):
    from prometheus_protocol.cli.main import main

    db = str(tmp_path / "ledger.db")
    _seed_pending(db, created_at=_T0, subject="deploy/x", code="print('x')")
    monkeypatch.setenv("PROM_LEDGER_PATH", db)
    assert main(["retry-execution", "999", "--by", "will@driivai.com"]) == 1
    assert "no pending action with id 999" in capsys.readouterr().err


def test_cli_retry_execution_fail_closes_without_a_sandbox(tmp_path, monkeypatch, capsys):
    # The eligible-but-sandbox-missing branch: retry_decision succeeds, execution
    # is refused fail-closed, the command reports it and returns 1.
    from prometheus_protocol.cli.main import main

    db = str(tmp_path / "ledger.db")
    pid = _seed_pending(
        db, created_at="2026-07-01T00:00:00Z", subject="deploy/x", code="print('x')"
    )
    monkeypatch.setenv("PROM_LEDGER_PATH", db)
    monkeypatch.setenv("PROM_PENDING_TTL", "0")
    # No isolating runtime available -> the controller's SandboxExecutor refuses.
    monkeypatch.setenv("PROM_SANDBOX", "container")  # no daemon here -> fail-closed

    assert main(["approve", str(pid), "--by", "will@driivai.com", "--no-exec"]) == 0
    capsys.readouterr()
    assert main(["retry-execution", str(pid), "--by", "will@driivai.com"]) == 1
    assert "refused (fail-closed)" in capsys.readouterr().err
    # The hold is untouched (still approved) and stays retry-eligible.
    ledger = SqliteLedger(db)
    assert ledger.pending_action(pid)["status"] == "approved"
    assert ledger.pending_action(pid)["execution_committed_at"] is None
