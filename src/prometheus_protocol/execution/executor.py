"""The real executor: every side-effect runs inside the sandbox.

``SandboxExecutor`` is the wall's enforcement point made live. It accepts only an
approved :class:`GateDecision` and runs the action it authorizes through the
existing :class:`Sandbox` port — the same isolation the verifier uses, reused,
not forked. It is **fail-closed** (INV-EXEC-1): if the configured sandbox does
not isolate, or isolation does not start, it *refuses* and records the refusal;
it never degrades to running the action in the clear. The action set is minimal
and explicit — in-sandbox code only — with no network or external connectors
this sprint (the sandbox denies the network regardless).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from prometheus_protocol.core.models import ACTION_PYTHON_CODE, ExecutableAction
from prometheus_protocol.gate.promotion import GateDecision
from prometheus_protocol.sandbox import Limits, Sandbox, build_sandbox
from prometheus_protocol.swarm.executor import Executor
from prometheus_protocol.swarm.models import ExecutionResult

#: The candidate program is written here inside the sandbox workspace and run
#: in isolated mode, exactly as the verifier runs untrusted code.
_ACTION_FILE = "_action.py"


class SandboxExecutor(Executor):
    """Executes an approved decision's action inside an isolating sandbox."""

    def __init__(
        self, *, sandbox: Sandbox | None = None, limits: Limits | None = None
    ) -> None:
        # Defaults to the configured/auto isolating adapter; build_sandbox never
        # returns the unsafe runner without an explicit opt-in, and returns the
        # NullSandbox backstop when nothing isolating is available.
        self._sandbox = sandbox if sandbox is not None else build_sandbox()
        self._limits = limits or Limits()

    @property
    def sandbox(self) -> Sandbox:
        return self._sandbox

    def execute(self, decision: GateDecision) -> ExecutionResult:
        # The wall: only a gate-produced, approved decision may cross into
        # execution. A raw proposal or test plan is a type error; an unapproved
        # decision (blocked, or a still-pending hold) is refused loudly.
        if not isinstance(decision, GateDecision):
            raise TypeError(
                "Executor.execute accepts only a GateDecision; a proposal or "
                "test plan cannot be executed"
            )
        if not decision.approved:
            raise ValueError("refusing to execute an unapproved gate decision")

        action = decision.action
        if action is None:
            return self._refuse(decision, "approved decision carries no executable action")
        if action.kind != ACTION_PYTHON_CODE:
            return self._refuse(decision, f"unsupported action kind {action.kind!r}")

        # Fail-closed: a non-isolating adapter (the unsafe runner) is refused
        # before it can run anything. Isolation is mandatory for a side-effect.
        if not self._sandbox.isolating:
            return self._refuse(
                decision,
                f"sandbox {self._sandbox.name!r} does not isolate; refusing to "
                "execute unsandboxed",
            )
        return self._run(decision, action)

    def _run(self, decision: GateDecision, action: ExecutableAction) -> ExecutionResult:
        with tempfile.TemporaryDirectory(prefix="prom-exec-") as workspace:
            Path(workspace, _ACTION_FILE).write_text(action.code, encoding="utf-8")
            result = self._sandbox.run(
                argv=[sys.executable, "-I", _ACTION_FILE],
                workspace=workspace,
                limits=self._limits,
            )

        if not result.started_ok:
            # Isolation could not start (NullSandbox, or no runtime). Fail-closed:
            # the action did NOT run, and we never retry it unsandboxed.
            return self._refuse(
                decision,
                f"sandbox did not start: {result.detail}",
                started_ok=False,
            )

        # The action ran inside isolation. exit_status records its own success
        # or failure; the side-effect (whatever it wrote to its workspace) has
        # happened. stdout is already bounded by the adapter's output cap.
        return ExecutionResult(
            executed=True,
            subject_id=decision.subject_id,
            detail=(
                f"ran in sandbox {self._sandbox.name!r} "
                f"(exit {result.exit_status}, network denied)"
            ),
            refused=False,
            started_ok=True,
            sandbox_name=self._sandbox.name,
            exit_status=result.exit_status,
            stdout=result.stdout,
        )

    def _refuse(
        self, decision: GateDecision, detail: str, *, started_ok: bool = True
    ) -> ExecutionResult:
        return ExecutionResult(
            executed=False,
            subject_id=decision.subject_id,
            detail=f"refused: {detail}",
            refused=True,
            started_ok=started_ok,
            sandbox_name=self._sandbox.name,
            exit_status=None,
            stdout="",
        )
