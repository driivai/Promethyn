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
        from prometheus_protocol.policy.execution import (
            AuthorizedExecution,
            consume_authorization,
        )
        if not isinstance(decision.authorization, AuthorizedExecution):
            raise ValueError("gate decision carries no validated execution descriptor")
        if not decision.approved:
            raise ValueError("refusing to execute an unapproved gate decision")
        # G24: the authorization is spent HERE, by the executor that acts on
        # it, because a caller holding a retained decision reaches this line
        # without passing a gateway. Before the sandbox check and before any
        # refusal: a second presentation is refused for being a second
        # presentation, whatever the sandbox would have said about it.
        consume_authorization(decision.authorization)

        action = decision.action
        if action is None:
            return self._refuse(decision, "approved decision carries no executable action")
        if decision.authorization.action != action:
            return self._refuse(decision, "decision action differs from its validated descriptor")
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
                candidate_started=False,
            )

        if not result.candidate_started:
            # ISOLATION CAME UP AND THE CANDIDATE STILL NEVER RAN. The sandbox
            # contract names this exactly (``sandbox/base.py``): ``started_ok``
            # answers "did isolation start", ``candidate_started`` is the
            # stronger, definite signal that the command itself began, and
            # ``started_ok=True`` with ``candidate_started=False`` — a wall-clock
            # timeout during SETUP — "stays a harness fault".
            #
            # Reading ``started_ok`` alone recorded that as ``executed=True``
            # with "ran in sandbox": could-not-verify written into the receipt
            # as verified-clean, at the one point downstream cannot recover the
            # difference. Doctrine #1 where it is most expensive.
            #
            # WHY THIS OUTCOME AND NOT A NEW ONE. ``runner.py``'s three-way
            # split is the precedent: a resource kill is a verdict ABOUT the
            # candidate, a harness fault is not a verdict at all, isolation
            # never starting is the same non-verdict. The executor has no
            # verdict to give — ``exit_status`` carries the candidate's own
            # outcome — so the split collapses onto the two outcomes it already
            # has, and this is the second for the same reason ``started_ok=False``
            # already is. The verifier seam has classified this triple as
            # ``Unavailable(INFRA_FAULT)`` since the same bug was found there;
            # this is the executor catching up to its own contract.
            #
            # KEYED ON ``candidate_started``, NOT ON ``timed_out``: a candidate
            # that STARTED and was then killed by the wall clock really did run
            # and its side effects happened. Keying on the timeout would discard
            # that execution's record.
            return self._refuse(
                decision,
                "sandbox started but the candidate never did, so nothing ran "
                f"and nothing can be claimed about it: {result.detail}",
                # ISOLATION REALLY DID START, and the record says so. Writing
                # ``started_ok=False`` here would overwrite a true fact with a
                # false one and make this indistinguishable from a missing
                # runtime — two harness faults with different remedies,
                # collapsed into one value. ``candidate_started`` carries what
                # actually went wrong.
                #
                # The MEASURED value, not the literal ``True`` this used to
                # pass: the guard above returns on ``not result.started_ok``,
                # so the two agree today, and passing what the adapter reported
                # means they cannot stop agreeing silently.
                started_ok=result.started_ok,
                candidate_started=result.candidate_started,
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
            # THE MEASURED VALUES, not literals. Both are necessarily True
            # here — the two guards above return on the False branch — and
            # passing what the adapter reported rather than ``True`` means the
            # claim cannot survive a change to either guard.
            started_ok=result.started_ok,
            candidate_started=result.candidate_started,
            sandbox_name=self._sandbox.name,
            exit_status=result.exit_status,
            stdout=result.stdout,
            # The candidate ran and this IS its output. One of exactly two
            # sites in the tree that may say so.
            stdout_recorded=True,
        )

    def _refuse(
        self,
        decision: GateDecision,
        detail: str,
        *,
        started_ok: bool = False,
        candidate_started: bool = False,
    ) -> ExecutionResult:
        """Both facts default to the fail-closed answer.

        These defaulted ``True``, and four of this module's six ``_refuse``
        calls are refusals taken BEFORE ``_run`` — no action, a descriptor
        mismatch, an unsupported kind, a non-isolating adapter — where the
        sandbox is never constructed. Every one of them claimed isolation had
        started and the candidate had begun, and the controller persists both
        into the audit ledger. The two calls that really did observe isolation
        state what they observed and are unaffected.
        """
        return ExecutionResult(
            executed=False,
            subject_id=decision.subject_id,
            detail=f"refused: {detail}",
            refused=True,
            started_ok=started_ok,
            candidate_started=candidate_started,
            sandbox_name=self._sandbox.name,
            exit_status=None,
            stdout="",
        )
