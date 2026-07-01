"""Live execution: the human hold and the real, sandboxed executor.

This package is where a judged action turns into a side-effect — safely. The
:class:`ExecutionController` is the only path from a judgment to execution: an
approved action executes immediately, a routed action *halts* as a
:class:`PendingAction` until a recorded human approval flips it, and a blocked
action never executes. All side-effects run through the existing Sandbox port;
if no isolating sandbox is available the executor refuses (fail-closed) rather
than run in the clear. Every outcome — the hold, the human decision, and each
execution — is recorded in the ledger.
"""

from __future__ import annotations

from prometheus_protocol.execution.controller import (
    ExecutionController,
    SubmitOutcome,
)
from prometheus_protocol.execution.executor import SandboxExecutor
from prometheus_protocol.execution.models import (
    HumanDecision,
    PendingAction,
    PendingStatus,
)
from prometheus_protocol.execution.pending import PendingActionService

__all__ = [
    "ExecutionController",
    "SubmitOutcome",
    "SandboxExecutor",
    "PendingActionService",
    "PendingAction",
    "PendingStatus",
    "HumanDecision",
]
