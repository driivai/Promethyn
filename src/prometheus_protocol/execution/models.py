"""Execution-side value objects: the human hold on a routed action.

A :class:`PendingAction` is a routed ``GateDecision`` frozen mid-flight — it
holds the action, the judgment it rests on, and the reason it routed — and it
cannot become executed until a recorded :class:`HumanDecision` approves it.
These are plain records; the behaviour lives in the pending service and the
controller.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from prometheus_protocol.core.models import ExecutableAction, Judgment


class PendingStatus(str, Enum):
    """Lifecycle of a routed action. ``PENDING`` is the only open state."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass(frozen=True)
class HumanDecision:
    """A recorded human approve/reject: who, when, and why."""

    decision: str  # "approved" | "rejected" | "expired"
    identity: str
    timestamp: str
    reason: str = ""


@dataclass(frozen=True)
class PendingAction:
    """A routed action held for a human, reconstructed from the ledger."""

    id: int
    subject_id: str
    risk_class: str
    reason: str
    action: ExecutableAction
    judgment: Judgment
    status: PendingStatus
    created_at: str
    human_decision: HumanDecision | None = None
