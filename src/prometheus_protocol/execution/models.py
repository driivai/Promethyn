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
from prometheus_protocol.policy.execution import AuthorizedExecution


class PendingStatus(str, Enum):
    """Lifecycle of a routed action. ``PENDING`` is the only open state.

    ``INVALIDATED`` is a system transition, like ``EXPIRED``: the policy the
    hold was pinned to is no longer the one the deployment selects, so the
    hold can never be approved and verification must be re-run. It is kept
    separate from ``EXPIRED`` so the ledger can tell "this lapsed" from "this
    was voided by a rotation".
    """

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"


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
    #: The seam-minted authorization. Set on the value ``hold`` returns; on a
    #: hold reloaded from the ledger it is minted again only by revalidation
    #: (approval, retry), after the pinned record has been checked against its
    #: chain entry and the selected policy.
    authorization: AuthorizedExecution[ExecutableAction] | None = None
    #: The pinned authorization record, exactly as persisted (``policy/record.py``).
    #: ``None`` for a legacy hold written before records existed, which is
    #: refused at approval as re-verification required.
    record: dict | None = None
