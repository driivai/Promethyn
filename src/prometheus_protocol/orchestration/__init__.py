"""Governed multi-agent orchestration (skeleton).

Generalises the *proposer* side into a DAG of agents while the Hearth stays
singular: every agent's every action routes through the existing
verify → gate → human-hold → execute → ledger pipeline, and inter-agent
messages are tier-tagged so errors cannot silently compound. The orchestrator
has no authority to execute — its only door to action is a submit-only
:class:`ActionGateway` that always ends at the gate.

See ``docs/orchestration.md`` for the layer, the invariants it upholds, and the
one thing it deliberately does NOT solve (principled confidence composition).
"""

from __future__ import annotations

from prometheus_protocol.orchestration.gateway import ActionGateway, SubmitFn
from prometheus_protocol.orchestration.messages import AgentMessage, content_hash
from prometheus_protocol.orchestration.runtime import (
    StepRecord,
    WorkflowLedgerPort,
    WorkflowRun,
    WorkflowRuntime,
)
from prometheus_protocol.orchestration.workflow import (
    Agent,
    AgentProposal,
    AgentStep,
    StepGrader,
    Workflow,
    WorkflowError,
)

__all__ = [
    "AgentMessage",
    "content_hash",
    "Agent",
    "AgentProposal",
    "StepGrader",
    "AgentStep",
    "Workflow",
    "WorkflowError",
    "ActionGateway",
    "SubmitFn",
    "WorkflowRuntime",
    "WorkflowRun",
    "StepRecord",
    "WorkflowLedgerPort",
]
