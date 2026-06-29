"""Swarm reasoning front-end.

Generates candidate decisions on the proposer side and routes them through the
existing grounding stack (verifier bank, gate, executor, ledger) for judgment
and authorization. The wall between proposing and asserting truth is enforced
by types: see :mod:`prometheus_protocol.swarm.models`.
"""

from prometheus_protocol.swarm.debate import DebateLayer
from prometheus_protocol.swarm.executor import Executor, RecordingExecutor
from prometheus_protocol.swarm.models import (
    ExecutionResult,
    FalsificationCheck,
    Proposal,
    Provenance,
    TaskPacket,
    TestPlan,
    TestPlanEntry,
    VerificationRequest,
    VerifiedProposal,
)
from prometheus_protocol.swarm.roles import (
    AnalystRole,
    PlannerRole,
    PolicyReviewer,
    ProposerContext,
    Role,
    Skeptic,
)
from prometheus_protocol.swarm.runtime import ChainRecord, SwarmRun, SwarmRuntime
from prometheus_protocol.swarm.synthesis import (
    RoleSynthesisEngine,
    Swarm,
    SwarmConfig,
)

__all__ = [
    # models / wall
    "TaskPacket",
    "Proposal",
    "Provenance",
    "FalsificationCheck",
    "VerificationRequest",
    "TestPlan",
    "TestPlanEntry",
    "VerifiedProposal",
    "ExecutionResult",
    # roles
    "Role",
    "ProposerContext",
    "PlannerRole",
    "AnalystRole",
    "Skeptic",
    "PolicyReviewer",
    # synthesis / debate
    "RoleSynthesisEngine",
    "Swarm",
    "SwarmConfig",
    "DebateLayer",
    # runtime / executor
    "SwarmRuntime",
    "SwarmRun",
    "ChainRecord",
    "Executor",
    "RecordingExecutor",
]
