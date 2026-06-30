"""Prometheus Protocol — a verifiable, reversible, self-improving runtime.

THIS MODULE IS THE OPEN-CORE LINE.

Everything re-exported here is the supported public API of the open
distribution. A frozen model proposes solutions; a sandboxed verifier returns
a hard pass/fail; failures are mined into reusable markdown skills; and a
promotion gate, guarded by the held-out firewall, decides what is kept.

The held-out firewall — the forge never learns from held-out tasks, and the
gate only ever scores against them — is the load-bearing safety invariant and
is enforced in code (see :mod:`prometheus_protocol.gate`).

Anything not exported here, and anything under an underscore-prefixed module,
is an implementation detail and may change without notice.
"""

from __future__ import annotations

from prometheus_protocol.core.config import Config
from prometheus_protocol.core.errors import (
    ConfigError,
    PrometheusError,
    StateError,
)
from prometheus_protocol.core.interfaces import (
    Gate,
    Ledger,
    Provider,
    Registry,
    Verifier,
)
from prometheus_protocol.core.models import (
    AUTHORITATIVE_TIERS,
    SPLIT_HELDOUT,
    SPLIT_TRAIN,
    Attempt,
    Case,
    Evidence,
    Judgment,
    Skill,
    Task,
    Tier,
    Verdict,
)
from prometheus_protocol.forge.miner import LessonForge
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import (
    FirewallError,
    GateDecision,
    PromotionGate,
    assert_disjoint,
)
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.memory.tiers import InMemoryTier, MemoryTier
from prometheus_protocol.provider.mock import MockProvider, MockSolution
from prometheus_protocol.provider.remote import ProviderError, RemoteModelProvider
from prometheus_protocol.registry.markdown_registry import MarkdownSkillRegistry
from prometheus_protocol.runtime.factory import build_orchestrator, build_provider
from prometheus_protocol.sandbox import (
    ContainerSandbox,
    Limits,
    NamespaceSandbox,
    NullSandbox,
    Sandbox,
    SandboxResult,
    UnsafeLocalSandbox,
    build_sandbox,
)
from prometheus_protocol.runtime.orchestrator import (
    CycleReport,
    Orchestrator,
    RunReport,
    TaskOutcome,
)
from prometheus_protocol.verifier.bank import RankEntry, VerifierBank
from prometheus_protocol.verifier.model_judge import ModelJudgeVerifier
from prometheus_protocol.verifier.runner import SubprocessVerifier
from prometheus_protocol.verifier.store import (
    InMemoryTrustStore,
    SqliteTrustStore,
    TrustStore,
)
from prometheus_protocol.verifier.trust import TrustStats
from prometheus_protocol.swarm.debate import DebateLayer
from prometheus_protocol.swarm.executor import Executor, RecordingExecutor
from prometheus_protocol.swarm.models import (
    ExecutionResult,
    FalsificationCheck,
    Proposal,
    Provenance,
    TaskPacket,
    TestPlan,
    VerifiedProposal,
)
from prometheus_protocol.swarm.roles import Role
from prometheus_protocol.swarm.runtime import SwarmRuntime
from prometheus_protocol.swarm.synthesis import (
    RoleSynthesisEngine,
    Swarm,
    SwarmConfig,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # configuration
    "Config",
    # domain errors
    "PrometheusError",
    "StateError",
    "ConfigError",
    # models
    "Task",
    "Skill",
    "Attempt",
    "Evidence",
    "Case",
    "SPLIT_TRAIN",
    "SPLIT_HELDOUT",
    # verifier-trust domain
    "Verdict",
    "Tier",
    "AUTHORITATIVE_TIERS",
    "Judgment",
    # interfaces
    "Provider",
    "Verifier",
    "Registry",
    "Gate",
    "Ledger",
    "MemoryTier",
    # implementations
    "SubprocessVerifier",
    "ModelJudgeVerifier",
    # verifier-trust ranking
    "VerifierBank",
    "RankEntry",
    "TrustStore",
    "InMemoryTrustStore",
    "SqliteTrustStore",
    "TrustStats",
    "SqliteLedger",
    "MarkdownSkillRegistry",
    "LessonForge",
    "PromotionGate",
    "GateDecision",
    "ActionGate",
    "InMemoryTier",
    "MockProvider",
    "MockSolution",
    "RemoteModelProvider",
    "ProviderError",
    # firewall
    "FirewallError",
    "assert_disjoint",
    # runtime
    "Orchestrator",
    "CycleReport",
    "RunReport",
    "TaskOutcome",
    "build_orchestrator",
    "build_provider",
    # swarm reasoning front-end
    "TaskPacket",
    "Proposal",
    "Provenance",
    "FalsificationCheck",
    "TestPlan",
    "VerifiedProposal",
    "ExecutionResult",
    "Role",
    "RoleSynthesisEngine",
    "Swarm",
    "SwarmConfig",
    "DebateLayer",
    "SwarmRuntime",
    "Executor",
    "RecordingExecutor",
    # sandbox isolation
    "Sandbox",
    "SandboxResult",
    "Limits",
    "NamespaceSandbox",
    "ContainerSandbox",
    "UnsafeLocalSandbox",
    "NullSandbox",
    "build_sandbox",
]
