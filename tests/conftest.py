"""Shared fixtures.

Every fixture uses ephemeral storage: a temporary registry directory and an
in-memory ledger. The verifier's address-space limit is disabled here so the
load-bearing regression numbers are stable across CI runners; the CPU-time and
file-size limits, and the wall-clock timeout, still apply.
"""

from __future__ import annotations

import pytest

from harness.benchmarks.python_functions import build_benchmark
from prometheus_protocol import Config, build_orchestrator


@pytest.fixture
def config(tmp_path):
    return Config(
        provider="mock",
        registry_dir=tmp_path / "skills",
        ledger_path=":memory:",
        verifier_memory_mb=0,
    )


@pytest.fixture
def orchestrator(config):
    return build_orchestrator(config)


@pytest.fixture
def benchmark():
    return build_benchmark()


@pytest.fixture
def swarm_runtime():
    """A swarm runtime wired entirely from existing grounding components."""

    from prometheus_protocol._examples.swarm_tasks import build_swarm_provider
    from prometheus_protocol.gate.authorization import ActionGate
    from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
    from prometheus_protocol.swarm.debate import DebateLayer
    from prometheus_protocol.swarm.executor import RecordingExecutor
    from prometheus_protocol.swarm.runtime import SwarmRuntime
    from prometheus_protocol.swarm.synthesis import RoleSynthesisEngine
    from prometheus_protocol.verifier.bank import VerifierBank
    from prometheus_protocol.verifier.store import InMemoryTrustStore

    # Roles reason via a deterministic mock provider (scripted role outputs).
    provider = build_swarm_provider()
    return SwarmRuntime(
        synthesis=RoleSynthesisEngine(provider=provider),
        debate=DebateLayer(),
        bank=VerifierBank(InMemoryTrustStore()),
        gate=ActionGate(),
        executor=RecordingExecutor(),
        ledger=SqliteLedger(":memory:"),
        provider=provider,
    )
