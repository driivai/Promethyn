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

    from prometheus_protocol._examples.swarm_tasks import correct_code_task
    from prometheus_protocol.sandbox.unsafe import UnsafeLocalSandbox
    from prometheus_protocol.verifier.runner import SubprocessVerifier

    # Roles reason via a deterministic mock provider (scripted role outputs).
    #
    # PHASE-1.2a — THE EXAMPLE IS NOW POLICY-COMPLIANT, and it had to become so.
    # It previously scripted NO executable cases and wired NO code verifier, so
    # a proposed action reached the executor on structural predicates alone.
    # That was the reproduced fail-open, demonstrated by the shipped example: the
    # baseline profile requires ``executable.cases`` for ``sandbox.execute``, and
    # under it this fixture authorized nothing until the executable path was
    # real. Tests that assert an action executes therefore pass a packet with an
    # ``entry_point``, which is what makes the skeptic attach cases.
    #
    # ``UnsafeLocalSandbox`` is deliberate here and nowhere near production: the
    # "candidate" is the four characters of arithmetic in ``correct_code_task``,
    # a fixture this repository authored, not an untrusted proposal. Isolation
    # exists to contain code whose behaviour is not known in advance. The tests
    # that verify isolation ITSELF live in the sandbox suite.
    provider = build_swarm_provider([correct_code_task()])
    return SwarmRuntime(
        synthesis=RoleSynthesisEngine(provider=provider),
        debate=DebateLayer(),
        bank=VerifierBank(InMemoryTrustStore()),
        gate=ActionGate(
            target_canonical="sandbox://swarm",
        ),
        executor=RecordingExecutor(),
        ledger=SqliteLedger(":memory:"),
        provider=provider,
        code_verifier=SubprocessVerifier(memory_mb=0, sandbox=UnsafeLocalSandbox()),
    )
