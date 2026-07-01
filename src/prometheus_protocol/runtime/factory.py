"""Composition root: build a fully wired runtime from a :class:`Config`.

Keeping the wiring in one place means the CLI, the example scripts, and the
tests all assemble the same runtime the same way, and the choice of provider
is made by configuration rather than by code edits.
"""

from __future__ import annotations

import logging

from prometheus_protocol.core.config import PROVIDER_REMOTE, Config
from prometheus_protocol.core.interfaces import Ledger, Provider, Verifier
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.executor import SandboxExecutor
from prometheus_protocol.forge.miner import LessonForge
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import PromotionGate
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.sandbox import Limits
from prometheus_protocol.memory.tiers import InMemoryTier, MemoryTier
from prometheus_protocol.provider.mock import MockProvider, SolutionBook
from prometheus_protocol.provider.remote import RemoteModelProvider
from prometheus_protocol.registry.markdown_registry import MarkdownSkillRegistry
from prometheus_protocol.runtime.orchestrator import Orchestrator
from prometheus_protocol.sandbox import build_sandbox
from prometheus_protocol.swarm.debate import DebateLayer
from prometheus_protocol.swarm.executor import RecordingExecutor
from prometheus_protocol.swarm.runtime import SwarmRuntime
from prometheus_protocol.swarm.synthesis import RoleSynthesisEngine
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.model_judge import ModelJudgeVerifier
from prometheus_protocol.verifier.runner import SubprocessVerifier
from prometheus_protocol.verifier.store import InMemoryTrustStore, SqliteTrustStore

_LOG = logging.getLogger(__name__)


def build_provider(
    config: Config, solution_book: SolutionBook | None = None
) -> Provider:
    """Select the provider named by ``config.provider``.

    For the (default) mock provider, fall back to the shipped example solution
    book when none is supplied, so the offline demo works out of the box.
    """

    if config.provider == PROVIDER_REMOTE:
        return RemoteModelProvider.from_config(config)
    if solution_book is None:
        from prometheus_protocol._examples.python_functions import build_solution_book

        solution_book = build_solution_book()
    return MockProvider(book=solution_book)


def build_judge_provider(
    config: Config, solution_book: SolutionBook | None = None
) -> Provider:
    """Provider for the soft model-judge.

    Uses an independent judge model when ``judge_model`` is set on a remote
    provider (reduces correlated error: the same model producing and grading
    inflates agreement); otherwise reuses the actor provider.
    """

    if (
        config.provider == PROVIDER_REMOTE
        and config.judge_model
        and config.judge_model != config.model
    ):
        return RemoteModelProvider(
            api_base=config.api_base or "",
            model=config.judge_model,
            api_key=config.api_key,
            timeout_s=config.request_timeout_s,
        )
    return build_provider(config, solution_book)


def build_orchestrator(
    config: Config | None = None,
    *,
    solution_book: SolutionBook | None = None,
    memory: MemoryTier | None = None,
) -> Orchestrator:
    config = config or Config()

    verifier = SubprocessVerifier(
        timeout_s=config.verifier_timeout_s,
        memory_mb=config.verifier_memory_mb,
        cpu_seconds=config.verifier_cpu_seconds,
        max_processes=config.verifier_max_processes,
        sandbox=build_sandbox(config.sandbox),
    )

    # Persist trust alongside the ledger; use an in-memory store when the ledger
    # is itself in-memory (tests). Register the verifier so its hard-tier prior
    # applies from the first judgment.
    if str(config.ledger_path) == ":memory:":
        trust_store = InMemoryTrustStore()
    else:
        trust_store = SqliteTrustStore(config.trust_store_path)
    bank = VerifierBank(trust_store)
    bank.register(verifier.verifier_id, verifier.tier)
    _LOG.info(
        "registered verifier %s (tier=%s)", verifier.verifier_id, verifier.tier.value
    )

    # Optional soft model-judge advisor (off by default). The bank calibrates it
    # against the hard reference; it never decides a verdict.
    advisors: list[Verifier] = []
    if config.enable_model_judge:
        judge = ModelJudgeVerifier(build_judge_provider(config, solution_book))
        bank.register(judge.verifier_id, judge.tier)
        advisors.append(judge)
        _LOG.info(
            "registered advisor %s (tier=%s)", judge.verifier_id, judge.tier.value
        )

    _LOG.info(
        "orchestrator built (provider=%s, ledger=%s)",
        config.provider,
        config.ledger_path,
    )
    return Orchestrator(
        provider=build_provider(config, solution_book),
        verifier=verifier,
        registry=MarkdownSkillRegistry(config.registry_dir),
        gate=PromotionGate(threshold=config.gate_threshold),
        ledger=SqliteLedger(config.ledger_path),
        forge=LessonForge(),
        config=config,
        memory=memory if memory is not None else InMemoryTier(),
        bank=bank,
        advisors=advisors,
    )


def build_swarm_runtime(
    config: Config | None = None,
    *,
    provider: Provider,
    ledger=None,
    memory: MemoryTier | None = None,
) -> SwarmRuntime:
    """Wire a swarm runtime: model-backed roles, the bank/gate/firewall, a no-op
    executor, and a HARD code verifier that runs the Skeptic's executable cases.

    The roles reason via ``provider`` (capped at ``config.max_role_calls`` calls
    per task). The trusted core — bank fusion, the gate, the held-out firewall,
    and the proposer/judge wall — is reused unchanged, and the executor stays a
    no-op recorder.
    """

    config = config or Config()
    if str(config.ledger_path) == ":memory:":
        trust_store = InMemoryTrustStore()
    else:
        trust_store = SqliteTrustStore(config.trust_store_path)
    code_verifier = SubprocessVerifier(
        timeout_s=config.verifier_timeout_s,
        memory_mb=config.verifier_memory_mb,
        cpu_seconds=config.verifier_cpu_seconds,
        max_processes=config.verifier_max_processes,
        sandbox=build_sandbox(config.sandbox),
    )
    _LOG.info("swarm runtime built (max_role_calls=%d)", config.max_role_calls)
    return SwarmRuntime(
        synthesis=RoleSynthesisEngine(
            provider=provider, max_role_calls=config.max_role_calls
        ),
        debate=DebateLayer(),
        bank=VerifierBank(trust_store),
        gate=ActionGate(),
        executor=RecordingExecutor(),
        ledger=ledger if ledger is not None else SqliteLedger(config.ledger_path),
        provider=provider,
        memory=memory,
        code_verifier=code_verifier,
    )


def build_execution_controller(
    config: Config | None = None, *, ledger: Ledger | None = None
) -> ExecutionController:
    """Wire the live-execution path: routing gate -> human hold -> sandbox executor.

    The action gate runs in routing mode (low-confidence and high-risk actions
    halt for a human), and the executor runs every side-effect through the
    configured isolating sandbox — fail-closed if none is available. The bank,
    the firewall, the proposer/judge wall, and verdict semantics are untouched:
    this only turns the executor real and adds the human halt.
    """

    config = config or Config()
    limits = Limits(
        wall_time_s=config.verifier_timeout_s,
        cpu_time_s=config.verifier_cpu_seconds,
        memory_bytes=(
            config.verifier_memory_mb * 1024 * 1024
            if config.verifier_memory_mb > 0
            else 0
        ),
        max_processes=config.verifier_max_processes,
    )
    _LOG.info("execution controller built (escalate_below=%.2f)", config.escalate_below)
    return ExecutionController(
        gate=ActionGate(escalate_below=config.escalate_below, route_high_risk=True),
        executor=SandboxExecutor(sandbox=build_sandbox(config.sandbox), limits=limits),
        ledger=ledger if ledger is not None else SqliteLedger(config.ledger_path),
    )
