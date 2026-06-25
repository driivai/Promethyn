"""Composition root: build a fully wired runtime from a :class:`Config`.

Keeping the wiring in one place means the CLI, the example scripts, and the
tests all assemble the same runtime the same way, and the choice of provider
is made by configuration rather than by code edits.
"""

from __future__ import annotations

from prometheus_protocol.core.config import PROVIDER_REMOTE, Config
from prometheus_protocol.core.interfaces import Provider
from prometheus_protocol.forge.miner import LessonForge
from prometheus_protocol.gate.promotion import PromotionGate
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.memory.tiers import InMemoryTier, MemoryTier
from prometheus_protocol.provider.mock import MockProvider, SolutionBook
from prometheus_protocol.provider.remote import RemoteModelProvider
from prometheus_protocol.registry.markdown_registry import MarkdownSkillRegistry
from prometheus_protocol.runtime.orchestrator import Orchestrator
from prometheus_protocol.verifier.runner import SubprocessVerifier


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


def build_orchestrator(
    config: Config | None = None,
    *,
    solution_book: SolutionBook | None = None,
    memory: MemoryTier | None = None,
) -> Orchestrator:
    config = config or Config()
    return Orchestrator(
        provider=build_provider(config, solution_book),
        verifier=SubprocessVerifier(
            timeout_s=config.verifier_timeout_s,
            memory_mb=config.verifier_memory_mb,
            cpu_seconds=config.verifier_cpu_seconds,
        ),
        registry=MarkdownSkillRegistry(config.registry_dir),
        gate=PromotionGate(threshold=config.gate_threshold),
        ledger=SqliteLedger(config.ledger_path),
        forge=LessonForge(),
        config=config,
        memory=memory if memory is not None else InMemoryTier(),
    )
