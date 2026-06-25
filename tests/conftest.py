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
