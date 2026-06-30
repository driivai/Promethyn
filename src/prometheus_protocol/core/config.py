"""Runtime configuration, resolved from the environment.

All knobs are read from ``PROM_*`` environment variables so the same build
runs unchanged across a laptop, CI, and a server. Nothing here is specific to
any model vendor: the provider boundary is selected by name and configured by
generic endpoint settings.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

PROVIDER_MOCK = "mock"
PROVIDER_REMOTE = "remote"


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_float(value: str | None, default: float) -> float:
    if value is None or value.strip() == "":
        return default
    return float(value)


def _as_int(value: str | None, default: int) -> int:
    if value is None or value.strip() == "":
        return default
    return int(value)


@dataclass(frozen=True)
class Config:
    """Resolved configuration for a runtime instance."""

    provider: str = PROVIDER_MOCK
    api_base: str | None = None
    model: str | None = None
    api_key: str | None = None

    # Soft model-judge advisor. Off by default: it issues model calls and the
    # offline default provider cannot meaningfully judge. ``judge_model``, when
    # set (remote provider), runs the judge on a different model than the actor
    # to reduce correlated error; otherwise the judge reuses the actor provider.
    enable_model_judge: bool = False
    judge_model: str | None = None

    registry_dir: Path = Path(".prometheus/skills")
    ledger_path: Path = Path(".prometheus/ledger.db")
    trust_store_path: Path = Path(".prometheus/trust.db")

    verifier_timeout_s: float = 5.0
    verifier_memory_mb: int = 256
    verifier_cpu_seconds: int = 5
    verifier_max_processes: int = 64

    # Sandbox adapter for executing untrusted candidate code: "auto" (pick the
    # best available isolating adapter), "namespace", "container", or "unsafe"
    # (the unsafe direct runner, which additionally requires
    # PROM_ALLOW_UNSAFE_EXEC=1). Default is an isolating adapter.
    sandbox: str = "auto"

    gate_threshold: float = 0.0
    retrieval_k: int = 5

    request_timeout_s: float = 30.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Config":
        env = os.environ if env is None else env
        return cls(
            provider=env.get("PROM_PROVIDER", PROVIDER_MOCK),
            api_base=env.get("PROM_API_BASE"),
            model=env.get("PROM_MODEL"),
            api_key=env.get("PROM_API_KEY"),
            enable_model_judge=_as_bool(env.get("PROM_ENABLE_MODEL_JUDGE"), False),
            judge_model=env.get("PROM_JUDGE_MODEL"),
            registry_dir=Path(env.get("PROM_REGISTRY_DIR", ".prometheus/skills")),
            ledger_path=Path(env.get("PROM_LEDGER_PATH", ".prometheus/ledger.db")),
            trust_store_path=Path(
                env.get("PROM_TRUST_STORE_PATH", ".prometheus/trust.db")
            ),
            verifier_timeout_s=_as_float(env.get("PROM_VERIFIER_TIMEOUT_S"), 5.0),
            verifier_memory_mb=_as_int(env.get("PROM_VERIFIER_MEMORY_MB"), 256),
            verifier_cpu_seconds=_as_int(env.get("PROM_VERIFIER_CPU_SECONDS"), 5),
            verifier_max_processes=_as_int(env.get("PROM_VERIFIER_MAX_PROCESSES"), 64),
            sandbox=env.get("PROM_SANDBOX", "auto"),
            gate_threshold=_as_float(env.get("PROM_GATE_THRESHOLD"), 0.0),
            retrieval_k=_as_int(env.get("PROM_RETRIEVAL_K"), 5),
            request_timeout_s=_as_float(env.get("PROM_REQUEST_TIMEOUT_S"), 30.0),
        )
