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
    # set, runs the judge on a model independent of the actor/roles model to
    # reduce correlated error (the same model proposing and grading inflates
    # agreement); otherwise the judge reuses the actor provider and the runtime
    # logs a one-line correlated-grader notice. ``judge_api_base`` /
    # ``judge_api_key`` optionally point the judge at a different gateway (a
    # fully independent grading endpoint); unset, they inherit the actor's.
    enable_model_judge: bool = False
    judge_model: str | None = None
    judge_api_base: str | None = None
    judge_api_key: str | None = None
    # Judge sampling temperature. Default 0.0 keeps the judge deterministic
    # (unchanged behaviour). It exists so the self-consistency / repeated-
    # sampling calibration lever can draw genuinely varied samples: at
    # temperature 0 repeated calls are identical and majority-of-k is a no-op.
    # Only the judge's `assess` path reads this; the actor/proposer path stays
    # deterministic regardless.
    judge_temperature: float = 0.0

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

    # Container image provenance. When set, the container adapter REFUSES to run
    # an image referenced by a bare tag — only a digest-pinned image
    # (``…@sha256:…``) is allowed, so a tag cannot be silently repointed after it
    # was vetted. Off by default for dev convenience; the recommended production
    # posture. A bare tag is always logged as a supply-chain risk regardless.
    require_digest_pin: bool = False

    gate_threshold: float = 0.0
    retrieval_k: int = 5

    # Action-authorization human-routing. When the action gate is run in
    # routing mode, an authoritative PASS whose confidence is below
    # ``escalate_below`` (or any high-risk action) is not auto-executed: it
    # halts as a pending action for a human to approve or reject. Mirrors the
    # verifier bank's escalate_below default.
    escalate_below: float = 0.75

    # How long a pending (human-hold) action stays approvable before it lapses.
    # A `sweep` transitions holds older than this to EXPIRED, and approval
    # re-checks it at decision time; an expired hold can never execute. Default
    # is 24h; set to 0 to disable expiry (holds live until decided).
    pending_ttl_seconds: int = 86_400

    # Swarm cost control: the maximum number of role/provider generation calls a
    # single swarm task may make. Modest by default so a run cannot make
    # unbounded provider calls; raise it for wider role panels.
    max_role_calls: int = 16

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
            # Empty means unset for both: they then inherit the actor's endpoint.
            judge_api_base=env.get("PROM_JUDGE_API_BASE") or None,
            judge_api_key=env.get("PROM_JUDGE_API_KEY") or None,
            judge_temperature=_as_float(env.get("PROM_JUDGE_TEMPERATURE"), 0.0),
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
            require_digest_pin=_as_bool(env.get("PROM_REQUIRE_DIGEST_PIN"), False),
            gate_threshold=_as_float(env.get("PROM_GATE_THRESHOLD"), 0.0),
            retrieval_k=_as_int(env.get("PROM_RETRIEVAL_K"), 5),
            escalate_below=_as_float(env.get("PROM_ESCALATE_BELOW"), 0.75),
            pending_ttl_seconds=_as_int(env.get("PROM_PENDING_TTL"), 86_400),
            max_role_calls=_as_int(env.get("PROM_MAX_ROLE_CALLS"), 16),
            request_timeout_s=_as_float(env.get("PROM_REQUEST_TIMEOUT_S"), 30.0),
        )
