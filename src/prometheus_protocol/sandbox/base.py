"""The Sandbox port: run untrusted code under isolation.

This is the trusted-core safety boundary expressed as a small, swappable port.
Adapters (namespace, container, unsafe) provide the mechanism; the guarantee —
"untrusted code runs only under isolation" — lives here and is proven by the
INV-SANDBOX conformance tests. The port is deliberately generic (it runs a
command in an isolated, writable workspace) so the future live executor can
reuse it; this sprint wires it only into the verifier.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

#: Hard cap on a candidate's on-disk writes, regardless of output limits.
FSIZE_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True)
class Limits:
    """Resource and policy limits for one sandboxed run.

    ``memory_bytes <= 0`` disables the address-space cap (it can prevent some
    interpreters from starting if set too low). The filesystem policy is fixed
    by the adapter: the ``workspace`` is read-write, the rest of the filesystem
    is read-only or hidden. ``deny_network`` is always honoured by an isolating
    adapter.
    """

    wall_time_s: float = 5.0
    cpu_time_s: int = 5
    memory_bytes: int = 256 * 1024 * 1024
    max_processes: int = 64
    max_output_bytes: int = 1_000_000
    deny_network: bool = True


@dataclass(frozen=True)
class SandboxResult:
    """The outcome of one sandboxed run.

    ``started_ok`` answers the load-bearing question: did isolation start at
    all? When it is ``False`` the candidate did not run under isolation (a
    missing runtime, a failed setup, or a deliberate policy refusal), and the
    caller must treat the run as **could-not-execute** — a non-verdict outcome
    (:class:`~prometheus_protocol.core.models.Unavailable`), never a pass, a
    fail, or an abstention. ``policy_refusal`` distinguishes *why* it could not
    run: ``True`` for a deliberate refusal to run (a supply-chain guard, e.g. an
    unpinned image under a required digest pin — a chosen "no"), ``False`` for an
    infrastructure fault (no runtime, setup failure — a fault to repair). A caller
    maps the two to ``Unavailability.POLICY_REFUSAL`` / ``INFRA_FAULT`` so they
    are never flattened together.

    ``candidate_started`` is the stronger, *definite* signal: the candidate
    command actually began executing under isolation. It is set only when the
    adapter has positive confirmation the candidate ran, so ``started_ok=True``
    with ``candidate_started=False`` — e.g. a wall-clock timeout during setup,
    before the candidate ran — stays a harness fault. A candidate that ran and
    then crashed (``candidate_started=True``, no verdict produced) is the
    candidate's own fault, not the harness's.

    For the isolating adapters both flags rest on the unforgeable start signal
    (``_start_signal.py``): tokens a bootstrap emits at the point isolation is
    established, on a channel the candidate can neither write nor unsay — a
    close-on-exec status pipe (namespace) or nonce-keyed stream lines whose
    nonce the candidate can never read (container). Neither flag is ever
    inferred from exit codes or output text a hostile candidate controls, so
    printing a fake failure marker (with any exit status) cannot turn the
    candidate's own crash into a harness fault.
    """

    stdout: str = ""
    stderr: str = ""
    exit_status: int | None = None
    timed_out: bool = False
    memory_exceeded: bool = False
    pids_exceeded: bool = False
    output_truncated: bool = False
    started_ok: bool = True
    candidate_started: bool = False
    #: When ``started_ok`` is False, whether the run was *deliberately refused*
    #: (a policy/supply-chain guard) rather than an infrastructure fault. Set
    #: structurally at the refusal site — never inferred from ``detail`` text —
    #: so a caller can classify the unavailability without parsing a string.
    policy_refusal: bool = False
    #: Which process/resource-limit lever the adapter used: ``"cgroup"`` (the
    #: stronger, per-cgroup cap — pids.max and, on v2, memory/cpu) or ``"rlimit"``
    #: (the POSIX rlimit fallback). Never silently weaker: a caller can tell.
    limiter: str = "rlimit"
    detail: str = ""


def clip(text: str | None, limit: int) -> tuple[str, bool]:
    """Truncate ``text`` to ``limit`` bytes-ish; return (text, truncated)."""

    if not text:
        return "", False
    if len(text) <= limit:
        return text, False
    return text[:limit] + "\n... (truncated)", True


class Sandbox(ABC):
    """Runs a command in an isolated, writable workspace and reports the result."""

    #: Stable adapter name (matches ``Config.sandbox`` / ``PROM_SANDBOX``).
    name: str = "sandbox"
    #: True for adapters that actually isolate; False for the unsafe runner.
    isolating: bool = True

    @abstractmethod
    def run(
        self,
        *,
        argv: Sequence[str],
        workspace: Path | str,
        limits: Limits = Limits(),
        stdin: str = "",
    ) -> SandboxResult:
        """Run ``argv`` with ``cwd`` = ``workspace`` under isolation."""
        raise NotImplementedError

    @classmethod
    def available(cls) -> bool:
        """Whether this adapter's isolation runtime is usable on this host."""

        return True
