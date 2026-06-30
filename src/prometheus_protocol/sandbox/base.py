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
    missing runtime, a failed setup), and the caller must treat the run as "could
    not verify" (ABSTAIN) — never as a pass or a fail.
    """

    stdout: str = ""
    stderr: str = ""
    exit_status: int | None = None
    timed_out: bool = False
    memory_exceeded: bool = False
    pids_exceeded: bool = False
    output_truncated: bool = False
    started_ok: bool = True
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
