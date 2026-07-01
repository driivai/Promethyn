"""The explicitly-unsafe direct runner, and a null no-isolation backstop.

``UnsafeLocalSandbox`` is the historical subprocess-with-timeout path. It is
**NOT a sandbox**: no network, filesystem, or privilege isolation — only a
wall-clock timeout and POSIX rlimits that bound *accidental* runaway code. It is
for offline development against trusted/mock examples and is selectable ONLY
with ``PROM_ALLOW_UNSAFE_EXEC=1``; it logs a warning every time it runs.

``NullSandbox`` runs nothing and reports ``started_ok=False``. It is the
backstop when no isolating adapter is available and the unsafe runner was not
opted into, so the default path can never silently execute untrusted code
without isolation.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Sequence

from prometheus_protocol.sandbox.base import (
    FSIZE_BYTES,
    Limits,
    Sandbox,
    SandboxResult,
    clip,
)

_LOG = logging.getLogger(__name__)


def _rlimits(cpu_seconds: int, memory_bytes: int):
    if os.name != "posix":
        return None
    import resource

    def _apply() -> None:
        if cpu_seconds > 0:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        if memory_bytes > 0:
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (FSIZE_BYTES, FSIZE_BYTES))

    return _apply


class UnsafeLocalSandbox(Sandbox):
    name = "unsafe"
    isolating = False

    def run(
        self,
        *,
        argv: Sequence[str],
        workspace: Path | str,
        limits: Limits = Limits(),
        stdin: str = "",
    ) -> SandboxResult:
        _LOG.warning(
            "UNSAFE execution: running candidate code WITHOUT isolation "
            "(no network/filesystem/privilege containment). Dev-only."
        )
        try:
            proc = subprocess.run(
                list(argv),
                cwd=str(workspace),
                capture_output=True,
                text=True,
                timeout=limits.wall_time_s,
                input=stdin or None,
                preexec_fn=_rlimits(limits.cpu_time_s, limits.memory_bytes),
            )
        except subprocess.TimeoutExpired as exc:
            out, truncated = clip(exc.stdout, limits.max_output_bytes)
            err, _ = clip(exc.stderr, limits.max_output_bytes)
            return SandboxResult(
                stdout=out, stderr=err, timed_out=True, started_ok=True,
                candidate_started=True,
                output_truncated=truncated, detail=f"wall-time limit {limits.wall_time_s}s",
            )
        out, truncated = clip(proc.stdout, limits.max_output_bytes)
        err, _ = clip(proc.stderr, limits.max_output_bytes)
        # The unsafe runner execs the candidate directly, with no fallible setup
        # step: a completed subprocess run means the candidate definitely started.
        return SandboxResult(
            stdout=out, stderr=err, exit_status=proc.returncode,
            candidate_started=True,
            output_truncated=truncated, started_ok=True,
        )


class NullSandbox(Sandbox):
    name = "null"
    isolating = True  # it refuses to run unsandboxed, which is the safe default

    def run(
        self,
        *,
        argv: Sequence[str],
        workspace: Path | str,
        limits: Limits = Limits(),
        stdin: str = "",
    ) -> SandboxResult:
        return SandboxResult(
            started_ok=False,
            detail=(
                "no isolating sandbox is available; refusing to run untrusted "
                "code unsandboxed (set PROM_SANDBOX or PROM_ALLOW_UNSAFE_EXEC)"
            ),
        )
