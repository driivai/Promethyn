"""Daemonless isolating adapter built on Linux user namespaces.

Runs the candidate under ``unshare`` in fresh user + mount + network + PID
namespaces, then (via :mod:`._bootstrap`) makes the root filesystem read-only
with a writable workspace, hides sensitive paths, drops new-privilege
acquisition, and applies POSIX rlimits. The network namespace has no interfaces,
so all outbound connections fail; nothing requires a container daemon or root.

This is the default isolating adapter where a container runtime is unavailable.
See ``docs/sandbox.md`` for the threat model and the requirements (an
unprivileged-user-namespaces-capable Linux kernel).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from prometheus_protocol.sandbox.base import (
    FSIZE_BYTES,
    Limits,
    Sandbox,
    SandboxResult,
    clip,
)

_BOOTSTRAP = Path(__file__).with_name("_bootstrap.py")
_MARKER = "sandbox-bootstrap:"
# Cached result of the functional availability probe (per process).
_AVAILABLE_CACHE: bool | None = None
_UNSHARE_FLAGS = (
    "--user",
    "--map-root-user",
    "--mount",
    "--net",
    "--pid",
    "--fork",
    "--kill-child",
)


class NamespaceSandbox(Sandbox):
    name = "namespace"
    isolating = True

    def __init__(self, *, unshare_path: str | None = None) -> None:
        self.unshare = unshare_path or shutil.which("unshare")

    @classmethod
    def available(cls) -> bool:
        """Whether a full isolated run actually works here (cached).

        This is a *functional* probe — it runs a trivial candidate through the
        complete bootstrap (namespaces + mounts + cap drop), not merely a check
        that ``unshare`` starts — so a host where unprivileged user namespaces
        start but mounts are restricted is correctly reported as unavailable.
        """

        global _AVAILABLE_CACHE
        if _AVAILABLE_CACHE is None:
            _AVAILABLE_CACHE = cls._probe_available()
        return _AVAILABLE_CACHE

    @classmethod
    def _probe_available(cls) -> bool:
        if shutil.which("unshare") is None:
            return False
        try:
            with tempfile.TemporaryDirectory(prefix="prom-sbprobe-") as ws:
                Path(ws, "_probe.py").write_text(
                    "print('sandbox-ok')", encoding="utf-8"
                )
                result = cls().run(
                    argv=[sys.executable, "-I", "_probe.py"],
                    workspace=ws,
                    limits=Limits(wall_time_s=20, memory_bytes=0),
                )
        except Exception:
            return False
        return (
            result.started_ok
            and result.exit_status == 0
            and "sandbox-ok" in result.stdout
        )

    def run(
        self,
        *,
        argv: Sequence[str],
        workspace: Path | str,
        limits: Limits = Limits(),
        stdin: str = "",
    ) -> SandboxResult:
        if self.unshare is None:
            return SandboxResult(started_ok=False, detail="unshare not found")

        command = [
            self.unshare,
            *_UNSHARE_FLAGS,
            sys.executable,
            "-I",
            str(_BOOTSTRAP),
            str(workspace),
            str(limits.memory_bytes),
            str(limits.cpu_time_s),
            str(limits.max_processes),
            str(FSIZE_BYTES),
            "--",
            *argv,
        ]
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=limits.wall_time_s,
                input=stdin or None,
            )
        except subprocess.TimeoutExpired as exc:
            out, truncated = clip(exc.stdout, limits.max_output_bytes)
            err, _ = clip(exc.stderr, limits.max_output_bytes)
            return SandboxResult(
                stdout=out,
                stderr=err,
                exit_status=None,
                timed_out=True,
                output_truncated=truncated,
                started_ok=True,
                detail=f"wall-time limit {limits.wall_time_s}s",
            )
        except OSError as exc:
            return SandboxResult(started_ok=False, detail=f"could not launch sandbox: {exc}")

        # Did isolation start? The bootstrap exits 127 with a marker if FS setup
        # or exec failed before the candidate ran.
        started_ok = not (proc.returncode == 127 and _MARKER in (proc.stderr or ""))
        out, truncated = clip(proc.stdout, limits.max_output_bytes)
        err, _ = clip(proc.stderr, limits.max_output_bytes)
        rc = proc.returncode
        # Best-effort breach flags. A child killed by SIGKILL (-9) under the
        # address-space cap, or a Python MemoryError, signals memory pressure; a
        # fork that hit RLIMIT_NPROC reports as a resource-temporarily-unavailable.
        memory_exceeded = rc in (-9, 137) or "MemoryError" in (err or "")
        pids_exceeded = (
            "BlockingIOError" in (err or "")
            or "Resource temporarily unavailable" in (err or "")
        )
        return SandboxResult(
            stdout=out,
            stderr=err,
            exit_status=rc,
            memory_exceeded=memory_exceeded,
            pids_exceeded=pids_exceeded,
            output_truncated=truncated,
            started_ok=started_ok,
            detail="" if started_ok else "sandbox setup failed",
        )
