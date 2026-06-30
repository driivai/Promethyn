"""Container isolating adapter (Docker or Podman).

The most robust production option: the candidate runs in a container with
``--network none`` (no network), a read-only root plus a writable workspace
bind, ``--memory`` / CPU quota / ``--pids-limit`` (resource bounds),
``--cap-drop ALL`` and ``--security-opt no-new-privileges`` and a non-root user
(least privilege), and the runtime's default seccomp profile. The image should
be pinned by digest in production (``PROM_SANDBOX_IMAGE``); a bare tag is
accepted but logged as a supply-chain risk.

It requires a running container daemon, so where none is available the
namespace adapter is preferred. See ``docs/sandbox.md``.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Sequence

from prometheus_protocol.sandbox.base import Limits, Sandbox, SandboxResult, clip

_LOG = logging.getLogger(__name__)

# Overridable; production should pin by digest, e.g. python:3.12-slim@sha256:...
_DEFAULT_IMAGE = os.environ.get("PROM_SANDBOX_IMAGE", "python:3.12-slim")
_WORKDIR = "/workspace"


def _runtime() -> str | None:
    for candidate in ("docker", "podman"):
        if shutil.which(candidate):
            return candidate
    return None


class ContainerSandbox(Sandbox):
    name = "container"
    isolating = True

    def __init__(self, *, runtime: str | None = None, image: str | None = None) -> None:
        self.runtime = runtime or _runtime()
        self.image = image or _DEFAULT_IMAGE
        if "@sha256:" not in self.image:
            _LOG.warning(
                "container sandbox image %r is not digest-pinned; pin it in "
                "production via PROM_SANDBOX_IMAGE",
                self.image,
            )

    @classmethod
    def available(cls) -> bool:
        runtime = _runtime()
        if runtime is None:
            return False
        try:
            probe = subprocess.run(
                [runtime, "info"], capture_output=True, timeout=20
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return probe.returncode == 0

    def run(
        self,
        *,
        argv: Sequence[str],
        workspace: Path | str,
        limits: Limits = Limits(),
        stdin: str = "",
    ) -> SandboxResult:
        if self.runtime is None:
            return SandboxResult(started_ok=False, detail="no container runtime")

        # Rewrite the interpreter path: argv[0] is the host interpreter; in the
        # image the candidate runs under the image's python with the same flags.
        inner_argv = ["python", *argv[1:]] if argv else ["python"]
        command = [
            self.runtime, "run", "--rm", "--interactive",
            "--network", "none",
            "--read-only",
            "--tmpfs", "/tmp:rw,size=64m",
            "--volume", f"{workspace}:{_WORKDIR}:rw",
            "--workdir", _WORKDIR,
            "--memory", str(max(limits.memory_bytes, 16 * 1024 * 1024)),
            "--memory-swap", str(max(limits.memory_bytes, 16 * 1024 * 1024)),
            "--cpus", "1",
            "--pids-limit", str(limits.max_processes),
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", "65534:65534",
            self.image,
            *inner_argv,
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
                stdout=out, stderr=err, timed_out=True, started_ok=True,
                output_truncated=truncated, detail=f"wall-time limit {limits.wall_time_s}s",
            )
        except OSError as exc:
            return SandboxResult(started_ok=False, detail=f"could not launch container: {exc}")

        # A failure to create the container (bad image, daemon error) is a
        # could-not-verify, not a candidate fault.
        started_ok = not (proc.returncode == 125)
        out, truncated = clip(proc.stdout, limits.max_output_bytes)
        err, _ = clip(proc.stderr, limits.max_output_bytes)
        return SandboxResult(
            stdout=out, stderr=err, exit_status=proc.returncode,
            memory_exceeded=proc.returncode in (-9, 137),
            output_truncated=truncated, started_ok=started_ok,
            detail="" if started_ok else "container could not start",
        )
