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

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from prometheus_protocol.sandbox._start_signal import (
    pipe_candidate_started,
    pipe_exec_failed,
    pipe_setup_failed,
)
from prometheus_protocol.sandbox.base import (
    FSIZE_BYTES,
    Limits,
    Sandbox,
    SandboxResult,
    clip,
)
from prometheus_protocol.sandbox.cgroup import (
    create_pids_cgroup,
    join_current_process,
)

_BOOTSTRAP = Path(__file__).with_name("_bootstrap.py")
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

        # A status pipe carries a definite "candidate started" token from the
        # bootstrap. The write end is inherited by the child and closed on exec,
        # so the candidate never sees the fd and cannot forge or suppress it.
        status_r, status_w = os.pipe()
        # Cap the candidate process tree with the stronger cgroup lever where a
        # writable cgroup is available; the bootstrap's POSIX rlimits stay as the
        # floor regardless, so this only adds containment, never removes it.
        cgroup = create_pids_cgroup(
            pids_max=limits.max_processes,
            memory_bytes=limits.memory_bytes,
            cpu_seconds=limits.cpu_time_s,
        )
        limiter = "cgroup" if cgroup is not None else "rlimit"
        preexec = (
            (lambda procs=cgroup.procs_path: join_current_process(procs))
            if cgroup is not None
            else None
        )
        try:
            os.set_inheritable(status_w, True)
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
                str(status_w),
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
                    pass_fds=(status_w,),
                    preexec_fn=preexec,
                )
            except subprocess.TimeoutExpired as exc:
                os.close(status_w)
                status_w = -1
                out, truncated = clip(exc.stdout, limits.max_output_bytes)
                err, _ = clip(exc.stderr, limits.max_output_bytes)
                return SandboxResult(
                    stdout=out,
                    stderr=err,
                    exit_status=None,
                    timed_out=True,
                    pids_exceeded=(cgroup.hit_limit() if cgroup is not None else False),
                    output_truncated=truncated,
                    started_ok=True,
                    candidate_started=pipe_candidate_started(
                        self._read_status(status_r)
                    ),
                    limiter=limiter,
                    detail=f"wall-time limit {limits.wall_time_s}s",
                )
            except OSError as exc:
                return SandboxResult(started_ok=False, detail=f"could not launch sandbox: {exc}")

            os.close(status_w)
            status_w = -1
            status = self._read_status(status_r)
            candidate_started = pipe_candidate_started(status)

            # Did isolation start, and did the candidate actually run? Decided
            # by the status-pipe tokens ALONE — a channel the candidate cannot
            # write — never by parsing exit codes or stderr text a hostile
            # candidate controls. Printing the old bootstrap marker and exiting
            # 127 therefore forges nothing: with an unrevoked started token the
            # run is the candidate's own. Conservative on doubt: no token (the
            # bootstrap never ran), a setup-failed token, or a revoked start
            # (exec failed — the candidate never ran) all report not-started,
            # which callers treat as a harness fault, never a claimed execution.
            started_ok = candidate_started
            if pipe_exec_failed(status):
                detail = "candidate exec failed inside the sandbox"
            elif pipe_setup_failed(status):
                detail = "sandbox setup failed"
            elif not candidate_started:
                detail = "sandbox did not confirm candidate start"
            else:
                detail = ""
            out, truncated = clip(proc.stdout, limits.max_output_bytes)
            err, _ = clip(proc.stderr, limits.max_output_bytes)
            rc = proc.returncode
            # Best-effort breach flags. A child killed by SIGKILL (-9) under the
            # address-space cap, or a Python MemoryError, signals memory pressure;
            # a fork that hit RLIMIT_NPROC reports as a resource-temporarily-
            # unavailable.
            memory_exceeded = rc in (-9, 137) or "MemoryError" in (err or "")
            # The cgroup ``pids.events`` counter is the unforgeable signal that the
            # stronger lever denied a fork; OR it in so a cgroup-enforced cap is
            # reported even when the candidate swallowed the errno.
            pids_exceeded = (
                "BlockingIOError" in (err or "")
                or "Resource temporarily unavailable" in (err or "")
                or (cgroup.hit_limit() if cgroup is not None else False)
            )
            return SandboxResult(
                stdout=out,
                stderr=err,
                exit_status=rc,
                memory_exceeded=memory_exceeded,
                pids_exceeded=pids_exceeded,
                output_truncated=truncated,
                started_ok=started_ok,
                candidate_started=candidate_started,
                limiter=limiter,
                detail=detail,
            )
        finally:
            os.close(status_r)
            if status_w != -1:
                os.close(status_w)
            if cgroup is not None:
                cgroup.close()

    @staticmethod
    def _read_status(status_r: int) -> bytes:
        """Drain the status pipe: the bootstrap's tokens, or empty on none.

        All write ends are closed by the time this is called (the child has
        exited and the parent closed its own), so the loop terminates promptly
        at EOF. Bounded: the bootstrap writes at most two short tokens.
        """

        data = b""
        try:
            while len(data) < 256:
                chunk = os.read(status_r, 256)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        return data
