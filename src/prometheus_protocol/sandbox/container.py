"""Container isolating adapter (Docker or Podman).

The most robust production option: the candidate runs in a container with
``--network none`` (no network), a read-only root plus a writable workspace
bind, ``--memory`` / CPU quota / ``--pids-limit`` (cgroup-backed resource
bounds), ``--cap-drop ALL`` and ``--security-opt no-new-privileges`` and a
non-root user (least privilege), and the runtime's default seccomp profile. The
image should be pinned by digest in production (``PROM_SANDBOX_IMAGE``); a bare
tag is accepted but logged as a supply-chain risk, and can be *refused* outright
by setting ``PROM_REQUIRE_DIGEST_PIN`` (fail-closed production posture).

Every run is wrapped by a small bootstrap mounted read-only into the container
that carries the unforgeable candidate-start signal (a per-run nonce over
stdin, nonce-keyed lines on stderr — see ``_start_signal.py``), so a
container-run candidate crash is attributed to the candidate exactly as on the
namespace adapter, and a run whose candidate never started is never reported
as started.

It requires a running container daemon, so where none is available the
namespace adapter is preferred. See ``docs/sandbox.md``.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Mapping, Sequence

from prometheus_protocol.sandbox._start_signal import (
    exec_failed_line,
    interpret_stream,
    new_nonce,
)
from prometheus_protocol.sandbox.base import Limits, Sandbox, SandboxResult, clip

_LOG = logging.getLogger(__name__)

# Overridable; production should pin by digest, e.g. python:3.12-slim@sha256:...
_DEFAULT_IMAGE = os.environ.get("PROM_SANDBOX_IMAGE", "python:3.12-slim")
_WORKDIR = "/workspace"
# The in-container bootstrap that carries the unforgeable candidate-start
# signal (see ``_start_signal.py``); staged into each run's workspace and run
# from there (``/workspace/.prom-start.py``, invoked relative to the workdir).
_BOOTSTRAP = Path(__file__).with_name("_container_bootstrap.py")
_BOOTSTRAP_NAME = ".prom-start.py"


def _runtime() -> str | None:
    for candidate in ("docker", "podman"):
        if shutil.which(candidate):
            return candidate
    return None


def _as_text(stream) -> str | None:
    """Coerce a subprocess stream to str; ``TimeoutExpired`` gives bytes."""

    if stream is None:
        return None
    if isinstance(stream, bytes):
        return stream.decode("utf-8", "replace")
    return stream


def is_digest_pinned(image: str) -> bool:
    """Whether ``image`` names an immutable image by content digest.

    A digest pin (``…@sha256:…``) binds the name to a specific content hash; a
    bare tag can be repointed at a different image after it was vetted, so a
    production posture may require the pin (see ``require_digest_pin``).
    """

    return "@sha256:" in image


def _require_digest_pin(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return (env.get("PROM_REQUIRE_DIGEST_PIN", "") or "").strip().lower() in {
        "1", "true", "yes", "on",
    }


class ContainerSandbox(Sandbox):
    name = "container"
    isolating = True

    def __init__(
        self,
        *,
        runtime: str | None = None,
        image: str | None = None,
        require_digest_pin: bool | None = None,
    ) -> None:
        self.runtime = runtime or _runtime()
        self.image = image or _DEFAULT_IMAGE
        # Refuse a bare-tag image when set (fail-closed); default off, resolved
        # from PROM_REQUIRE_DIGEST_PIN, so dev keeps its convenience.
        self.require_digest_pin = (
            _require_digest_pin() if require_digest_pin is None else require_digest_pin
        )
        if not is_digest_pinned(self.image):
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
        # Fail closed on an unpinned image when digest pinning is required: a bare
        # tag can be silently repointed at a different image after it was vetted,
        # so refuse rather than run a possibly-substituted image. Checked before
        # the runtime probe so the refusal is deterministic and testable without a
        # container daemon. This never loosens anything — with the flag off,
        # behaviour is unchanged (a bare tag still runs, with the warning above).
        if self.require_digest_pin and not is_digest_pinned(self.image):
            _LOG.error(
                "refusing container image %r: PROM_REQUIRE_DIGEST_PIN is set but the "
                "image is not digest-pinned (…@sha256:…)",
                self.image,
            )
            return SandboxResult(
                started_ok=False,
                detail=(
                    f"image {self.image!r} is not digest-pinned and "
                    "PROM_REQUIRE_DIGEST_PIN is set"
                ),
            )

        if self.runtime is None:
            return SandboxResult(started_ok=False, detail="no container runtime")

        # Stage the start-signal bootstrap into the run's own workspace (already
        # bind-mounted read-write) rather than bind-mounting the installed
        # package file: a fresh, world-readable copy per run avoids depending on
        # the install-path file's mode (a 0600 install, or an SELinux label on a
        # separate mount, would otherwise make the container user unable to read
        # it and fail every run closed). The candidate cannot subvert it — the
        # bootstrap has exec'd the candidate away before the candidate's code
        # runs, each run gets a fresh workspace, and the per-run nonce arrives on
        # stdin, never from this file.
        try:
            staged = Path(workspace) / _BOOTSTRAP_NAME
            shutil.copyfile(_BOOTSTRAP, staged)
            os.chmod(staged, 0o644)
        except OSError as exc:
            return SandboxResult(
                started_ok=False, detail=f"could not stage container bootstrap: {exc}"
            )

        # Rewrite the interpreter path: argv[0] is the host interpreter; in the
        # image the candidate runs under the image's python with the same flags.
        # The candidate command is wrapped by the staged bootstrap, which carries
        # the unforgeable candidate-start signal: it consumes a fresh per-run
        # nonce from the first line of stdin (a place the candidate can never
        # read it back from) and emits the nonce-keyed started line on stderr
        # right before exec'ing the candidate.
        inner_argv = ["python", *argv[1:]] if argv else ["python"]
        nonce = new_nonce()
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
            "python", _BOOTSTRAP_NAME, "--",
            *inner_argv,
        ]
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=limits.wall_time_s,
                input=f"{nonce}\n{stdin or ''}",
            )
        except subprocess.TimeoutExpired as exc:
            # CPython populates TimeoutExpired.stdout/.stderr as *bytes* even
            # under text=True, so decode before interpreting the signal (else
            # the started line is never seen and its stderr is dropped).
            candidate_started, err_text = interpret_stream(
                _as_text(exc.stderr), nonce
            )
            out, truncated = clip(_as_text(exc.stdout), limits.max_output_bytes)
            err, _ = clip(err_text, limits.max_output_bytes)
            return SandboxResult(
                stdout=out, stderr=err, timed_out=True, started_ok=True,
                candidate_started=candidate_started,
                output_truncated=truncated, limiter="cgroup",
                detail=f"wall-time limit {limits.wall_time_s}s",
            )
        except OSError as exc:
            return SandboxResult(started_ok=False, detail=f"could not launch container: {exc}")

        candidate_started, err_text = interpret_stream(proc.stderr, nonce)
        # Fail-closed start reporting on the unforgeable signal ALONE, mirroring
        # the namespace adapter (started_ok == candidate_started): the run is
        # "started" only when the bootstrap's nonce-keyed started line is
        # present and unrevoked — a signal the candidate cannot write or unsay.
        # Never inferred from the exit code, which the candidate controls: a
        # contained candidate that itself exits 125 is a real (started) run, and
        # docker's own 125 "could not create container" simply produces no
        # started line (candidate_started False) via the same path. This closes
        # the parity gap without letting a chosen exit code fake a harness fault.
        started_ok = candidate_started
        if candidate_started:
            detail = ""
        elif exec_failed_line(nonce) in (proc.stderr or ""):
            detail = "candidate could not be started inside the container"
        elif proc.returncode == 125:
            detail = "container could not start"
        else:
            detail = "container did not confirm candidate start"
        out, truncated = clip(proc.stdout, limits.max_output_bytes)
        err, _ = clip(err_text, limits.max_output_bytes)
        return SandboxResult(
            stdout=out, stderr=err, exit_status=proc.returncode,
            memory_exceeded=proc.returncode in (-9, 137),
            output_truncated=truncated, started_ok=started_ok,
            candidate_started=candidate_started, limiter="cgroup",
            detail=detail,
        )
