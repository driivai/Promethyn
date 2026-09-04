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
import stat
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

#: The unprivileged identity the candidate runs as inside the container when the
#: host is privileged enough to hand it the workspace.
CONTAINER_UID = 65534
CONTAINER_GID = 65534

#: The only mode the workspace is ever given: owner-only. Nothing for group, and
#: nothing for other.
WORKSPACE_MODE = 0o700


def prepare_workspace(workspace: Path | str) -> tuple[str | None, str]:
    """Make the bind-mounted workspace usable by the container user, owner-only.

    Returns ``(container_user, "")`` for ``--user``, or ``(None, reason)``.

    The workspace is a fresh per-run host directory holding the candidate's code
    going in and its results coming out. The container runs as a non-root user,
    which must be able to traverse the directory, read those files, and write
    back — but the directory must NOT become readable or writable by every other
    account on the host. It previously did: it was chmod'd ``0o777``, so any
    local user could read the agent's workspace and, more seriously, alter an
    artifact between the moment it was written and the moment it was hashed.
    That is a local-tampering hole open to any unprivileged account, requiring no
    vulnerability at all.

    Two ways to get access without granting it to the world, in preference order:

    1. **Hand the directory to the unprivileged container user.** Requires
       privilege to ``chown``, so it is the path taken when the runner is root.
       The candidate then runs as ``nobody`` and the workspace is ``0700`` owned
       by ``nobody`` — the strongest arrangement, since an escape lands as an
       account that owns nothing else.
    2. **Run the container as the host user.** An unprivileged runner cannot
       ``chown`` away, but it can run the container under its own uid/gid, which
       already traverses its own ``0700`` directory. The trade is stated in
       ``docs/threat-model.md`` §2: an escape then lands as the runner user
       rather than as ``nobody``. It is the right trade — a container escape past
       ``--cap-drop ALL --security-opt no-new-privileges --read-only --network
       none`` needs a runtime vulnerability, while a world-writable workspace
       needs only a local shell.

    Never falls back to widening the mode: if neither path works the run is
    refused, because a workspace nobody can reach is a failed run, while a
    workspace everybody can reach is a silent downgrade.
    """

    path = os.fspath(workspace)

    # Refuse to touch a SHARED directory. This function changes the mode and
    # possibly the owner of what it is given, which is correct for a private
    # per-run directory and destructive for a communal one: handed ``/tmp`` it
    # would take the whole machine's scratch space away from every other process.
    # That is not hypothetical — the repository's own provenance tests passed
    # ``workspace="/tmp"``, and the previous ``chmod(workspace, 0o777)`` quietly
    # stripped the sticky bit off the CI runner's ``/tmp`` on every run, which is
    # the very world-writable-path class this hardening is about. The sticky bit
    # is the kernel's own marker for "shared drop-box", so refuse those outright.
    try:
        info = os.stat(path)
    except OSError as exc:
        return None, f"workspace is unusable: {exc}"
    if not stat.S_ISDIR(info.st_mode):
        return None, "workspace must be a directory"
    if info.st_mode & stat.S_ISVTX:
        return None, (
            "workspace is a shared sticky directory; the sandbox needs a private "
            "per-run directory it may restrict, and must not re-permission a "
            "communal one"
        )

    try:
        os.chmod(path, WORKSPACE_MODE)
    except OSError as exc:
        return None, f"could not restrict workspace permissions: {exc}"

    try:
        os.chown(path, CONTAINER_UID, CONTAINER_GID)
    except (OSError, AttributeError) as exc:
        getuid = getattr(os, "getuid", None)
        getgid = getattr(os, "getgid", None)
        if getuid is None or getgid is None:
            return None, f"cannot determine a container user: {exc}"
        uid, gid = getuid(), getgid()
        if uid == 0:
            # Root that cannot chown means something is wrong with the workspace
            # itself. Running the candidate as root inside the container instead
            # would be a real weakening, so refuse rather than quietly do it.
            return None, f"privileged runner could not hand over the workspace: {exc}"
        return f"{uid}:{gid}", ""
    return f"{CONTAINER_UID}:{CONTAINER_GID}", ""


# The in-container bootstrap that carries the unforgeable candidate-start signal
# (see ``_start_signal.py``). It is delivered as ``python -c <source>`` — its
# source is read here at import and passed on the command line, NEVER staged as a
# file into the bind-mounted workspace. So the candidate cannot tamper with or
# replace it (nothing on the shared writable mount is load-bearing), and it
# sidesteps the ``--user``/bind-mount readability interaction a staged file hit:
# a non-root container user could not read the root-owned staged file (Errno 13),
# which made the start signal silently fail.
_BOOTSTRAP = Path(__file__).with_name("_container_bootstrap.py")
_BOOTSTRAP_SOURCE = _BOOTSTRAP.read_text(encoding="utf-8")
#: Retained only so a test can prove that a candidate WRITING this name into the
#: workspace forges nothing — the bootstrap is never read from there.
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
                # A deliberate refusal to run (a supply-chain guard), NOT an infra
                # fault: mark it structurally so the verifier maps it to
                # Unavailability.POLICY_REFUSAL, never flattened with a daemon-down
                # INFRA_FAULT.
                policy_refusal=True,
                detail=(
                    f"image {self.image!r} is not digest-pinned and "
                    "PROM_REQUIRE_DIGEST_PIN is set"
                ),
            )

        if self.runtime is None:
            return SandboxResult(started_ok=False, detail="no container runtime")

        # Give the container user access to the bind-mounted workspace WITHOUT
        # opening it to every local account. See :func:`prepare_workspace`.
        container_user, prep_error = prepare_workspace(workspace)
        if container_user is None:
            return SandboxResult(
                started_ok=False,
                detail=f"could not prepare container workspace: {prep_error}",
            )

        # Rewrite the interpreter path: argv[0] is the host interpreter; in the
        # image the candidate runs under the image's python with the same flags.
        # The candidate command is wrapped by the bootstrap delivered via ``-c``,
        # which carries the unforgeable candidate-start signal: it consumes a fresh
        # per-run nonce from the first line of stdin (a place the candidate can
        # never read it back from) and emits the nonce-keyed started line on stderr
        # right before exec'ing the candidate.
        # Prepend ``-B`` (never write bytecode) to the candidate harness command.
        # This is the load-bearing half of the no-orphan guarantee (see the
        # ``--env`` note below for why the env var alone cannot do it): the harness
        # runs under ``python -I`` and isolated mode implies ``-E``, so the
        # interpreter IGNORES every ``PYTHON*`` env var — ``PYTHONDONTWRITEBYTECODE``
        # included. Left unset, importing the candidate writes a ``__pycache__``
        # owned by the non-root container user (65534) into the bind-mounted
        # workspace, a sub-directory the unprivileged host then cannot remove when
        # it tears down its temp dir (a green run with a failing cleanup). ``-B`` is
        # a command-line flag ``-I`` does not suppress, so it stops the write at the
        # one process that actually does it.
        inner_argv = ["python", "-B", *argv[1:]] if argv else ["python", "-B"]
        nonce = new_nonce()
        command = [
            self.runtime, "run", "--rm", "--interactive",
            "--network", "none",
            "--read-only",
            "--tmpfs", "/tmp:rw,size=64m",
            "--volume", f"{workspace}:{_WORKDIR}:rw",
            "--workdir", _WORKDIR,
            # Belt to the ``-B`` suspenders above (which handles the isolated
            # harness process). Env vars ARE inherited across ``exec`` where the
            # ``-B`` flag is not, so this covers any NON-isolated ``python`` the
            # candidate itself spawns — stopping it, too, from leaving a
            # 65534-owned ``__pycache__`` on the shared mount that the host cannot
            # reap. The two are complementary; caching buys nothing for a one-shot
            # sandboxed run anyway.
            "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--memory", str(max(limits.memory_bytes, 16 * 1024 * 1024)),
            "--memory-swap", str(max(limits.memory_bytes, 16 * 1024 * 1024)),
            "--cpus", "1",
            "--pids-limit", str(limits.max_processes),
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", container_user,
            self.image,
            "python", "-c", _BOOTSTRAP_SOURCE, "--",
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
