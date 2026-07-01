"""Best-effort cgroup process/resource limiting for the namespace sandbox.

``RLIMIT_NPROC`` is a per-uid cap that a privileged nested process can bypass; a
cgroup ``pids.max`` is a per-cgroup cap that it cannot. Where a writable cgroup
is available — the v2 unified hierarchy with the ``pids`` controller delegated,
or the v1 ``pids`` controller — we create a scoped cgroup, cap it (pids, and on
v2 also memory and cpu), and move the candidate process tree into it before it
runs, so the whole tree is bounded by the stronger lever.

Everything here is **best-effort and defensive**: any failure returns ``None``
or does nothing, and the caller keeps applying its POSIX rlimits regardless. So
this can only *add* containment — it never removes a guarantee and never breaks a
run. The caller records which lever was used (``SandboxResult.limiter``).
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

_CG_ROOT = Path("/sys/fs/cgroup")


def _write(path: Path, value: str) -> bool:
    try:
        with open(path, "w", encoding="ascii") as handle:
            handle.write(value)
        return True
    except OSError:
        return False


def _v2_self_dir() -> Path | None:
    """The process's cgroup v2 directory, iff the ``pids`` controller is available."""

    try:
        controllers = (_CG_ROOT / "cgroup.controllers").read_text().split()
    except OSError:
        return None
    if "pids" not in controllers:
        return None
    try:
        for line in Path("/proc/self/cgroup").read_text().splitlines():
            if line.startswith("0::"):  # the unified (v2) entry
                rel = line.split(":", 2)[2].strip().lstrip("/")
                return _CG_ROOT / rel
    except OSError:
        pass
    return None


class PidsCgroup:
    """A scoped cgroup that caps the process count (and, on v2, memory/cpu)."""

    def __init__(self, path: Path, *, kind: str) -> None:
        self._path = path
        self.kind = kind  # "v2" or "v1"

    @property
    def procs_path(self) -> str:
        return str(self._path / "cgroup.procs")

    def hit_limit(self) -> bool:
        """Whether the cgroup itself denied a fork (the pids cap was reached).

        Reads ``pids.events``' ``max`` counter — a cgroup-specific, unforgeable
        signal that the stronger lever enforced the cap.
        """

        try:
            for line in (self._path / "pids.events").read_text().splitlines():
                if line.startswith("max ") and int(line.split()[1]) > 0:
                    return True
        except (OSError, ValueError):
            pass
        return False

    def close(self) -> None:
        # Removable only once empty; the candidate tree is reaped before we get
        # here, so this normally succeeds. Best-effort — a transient non-empty
        # cgroup is harmless and reclaimed by the kernel when it drains.
        try:
            os.rmdir(self._path)
        except OSError:
            pass


def create_pids_cgroup(
    *, pids_max: int, memory_bytes: int, cpu_seconds: int
) -> PidsCgroup | None:
    """Create a scoped cgroup capping pids (and, on v2, memory/cpu). ``None`` on any failure."""

    if pids_max <= 0:
        return None
    name = f"prom-sbox-{os.getpid()}-{uuid.uuid4().hex[:8]}"

    # Prefer cgroup v2: one directory holds pids, memory, and cpu.
    v2 = _v2_self_dir()
    if v2 is not None:
        cgroup = v2 / name
        try:
            cgroup.mkdir()
        except OSError:
            cgroup = None
        if cgroup is not None:
            if (cgroup / "pids.max").exists() and _write(cgroup / "pids.max", str(pids_max)):
                if memory_bytes > 0 and (cgroup / "memory.max").exists():
                    _write(cgroup / "memory.max", str(memory_bytes))
                if cpu_seconds > 0 and (cgroup / "cpu.max").exists():
                    # Coarse cpu quota: at most ``cpu_seconds`` cores of runtime
                    # per 1s window (>= 1 core so ordinary work still runs).
                    _write(cgroup / "cpu.max", f"{max(cpu_seconds, 1) * 100000} 100000")
                return PidsCgroup(cgroup, kind="v2")
            try:
                os.rmdir(cgroup)  # pids not delegated here; don't disturb subtree_control
            except OSError:
                pass

    # Fall back to the cgroup v1 pids controller.
    v1 = _CG_ROOT / "pids"
    if (v1 / "cgroup.procs").exists():
        cgroup = v1 / name
        try:
            cgroup.mkdir()
        except OSError:
            return None
        if (cgroup / "pids.max").exists() and _write(cgroup / "pids.max", str(pids_max)):
            return PidsCgroup(cgroup, kind="v1")
        try:
            os.rmdir(cgroup)
        except OSError:
            pass
    return None


def join_current_process(procs_path: str) -> None:
    """Move the calling process into the cgroup. Best-effort — never raises.

    Runs from the child's pre-exec hook, before ``unshare``, so the whole
    candidate tree inherits the cgroup. A failure here is non-fatal: the rlimit
    floor still applies.
    """

    try:
        fd = os.open(procs_path, os.O_WRONLY)
        try:
            os.write(fd, str(os.getpid()).encode("ascii"))
        finally:
            os.close(fd)
    except OSError:
        pass
