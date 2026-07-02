"""Runs INSIDE the unshare namespaces, then execs the candidate command.

Invoked as::

    python -I _bootstrap.py <workspace> <mem> <cpu> <nproc> <fsize> -- argv...

Standard library only (it runs under ``-I``). It makes the root filesystem
read-only with the workspace kept read-write, hides a small set of sensitive
host directories, drops new-privilege acquisition, applies POSIX rlimits to the
candidate, then ``execv``s the command. Every outcome is reported on the status
pipe — a channel the candidate can neither write nor unsay (the tokens are
written before its code runs, on a fd made close-on-exec, so the candidate
never holds it): a setup failure writes the setup-failed token, an established
isolation writes the started token right before exec, and a failed exec revokes
it with the exec-failed token. The stderr marker lines remain for human
diagnostics only; nothing load-bearing parses them, so a candidate printing
them (plus any exit status) forges nothing.
"""

import ctypes
import ctypes.util
import os
import resource
import sys

# Host directories hidden from the candidate (overlaid with empty tmpfs). Kept
# minimal so the interpreter and its libraries (under /usr, /lib) still load.
_SENSITIVE = ("/root", "/home")

_MARKER = "sandbox-bootstrap:"
# Status-pipe tokens. Kept in sync with ``_start_signal.py`` (this file runs
# standalone under ``-I`` and cannot import the package); a conformance test
# asserts the copies match.
_STARTED_TOKEN = b"prom-candidate-started"
_EXEC_FAILED_TOKEN = b"prom-candidate-exec-failed"
_SETUP_FAILED_TOKEN = b"prom-sandbox-setup-failed"

_PR_CAPBSET_DROP = 24
_CAP_LAST = 40  # capabilities are 0..40 on current kernels; dropping past the
#                 last valid one simply returns EINVAL, which we ignore.
_LINUX_CAPABILITY_VERSION_3 = 0x20080522


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


def _drop_capabilities(libc) -> None:
    for cap in range(_CAP_LAST + 1):
        libc.prctl(_PR_CAPBSET_DROP, cap, 0, 0, 0)
    header = _CapHeader(_LINUX_CAPABILITY_VERSION_3, 0)
    data = (_CapData * 2)()  # all-zero: drop effective/permitted/inheritable
    try:
        libc.capset(ctypes.byref(header), ctypes.byref(data))
    except Exception:
        pass


def _signal(status_fd: int, token: bytes) -> None:
    """Best-effort token write to the status pipe; never raises."""

    try:
        os.write(status_fd, token)
    except OSError:
        pass


def _main() -> None:
    workspace = sys.argv[1]
    mem, cpu, nproc, fsize = (int(x) for x in sys.argv[2:6])
    status_fd = int(sys.argv[6])
    if sys.argv[7] != "--":
        _signal(status_fd, _SETUP_FAILED_TOKEN)
        sys.stderr.write(f"{_MARKER} malformed bootstrap args\n")
        os._exit(127)
    cmd = sys.argv[8:]

    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)

    def mount(src, target, fstype, flags, data=""):
        rc = libc.mount(
            (src or "").encode() or None,
            target.encode(),
            (fstype or "").encode() or None,
            flags,
            (data or "").encode() or None,
        )
        if rc != 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err), target)

    MS_RDONLY, MS_REMOUNT, MS_BIND, MS_REC, MS_PRIVATE = 1, 32, 4096, 16384, 1 << 18

    try:
        mount("", "/", "", MS_REC | MS_PRIVATE)
        mount(workspace, workspace, "", MS_BIND | MS_REC)  # workspace its own mount
        for sensitive in _SENSITIVE:
            if os.path.isdir(sensitive) and not workspace.startswith(sensitive):
                try:
                    mount("tmpfs", sensitive, "tmpfs", 0)
                except OSError:
                    pass
        mount("", "/", "", MS_REMOUNT | MS_BIND | MS_RDONLY)  # root read-only
        mount("", workspace, "", MS_REMOUNT | MS_BIND)  # keep workspace writable
    except OSError as exc:
        _signal(status_fd, _SETUP_FAILED_TOKEN)
        sys.stderr.write(f"{_MARKER} filesystem isolation failed: {exc}\n")
        os._exit(127)

    # Drop all capabilities now that the (privileged) mount setup is done:
    # clear the bounding set and the effective/permitted/inheritable sets, so the
    # candidate runs unprivileged even though it is root inside the user
    # namespace. This also lets RLIMIT_NPROC bind (CAP_SYS_RESOURCE would bypass
    # it) wherever the kernel honours the ucount.
    _drop_capabilities(libc)

    # No new privileges (PR_SET_NO_NEW_PRIVS = 38): defeats setuid escalation.
    libc.prctl(38, 1, 0, 0, 0)

    if cpu > 0:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    if mem > 0:
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
    if nproc > 0:
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
    if fsize > 0:
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))

    os.chdir(workspace)

    # Isolation is fully established and we are about to hand control to the
    # candidate. Emit a definite "candidate started" token on the status pipe —
    # a channel the candidate cannot forge or suppress: it is written before the
    # candidate's code runs and set close-on-exec, so the candidate never inherits
    # the fd. A missing token means setup failed before the candidate ran (a
    # harness fault); its presence means any later crash is the candidate's own.
    _signal(status_fd, _STARTED_TOKEN)
    try:
        os.set_inheritable(status_fd, False)
    except OSError:
        pass

    try:
        os.execv(cmd[0], cmd)
    except OSError as exc:
        # The candidate never ran: revoke the started token on the same
        # unforgeable channel (the fd is close-on-exec but still ours — the
        # exec failed), so this stays a harness fault, not a candidate crash.
        _signal(status_fd, _EXEC_FAILED_TOKEN)
        sys.stderr.write(f"{_MARKER} exec failed: {exc}\n")
        os._exit(127)


if __name__ == "__main__":
    _main()
