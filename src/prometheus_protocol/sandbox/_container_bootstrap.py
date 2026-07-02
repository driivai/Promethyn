"""Runs INSIDE the container, then execs the candidate command.

Invoked (mounted read-only into the container) as::

    python /.prom-start.py -- argv...

Standard library only. It carries the unforgeable candidate-start signal
across the container boundary, mirroring the namespace adapter's close-on-exec
status pipe (see ``_start_signal.py``): no fd crosses a ``docker run``
boundary, so the host sends a fresh random nonce as the first line of stdin.
This bootstrap consumes exactly that line, byte by byte — the candidate
inherits stdin positioned right after it, and the nonce is stored nowhere the
candidate can read: not argv, not the environment, not a file. At the point
isolation is established and the candidate is about to run it emits the
nonce-keyed started line on stderr, then execs the candidate over itself. If
the exec fails it emits the nonce-keyed revocation line and exits 127, so a
start that never happened is never counted. A candidate may print anything,
including these token names — without the nonce it cannot forge the signal,
and it cannot unsay a line written before its code ran.
"""

import os
import sys

# Kept in sync with ``_start_signal.py`` (this file runs standalone inside the
# container image and cannot import the package). A conformance test asserts
# the copies match.
_STARTED = "prom-candidate-started"
_EXEC_FAILED = "prom-candidate-exec-failed"
#: Upper bound on the nonce line; anything longer is not a nonce we sent.
_MAX_NONCE = 128


def _read_nonce():
    """The first stdin line, read byte by byte so nothing past it is consumed."""

    chunks = []
    while len(chunks) < _MAX_NONCE:
        byte = os.read(0, 1)
        if not byte or byte == b"\n":
            break
        chunks.append(byte)
    return b"".join(chunks).decode("ascii", "replace").strip()


def _main():
    if len(sys.argv) < 3 or sys.argv[1] != "--":
        os.write(2, b"container bootstrap: malformed args\n")
        os._exit(127)
    cmd = sys.argv[2:]
    nonce = _read_nonce()
    if not nonce:
        # No nonce reached us, so no signal can be keyed. Run nothing: the host
        # sees no started line and treats the run as a harness fault (ABSTAIN),
        # never as the candidate's.
        os.write(2, b"container bootstrap: no start nonce on stdin\n")
        os._exit(127)
    os.write(2, ("%s:%s\n" % (_STARTED, nonce)).encode("ascii"))
    try:
        os.execvp(cmd[0], cmd)
    except OSError as exc:
        os.write(2, ("%s:%s\n" % (_EXEC_FAILED, nonce)).encode("ascii"))
        os.write(2, ("container bootstrap: exec failed: %s\n" % (exc,)).encode("utf-8"))
        os._exit(127)


if __name__ == "__main__":
    _main()
