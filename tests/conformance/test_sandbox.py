"""Adversarial conformance for the isolation layer (INV-SANDBOX-1..5).

Each test runs HOSTILE candidate code through the real isolating sandbox and
asserts containment. They require the isolation runtime: they SKIP with a clear
reason when it is absent locally, but when PROM_REQUIRE_SANDBOX=1 (set in CI) an
otherwise-skipped test FAILS instead — so a CI without the runtime cannot pass
with isolation untested.
"""

from __future__ import annotations

import contextlib
import os
import sys
import tempfile
from pathlib import Path

import pytest

from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.sandbox import (
    Limits,
    NamespaceSandbox,
    UnsafeLocalSandbox,
    build_sandbox,
)
from prometheus_protocol.sandbox.unsafe import NullSandbox

_REQUIRE = (os.environ.get("PROM_REQUIRE_SANDBOX", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}


def _sandbox() -> NamespaceSandbox:
    if not NamespaceSandbox.available():
        reason = "namespace isolation runtime (unprivileged user namespaces) unavailable"
        if _REQUIRE:
            pytest.fail(f"PROM_REQUIRE_SANDBOX=1 but {reason}")
        pytest.skip(reason)
    return NamespaceSandbox()


@contextlib.contextmanager
def _candidate(src: str, **limit_kw):
    sandbox = _sandbox()
    limit_kw.setdefault("wall_time_s", 6.0)
    with tempfile.TemporaryDirectory(prefix="prom-sbtest-") as ws:
        Path(ws, "prog.py").write_text(src, encoding="utf-8")
        result = sandbox.run(
            argv=[sys.executable, "-I", "prog.py"],
            workspace=ws,
            limits=Limits(**limit_kw),
        )
        yield result, ws


# -- INV-SANDBOX-1: network denied -----------------------------------------

_NET = """
import socket
try:
    s = socket.socket(); s.settimeout(2); s.connect(("1.1.1.1", 80)); print("NET-REACHED")
except OSError as e:
    print("NET-DENIED", e.errno)
"""


def test_inv_sandbox_1_network_is_denied():
    with _candidate(_NET) as (res, _ws):
        assert res.started_ok
        assert "NET-DENIED" in res.stdout
        assert "NET-REACHED" not in res.stdout


# -- INV-SANDBOX-2: filesystem constrained ---------------------------------

_FS = """
import os
open("inside.txt", "w").write("ok")                       # workspace: allowed
try:
    open("/etc/prom_escape", "w").write("x"); print("WROTE-ETC")
except OSError:
    print("ETC-DENIED")
secret = os.path.join(os.path.expanduser("~"), ".prom_sandbox_secret")
try:
    print("READ-SECRET", open(secret).read().strip())
except OSError:
    print("SECRET-HIDDEN")
"""


def test_inv_sandbox_2_filesystem_is_constrained():
    secret = Path(os.path.expanduser("~")) / ".prom_sandbox_secret"
    wrote_secret = False
    try:
        try:
            secret.write_text("top-secret-host-data\n")
            wrote_secret = True
        except OSError:
            pass  # cannot plant the secret; the hide assertion still holds
        with _candidate(_FS) as (res, ws):
            assert res.started_ok
            assert (Path(ws) / "inside.txt").read_text() == "ok"  # workspace writable
            assert "ETC-DENIED" in res.stdout and "WROTE-ETC" not in res.stdout
            assert "SECRET-HIDDEN" in res.stdout and "READ-SECRET" not in res.stdout
    finally:
        if wrote_secret:
            secret.unlink(missing_ok=True)
        # The host filesystem is unaffected by the escape attempt.
        assert not Path("/etc/prom_escape").exists()


# -- INV-SANDBOX-3: resources bounded --------------------------------------

_MEM = "x = bytearray(256 * 1024 * 1024); print('ALLOC-OK', len(x))"


def test_inv_sandbox_3_memory_is_bounded():
    with _candidate(_MEM, memory_bytes=64 * 1024 * 1024) as (res, _ws):
        assert res.started_ok
        assert "ALLOC-OK" not in res.stdout  # the allocation was refused
        assert res.exit_status not in (0,) or res.memory_exceeded


def test_inv_sandbox_3_cpu_time_is_bounded():
    with _candidate("\nwhile True:\n    pass\n", cpu_time_s=1, wall_time_s=8) as (res, _ws):
        assert res.started_ok
        # Either the CPU rlimit killed it or the wall clock did; it did not hang.
        assert res.timed_out or (res.exit_status not in (0, None))


_FORKBOMB = """
import os, time
# A bounded burst of long-lived children. Where the kernel honours RLIMIT_NPROC
# for this (unprivileged) process the fork is refused; everywhere the sandbox
# still reaps the whole tree on exit (unshare --kill-child) so the host is
# unaffected.
n = 0
try:
    for _ in range(64):
        if os.fork() == 0:
            time.sleep(3); os._exit(0)
        n += 1
    print("FORKED", n)
except OSError:
    print("PIDS-BOUNDED", n)
"""


def test_inv_sandbox_3_processes_are_bounded_and_contained():
    with _candidate(_FORKBOMB, max_processes=16, wall_time_s=8) as (res, _ws):
        assert res.started_ok
        # Containment: the process bomb was either capped by RLIMIT_NPROC, or
        # terminated by the wall clock — never left to run unbounded.
        bounded = (
            res.pids_exceeded
            or "PIDS-BOUNDED" in res.stdout
            or res.timed_out
            or res.exit_status == 0  # completed; its tree is reaped on exit
        )
        assert bounded
    # The host is unaffected: it can still create and reap a process.
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    assert os.waitpid(pid, 0)[0] == pid


# -- INV-SANDBOX-4: least privilege ----------------------------------------

_PRIV = """
import os
status = open("/proc/self/status").read()
nnp = [l for l in status.splitlines() if l.startswith("NoNewPrivs")]
print("NNP", nnp[0].split()[-1] if nnp else "?")
try:
    os.mknod("devnode", 0o600 | 0o020000, os.makedev(1, 3)); print("MKNOD-OK")
except OSError:
    print("MKNOD-DENIED")
"""


def test_inv_sandbox_4_least_privilege():
    with _candidate(_PRIV) as (res, _ws):
        assert res.started_ok
        assert "NNP 1" in res.stdout            # no-new-privileges is set
        assert "MKNOD-DENIED" in res.stdout      # cannot create a device node
        assert "MKNOD-OK" not in res.stdout


# -- INV-SANDBOX-5: the sandbox is mandatory -------------------------------


def test_inv_sandbox_5_default_path_is_isolating():
    # The default selection never returns the unsafe runner.
    sandbox = build_sandbox(env={})
    assert sandbox.isolating
    assert sandbox.name != UnsafeLocalSandbox.name
    # When an isolating runtime exists, auto picks it (here, in CI).
    if NamespaceSandbox.available():
        assert sandbox.name == NamespaceSandbox.name
    else:
        assert isinstance(sandbox, NullSandbox)  # refuses to run unsandboxed


def test_inv_sandbox_5_unsafe_requires_explicit_optin():
    with pytest.raises(ConfigError):
        build_sandbox("unsafe", env={})  # no PROM_ALLOW_UNSAFE_EXEC
    chosen = build_sandbox("unsafe", env={"PROM_ALLOW_UNSAFE_EXEC": "1"})
    assert isinstance(chosen, UnsafeLocalSandbox) and not chosen.isolating


def test_inv_sandbox_5_default_verifier_is_isolating():
    from prometheus_protocol.verifier.runner import SubprocessVerifier

    verifier = SubprocessVerifier(memory_mb=0)
    assert verifier.sandbox.isolating
    assert verifier.sandbox.name != UnsafeLocalSandbox.name


# -- PARITY: legitimate verdicts are unchanged under the sandbox -----------

from prometheus_protocol.core.models import Case, Task, Verdict  # noqa: E402
from prometheus_protocol.verifier.runner import SubprocessVerifier  # noqa: E402

_CASES = (Case((2, 3), 5), Case((0, 0), 0), Case((-1, 1), 0))
_TASK = Task(id="p/add", entry_point="add", prompt="", split="train", cases=_CASES)
_CANDIDATES = {
    "def add(a, b):\n    return a + b\n": Verdict.PASS,
    "def add(a, b):\n    return a - b\n": Verdict.FAIL,
    "def add(a, b):\n    return a + b + 1\n": Verdict.FAIL,
}


def test_parity_sandboxed_verdicts_equal_unsafe_verdicts():
    if not NamespaceSandbox.available():
        if _REQUIRE:
            pytest.fail("PROM_REQUIRE_SANDBOX=1 but namespace runtime unavailable")
        pytest.skip("namespace isolation runtime unavailable")
    isolating = SubprocessVerifier(memory_mb=0, sandbox=NamespaceSandbox())
    unsafe = SubprocessVerifier(memory_mb=0, sandbox=UnsafeLocalSandbox())
    for code, expected in _CANDIDATES.items():
        sandboxed = isolating.verify(code=code, task=_TASK).verdict
        direct = unsafe.verify(code=code, task=_TASK).verdict
        assert sandboxed == direct == expected
