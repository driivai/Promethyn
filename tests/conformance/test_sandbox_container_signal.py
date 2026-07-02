"""Conformance: the unforgeable candidate-start signal on the container adapter.

Signal parity with the namespace adapter: a container-run candidate crash (with
isolation confirmed started) classifies FAIL; container harness faults stay
ABSTAIN. No fd crosses a ``docker run`` boundary, so the transport differs — a
fresh per-run nonce goes to the in-container bootstrap on stdin (consumed
before the candidate runs, stored nowhere the candidate can read) and the
bootstrap emits nonce-keyed lines on stderr — but the property is the same:
the candidate can neither forge nor suppress the signal.

Layered honestly by what each layer needs:

* the pure stream protocol needs nothing (always runs);
* the bootstrap itself is a plain script — exercised end-to-end as a host
  subprocess (always runs);
* the adapter's full wiring is exercised against a stub runtime that executes
  the container command locally (always runs; it proves the adapter/transport
  logic, NOT container isolation);
* real-container-isolation runs are OPT-IN via PROM_REQUIRE_CONTAINER=1: they
  SKIP by default even where a daemon is present, and only under that flag do
  they run (and then FAIL rather than skip if the runtime/image is unusable).
  This is deliberately stricter than a presence probe: no prior test spawned a
  real container, and CI (which sets PROM_REQUIRE_SANDBOX=1 on runners that DO
  have docker) must not start pulling images and running real containers as a
  side effect. A deployment that wants the container path proven end-to-end
  sets PROM_REQUIRE_CONTAINER=1 explicitly.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

from prometheus_protocol.core.models import Case, Task, Verdict
from prometheus_protocol.sandbox import Limits
from prometheus_protocol.sandbox import _container_bootstrap
from prometheus_protocol.sandbox._start_signal import (
    EXEC_FAILED_TOKEN,
    SETUP_FAILED_TOKEN,
    STARTED_TOKEN,
    exec_failed_line,
    interpret_stream,
    new_nonce,
    started_line,
)
from prometheus_protocol.sandbox.container import ContainerSandbox
from prometheus_protocol.verifier.runner import SubprocessVerifier

_REQUIRE_CONTAINER = (
    os.environ.get("PROM_REQUIRE_CONTAINER", "") or ""
).strip().lower() in {"1", "true", "yes", "on"}
_BOOTSTRAP = Path(_container_bootstrap.__file__)
_PINNED_FAKE_IMAGE = "prom-fake@sha256:" + "0" * 64
_TASK = Task(id="t/f", entry_point="f", prompt="", split="train", cases=(Case((1,), 1),))
_CRASH = "def f(n):\n    return n\nimport os\nos.abort()\n"


# -- the pure stream protocol -------------------------------------------------


def test_stream_signal_requires_the_nonce():
    nonce = new_nonce()
    started, _ = interpret_stream(f"{started_line(nonce)}\n", nonce)
    assert started
    # The token name without the right nonce forges nothing.
    forged, _ = interpret_stream(
        f"{STARTED_TOKEN.decode()}:0000\n{STARTED_TOKEN.decode()}\n", nonce
    )
    assert not forged


def test_stream_signal_revocation_wins_and_cannot_be_forged():
    nonce = new_nonce()
    genuine = f"{started_line(nonce)}\n{exec_failed_line(nonce)}\n"
    assert interpret_stream(genuine, nonce)[0] is False
    # A candidate printing an un-keyed revocation cannot turn its own crash
    # into a harness fault.
    hostile = f"{started_line(nonce)}\n{EXEC_FAILED_TOKEN.decode()}\nboom\n"
    started, cleaned = interpret_stream(hostile, nonce)
    assert started
    assert cleaned == f"{EXEC_FAILED_TOKEN.decode()}\nboom\n"  # its output survives


def test_stream_signal_strips_only_the_harness_lines():
    nonce = new_nonce()
    text = f"warning: something\n{started_line(nonce)}\ncandidate noise\n"
    started, cleaned = interpret_stream(text, nonce)
    assert started and cleaned == "warning: something\ncandidate noise\n"
    assert interpret_stream(None, nonce) == (False, "")


def test_bootstrap_token_literals_stay_in_sync_with_the_signal_module():
    assert _container_bootstrap._STARTED.encode("ascii") == STARTED_TOKEN
    assert _container_bootstrap._EXEC_FAILED.encode("ascii") == EXEC_FAILED_TOKEN
    from prometheus_protocol.sandbox import _bootstrap as namespace_bootstrap

    assert namespace_bootstrap._STARTED_TOKEN == STARTED_TOKEN
    assert namespace_bootstrap._EXEC_FAILED_TOKEN == EXEC_FAILED_TOKEN
    assert namespace_bootstrap._SETUP_FAILED_TOKEN == SETUP_FAILED_TOKEN


# -- the bootstrap, end to end as a plain subprocess --------------------------


def _run_bootstrap(cmd: list[str], stdin: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_BOOTSTRAP), "--", *cmd],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_bootstrap_emits_the_keyed_started_line_and_preserves_candidate_stdin():
    nonce = new_nonce()
    proc = _run_bootstrap(
        [sys.executable, "-c", "import sys; print('IN:' + sys.stdin.read().strip())"],
        stdin=f"{nonce}\npayload",
    )
    assert proc.returncode == 0
    assert started_line(nonce) in proc.stderr  # the keyed signal
    assert "IN:payload" in proc.stdout  # stdin past the nonce reaches the candidate
    assert nonce not in proc.stdout  # ...and the nonce itself does not


def test_bootstrap_revokes_the_start_when_exec_fails():
    nonce = new_nonce()
    proc = _run_bootstrap(["/nonexistent/bin/candidate"], stdin=f"{nonce}\n")
    assert proc.returncode == 127
    started, _ = interpret_stream(proc.stderr, nonce)
    assert not started  # revoked: the candidate never ran
    assert exec_failed_line(nonce) in proc.stderr


def test_bootstrap_runs_nothing_without_a_nonce():
    proc = _run_bootstrap([sys.executable, "-c", "print('RAN')"], stdin="")
    assert proc.returncode == 127 and "RAN" not in proc.stdout


def test_candidate_cannot_read_the_nonce_from_its_environment():
    nonce = new_nonce()
    probe = (
        "import os, sys\n"
        "leaks = [v for v in list(os.environ.values()) + sys.argv if %r in v]\n"
        "print('LEAKED' if leaks else 'NO-LEAK')\n" % nonce
    )
    proc = _run_bootstrap([sys.executable, "-c", probe], stdin=f"{nonce}\n")
    assert "NO-LEAK" in proc.stdout and "LEAKED" not in proc.stdout


# -- the adapter's wiring, against a stub runtime ------------------------------
#
# The stub parses the exact command the adapter builds and executes the
# container's command locally (volumes mapped to host paths, "python" mapped to
# this interpreter). It proves the adapter's transport wiring — nonce over
# stdin, bootstrap wrapping, stderr interpretation, fail-closed start
# reporting — NOT container isolation, which only the gated real-runtime tests
# below (and the runtime itself) provide.

_STUB = textwrap.dedent(
    """\
    #!%(python)s
    import os, sys
    args = sys.argv[1:]
    assert args and args[0] == "run", args
    args = args[1:]
    BARE = {"--rm", "--interactive", "--read-only"}
    VALUED = {"--network", "--tmpfs", "--volume", "--workdir", "--memory",
              "--memory-swap", "--cpus", "--pids-limit", "--cap-drop",
              "--security-opt", "--user"}
    volumes, workdir, i = {}, None, 0
    while i < len(args):
        if args[i] in BARE:
            i += 1
        elif args[i] in VALUED:
            if args[i] == "--volume":
                host, cont = args[i + 1].split(":")[:2]
                volumes[cont] = host
            if args[i] == "--workdir":
                workdir = args[i + 1]
            i += 2
        else:
            break
    image, inner = args[i], args[i + 1:]
    resolved = [
        sys.executable if tok == "python" else volumes.get(tok, tok)
        for tok in inner
    ]
    os.chdir(volumes[workdir])
    os.execv(resolved[0], resolved)
    """
)


@pytest.fixture
def stub_runtime(tmp_path):
    stub = tmp_path / "stub-container-runtime"
    stub.write_text(_STUB % {"python": sys.executable}, encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    return str(stub)


def _stub_sandbox(stub_runtime: str) -> ContainerSandbox:
    return ContainerSandbox(runtime=stub_runtime, image=_PINNED_FAKE_IMAGE)


def _run_code(sandbox: ContainerSandbox, code: str, **limit_kw):
    limit_kw.setdefault("wall_time_s", 30)
    limit_kw.setdefault("memory_bytes", 0)
    with tempfile.TemporaryDirectory(prefix="prom-ctr-") as ws:
        Path(ws, "prog.py").write_text(code, encoding="utf-8")
        return sandbox.run(
            argv=[sys.executable, "-I", "prog.py"],
            workspace=ws,
            limits=Limits(**limit_kw),
        )


def test_adapter_reports_candidate_started_for_a_normal_run(stub_runtime):
    res = _run_code(_stub_sandbox(stub_runtime), "print('ok')")
    assert res.started_ok and res.candidate_started and res.exit_status == 0
    assert "ok" in res.stdout
    assert "prom-candidate-started" not in res.stderr  # transport lines stripped


def test_adapter_reports_candidate_started_for_a_crashing_candidate(stub_runtime):
    res = _run_code(_stub_sandbox(stub_runtime), "import os\nos.abort()\n")
    assert res.started_ok and res.candidate_started
    assert res.exit_status not in (0, None)


def test_adapter_marker_forgery_is_still_a_candidate_start(stub_runtime):
    # The candidate prints the namespace bootstrap's old marker AND un-keyed
    # token names, then exits 127: without the nonce it forges nothing.
    forge = (
        "import sys, os\n"
        "sys.stderr.write('sandbox-bootstrap: filesystem isolation failed: x\\n')\n"
        "sys.stderr.write('prom-candidate-exec-failed\\n')\n"
        "os._exit(127)\n"
    )
    res = _run_code(_stub_sandbox(stub_runtime), forge)
    assert res.started_ok and res.candidate_started and res.exit_status == 127


def test_container_candidate_crash_classifies_fail_via_the_verifier(stub_runtime):
    evidence = SubprocessVerifier(
        memory_mb=0, timeout_s=30, sandbox=_stub_sandbox(stub_runtime)
    ).verify(code=_CRASH, task=_TASK)
    assert evidence.verdict == Verdict.FAIL, evidence.detail


def test_container_parity_pass_and_clean_fail_are_unchanged(stub_runtime):
    verifier = SubprocessVerifier(
        memory_mb=0, timeout_s=30, sandbox=_stub_sandbox(stub_runtime)
    )
    ok = verifier.verify(code="def f(n):\n    return n\n", task=_TASK)
    assert ok.verdict == Verdict.PASS, ok.detail
    wrong = verifier.verify(code="def f(n):\n    return n + 1\n", task=_TASK)
    assert wrong.verdict == Verdict.FAIL


def test_adapter_timeout_reads_the_signal_from_bytes_stderr(stub_runtime):
    # A candidate that starts then hangs: the run times out. TimeoutExpired
    # carries bytes stderr even under text=True, so this pins that the adapter
    # decodes it and still reads the (already-emitted) nonce-keyed start line.
    res = _run_code(
        _stub_sandbox(stub_runtime),
        "import time\nprint('BEFORE', flush=True)\ntime.sleep(30)\n",
        wall_time_s=1,
    )
    assert res.timed_out and res.started_ok
    assert res.candidate_started  # the start line was seen despite the timeout
    assert "prom-candidate-started" not in (res.stderr or "")  # transport stripped


def test_container_missing_start_confirmation_is_a_harness_fault(tmp_path):
    # A "runtime" whose container never runs the bootstrap: no keyed line ever
    # appears, so the adapter fail-closes the start report (-> ABSTAIN upstream).
    stub = tmp_path / "stub-noop-runtime"
    stub.write_text(f"#!{sys.executable}\nimport sys\nsys.exit(0)\n", encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    res = _run_code(ContainerSandbox(runtime=str(stub), image=_PINNED_FAKE_IMAGE), "print('x')")
    assert not res.started_ok and not res.candidate_started
    assert "did not confirm" in res.detail


# -- real container runtime (gated) -------------------------------------------


def _real_container() -> ContainerSandbox:
    # Opt-in ONLY. Skip by default even if a daemon is present, so CI (which does
    # not set this flag) never starts pulling images and running real containers.
    if not _REQUIRE_CONTAINER:
        pytest.skip("real-container run is opt-in; set PROM_REQUIRE_CONTAINER=1")
    if not ContainerSandbox.available():
        pytest.fail(
            "PROM_REQUIRE_CONTAINER=1 but no functioning container runtime "
            "(docker/podman daemon) is available"
        )
    sandbox = ContainerSandbox()
    pull = subprocess.run(
        [sandbox.runtime, "pull", sandbox.image], capture_output=True, timeout=600
    )
    if pull.returncode != 0:
        pytest.fail(
            f"PROM_REQUIRE_CONTAINER=1 but could not pull image {sandbox.image!r}"
        )
    return sandbox


def test_real_container_run_confirms_candidate_start():
    res = _run_code(_real_container(), "print('ok')", wall_time_s=60)
    assert res.started_ok and res.candidate_started and res.exit_status == 0


def test_real_container_candidate_crash_classifies_fail():
    evidence = SubprocessVerifier(
        memory_mb=0, timeout_s=60, sandbox=_real_container()
    ).verify(code=_CRASH, task=_TASK)
    assert evidence.verdict == Verdict.FAIL, evidence.detail
