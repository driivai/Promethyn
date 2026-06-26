"""Subprocess verifier: run candidate code against hidden cases.

============================  SECURITY NOTICE  ============================
This is NOT a real sandbox. It runs candidate code in a child Python
process with a wall-clock timeout and POSIX resource limits (CPU time,
address space, file size). Those limits bound accidental runaway code; they
do NOT contain hostile code. A determined payload can still read the
filesystem, open sockets, or exhaust shared resources.

Before running UNTRUSTED code you MUST run this inside a real isolation
boundary (a locked-down container, microVM, or seccomp/namespace jail) with
no network and a read-only, throwaway filesystem. Treat the limits here as
defence in depth, never as the only line of defence.
=========================================================================
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from prometheus_protocol.core.interfaces import Verifier
from prometheus_protocol.core.models import Evidence, Task, Tier, Verdict

# The harness that runs inside the child process. It imports the candidate as
# a module, calls the entry point for each hidden case, and writes a JSON
# verdict to a result file (kept off stdout so candidate prints cannot corrupt
# it).
_RUNNER_TEMPLATE = '''\
import json, math, os, sys, traceback

# Isolated mode (-I) does not prepend the script directory to sys.path, so add
# it back explicitly to import the candidate as the ``solution`` module.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

CASES = {cases!r}
ENTRY = {entry!r}
RESULT_PATH = {result!r}


def _equal(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, float) or isinstance(b, float):
        try:
            return math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-9)
        except TypeError:
            return a == b
    return a == b


def _write(total, passed, failures):
    with open(RESULT_PATH, "w", encoding="utf-8") as fh:
        json.dump({{"total": total, "passed": passed, "failures": failures}}, fh)


def main():
    total = len(CASES)
    failures = []
    try:
        import solution
    except BaseException:
        last = traceback.format_exc().strip().splitlines()[-1]
        _write(total, 0, ["import error: " + last])
        return
    fn = getattr(solution, ENTRY, None)
    if not callable(fn):
        _write(total, 0, ["entry point %r is not callable" % ENTRY])
        return
    passed = 0
    for i, (args, expected) in enumerate(CASES):
        try:
            got = fn(*args)
        except BaseException as exc:
            failures.append("case %d raised %s: %s" % (i, type(exc).__name__, exc))
            continue
        if _equal(got, expected):
            passed += 1
        else:
            failures.append("case %d: expected %r, got %r" % (i, expected, got))
    _write(total, passed, failures)


main()
'''


def _resource_limits(cpu_seconds: int, memory_mb: int):
    """Build a ``preexec_fn`` that applies POSIX rlimits, or ``None``.

    Returns ``None`` on non-POSIX platforms (where ``preexec_fn`` and the
    ``resource`` module are unavailable).
    """

    if os.name != "posix":
        return None

    import resource

    def _apply() -> None:
        if cpu_seconds > 0:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        # Address-space caps can prevent the interpreter from starting if set
        # too low, so they are opt-in: a non-positive value disables them.
        if memory_mb > 0:
            nbytes = memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (nbytes, nbytes))
        # Cap accidental large writes to ten megabytes.
        resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))

    return _apply


class SubprocessVerifier(Verifier):
    """Default verifier. See the module-level security notice.

    Emits tier-tagged :class:`Evidence`: it is an authoritative hard check, so
    its verdict is PASS when every case passes, FAIL when the tests run and the
    candidate fails (a wrong answer or an exception raised inside a case), and
    ABSTAIN when the check could not run at all (timeout or harness crash). An
    ABSTAIN is a genuine "no opinion": it must not be counted as a pass and must
    not feed calibration.
    """

    #: Stable identifier this verifier reports in every Evidence it emits.
    VERIFIER_ID = "subprocess-tests"
    #: A sandboxed test run is an authoritative hard check.
    TIER = Tier.HARD

    def __init__(
        self,
        *,
        timeout_s: float = 5.0,
        memory_mb: int = 256,
        cpu_seconds: int = 5,
    ) -> None:
        self.timeout_s = timeout_s
        self.memory_mb = memory_mb
        self.cpu_seconds = cpu_seconds
        self.verifier_id = self.VERIFIER_ID
        self.tier = self.TIER

    def _evidence(
        self,
        *,
        verdict: Verdict,
        total: int,
        passed_count: int,
        failures: tuple[str, ...],
        stdout: str,
        stderr: str,
        duration_s: float,
        timed_out: bool,
    ) -> Evidence:
        detail = "; ".join(failures) or stderr or stdout
        return Evidence(
            passed=(verdict == Verdict.PASS),
            total=total,
            passed_count=passed_count,
            failures=failures,
            stdout=stdout,
            stderr=stderr,
            duration_s=duration_s,
            timed_out=timed_out,
            verifier_id=self.verifier_id,
            verdict=verdict,
            tier=self.tier,
            cost=duration_s,
            latency_ms=duration_s * 1000.0,
            detail=_clip(detail, 1000),
        )

    def verify(self, *, code: str, task: Task) -> Evidence:
        cases = [(case.args, case.expected) for case in task.cases]
        total = len(cases)
        with tempfile.TemporaryDirectory(prefix="prom-verify-") as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "solution.py").write_text(code, encoding="utf-8")
            result_path = tmp_path / "result.json"
            runner = _RUNNER_TEMPLATE.format(
                cases=cases, entry=task.entry_point, result=str(result_path)
            )
            (tmp_path / "_runner.py").write_text(runner, encoding="utf-8")

            started = time.monotonic()
            try:
                proc = subprocess.run(
                    [sys.executable, "-I", "_runner.py"],
                    cwd=tmp,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_s,
                    preexec_fn=_resource_limits(self.cpu_seconds, self.memory_mb),
                )
            except subprocess.TimeoutExpired as exc:
                duration = time.monotonic() - started
                # The check could not run to completion: no opinion (ABSTAIN).
                return self._evidence(
                    verdict=Verdict.ABSTAIN,
                    total=total,
                    passed_count=0,
                    failures=(f"timed out after {self.timeout_s}s",),
                    stdout=_clip(exc.stdout),
                    stderr=_clip(exc.stderr),
                    duration_s=duration,
                    timed_out=True,
                )

            duration = time.monotonic() - started
            result = _read_result(result_path)
            if result is None:
                # Harness crash / killed before writing a verdict: ABSTAIN.
                return self._evidence(
                    verdict=Verdict.ABSTAIN,
                    total=total,
                    passed_count=0,
                    failures=(
                        f"no verdict produced (exit code {proc.returncode}); "
                        "the child may have been killed by a resource limit",
                    ),
                    stdout=_clip(proc.stdout),
                    stderr=_clip(proc.stderr),
                    duration_s=duration,
                    timed_out=False,
                )

            passed_count = int(result.get("passed", 0))
            reported_total = int(result.get("total", total))
            failures = tuple(str(f) for f in result.get("failures", ()))
            all_passed = passed_count == reported_total and reported_total > 0
            return self._evidence(
                verdict=Verdict.PASS if all_passed else Verdict.FAIL,
                total=reported_total,
                passed_count=passed_count,
                failures=failures,
                stdout=_clip(proc.stdout),
                stderr=_clip(proc.stderr),
                duration_s=duration,
                timed_out=False,
            )


def _read_result(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _clip(text: str | None, limit: int = 4000) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... (truncated)"
