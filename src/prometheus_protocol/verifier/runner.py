"""Subprocess verifier: run candidate code against hidden cases.

============================  SECURITY NOTICE  ============================
Candidate code is executed through an isolating :class:`Sandbox` (the
configured adapter; default = an isolating one). The sandbox denies network,
constrains the filesystem to a writable workspace over a read-only root, and
bounds resources; see ``docs/sandbox.md`` and the INV-SANDBOX conformance
tests. The historical no-isolation path remains available only as the
explicitly opt-in ``UnsafeLocalSandbox`` (``PROM_ALLOW_UNSAFE_EXEC=1``); it is
for trusted/mock dev examples, never for untrusted code.
=========================================================================
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

from prometheus_protocol.core.interfaces import Verifier
from prometheus_protocol.core.models import Evidence, Task, Tier, Verdict
from prometheus_protocol.sandbox import Limits, Sandbox, build_sandbox

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


class SubprocessVerifier(Verifier):
    """Default verifier. See the module-level security notice.

    Emits tier-tagged :class:`Evidence`: it is an authoritative hard check, so
    its verdict is PASS when every case passes, FAIL when the tests run and the
    candidate fails (a wrong answer or an exception raised inside a case), and
    ABSTAIN when there was nothing to decide — the check could not run at all
    (timeout or harness crash) or the task had no cases to verify. An ABSTAIN is
    a genuine "no opinion": it must not be counted as a pass and must not feed
    calibration.
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
        max_processes: int = 64,
        sandbox: Sandbox | None = None,
    ) -> None:
        self.timeout_s = timeout_s
        self.memory_mb = memory_mb
        self.cpu_seconds = cpu_seconds
        self.max_processes = max_processes
        # The isolation boundary candidate code runs through. Defaults to the
        # configured/auto adapter (an isolating one); never the unsafe runner
        # unless explicitly opted in via PROM_ALLOW_UNSAFE_EXEC.
        self.sandbox = sandbox if sandbox is not None else build_sandbox()
        self.verifier_id = self.VERIFIER_ID
        self.tier = self.TIER

    def _limits(self) -> Limits:
        return Limits(
            wall_time_s=self.timeout_s,
            cpu_time_s=self.cpu_seconds,
            memory_bytes=self.memory_mb * 1024 * 1024 if self.memory_mb > 0 else 0,
            max_processes=self.max_processes,
        )

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
            sb = self.sandbox.run(
                argv=[sys.executable, "-I", "_runner.py"],
                workspace=tmp,
                limits=self._limits(),
            )
            duration = time.monotonic() - started

            if not sb.started_ok:
                # Isolation could not start: we could not verify. ABSTAIN — no
                # opinion, no calibration sample, never a pass or a fail.
                return self._evidence(
                    verdict=Verdict.ABSTAIN,
                    total=total,
                    passed_count=0,
                    failures=(f"sandbox did not start: {sb.detail}",),
                    stdout=sb.stdout,
                    stderr=sb.stderr,
                    duration_s=duration,
                    timed_out=False,
                )
            if sb.timed_out:
                # The check could not run to completion: no opinion (ABSTAIN).
                return self._evidence(
                    verdict=Verdict.ABSTAIN,
                    total=total,
                    passed_count=0,
                    failures=(f"timed out after {self.timeout_s}s",),
                    stdout=sb.stdout,
                    stderr=sb.stderr,
                    duration_s=duration,
                    timed_out=True,
                )

            result = _read_result(result_path)
            if result is None:
                # Harness crash / killed before writing a verdict: ABSTAIN.
                return self._evidence(
                    verdict=Verdict.ABSTAIN,
                    total=total,
                    passed_count=0,
                    failures=(
                        f"no verdict produced (exit code {sb.exit_status}); "
                        "the child may have been killed by a resource limit",
                    ),
                    stdout=sb.stdout,
                    stderr=sb.stderr,
                    duration_s=duration,
                    timed_out=False,
                )

            passed_count = int(result.get("passed", 0))
            reported_total = int(result.get("total", total))
            failures = tuple(str(f) for f in result.get("failures", ()))
            if reported_total == 0:
                # There were no cases to run, so the check has no opinion: this
                # is ABSTAIN, not a confident failure. (An ABSTAIN is not a pass
                # and never feeds calibration.) For any non-empty case set the
                # verdict below is unchanged.
                return self._evidence(
                    verdict=Verdict.ABSTAIN,
                    total=reported_total,
                    passed_count=passed_count,
                    failures=failures or ("no cases to verify",),
                    stdout=sb.stdout,
                    stderr=sb.stderr,
                    duration_s=duration,
                    timed_out=False,
                )
            all_passed = passed_count == reported_total
            return self._evidence(
                verdict=Verdict.PASS if all_passed else Verdict.FAIL,
                total=reported_total,
                passed_count=passed_count,
                failures=failures,
                stdout=sb.stdout,
                stderr=sb.stderr,
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
