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
from prometheus_protocol.core.models import (
    Evidence,
    Task,
    Tier,
    Unavailability,
    Unavailable,
    Verdict,
)
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

    It is an authoritative hard check, and its outcome is one of two *types*, so
    "could not execute" can never be mistaken for a verdict:

    * :class:`Evidence` when the check ran. ``PASS`` when every case passes;
      ``FAIL`` when the candidate itself is at fault — a wrong answer, an
      exception raised inside a case, or the candidate crashing / being killed by
      a resource limit on its own code (a *confirmed* candidate start that
      produced no verdict); ``ABSTAIN`` only for a genuine "no opinion after
      running" — the task had no cases (nothing to check), or the candidate
      started and then ran past the wall clock (its own hang; unchanged
      semantics). An ABSTAIN never feeds calibration; a FAIL does.
    * :class:`Unavailable` when the check could **not** run — isolation did not
      start, the candidate was never confirmed to begin, a wall-clock timeout
      *before* the candidate started, or a deliberate policy refusal. This is not
      a verdict and carries no ``verdict``: an authoritative verifier that could
      not execute must never silently degrade into an abstention. The
      candidate-vs-harness distinction rests on the sandbox's definite
      ``candidate_started`` signal; on doubt the run is Unavailable, never a pass
      or a fail.
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

    def _unavailable(self, *, reason: Unavailability, detail: str) -> Unavailable:
        """A could-not-execute outcome — a non-verdict this HARD check emits when
        it could not run the candidate at all (see the class docstring)."""

        return Unavailable(
            verifier_id=self.verifier_id,
            tier=self.tier,
            reason=reason,
            detail=_clip(detail, 1000),
        )

    def verify(self, *, code: str, task: Task) -> Evidence | Unavailable:
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
                # Isolation could not start: we could NOT execute the candidate.
                # A non-verdict outcome (Unavailable), never an abstention — an
                # authoritative check that could not run must not degrade into
                # "no opinion". The reason is carried structurally by the adapter
                # (a deliberate policy refusal vs an infrastructure fault), never
                # parsed from the detail text.
                reason = (
                    Unavailability.POLICY_REFUSAL
                    if sb.policy_refusal
                    else Unavailability.INFRA_FAULT
                )
                return self._unavailable(
                    reason=reason, detail=f"sandbox did not start: {sb.detail}"
                )
            if sb.timed_out:
                if sb.candidate_started:
                    # The candidate started and then ran past the wall clock: its
                    # own hang. Unchanged semantics — a genuine "no opinion after
                    # running" (ABSTAIN), NOT could-not-execute. (Whether a
                    # confirmed-start timeout should be a FAIL is a separate
                    # question, deliberately out of EX-1's scope.)
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
                # Timed out before the candidate was ever confirmed to start: the
                # check could not run — a harness/infra fault, not the candidate's.
                return self._unavailable(
                    reason=Unavailability.INFRA_FAULT,
                    detail=(
                        f"timed out after {self.timeout_s}s before the candidate "
                        "was confirmed to start"
                    ),
                )

            result = _read_result(result_path)
            if result is None:
                # No verdict was written. Attribute the fault:
                #   * the candidate definitely started (isolation confirmed) → it
                #     crashed or was killed by a resource limit on its OWN code, a
                #     real FAIL that feeds calibration; or
                #   * the candidate was never confirmed to start → a harness/infra
                #     fault we cannot pin on the candidate → ABSTAIN (no sample).
                # Conservative on doubt: only a confirmed candidate start FAILs.
                if sb.candidate_started:
                    return self._evidence(
                        verdict=Verdict.FAIL,
                        total=total,
                        passed_count=0,
                        failures=(_crash_detail(sb),),
                        stdout=sb.stdout,
                        stderr=sb.stderr,
                        duration_s=duration,
                        timed_out=False,
                    )
                return self._unavailable(
                    reason=Unavailability.INFRA_FAULT,
                    detail=(
                        f"no verdict produced (exit code {sb.exit_status}) and the "
                        "candidate was not confirmed to start; a harness fault"
                    ),
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


def _crash_detail(sb) -> str:
    """A specific reason for a candidate that crashed without a verdict."""

    if sb.memory_exceeded:
        reason = "killed by the memory limit"
    elif sb.pids_exceeded:
        reason = "hit the process limit"
    else:
        reason = "crashed or was killed by a resource limit"
    return (
        f"candidate {reason} without producing a verdict (exit code {sb.exit_status})"
    )


def _clip(text: str | None, limit: int = 4000) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... (truncated)"
