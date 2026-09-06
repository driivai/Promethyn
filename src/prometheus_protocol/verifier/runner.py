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

import math
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
from prometheus_protocol.core.validation import (
    require_non_negative_int,
    require_positive,
)
from prometheus_protocol.sandbox import Limits, Sandbox, build_sandbox
from prometheus_protocol.verifier import _value_codec

# Everything in this harness is candidate-controlled. It returns DATA, never
# verdicts. Expected answers and comparisons stay exclusively in the parent.
_RUNNER_TEMPLATE = """\
import contextlib, os, sys, traceback

# Isolated mode (-I) does not prepend the script directory to sys.path, so add
# it back explicitly to import the candidate as the ``solution`` module.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _value_codec import dumps, loads
ARGS = loads({args_wire!r})
ENTRY = {entry!r}


def main():
    try:
        import solution
    except BaseException:
        last = traceback.format_exc().strip().splitlines()[-1]
        return [("error", "import error: " + last) for _ in ARGS]
    fn = getattr(solution, ENTRY, None)
    if not callable(fn):
        return [("error", "entry point %r is not callable" % ENTRY) for _ in ARGS]
    results = []
    for args in ARGS:
        try:
            # Snapshot the return value before a later call mutates it; never
            # pickle or transfer an object with candidate-defined operators.
            got = loads(dumps(fn(*args)))
            results.append(("ok", got))
        except BaseException as exc:
            results.append(("error", type(exc).__name__ + ": " + str(exc)))
    return results


# Ordinary prints are diagnostics. A malicious process can replace this stream
# entirely, but can only submit values for the parent's independent comparison.
with contextlib.redirect_stdout(sys.stderr):
    response = dumps(main())
sys.stdout.write(response)
"""


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
        self.timeout_s = require_positive(timeout_s, name="timeout_s")
        self.memory_mb = require_non_negative_int(memory_mb, name="memory_mb")
        self.cpu_seconds = require_non_negative_int(cpu_seconds, name="cpu_seconds")
        self.max_processes = require_non_negative_int(
            max_processes, name="max_processes"
        )
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
        total = len(task.cases)
        if not total:
            return self._evidence(
                verdict=Verdict.ABSTAIN,
                total=0,
                passed_count=0,
                failures=("no cases to verify",),
                stdout="",
                stderr="",
                duration_s=0.0,
                timed_out=False,
            )
        try:
            args_wire = _value_codec.dumps([case.args for case in task.cases])
            # Validate and snapshot trusted expectations using the same data-only
            # contract. This wire is NEVER staged or sent into the sandbox.
            expected_results = _value_codec.loads(
                _value_codec.dumps([("ok", case.expected) for case in task.cases])
            )
            # Include response-envelope overhead in validation so a correct
            # answer is representable under the same depth/node/byte limits.
            expected = [result[1] for result in expected_results]
        except (ValueError, TypeError, OverflowError, RecursionError) as exc:
            return self._unavailable(
                reason=Unavailability.POLICY_REFUSAL,
                detail=f"unsupported verification cases: {exc}",
            )
        with tempfile.TemporaryDirectory(prefix="prom-verify-") as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "solution.py").write_text(code, encoding="utf-8")
            runner = _RUNNER_TEMPLATE.format(
                args_wire=args_wire, entry=task.entry_point
            )
            (tmp_path / "_runner.py").write_text(runner, encoding="utf-8")
            (tmp_path / "_value_codec.py").write_text(
                Path(_value_codec.__file__).read_text(encoding="utf-8"),
                encoding="utf-8",
            )

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

            if not sb.candidate_started:
                return self._unavailable(
                    reason=Unavailability.INFRA_FAULT,
                    detail=(
                        f"candidate was not confirmed to start (exit code "
                        f"{sb.exit_status}); response cannot be trusted"
                    ),
                )
            passed_count = 0
            failures = []
            if sb.exit_status != 0 or sb.memory_exceeded or sb.pids_exceeded:
                failures.append(_crash_detail(sb))
            elif sb.output_truncated:
                failures.append("candidate response exceeded output limit")
            else:
                try:
                    results = _value_codec.loads(sb.stdout)
                    if type(results) is not list or len(results) != total:
                        raise ValueError(
                            "response must contain exactly one result per case"
                        )
                    for result in results:
                        if (
                            type(result) is not tuple
                            or len(result) != 2
                            or type(result[0]) is not str
                            or result[0] not in ("ok", "error")
                            or (result[0] == "error" and type(result[1]) is not str)
                        ):
                            raise ValueError("invalid case response")
                    for i, ((status, got), answer) in enumerate(zip(results, expected)):
                        if status == "error":
                            failures.append(f"case {i} raised {_clip(got, 500)}")
                        elif _equal(got, answer):
                            passed_count += 1
                        else:
                            failures.append(
                                f"case {i}: expected {_clip(repr(answer), 200)}, "
                                f"got {_clip(repr(got), 200)}"
                            )
                except (ValueError, TypeError, OverflowError, RecursionError) as exc:
                    passed_count = 0
                    failures = [f"invalid candidate response: {_clip(str(exc), 500)}"]
            all_passed = passed_count == total and not failures
            return self._evidence(
                verdict=Verdict.PASS if all_passed else Verdict.FAIL,
                total=total,
                passed_count=passed_count,
                failures=tuple(failures),
                stdout="",  # Wire data is not diagnostic output; prints go to stderr.
                stderr=sb.stderr,
                duration_s=duration,
                timed_out=False,
            )


def _equal(a, b) -> bool:
    """Trusted comparison of decoded builtins, never candidate-owned objects."""
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, float) or isinstance(b, float):
        try:
            return math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-9)
        except (TypeError, OverflowError):
            return a == b
    return a == b


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
