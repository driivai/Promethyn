"""What a resource bound does to a VERDICT, measured on the real verifier.

WHY THIS EXISTS. The G17 ruling classified six resource-bound Config fields as
outcome-affecting and asked for proofs showing the Unavailable path:
"neutralize the bound, show the verifier fails to yield a verdict, show coverage
reports incomplete, show the refusal follows from that."

Measured 2026-09-14, driving `SubprocessVerifier` with real candidates: **that
path does not exist for these fields, and the reason is deliberate.** A
resource-limit kill is a FAIL — a verdict about the candidate — not an
Unavailable. `runner.py`'s own docstring says so precisely and is accurate:

  * FAIL — "the candidate crashing / being killed by a resource limit on its own
    code (a *confirmed* candidate start that produced no verdict)";
  * ABSTAIN — "the candidate started and then ran past the wall clock";
  * Unavailable — "a wall-clock timeout *before* the candidate started".

All four measurements below match that text exactly. So the concern the ruling
was guarding against — couldn't-verify collapsing into verified-clean at the
resource layer — is NOT what happens: there is no couldn't-verify state on this
path to collapse from.

WHAT IS TRUE, AND IS THE FINDING (OPEN-GAPS G21). Three of the six bounds accept
``0`` as "no bound" at `Config` load, and removing the bound turns a FAIL into a
PASS on byte-identical candidate code. The bound is therefore outcome-affecting
in the strongest sense — it does not merely remove a refusal path, it changes
the verdict — and an operator who sets one to zero silently widens what passes.

THE CONTROL THAT EXISTS, named so this is not read as worse than it is: every
one of these values is captured in the startup posture record
(`attestation/runtime.py`), so the budget a verdict was produced under is
recorded rather than implicit. That is what those fields are doing in the
attestation snapshot.

These tests are deliberately SLOW (real subprocesses, real limits). They are
the measurement; a faster version would be a different measurement.
"""

from __future__ import annotations

import pytest

from prometheus_protocol.core.config import Config
from prometheus_protocol.core.models import Case, Evidence, Task, Unavailable, Verdict
from prometheus_protocol.verifier.runner import SubprocessVerifier


def _task(entry_point: str, cases: list[Case]) -> Task:
    # Inlined rather than imported from tests/unit: a conformance module
    # reaching into another test package is a coupling the type gate refused
    # (`unit.test_verifier` is not on mypy_path), and it was right to.
    return Task(
        id=f"t/{entry_point}",
        entry_point=entry_point,
        prompt="x",
        split="train",
        cases=tuple(cases),
    )

#: A candidate that breaches one bound and is otherwise correct.
HUNGRY = "def probe(n):\n    b = bytearray(300 * 1024 * 1024)\n    return len(b) and n\n"
SPINNER = (
    "def probe(n):\n"
    "    import time\n"
    "    t = time.process_time()\n"
    "    while time.process_time() - t < 6:\n"
    "        pass\n"
    "    return n\n"
)
FORKER = (
    "def probe(n):\n"
    "    import os\n"
    "    for _ in range(40):\n"
    "        if os.fork() == 0:\n"
    "            os._exit(0)\n"
    "    return n\n"
)
SLEEPER = "def probe(n):\n    import time\n    time.sleep(20)\n    return n\n"

#: The three bounds that `Config` accepts a zero for, and the candidate that
#: breaches each. `verifier_timeout_s`, `request_timeout_s` and
#: `provider_max_response_bytes` are NOT here: they refuse zero at load, which
#: `test_the_three_fail_closed_bounds_refuse_a_zero` pins.
NEUTRALIZABLE = [
    pytest.param("memory_mb", 64, HUNGRY, id="memory_mb"),
    pytest.param("cpu_seconds", 2, SPINNER, id="cpu_seconds"),
    pytest.param("max_processes", 4, FORKER, id="max_processes"),
]


def _verify(
    code: str,
    *,
    timeout_s: float = 45,
    memory_mb: int = 0,
    cpu_seconds: int = 0,
    max_processes: int = 0,
) -> Evidence | Unavailable:
    verifier = SubprocessVerifier(
        timeout_s=timeout_s,
        memory_mb=memory_mb,
        cpu_seconds=cpu_seconds,
        max_processes=max_processes,
    )
    return verifier.verify(code=code, task=_task("probe", [Case(args=(1,), expected=1)]))


@pytest.mark.parametrize("bound,enforced,code", NEUTRALIZABLE)
def test_removing_a_resource_bound_turns_a_FAIL_into_a_PASS(bound, enforced, code):
    """The finding, as a passing test. Identical candidate, opposite verdicts."""

    with_bound = _verify(code, **{bound: enforced})
    without = _verify(code, **{bound: 0})

    assert isinstance(with_bound, Evidence), (
        f"{bound}: a breach produced {type(with_bound).__name__}, which would "
        "change G21's finding — re-measure before trusting this docstring"
    )
    assert isinstance(without, Evidence), type(without).__name__
    assert with_bound.verdict is Verdict.FAIL, (bound, with_bound.verdict)
    assert without.verdict is Verdict.PASS, (bound, without.verdict)


@pytest.mark.parametrize("bound,enforced,code", NEUTRALIZABLE)
def test_each_neutralizable_bound_accepts_a_zero_at_config_load(bound, enforced, code):
    """Zero is reachable through Config, which is what makes the above a
    deployment property rather than a laboratory one."""

    field = {"memory_mb": "verifier_memory_mb", "cpu_seconds": "verifier_cpu_seconds",
             "max_processes": "verifier_max_processes"}[bound]
    assert getattr(Config(**{field: 0}), field) == 0
    with pytest.raises(ValueError):
        Config(**{field: -1})


def test_the_three_fail_closed_bounds_refuse_a_zero():
    """The other half of the six. These cannot be neutralized at all, which is
    why they are not in the table above — the asymmetry is the point."""

    for field in ("verifier_timeout_s", "request_timeout_s", "provider_max_response_bytes"):
        with pytest.raises(ValueError):
            Config(**{field: 0})
        with pytest.raises(ValueError):
            Config(**{field: -1})


def test_a_confirmed_start_that_runs_past_the_wall_clock_is_ABSTAIN_not_FAIL():
    """The documented split, measured. `runner.py` says a confirmed start that
    hangs is "its own hang" and abstains; an ABSTAIN never feeds calibration."""

    out = _verify(SLEEPER, timeout_s=3)
    assert isinstance(out, Evidence), type(out).__name__
    assert out.verdict is Verdict.ABSTAIN, out.verdict


def test_the_positive_control_an_unbreached_bound_still_returns_a_real_verdict():
    """Without it, every assertion above is consistent with a verifier that
    fails everything under a bound and passes everything without one."""

    correct = _verify("def probe(n):\n    return n\n", memory_mb=256, cpu_seconds=30)
    wrong = _verify("def probe(n):\n    return n + 1\n", memory_mb=256, cpu_seconds=30)
    assert isinstance(correct, Evidence) and isinstance(wrong, Evidence)
    assert correct.verdict is Verdict.PASS
    assert wrong.verdict is Verdict.FAIL
