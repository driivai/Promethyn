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

WHAT IS TRUE, AND IS THE FINDING (OPEN-GAPS G21). Three of the six bounds could
be neutralized, and removing the bound turns a FAIL into a PASS on byte-identical
candidate code. The bound is therefore outcome-affecting in the strongest sense:
it does not merely remove a refusal path, it changes the verdict.

THE REMEDY, ruled and landed in the same change as this note. Unbounded is kept
— `Limits` documents that a disabled address-space cap avoids refusing
legitimate workloads, and this repository relies on that — but it must now be
NAMED: `Config(verifier_memory_mb=UNBOUNDED)`. A bare ``0`` is refused at load
with a typed reason, which is how the other three bounds already behaved. Three
fields in one struct failing closed while three did not was the inconsistency;
this removes it without pretending the unbounded posture is never wanted.

THIS FILE'S PROOF SHAPE IS NOT THE ONE THE OTHER 20 FIELDS USE, and the
difference is deliberate — see `test_security_posture.py`. There, neutralizing a
field makes a named test RED. Here, neutralizing a bound produces a DIFFERENT
VERDICT, which no refusal test can catch because nothing refuses. A verdict flip
is the stronger observation and the weaker guarantee, and conflating the two
would let this file be read as evidence of a refusal path that does not exist.

THE CONTROL THAT EXISTS, named so this is not read as worse than it is: every
one of these values is captured in the startup posture record
(`attestation/runtime.py`) as the operator SPELLED it, so a run under no memory
cap is distinguishable in the record from one under a cap of zero. That is what
those fields are doing in the attestation snapshot.

These tests are deliberately SLOW (real subprocesses, real limits). They are
the measurement; a faster version would be a different measurement.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from prometheus_protocol.core.config import UNBOUNDED, Config, resolve_bound
from prometheus_protocol.core.errors import ConfigError
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

#: `SubprocessVerifier`'s keyword -> the `Config` field that supplies it.
_CONFIG_FIELD = {
    "memory_mb": "verifier_memory_mb",
    "cpu_seconds": "verifier_cpu_seconds",
    "max_processes": "verifier_max_processes",
}


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
def test_a_bare_zero_is_refused_at_config_load(bound, enforced, code):
    """The G21 remedy. Unbounded stays reachable, but only by NAME.

    A bare 0 is what an unset variable, a truncated template and a slipped
    keystroke all look like, and it used to load silently into the verdict flip
    above. It is now a refusal with a typed reason, asserted structurally rather
    than by message (G19).
    """

    field = _CONFIG_FIELD[bound]
    with pytest.raises(ConfigError) as refusal:
        Config(**{field: 0})
    assert refusal.value.reason == "bound_zero_is_not_unbounded"

    with pytest.raises(ConfigError) as negative:
        Config(**{field: -1})
    assert negative.value.reason == "bound_zero_is_not_unbounded"


@pytest.mark.parametrize("bound,enforced,code", NEUTRALIZABLE)
def test_the_positive_control_the_named_value_loads_and_still_widens(bound, enforced, code):
    """Doctrine #4: the refusal above is only worth something if the posture it
    replaced is still reachable. So this asserts BOTH halves — the named value
    loads, AND it produces the documented widened behaviour: the candidate that
    FAILs under the bound PASSes without it.

    Without this, `test_a_bare_zero_is_refused_at_config_load` is equally
    consistent with unbounded having been removed outright, which is a different
    product and not what was ruled.
    """

    field = _CONFIG_FIELD[bound]
    loaded = Config(**{field: UNBOUNDED})
    assert getattr(loaded, field) == UNBOUNDED
    assert resolve_bound(getattr(loaded, field)) == 0

    widened = _verify(code, **{bound: resolve_bound(getattr(loaded, field))})
    assert isinstance(widened, Evidence), type(widened).__name__
    assert widened.verdict is Verdict.PASS, (bound, widened.verdict)


@pytest.mark.parametrize("bound,enforced,code", NEUTRALIZABLE)
def test_an_unrecognised_spelling_of_unbounded_is_refused(bound, enforced, code):
    """The allowlist is over the permitted SPELLINGS, so a near-miss is refused
    rather than falling back to a bound or to unbounded. Both directions of the
    near-miss: a typo, and a stringified number."""

    field = _CONFIG_FIELD[bound]
    for spelling in ("unbouned", "none", "0", str(enforced), "inf"):
        with pytest.raises(ConfigError) as refusal:
            Config(**{field: spelling})
        assert refusal.value.reason == "unknown_unbounded_spelling", spelling


@pytest.mark.parametrize("bound,enforced,code", NEUTRALIZABLE)
def test_a_named_unbounded_config_round_trips_through_replace(bound, enforced, code):
    """`__post_init__` re-validates whatever was STORED, so a normalisation that
    did not round-trip would make a valid Config un-copyable — and `replace` is
    how most of this tree derives one config from another."""

    field = _CONFIG_FIELD[bound]
    once = Config(**{field: UNBOUNDED})
    twice = replace(once)
    assert getattr(twice, field) == UNBOUNDED


def test_the_three_fail_closed_bounds_have_no_unbounded_spelling_at_all():
    """The other half of the six, and the asymmetry that REMAINS after the
    remedy — deliberately, because none of these has a safe unbounded meaning:
    a verifier with no wall clock never returns, and a response body with no
    ceiling is the one an adversary sizes."""

    for field in ("verifier_timeout_s", "request_timeout_s", "provider_max_response_bytes"):
        with pytest.raises(ValueError):
            Config(**{field: 0})
        with pytest.raises(ValueError):
            Config(**{field: -1})
        with pytest.raises((ValueError, TypeError)):
            Config(**{field: UNBOUNDED})


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
