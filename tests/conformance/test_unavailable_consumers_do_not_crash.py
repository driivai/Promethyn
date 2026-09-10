"""Every consumer the review crashed, driven with a REAL Unavailable.

A type fix that satisfies mypy but still crashes at runtime is a void guard.
mypy proves the ``Unavailable`` branch is *handled*; it cannot prove the handler
is reachable, that it produces a sensible outcome, or that some later line in
the same function reaches for a field the branch never set. Only running the
real consumer over a real could-not-run proves that.

So this module drives each crash site the independent review reproduced with an
actual ``Unavailable`` produced by an actual verifier hitting an actual fault —
never a hand-built ``Unavailable(...)`` and never a stub verifier. Two fault
shapes, both real:

* ``ModelJudgeVerifier`` / ``GroundingVerifier`` over a provider whose
  ``assess`` raises ``TimeoutError``. This is the shape the review used, and it
  is the transport fault EX-1 exists for: a dead endpoint must never read as a
  judge that ran and declined.
* ``SubprocessVerifier`` / ``SqlVerifier`` over ``NullSandbox``, which refuses
  to start. This is the HARD-tier equivalent: the isolation runtime is absent,
  so the check could not execute at all.

Each test asserts a STRUCTURED non-crash outcome — the consumer reports the
could-not-run as itself, and does not report it as a pass, a fail, or an
abstention. Not merely "it did not raise": an except-and-return-PASS would also
not raise, and would be worse than the crash.

These run in CI on every supported Python and never skip. None of them needs the
isolation runtime: the fault under test IS the runtime being unavailable.
"""

from __future__ import annotations

from typing import Sequence

import pytest

from prometheus_protocol.core.interfaces import Provider
from prometheus_protocol.core.models import (
    Case,
    Evidence,
    Judgment,
    Skill,
    Task,
    Tier,
    Unavailable,
    Verdict,
)
from prometheus_protocol.sandbox import NullSandbox
from prometheus_protocol.sandbox.unsafe import UnsafeLocalSandbox
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.grounding import GroundingTask, GroundingVerifier
from prometheus_protocol.verifier.model_judge import ModelJudgeVerifier
from prometheus_protocol.verifier.runner import SubprocessVerifier
from prometheus_protocol.verifier.sql import SqlTask, SqlVerifier

# --------------------------------------------------------------------------
# the real faults
# --------------------------------------------------------------------------


class TimingOutProvider(Provider):
    """A provider whose ``assess`` times out — the review's fault shape.

    Not a stub verifier: the verifier under it is the real one, and it takes the
    real transport-failure path. ``propose_solution`` raises too, so nothing can
    accidentally route around the fault.
    """

    model = "timing-out"

    def __init__(self) -> None:
        self.calls = 0

    def propose_solution(self, *, prompt, entry_point, skills: Sequence[Skill] = ()):
        raise TimeoutError("provider timed out while proposing")

    def assess(self, *, prompt: str, system: str | None = None) -> str:
        self.calls += 1
        raise TimeoutError("provider timed out after 30s")


_TASK = Task(
    id="unavail/add", entry_point="add",
    prompt="Return the sum of two integers.", split="train",
    cases=(Case((2, 3), 5), Case((-1, 1), 0)),
)
_GROUNDING_TASK = GroundingTask(
    id="unavail/g", source="The hall opens at nine and admission is free.",
)
_SQL_TASK = SqlTask(
    id="unavail/sum", prompt="Total of v.",
    schema_sql="CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER NOT NULL);",
    fixture_sql="INSERT INTO t VALUES (1, 10), (2, 20);",
    reference_query="SELECT SUM(v) FROM t",
)


def timing_out_judge() -> ModelJudgeVerifier:
    return ModelJudgeVerifier(TimingOutProvider())


def timing_out_grounding_judge() -> GroundingVerifier:
    return GroundingVerifier(TimingOutProvider())


def refusing_sql_verifier() -> SqlVerifier:
    """A real SQL verifier whose isolation runtime refuses to start."""

    return SqlVerifier(sandbox=NullSandbox())


def refusing_code_verifier() -> SubprocessVerifier:
    return SubprocessVerifier(memory_mb=0, sandbox=NullSandbox())


def test_the_fault_shapes_really_produce_unavailable():
    """The premise of every test below. If a fault shape stopped producing an
    ``Unavailable``, the rest of this module would pass while testing nothing."""

    assert isinstance(timing_out_judge().verify(code="x", task=_TASK), Unavailable)
    assert isinstance(
        timing_out_grounding_judge().verify(code="c", task=_GROUNDING_TASK), Unavailable
    )
    assert isinstance(
        refusing_sql_verifier().verify(code="SELECT 1", task=_SQL_TASK), Unavailable
    )
    assert isinstance(
        refusing_code_verifier().verify(code="def add(a, b): return a + b", task=_TASK),
        Unavailable,
    )


# --------------------------------------------------------------------------
# 1-3. verifier/soft_levers.py — the three levers
# --------------------------------------------------------------------------


def test_confidence_threshold_lever_propagates_the_could_not_run():
    """soft_levers.py:129-130 — the lever read ``.decided`` off the base result.

    A lever gates a PASS on stated confidence. There is no PASS to gate when the
    judge never ran, and withholding to ABSTAIN would assert the judge ran and
    had no opinion — the collapse EX-1 makes unrepresentable.
    """

    from prometheus_protocol.benchmarks.judge_eval import parse_confidence
    from prometheus_protocol.verifier.soft_levers import ConfidenceThresholdJudge

    lever = ConfidenceThresholdJudge(
        timing_out_judge(), min_confidence=0.8, confidence_parser=parse_confidence
    )
    result = lever.verify(code="def add(a, b): return a + b", task=_TASK)

    assert isinstance(result, Unavailable)
    assert not isinstance(result, Evidence)
    # F8: the detail is bounded now — it carries the exception TYPE, not the
    # provider's message text. The property under test is unchanged (a timeout
    # propagates as a could-not-run) and the operator distinction survives:
    # TimeoutError is still named, distinguishably from any other fault.
    assert "error_type=TimeoutError" in (result.detail or "")


def test_ensemble_lever_reports_how_many_judges_could_not_run():
    """soft_levers.py:186 — the ensemble read ``.decided`` on every member.

    Unanimity cannot be established when a member never ran. The ensemble must
    say so, and say how many of how many — not silently poll the survivors,
    which would let one reachable judge speak for a quorum that never met.
    """

    from prometheus_protocol.verifier.soft_levers import EnsembleJudge

    ensemble = EnsembleJudge(
        [timing_out_judge(), timing_out_judge()], on_disagreement="abstain"
    )
    result = ensemble.verify(code="def add(a, b): return a + b", task=_TASK)

    assert isinstance(result, Unavailable)
    detail = result.detail or ""
    assert "2" in detail, f"the ensemble must name how many judges could not run: {detail!r}"


def test_ensemble_lever_does_not_let_survivors_speak_for_the_quorum():
    """A partially-unavailable ensemble is still not a unanimous ensemble."""

    from prometheus_protocol.benchmarks.judge_eval import ScriptedJudgeProvider
    from prometheus_protocol.verifier.soft_levers import EnsembleJudge

    reachable = ModelJudgeVerifier(ScriptedJudgeProvider({}, model="scripted"))
    ensemble = EnsembleJudge(
        [reachable, timing_out_judge()], on_disagreement="abstain"
    )
    result = ensemble.verify(code="def add(a, b): return a + b", task=_TASK)

    assert isinstance(result, Unavailable), (
        "one judge that could not run breaks unanimity; the reachable judge must "
        "not be allowed to decide on the ensemble's behalf"
    )


def test_repeated_sampling_lever_propagates_the_could_not_run():
    """soft_levers.py:263 — k-sample read ``.decided`` on each sample."""

    from prometheus_protocol.verifier.soft_levers import RepeatedSamplingJudge

    lever = RepeatedSamplingJudge(timing_out_judge(), k=3, require="unanimous")
    result = lever.verify(code="def add(a, b): return a + b", task=_TASK)

    assert isinstance(result, Unavailable)
    assert result.tier is Tier.SOFT, "a lever never promotes its own tier"


# --------------------------------------------------------------------------
# 4. conformance/contract.py — check_verifier
# --------------------------------------------------------------------------


def test_conformance_check_reports_a_could_not_run_verifier_as_unavailable():
    """contract.py:258,260,274,275 — the contract checker read ``.verdict`` off
    the PASS/FAIL example results.

    A conformance run against a verifier that cannot execute must report the
    checks as could-not-run. Reporting them as PASSED would certify a contract
    nobody observed; reporting them as FAILED would blame the verifier for its
    runtime's absence.
    """

    from prometheus_protocol.conformance.contract import VerifierCase, check_verifier

    case = VerifierCase(
        name="sql (isolation runtime refuses to start)",
        verifier=refusing_sql_verifier(),
        tier=Tier.HARD,
        failclosed=(refusing_sql_verifier(), ("SELECT SUM(v) FROM t", _SQL_TASK)),
        passing=("SELECT SUM(v) FROM t", _SQL_TASK),
        failing=("SELECT COUNT(v) FROM t", _SQL_TASK),
    )
    report = check_verifier(case)

    behavioural = [
        c for c in report.checks
        if c.name in {"passes-a-correct-candidate", "fails-a-faulty-candidate"}
    ]
    assert behavioural, "the behavioural checks must appear in the report"
    for check in behavioural:
        assert check.unavailable is True, (
            f"{check.name} must be reported as could-not-run, not as "
            f"{'passed' if check.ok else 'failed'}: {check.detail}"
        )
        assert check.ok is False, (
            f"{check.name} reports ok=True for a check that never ran — a "
            "property that could not be exercised has not been certified"
        )
        assert check.skipped is False, (
            f"{check.name} reports skipped=True for a check that WAS attempted"
        )

    rendered = report.render()
    assert "UNAVAIL" in rendered, rendered


def test_conformance_fail_closed_check_survives_an_unavailable_probe():
    """The fail-closed check itself feeds an Unavailable through the reporter —
    the ``getattr(fc_evidence, 'verdict', ...)`` probe that used to sit here."""

    from prometheus_protocol.conformance.contract import VerifierCase, check_verifier

    case = VerifierCase(
        name="code (isolation runtime refuses to start)",
        verifier=refusing_code_verifier(),
        tier=Tier.HARD,
        failclosed=(refusing_code_verifier(), ("def add(a, b): return a + b", _TASK)),
        passing=("def add(a, b): return a + b", _TASK),
        failing=("def add(a, b): return a - b", _TASK),
    )
    report = check_verifier(case)

    fail_closed = next(c for c in report.checks if c.name == "fail-closed")
    assert fail_closed.ok is True, (
        "a verifier whose sandbox refuses to start IS failing closed: "
        f"{fail_closed.detail}"
    )


# --------------------------------------------------------------------------
# 5-6. conformance/cases.py — the two adversarial probes
# --------------------------------------------------------------------------


def test_code_adversarial_probe_reports_unsound_when_it_could_not_run(monkeypatch):
    """cases.py:48,51 — the probe read ``.decided`` on the forging candidate's
    result. If the probe could not run, soundness was NOT demonstrated; saying
    it was would certify a property nobody observed."""

    from prometheus_protocol.conformance import cases

    monkeypatch.setattr(cases, "SubprocessVerifier", lambda **kw: refusing_code_verifier())
    ok, detail = cases._code_adversarial()

    assert ok is False, "a probe that never ran cannot report the verifier sound"
    assert "could not run" in detail, detail


def test_grounding_adversarial_probe_reports_unsound_when_it_could_not_run(monkeypatch):
    """cases.py:170,173 — same shape on the grounding judge."""

    from prometheus_protocol.conformance import cases

    monkeypatch.setattr(
        cases, "GroundingVerifier", lambda *a, **kw: timing_out_grounding_judge()
    )
    ok, detail = cases._grounding_adversarial()

    assert ok is False
    assert "could not run" in detail, detail


# --------------------------------------------------------------------------
# 7-8. swarm/runtime.py — the verify path and the bank path
# --------------------------------------------------------------------------


def _swarm_runtime(synthesis, code_verifier=None):
    from prometheus_protocol.gate.authorization import ActionGate
    from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
    from prometheus_protocol.swarm.debate import DebateLayer
    from prometheus_protocol.swarm.executor import RecordingExecutor
    from prometheus_protocol.swarm.runtime import SwarmRuntime
    from prometheus_protocol.verifier.store import InMemoryTrustStore

    return SwarmRuntime(
        synthesis=synthesis,
        debate=DebateLayer(),
        bank=VerifierBank(InMemoryTrustStore()),
        gate=ActionGate(),
        executor=RecordingExecutor(),
        ledger=SqliteLedger(":memory:"),
        code_verifier=code_verifier,
    )


def _executable_swarm(entry_point: str = "add"):
    """A real synthesis engine whose skeptic attaches EXECUTABLE cases.

    The shipped example provider produces only structural checks, so the HARD
    code verifier is never reached and the fault under test would never fire.
    These are the ordinary role and check objects the runtime already consumes —
    the runtime, the debate layer, the bank, the gate and the verifier are all
    the real ones.
    """

    from prometheus_protocol.core.models import Case as _Case
    from prometheus_protocol.swarm.models import (
        KIND_CRITIQUE,
        KIND_PROPOSED_ACTION,
        FalsificationCheck,
        Proposal,
        Provenance,
        content_hash,
    )
    from prometheus_protocol.swarm.roles import Role
    from prometheus_protocol.swarm.synthesis import RoleSynthesisEngine

    _CODE = "def add(a, b):\n    return a + b\n"

    def _proposal(role_id, kind, content, rationale, *, inputs=(), checks=()):
        digest = content_hash(content)
        return Proposal(
            id=f"{role_id}/{kind}/{digest[:8]}",
            role_id=role_id,
            kind=kind,
            content=content,
            rationale=rationale,
            provenance=Provenance(content_hash=digest, inputs=tuple(inputs)),
            falsification_checks=tuple(checks),
        )

    class CodePlanner(Role):
        id = "planner"
        kind = KIND_PROPOSED_ACTION

        def propose(self, packet, context):
            return [_proposal(self.id, self.kind, _CODE, "Candidate implementation.")]

    class ExecutableSkeptic(Role):
        id = "skeptic"
        kind = KIND_CRITIQUE
        mandatory = True

        def propose(self, packet, context):
            out = []
            for proposal in context.proposals:
                if proposal.kind == KIND_CRITIQUE:
                    continue
                check = FalsificationCheck(
                    id=f"falsify/{proposal.id}/cases",
                    description="candidate must satisfy 2 skeptic case(s)",
                    predicate="executable_cases",
                    entry_point=entry_point,
                    cases=(_Case((2, 3), 5), _Case((-1, 1), 0)),
                )
                out.append(_proposal(
                    self.id, KIND_CRITIQUE,
                    f"Critique of {proposal.id}: attach falsification checks.",
                    "A proposal that cannot survive falsification is unsound.",
                    inputs=(proposal.id,), checks=(check,),
                ))
            return out

    return RoleSynthesisEngine([CodePlanner(), ExecutableSkeptic()])


def test_swarm_records_an_unavailable_chain_and_executes_nothing():
    """swarm/runtime.py:102 and :208 — the runtime annotated ``_verify`` as
    ``Evidence | None`` while it actually returned ``Evidence | Unavailable``,
    and handed the bank's result to ``VerifiedProposal.from_judgment`` without
    narrowing.

    With the HARD code verifier's sandbox refusing to start, the chain must fail
    CLOSED: the unavailability is recorded, no VerifiedProposal is built (there
    is no judgment to carry), the gate is not consulted, and the executor runs
    nothing.
    """

    from prometheus_protocol.swarm.models import TaskPacket

    runtime = _swarm_runtime(
        _executable_swarm(), code_verifier=refusing_code_verifier()
    )
    run = runtime.run(TaskPacket(goal="add two integers", budget=5, entry_point="add"))

    unavailable = [r for r in run.records if isinstance(r.evidence, Unavailable)]
    assert unavailable, (
        "no chain recorded an Unavailable — the fault did not reach the runtime, "
        "so this test proves nothing"
    )
    for record in unavailable:
        assert record.verified is None, (
            "a VerifiedProposal was built without a judgment to carry"
        )
        assert record.decision is None, "the gate was consulted with no judgment"
        assert record.execution is None
    assert runtime.executor.executed == [], (
        "something executed off a chain whose verification could not run"
    )


def working_code_verifier() -> SubprocessVerifier:
    """A code verifier that CAN run, on any host, with no capability probe.

    This exists for the positive control below, and the choice of sandbox is the
    whole point. ``SubprocessVerifier(memory_mb=0)`` with auto-detected isolation
    was environment-dependent: on a host without unprivileged user namespaces it
    does not skip, it FAILS with "no isolating sandbox runtime available;
    candidate code will ABSTAIN" — which an independent review hit. A control
    that only runs on some hosts is not a control.

    ``UnsafeLocalSandbox`` runs the candidate as an ordinary subprocess with
    rlimits, deterministically, everywhere. That is appropriate HERE and nowhere
    near production, and the distinction is the trust assumption, not
    convenience: the "candidate" is four characters of arithmetic written by the
    line above (``def add(a, b): return a + b``), a fixture this test authored,
    not an untrusted proposal from a model. Isolation exists to contain code
    whose behaviour is not known in advance; this code's behaviour is the
    fixture. The tests that verify isolation ITSELF live in the sandbox suite and
    correctly demand a real runtime.

    What is NOT weakened: the negative test still injects a real ``NullSandbox``
    refusal and still asserts fail-closed. Deleting this control instead would
    make the suite portable and weaker — the fail-closed assertion could then
    pass merely because the swarm is incapable of executing anything at all.
    """

    return SubprocessVerifier(memory_mb=0, sandbox=UnsafeLocalSandbox())


def test_swarm_that_can_verify_still_executes():
    """The control. If the fault injection above simply broke the swarm, the
    fail-closed assertion would pass for the wrong reason — so the same swarm,
    with a code verifier that CAN run, must still reach the executor.

    Runs on every host: see ``working_code_verifier``.
    """

    from prometheus_protocol.swarm.models import TaskPacket

    runtime = _swarm_runtime(
        _executable_swarm(), code_verifier=working_code_verifier()
    )
    run = runtime.run(TaskPacket(goal="add two integers", budget=5, entry_point="add"))

    assert not any(isinstance(r.evidence, Unavailable) for r in run.records), (
        "a working verifier still produced an Unavailable"
    )
    assert any(r.verified is not None for r in run.records)


def test_swarm_unavailable_chain_is_visible_in_the_ledger():
    """Fail-closed is only auditable if it is recorded. Nothing may be recorded
    as executed for a chain whose verification could not run."""

    from prometheus_protocol.swarm.models import TaskPacket

    runtime = _swarm_runtime(
        _executable_swarm(), code_verifier=refusing_code_verifier()
    )
    run = runtime.run(TaskPacket(goal="add two integers", budget=5, entry_point="add"))

    assert any(isinstance(r.evidence, Unavailable) for r in run.records)
    rows = runtime.ledger.executions()
    assert not any(row["executed"] for row in rows), (
        "an execution was recorded for a chain whose verification could not run"
    )


# --------------------------------------------------------------------------
# 9. benchmarks/grounding_eval.py
# --------------------------------------------------------------------------


def test_grounding_eval_records_a_could_not_run_judge_without_crashing():
    """grounding_eval.py:267 — ``judged.verdict`` on an Evidence | Unavailable.

    The row must carry no verdict and must be FLAGGED, so the fault is counted
    rather than silently vanishing from a denominator.
    """

    from prometheus_protocol.benchmarks import grounding_eval as ge
    from prometheus_protocol.benchmarks.grounding_items import build_grounding_items

    items = build_grounding_items()[:4]
    rows = ge.run_grounding_eval(items, judge=timing_out_grounding_judge())

    assert len(rows) == len(items)
    for row in rows:
        assert row.judged is None, "a verdict was invented for a judge that never ran"
        assert row.judge_unavailable is True
        assert row.confidence is None, (
            "a confidence was parsed off a judgment that does not exist"
        )

    report = ge.render_grounding_report(
        rows, items, judge_model="timing-out", mode="unavailable-probe"
    )
    assert "could not run" in report, report


# --------------------------------------------------------------------------
# 10. benchmarks/sql_items.py
# --------------------------------------------------------------------------


def test_sql_reliability_sweep_reports_could_not_run_and_refuses_to_call_it_clean(
    monkeypatch, capsys
):
    """sql_items.py:469 — ``evidence.verdict`` on an Evidence | Unavailable.

    A sweep that could not run is not a clean sweep: nothing was measured, so
    nothing is demonstrated. It must land in its own bucket (never in
    ``abstains``, which means "ran, no opinion") and must fail the run.
    """

    from prometheus_protocol.benchmarks import sql_items

    monkeypatch.setattr(sql_items, "SqlVerifier", lambda **kw: refusing_sql_verifier())
    lines: list[str] = []
    summary = sql_items.run_reliability(out=lines.append)

    assert summary["unavailable"], "the could-not-run bucket is empty"
    assert summary["abstains"] == [], (
        "a could-not-run was filed as an abstention — the exact EX-1 collapse"
    )
    assert summary["correct_total"] == 0 and summary["wrong_total"] == 0
    assert any("could not run" in line for line in lines)
    assert not any("CLEAN" in line for line in lines), (
        "a sweep that measured nothing reported itself CLEAN"
    )


# --------------------------------------------------------------------------
# 11-12. benchmarks/chain_eval.py — run_chain and the instrument self-check
# --------------------------------------------------------------------------


def test_chain_eval_excludes_a_could_not_run_chain_from_calibration():
    """chain_eval.py:136 — ``ev.verdict`` on an Evidence | Unavailable.

    A chain with no executed ground truth is excluded from calibration and
    reported as could-not-run — distinct from an abstention, which IS a
    measurement the verifier made.
    """

    from prometheus_protocol.benchmarks.chain_eval import CHAINS, run_chain

    outcome = run_chain(CHAINS[0], refusing_sql_verifier())

    assert outcome.unavailable is True
    assert outcome.correct is None, "a correctness was invented for an unrun chain"
    assert "could not run" in outcome.detail, outcome.detail


def test_chain_eval_instrument_self_check_refuses_to_report_itself_sound(monkeypatch):
    """chain_eval.py:427 — ``ref.verdict`` in the soundness gate.

    This gate exists to earn the right to report a measurement. A check that
    could not run has not demonstrated soundness; silence is not evidence.
    """

    from prometheus_protocol.benchmarks import chain_eval

    monkeypatch.setattr(chain_eval, "SqlVerifier", lambda **kw: refusing_sql_verifier())
    lines: list[str] = []
    sound = chain_eval.instrument_self_check(out=lines.append)

    assert sound is False, "an instrument that could not run reported itself SOUND"
    assert any("could not run" in line for line in lines), lines


# --------------------------------------------------------------------------
# 13-14. the two loop demos
# --------------------------------------------------------------------------


def test_sql_loop_demo_does_not_submit_an_action_it_cannot_judge(monkeypatch):
    """sql_loop_demo.py:106 — ``evidence.verdict.value`` in the loop narrative.

    With no judgment there is nothing to authorize on, so the gate is never
    consulted and nothing executes.
    """

    from prometheus_protocol.benchmarks import sql_loop_demo
    from prometheus_protocol.gate.promotion import OUTCOME_UNAVAILABLE

    monkeypatch.setattr(sql_loop_demo, "SqlVerifier", lambda **kw: refusing_sql_verifier())
    lines: list[str] = []
    summary = sql_loop_demo.run_loop(out=lines.append)

    assert summary["sql/03-paid-revenue"] == OUTCOME_UNAVAILABLE
    assert summary["executed"] == 0
    assert any("NOT SUBMITTED" in line for line in lines), lines


def test_grounding_loop_demo_renders_a_could_not_run_and_never_a_verdict(monkeypatch):
    """grounding_loop_demo.py — nineteen union-attr diagnostics, the largest
    single cluster in the pre-fix baseline: every beat printed
    ``.verdict.value`` on an ``Evidence | Unavailable``.

    With the judge unreachable the whole loop must still run to completion, and
    every judge line must read as a could-not-run. A judge that never ran must
    never be printed as PASS, FAIL or ABSTAIN — the reader of a loop narrative
    has no other way to tell "the judge declined" from "the judge was down".

    The bank's own handling of a soft-only Unavailable (it currently fuses it
    into a non-authoritative ABSTAIN judgment) is Phase 1.2 and is deliberately
    NOT asserted on here; what is asserted is that the demo neither crashes nor
    misreports the judge, and that soft-only evidence still authorizes nothing.
    """

    from prometheus_protocol.benchmarks import grounding_loop_demo

    monkeypatch.setattr(
        grounding_loop_demo, "GroundingVerifier",
        lambda *a, **kw: timing_out_grounding_judge(),
    )
    lines: list[str] = []
    summary = grounding_loop_demo.run_loop(out=lines.append)

    judge_lines = [line for line in lines if "[loop] judge" in line]
    assert len(judge_lines) == 3, judge_lines
    for line in judge_lines:
        assert "UNAVAILABLE (could not run" in line, line
        for word in ("PASS", "FAIL", "ABSTAIN"):
            assert word not in line, (
                f"a judge that never ran was printed as {word}: {line!r}"
            )

    assert summary["soft_only"]["executed"] is False, (
        "soft-only evidence authorized an execution"
    )


# --------------------------------------------------------------------------
# the reporting helpers themselves
# --------------------------------------------------------------------------


@pytest.mark.parametrize("verdict", [Verdict.PASS, Verdict.FAIL, Verdict.ABSTAIN])
def test_render_outcome_keeps_all_four_outcomes_distinct(verdict: Verdict):
    """render_outcome must never render a could-not-run as a verdict, and never
    render a verdict as a could-not-run."""

    from prometheus_protocol.core.reporting import render_outcome

    evidence = Evidence(
        passed=(verdict == Verdict.PASS), total=1,
        passed_count=1 if verdict == Verdict.PASS else 0, failures=(),
        verifier_id="probe", verdict=verdict, tier=Tier.SOFT,
    )
    rendered = render_outcome(evidence)
    assert verdict.value.upper() in rendered
    assert "UNAVAILABLE" not in rendered

    unavailable = timing_out_judge().verify(code="x", task=_TASK)
    assert isinstance(unavailable, Unavailable)
    could_not_run = render_outcome(unavailable)
    assert "UNAVAILABLE" in could_not_run and "could not run" in could_not_run
    for word in ("PASS", "FAIL", "ABSTAIN"):
        assert word not in could_not_run, (
            f"a could-not-run rendered the word {word!r}: {could_not_run!r}"
        )


def test_render_judgment_never_invents_a_verdict():
    from prometheus_protocol.core.reporting import render_judgment

    bank = VerifierBank()
    unavailable = timing_out_judge().verify(code="x", task=_TASK)
    assert isinstance(unavailable, Unavailable)
    judgment = bank.judge([unavailable])

    rendered = render_judgment(judgment)
    if isinstance(judgment, Unavailable):
        assert "UNAVAILABLE" in rendered and "no judgment" in rendered
        assert "verdict=" not in rendered
    else:  # a soft-only bank may still fuse; then it must be a real Judgment
        assert isinstance(judgment, Judgment)
        assert "verdict=" in rendered
