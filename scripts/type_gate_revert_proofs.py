"""Executed TYPE-GATE union reverts: put each union fix back the way it was, in
memory, run the behavioural tests that must go red, restore, and refuse any
drift against the pinned counts.

Same discipline and the same harness as the F11, PROM-FIX-B, substrate and
PIH-4a runners: a mutation that produces no call-phase failure, or a run whose
count differs from its pin in EITHER direction, is itself a failure. Production
files are never edited.

What this proves that mypy cannot. mypy proves the ``Unavailable`` branch is
*written*; it cannot prove the branch is reached, that it produces a sensible
outcome, or that the test asserting so would notice its absence. Each mutation
below reverts one narrowing to the shape the independent review found — reading
the Evidence-only field straight off the union, or collapsing the could-not-run
into an abstention — and the run shows the behavioural test going red on it. A
guard nothing can break is a guard that is not guarding.

Run with the repository's test environment:
    python scripts/type_gate_revert_proofs.py
"""

from __future__ import annotations

from prometheus_protocol.benchmarks import chain_eval, grounding_eval, sql_items
from prometheus_protocol.conformance import cases, contract
from prometheus_protocol.core import reporting
from prometheus_protocol.swarm import runtime as swarm_runtime
from prometheus_protocol.verifier import soft_levers

import fix_b_revert_proofs as harness

CRASHES = "tests/conformance/test_unavailable_consumers_do_not_crash.py"

#: Observed first, then pinned — never predicted. Both a shortfall and an excess
#: are refused: a runner that quietly stops executing proofs would print a
#: smaller number and exit 0, and one that starts catching unrelated failures is
#: no longer measuring what it claims to.
EXPECTED_REVERTS = 12
EXPECTED_CALL_FAILURES = 17


def enforce_expected(caught: int, failures: int) -> None:
    if caught != EXPECTED_REVERTS or failures != EXPECTED_CALL_FAILURES:
        raise AssertionError(
            f"TYPE-GATE revert count drifted: {caught} reverts / {failures} "
            f"call-phase failures observed, {EXPECTED_REVERTS} / "
            f"{EXPECTED_CALL_FAILURES} pinned. A proof was added, removed or "
            "stopped executing; update the pin in the same change that changes "
            "the mutation list, never alone."
        )


def mutations():
    """(name, function, [(old, new)], test file, -k selection).

    Every ``new`` here is a shape this sprint FORBIDS, reintroduced on purpose
    for the length of one pytest run: a could-not-run collapsed into an
    abstention, an Evidence-only field read off the union, or a check that never
    ran reported as one that passed.
    """

    return [
        # -- the levers: a could-not-run is not an abstention -----------------
        (
            "threshold-lever-collapses-could-not-run-into-abstain",
            soft_levers.ConfidenceThresholdJudge.verify,
            [(
                "    if isinstance(result, Unavailable):",
                "    if False:",
            )],
            CRASHES,
            "threshold_lever",
        ),
        (
            "ensemble-lets-the-reachable-judges-decide",
            soft_levers.EnsembleJudge.verify,
            [(
                "    if missing:",
                "    if False:",
            )],
            CRASHES,
            "ensemble_lever",
        ),
        (
            "k-sample-counts-a-sample-that-never-ran",
            soft_levers.RepeatedSamplingJudge.verify,
            [(
                "    if missing:",
                "    if False:",
            )],
            CRASHES,
            "repeated_sampling",
        ),
        # -- the conformance harness: certify only what was observed ----------
        (
            "behavioural-check-reports-an-unrun-check-as-passed",
            contract._behavioural,
            [(
                "    if isinstance(outcome, Unavailable):",
                "    if False:",
            )],
            CRASHES,
            "conformance_check",
        ),
        (
            "code-adversarial-probe-claims-soundness-it-did-not-observe",
            cases._code_adversarial,
            [(
                "    if isinstance(ev, Unavailable):",
                "    if False:",
            )],
            CRASHES,
            "code_adversarial",
        ),
        (
            "grounding-adversarial-probe-claims-soundness-it-did-not-observe",
            cases._grounding_adversarial,
            [(
                "    if isinstance(ev, Unavailable):",
                "    if False:",
            )],
            CRASHES,
            "grounding_adversarial",
        ),
        # -- the swarm: fail closed, or do not proceed ------------------------
        (
            "swarm-proceeds-on-checks-that-could-not-run",
            swarm_runtime.SwarmRuntime._verify,
            [(
                "        if isinstance(evidence, Unavailable):",
                "        if False:",
            )],
            CRASHES,
            "swarm_records_an_unavailable",
        ),
        # -- the evaluators: an unrun check is not a measurement --------------
        (
            "grounding-eval-parses-a-confidence-off-a-non-judgment",
            grounding_eval.run_grounding_eval,
            [(
                "                judged=None if isinstance(judged, Unavailable) else judged.verdict,\n"
                "                confidence=(\n"
                "                    None\n"
                "                    if isinstance(judged, Unavailable)\n"
                "                    else parse_grounding_confidence(judged.detail)\n"
                "                ),\n"
                "                judge_unavailable=isinstance(judged, Unavailable),\n",
                "                judged=judged.verdict,\n"
                "                confidence=parse_grounding_confidence(judged.detail),\n",
            )],
            CRASHES,
            "grounding_eval",
        ),
        (
            "sql-sweep-files-a-could-not-run-as-an-abstention",
            sql_items.run_reliability,
            [(
                "        if isinstance(evidence, Unavailable):",
                "        if False:",
            )],
            CRASHES,
            "sql_reliability_sweep",
        ),
        # -- the chain study: an unrun chain is not a measurement -------------
        (
            "chain-eval-invents-a-correctness-for-an-unrun-chain",
            chain_eval.run_chain,
            [(
                "    if isinstance(ev, Unavailable):",
                "    if False:",
            )],
            CRASHES,
            "chain_eval_excludes",
        ),
        (
            "instrument-self-check-reports-itself-sound-without-running",
            chain_eval.instrument_self_check,
            [(
                "        if isinstance(ref, Unavailable):",
                "        if False:",
            )],
            CRASHES,
            "instrument_self_check",
        ),
        # -- the renderers: never print a verdict nobody reached --------------
        (
            "render-outcome-prints-a-verdict-for-a-could-not-run",
            reporting.render_outcome,
            [(
                '    if isinstance(outcome, Unavailable):',
                '    if False:',
            )],
            CRASHES,
            "render_outcome or grounding_loop_demo or sql_loop_demo",
        ),
    ]


def main() -> int:
    harness.EXPECTED_REVERTS = EXPECTED_REVERTS
    harness.EXPECTED_CALL_FAILURES = EXPECTED_CALL_FAILURES
    harness.enforce_expected = enforce_expected
    harness.mutations = mutations
    return harness.main()


if __name__ == "__main__":
    raise SystemExit(main())
