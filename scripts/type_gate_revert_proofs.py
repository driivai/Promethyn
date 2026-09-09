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

WHAT THIS DOES AND DOES NOT PROVE. It proves that the PINNED mutations still
make their tests go red — that these particular guards are load-bearing today.
It does NOT prove the mutation set is complete, and the count says nothing about
semantic coverage: fourteen mutations that all hit one module would print the
same reassuring number as fourteen that span the system.

Nor is it externally anchored. The runner, its pins, its mutation list and the
pin tests that hold them are all editable in one change by whoever edits the
code under test — so it raises the cost of removing a guard, and it does not
make removal detectable to anyone outside this repository. Treat "12/17, pinned"
as "these twelve reverts were executed and caught", never as "the guards are
complete" or "nobody could have quietly changed this".

An independent review made the point concretely: the first twelve mutations
covered none of the namespace narrowing defect, the config bypass, the CI
bypass, or the bank's partial-unavailability handling. Two of those four are now
covered (the config and CI bypasses, added below). The other two are named here
rather than left for the next reviewer to find.

Run with the repository's test environment:
    python scripts/type_gate_revert_proofs.py
"""

from __future__ import annotations

from pathlib import Path

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

#: Phase 2 (the guards themselves). Observed then pinned, same discipline.
EXPECTED_CONFIG_MUTATIONS = 10
EXPECTED_GUARD_FAILURES = 11


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
                "        if isinstance(outcome, Unavailable):",
                "        if False:",
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




# --------------------------------------------------------------------------
# Phase 2: the GUARDS themselves, mutated on disk
# --------------------------------------------------------------------------
#
# The mutations above rewrite a function in memory. The two bypasses an
# independent review actually used were not in a function at all — one was a
# line in ``mypy.ini``, the other a shell operator in ``ci.yml`` — and the first
# twelve proofs therefore said nothing about either. These do.
#
# The files ARE edited here, unlike the in-memory phase, so every mutation is
# applied and restored under try/finally and the runner verifies the restore
# before it exits. A crash mid-mutation leaves the file changed; the check at
# the end says so loudly rather than letting a weakened config sit in the tree.

REPO = Path(__file__).resolve().parent.parent
GATE_TESTS = "tests/conformance/test_type_gate.py"


def config_mutations():
    """(name, path, old, new, test file, -k selection)."""

    return [
        (
            # The review's exact finding: one line, gate green, real defect in
            # the tree. The old guard was a denylist and never considered it.
            "config-suppresses-the-union-error-code",
            "mypy.ini",
            "files = src/prometheus_protocol, scripts, tests",
            "files = src/prometheus_protocol, scripts, tests\ndisable_error_code = union-attr",
            GATE_TESTS,
            "allowed_keys or planted_union_defect",
        ),
        (
            # A spelling nobody blacklisted, to show the allowlist is not just a
            # longer denylist: a per-module section that un-checks the levers.
            "config-carves-out-a-module",
            "mypy.ini",
            "files = src/prometheus_protocol, scripts, tests",
            "files = src/prometheus_protocol, scripts, tests\n\n"
            "[mypy-prometheus_protocol.verifier.*]\nignore_errors = True",
            GATE_TESTS,
            "allowed_keys or per_module_sections or planted_union_defect",
        ),
        (
            # The review's CI bypass: the step contains the gate command, carries
            # no blacklisted escape, and never runs it.
            "ci-step-never-executes-the-gate",
            ".github/workflows/ci.yml",
            "        run: python scripts/type_gate.py",
            "        run: true || python scripts/type_gate.py",
            GATE_TESTS,
            "gate_step_command",
        ),
        (
            # Uncovered before because only the extracted step was inspected.
            "ci-job-is-disabled-wholesale",
            ".github/workflows/ci.yml",
            "  build:\n    runs-on: ubuntu-latest",
            "  build:\n    if: false\n    runs-on: ubuntu-latest",
            GATE_TESTS,
            "build_job_itself_is_unconditional",
        ),
        (
            # TYPE-GATE-HARDEN-2 / F-1: the class the config allowlist could not
            # see. A per-file directive, no config change at all.
            "source-file-reconfigures-the-checker-inline",
            "src/prometheus_protocol/core/reporting.py",
            '"""Human-readable renderings of the outcome unions. Reporting only.',
            '# mypy: disable-error-code="union-attr"\n'
            '"""Human-readable renderings of the outcome unions. Reporting only.',
            GATE_TESTS,
            "inline_mypy_directive",
        ),
        (
            # F-2: one scope up from the step-level check that was bypassed.
            "ci-job-is-made-advisory",
            ".github/workflows/ci.yml",
            "  build:\n    runs-on: ubuntu-latest",
            "  build:\n    continue-on-error: true\n    runs-on: ubuntu-latest",
            GATE_TESTS,
            "build_job_carries_exactly_the_permitted_keys",
        ),
        (
            # F-2 again, a key nobody would have thought to blacklist.
            "ci-job-is-starved-of-time",
            ".github/workflows/ci.yml",
            "  build:\n    runs-on: ubuntu-latest",
            "  build:\n    timeout-minutes: 1\n    runs-on: ubuntu-latest",
            GATE_TESTS,
            "build_job_carries_exactly_the_permitted_keys",
        ),
        (
            # F-3: the workflow simply never fires on a pull request.
            "ci-stops-answering-to-pull-requests",
            ".github/workflows/ci.yml",
            "on:\n  push:\n    branches: [main]\n  pull_request:\n",
            "on:\n  push:\n    branches: [main]\n",
            GATE_TESTS,
            "workflow_answers_to_exactly_the_permitted_triggers",
        ),
        (
            # F-5: a flag inside the entry point, which the old proof never
            # passed through.
            "gate-script-suppresses-the-union-error-code",
            "scripts/type_gate.py",
            '[sys.executable, "-m", "mypy", "--config-file", str(CONFIG)],',
            '[sys.executable, "-m", "mypy", "--disable-error-code=union-attr", '
            '"--config-file", str(CONFIG)],',
            GATE_TESTS,
            "planted_union_defect",
        ),
        (
            # Presence is not execution: delete the receipt check and the
            # non-execution of the gate stops being detectable at all.
            "ci-drops-the-execution-receipt-check",
            ".github/workflows/ci.yml",
            "      - name: Type gate receipt (the gate must have EXECUTED, not merely existed)",
            "      - name: Type gate receipt (disabled)\n        if: false",
            GATE_TESTS,
            "separate_mandatory_step_requires",
        ),
    ]


def run_config_mutations() -> int:
    """Apply each guard mutation on disk, prove the guard goes red, restore."""

    import io
    import contextlib
    import tempfile
    import xml.etree.ElementTree as ET

    import pytest

    total = 0
    with tempfile.TemporaryDirectory(prefix="prom-type-gate-guard-") as directory:
        for name, rel, old, new, test_file, selection in config_mutations():
            path = REPO / rel
            before = path.read_text(encoding="utf-8")
            if old not in before:
                raise AssertionError(f"{name}: mutation target disappeared: {old!r}")
            report = Path(directory) / f"{name}.xml"
            captured = io.StringIO()
            try:
                path.write_text(before.replace(old, new, 1), encoding="utf-8")
                with (
                    contextlib.redirect_stdout(captured),
                    contextlib.redirect_stderr(captured),
                ):
                    result = pytest.main(
                        ["-q", "-p", "no:cacheprovider", test_file, "-k", selection,
                         f"--junitxml={report}"]
                    )
            finally:
                path.write_text(before, encoding="utf-8")
                if path.read_text(encoding="utf-8") != before:
                    raise AssertionError(f"{name}: FAILED TO RESTORE {rel}")
            cases = list(ET.parse(report).iter("testcase")) if report.exists() else []
            failed = [c for c in cases if c.find("failure") is not None]
            if result != pytest.ExitCode.TESTS_FAILED or not failed:
                print(captured.getvalue())
                raise AssertionError(f"{name}: the guard did NOT catch this bypass")
            total += len(failed)
            print(f"CAUGHT {name}: {len(failed)} guard failure(s); {test_file} -k {selection!r}")
    return total


def main() -> int:
    harness.EXPECTED_REVERTS = EXPECTED_REVERTS
    harness.EXPECTED_CALL_FAILURES = EXPECTED_CALL_FAILURES
    harness.enforce_expected = enforce_expected
    harness.mutations = mutations
    rc = harness.main()
    if rc != 0:
        return rc
    print("")
    print("=== phase 2: the guards themselves (config + CI bypasses) ===")
    caught = run_config_mutations()
    if len(config_mutations()) != EXPECTED_CONFIG_MUTATIONS or caught != EXPECTED_GUARD_FAILURES:
        raise AssertionError(
            f"guard-bypass count drifted: {len(config_mutations())} mutations / "
            f"{caught} guard failures observed, {EXPECTED_CONFIG_MUTATIONS} / "
            f"{EXPECTED_GUARD_FAILURES} pinned."
        )
    print(
        f"{len(config_mutations())} guard bypasses caught; {caught} guard "
        f"failures; pinned {EXPECTED_CONFIG_MUTATIONS} / {EXPECTED_GUARD_FAILURES}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
