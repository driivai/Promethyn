"""Executed PHASE-1.2 CHECKPOINT 3 guard reverts: let advisory evidence satisfy
a requirement again, in memory, and watch the tests that must go red do so.
Restore, and refuse any drift.

Same discipline and the same harness as the ten runners before it. A mutation
that produces no call-phase failure, or a run whose count differs from its pin
in EITHER direction, is itself a failure. Production files are never edited on
disk.

The mutations come in two families:

* **THE ACCEPTANCE CONDITION.** Each mutation lets advisory evidence, or
  evidence whose tier could not be established, satisfy a requirement. That was
  the measured gap: ``validate_coverage`` was tier-blind, so a policy naming any
  advisory implementation made advisory evidence sufficient for coverage.
* **THE FAIL-CLOSED DEFAULT.** ``Evidence.tier`` is optional, and coverage holds
  no trust store. A missing tier must be a tier it could not establish.

WHAT THIS DOES AND DOES NOT PROVE. It proves the pinned mutations still make
their tests go red — that these guards are load-bearing today. It does NOT prove
the mutation set is complete, and the count says nothing about semantic
coverage. Nor is it externally anchored: the runner, its pins and its mutation
list are editable in one change by whoever edits the code under test.

Run with the repository's test environment:
    python scripts/phase_1_2c_revert_proofs.py
"""

from prometheus_protocol.policy import coverage

import fix_b_revert_proofs as harness

ADVISORY = "tests/conformance/test_advisory_cannot_satisfy.py"

#: Observed first, then pinned — never predicted. Both a shortfall and an excess
#: are refused.
EXPECTED_REVERTS = 3
EXPECTED_CALL_FAILURES = 7


def enforce_expected(caught: int, failures: int) -> None:
    if caught != EXPECTED_REVERTS or failures != EXPECTED_CALL_FAILURES:
        raise AssertionError(
            f"PHASE-1.2c revert count drifted: {caught} reverts / {failures} "
            f"call-phase failures observed, {EXPECTED_REVERTS} / "
            f"{EXPECTED_CALL_FAILURES} pinned. A proof was added, removed or "
            "stopped executing; update the pin in the same change that changes "
            "the mutation list, never alone."
        )


def mutations():
    """(name, function, [(old, new)], test file, -k selection)."""

    return [
        # -- the acceptance condition ----------------------------------------
        (
            # THE SPRINT, INVERTED. Make the rule tier-blind again: any PASS
            # satisfies, including one from a soft-lever wrapper.
            "advisory-evidence-satisfies-a-requirement-again",
            coverage._authoritative,
            [("    return outcome.tier in AUTHORITATIVE_TIERS", "    return True")],
            ADVISORY,
            "advisory_evidence_does_not_satisfy or no_wrapper_can_satisfy",
        ),
        (
            # The fail-closed default. An Evidence with no tier is a tier
            # coverage could not establish, and could-not-establish is never
            # established. Treating None as authoritative is the quiet version
            # of the same hole.
            "a-missing-tier-is-treated-as-authoritative",
            coverage._authoritative,
            [(
                "    return outcome.tier in AUTHORITATIVE_TIERS",
                "    return outcome.tier is None or outcome.tier in AUTHORITATIVE_TIERS",
            )],
            ADVISORY,
            "a_missing_tier_fails_closed",
        ),
        # -- the refusal must actually refuse ---------------------------------
        (
            # The row exists but does nothing: an advisory PASS is remembered and
            # then falls through to the incomplete row. Same end state, wrong
            # reason — and a reason an operator would act on differently, since
            # "incomplete" reads as a run to retry and "advisory_only" reads as a
            # policy to fix.
            "the-advisory-refusal-reports-the-wrong-row",
            coverage.validate_coverage,
            [("        if advisory_pass is not None:", "        if False:")],
            ADVISORY,
            "advisory_evidence_does_not_satisfy or advisory_plus_unavailable",
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
