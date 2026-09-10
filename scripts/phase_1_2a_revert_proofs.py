"""Executed PHASE-1.2a guard reverts: put each fix back the way it was, in
memory, run the tests that must go red, restore, and refuse any drift.

Same discipline and the same harness as the F11, PROM-FIX-B, substrate, PIH-4a,
TYPE-GATE, PROD-FIX-1 and PROD-FIX-2 runners: a mutation that produces no
call-phase failure, or a run whose count differs from its pin in EITHER
direction, is itself a failure. Production files are never edited on disk.

The mutations come in four families, matching the four things this sprint added:

* **THE OMISSION RULE.** The requirement set must come from the policy and the
  action class ALONE. Each mutation lets the plan influence what is required —
  which is the reproduced attack, because the attack is omission.
* **COVERAGE BEFORE FUSION.** Each mutation lets fusion happen without coverage
  holding, or lets a row of the enforcement table stop refusing.
* **THE R3 LINE.** The mutation makes absence satisfy a requirement — quorum
  wearing this design's clothes.
* **THE SWARM AS A CALLER.** The mutation puts the swarm's own aggregate back.

WHAT THIS DOES AND DOES NOT PROVE. It proves the pinned mutations still make
their tests go red — that these guards are load-bearing today. It does NOT prove
the mutation set is complete, and the count says nothing about semantic
coverage. Nor is it externally anchored: the runner, its pins and its mutation
list are editable in one change by whoever edits the code under test.

Run with the repository's test environment:
    python scripts/phase_1_2a_revert_proofs.py
"""

from prometheus_protocol.policy import coverage, profile, resolver, snapshot
from prometheus_protocol.swarm import runtime as swarm_runtime
from prometheus_protocol.verifier import bank

import fix_b_revert_proofs as harness

ENFORCE = "tests/conformance/test_coverage_enforcement.py"
REGRESS = "tests/conformance/test_policy_enforcement_regression.py"
ENCODE = "tests/conformance/test_bound_requirements_encoding.py"

#: Observed first, then pinned — never predicted. Both a shortfall and an excess
#: are refused.
EXPECTED_REVERTS = 11
EXPECTED_CALL_FAILURES = 25


def enforce_expected(caught: int, failures: int) -> None:
    if caught != EXPECTED_REVERTS or failures != EXPECTED_CALL_FAILURES:
        raise AssertionError(
            f"PHASE-1.2a revert count drifted: {caught} reverts / {failures} "
            f"call-phase failures observed, {EXPECTED_REVERTS} / "
            f"{EXPECTED_CALL_FAILURES} pinned. A proof was added, removed or "
            "stopped executing; update the pin in the same change that changes "
            "the mutation list, never alone."
        )


def mutations():
    """(name, function, [(old, new)], test file, -k selection)."""

    return [
        # -- the omission rule --------------------------------------------
        # NOTE — a mutation that did NOT work, recorded rather than dropped.
        # ``resolver.resolve``'s ``if not required:`` guard was tried here and
        # produced NO failure, because ``VerificationPolicy.__post_init__``
        # already refuses a covered action class with no requirement, making the
        # resolver's check unreachable defence-in-depth. Its own docstring says
        # so. The policy floor is what is load-bearing, and it IS pinned below as
        # ``policy-allows-a-covered-class-with-no-requirement``.
        (
            "resolver-authorizes-an-action-class-the-policy-does-not-cover",
            resolver.resolve,
            [(
                "    if not policy.covers(action_class):",
                "    if False:",
            )],
            ENFORCE,
            "resolver_refuses_an_action_class",
        ),
        (
            # A requested check that collides with a policy requirement, merged
            # instead of refused, is where a downgrade would hide.
            "resolver-merges-an-untrusted-request-over-a-policy-requirement",
            resolver.resolve,
            [(
                "        if item.check_id in policy_required:",
                "        if False:",
            )],
            ENFORCE,
            "untrusted_request_can_only_ADD",
        ),
        (
            # A policy covering an action class with no requirement for it
            # resolves to the empty set, which anything satisfies.
            "policy-allows-a-covered-class-with-no-requirement",
            profile.VerificationPolicy.__post_init__,
            [(
                "        if not any(action_class in item.applies_to for item in items):",
                "        if False:",
            )],
            ENFORCE,
            "policy_covering_a_class_with_no_requirement",
        ),
        # -- coverage before fusion ----------------------------------------
        (
            # THE ORDER IS THE POINT. Fuse first and the missing check is a
            # question nobody was owed an answer to.
            "bank-fuses-without-validating-coverage",
            bank.VerifierBank.judge_covered,
            [(
                "    if isinstance(outcome, CoverageRefused):",
                "    if False:",
            )],
            REGRESS,
            "structural_pass_cannot_stand_in or swarm_matrix",
        ),
        (
            "coverage-treats-an-abstention-as-satisfactory",
            coverage._satisfactory,
            [(
                "    return outcome.decided == Verdict.PASS",
                "    return outcome.decided != Verdict.FAIL",
            )],
            ENFORCE,
            # This read "row_abstain or eight_state" and the second term was DEAD
            # from the start: the matrix lives in the regression file, not this
            # one, so pytest deselected it silently and the proof was half what
            # it claimed. Found by the term-level check in the pin test, not by
            # the count — which is the whole argument for checking terms.
            "row_abstain",
        ),
        (
            "coverage-stops-refusing-a-failed-required-check",
            coverage.validate_coverage,
            [("        if saw_fail:", "        if False:")],
            ENFORCE,
            "row_fail_refuses",
        ),
        (
            "coverage-stops-checking-the-snapshot-binding",
            coverage.validate_coverage,
            [("        if result.snapshot_digest != digest:", "        if False:")],
            ENFORCE,
            "row_wrong_attempt or row_wrong_policy or unrequired_result_with_a_bad_binding",
        ),
        (
            "coverage-accepts-an-implementation-the-policy-does-not-permit",
            coverage.validate_coverage,
            [(
                "        if permitted is not None and result.implementation not in permitted:",
                "        if False:",
            )],
            ENFORCE,
            "unpermitted_implementation",
        ),
        (
            "coverage-lets-a-duplicate-count-toward-coverage",
            coverage.validate_coverage,
            [("        if result.implementation in answered:", "        if False:")],
            ENFORCE,
            "row_duplicates",
        ),
        # -- the R3 line ----------------------------------------------------
        (
            # QUORUM WEARING THIS DESIGN'S CLOTHES: "two permitted, one
            # unavailable, therefore covered". This is the mutation the ruling
            # exists to forbid, and it must go red.
            "coverage-lets-absence-satisfy-a-requirement",
            coverage.validate_coverage,
            [(
                "        return CoverageRefused(\n"
                "            REFUSED_INCOMPLETE,\n"
                "            item.check_id,\n"
                '            "no permitted implementation produced a result for the required check",\n'
                "        )",
                "        answered_by[item.check_id] = \"<absent>\"\n"
                "        continue",
            )],
            ENFORCE,
            "r3_both_permitted_unavailable or r3_one_permitted_unavailable or row_missing",
        ),
        # -- the swarm as a caller ------------------------------------------
        (
            # Put the swarm's own aggregate back: report the executable outcome
            # under the SWARM's id, so it satisfies nothing the policy permits
            # and the plan decides coverage again.
            "swarm-reports-the-executable-check-under-its-own-identity",
            swarm_runtime.SwarmRuntime._verify,
            [(
                "                    self.code_verifier.verifier_id,",
                "                    self.verifier_id,",
            )],
            REGRESS,
            "swarm_matrix or positive_control",
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
