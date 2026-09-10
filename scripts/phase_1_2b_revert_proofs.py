"""Executed PHASE-1.2b guard reverts: reopen the bypass, in memory, and watch
the tests that must go red do so. Restore, and refuse any drift.

Same discipline and the same harness as the nine runners before it. A mutation
that produces no call-phase failure, or a run whose count differs from its pin
in EITHER direction, is itself a failure. Production files are never edited on
disk.

The mutations come in three families, matching what this sprint installed:

* **THE INTERFACE.** Each mutation puts back a parameter an unbound verdict can
  arrive through, or makes a surface read one when it gets it. This is the family
  that matters: the whole claim is that there is no parameter for it.
* **THE MINT GUARD.** Each mutation lets a ``PolicyAssessment`` be built without
  minting, or lets a copy inherit a live token — the ``dataclasses.replace``
  forge that worked before the token was consumed.
* **THE BINDING.** Each mutation lets an assessment resolved for one action
  authorize a different one, which is how a policy evaluation of a harmless
  migration would authorize a destructive one.

WHAT THIS DOES AND DOES NOT PROVE. It proves the pinned mutations still make
their tests go red — that these guards are load-bearing today. It does NOT prove
the mutation set is complete, and the count says nothing about semantic
coverage. Nor is it externally anchored: the runner, its pins and its mutation
list are editable in one change by whoever edits the code under test.

Run with the repository's test environment:
    python scripts/phase_1_2b_revert_proofs.py
"""

from prometheus_protocol.chokepoint import approval
from prometheus_protocol.execution import controller
from prometheus_protocol.gate import authorization
from prometheus_protocol.policy import assessment
from prometheus_protocol.verifier import bank

import fix_b_revert_proofs as harness

CLOSED = "tests/conformance/test_unbound_authorization_closed.py"
AGGREGATOR = "tests/conformance/test_no_second_aggregator.py"

#: Observed first, then pinned — never predicted. Both a shortfall and an excess
#: are refused.
EXPECTED_REVERTS = 7
EXPECTED_CALL_FAILURES = 10


def enforce_expected(caught: int, failures: int) -> None:
    if caught != EXPECTED_REVERTS or failures != EXPECTED_CALL_FAILURES:
        raise AssertionError(
            f"PHASE-1.2b revert count drifted: {caught} reverts / {failures} "
            f"call-phase failures observed, {EXPECTED_REVERTS} / "
            f"{EXPECTED_CALL_FAILURES} pinned. A proof was added, removed or "
            "stopped executing; update the pin in the same change that changes "
            "the mutation list, never alone."
        )


def mutations():
    """(name, function, [(old, new)], test file, -k selection)."""

    return [
        # -- the interface: no parameter for an unbound verdict --------------
        (
            # THE SPRINT, INVERTED. Accept whatever arrives and read a verdict
            # off it — which is exactly what the gate did before.
            "gate-reads-a-raw-judgment-again",
            authorization.ActionGate.decide,
            [(
                '    judgment = require_assessment(assessment, surface="ActionGate.decide").outcome',
                "    judgment = getattr(assessment, \"outcome\", assessment)",
            )],
            CLOSED,
            "presenting_one_anyway or no_approval_and_zero_executor_calls",
        ),
        (
            # The migration authority: the fourth surface, and the one that
            # mints a signed capability against a privileged principal.
            "migration-authority-accepts-a-raw-judgment",
            approval.ApprovalAuthority.authorize,
            [(
                "    checked = require_assessment(\n"
                "        assessment, surface=\"ApprovalAuthority.authorize\"\n"
                "    )",
                "    checked = assessment",
            )],
            CLOSED,
            "migration_authority_mints_no_capability",
        ),
        # -- the binding: an assessment is for ONE action --------------------
        (
            "migration-authority-stops-checking-the-artifact",
            approval.ApprovalAuthority.authorize,
            [(
                "    if not hmac.compare_digest(checked.artifact_sha256, artifact.sha256):",
                "    if False:",
            )],
            CLOSED,
            "DIFFERENT_action_mints_no_capability",
        ),
        (
            "migration-authority-stops-checking-the-action-class",
            approval.ApprovalAuthority.authorize,
            [(
                "    if checked.action_class != ACTION_DATABASE_MIGRATE:",
                "    if False:",
            )],
            CLOSED,
            "DIFFERENT_ACTION_CLASS_mints_no_capability",
        ),
        # -- the mint guard --------------------------------------------------
        (
            # The token is what makes an accidental assessment impossible.
            "assessment-can-be-constructed-directly",
            assessment.PolicyAssessment.__post_init__,
            [("    if self._minted is not _MINT:", "    if False:")],
            CLOSED,
            "direct_construction_is_refused",
        ),
        (
            # THE MEASURED ONE. Before the token was consumed,
            # ``dataclasses.replace`` minted a valid-looking assessment carrying
            # an outcome coverage never validated. Putting the live token back is
            # that forge, restored.
            "replace-inherits-a-live-minting-token",
            assessment.PolicyAssessment.__post_init__,
            [('    object.__setattr__(self, "_minted", None)', "    pass")],
            CLOSED,
            "copying_a_real_one_is_refused",
        ),
        # -- the bank is the only minter -------------------------------------
        (
            # Not the bypass itself: the capability that would reopen it. A
            # production module able to mint can authorize around any verdict.
            "the-bank-mints-without-validating-coverage",
            bank.VerifierBank.assess,
            [(
                "    return mint(snapshot, self.judge_covered(snapshot, results))",
                "    from prometheus_protocol.core.models import Judgment, Verdict\n"
                "    return mint(snapshot, Judgment(\n"
                "        verdict=Verdict.PASS, confidence=1.0, authoritative=True))",
            )],
            CLOSED,
            "refused_coverage_still_refuses",
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
