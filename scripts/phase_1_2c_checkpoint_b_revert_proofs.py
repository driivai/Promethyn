"""Executed Checkpoint-B mutations for the single execution-descriptor seam.

Each mutation removes one load-bearing join, runs the behavioural test that must
fail, restores the function in memory, and refuses count drift in either
direction.  This proves these five mutations are caught; it does not claim the
mutation set is complete and is not an external integrity anchor.
"""

from prometheus_protocol.execution.pending import PendingActionService
from prometheus_protocol.policy.execution import ExecutionAuthorizer
from prometheus_protocol.runtime.factory import build_execution_controller
from prometheus_protocol.verifier.bank import VerifierBank

import fix_b_revert_proofs as harness

TEST = "tests/conformance/test_execution_descriptor.py"
EXPECTED_REVERTS = 6
EXPECTED_CALL_FAILURES = 7


def enforce_expected(caught: int, failures: int) -> None:
    if (caught, failures) != (EXPECTED_REVERTS, EXPECTED_CALL_FAILURES):
        raise AssertionError(
            f"Checkpoint-B revert count drifted: {caught} mutations / {failures} "
            f"call failures observed, expected {EXPECTED_REVERTS} / "
            f"{EXPECTED_CALL_FAILURES}; shortfall and excess are both refused"
        )


def mutations():
    return [
        (
            "re-resolve-replaced-by-redigest",
            VerifierBank.assess,
            [
                (
                    """    policy = self._policy_supplier()
    expected = resolve(
        policy,
        artifact_sha256=snapshot.artifact_sha256,
        target_canonical=snapshot.target_canonical,
        action_class=snapshot.action_class,
        attempt_id=snapshot.attempt_id,
    )
    if snapshot_digest(expected) != snapshot_digest(snapshot):
        raise ExecutionNotAuthorized(
            "snapshot differs from requirements re-resolved from selected policy"
        )""",
                    """    expected = snapshot
    snapshot_digest(expected)""",
                )
            ],
            TEST,
            "honestly_redigested_weakened",
        ),
        (
            "action-class-comparison-removed",
            ExecutionAuthorizer.authorize_context,
            [
                (
                    '        "action_class",\n',
                    "",
                )
            ],
            TEST,
            "cross_action_mismatch",
        ),
        (
            "attempt-id-comparison-removed",
            ExecutionAuthorizer.authorize_context,
            [('        "attempt_id",\n', "")],
            TEST,
            "cross_action_mismatch",
        ),
        (
            "hold-admission-check-removed",
            PendingActionService.hold,
            [
                (
                    "    if not isinstance(authorization, AuthorizedExecution):",
                    "    if False:",
                )
            ],
            TEST,
            "hold_admission_refuses",
        ),
        (
            "hold-policy-re-resolution-removed",
            ExecutionAuthorizer.revalidate,
            [
                (
                    "    d = authorization.descriptor",
                    "    return authorization\n    d = authorization.descriptor",
                )
            ],
            TEST,
            "hold_approval_re_resolves",
        ),
        (
            "selected-profile-injection-unwired",
            build_execution_controller,
            [
                (
                    "lambda: build_verification_policy(config)",
                    "lambda: build_verification_policy(Config())",
                ),
                (
                    "build_verification_policy(config)",
                    "build_verification_policy(Config())",
                ),
            ],
            TEST,
            "unknown_selected_profile or nonbaseline_profile_is_injected",
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
