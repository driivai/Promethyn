"""Executed mutations for the authorization record and the pinned hold (TASK 5/6).

Each mutation removes one load-bearing join in memory, runs the behavioural
test that must fail, restores the function, and refuses count drift in either
direction. Six mutations: the two halves of the chain binding, the pinned
policy comparison, the invalidation write, the coverage report at minting, and
the execution row's record. As with the Checkpoint-B runner, this proves these
mutations are caught; it does not claim the set is complete.
"""

from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.pending import PendingActionService
from prometheus_protocol.verifier.bank import VerifierBank

import fix_b_revert_proofs as harness

RECORD = "tests/conformance/test_execution_authorization_record.py"
PINNING = "tests/conformance/test_hold_pinning.py"
EXPECTED_REVERTS = 6
EXPECTED_CALL_FAILURES = 14


def enforce_expected(caught: int, failures: int) -> None:
    if (caught, failures) != (EXPECTED_REVERTS, EXPECTED_CALL_FAILURES):
        raise AssertionError(
            f"record revert count drifted: {caught} mutations / {failures} call "
            f"failures observed, expected {EXPECTED_REVERTS} / "
            f"{EXPECTED_CALL_FAILURES}; shortfall and excess are both refused"
        )


def mutations():
    # FOUR spaces where the file shows eight: the runner reads inspect.getsource
    # of a METHOD and dedents it.
    return [
        (
            "chain-row-comparison-removed",
            PendingActionService._require_chain_binding,
            [("    if stored != pending.record:", "    if False:")],
            RECORD,
            "altered_pinned_requirement_set",
        ),
        (
            "chain-verification-removed",
            PendingActionService._require_chain_binding,
            [("    if not verification.ok:", "    if False:")],
            RECORD,
            "altered_chain_entry",
        ),
        (
            "pinned-policy-comparison-removed",
            PendingActionService._require_pinned_policy,
            [
                (
                    "    if self._pinned_to(pending, current):\n        return",
                    "    if True:\n        return",
                )
            ],
            PINNING,
            "superseded_policy_is_refused or weaker_policy",
        ),
        (
            "invalidation-write-removed",
            PendingActionService._invalidate,
            [
                (
                    "    self._ledger.invalidate_pending_action(",
                    "    return reason\n    self._ledger.invalidate_pending_action(",
                )
            ],
            PINNING,
            "superseded_policy_is_refused or explicit_rotation",
        ),
        (
            "coverage-report-dropped-at-mint",
            VerifierBank.assess,
            [
                (
                    "    return mint(expected, outcome, coverage=report)",
                    "    return mint(expected, outcome)",
                )
            ],
            RECORD,
            "persists_a_versioned_record or refused_by_a_real_coverage_row",
        ),
        (
            # No leading spaces: ``_execute`` writes the record at two sites
            # (the refused-claim row and the executed row) at different depths,
            # and the first attempt matched only the first, so the executed
            # path stayed unmutated and the "proof" was of nothing.
            "execution-row-record-dropped",
            ExecutionController._execute,
            [("authorization=record,", "authorization=None,")],
            RECORD,
            "auto_approved_execution_row or human_approved_execution_row",
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
