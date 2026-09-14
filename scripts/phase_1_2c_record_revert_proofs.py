"""Executed mutations for the authorization record and the pinned hold (TASK 5/6).

Each mutation removes one load-bearing join in memory, runs the behavioural
test that must fail, restores the function, and refuses count drift in either
direction. Seven mutations: the two halves of the chain binding's CHECK, the
binding's WRITE, the pinned policy comparison, the invalidation write, the
coverage report at minting, and the execution row's record. As with the
Checkpoint-B runner, this proves these mutations are caught; it does not claim
the set is complete.
"""

from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.pending import PendingActionService
from prometheus_protocol.verifier.bank import VerifierBank

import fix_b_revert_proofs as harness

RECORD = "tests/conformance/test_execution_authorization_record.py"
PINNING = "tests/conformance/test_hold_pinning.py"
EXPECTED_REVERTS = 7
#: PHASE-1.2c FINAL — 14 -> 15. The sixth refusing-coverage row
#: (``coverage.ambiguous``) adds one parametrisation to
#: ``refused_by_a_real_coverage_row``, so "coverage-report-dropped-at-mint"
#: reddens six tests where it reddened five. No mutation changed, and no
#: mutation's SELECTION changed; one more test stands behind one of them.
#:
#: CLOSE-OUT — 15 -> 18. "chain-append-removed-at-hold" is the seventh
#: mutation and reddens three tests: the altered-requirements detection, the
#: no-chain-entry refusal, and the binding's own structural test.
EXPECTED_CALL_FAILURES = 18


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
            # 1a's RULING, mutated rather than argued. The two above disable the
            # CHECK at approval; this removes the BINDING at write time — the
            # record still goes into pending_actions.authorization, it just
            # never reaches the chain. If the detection survived that, it would
            # be keyed on something other than the binding and 1a would not be
            # closed whatever the test is called.
            #
            # It does not survive: the refusal changes from "does not match its
            # tamper-evident chain entry" to "has 0 tamper-evident chain
            # entries", and the test's ``match=`` refuses the substitution.
            # Measured second-order, because that is a thin thread to hang a
            # ruling on: with the SAME mutation and the ``match=`` dropped, the
            # test goes GREEN — approval still refuses, just not for this
            # reason. So the string is load-bearing, and
            # ``test_the_hold_record_is_bound_into_the_audit_chain_under_the_holds_identity``
            # now asserts the entry structurally as well, so the proof does not
            # rest on one literal.
            "chain-append-removed-at-hold",
            PendingActionService.hold,
            [
                (
                    "    self._ledger.record_chained(\n"
                    "        event=PINNED_HOLD_EVENT,\n"
                    "        subject=_hold_subject(pending_id),\n"
                    "        payload=record,\n"
                    "        created_at=created,\n"
                    "    )",
                    "    pass",
                )
            ],
            RECORD,
            "altered_pinned_requirement_set or no_chain_entry or bound_into_the_audit_chain",
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
