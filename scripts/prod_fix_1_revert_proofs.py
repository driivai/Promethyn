"""Executed PROD-FIX-1 guard reverts: put each fix back the way it was, in
memory, run the tests that must go red, restore, and refuse any drift.

Same discipline and the same harness as the F11, PROM-FIX-B, substrate, PIH-4a
and TYPE-GATE runners: a mutation that produces no call-phase failure, or a run
whose count differs from its pin in EITHER direction, is itself a failure.
Production files are never edited on disk.

The three fixes this covers, and what each mutation reintroduces:

* **F7 (approval expiry across an unbounded preparation interval).** Each
  mutation removes one admission boundary, or one rule of the clock model, and
  the phase table in ``test_approval_expiry_across_preparation.py`` must catch
  it. Removing the wall-clock arm, the elapsed arm, the sampling ORDER, the
  fixed-deadline rule, or either executor boundary are all separate mutations,
  because each was named as a fix that would NOT close F7 on its own.
* **P-1 (equal-time attestations ordered by digest).** The mutations restore
  ``records[-1]`` and disable the ambiguity refusal.
* **P-2 (Unicode hostnames escaping the transport taxonomy).** The mutations
  remove the normalisation and the malformed-name refusal.

WHAT THIS DOES AND DOES NOT PROVE. It proves the pinned mutations still make
their tests go red — that these guards are load-bearing today. It does NOT prove
the mutation set is complete, and the count says nothing about semantic
coverage. Nor is it externally anchored: the runner, its pins and its mutation
list are editable in one change by whoever edits the code under test.

Run with the repository's test environment:
    python scripts/prod_fix_1_revert_proofs.py
"""

from prometheus_protocol.attestation import attest
from prometheus_protocol.chokepoint import admission, runner
from prometheus_protocol.core import endpoint

import fix_b_revert_proofs as harness

F7 = "tests/chokepoint/test_approval_expiry_across_preparation.py"
P1 = "tests/conformance/test_attestation_chronology.py"
P2 = "tests/conformance/test_unicode_hostname_taxonomy.py"

#: Observed first, then pinned — never predicted. Both a shortfall and an excess
#: are refused: a runner that quietly stops executing proofs would print a
#: smaller number and exit 0, and one that starts catching unrelated failures is
#: no longer measuring what it claims to.
EXPECTED_REVERTS = 14
EXPECTED_CALL_FAILURES = 23


def enforce_expected(caught: int, failures: int) -> None:
    if caught != EXPECTED_REVERTS or failures != EXPECTED_CALL_FAILURES:
        raise AssertionError(
            f"PROD-FIX-1 revert count drifted: {caught} reverts / {failures} "
            f"call-phase failures observed, {EXPECTED_REVERTS} / "
            f"{EXPECTED_CALL_FAILURES} pinned. A proof was added, removed or "
            "stopped executing; update the pin in the same change that changes "
            "the mutation list, never alone."
        )


def mutations():
    """(name, function, [(old, new)], test file, -k selection)."""

    return [
        # -- F7: the admission boundaries --------------------------------------
        (
            # The review's own reproduction: sample once, never look again.
            "runner-stops-checking-before-the-executor",
            runner.BrokeredMigrationRunner._execute_owned,
            [(
                "    admission = deadline.admit()\n"
                "    if not admission.admitted:\n"
                "        outcome = self._record(",
                "    admission = admission_always_ok()\n"
                "    if not admission.admitted:\n"
                "        outcome = self._record(",
            )],
            F7,
            "reviews_reproduction or after_the_durable_intent or terminal_append",
        ),
        (
            "runner-stops-checking-before-the-nonce-claim",
            runner.BrokeredMigrationRunner._execute_owned,
            [(
                "    admission = deadline.admit()\n"
                "    if not admission.admitted:\n"
                "        audit = self._record(\n"
                '            "refuse",\n'
                "            self._target.identity.canonical,\n"
                "            {\n"
                '                "phase": "expiry_before_spend",',
                "    admission = admission_always_ok()\n"
                "    if not admission.admitted:\n"
                "        audit = self._record(\n"
                '            "refuse",\n'
                "            self._target.identity.canonical,\n"
                "            {\n"
                '                "phase": "expiry_before_spend",',
            )],
            F7,
            "before_the_nonce_claim or reviews_reproduction",
        ),
        (
            "runner-stops-checking-after-the-nonce-claim",
            runner.BrokeredMigrationRunner._execute_owned,
            [(
                "    admission = deadline.admit()\n"
                "    if not admission.admitted:\n"
                "        audit = self._record(\n"
                '            "refuse",\n'
                "            self._target.identity.canonical,\n"
                "            {\n"
                '                "phase": "expiry_after_spend",',
                "    admission = admission_always_ok()\n"
                "    if not admission.admitted:\n"
                "        audit = self._record(\n"
                '            "refuse",\n'
                "            self._target.identity.canonical,\n"
                "            {\n"
                '                "phase": "expiry_after_spend",',
            )],
            F7,
            "after_the_claim_keeps_the_nonce_spent",
        ),
        (
            # BOUNDARY 2a. A runner-side check alone does not establish that no
            # privileged contact happens after expiry — this is the mutation
            # that proves it.
            "executor-opens-a-connection-after-expiry",
            runner.postgres_executor,
            [(
                "    if deadline is not None:\n"
                "        admission = deadline.admit()\n"
                "        if not admission.admitted:\n"
                "            return ExecutorResult(\n"
                "                EXECUTION_NOT_ATTEMPTED,\n"
                '                f"approval not admissible ({admission.reason}); no credential "',
                "    if False:\n"
                "        admission = deadline.admit()\n"
                "        if not admission.admitted:\n"
                "            return ExecutorResult(\n"
                "                EXECUTION_NOT_ATTEMPTED,\n"
                '                f"approval not admissible ({admission.reason}); no credential "',
            )],
            F7,
            "boundary_2a",
        ),
        (
            # BOUNDARY 2b. Both advisory locks BLOCK; without the recheck a lock
            # that blocked past the deadline authors bootstrap DDL anyway.
            "executor-writes-bootstrap-ddl-after-the-locks-blocked-past-expiry",
            runner.postgres_executor,
            [(
                "            if deadline is not None:\n"
                "                admission = deadline.admit()\n"
                "                if not admission.admitted:\n"
                "                    return ExecutorResult(\n"
                "                        EXECUTION_NOT_ATTEMPTED,\n"
                '                        f"approval not admissible after acquiring the execution "',
                "            if False:\n"
                "                admission = deadline.admit()\n"
                "                if not admission.admitted:\n"
                "                    return ExecutorResult(\n"
                "                        EXECUTION_NOT_ATTEMPTED,\n"
                '                        f"approval not admissible after acquiring the execution "',
            )],
            F7,
            "boundary_2b or lock_timeout_from_the_remaining_budget",
        ),
        # -- F7: the clock model ------------------------------------------------
        (
            # Wall-clock-only is insufficient: a backward step extends the
            # invocation. Removing the elapsed arm must be caught.
            "clock-drops-the-elapsed-arm",
            admission.ExecutionDeadline.admit,
            [("    if elapsed_remaining <= 0:", "    if False:")],
            F7,
            "backward_wall_step or deadline_is_fixed_once",
        ),
        (
            # Elapsed-only is insufficient: a forward step lets an approval that
            # is genuinely expired run.
            "clock-drops-the-wall-arm",
            admission.ExecutionDeadline.admit,
            [("    if wall_remaining <= 0:", "    if False:")],
            F7,
            "forward_wall_step or reviews_reproduction or before_the_nonce_claim",
        ),
        (
            # THE SAMPLING ORDER. Sampling wall first puts a pause into the
            # elapsed reading, which moves the deadline later while the budget
            # stays large — the pause would ENLARGE the invocation.
            "clock-samples-the-wall-clock-first",
            # ``open`` is a classmethod: the harness swaps ``__code__`` on the
            # underlying function, not on the bound descriptor.
            admission.ExecutionDeadline.open.__func__,
            [(
                "    opened_elapsed = read_elapsed()\n"
                "    opened_wall = _finite(clock(), name=\"now\")",
                "    opened_wall = _finite(clock(), name=\"now\")\n"
                "    opened_elapsed = read_elapsed()",
            )],
            F7,
            "sampled_before_the_wall_clock",
        ),
        (
            "clock-drops-the-declared-uncertainty",
            admission.ExecutionDeadline.admit,
            [("    if remaining <= self.uncertainty_s:", "    if False:")],
            F7,
            "inside_the_declared_clock_uncertainty",
        ),
        (
            # Two local clocks do not repair untrusted UTC.
            "clock-pretends-untrusted-utc-is-usable",
            # ``open`` is a classmethod: the harness swaps ``__code__`` on the
            # underlying function, not on the bound descriptor.
            admission.ExecutionDeadline.open.__func__,
            [("    if not trust_utc:", "    if False:")],
            F7,
            "untrusted_utc or runner_refuses_when_utc",
        ),
        (
            # PostgreSQL: statement_timeout = 0 DISABLES the timeout, so a
            # positive budget must never round down to zero.
            "timeout-rounds-a-positive-budget-down-to-zero",
            admission.timeout_ms,
            [(
                "    return max(MINIMUM_TIMEOUT_MS, min(int(remaining_s * 1000), cap_ms))",
                "    return min(int(remaining_s * 1000), cap_ms)",
            )],
            F7,
            "never_becomes_an_unlimited_timeout",
        ),
        # -- P-1: the equal-time ambiguity ---------------------------------------
        (
            # The finding itself: records[-1] as "the newest", on a target whose
            # order comes from a clock reading.
            "verifier-takes-the-last-listed-record-again",
            attest.verify_attestation,
            [(
                "        selected, ambiguity = newest_record(records)",
                "        selected, ambiguity = (records[-1], \"\")",
            )],
            P1,
            "refuses_rather_than_comparing or rollback_to_an_older_posture",
        ),
        (
            "ambiguity-is-resolved-instead-of-refused",
            attest.newest_record,
            [("    if len(distinct) > 1:", "    if False:")],
            P1,
            "refuses_only_a_genuine_ambiguity or rollback_to_an_older_posture",
        ),
        # -- P-2: the hostname taxonomy hole -------------------------------------
        (
            "endpoint-stops-normalizing-the-hostname",
            endpoint.validate_endpoint,
            [(
                "    host = normalize_host(parts.hostname, name=name)",
                "    host = parts.hostname",
            )],
            P2,
            "normalized_at_endpoint_construction or dns_and_tls or refusal_happens_at_construction",
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
