"""Executed PIH-4a guard reverts: mutate each attestation guard in memory, run
the tests that must go red, restore, and refuse a shortfall against the pins.

Same discipline and the same harness as the F11, PROM-FIX-B and substrate
runners: a mutation that produces no call-phase failure, or a run that executes
fewer reversions than pinned, is itself a failure. Production files are never
edited.

Run with the repository's test environment: python scripts/pih4a_revert_proofs.py
"""

from prometheus_protocol.attestation import attest, posture, runtime
from prometheus_protocol.core import config as core_config

import fix_b_revert_proofs as harness

TESTS = "tests/conformance/test_config_attestation.py"

#: Observed, then pinned — never the other way round.
EXPECTED_REVERTS = 12
EXPECTED_CALL_FAILURES = 18


def enforce_expected(caught: int, failures: int) -> None:
    if caught != EXPECTED_REVERTS or failures != EXPECTED_CALL_FAILURES:
        raise AssertionError(
            f"PIH-4a revert count drifted: {caught} / {failures} observed; "
            f"{EXPECTED_REVERTS} / {EXPECTED_CALL_FAILURES} pinned. Update the "
            "pin in the same change that changes the mutation list, never alone."
        )


def mutations():
    """(name, function, [(old, new)], test file, -k selection)."""

    return [
        # -- the digest covers the RESOLVED posture, encoded unambiguously ----
        (
            "digest-ignores-a-covered-field",
            posture.posture_preimage,
            [("    for name in POSTURE_FIELDS:",
              "    for name in POSTURE_FIELDS[:-1]:")],
            TESTS,
            "changing_any_covered_field or no_two_covered_postures or known_answer",
        ),
        (
            "digest-drops-the-field-name",
            posture.posture_preimage,
            [('        parts.append(_lp(name.encode("ascii")))', "        pass")],
            TESTS,
            "known_answer",
        ),
        (
            "digest-drops-the-length-prefix",
            posture.posture_preimage,
            [("        parts.append(_lp(encode_value(getattr(posture, name))))",
              "        parts.append(encode_value(getattr(posture, name)))")],
            TESTS,
            "typed_and_length_prefixed or known_answer",
        ),
        (
            "encoding-loses-its-type-tag",
            posture.encode_value,
            [("        return _TAG_BOOL + (b\"\\x01\" if value else b\"\\x00\")",
              "        return _TAG_INT + int(value).to_bytes(8, \"big\", signed=True)")],
            TESTS,
            "typed_and_length_prefixed or known_answer",
        ),
        (
            "encoding-stringifies-the-unencodable",
            posture.encode_value,
            [('    raise TypeError(f"no canonical encoding for {type(value).__name__} in a posture")',
              "    return _TAG_STR + str(value).encode()")],
            TESTS,
            "typed_and_length_prefixed",
        ),
        # -- resolved, not declared: the load-bearing property ----------------
        (
            "posture-reports-the-declared-sandbox",
            runtime.resolve_posture,
            [("        sandbox_adapter=sandbox.name,",
              "        sandbox_adapter=config.sandbox,")],
            TESTS,
            "resolving_weaker",
        ),
        (
            "posture-reports-the-declared-anchor-instead-of-the-resolved-class",
            runtime.resolve_posture,
            [("        anchor_append_only=bool(getattr(anchor, \"append_only\", False)) if anchor else False,",
              "        anchor_append_only=bool(config.ledger_anchor),")],
            TESTS,
            "non_protecting_file_is_a_different_posture",
        ),
        (
            "posture-ignores-the-signer-in-use",
            runtime.resolve_posture,
            [('        signer_external=bool(getattr(signer, "external", False)),',
              "        signer_external=bool(config.require_external_signer),")],
            TESTS,
            "signer_actually_in_use",
        ),
        # -- the verdicts stay honest ----------------------------------------
        (
            "unverifiable-reported-as-attested",
            attest.verify_attestation,
            [('    if not verifier.verify(record.message, record.signature):', "    if False:")],
            TESTS,
            "tampered_record_is_not_verifiable",
        ),
        (
            "mismatch-reported-as-attested",
            attest.verify_attestation,
            [("    if live != record.digest:", "    if False:")],
            TESTS,
            "silent_flip or mismatch",
        ),
        # -- publish failure is not swallowed ---------------------------------
        (
            "failed-publish-swallowed",
            attest.ConfigAttestor._fail,
            # inspect.getsource dedents a method to its own level.
            [("    if self._required:", "    if False:")],
            TESTS,
            "fail_closed_under_the_requirement or cannot_sign",
        ),
        # -- the local-only target is refused under the requirement -----------
        (
            "local-only-target-accepted-under-the-requirement",
            core_config.Config.__post_init__,
            [("        if attestation.kind == ANCHOR_FILE:", "        if False:")],
            TESTS,
            "local_only_target_is_refused",
        ),
    ]


def main() -> int:
    saved = (harness.mutations, harness.enforce_expected,
             harness.EXPECTED_REVERTS, harness.EXPECTED_CALL_FAILURES)
    try:
        harness.mutations = mutations
        harness.enforce_expected = enforce_expected
        harness.EXPECTED_REVERTS = EXPECTED_REVERTS
        harness.EXPECTED_CALL_FAILURES = EXPECTED_CALL_FAILURES
        return harness.main()
    finally:
        (harness.mutations, harness.enforce_expected,
         harness.EXPECTED_REVERTS, harness.EXPECTED_CALL_FAILURES) = saved


if __name__ == "__main__":
    raise SystemExit(main())
