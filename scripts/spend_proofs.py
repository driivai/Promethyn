"""Executed mutation proofs for G24's spend, exclusively in MutationWorktree.

Every row disables one thing the spend does and names the proof in
``tests/conformance/test_spend_the_authorization.py`` that must go red for it.
Both attack classes are here, because a guard that survives only deletion has
been shown to catch a vandal and not a substitution:

  * DELETION — the spend check, the chained counterpart (leaving the row), the
    claim, the executor wall's consume, and the fold's out-of-order refusal;
  * CROSS-CONTEXT SUBSTITUTION — the key comparison made to compare a value
    against ITSELF, the re-attribution refusal removed so a spend record from a
    DIFFERENT occurrence passes as this one's, the auto-approved path excluded
    from the claim again (the original finding, re-introduced), and the
    occurrence's identity narrowed so a changed bound field reads as a retry.

A ROW MAY CARRY SEVERAL EDITS. "Exclude the auto-approved path from the claim
again" is two statements in ``controller.py``; splitting it into two rows would
measure two things neither of which is the finding.

SECOND ORDER, ON EVERY ROW. Each runs twice — as written, and with every
assert in the proof module replaced by ``pass``. What survives the second run
is carried by a ``pytest.raises`` or by an error, not by an assertion, and the
two are reported separately rather than summed.

WHAT DEFENCE IN DEPTH DOES TO THIS RUNNER, stated because it changed the
answers. The spend has two independent barriers — the READ (``retry_verdict``
over the chain fold) and the CLAIM (one INSERT against a PRIMARY KEY) — and
removing either alone leaves the other standing. So a row that deletes the read
does NOT redden the reproduction; it reddens the retry, which is the behaviour
only the read can provide. Each row below names the proof that its mutation
actually reaches, measured, rather than the proof it feels like it should.

Run with the repository's environment: python scripts/spend_proofs.py
"""

from __future__ import annotations

import ast
import re

from mutation_worktree import MutationWorktree

TESTS = "tests/conformance/test_spend_the_authorization.py"
SPEND = "src/prometheus_protocol/ledger/spend.py"
LEDGER = "src/prometheus_protocol/ledger/sqlite_ledger.py"
CONTROLLER = "src/prometheus_protocol/execution/controller.py"
POLICY = "src/prometheus_protocol/policy/execution.py"

#: ``(label, [(path, old, new), ...], selector)``.
MUTATIONS: tuple[tuple[str, tuple[tuple[str, str, str], ...], str], ...] = (
    # 1. THE SPEND CHECK, DELETED. The read is what turns a spent occurrence
    #    into a typed answer; with it gone the claim still refuses a replay, so
    #    what is lost is the RETRY — the one thing only the read can give.
    (
        "spend-check-deleted",
        (
            (
                SPEND,
                "    if not state.is_spent:\n        return MAY_EXECUTE\n",
                "    if True:\n        return MAY_EXECUTE\n",
            ),
        ),
        "test_a_declared_retry_with_a_matching_key_returns_the_PRIOR_result",
    ),
    # 2. THE CHAINED COUNTERPART REMOVED, THE ROW LEFT. §2's ruling made
    #    concrete: if the row were the authority this would change nothing.
    (
        "chain-entry-removed-row-kept",
        (
            (
                LEDGER,
                "        self.record_chained(\n"
                "            event=SPEND_EVENT,\n"
                "            subject=spend_subject(key),\n"
                "            payload=spend_payload(\n"
                "                key,\n"
                "                attempt_id=attempt_id,\n"
                "                idempotency_key=idempotency_key,\n"
                "                claimed_at=claimed_at,\n"
                "            ),\n"
                "            created_at=claimed_at,\n"
                "        )\n"
                "        return True\n",
                "        return True\n",
            ),
        ),
        "test_the_held_path_records_its_spend_under_the_SAME_derived_key",
    ),
    # 3. THE COMPARISON COMPARES A VALUE AGAINST ITSELF. The G25 shape, inside
    #    the key check: every key then "matches" and a replay is handed the
    #    prior result.
    (
        "key-compared-against-itself",
        (
            (
                SPEND,
                "    if idempotency_key != state.idempotency_key:\n",
                "    if idempotency_key != idempotency_key:\n",
            ),
        ),
        "test_each_way_a_claim_of_retry_fails_has_its_own_reason[key-does-not-match]",
    ),
    # 4. THE ORIGINAL FINDING, RE-INTRODUCED: the auto-approved path excluded
    #    from the claim, exactly as ``controller.py:367`` had it at 7cc2c4c.
    (
        "auto-approved-path-excluded-again",
        (
            (
                CONTROLLER,
                "        prior = self._settle_spend(\n",
                "        prior = None if pending_id is None else self._settle_spend(\n",
            ),
            (
                CONTROLLER,
                "        if not self._ledger.claim_authorization(\n",
                "        if pending_id is not None and not self._ledger.claim_authorization(\n",
            ),
        ),
        "test_the_same_auto_approved_occurrence_submitted_twice_executes_ONCE",
    ),
    # 5. THE RETRY PATH SKIPS THE DESCRIPTOR COMPARISON. It cannot be skipped
    #    directly — the comparison is structural, because the key IS the bound
    #    fields — so the mutation attacks the structure: narrow the occurrence's
    #    identity by one field.
    #
    #    THE PROOF IT REDDENS IS THE COMPOSITION PIN, NOT A BEHAVIOURAL ONE,
    #    and that is measured rather than chosen. ``resolve`` binds the
    #    artifact, target, action class and attempt into the snapshot, so
    #    ``snapshot_digest`` covaries with all six descriptor fields: with
    #    ``artifact_sha256`` removed, two occurrences differing in it STILL
    #    derive different keys and every behavioural proof stays green. Only a
    #    pin on the membership itself can see the narrowing — G25 exactly, a
    #    behaviour standing in for a composition.
    #    ``test_the_MEASURED_redundancy_snapshot_digest_already_covaries``
    #    records the measurement; if it ever reddens, this row's selector is
    #    wrong and a behavioural proof became available.
    (
        "occurrence-identity-narrowed",
        (
            (
                SPEND,
                '    "artifact_sha256",\n',
                "",
            ),
        ),
        "test_the_key_fields_are_the_DESCRIPTOR_plus_the_assessment_binding",
    ),
    # -- beyond the five the brief named ------------------------------------
    # 6. SUBSTITUTION, the second attack class: a spend record from a DIFFERENT
    #    occurrence re-attributed to this subject, and the fold no longer
    #    objects.
    (
        "re-attribution-refusal-deleted",
        (
            (
                SPEND,
                "        if payload.get(\"key\") != key:\n",
                "        if False:\n",
            ),
        ),
        "test_a_spend_record_from_a_DIFFERENT_attempt_is_detected",
    ),
    # 7. THE CLAIM, DELETED — the other half of the pair the read belongs to.
    #    Without it the read still refuses a replay, so what is lost is the
    #    atomicity, and the proof that reddens is the one that watches a loser
    #    refuse.
    (
        "claim-always-wins",
        (
            (
                LEDGER,
                "            self._conn.rollback()\n            return False\n",
                "            self._conn.rollback()\n",
            ),
        ),
        "test_the_claim_is_what_makes_it_atomic_a_second_claimant_loses",
    ),
    # 8. THE EXECUTOR WALL, DELETED. The in-process half: a retained decision
    #    handed straight to a concrete executor never passes a gateway, so the
    #    ledger spend cannot be what stops it.
    (
        "executor-wall-consume-deleted",
        (
            (
                POLICY,
                "    if getattr(authorization, _CONSUMED, False):\n",
                "    if False:\n",
            ),
        ),
        "test_a_retained_approved_decision_handed_to_an_executor_twice_runs_ONCE",
    ),
    # 9. THE OUT-OF-ORDER REFUSAL, DELETED. A completion with no open spend is
    #    a broken history; reading it as a completion invents a state.
    (
        "out-of-order-outcome-accepted",
        (
            (
                SPEND,
                "            if status != SPENT:\n",
                "            if False:\n",
            ),
        ),
        "test_an_outcome_entry_with_no_open_spend_is_a_broken_history",
    ),
    # 10. THE WINDOW, DISABLED. An expired credential silently honoured
    #     forever — the failure that leaves no trace in behaviour.
    (
        "retry-window-never-expires",
        (
            (
                SPEND,
                "    if _expired(state.claimed_at, now=now, window_seconds=window_seconds):\n",
                "    if False:\n",
            ),
        ),
        "test_a_matching_key_is_refused_once_the_retry_window_has_passed",
    ),
    # 11. THE WINDOW, FAIL-OPEN INSTEAD OF FAIL-CLOSED. An age that cannot be
    #     established read as fresh rather than as expired.
    (
        "unreadable-age-read-as-fresh",
        (
            (
                SPEND,
                "    if claimed_at is None:\n        return True\n",
                "    if claimed_at is None:\n        return False\n",
            ),
        ),
        "test_the_window_boundary_is_pinned_on_both_sides[no-claim-time-at-all]",
    ),
    # -- the three findings from the review of #127 -------------------------
    # 12. THE RELEASE'S ORDERING CHECK, DELETED — and this is the one that was
    #     REALLY MISSING until review found it, not a mutation of a guard that
    #     was already there. A release appended after a completion un-spends
    #     the occurrence, the chain still verifies, and the executor runs
    #     again.
    (
        "release-ordering-check-deleted",
        (
            (
                SPEND,
                "            if status != SPENT:\n"
                "                raise SpendRecordMalformed(\n"
                "                    f\"a chained {RELEASE_EVENT!r} entry under {subject!r} \"\n",
                "            if False:\n"
                "                raise SpendRecordMalformed(\n"
                "                    f\"a chained {RELEASE_EVENT!r} entry under {subject!r} \"\n",
            ),
        ),
        "test_a_release_cannot_UN_SPEND_a_completed_occurrence",
    ),
    # 13. THE EXECUTOR WALL'S CHECK-AND-SET, MADE NON-ATOMIC AGAIN. The lock
    #     replaced by a no-op context manager, so the two operations can
    #     interleave exactly as they did before.
    #
    #     CAUGHT STRUCTURALLY, NOT BEHAVIOURALLY, and that is measured rather
    #     than preferred. A thread test for this mutation ran GREEN, so the
    #     field was probed directly on unmutated-but-unlocked code: 32 threads
    #     from a barrier raced 0 of 400 trials at CPython's default 5ms switch
    #     interval and 9 of 400 at 1e-7 — about 1% per trial at every thread
    #     count tried. The race is real; a behavioural proof of it would miss
    #     its own guard's deletion ~99% of the time, which reads as a proof and
    #     is not one. The named test asserts the read and the write are inside
    #     the lock, derived from the AST, which this mutation reddens with
    #     certainty.
    (
        "consume-check-and-set-not-atomic",
        (
            (
                POLICY,
                "    with _CONSUME_LOCK:\n",
                "    with contextlib.nullcontext():\n",
            ),
            (
                POLICY,
                "import threading\n",
                "import contextlib\nimport threading\n",
            ),
        ),
        "test_the_check_and_set_in_consume_authorization_is_INSIDE_the_lock",
    ),
    # 14. THE UNRECORDED STDOUT, SILENTLY DEFAULTED. "Never recorded" and
    #     "printed nothing" collapse into the same bytes at the one point a
    #     caller reads them — doctrine #1.
    (
        "unrecorded-stdout-defaulted-to-empty",
        (
            (
                CONTROLLER,
                "                stdout=_STDOUT_NOT_RECORDED,\n",
                '                stdout="",\n',
            ),
        ),
        "test_a_returned_prior_result_NAMES_the_stdout_it_cannot_have",
    ),
)


class WithoutAssertions(ast.NodeTransformer):
    def visit_Assert(self, node: ast.Assert) -> ast.Pass:
        return ast.copy_location(ast.Pass(), node)


def run() -> int:
    # The count comes from the TABLE, printed by the runner, so no report has
    # to count labels in this log through a filter (doctrine #11, G53).
    print(
        f"rows: {len(MUTATIONS)} first-order, {2 * len(MUTATIONS)} runs including "
        "the assertions-deleted variants",
        flush=True,
    )
    survivors: list[str] = []
    with MutationWorktree(include_dirty=True) as tree:
        reds, summary = tree.pytest([TESTS])
        print(f"baseline: {summary}", flush=True)
        clean = re.fullmatch(r"(\d+) passed in [\d.]+s", summary)
        if reds or clean is None:
            raise RuntimeError("baseline did not pass; no mutation evidence collected")
        baseline_count = int(clean.group(1))
        for label, edits, selector in MUTATIONS:
            for stripped in (False, True):
                tree.revert()
                for path, old, new in edits:
                    tree.apply(path, old, new)
                if stripped:
                    original = (tree.path / TESTS).read_text()
                    weakened = (
                        ast.unparse(WithoutAssertions().visit(ast.parse(original))) + "\n"
                    )
                    tree.apply(TESTS, original, weakened)
                reds, summary = tree.pytest([TESTS])
                name = f"{label}{'-assertions-deleted' if stripped else ''}"
                print(f"{name}: {summary}", flush=True)
                for node in reds:
                    print(f"  RED {node}", flush=True)
                counts = re.fullmatch(r"(\d+) failed, (\d+) passed in [\d.]+s", summary)
                if stripped:
                    # The second-order run MAY be green: that means the row is
                    # caught only by an assert. It is reported, never failed
                    # on, and never summed with the first-order result.
                    if not reds:
                        survivors.append(label)
                    continue
                if not reds or counts is None:
                    raise RuntimeError(f"{label}: no valid red measurement")
                if int(counts.group(1)) + int(counts.group(2)) != baseline_count:
                    raise RuntimeError(
                        f"{label}: proof population changed from {baseline_count}"
                    )
                if not any(node.endswith("::" + selector) for node in reds):
                    raise RuntimeError(
                        f"{label}: the named proof {selector} did not redden; "
                        f"reds were {reds}"
                    )
    print(f"all {len(MUTATIONS)} rows caught first-order, each by its named proof", flush=True)
    print(
        f"second-order: {len(MUTATIONS) - len(survivors)} of {len(MUTATIONS)} rows "
        "still red with every assert deleted "
        f"(carried by raises/errors); assert-only rows: {sorted(survivors) or 'none'}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
