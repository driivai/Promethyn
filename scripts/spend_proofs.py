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
MODELS = "src/prometheus_protocol/swarm/models.py"
EXECUTOR = "src/prometheus_protocol/execution/executor.py"
GIT = "src/prometheus_protocol/tools/git.py"
START_SIGNAL = "tests/conformance/test_execution_start_signal.py"

#: ``(label, [(path, old, new), ...], selector)`` or, where the proof lives in
#: a different module, ``(label, edits, selector, module)``.
#:
#: THE MODULE IS PART OF THE ROW because a runner bound to one test file can
#: only pin proofs that happen to live there, and the fail-open harness-fact
#: rows below are proved in ``test_execution_start_signal.py`` — the module
#: that owns those two flags. Each distinct module gets its OWN clean baseline
#: and its own stripped baseline, established before any mutation is applied;
#: a module whose stripped baseline is red has no second-order control and the
#: run refuses rather than reporting a figure it did not measure.
MUTATIONS: tuple[tuple, ...] = (
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
    # 9. THE OUT-OF-ORDER REFUSAL, WIDENED AWAY. A completion with no open
    #    spend is a broken history; reading it as a completion invents a state.
    #    Expressed against the transition table, which is where the ordering
    #    rules now live for all three events rather than in three branches.
    (
        "out-of-order-outcome-accepted",
        (
            (
                SPEND,
                "    SPEND_OUTCOME_EVENT: frozenset({SPENT}),\n",
                "    SPEND_OUTCOME_EVENT: frozenset({SPENT, UNSPENT, COMPLETED, RELEASED}),\n",
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
                "    RELEASE_EVENT: frozenset({SPENT}),\n",
                "    RELEASE_EVENT: frozenset({SPENT, COMPLETED}),\n",
            ),
        ),
        "test_a_release_cannot_UN_SPEND_a_completed_occurrence",
    ),
    # 12b. THE SPEND'S OWN ORDERING, WIDENED — the second review's finding. A
    #      re-claim permitted from COMPLETED is what turned a reset mutex row
    #      into a forged open spend and made the guarded release legal again.
    (
        "spend-permitted-after-a-completion",
        (
            (
                SPEND,
                "    SPEND_EVENT: frozenset({UNSPENT, RELEASED}),\n",
                "    SPEND_EVENT: frozenset({UNSPENT, RELEASED, COMPLETED}),\n",
            ),
        ),
        "test_resetting_the_row_and_RE_CLAIMING_does_not_reopen_the_release",
    ),
    # 12c. THE TABLE BYPASSED ENTIRELY. The lookup is what makes forgetting a
    #      branch inexpressible; removing it restores three-checks-by-hand with
    #      none of them present.
    (
        "transition-table-not-consulted",
        (
            (
                SPEND,
                "        allowed = _PERMITTED_FROM[event]\n        if status not in allowed:\n",
                "        allowed = _PERMITTED_FROM[event]\n        if False:\n",
            ),
        ),
        "test_every_sequence_of_three_events_is_permitted_or_refused_by_the_TABLE[completed-then-reclaimed]",
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
    # 14. THE UNRECORDED STDOUT, REPORTED AS RECORDED. "Never recorded" and
    #     "printed nothing" collapse at the one point a caller reads them —
    #     doctrine #1. The signal is OUT OF BAND after the second review: a
    #     sentence in ``stdout`` is one a candidate can print verbatim, so the
    #     availability is its own field and this row flips that field.
    (
        "unrecorded-stdout-defaulted-to-empty",
        (
            (
                CONTROLLER,
                "                stdout_recorded=False,\n",
                "                stdout_recorded=True,\n",
            ),
        ),
        "test_a_returned_prior_result_NAMES_the_stdout_it_cannot_have",
    ),
    # 15. THE FLAG DEFAULTED FAIL-OPEN AGAIN — the third review's finding. Of
    #     ELEVEN ``ExecutionResult`` constructions only two capture output;
    #     with a ``True`` default the other nine tell a consumer the empty
    #     string is the program's own.
    (
        "stdout-recorded-defaults-fail-open",
        (
            (
                MODELS,
                "    stdout_recorded: bool = False\n",
                "    stdout_recorded: bool = True\n",
            ),
        ),
        "test_the_flag_defaults_to_the_fail_closed_answer",
    ),
    # 16. A REFUSAL CLAIMING IT CAPTURED. The population rule from the other
    #     side: a site that records nothing must not say it did.
    (
        "a-refusal-claims-it-captured-output",
        (
            (
                EXECUTOR,
                "            sandbox_name=self._sandbox.name,\n"
                "            exit_status=None,\n"
                '            stdout="",\n'
                "        )\n",
                "            sandbox_name=self._sandbox.name,\n"
                "            exit_status=None,\n"
                '            stdout="",\n'
                "            stdout_recorded=True,\n"
                "        )\n",
            ),
        ),
        "test_only_a_site_that_CAPTURES_output_may_claim_it_recorded_it",
    ),
    # ---- THE SAME CLASS ON THE TWO FLAGS #130's OWN ENTRY NAMED -----------
    #
    # ``stdout_recorded`` was flipped fail-closed; ``started_ok`` and
    # ``candidate_started`` — named as "two facts" one paragraph above in the
    # same docstring — were left defaulting ``True``. Measured before the fix:
    # ``started_ok`` inherited at 6 of 11 constructions, ``candidate_started``
    # at 9 of 11, and 9 of 13 ``_refuse`` calls inherited at least one. These
    # rows restore each half of the defect.
    #
    # 17. THE CLASS DEFAULTS, FLIPPED FAIL-OPEN AGAIN.
    (
        "harness-facts-default-fail-open",
        (
            (
                MODELS,
                # Re-stated after the flags became keyword-only (#131, third
                # review round). The runner REFUSED the old string rather than
                # running a mutation that would not apply, which is the whole
                # point of the drift check: this row would otherwise have gone
                # on reporting a caught defect it never planted.
                "    started_ok: bool = field(default=False, kw_only=True)\n"
                "    candidate_started: bool = field(default=False, kw_only=True)\n",
                "    started_ok: bool = field(default=True, kw_only=True)\n"
                "    candidate_started: bool = field(default=True, kw_only=True)\n",
            ),
        ),
        "test_the_two_harness_flags_default_to_the_fail_closed_answer",
        START_SIGNAL,
    ),
    # 18. THE REFUSAL HELPER'S DEFAULTS, RESTORED TO THE PERMISSIVE VALUE.
    #     Four of this module's six ``_refuse`` calls are refusals taken
    #     BEFORE the sandbox is constructed, and every one inherited these.
    (
        "refusal-helper-claims-what-it-never-observed",
        (
            (
                EXECUTOR,
                "        started_ok: bool = False,\n        candidate_started: bool = False,\n",
                "        started_ok: bool = True,\n        candidate_started: bool = True,\n",
            ),
        ),
        "test_a_refusal_taken_BEFORE_the_sandbox_claims_neither_harness_fact",
        START_SIGNAL,
    ),
    # 19. THE SAME, MEASURED AT THE AUDIT LEDGER rather than at the executor's
    #     return value — the consequential half, since the controller persists
    #     both flags into the ``executions`` table.
    (
        "refusal-claims-reach-the-audit-ledger",
        (
            (
                EXECUTOR,
                "        started_ok: bool = False,\n        candidate_started: bool = False,\n",
                "        started_ok: bool = True,\n        candidate_started: bool = True,\n",
            ),
        ),
        "test_the_refusal_reaches_the_AUDIT_LEDGER_claiming_nothing",
        START_SIGNAL,
    ),
    # 20. A HAND-WRITTEN CLAIM WHERE A MEASUREMENT BELONGS. The shape rule has
    #     no allowlist: a literal ``True`` is a claim nothing measured, and the
    #     site restored here is the git dry-run, which constructs no sandbox.
    (
        "a-literal-claim-replaces-a-measurement",
        (
            (
                GIT,
                "                refused=False,\n                # NOTHING RAN.",
                "                refused=False,\n                started_ok=True,\n                # NOTHING RAN.",
            ),
        ),
        "test_no_site_may_claim_a_harness_fact_it_did_not_MEASURE",
        START_SIGNAL,
    ),
    # 21. THE REPLAY DROPS THE STORED FACTS AGAIN. A row whose columns are
    #     NULL — no executor invoked — read back as the class default.
    (
        "replay-discards-the-stored-harness-facts",
        (
            (
                CONTROLLER,
                '                started_ok=bool(row["started_ok"]),\n'
                '                candidate_started=bool(row["candidate_started"]),\n',
                "",
            ),
        ),
        "test_the_replay_carries_the_STORED_harness_facts_not_a_default",
        START_SIGNAL,
    ),
    # 22. THE PASS-THROUGH'S PREMISE, REMOVED. ``started_ok=started_ok`` is a
    #     measurement only because the parameter it forwards defaults to the
    #     fail-closed answer; flip that default and every call-site SHAPE is
    #     unchanged, the census is unchanged, and every pre-sandbox refusal
    #     claims isolation started again. The second #131 review found that the
    #     rule accepted the pass-through on its SPELLING, so this mutation was
    #     green. It is a row now because the premise lives in a different
    #     statement from the claim that rests on it, which is how it went
    #     unnoticed the first time.
    (
        "pass-through-parameter-default-flipped-fail-open",
        (
            (
                GIT,
                "        started_ok: bool = False,\n"
                "        candidate_started: bool = False,\n",
                "        started_ok: bool = True,\n"
                "        candidate_started: bool = True,\n",
            ),
        ),
        "test_no_site_may_claim_a_harness_fact_it_did_not_MEASURE",
        START_SIGNAL,
    ),
    # 23. THE KEYWORD-ONLY GUARD REMOVED. ExecutionResult is an ordinary
    #     dataclass, so before the flags were made keyword-only a caller could
    #     claim both harness facts in the fifth and sixth POSITIONAL slots --
    #     invisible to a rule that read node.keywords, with the census unmoved.
    #     The third #131 review round found it. The class now refuses the shape;
    #     this row is what notices if that line goes away. The rule itself reads
    #     the positional slots as well, so the two halves fail independently.
    (
        "record-class-harness-flags-no-longer-keyword-only",
        (
            (
                MODELS,
                "    started_ok: bool = field(default=False, kw_only=True)\n"
                "    candidate_started: bool = field(default=False, kw_only=True)\n",
                "    started_ok: bool = False\n    candidate_started: bool = False\n",
            ),
        ),
        "test_the_two_harness_flags_are_KEYWORD_ONLY_on_the_record_class",
        START_SIGNAL,
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
    modules = []
    for row in MUTATIONS:
        module = row[3] if len(row) > 3 else TESTS
        if module not in modules:
            modules.append(module)
    print(f"proof modules named by the table: {len(modules)} -> {modules}", flush=True)
    baseline_counts: dict[str, int] = {}
    with MutationWorktree(include_dirty=True) as tree:
        for module in modules:
            reds, summary = tree.pytest([module])
            print(f"baseline[{module}]: {summary}", flush=True)
            clean = re.fullmatch(r"(\d+) passed in [\d.]+s", summary)
            if reds or clean is None:
                raise RuntimeError(
                    f"baseline did not pass for {module}; no mutation evidence collected"
                )
            baseline_counts[module] = int(clean.group(1))

        # THE STRIPPED BASELINE, MEASURED BEFORE ANY MUTATION IS APPLIED, and
        # this runner published a false number for want of it.
        #
        # WHAT WENT WRONG. The second-order pass deletes every assert and then
        # asked only "are there any reds?". A test that performs an effect
        # INSIDE an assert — ``assert ledger.claim_authorization(...)`` — loses
        # the effect when the assert goes, and fails for a reason that has
        # nothing to do with the mutation. Measured on this module: the
        # stripped baseline was RED on one test with no mutation applied, so
        # every "still red with every assert deleted" result counted that one
        # invariant failure. The published 18 of 18 was not what it claimed,
        # and neither were the 16 of 16, 9 of 14 and 8 of 11 before it.
        #
        # REFUSED RATHER THAN SUBTRACTED. Excluding the known-red test would
        # make the count arithmetic over a number nobody re-derives. A stripped
        # baseline that is not clean means the second-order experiment has no
        # control, and an experiment with no control produces no evidence —
        # doctrine #8, applied to a runner rather than a sweep.
        for module in modules:
            tree.revert()
            original = (tree.path / module).read_text()
            weakened = ast.unparse(WithoutAssertions().visit(ast.parse(original))) + "\n"
            tree.apply(module, original, weakened)
            stripped_reds, stripped_summary = tree.pytest([module])
            print(f"stripped baseline[{module}]: {stripped_summary}", flush=True)
            for node in stripped_reds:
                print(f"  RED {node}", flush=True)
            if stripped_reds:
                raise RuntimeError(
                    f"the assertions-deleted baseline is RED for {module} before any "
                    "mutation is applied, so the second-order runs have no control "
                    "and measure nothing. Almost always a side-effecting assert: "
                    f"move the call out of the assert. Reds: {stripped_reds}"
                )
        tree.revert()
        for row in MUTATIONS:
            label, edits, selector = row[0], row[1], row[2]
            module = row[3] if len(row) > 3 else TESTS
            for stripped in (False, True):
                tree.revert()
                for path, old, new in edits:
                    tree.apply(path, old, new)
                if stripped:
                    original = (tree.path / module).read_text()
                    weakened = (
                        ast.unparse(WithoutAssertions().visit(ast.parse(original))) + "\n"
                    )
                    tree.apply(module, original, weakened)
                reds, summary = tree.pytest([module])
                name = f"{label}{'-assertions-deleted' if stripped else ''}"
                print(f"{name}: {summary}", flush=True)
                for node in reds:
                    print(f"  RED {node}", flush=True)
                counts = re.fullmatch(r"(\d+) failed, (\d+) passed in [\d.]+s", summary)
                if stripped:
                    # THE NAMED PROOF, in the stripped run too. "Some test went
                    # red" is not evidence that THIS mutation is caught without
                    # assertions — it was exactly that looseness, plus a red
                    # stripped baseline, that let this runner publish a
                    # second-order figure it had not measured.
                    #
                    # A row whose named proof stays green here is caught ONLY
                    # by an assert. That is reported, never failed on, and
                    # never summed with the first-order result.
                    if not any(node.endswith("::" + selector) for node in reds):
                        survivors.append(label)
                    continue
                if not reds or counts is None:
                    raise RuntimeError(f"{label}: no valid red measurement")
                if int(counts.group(1)) + int(counts.group(2)) != baseline_counts[module]:
                    raise RuntimeError(
                        f"{label}: proof population in {module} changed from "
                        f"{baseline_counts[module]}"
                    )
                if not any(node.endswith("::" + selector) for node in reds):
                    raise RuntimeError(
                        f"{label}: the named proof {selector} did not redden; "
                        f"reds were {reds}"
                    )
    print(f"all {len(MUTATIONS)} rows caught first-order, each by its named proof", flush=True)
    print(
        f"second-order: {len(MUTATIONS) - len(survivors)} of {len(MUTATIONS)} rows "
        "still redden THEIR NAMED PROOF with every assert deleted, against a "
        "stripped baseline verified clean above "
        f"(carried by raises/errors); assert-only rows: {sorted(survivors) or 'none'}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
