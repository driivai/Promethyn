"""Executed mutation proofs for the cross-version agreement guard, in a worktree.

Every row disables one thing ``scripts/check_matrix_agreement.py`` does and
names the test in ``tests/conformance/test_matrix_agreement.py`` that must go
red for it. Both attack classes are here, because a guard that survives only
deletion has been shown to catch a vandal and not a substitution:

  * DELETION — the collected-set comparison, the skipped-set comparison, the
    empty-report refusal, the failure and error refusals, each removed;
  * CROSS-CONTEXT SUBSTITUTION — a set replaced by a count (OPEN-GAPS G25, in
    both places the guard compares sets: test ids and versions), every
    version's set compared against ITSELF so nothing can ever differ, and the
    matrix read from the workflow replaced by a list typed into the script.

First-order only, stated rather than implied: the assertion-deleted
second-order run the reachability runners perform measures how much of a
PROOF MODULE is carried by its asserts; this runner measures whether the GUARD
is load-bearing, which is the question the sprint asked. Run with the
repository's environment: python scripts/matrix_agreement_proofs.py
"""

from __future__ import annotations

import re

from mutation_worktree import MutationWorktree

TESTS = "tests/conformance/test_matrix_agreement.py"
GUARD = "scripts/check_matrix_agreement.py"

MUTATIONS = (
    ("collected-comparison-deleted", GUARD,
     '    for field in ("collected", "skipped"):\n',
     '    for field in ("skipped",):\n',
     "test_a_test_collected_on_one_version_only_is_refused_naming_the_test_and_the_versions_that_lack_it"),
    ("skipped-comparison-deleted", GUARD,
     '    for field in ("collected", "skipped"):\n',
     '    for field in ("collected",):\n',
     "test_the_same_collected_set_with_a_different_skip_set_is_refused"),
    ("composition-substituted-by-count", GUARD,
     "        sets = {version: getattr(outcomes[version], field) for version in expected}\n",
     "        sets = {version: frozenset(range(len(getattr(outcomes[version], field)))) for version in expected}\n",
     "test_the_same_count_with_different_membership_is_refused"),
    ("every-version-compared-against-itself", GUARD,
     "            absent = sorted(union - sets[version])\n",
     "            absent = sorted(sets[version] - sets[version])\n",
     "test_a_test_collected_on_one_version_only_is_refused_naming_the_test_and_the_versions_that_lack_it"),
    ("empty-report-refusal-deleted", GUARD,
     "        if not outcome.collected:\n",
     "        if False:\n",
     "test_an_empty_report_is_refused_before_anything_is_compared"),
    ("failure-refusal-deleted", GUARD,
     "        if outcome.failed:\n",
     "        if False:\n",
     "test_a_failure_or_an_error_on_any_version_is_refused"),
    ("error-refusal-deleted", GUARD,
     "        if outcome.errored:\n",
     "        if False:\n",
     "test_a_failure_or_an_error_on_any_version_is_refused"),
    ("version-set-substituted-by-count", GUARD,
     "    if set(got) != set(expected):\n",
     "    if len(got) != len(expected):\n",
     "test_a_report_from_a_version_the_matrix_does_not_run_is_refused_even_when_the_count_of_versions_matches"),
    ("matrix-hand-listed-instead-of-read", GUARD,
     '    versions = document["jobs"]["build"]["strategy"]["matrix"]["python-version"]\n',
     '    versions = ["3.10", "3.11", "3.12"]\n',
     "test_the_version_list_is_derived_from_the_workflow_it_is_given"),
)


def run() -> int:
    print(f"rows: {len(MUTATIONS)} first-order mutations of {GUARD}", flush=True)
    with MutationWorktree(include_dirty=True) as tree:
        reds, summary = tree.pytest([TESTS])
        print(f"baseline: {summary}", flush=True)
        clean = re.fullmatch(r"(\d+) passed in [\d.]+s", summary)
        if reds or clean is None:
            raise RuntimeError("baseline did not pass; no mutation evidence collected")
        baseline_count = int(clean.group(1))
        for label, path, old, new, selector in MUTATIONS:
            tree.revert()
            tree.apply(path, old, new)
            reds, summary = tree.pytest([TESTS])
            print(f"{label}: {summary}", flush=True)
            for node in reds:
                print(f"  RED {node}", flush=True)
            counts = re.fullmatch(r"(\d+) failed, (\d+) passed in [\d.]+s", summary)
            if not reds or counts is None:
                raise RuntimeError(f"{label}: no valid red measurement")
            if int(counts.group(1)) + int(counts.group(2)) != baseline_count:
                raise RuntimeError(f"{label}: proof population changed from {baseline_count}")
            if not any(node.endswith("::" + selector) for node in reds):
                raise RuntimeError(f"{label}: the named proof {selector} did not redden; reds were {reds}")
    print(f"all {len(MUTATIONS)} rows caught, each by its named proof", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
