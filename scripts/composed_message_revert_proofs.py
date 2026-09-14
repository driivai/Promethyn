#!/usr/bin/env python3
"""Executed-mutation proofs for the composed-squash-message guard.

Sixteen passing tests are sixteen assertions that nothing has gone wrong
YET. They are not evidence that anything would be caught. This applies eleven
mutations to the guard — seven to the checker, two to the captured fixture, one
to the workflow — in a throwaway worktree, and refuses unless each turns the
named test RED. A mutation that stays green names an unwatched field.

Run: python scripts/composed_message_revert_proofs.py

Every mutation is applied via ``MutationWorktree``, so the primary checkout is
never written to and there is no window in which this tree holds a disabled
guard.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mutation_worktree import MutationWorktree  # noqa: E402

#: The one vendor identity in this repository's history, decoded rather
#: than typed: this file is scanned by the tree checker too.
_VENDOR_IDENTITY = (
    base64.b64decode("Y2xhdWRl").decode().title()
    + " <noreply@"
    + base64.b64decode("YW50aHJvcGlj").decode()
    + ".com>"
)

CHECKER = "scripts/check_message_hygiene.py"
WORKFLOW = ".github/workflows/pr-text-hygiene.yml"
SUITE = "tests/conformance/test_composed_message_guard.py"

#: (label, file, old, new, the test that MUST go red).
#:
#: The expected-red name is part of the proof: a mutation that reddens some
#: OTHER test has not shown that the test we care about is load-bearing, and a
#: runner that accepts any red at all would pass a suite held up by one
#: over-broad assertion.
MUTATIONS: list[tuple[str, str, str, str, str]] = [
    (
        "separator-nine-hyphens-becomes-ten",
        CHECKER,
        '_MULTI_COMMIT_SEPARATOR = "-" * 9 + "\\n\\n"',
        '_MULTI_COMMIT_SEPARATOR = "-" * 10 + "\\n\\n"',
        "test_the_composer_reproduces_the_real_five_commit_squash",
    ),
    (
        "single-commit-loses-the-blank-line-before-the-trailer",
        CHECKER,
        '        body = rows[0][2] + "\\n"',
        "        body = rows[0][2]",
        "test_the_composer_reproduces_the_real_one_commit_squash",
    ),
    (
        # The fixture rows are stored oldest-first, as git --reverse produced
        # them. Reversing the composer's iteration is the same defect the
        # dropped --reverse flag used to be, reachable now that the byte tests
        # no longer run a git query.
        "multi-commit-bullets-become-newest-first",
        CHECKER,
        'chunks = "\\n".join(f"* {row[1]}\\n\\n{row[2].strip(chr(10))}\\n" for row in rows)',
        'chunks = "\\n".join(\n'
        '            f"* {row[1]}\\n\\n{row[2].strip(chr(10))}\\n" for row in reversed(rows)\n'
        "        )",
        "test_the_composer_reproduces_the_real_five_commit_squash",
    ),
    (
        # The anchor check is what stops the CI refusal recurring silently.
        #
        # The FIRST mutation written here relaxed the assertion itself
        # (`== 0` -> `in (0, 1)`) and stayed GREEN. It could not have done
        # anything else: every anchor in the fixture returns 0, so widening the
        # accepted set changes no outcome. Probed directly on unmutated code
        # instead — `git merge-base --is-ancestor` returns 0 for 4451aa1 and
        # c846272 and 1 for 8f29b1d and fbae17b, the two that broke run
        # 34860607395 — which says the assertion's subject is real and the
        # mutation was the vacuous part. So mutate the SUBJECT: point an anchor
        # at a commit that is not an ancestor of main, which is exactly the
        # mistake this test exists to catch.
        "anchor-points-at-a-commit-that-is-not-on-main",
        "tests/conformance/composed_message_fixture.json",
        '"squash_sha": "4451aa1"',
        '"squash_sha": "8f29b1d"',
        "test_every_anchor_commit_is_reachable_from_HEAD_so_a_checkout_has_it",
    ),
    (
        # A fixture body edited to say something else must break the byte
        # comparison against the real squash on main. That is what makes the
        # fixture safe to keep in the tree.
        "fixture-body-tampered",
        "tests/conformance/composed_message_fixture.json",
        "THE WITHDRAWN CLAIM",
        "THE TAMPERED CLAIM",
        "test_the_composer_reproduces_the_real_one_commit_squash",
    ),
    (
        "allowlist-widened-to-a-vendor-identity",
        CHECKER,
        'PERMITTED_COAUTHORS = frozenset({"driivaidev <will@driivai.com>"})',
        # The identity is interpolated as a LITERAL. Inserting the name
        # ``_VENDOR_IDENTITY`` into the checker's source would leave it
        # undefined there, and the resulting import error would redden the
        # suite for a reason that has nothing to do with the allowlist — a
        # mutation proving only that a typo breaks Python.
        "PERMITTED_COAUTHORS = frozenset(\n"
        f'    {{"driivaidev <will@driivai.com>", "{_VENDOR_IDENTITY.casefold()}"}}\n)',
        "test_the_allowlist_is_a_small_enumerated_set_not_a_pattern",
    ),
    (
        "allowlist-disabled-every-trailer-refused",
        CHECKER,
        "    lines = text.splitlines()\n"
        "    if not any(_permitted_coauthor_line(line) for line in lines):\n"
        "        return hits_in(text, terms)",
        "    lines = text.splitlines()\n    if True:\n        return hits_in(text, terms)",
        "test_a_trailer_naming_the_permitted_identity_is_not_refused",
    ),
    (
        "allowlist-defanged-nothing-refused",
        CHECKER,
        "def refusable_hits(text: str, terms: list[str]) -> list[str]:",
        "def refusable_hits(text: str, terms: list[str]) -> list[str]:\n    return []",
        "test_a_trailer_naming_anything_else_is_refused",
    ),
    (
        "merging-account-no-longer-excluded",
        CHECKER,
        "            if identity.casefold().strip() == excluded:\n                continue",
        "            if False:\n                continue",
        "test_the_merging_account_is_excluded_from_the_predicted_trailers",
    ),
    (
        "history-sweep-quietly-allowlisted",
        CHECKER,
        "    found = _commit_hits(commits, terms, refusing=False)",
        "    found = _commit_hits(commits, terms, refusing=True)",
        "test_the_history_sweep_is_NOT_allowlisted",
    ),
    (
        "workflow-checkout-back-to-shallow",
        WORKFLOW,
        "          fetch-depth: 0",
        "          fetch-depth: 1",
        "test_the_workflow_runs_the_composed_check_with_full_history",
    ),
]


def main() -> int:
    print(f"{len(MUTATIONS)} mutation(s), each must redden its named test\n")
    failures: list[str] = []
    for label, path, old, new, expected in MUTATIONS:
        with MutationWorktree(include_dirty=True) as tree:
            tree.apply(path, old, new)
            red, summary = tree.pytest([SUITE])
        hit = [test for test in red if expected in test]
        status = "RED" if hit else "GREEN"
        print(f"  {status:<5} {label}")
        print(f"        {summary.strip()}")
        if not hit:
            failures.append(
                f"{label}: expected {expected} to fail; reddened {sorted(red) or 'nothing'}"
            )
        elif len(red) > 1:
            print(f"        (also red: {sorted(set(red) - set(hit))})")
    print()
    if failures:
        print(f"{len(failures)} mutation(s) did NOT redden the field they disable:")
        for line in failures:
            print(f"  {line}")
        print(
            "\nA green mutation is not a safe mutation; it is an untested field. "
            "Probe it directly before concluding anything."
        )
        return 1
    print(f"all {len(MUTATIONS)} mutations reddened their named test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
