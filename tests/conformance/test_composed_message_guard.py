"""The squash message is derivable, so it is refusable before it exists.

`scripts/check_message_hygiene.py` used to record the squash-merge commit as
the one thing no pre-merge check could refuse: GitHub writes it when the merge
button is pressed, after every check has passed. That was true about the
ORDERING and false about the KNOWABILITY. The message GitHub will write is a
function of the branch's commits, the pull request's title and number, and the
merging account's identity — three things a pull-request event already has, and
one it does not.

So this module pins the composition against the only two real squash commits
this repository has, byte for byte:

* `4451aa1` (#102) — one commit. Subject is the title with ` (#102)`; body is
  that commit's body verbatim; then a blank line and one trailer.
* `c846272` (#101) — five commits. Body is each commit oldest-first as
  `* <subject>`, a blank line, its body; then a NINE-hyphen separator line and
  the trailers.

WHERE THE INPUTS COME FROM, and why not from git. The first version of this
module read the SOURCE commits of each squash out of history by range. That
passed here and refused all three jobs of run 34860607395 with
`fatal: ambiguous argument 'c846272..8f29b1d': unknown revision`. The reason is
ordinary and was not a history rewrite: a squash merge does not keep its source
commits, and once the branch is deleted they are reachable from NO ref, so a CI
checkout does not have them however deep it fetches. It passed locally only
because this clone still carried the merged branches. Verifying a fixture in
the one checkout that happens to have it is the failure this repository keeps
naming, and I walked into it.

The source rows are therefore captured in `composed_message_fixture.json`. The
EXPECTED output is deliberately NOT captured: it is read live from the squash
commit, which is on `main` and permanent. That anchors the fixture — edit a
body in the JSON and the composition stops matching GitHub's real bytes — so
the fixture cannot drift without a test going red, and nothing here depends on
a commit that a merge can take away.

Both were got wrong on the first attempt — a missing blank line before the
trailer, and a ten-hyphen separator that is nine in the artifact — and the byte
comparison is what caught each. That is the point of comparing against a real
commit rather than asserting a shape: a model of GitHub's behaviour that nobody
diffed against GitHub is a guess with tests.

WHY THE ALLOWLIST, measured rather than argued. Across all refs on 2026-09-14
there are 90 co-authorship trailers. 89 name `DriivAIDev <will@driivai.com>` —
this repository's own author, written by GitHub because the merging account's
commit email differs from the author's. ONE names a vendor, and that one is
independently caught by three vendor-name terms in the same list. A rule keyed
on the literal trailer key therefore fired 89 times on the
repository's own identity and once on a real finding, and turning `main` red on
every squash merge is what it bought (`docs/OPEN-GAPS.md` G13). The refusing
modes now ask WHO is named against an enumerated set, which is the same
allowlist doctrine the rest of the guards use, and the vendor terms still match
as strings everywhere including inside a permitted trailer.

NAMED LIMITS, none of which this module can close:

* the merging account is not in a `pull_request` payload, so `--composed`
  assumes the worst case — every distinct identity becomes a trailer — unless
  `--merged-by` is passed. The worst case is also what this repository has
  actually merged under, twice;
* a human can edit the squash message in the merge dialog after this passes.
  The push-to-`main` run is the backstop and is unchanged;
* the `----------` rule is observed from ONE multi-commit squash, because that
  is how many this repository has. `test_the_composer_reproduces_the_real_five_commit_squash`
  is what will notice if the next one disagrees;
* whether a red run here can block a merge is branch protection, not a
  workflow property.

IF A HISTORY REWRITE LANDS (PROM-IP Part B), the pinned SHAs below go away and
these tests FAIL rather than skip. That is deliberate: re-pinning them against
the rewritten history is the work, and a guard that quietly passes when its
fixture has vanished is the failure mode this repository keeps finding.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from check_hygiene import load_terms  # noqa: E402
from check_message_hygiene import (  # noqa: E402
    PERMITTED_COAUTHORS,
    _COAUTHOR_PREFIX,
    _COAUTHOR_TRAILER,
    compose_from_rows,
    compose_squash_message,
    hits_in,
    predicted_coauthors,
    refusable_hits,
    refuse_composed,
    squashed_commits,
)

FIXTURE = json.loads(
    (Path(__file__).with_name("composed_message_fixture.json")).read_text(encoding="utf-8")
)
#: Keyed by PULL REQUEST NUMBER, not by the squash sha. The sha is a value
#: under test — the anchor check reads it — so keying on it would make any
#: mutation of it a KeyError at import rather than a red test, and a mutation
#: that only proves Python raises on a missing key proves nothing.
CASES = {case["pr_number"]: case for case in FIXTURE["cases"]}
ONE_COMMIT = CASES[102]
FIVE_COMMITS = CASES[101]


def rows_of(case) -> list[tuple[str, str, str, str, str]]:
    return [
        (c["sha"], c["subject"], c["body"], c["author"], c["committer"])
        for c in case["commits"]
    ]


def composed(case, **kw) -> str:
    return compose_from_rows(rows_of(case), case["pr_number"], title=case["title"], **kw)


#: Ranges that are reachable from `main` and therefore survive a branch
#: deletion, for the tests that must exercise the git-backed path.
VENDOR_RANGE = "267a586~1..267a586"
MAIN_RANGE = "4451aa1~1..4451aa1"

#: The trailer key and the two vendor terms, decoded rather than typed: the
#: tree checker scans this file as well, so a test about banned tokens
#: cannot spell them. Same base64 idiom as scripts/hygiene_terms.txt.
COAUTHOR_TERM = _COAUTHOR_PREFIX.rstrip(":")
VENDOR_TERMS = frozenset(
    base64.b64decode(b).decode() for b in ("Y2xhdWRl", "YW50aHJvcGlj")
)

#: The one commit in this repository's history whose co-authorship trailer names
#: a vendor rather than its author. The negative control for the allowlist.
VENDOR_TRAILER_COMMIT = "267a586"


def _real_message(sha: str) -> str:
    proc = subprocess.run(
        ["git", "log", "-1", "--format=%B", sha],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, (
        f"{sha} is not reachable from this checkout. If history was rewritten, "
        f"re-pin this module against the new SHAs — do not delete the check."
    )
    return proc.stdout


@pytest.fixture(scope="module")
def terms() -> list[str]:
    loaded = load_terms()
    assert loaded, "no hygiene terms decoded; every assertion below would be vacuous"
    return loaded


def test_the_composer_reproduces_the_real_one_commit_squash():
    assert composed(ONE_COMMIT) == _real_message(ONE_COMMIT["squash_sha"])


def test_the_composer_reproduces_the_real_five_commit_squash():
    assert composed(FIVE_COMMITS) == _real_message(FIVE_COMMITS["squash_sha"])


def test_the_two_fixture_cases_really_are_one_commit_and_five():
    # Otherwise the pair above could both be exercising the same branch of the
    # composer and the multi-commit shape would be untested.
    assert len(ONE_COMMIT["commits"]) == 1
    assert len(FIVE_COMMITS["commits"]) == 5


def test_every_anchor_commit_is_reachable_from_HEAD_so_a_checkout_has_it():
    # The defect this module shipped with, turned into a check — and the
    # predicate matters. The first version asked whether each anchor was an
    # ancestor of `origin/main`, which fails in a CI checkout for a reason that
    # has nothing to do with the anchors: a pull-request checkout has no
    # `origin/main` remote-tracking ref at all (measured in a clone made the
    # way the runner makes one: `fatal: ambiguous argument 'origin/main'`).
    # That would have been the same mistake twice — depending on something the
    # checkout does not have.
    #
    # Ancestry of HEAD is the property actually wanted. "Is it on main" was
    # only ever a proxy for "will a checkout of this branch contain it", and
    # this asks that directly.
    for sha in (ONE_COMMIT["squash_sha"], FIVE_COMMITS["squash_sha"]):
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", sha, "HEAD"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0, (
            f"{sha} is not reachable from HEAD ({result.stderr.strip()}), so a "
            f"checkout of this branch need not contain it and this module would "
            f"refuse in CI the way run 34860607395 did"
        )


def test_the_git_backed_path_still_works_on_a_range_that_survives():
    # compose_from_rows is what the byte tests drive, so the git query needs
    # its own exercise or it could break unnoticed.
    message = compose_squash_message(MAIN_RANGE, 999, title="probe")
    assert message.startswith("probe (#999)")
    assert len(squashed_commits(MAIN_RANGE)) == 1


def test_the_composed_message_is_what_carries_the_trailer_not_the_commits(terms):
    # The whole reason this mode exists: the branch commits are clean, and the
    # thing that lands is not. Shown, rather than asserted in a comment.
    for _sha_i, _subject, body, _author, _committer in rows_of(FIVE_COMMITS):
        assert COAUTHOR_TERM not in body.lower()
    assert COAUTHOR_TERM in composed(FIVE_COMMITS).lower()


def test_a_trailer_naming_the_permitted_identity_is_not_refused(terms):
    message = composed(FIVE_COMMITS)
    assert hits_in(message, terms) == [COAUTHOR_TERM], (
        "the raw matcher must still see it — the allowlist is applied by "
        "refusable_hits, not by hiding the term from the list"
    )
    assert refusable_hits(message, terms) == []


def test_a_trailer_naming_anything_else_is_refused(terms):
    # A plausible human identity that nobody allowlisted. Not a vendor: this
    # isolates the allowlist from the vendor-name terms.
    message = composed(FIVE_COMMITS, merged_by="nobody <nobody@example.invalid>")
    forged = message.replace(
        f"{_COAUTHOR_TRAILER} DriivAIDev <will@driivai.com>",
        f"{_COAUTHOR_TRAILER} Someone Else <someone@example.invalid>",
    )
    assert "someone@example.invalid" in forged
    assert COAUTHOR_TERM in refusable_hits(forged, terms)


def test_a_vendor_named_trailer_is_refused_by_the_identity_AND_by_the_terms(terms):
    real = _real_message(VENDOR_TRAILER_COMMIT)
    found = refusable_hits(real, terms)
    assert COAUTHOR_TERM in found, "the named identity is not allowlisted"
    assert VENDOR_TERMS <= set(found), (
        "and the vendor terms match it independently, so the allowlist is not "
        "load-bearing for this case"
    )


def test_the_allowlist_is_a_small_enumerated_set_not_a_pattern():
    # Doctrine: a guard says what is PERMITTED. If this ever grows a wildcard,
    # a regex, or a domain suffix, the question stops being "who" and becomes
    # "what shape", which is the failure this replaced.
    assert isinstance(PERMITTED_COAUTHORS, frozenset)
    assert len(PERMITTED_COAUTHORS) == 1
    for entry in PERMITTED_COAUTHORS:
        assert entry == entry.casefold(), "entries are compared case-folded"
        assert "*" not in entry and "@" in entry and entry.endswith(">")


def test_the_merging_account_is_excluded_from_the_predicted_trailers():
    rows = rows_of(FIVE_COMMITS)
    everyone = predicted_coauthors(rows, None)
    assert everyone == ["DriivAIDev <will@driivai.com>"]
    # GitHub omits the merging account's own identity. With that account as the
    # merger there is no trailer at all — which is one of G13's four remedies,
    # and the only one this file can demonstrate.
    assert predicted_coauthors(rows, "DriivAIDev <will@driivai.com>") == []
    assert predicted_coauthors(rows, "driivaidev <WILL@driivai.com>") == []


def test_composing_an_empty_range_refuses_rather_than_reporting_a_clean_nothing():
    with pytest.raises(SystemExit):
        compose_squash_message("origin/main..origin/main", 1)
    with pytest.raises(SystemExit):
        compose_from_rows([], 1)


def test_refuse_composed_refuses_a_vendor_term_and_an_unallowlisted_identity(terms):
    # Two different grounds for refusal, on two ranges that both survive a
    # branch deletion, kept apart so neither can stand in for the other.
    assert refuse_composed(VENDOR_RANGE, 999, terms) == 1
    assert VENDOR_TERMS <= set(refusable_hits(_real_message(VENDOR_TRAILER_COMMIT), terms))

    # A commit already ON main re-composes to a refusal too, and NOT because of
    # any vendor name: every squash here is committed by `GitHub
    # <noreply@github.com>`, which nobody allowlisted. Worth pinning, because
    # it is the difference between "this text is dirty" and "this identity is
    # not on the list", and a guard that conflated them would be unreadable.
    assert refuse_composed(MAIN_RANGE, 999, terms, title="probe") == 1
    found = refusable_hits(compose_squash_message(MAIN_RANGE, 999, title="probe"), terms)
    assert found == [COAUTHOR_TERM], found


def test_the_clean_case_returns_zero(terms):
    # The positive control, on the fixture rows, whose identities ARE the ones
    # this repository allowlisted. Without it every assertion above is
    # consistent with a checker that refuses everything.
    assert refusable_hits(composed(FIVE_COMMITS), terms) == []
    assert refusable_hits(composed(ONE_COMMIT), terms) == []


def test_the_history_sweep_is_NOT_allowlisted(terms):
    # The sweep sizes PROM-IP Part B. If the allowlist reached it, the count
    # would drop by 89 and the rewrite would be planned against a number that
    # had been quietly filtered.
    source = (REPO_ROOT / "scripts" / "check_message_hygiene.py").read_text()
    sweep = source[source.index("def sweep_history") :]
    sweep = sweep[: sweep.index("\ndef ")]
    assert "refusing=False" in sweep
    assert "refusable_hits" not in sweep


def test_the_workflow_runs_the_composed_check_with_full_history():
    # A shallow checkout cannot see the branch's commits, so the composer would
    # have nothing to compose. This is the defect the first wiring had.
    workflow = (REPO_ROOT / ".github" / "workflows" / "pr-text-hygiene.yml").read_text()
    assert "--composed" in workflow
    assert "fetch-depth: 0" in workflow
    assert "pull_request.number" in workflow
