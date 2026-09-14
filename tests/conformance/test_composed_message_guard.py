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
    compose_squash_message,
    hits_in,
    predicted_coauthors,
    refusable_hits,
    refuse_composed,
    squashed_commits,
)

#: (range, pr number, title, the squash commit it produced). Real, all of it.
ONE_COMMIT = (
    "c846272..8f29b1d",
    102,
    "PHASE-1.2c FINAL: a withdrawn claim, the TTL boundary, and the sixth refusal row",
    "4451aa1",
)
FIVE_COMMITS = (
    "af93238..fbae17b",
    101,
    "PHASE-1.2c: refuse banned tokens by construction, three platform channels, "
    "the pinned authorization record, and docs/OPEN-GAPS.md",
    "c846272",
)

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
    rev_range, number, title, sha = ONE_COMMIT
    assert compose_squash_message(rev_range, number, title=title) == _real_message(sha)


def test_the_composer_reproduces_the_real_five_commit_squash():
    rev_range, number, title, sha = FIVE_COMMITS
    assert compose_squash_message(rev_range, number, title=title) == _real_message(sha)


def test_the_two_pinned_ranges_really_are_one_commit_and_five():
    # Otherwise the pair above could both be exercising the same branch of the
    # composer and the multi-commit shape would be untested.
    assert len(squashed_commits(ONE_COMMIT[0])) == 1
    assert len(squashed_commits(FIVE_COMMITS[0])) == 5


def test_the_composed_message_is_what_carries_the_trailer_not_the_commits(terms):
    # The whole reason this mode exists: the branch commits are clean, and the
    # thing that lands is not. Shown, rather than asserted in a comment.
    rev_range, number, title, _sha = FIVE_COMMITS
    for _sha_i, _subject, body, _author, _committer in squashed_commits(rev_range):
        assert COAUTHOR_TERM not in body.lower()
    composed = compose_squash_message(rev_range, number, title=title)
    assert COAUTHOR_TERM in composed.lower()


def test_a_trailer_naming_the_permitted_identity_is_not_refused(terms):
    rev_range, number, title, _sha = FIVE_COMMITS
    composed = compose_squash_message(rev_range, number, title=title)
    assert hits_in(composed, terms) == [COAUTHOR_TERM], (
        "the raw matcher must still see it — the allowlist is applied by "
        "refusable_hits, not by hiding the term from the list"
    )
    assert refusable_hits(composed, terms) == []


def test_a_trailer_naming_anything_else_is_refused(terms):
    # A plausible human identity that nobody allowlisted. Not a vendor: this
    # isolates the allowlist from the vendor-name terms.
    composed = compose_squash_message(
        *FIVE_COMMITS[:2], title=FIVE_COMMITS[2], merged_by="nobody <nobody@example.invalid>"
    )
    forged = composed.replace(
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
    rows = squashed_commits(FIVE_COMMITS[0])
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


def test_refuse_composed_returns_one_for_the_vendor_commit_and_zero_for_ours(terms):
    assert (
        refuse_composed(
            f"{VENDOR_TRAILER_COMMIT}~1..{VENDOR_TRAILER_COMMIT}", 999, terms
        )
        == 1
    )
    assert (
        refuse_composed(FIVE_COMMITS[0], FIVE_COMMITS[1], terms, title=FIVE_COMMITS[2])
        == 0
    )


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
