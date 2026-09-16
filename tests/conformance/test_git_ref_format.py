"""The branch-name predicate, checked against git rather than against itself.

THE DEFECT. ``is_usable_branch_name`` was a charset pattern: a permitted first
character and a permitted set thereafter. Git's reference-name rules are more
than a charset, so names git rejects passed it — and a base branch that passes
composition and then fails every read is exactly the delayed, feature-wide
denial that predicate was added to prevent. Measured against
``git check-ref-format --branch``:

    'release/'  ours True   git False      trailing slash
    'a..b'      ours True   git False      the range operator
    'a.lock'    ours True   git False      git's own lock suffix
    'main\\n'    ours True   git False      Python's ``$`` matches before a
                                           trailing newline
    'a//b'      ours True   git False      empty path component
    'a.'        ours True   git False      trailing dot

Two more came from widening the corpus rather than from the report:
``a.lock/b`` and ``a/.b``. **Git's rules are PER COMPONENT**, and a whole-name
check cannot express them.

THE INVARIANT IS ONE-DIRECTIONAL, and that is the point of this module.
Anything this predicate accepts, git must accept. The converse deliberately
does NOT hold: the predicate is a conservative SUBSET, refusing things git
allows (a leading underscore, a bare ``@``, a mid-path component ending in a
dot). Refusing a name git would have taken costs a caller an error message;
accepting one git will reject costs every hold on that deployment.

WHY A DIFFERENTIAL TEST AND NOT A LONGER REGEX. The rules belong to git. Any
spelling of them here is a second definition free to drift, which is the defect
this module exists to catch — so the spelling is checked against the authority
on every run, over a hand-written corpus AND randomised names, rather than
being believed.
"""

from __future__ import annotations

import random
import shutil
import string
import subprocess

import pytest

from prometheus_protocol.tools.git import is_usable_branch_name

#: The names the review named, plus the two the widened corpus found.
REPORTED = [
    ("release/", "trailing slash"),
    ("a..b", "the range operator"),
    ("a.lock", "git's own lock suffix"),
    ("main\n", "Python's $ matches before a trailing newline"),
    ("a//b", "empty path component"),
    ("a.", "trailing dot"),
    ("a.lock/b", "a .lock COMPONENT, not just a .lock name"),
    ("a/.b", "a component beginning with a dot"),
    ("HEAD", "a symbolic ref, not a branch"),
]

LEGITIMATE = [
    "main",
    "master",
    "release/1.2",
    "feat/a-b_c",
    "v1.0",
    "x.lockfile",
    "a/b/c",
    "0",
]


def _git() -> str:
    found = shutil.which("git")
    # Deliberately not a skip. This module's whole claim is that the predicate
    # agrees with git, and a run without git would assert nothing while
    # reporting success — the empty-instrument pass this repository refuses.
    assert found, "git is required to check the predicate against its authority"
    return found


def _git_accepts(name: str) -> bool:
    return (
        subprocess.run(
            [_git(), "check-ref-format", "--branch", name],
            capture_output=True,
            text=True,
        ).returncode
        == 0
    )


# ---------------------------------------------------------------------------
# the reproduction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,why", REPORTED, ids=[n for n, _ in REPORTED])
def test_a_name_git_rejects_is_refused_by_the_predicate(name, why):
    """Each reported name, and each one the widened corpus added."""

    assert not _git_accepts(name), f"this fixture assumes git rejects {name!r}"
    assert not is_usable_branch_name(name), why


@pytest.mark.parametrize("name", LEGITIMATE)
def test_a_name_git_accepts_is_still_accepted(name):
    """The paired positive control (doctrine #4). Without it the refusals above
    are consistent with a predicate that has stopped accepting anything.

    ``x.lockfile`` is here on purpose: it ENDS with neither ``.lock`` nor a
    dot, and a suffix check written carelessly would refuse it.
    """

    assert _git_accepts(name)
    assert is_usable_branch_name(name)


# ---------------------------------------------------------------------------
# the differential, against the authority
# ---------------------------------------------------------------------------


def _corpus() -> list[str]:
    hand = [n for n, _ in REPORTED] + LEGITIMATE + [
        "-x", "", "@", "a b", "a\tb", "...", "a/", "/a", "a\\b", "a~1", "a^",
        "a:b", "a?", "a*", "a[", "@{", "..", "refs/heads/x", "b.lock.x", "-",
        "--all", ".hidden", "a/b.lock", "a/b./c", "a/./b", "lock", "a.locks",
        "x/y.lock/z", "..a", "a..", "a/b..c", "z" * 200,
    ]
    # Randomised names over the permitted charset, to reach shapes a
    # hand-written list would not think of. Seeded, so a failure is reproducible.
    alphabet = string.ascii_letters + string.digits + "._/-"
    rng = random.Random(16)
    hand += [
        "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 8)))
        for _ in range(400)
    ]
    return hand


def test_the_predicate_never_accepts_what_git_rejects():
    """THE LOAD-BEARING DIRECTION. A name this predicate accepts and git refuses
    is a base branch that passes composition and then fails every read — the
    delayed denial the predicate exists to prevent, reintroduced."""

    looser = [
        name
        for name in _corpus()
        if is_usable_branch_name(name) and not _git_accepts(name)
    ]

    assert not looser, (
        "the predicate accepts names git rejects, so a deployment could be "
        f"configured with a base branch that can never be read: {sorted(set(looser))}"
    )


def test_the_predicate_IS_stricter_than_git_and_that_is_deliberate():
    """The other direction, asserted as a NON-property.

    Stated rather than left implicit, because a reader who assumes the two
    agree exactly would "fix" the strictness and widen the accepted set. Being
    stricter costs a caller an error message; being looser costs every hold on
    that deployment.
    """

    stricter = [
        name
        for name in _corpus()
        if _git_accepts(name) and not is_usable_branch_name(name)
    ]

    assert stricter, (
        "the predicate is no longer stricter than git anywhere; if that is "
        "intended, this test should be replaced rather than deleted"
    )
    # A bare '@' is the stable example: git takes it, this tool will not.
    assert "@" in stricter


def test_the_corpus_is_not_trivially_small_or_one_sided():
    """An instrument that returns an empty set reads downstream as a pass
    (doctrine #8). Both halves of the corpus must be non-trivial, or the
    differential above proves nothing."""

    corpus = _corpus()
    accepted = [n for n in corpus if is_usable_branch_name(n)]
    rejected = [n for n in corpus if not is_usable_branch_name(n)]

    assert len(corpus) > 400
    assert len(accepted) > 50, "nothing is accepted; the differential is vacuous"
    assert len(rejected) > 20, "nothing is rejected; the differential is vacuous"


# ---------------------------------------------------------------------------
# the anchor
# ---------------------------------------------------------------------------


def test_the_pattern_is_anchored_with_Z_not_dollar():
    """``$`` also matches immediately before a trailing newline, so ``"main\\n"``
    matched the old pattern while git rejects it. Pinned on the pattern itself,
    because the behavioural proof above would also pass if the newline were
    stripped somewhere upstream — and then the anchor could quietly regress."""

    from prometheus_protocol.tools.git import _BRANCH_RE

    assert _BRANCH_RE.pattern.endswith(r"\Z")
    assert "$" not in _BRANCH_RE.pattern
    assert not _BRANCH_RE.match("main\n")
    assert _BRANCH_RE.match("main")
