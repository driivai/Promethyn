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

import ast
import random
import shutil
import string
import subprocess
from pathlib import Path

import pytest

from prometheus_protocol.sandbox.unsafe import UnsafeLocalSandbox
from prometheus_protocol.tools.git import GitTool, is_usable_branch_name

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


#: The corpus and its two halves, observed at base ce16a19 on 2026-09-19.
#: Re-pin from the observed split in the change that moves it.
CORPUS_SIZE = 449
ACCEPTED_SIZE = 377
REJECTED_SIZE = 72


def test_the_corpus_is_not_trivially_small_or_one_sided():
    """An instrument that returns an empty set reads downstream as a pass
    (doctrine #8). Both halves of the corpus must be non-trivial, or the
    differential above proves nothing."""

    corpus = _corpus()
    accepted = [n for n in corpus if is_usable_branch_name(n)]
    rejected = [n for n in corpus if not is_usable_branch_name(n)]

    # COUNTS, exact, shortfall and excess both refused. Counts rather than
    # membership because the corpus is enumerated by construction and its
    # VALUE is that both halves stay large enough to be a differential; which
    # particular name sits in which half is already asserted name-by-name by
    # the differential tests above, so membership here would restate them.
    #
    # What the floors permitted, measured at base ce16a19: 449 / 377 / 72
    # against > 400 / > 50 / > 20 — slack of 49, 327 and 52. The middle one is
    # the worst in the tree: 327 accepted names could have stopped being
    # generated and "nothing is accepted; the differential is vacuous" would
    # still have read as a pass.
    assert len(corpus) == CORPUS_SIZE, (len(corpus), CORPUS_SIZE)
    assert len(accepted) == ACCEPTED_SIZE, (
        f"{len(accepted)} accepted, pinned {ACCEPTED_SIZE}; the differential's "
        "accepting half changed size and that is either a corpus change to "
        "re-pin or a validator change to answer for"
    )
    assert len(rejected) == REJECTED_SIZE, (
        f"{len(rejected)} rejected, pinned {REJECTED_SIZE}; the differential's "
        "rejecting half changed size"
    )
    assert len(accepted) + len(rejected) == len(corpus), "the split lost a name"


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


# ---------------------------------------------------------------------------
# THE READS, NOT JUST THE ROOT
#
# Review finding on PR #118, reproduced below. ``is_usable_branch_name`` was
# strengthened and EXPORTED for the composition root, and its own docstring
# promised "one definition of a branch name this tool will touch". The reads
# went on checking ``_BRANCH_RE``. So the strengthening reached the root and
# nothing else, and the exported predicate became the second definition the
# docstring said it was there to prevent — the drift, at one remove, in the
# direction that costs.
#
# ``HEAD`` is the load-bearing example and it is not hypothetical. Measured on
# a real repository (below): git resolves ``HEAD^{commit}`` at exit 0 and
# reports ``rev-list --count main..HEAD`` as ``0``. Zero commits absent from
# the base is the exact evidence that authorises an irreversible delete. The
# delete then fails — ``git branch -D HEAD`` exits 1, "branch 'HEAD' not
# found" — so the sequence is: observe a symbolic ref as a branch, classify it
# as provably merged, approve the delete on that evidence, and fail at the one
# step that was supposed to be the formality.
# ---------------------------------------------------------------------------


def _make_repo(path: Path) -> None:
    """``main`` with two commits. Nothing exotic; the defect needs no setup."""

    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [_git(), "-C", str(path), "-c", "init.defaultBranch=main", "init", "-q"],
        check=True,
    )
    for message in ("base", "second"):
        subprocess.run(
            [
                _git(), "-C", str(path),
                "-c", "user.email=fixture@example.invalid",
                "-c", "user.name=fixture",
                "commit", "-q", "--allow-empty", "-m", message,
            ],
            check=True,
        )


def _tool(repo: Path) -> GitTool:
    return GitTool(repo_path=repo, sandbox=UnsafeLocalSandbox(), base_branch="main")


def _approved_delete_decision(repo: Path, branch: str):
    """An APPROVED delete of ``branch``, through the real gate.

    The merge evidence is supplied as ``unmerged_commits=0`` rather than read
    from ``classify``, and that is the point of the test it serves. After the
    fix ``classify("HEAD")`` refuses, so the real reading can no longer produce
    an approval — which means routing this through ``classify`` would build a
    test that passes because the decision was never approved, not because the
    executor refused. Supplying the verdict reconstructs the state the gate was
    in BEFORE the fix and asks the executor, the last gate before the mutation,
    to refuse on its own. Defence in depth: the executor's check must not
    depend on the classifier upstream of it being right.

    Everything else is real — the real policy, the real bank, the real gate.
    """

    from prometheus_protocol.policy.coverage import BoundResult
    from prometheus_protocol.policy.profile import (
        CHECK_MERGE_PROOF,
        DEFAULT_PROFILE_ID,
        load_profile,
    )
    from prometheus_protocol.policy.resolver import resolve
    from prometheus_protocol.policy.snapshot import (
        ACTION_BRANCH_DELETE,
        snapshot_digest,
    )
    from prometheus_protocol.gate.authorization import ActionGate
    from prometheus_protocol.policy.execution import ExecutionAuthorizer
    from prometheus_protocol.swarm.models import content_hash
    from prometheus_protocol.tools.git import (
        BranchClassification,
        MERGE_CHECK_VERIFIER_ID,
        evidence_for,
    )
    from prometheus_protocol.core.models import Tier
    from prometheus_protocol.verifier.bank import VerifierBank
    from prometheus_protocol.verifier.store import InMemoryTrustStore

    tool = _tool(repo)
    attempt = f"delete-branch:{branch}"
    policy = load_profile(DEFAULT_PROFILE_ID)
    snapshot = resolve(
        policy,
        artifact_sha256=content_hash(branch),
        target_canonical=f"git://{tool.repo_path}",
        action_class=ACTION_BRANCH_DELETE,
        attempt_id=attempt,
    )
    bank = VerifierBank(InMemoryTrustStore(), policy_supplier=lambda: policy)
    bank.register(MERGE_CHECK_VERIFIER_ID, Tier.HARD)
    assessed = bank.assess(
        snapshot,
        [
            BoundResult(
                check_id=CHECK_MERGE_PROOF,
                snapshot_digest=snapshot_digest(snapshot),
                implementation=MERGE_CHECK_VERIFIER_ID,
                outcome=evidence_for(
                    BranchClassification(branch=branch, unmerged_commits=0)
                ),
            )
        ],
    )
    decision = ActionGate(
        target_canonical=f"git://{tool.repo_path}",
        authorizer=ExecutionAuthorizer(lambda: policy),
    ).decide(
        assessed,
        attempt_id=attempt,
        action=tool.delete_action(branch),
        subject_id=attempt,
    )
    assert decision.approved, "this proof needs an APPROVED delete to execute"
    return decision


def test_git_itself_would_take_HEAD_as_a_rev_and_refuse_it_as_a_branch(tmp_path):
    """The premise the reproduction rests on, measured rather than assumed.

    If git ever stopped resolving ``HEAD`` this way the tests below would pass
    for a reason that has nothing to do with the predicate, so the asymmetry
    is pinned on git directly: readable as a rev, zero commits ahead of base,
    not a valid branch name, and undeletable as a branch.
    """

    _make_repo(tmp_path)
    run = lambda *a: subprocess.run(  # noqa: E731
        [_git(), "-C", str(tmp_path), *a], capture_output=True, text=True
    )

    assert run("rev-parse", "--verify", "HEAD^{commit}").returncode == 0
    assert run("rev-list", "--count", "main..HEAD").stdout.strip() == "0"
    assert run("check-ref-format", "--branch", "HEAD").returncode != 0
    assert run("branch", "-D", "HEAD").returncode != 0


def test_classify_does_not_report_a_symbolic_ref_as_provably_merged(tmp_path):
    """THE REPRODUCTION. ``unmerged_commits == 0`` is the merged verdict, and
    it is what authorises the delete. Anything the predicate refuses must
    classify as ``None`` — not provably merged — the same as a bad name, an
    unavailable sandbox or a git error. Doubt routes to a human."""

    _make_repo(tmp_path)

    classification = _tool(tmp_path).classify("HEAD")

    assert classification.unmerged_commits is None, (
        "a name the tool's own predicate refuses was classified as provably "
        f"merged ({classification.unmerged_commits} commits absent from base), "
        "which is the evidence an irreversible delete is approved on"
    )


def test_rev_does_not_resolve_a_name_the_predicate_refuses(tmp_path):
    """``rev`` is the observer's reader: the tips a hold is pinned to come from
    here. A tip read for a name that cannot be a branch pins a hold to a
    subject the delete can never act on."""

    _make_repo(tmp_path)

    assert _tool(tmp_path).rev("HEAD") is None


def test_the_delete_executor_refuses_a_name_the_predicate_refuses(tmp_path):
    """The last gate before the mutation, holding on its own.

    ``allow_delete=True`` deliberately: with the opt-out on, a passing result
    would be indistinguishable from the dry-run refusing everything. This is
    the configuration where the mutation really would be attempted.
    """

    from prometheus_protocol.tools.git import GitBranchDeleteExecutor

    _make_repo(tmp_path)
    executor = GitBranchDeleteExecutor(
        repo_path=tmp_path,
        sandbox=UnsafeLocalSandbox(),
        base_branch="main",
        allow_delete=True,
    )
    decision = _approved_delete_decision(tmp_path, "HEAD")

    result = executor.execute(decision)

    assert result.refused, (
        "an unusable branch name reached the delete path with deletes enabled, "
        "so it was handed to git"
    )
    assert not result.executed
    assert "unsafe branch name" in result.detail


@pytest.mark.parametrize(
    "name", ["release/", "a..b", "a.lock", "a//b", "a.", "a/.b", "a.lock/b"]
)
def test_every_reported_shape_is_refused_by_the_READS_too(name, tmp_path):
    """The class, not the instance — and THIS TEST WAS ALREADY GREEN BEFORE THE
    FIX. Recorded rather than presented as part of the reproduction.

    Measured on a real repository, all seven of these names pass ``_BRANCH_RE``
    and were handed to git, which refused each one at exit 128 — so the reads
    returned ``None`` for a reason that had nothing to do with the predicate.
    They were SAFE ONLY BY ACCIDENT, the same shape ``_ran`` was found in, and
    the accident is a property of git's argument parsing rather than of
    anything this module decides.

    ``HEAD`` is the single member of the refused set where the accident does
    not hold: git resolves it and reports a count. That is why the finding is
    an escalation and these are not. The test stays because the accident is
    not a guarantee — an argument git parses differently tomorrow moves a name
    from this list to that one, and then the reads must already be closed.
    """

    _make_repo(tmp_path)
    tool = _tool(tmp_path)

    assert not is_usable_branch_name(name), "fixture assumes the predicate refuses it"
    assert tool.rev(name) is None, name
    assert tool.classify(name).unmerged_commits is None, name


def test_the_escalation_needs_HEAD_AT_OR_BEHIND_BASE_and_that_is_stated(tmp_path):
    """The BOUNDARY of the finding, measured rather than left as an absolute.

    ``classify("HEAD")`` only produced the merged verdict where the worktree's
    ``HEAD`` was at or behind the base. Measured on a checkout sitting on a
    branch one commit ahead, ``rev-list --count main..HEAD`` returned ``1`` —
    not merged, so no approval. The review's wording ("in a repository on
    ``main``") is exactly right and this pins it, so nobody later reads the
    finding as broader than it is or narrower than it is.
    """

    _make_repo(tmp_path)
    subprocess.run(
        [_git(), "-C", str(tmp_path), "-c", "user.email=f@e.invalid",
         "-c", "user.name=f", "checkout", "-q", "-b", "ahead"],
        check=True,
    )
    subprocess.run(
        [_git(), "-C", str(tmp_path), "-c", "user.email=f@e.invalid",
         "-c", "user.name=f", "commit", "-q", "--allow-empty", "-m", "ahead"],
        check=True,
    )

    raw = subprocess.run(
        [_git(), "-C", str(tmp_path), "rev-list", "--count", "main..HEAD"],
        capture_output=True, text=True,
    )
    assert raw.stdout.strip() == "1", "the fixture must be AHEAD of base"

    # And the tool refuses it anyway, for the name — not for the count.
    assert _tool(tmp_path).classify("HEAD").unmerged_commits is None


def test_a_usable_name_still_reads_normally(tmp_path):
    """The paired positive control (doctrine #4). Without it every assertion
    above is equally consistent with reads that have stopped working."""

    _make_repo(tmp_path)
    tool = _tool(tmp_path)

    assert tool.rev("main") is not None
    assert tool.classify("main").unmerged_commits == 0


# ---------------------------------------------------------------------------
# the structural pin: one definition, enforced on the source
# ---------------------------------------------------------------------------

#: The only place in ``tools/git.py`` permitted to touch ``_BRANCH_RE``. An
#: allowlist, keyed on the enclosing function, rather than a count: a count
#: would be satisfied by moving the defect to a new read.
_BRANCH_RE_PERMITTED_IN = frozenset({"is_usable_branch_name"})


def test_no_read_spells_the_rule_a_second_time():
    """The behavioural proofs above cover the reads that exist TODAY. This one
    covers the read added next month.

    ``_BRANCH_RE`` is a charset pattern and a strict SUBSET of the rule; a site
    that consults it directly accepts names the tool has decided it will not
    touch. Exactly one function may see it — the predicate that wraps it.
    """

    import prometheus_protocol.tools.git as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    offenders: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name in _BRANCH_RE_PERMITTED_IN:
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Name) and inner.id == "_BRANCH_RE":
                offenders.append((node.name, inner.lineno))

    assert not offenders, (
        "these functions check the charset pattern instead of the tool's rule, "
        "so they accept names the tool refuses: "
        + ", ".join(f"{name} (line {line})" for name, line in offenders)
    )


def test_that_pin_would_catch_the_defect_it_was_written_for():
    """The pin's own positive control: it must be capable of failing.

    An allowlist test that passes because it found nothing to look at is the
    empty-instrument pass (doctrine #8). Re-run with the permitted name
    removed, the real source must produce a finding — proving the scan reaches
    the code rather than trivially agreeing.
    """

    import prometheus_protocol.tools.git as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    seen = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for inner in ast.walk(node)
        if isinstance(inner, ast.Name) and inner.id == "_BRANCH_RE"
    ]

    assert seen == ["is_usable_branch_name"], (
        "the scan no longer sees the one permitted use, so a green result "
        f"above would prove nothing; saw {seen}"
    )
