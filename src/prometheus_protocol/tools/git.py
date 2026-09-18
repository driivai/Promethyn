"""A narrow git tool: the first external connector, behind every safeguard.

The operation set is small and explicit, and nothing else is reachable:

* **read-side** — list branches; count the commits a branch carries that are
  absent from the base branch (`git rev-list --count base..branch`, the real
  content check — never a name heuristic);
* **one write op** — delete a branch. Nothing more: no push, no fetch, no
  force variants, no arbitrary git. The sandbox denies the network regardless,
  so no remote can be touched even in principle.

Every operation runs THROUGH the existing :class:`Sandbox` port with the
repository as the workspace — the same isolation the verifier and executor
use, reused, not forked. Read ops run freely; the delete is a destructive,
irreversible :class:`ExecutableAction` that exists only behind the gate:

PHASE-1.2b — THE MERGE CHECK REPORTS EVIDENCE, NOT A VERDICT. It used to return
``Judgment(authoritative=True)`` and the demo fed that straight to the execution
controller, so a branch classification authorized a deletion with no policy
resolved and no coverage validated. That was the sanctioned exposure Checkpoint 2
named, and it is closed here. The policy requires ``branch.merge_proof`` for a
``branch.delete``, the merge check is the permitted implementation, and only the
bank turns the finding into a verdict:

* a branch **provably fully merged** (zero commits absent from the base — the
  delete is provably lossless) is a PASS from an authoritative check, which
  satisfies the requirement; at medium risk the gate may auto-approve;
* **unmerged commits** is a FAIL: the required proof was not obtained, coverage
  refuses as unsatisfactory, and the delete is BLOCKED. This is stricter than
  the old shape, which returned a PASS at confidence 0.0 and relied on the risk
  class to route it to a human;
* a merge check that **could not run** is an ``Unavailable`` — could-not-verify
  is never verified-clean, and it is never a finding about the branch. Coverage
  refuses as incomplete and nothing executes.

Doubt never auto-deletes, and now it never reaches the executor at all.

The delete executor is bound to one repository at construction: the action
carries only a branch name, so no action can point the tool at another repo.
The base branch can never be deleted. Real deletion is an explicit opt-in
(``allow_delete=True``, off by default) enabled only after the halt was proven
with the dry-run; even opted in, it runs solely inside the sandbox on an
approved decision, and fail-closed if isolation does not start.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from prometheus_protocol.core.models import (
    ACTION_GIT_DELETE_BRANCH,
    Evidence,
    ExecutableAction,
    Tier,
    Unavailability,
    Unavailable,
    Verdict,
)
from prometheus_protocol.gate.promotion import GateDecision
from prometheus_protocol.policy.implementations import GIT_MERGE_CHECK
from prometheus_protocol.policy.reobservation import Unreadable
from prometheus_protocol.policy.target_state import BranchDeleteState
from prometheus_protocol.sandbox import Limits, Sandbox, build_sandbox
from prometheus_protocol.swarm.executor import Executor
from prometheus_protocol.swarm.models import ExecutionResult

#: The verifier identity the merge check reports in judgments it grounds. The
#: DECLARED object from ``policy/implementations.py``, by reference (G26).
MERGE_CHECK_VERIFIER_ID = GIT_MERGE_CHECK

#: Branch names the tool will touch: conservative charset, no leading dash
#: (nothing that could read as a git option), no traversal-looking segments.
#:
#: ``\Z``, NOT ``$``. Python's ``$`` also matches immediately before a trailing
#: newline, so ``"main\n"`` matched this pattern while ``git check-ref-format
#: --branch`` rejects it. Measured, and it is the reason the anchor is spelled
#: this way rather than the usual one.
_BRANCH_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._/-]*\Z")

#: Git's reference-name rules are PER COMPONENT, not per whole name. Found by
#: widening the differential corpus below: ``a.lock/b`` and ``a/.b`` both passed
#: a whole-name check and are both rejected by ``git check-ref-format``. So the
#: constructs are checked on each slash-separated component:
#:
#:   * no component may be empty (catches ``a//b``, a trailing ``/``)
#:   * no component may begin with ``.`` (catches ``a/.b``)
#:   * no component may end with ``.`` or ``.lock`` (catches ``a.``, ``a.lock/b``)
#:   * ``..`` may not appear anywhere (a range operator)
_FORBIDDEN_COMPONENT_PREFIXES = (".",)
_FORBIDDEN_COMPONENT_SUFFIXES = (".", ".lock")

#: Names git reserves and will not accept as a BRANCH, whatever their shape.
#: ``HEAD`` is a symbolic ref, not a branch, and passed the charset pattern.
_RESERVED_NAMES = frozenset({"HEAD"})


def is_usable_branch_name(name: str) -> bool:
    """Whether this tool would accept ``name`` as a branch or ref.

    Exported so a composition root can refuse an unusable base branch WHERE THE
    OPERATOR CAN SEE IT, instead of building a tool that refuses every read
    later. One definition of "a branch name this tool will touch": a root that
    spelled the rule again would be a second definition, free to drift from the
    one the reads actually use.

    THAT SENTENCE WAS ONCE FALSE OF THIS MODULE. When the rule was strengthened
    past the charset pattern, this function was the only thing strengthened:
    ``classify``, ``rev`` and ``GitBranchDeleteExecutor.execute`` went on
    matching ``_BRANCH_RE`` directly, so the tighter rule reached the
    composition root and nothing else — and the exported predicate became the
    second definition it exists to prevent, drifting in the one direction that
    costs. ``HEAD`` is the measured case: git resolves ``HEAD^{commit}`` and
    reports ``rev-list --count main..HEAD`` as ``0``, so a symbolic ref
    classified as PROVABLY MERGED — the evidence an irreversible delete is
    authorised on — and the delete then failed, because ``git branch -D HEAD``
    cannot work. Every read now calls this function, and
    ``test_git_ref_format.py`` pins that structurally so the next read added
    here cannot quietly reintroduce it.
    """

    if not _BRANCH_RE.match(name):
        return False
    if ".." in name or name in _RESERVED_NAMES:
        return False
    for component in name.split("/"):
        if not component:
            return False
        if component.startswith(_FORBIDDEN_COMPONENT_PREFIXES):
            return False
        if component.endswith(_FORBIDDEN_COMPONENT_SUFFIXES):
            return False
    return True

_LIMITS = Limits(wall_time_s=20.0, cpu_time_s=10, memory_bytes=0, max_processes=32)


def _ran(result) -> bool:
    """Whether a sandboxed git command ACTUALLY RAN, by the full signal.

    ``started_ok`` answers only "did isolation start". ``candidate_started`` is
    the definite signal that the command itself began, and the contract
    (``sandbox/base.py``) says ``started_ok=True`` with
    ``candidate_started=False`` — a wall-clock timeout during setup — stays a
    harness fault.

    WHY THIS IS A FUNCTION AND WHY EVERY READ USES IT. Before it, each read here
    tested ``started_ok or exit_status != 0`` and was SAFE ONLY BY ACCIDENT: the
    shipped adapters happen to leave ``exit_status`` at ``None`` on their
    timeout paths, and ``None != 0``. Measured with the same harness-fault
    signal and ``exit_status=0``: ``classify`` returned ``0`` — "zero commits
    absent from the base", the exact evidence that authorizes an irreversible
    delete — from a run where git never executed. The safety of this module
    rested on a property of a different module, checked by nothing.
    """

    return bool(result.started_ok and result.candidate_started)


class GitToolError(RuntimeError):
    """A read-side git operation could not produce a trustworthy answer."""


@dataclass(frozen=True)
class BranchClassification:
    """The merge check's finding for one branch.

    ``unmerged_commits`` is the count of commits reachable from the branch but
    not from the base branch — the content-diff. ``None`` means the check
    itself could not run (fail-closed: NOT provably merged). A branch is
    ``provably_merged`` only on a definite zero.
    """

    branch: str
    unmerged_commits: int | None

    @property
    def provably_merged(self) -> bool:
        return self.unmerged_commits == 0


class GitTool:
    """Read-side git operations, executed inside the sandbox."""

    def __init__(
        self,
        *,
        repo_path: Path | str,
        sandbox: Sandbox | None = None,
        base_branch: str = "main",
        git_path: str | None = None,
    ) -> None:
        self.repo_path = str(Path(repo_path).resolve())
        self.base_branch = base_branch
        self._sandbox = sandbox if sandbox is not None else build_sandbox()
        # The sandbox bootstrap execs without a PATH search; resolve on the host.
        self._git = git_path or shutil.which("git") or "git"

    def _run(self, *args: str):
        return self._sandbox.run(
            argv=[self._git, "-C", ".", *args],
            workspace=self.repo_path,
            limits=_LIMITS,
        )

    def branches(self) -> tuple[str, ...]:
        """All local branches except the base branch, in ref order."""

        result = self._run(
            "for-each-ref", "refs/heads", "--format=%(refname:short)"
        )
        if not _ran(result) or result.exit_status != 0:
            raise GitToolError(
                f"could not list branches (exit {result.exit_status}): "
                f"{(result.stderr or result.detail).strip()}"
            )
        names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return tuple(name for name in names if name != self.base_branch)

    def classify(self, branch: str) -> BranchClassification:
        """The real content check: commits on ``branch`` absent from base.

        Any failure — bad name, sandbox unavailable, git error — classifies as
        ``None`` (not provably merged), never as merged. Doubt routes to a
        human; it never widens what may auto-delete.
        """

        if not is_usable_branch_name(branch):
            return BranchClassification(branch=branch, unmerged_commits=None)
        result = self._run(
            "rev-list", "--count", f"{self.base_branch}..{branch}"
        )
        if not _ran(result) or result.exit_status != 0:
            return BranchClassification(branch=branch, unmerged_commits=None)
        try:
            count = int(result.stdout.strip())
        except ValueError:
            return BranchClassification(branch=branch, unmerged_commits=None)
        return BranchClassification(branch=branch, unmerged_commits=count)

    def delete_action(self, branch: str) -> ExecutableAction:
        """The one write op, as a gate-shaped action (never executed here)."""

        return ExecutableAction(kind=ACTION_GIT_DELETE_BRANCH, code=branch)

    def rev(self, ref: str) -> str | None:
        """The commit ``ref`` resolves to, or ``None`` when it cannot be read.

        ``None`` rather than a raise, and never an empty string: the caller
        turns any unreadable aspect into an unavailability, and an empty string
        would be a value that digests.
        """

        if not is_usable_branch_name(ref):
            return None
        result = self._run("rev-parse", "--verify", f"{ref}^{{commit}}")
        if not _ran(result) or result.exit_status != 0:
            return None
        tip = result.stdout.strip()
        return tip or None


class GitBranchStateObserver:
    """Reads the live state of a ``branch.delete`` target: two tips and a count.

    THE OBSERVER IS THE SAME READER THE MERGE PROOF USES. It goes through the
    same :class:`GitTool` — the same sandbox, the same repository, the same
    ``rev-list --count`` — so the state a hold is pinned to and the evidence the
    hold was authorized on are readings of one subject by one instrument. A
    second reader would be a second definition of "unmerged", and two
    definitions of the subject is how a digest comes to be stable under a change
    it should catch.

    ANY UNREADABLE ASPECT MAKES THE WHOLE READING UNAVAILABLE, and the refusal
    NAMES which aspects could not be read. A partial state is never returned:
    a digest over the readable half is a different measurement wearing the same
    name, and it would compare equal while the unreadable half moved. That is
    the same fail-closed direction the merge check itself takes — a count it
    could not establish is ``None``, never a zero.
    """

    def __init__(self, tool: GitTool) -> None:
        self._tool = tool

    @property
    def repo_path(self) -> str:
        return self._tool.repo_path

    def observe(
        self, *, target_canonical: str, action: ExecutableAction
    ) -> BranchDeleteState | Unreadable:
        expected = f"git://{self._tool.repo_path}"
        if target_canonical != expected:
            # The observer is bound to ONE repository at construction. A
            # descriptor naming another principal is not a target this observer
            # can speak about, and answering anyway would be an observation of
            # the wrong subject reported under the right name — the §7.5
            # substitution, at the observer.
            return self._unreadable(
                f"execution descriptor names {target_canonical!r}; this observer "
                f"is bound to {expected!r}",
                aspects_unread=("branch_tip", "base_tip", "unmerged_commits"),
            )
        if action.kind != ACTION_GIT_DELETE_BRANCH:
            return self._unreadable(
                f"action kind {action.kind!r} is not a branch delete",
                aspects_unread=("branch_tip", "base_tip", "unmerged_commits"),
            )
        branch = action.code
        unread: list[str] = []
        branch_tip = self._tool.rev(branch)
        if branch_tip is None:
            unread.append("branch_tip")
        base_tip = self._tool.rev(self._tool.base_branch)
        if base_tip is None:
            unread.append("base_tip")
        classification = self._tool.classify(branch)
        if classification.unmerged_commits is None:
            unread.append("unmerged_commits")
        if unread:
            return self._unreadable(
                f"could not read {len(unread)} aspect(s) of branch {branch!r}",
                aspects_unread=tuple(unread),
            )
        assert branch_tip is not None and base_tip is not None  # narrowed above
        return BranchDeleteState(
            branch_tip=branch_tip,
            base_tip=base_tip,
            unmerged_commits=classification.unmerged_commits or 0,
        )

    @staticmethod
    def _unreadable(detail: str, *, aspects_unread: tuple[str, ...]) -> Unreadable:
        """``Unreadable``, not ``Unavailable``, and the difference is the list.

        Doctrine #1's ``Unavailable`` says a check could not run. This says
        which ASPECTS of the target could not be read, which is what a partial
        read has to carry: "could not read the branch tip" and "could not reach
        the repository at all" are different operational findings with
        different remedies, and a single string collapses them.
        """

        return Unreadable(
            reason="aspects_unreadable",
            detail=detail,
            aspects_unread=aspects_unread,
        )


def evidence_for(classification: BranchClassification) -> Evidence | Unavailable:
    """The merge check's finding, as EVIDENCE — never as a verdict.

    PHASE-1.2b. This was ``judgment_for`` and it returned
    ``Judgment(authoritative=True)``: a second producer of the thing that
    authorizes, reached without the bank, without a policy, and without any
    coverage validation. ``tools/stale_branch_demo.py`` fed it straight into
    ``ExecutionController.submit``, so a branch classification authorized a
    deletion on its own say-so. That was the sanctioned exposure Checkpoint 2
    named, and this is it closed: a check reports what it found, and only the
    bank turns findings into a verdict.

    THE MAPPING, and why an unproven branch is a FAIL rather than a low
    confidence. The policy requires ``branch.merge_proof`` for a delete, and the
    requirement is proof the delete is LOSSLESS — not an opinion about how risky
    it looks. A branch with commits absent from the base has not been proven
    lossless, so the required check did not pass; coverage refuses as
    unsatisfactory and the delete is blocked. The old shape returned a PASS at
    confidence 0.0 and leaned on the risk class to route it, which is a
    verdict-shaped object saying "yes" while meaning "no" — the exact
    substitution the coverage layer exists to end.

    A check that could not RUN is an ``Unavailable``, never a FAIL: doubt about
    the harness is not a finding about the branch (EX-1).
    """

    if classification.provably_merged:
        return Evidence(
            passed=True,
            total=1,
            passed_count=1,
            failures=(),
            verifier_id=MERGE_CHECK_VERIFIER_ID,
            verdict=Verdict.PASS,
            tier=Tier.HARD,
            detail=(
                f"branch {classification.branch!r} has 0 commits absent "
                "from the base branch: deleting it is provably lossless"
            ),
        )
    if classification.unmerged_commits is None:
        return Unavailable(
            verifier_id=MERGE_CHECK_VERIFIER_ID,
            tier=Tier.HARD,
            reason=Unavailability.INFRA_FAULT,
            detail=(
                f"the merge check could not run for {classification.branch!r}; "
                "mergedness is unknown, which is not the same as unmerged"
            ),
        )
    return Evidence(
        passed=False,
        total=1,
        passed_count=0,
        failures=(
            f"{classification.unmerged_commits} commit(s) not on the base branch",
        ),
        verifier_id=MERGE_CHECK_VERIFIER_ID,
        verdict=Verdict.FAIL,
        tier=Tier.HARD,
        detail=(
            f"branch {classification.branch!r} carries "
            f"{classification.unmerged_commits} commit(s) NOT on the base branch: "
            "deletion would be irreversible data loss"
        ),
    )


def risk_class_for(classification: BranchClassification) -> str:
    """Deleting a branch is destructive, so it is HIGH risk by default.

    Authoritative proof of full mergedness is the one thing that lowers it: with
    zero commits absent from the base the delete is provably lossless. The risk
    class no longer decides whether an unproven delete proceeds — the policy
    does — so this is now only about how much confidence an ALLOWED delete needs.
    """

    return "medium" if classification.provably_merged else "high"


class GitBranchDeleteExecutor(Executor):
    """Executes ONLY git branch deletes, behind the same wall as any executor.

    It accepts only an *approved* :class:`GateDecision` whose action kind is
    the git delete; everything else is refused or a type error, exactly like
    the in-sandbox code executor. It is fail-closed: no isolating sandbox, no
    delete, and a sandbox that does not start refuses rather than degrades. It
    is bound to one repository at construction, and it refuses the base branch
    and any unsafe branch name regardless of approval.

    Real deletion is an explicit opt-in: with ``allow_delete=False`` (the
    default) the op is a dry-run that records intent without mutating the
    repository. The opt-in exists because the halt was proven first, and it is
    meant for a caller-controlled demo/scratch repository — the constructor
    pins the repo precisely so nothing else can be touched.
    """

    def __init__(
        self,
        *,
        repo_path: Path | str,
        sandbox: Sandbox | None = None,
        base_branch: str = "main",
        git_path: str | None = None,
        allow_delete: bool = False,
    ) -> None:
        self.repo_path = str(Path(repo_path).resolve())
        self.base_branch = base_branch
        self.allow_delete = allow_delete
        self._sandbox = sandbox if sandbox is not None else build_sandbox()
        self._git = git_path or shutil.which("git") or "git"

    @property
    def sandbox(self) -> Sandbox:
        return self._sandbox

    def execute(self, decision: GateDecision) -> ExecutionResult:
        # The wall, identical in shape to the in-sandbox code executor: only a
        # gate-produced, approved decision may cross into execution.
        if not isinstance(decision, GateDecision):
            raise TypeError(
                "Executor.execute accepts only a GateDecision; a proposal or "
                "test plan cannot be executed"
            )
        if not decision.approved:
            raise ValueError("refusing to execute an unapproved gate decision")

        action = decision.action
        from prometheus_protocol.policy.execution import (
            AuthorizedExecution,
            consume_authorization,
        )
        authorization = decision.authorization
        if not isinstance(authorization, AuthorizedExecution):
            raise ValueError("approved decision carries no validated execution descriptor")
        # G24, and NO EXCEPTION for this executor either — "the same gateway
        # with an exception" is the shape that made the claim unfalsifiable,
        # and a destructive git delete is the last place to carve one.
        consume_authorization(authorization)
        if authorization.action != action:
            raise ValueError("approved action differs from its execution descriptor")
        if authorization.descriptor.target_canonical != f"git://{self.repo_path}":
            raise ValueError("execution descriptor names a different git principal")
        if action is None:
            return self._refuse(decision, "approved decision carries no executable action")
        if action.kind != ACTION_GIT_DELETE_BRANCH:
            return self._refuse(decision, f"unsupported action kind {action.kind!r}")

        branch = action.code
        if not is_usable_branch_name(branch):
            return self._refuse(decision, f"unsafe branch name {branch!r}")
        if branch == self.base_branch:
            return self._refuse(decision, "refusing to delete the base branch")

        # Fail-closed: isolation is mandatory for a side-effect.
        if not self._sandbox.isolating:
            return self._refuse(
                decision,
                f"sandbox {self._sandbox.name!r} does not isolate; refusing to "
                "execute unsandboxed",
            )

        if not self.allow_delete:
            # Deletes not opted in: record the intent, mutate nothing.
            return ExecutionResult(
                executed=False,
                subject_id=decision.subject_id,
                detail=(
                    f"dry-run (deletes disabled): would delete branch {branch!r} "
                    f"in {self.repo_path}"
                ),
                refused=False,
                # NOTHING RAN. This said ``started_ok=True`` explicitly, which
                # is the only site in the tree that asserted the claim rather
                # than inheriting it: a dry run constructs no sandbox, so
                # isolation did not start and git did not begin. Both flags are
                # left at their fail-closed defaults and the record says so.
                sandbox_name=self._sandbox.name,
                exit_status=None,
                stdout="",
            )

        result = self._sandbox.run(
            argv=[self._git, "-C", ".", "branch", "-D", branch],
            workspace=self.repo_path,
            limits=_LIMITS,
        )
        if not result.started_ok:
            # Fail-closed: isolation did not start, so the delete did NOT run,
            # and it is never retried unsandboxed.
            return self._refuse(
                decision,
                f"sandbox did not start: {result.detail}",
                started_ok=False,
                candidate_started=False,
            )
        if not result.candidate_started:
            # F16, in the executor that really deletes. Isolation came up and
            # git never ran — a wall-clock timeout during SETUP. Reading
            # ``started_ok`` alone produced ``executed=False`` (fail-closed, so
            # no branch was lost) with the detail "ran in sandbox but failed"
            # and ``started_ok=True``: a record saying the delete was ATTEMPTED
            # and rejected by git, when git never started. An operator reading
            # it would look for the reason git refused, and there is none.
            return self._refuse(
                decision,
                "sandbox started but git never did, so the delete did not run "
                f"and nothing can be claimed about it: {result.detail}",
                # Isolation really did start; saying otherwise would collapse
                # this into "no runtime", a different fault with a different
                # remedy. ``candidate_started`` carries what went wrong. The
                # measured values, not literals — see the executor's twin.
                started_ok=result.started_ok,
                candidate_started=result.candidate_started,
            )
        deleted = result.exit_status == 0
        return ExecutionResult(
            executed=deleted,
            subject_id=decision.subject_id,
            detail=(
                f"deleted branch {branch!r} in sandbox {self._sandbox.name!r} "
                f"(exit {result.exit_status}, network denied)"
                if deleted
                else (
                    f"delete of branch {branch!r} ran in sandbox but failed "
                    f"(exit {result.exit_status}): {(result.stderr or '').strip()}"
                )
            ),
            refused=False,
            # The measured values, not literals — see the executor's twin.
            started_ok=result.started_ok,
            candidate_started=result.candidate_started,
            sandbox_name=self._sandbox.name,
            exit_status=result.exit_status,
            stdout=result.stdout,
            # The delete ran in the sandbox and this IS its output; the
            # dry-run and the refusals above leave the flag at its
            # fail-closed default.
            stdout_recorded=True,
        )

    def _refuse(
        self,
        decision: GateDecision,
        detail: str,
        *,
        started_ok: bool = False,
        candidate_started: bool = False,
    ) -> ExecutionResult:
        """Both facts default to the fail-closed answer.

        The same shape as ``execution/executor.py``: five of this module's
        seven ``_refuse`` calls are refusals taken before the sandbox runs —
        no action, an unsupported kind, an unsafe branch name, the base
        branch, a non-isolating adapter — and every one of them claimed
        isolation had started and git had begun.
        """
        return ExecutionResult(
            executed=False,
            subject_id=decision.subject_id,
            detail=f"refused: {detail}",
            refused=True,
            started_ok=started_ok,
            candidate_started=candidate_started,
            sandbox_name=self._sandbox.name,
            exit_status=None,
            stdout="",
        )
