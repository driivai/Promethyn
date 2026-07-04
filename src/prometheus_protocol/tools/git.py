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

* a branch **provably fully merged** (zero commits absent from the base — the
  delete is provably lossless) yields an authoritative PASS at confidence 1.0
  and medium risk, which the gate may auto-approve;
* anything else — unmerged commits, or a merge check that could not run —
  yields an authoritative PASS at confidence 0.0 and HIGH risk, which ALWAYS
  routes to a human (INV-EXEC-3). Doubt never auto-deletes.

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
    ExecutableAction,
    Judgment,
    Verdict,
)
from prometheus_protocol.gate.promotion import GateDecision
from prometheus_protocol.sandbox import Limits, Sandbox, build_sandbox
from prometheus_protocol.swarm.executor import Executor
from prometheus_protocol.swarm.models import ExecutionResult

#: The verifier identity the merge check reports in judgments it grounds.
MERGE_CHECK_VERIFIER_ID = "git-merge-check"

#: Branch names the tool will touch: conservative charset, no leading dash
#: (nothing that could read as a git option), no traversal-looking segments.
_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")

_LIMITS = Limits(wall_time_s=20.0, cpu_time_s=10, memory_bytes=0, max_processes=32)


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
        if not result.started_ok or result.exit_status != 0:
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

        if not _BRANCH_RE.match(branch):
            return BranchClassification(branch=branch, unmerged_commits=None)
        result = self._run(
            "rev-list", "--count", f"{self.base_branch}..{branch}"
        )
        if not result.started_ok or result.exit_status != 0:
            return BranchClassification(branch=branch, unmerged_commits=None)
        try:
            count = int(result.stdout.strip())
        except ValueError:
            return BranchClassification(branch=branch, unmerged_commits=None)
        return BranchClassification(branch=branch, unmerged_commits=count)

    def delete_action(self, branch: str) -> ExecutableAction:
        """The one write op, as a gate-shaped action (never executed here)."""

        return ExecutableAction(kind=ACTION_GIT_DELETE_BRANCH, code=branch)


def judgment_for(classification: BranchClassification) -> tuple[Judgment, str]:
    """Map the merge check's finding to a (judgment, risk_class) pair.

    Deleting a branch is destructive and irreversible, so it is HIGH risk by
    definition — with routing on, high risk always halts for a human. The ONE
    thing that downgrades it is authoritative proof of full mergedness: with
    zero commits absent from the base, the delete is provably lossless (every
    commit stays reachable), so the action is judged at confidence 1.0 and
    medium risk, which the gate may auto-approve. An unproven branch keeps
    high risk at confidence 0.0: the same gate ROUTES it (an authoritative
    PASS below the high-risk floor is held, not blocked), so a human decides.
    """

    if classification.provably_merged:
        return (
            Judgment(
                verdict=Verdict.PASS,
                confidence=1.0,
                authoritative=True,
                contributing=(MERGE_CHECK_VERIFIER_ID,),
                detail=(
                    f"branch {classification.branch!r} has 0 commits absent "
                    "from the base branch: deleting it is provably lossless"
                ),
            ),
            "medium",
        )
    if classification.unmerged_commits is None:
        why = "the merge check could not run"
    else:
        why = (
            f"branch {classification.branch!r} carries "
            f"{classification.unmerged_commits} commit(s) NOT on the base branch"
        )
    return (
        Judgment(
            verdict=Verdict.PASS,
            confidence=0.0,
            authoritative=True,
            contributing=(MERGE_CHECK_VERIFIER_ID,),
            detail=f"{why}: deletion would be irreversible data loss without review",
        ),
        "high",
    )


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
        if action is None:
            return self._refuse(decision, "approved decision carries no executable action")
        if action.kind != ACTION_GIT_DELETE_BRANCH:
            return self._refuse(decision, f"unsupported action kind {action.kind!r}")

        branch = action.code
        if not _BRANCH_RE.match(branch):
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
                started_ok=True,
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
            started_ok=True,
            sandbox_name=self._sandbox.name,
            exit_status=result.exit_status,
            stdout=result.stdout,
        )

    def _refuse(
        self, decision: GateDecision, detail: str, *, started_ok: bool = True
    ) -> ExecutionResult:
        return ExecutionResult(
            executed=False,
            subject_id=decision.subject_id,
            detail=f"refused: {detail}",
            refused=True,
            started_ok=started_ok,
            sandbox_name=self._sandbox.name,
            exit_status=None,
            stdout="",
        )
