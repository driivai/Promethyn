"""F16: a setup timeout must not record as a successful execution.

THE DEFECT, AND WHY IT IS THE RECEIPT THAT MATTERS. ``SandboxExecutor._run``
decided the outcome from ``started_ok`` ALONE. The sandbox contract
(``sandbox/base.py``) is explicit that this is not enough:

    ``candidate_started`` is the stronger, *definite* signal: the candidate
    command actually began executing under isolation. [...] ``started_ok=True``
    with ``candidate_started=False`` — e.g. a wall-clock timeout during setup,
    before the candidate ran — stays a harness fault.

So a wall-clock timeout that fired during SETUP, before the candidate ever ran,
returned ``executed=True`` with the detail "ran in sandbox". Could-not-verify
reported as verified-clean, written into the execution record, at the moment
the receipt is produced. Doctrine #1 at the point it is hardest to recover
from: downstream there is nothing left that knows the difference.

THE ASYMMETRY THIS CLOSES. The same triple is ALREADY classified correctly one
seam over. ``tests/conformance/test_sandbox_fault_classification.py`` proves
the verifier path maps ``started_ok=True, candidate_started=False`` to
``Unavailable(INFRA_FAULT)`` — a non-verdict — and has done since that bug was
found there. The executor was reading a narrower set of fields than the
verifier for the same underlying fact.

WHY NO FOURTH CATEGORY. ``runner.py``'s three-way split is the precedent: a
resource kill is a verdict ABOUT the candidate, a harness fault is not a
verdict at all, and isolation never starting is the same non-verdict. The
executor has no verdict to give — ``exit_status`` carries the candidate's own
outcome — so the split collapses to the two outcomes it already has: it
executed, or it could not. ``candidate_started=False`` is the second, for
exactly the reason ``started_ok=False`` already is.

WHAT IS REAL HERE. The triples are supplied by a fake sandbox, deliberately:
the property under test is the MAPPING, and reproducing a real setup-timeout
race would be non-deterministic and would skip wherever no isolation runtime
exists. ``test_reachability`` below pins that the shipped isolating adapters
really can produce each triple asserted, by reading their source — so the fake
is a stand-in for a reachable state, not an invented one.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from prometheus_protocol.core.models import ACTION_PYTHON_CODE, ExecutableAction
from prometheus_protocol.core.models import Judgment, Verdict
from prometheus_protocol.execution.executor import SandboxExecutor
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import GateDecision
from prometheus_protocol.policy.execution import ExecutionAuthorizer
from prometheus_protocol.policy.profile import DEFAULT_PROFILE_ID, load_profile
from prometheus_protocol.sandbox.base import Limits, Sandbox, SandboxResult
from prometheus_protocol.swarm.models import content_hash

from tests.support.assessments import a_policy, carrying

SRC = Path(__file__).resolve().parents[2] / "src" / "prometheus_protocol"


class _Triple(Sandbox):
    """An isolating sandbox returning one exact (started_ok, candidate_started,
    timed_out) triple. The mapping is what is under test."""

    name = "triple"
    isolating = True

    def __init__(
        self,
        *,
        started_ok: bool,
        candidate_started: bool,
        timed_out: bool = False,
        exit_status: int | None = 0,
    ) -> None:
        self._started_ok = started_ok
        self._candidate_started = candidate_started
        self._timed_out = timed_out
        self._exit_status = exit_status

    def run(
        self, *, argv, workspace, limits: Limits = Limits(), stdin: str = ""
    ) -> SandboxResult:
        return SandboxResult(
            started_ok=self._started_ok,
            candidate_started=self._candidate_started,
            timed_out=self._timed_out,
            exit_status=self._exit_status,
            detail="wall-time limit 5s" if self._timed_out else "",
        )


def _approved(code: str = "print('RAN')") -> GateDecision:
    action = ExecutableAction(kind=ACTION_PYTHON_CODE, code=code)
    assessed = carrying(
        Judgment(verdict=Verdict.PASS, confidence=1.0, authoritative=True),
        artifact_sha256=content_hash(code),
    )
    return ActionGate(
        target_canonical="sandbox://test",
        authorizer=ExecutionAuthorizer(lambda: a_policy()),
    ).decide(assessed, attempt_id="attempt-1", action=action, subject_id="s")


def _execute(**triple):
    return SandboxExecutor(sandbox=_Triple(**triple)).execute(_approved())


# ---------------------------------------------------------------------------
# PART 1 — the reproduction
# ---------------------------------------------------------------------------


def test_a_setup_timeout_is_NOT_recorded_as_a_successful_execution():
    """THE REPRODUCTION. The audit's exact probe.

    ``started_ok=True, candidate_started=False, timed_out=True``: isolation came
    up, the wall clock expired during setup, and the candidate never ran. Against
    the unfixed mapping this returned ``executed=True`` with "ran in sandbox".
    """

    result = _execute(started_ok=True, candidate_started=False, timed_out=True)

    assert not result.executed, (
        "a candidate that never started was recorded as an execution"
    )
    assert result.refused
    assert "ran in sandbox" not in result.detail


def test_the_receipt_says_the_candidate_never_started(tmp_path):
    """The other half. Refusing is not enough if the record cannot say WHY —
    an operator reading "refused" with no cause cannot tell a harness fault from
    a policy decision, and the two have different remedies."""

    result = _execute(started_ok=True, candidate_started=False, timed_out=True)

    assert "the candidate never" in result.detail, result.detail
    # And it must not read as a policy decision: the remedy for a harness fault
    # is to repair the harness, not to revisit an authorization.
    assert "refused" in result.detail
    # WITHDRAWN AND CORRECTED. This first asserted ``not result.started_ok``,
    # on the reasoning that the record "still claims the run started". That was
    # wrong: ``ExecutionResult.started_ok`` is documented as whether ISOLATION
    # started, and here it did. Asserting the false value made the two harness
    # faults — no runtime, and a setup that ran out of wall clock —
    # indistinguishable in the record, which is the collapse this whole module
    # exists to prevent, committed one field over.
    assert result.started_ok, "isolation started; the record must keep saying so"
    assert not result.candidate_started


# ---------------------------------------------------------------------------
# PART 2 — the paired positive control
# ---------------------------------------------------------------------------


def test_a_genuine_execution_is_still_recorded_as_executed():
    """THE PAIRED positive control (doctrine #4). Without it the reproduction is
    consistent with an executor that has stopped recording any execution."""

    result = _execute(started_ok=True, candidate_started=True, exit_status=0)

    assert result.executed and not result.refused
    assert result.started_ok
    assert "ran in sandbox" in result.detail


def test_a_candidate_that_ran_and_then_timed_out_is_still_an_execution():
    """THE BOUNDARY, and the one an over-broad fix would break. A candidate that
    STARTED and was then killed by the wall clock DID run — its side effects
    happened. That is the candidate's own outcome, not a harness fault, and the
    distinction is exactly what ``candidate_started`` exists to carry.

    A fix keyed on ``timed_out`` instead of ``candidate_started`` would refuse
    this, discarding a real execution's record.
    """

    result = _execute(started_ok=True, candidate_started=True, timed_out=True)

    assert result.executed and not result.refused


# ---------------------------------------------------------------------------
# PART 3 — the whole triple space, with reachability stated
# ---------------------------------------------------------------------------

#: Every (started_ok, candidate_started, timed_out) triple, the outcome the
#: mapping must produce, and whether a SHIPPED isolating adapter can produce it.
#:
#: Reachability measured from the adapters' source (see PART 4): both isolating
#: adapters tie ``started_ok = candidate_started`` on their NORMAL paths and
#: hard-code ``started_ok=True`` on their TIMEOUT paths. So
#: ``started_ok=True, candidate_started=False`` arises ONLY with
#: ``timed_out=True``, and ``started_ok=False, candidate_started=True`` cannot
#: arise at all.
TRIPLES = [
    # started_ok, candidate_started, timed_out, executed, reachable, why
    (True, True, False, True, True, "normal run, candidate confirmed"),
    (True, True, True, True, True, "candidate ran, then the wall clock killed it"),
    (True, False, True, False, True, "SETUP timeout: the candidate never ran"),
    (True, False, False, False, False,
     "no adapter path: the normal paths tie started_ok = candidate_started"),
    (False, False, False, False, True, "isolation never started"),
    (False, False, True, False, True, "launch failed; timeout flag immaterial"),
    (False, True, False, False, False,
     "contradictory: isolation down but the candidate confirmed running"),
    (False, True, True, False, False, "contradictory, as above"),
]


@pytest.mark.parametrize(
    "started_ok,candidate_started,timed_out,executed,reachable,why",
    TRIPLES,
    ids=[f"{int(a)}{int(b)}{int(c)}" for a, b, c, _, _, _ in TRIPLES],
)
def test_every_triple_maps_to_its_stated_outcome(
    started_ok, candidate_started, timed_out, executed, reachable, why
):
    """Total over the field space, reachable or not.

    The unreachable rows are asserted too, deliberately: "no adapter produces
    this today" is a statement about the adapters, and the mapping is what this
    module pins. An adapter change that makes one reachable must not also have
    to discover what the executor does with it.
    """

    result = _execute(
        started_ok=started_ok,
        candidate_started=candidate_started,
        timed_out=timed_out,
    )

    assert result.executed is executed, why
    assert result.refused is (not executed), why


def test_the_triple_table_is_total_over_the_field_space():
    """Eight rows for three booleans. A table that silently lost a row would
    leave a combination pinned by nothing, which is how this defect existed:
    the mapping read one field of three."""

    assert len(TRIPLES) == 8
    assert len({(a, b, c) for a, b, c, _, _, _ in TRIPLES}) == 8


# ---------------------------------------------------------------------------
# PART 4 — reachability, read from the adapters rather than asserted
# ---------------------------------------------------------------------------


def _assigned_literals(module: str, function_names: set[str], keyword: str) -> set:
    """Every literal passed as ``keyword`` to a ``SandboxResult(...)`` call in
    ``module``. ``None`` stands for "a computed value, not a literal"."""

    tree = ast.parse((SRC / module).read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", getattr(node.func, "attr", None))
        if name != "SandboxResult":
            continue
        for kw in node.keywords:
            if kw.arg != keyword:
                continue
            if isinstance(kw.value, ast.Constant):
                found.add(kw.value.value)
            else:
                found.add(None)  # computed
    return found


@pytest.mark.parametrize("module", ["sandbox/namespace.py", "sandbox/container.py"])
def test_the_isolating_adapters_really_can_report_started_without_a_candidate(module):
    """The reachability claim, measured rather than repeated.

    Each isolating adapter constructs at least one ``SandboxResult`` with
    ``started_ok=True`` as a LITERAL — the timeout path — while
    ``candidate_started`` comes from the start signal and may be False. That is
    the triple the reproduction uses, so the fake sandbox stands in for a state
    the shipped code really produces.
    """

    started = _assigned_literals(module, set(), "started_ok")
    candidate = _assigned_literals(module, set(), "candidate_started")

    assert True in started, f"{module} never reports started_ok=True as a literal"
    assert None in candidate, (
        f"{module} never computes candidate_started; if it is always a literal "
        "the reachability argument here no longer holds"
    )


@pytest.mark.parametrize("module", ["sandbox/namespace.py", "sandbox/container.py"])
def test_the_adapters_tie_started_to_the_candidate_on_their_normal_paths(module):
    """Why ``started_ok=True, candidate_started=False`` is a TIMEOUT-only state.

    Both adapters contain ``started_ok = candidate_started`` on the non-timeout
    path. Pinned because the triple table's reachability column rests on it: if
    an adapter stopped tying them, row ``100`` would become reachable and the
    table would be stale.
    """

    source = (SRC / module).read_text(encoding="utf-8")
    assert "started_ok = candidate_started" in source


# ---------------------------------------------------------------------------
# PART 5 — the class, not the instance
# ---------------------------------------------------------------------------
#
# F16 was found by checking ``started_ok`` against ``candidate_started`` in ONE
# executor. Sweeping every site that derives an execution or verification
# outcome from the sandbox result found two more in ``tools/git.py``, one of
# them in the executor that really deletes branches.
#
# THE SWEEP, and what each site read BEFORE this change:
#
#   verifier/runner.py   8 fields, incl. candidate_started      TOTAL
#   verifier/sql.py      branches on candidate_started inside
#                        timed_out and again for a missing
#                        payload                                TOTAL
#   execution/executor.py   started_ok alone                    NOT TOTAL (F16)
#   tools/git.py            started_ok + exit_status            NOT TOTAL (below)
#   sandbox/namespace.py    produces the result; derives nothing      n/a
#   execution/controller.py, cli/main.py, the demos
#                           read exit_status to RECORD, not to derive n/a


class _GitTriple(Sandbox):
    name = "git-triple"
    isolating = True

    def __init__(self, **fields) -> None:
        self._fields = fields

    def run(self, *, argv, workspace, limits: Limits = Limits(), stdin: str = ""):
        return SandboxResult(**self._fields)


def _tool(**fields):
    from prometheus_protocol.tools.git import GitTool

    return GitTool(repo_path="/tmp", sandbox=_GitTriple(**fields), base_branch="main")


HARNESS_FAULT = dict(started_ok=True, candidate_started=False, timed_out=True)


def test_a_git_read_after_a_setup_timeout_answers_NOTHING():
    """THE REPRODUCTION FOR THE READS, with ``exit_status=0``.

    Before this change the guards tested ``started_ok or exit_status != 0`` and
    were safe ONLY BY ACCIDENT: the shipped adapters leave ``exit_status`` at
    ``None`` on their timeout paths and ``None != 0``. With the same harness
    fault and a zero exit, ``classify`` returned ``0`` — "zero commits absent
    from the base", which is precisely the evidence that authorizes an
    irreversible branch delete — from a run where git never executed.
    """

    tool = _tool(**HARNESS_FAULT, exit_status=0, stdout="0\n")

    assert tool.classify("feature").unmerged_commits is None, (
        "a merge proof was produced by a git command that never ran"
    )
    assert tool.rev("main") is None
    with pytest.raises(Exception):
        tool.branches()


def test_the_same_reads_still_work_when_git_actually_ran():
    """The paired positive control (doctrine #4) for the reads."""

    tool = _tool(started_ok=True, candidate_started=True, exit_status=0, stdout="0\n")

    assert tool.classify("feature").unmerged_commits == 0
    assert _tool(
        started_ok=True, candidate_started=True, exit_status=0, stdout="a" * 40 + "\n"
    ).rev("main") == "a" * 40


def test_the_reads_were_previously_saved_by_a_CROSS_MODULE_accident():
    """Pins the invariant the old guards silently depended on.

    The old code was safe because the isolating adapters leave ``exit_status``
    unset on their timeout paths. That is a property of a DIFFERENT module, and
    nothing checked it. It is checked here now: if an adapter starts reporting a
    zero exit alongside a setup timeout, this fails and names why.
    """

    for module in ("sandbox/namespace.py", "sandbox/container.py"):
        source = (SRC / module).read_text(encoding="utf-8")
        timeout_block = source.split("TimeoutExpired", 1)[1].split("return SandboxResult", 1)[1]
        head = timeout_block[: timeout_block.index(")")]
        assert "exit_status=0" not in head, (
            f"{module} now reports exit_status=0 on its timeout path; the git "
            "reads no longer have the accidental safety they once had"
        )


def test_the_branch_delete_executor_does_not_claim_a_delete_that_never_ran(tmp_path):
    """THE SECOND F16, in the executor that really deletes.

    Reading ``started_ok`` alone produced ``executed=False`` — fail-closed, so
    no branch was lost — with the detail "ran in sandbox but failed (exit None)"
    and ``started_ok=True``. A record saying the delete was ATTEMPTED and
    rejected by git, when git never started: an operator would look for the
    reason git refused, and there is none.

    The AUTHORIZATION is real (a real repository, the real merge check, the real
    gate); only the executor's sandbox is the fake, because the triple is what
    is under test.
    """

    import test_reobservation_branch_delete as fixture
    from prometheus_protocol.tools.git import GitBranchDeleteExecutor

    fixture._make_repo(tmp_path)
    tool = fixture._tool(tmp_path)
    decision = ActionGate(
        target_canonical=f"git://{tool.repo_path}",
        authorizer=ExecutionAuthorizer(
            lambda: load_profile(DEFAULT_PROFILE_ID)
        ),
    ).decide(
        fixture._assessment(tool, fixture.BRANCH),
        attempt_id=f"delete-branch:{fixture.BRANCH}",
        action=tool.delete_action(fixture.BRANCH),
        subject_id="s",
    )
    assert decision.approved, "this proof needs an APPROVED delete to execute"

    executor = GitBranchDeleteExecutor(
        repo_path=tmp_path,
        sandbox=_GitTriple(**HARNESS_FAULT),
        allow_delete=True,
    )
    result = executor.execute(decision)

    assert not result.executed
    assert result.refused, "a harness fault was recorded as an attempted delete"
    assert result.started_ok, "isolation started; the record must keep saying so"
    assert not result.candidate_started
    assert "ran in sandbox but failed" not in result.detail
    assert "git never did" in result.detail
    # And the branch is still there: fail-closed in fact, not only in wording.
    assert tool.rev(fixture.BRANCH) is not None


def test_the_git_read_predicate_is_conservative_under_a_CONTRADICTORY_signal():
    """``_ran`` requires BOTH flags, and the second one is load-bearing only
    for a combination no shipped adapter produces.

    ``started_ok=False`` with ``candidate_started=True`` — isolation reported
    down while the candidate reported running — is contradictory, and the triple
    table above marks it unreachable for exactly the reason given there. It is
    asserted anyway, for the same reason those rows are: "no adapter produces
    this today" is a statement about the adapters, and a predicate that reads
    the contract must not have a branch decided by nothing.

    FOUND BY A GREEN MUTATION. Dropping ``started_ok`` from the predicate
    reddened nothing, because every reachable input agrees with
    ``candidate_started`` alone. Probing the predicate directly over all four
    combinations showed which input distinguishes them, and this pins it.
    """

    from prometheus_protocol.tools.git import _ran

    class _Signal:
        def __init__(self, started_ok, candidate_started):
            self.started_ok = started_ok
            self.candidate_started = candidate_started

    assert _ran(_Signal(True, True)) is True
    assert _ran(_Signal(True, False)) is False
    assert _ran(_Signal(False, False)) is False
    # The one that only ``started_ok`` can decide:
    assert _ran(_Signal(False, True)) is False, (
        "a contradictory signal was read as a completed run"
    )


# ---------------------------------------------------------------------------
# PART 6 — two harness faults, two records
# ---------------------------------------------------------------------------
#
# REPORTED ON THE FIX ITSELF, AND CORRECT. The first version of the refusal
# above wrote ``started_ok=False`` for a case where isolation HAD started. It
# refused correctly and recorded falsely: ``ExecutionResult.started_ok`` is
# documented as whether ISOLATION started, so the value was wrong, and it made
# the two harness faults indistinguishable in the record.
#
# That is the same collapse this module exists to prevent — could-not-verify
# rendered as something it is not — committed one field over while fixing it.


def test_the_two_harness_faults_are_DISTINGUISHABLE_in_the_record():
    """Their remedies differ, so the record must tell them apart.

    Isolation that never started is a missing or broken runtime: install it,
    check the configuration. Isolation that started while the candidate did not
    is a setup that ran out of wall clock: raise the limit, look at what setup
    is doing. An operator handed one value for both has to guess which.
    """

    no_runtime = _execute(started_ok=False, candidate_started=False)
    setup_timeout = _execute(
        started_ok=True, candidate_started=False, timed_out=True
    )

    # Both refuse, and neither claims an execution.
    for result in (no_runtime, setup_timeout):
        assert not result.executed and result.refused

    # And they are not the same record.
    assert no_runtime.started_ok is False
    assert setup_timeout.started_ok is True, (
        "isolation started here; recording False collapses this into 'no runtime'"
    )
    assert no_runtime.candidate_started is False
    assert setup_timeout.candidate_started is False
    assert (no_runtime.started_ok, no_runtime.candidate_started) != (
        setup_timeout.started_ok,
        setup_timeout.candidate_started,
    )


def test_the_execution_record_mirrors_the_sandbox_contract():
    """Both flags mean in ``ExecutionResult`` what they mean in
    ``SandboxResult``. Two types carrying the same two facts under the same two
    names, so a reader does not have to learn which layer redefines them."""

    from prometheus_protocol.swarm.models import ExecutionResult

    for field in ("started_ok", "candidate_started"):
        assert field in ExecutionResult.__dataclass_fields__
        assert field in SandboxResult.__dataclass_fields__

    # A real execution carries both as true, so the pair is not vestigial.
    ran = _execute(started_ok=True, candidate_started=True, exit_status=0)
    assert ran.started_ok and ran.candidate_started


def test_the_branch_delete_executor_keeps_the_same_distinction(tmp_path):
    """The identical rewrite was in ``GitBranchDeleteExecutor`` and is corrected
    there too — the reviewer named that site as well, and a fix applied to one
    executor and not its sibling is the asymmetry this sprint keeps finding."""

    import test_reobservation_branch_delete as fixture
    from prometheus_protocol.tools.git import GitBranchDeleteExecutor

    fixture._make_repo(tmp_path)
    tool = fixture._tool(tmp_path)
    decision = ActionGate(
        target_canonical=f"git://{tool.repo_path}",
        authorizer=ExecutionAuthorizer(lambda: load_profile(DEFAULT_PROFILE_ID)),
    ).decide(
        fixture._assessment(tool, fixture.BRANCH),
        attempt_id=f"delete-branch:{fixture.BRANCH}",
        action=tool.delete_action(fixture.BRANCH),
        subject_id="s",
    )

    def run(**fields):
        return GitBranchDeleteExecutor(
            repo_path=tmp_path, sandbox=_GitTriple(**fields), allow_delete=True
        ).execute(decision)

    no_runtime = run(started_ok=False, candidate_started=False)
    setup_timeout = run(**HARNESS_FAULT)

    assert no_runtime.started_ok is False
    assert setup_timeout.started_ok is True
    assert not setup_timeout.candidate_started
    assert tool.rev(fixture.BRANCH) is not None  # nothing was deleted either way
