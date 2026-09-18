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

    def run(**fields):
        # A FRESH decision per run. G24 made a minted authorization single-use
        # at the executor wall, so handing one object to both runs would now be
        # refused as a replay — and it should be: these are two attempts under
        # two different harness conditions, and the first one's refusal (no
        # side effect) is exactly the case that leaves the caller free to mint
        # again and try.
        decision = ActionGate(
            target_canonical=f"git://{tool.repo_path}",
            authorizer=ExecutionAuthorizer(lambda: load_profile(DEFAULT_PROFILE_ID)),
        ).decide(
            fixture._assessment(tool, fixture.BRANCH),
            attempt_id=f"delete-branch:{fixture.BRANCH}",
            action=tool.delete_action(fixture.BRANCH),
            subject_id="s",
        )
        return GitBranchDeleteExecutor(
            repo_path=tmp_path, sandbox=_GitTriple(**fields), allow_delete=True
        ).execute(decision)

    no_runtime = run(started_ok=False, candidate_started=False)
    setup_timeout = run(**HARNESS_FAULT)

    assert no_runtime.started_ok is False
    assert setup_timeout.started_ok is True
    assert not setup_timeout.candidate_started
    assert tool.rev(fixture.BRANCH) is not None  # nothing was deleted either way


# ---------------------------------------------------------------------------
# PART 7 — the vocabulary claim, pinned rather than left in prose
#
# G35's "CAN THE RECORD SAY IT?" section states two things about the outcome
# vocabulary, and F14 is expected to build on them. A contract-completeness
# claim carried in prose with no instrument behind it is precisely what that
# same entry criticises in F18, so both halves are pinned here. These are
# STATE-OF-THE-WORLD pins: they are written to fail when the world changes, so
# that whoever changes it also updates the entry F14 reads.
# ---------------------------------------------------------------------------


def test_the_execution_record_has_NO_typed_reason_field():
    """Half one: the record carries free text, not a closed-set token.

    If someone adds a typed reason to ``ExecutionResult`` this fails, and that
    is the intent — G35 tells F14 that option (2) is UNBUILT, and a silently
    built option (2) would leave F14 reading a stale entry.
    """

    import dataclasses

    from prometheus_protocol.swarm.models import ExecutionResult

    names = {f.name for f in dataclasses.fields(ExecutionResult)}

    assert names == {
        "executed", "subject_id", "detail", "refused", "started_ok",
        "candidate_started", "sandbox_name", "exit_status", "stdout",
        # G24/#128: whether ``stdout`` is captured output AT ALL. NOT a typed
        # reason and not option (2) — it carries no closed-set token and says
        # nothing about why anything was refused. It exists because a returned
        # prior result has no stdout to return (the ledger records no such
        # column) and the first attempt said so with a sentence INSIDE
        # ``stdout``, which candidate code can print verbatim. An in-band
        # signal a consumer cannot distinguish from real output; the
        # availability is its own fact, exactly as ``started_ok`` and
        # ``candidate_started`` are two facts and not one.
        "stdout_recorded",
    }, f"ExecutionResult's fields changed: {sorted(names)}"
    assert not {n for n in names if "reason" in n}, (
        "ExecutionResult gained a reason field — G35's 'as a typed reason, NO' "
        "is now false and F14's choice has been made by accident"
    )
    # And the field that DOES carry the cause is plain text.
    detail = next(f for f in dataclasses.fields(ExecutionResult) if f.name == "detail")
    assert detail.type in (str, "str"), detail.type


#: ``EXECUTION_REFUSAL_REASONS`` as it stands, pinned by MEMBERSHIP.
#:
#: WHY THE EXACT SET AND NOT A PREDICATE OVER NAMES. The first version of the
#: test below asked whether any member contained one of seven substrings
#: ("sandbox", "harness", "candidate", ...). Review found that it does not
#: detect the change it claims to pin, and a direct probe agreed: adding
#: ``runtime_unavailable``, ``setup_failed``, ``infra_fault`` or
#: ``execution_did_not_run`` to the set left every assertion GREEN — four of
#: five counterexamples missed, and the one it caught was the one that happened
#: to contain the author's own tokens.
#:
#: That is G25's rule restated: A NAME IS NOT A MEMBERSHIP. A predicate over
#: spellings infers semantics from whatever fragments the author thought of,
#: and an addition is free to be named anything. So the set is pinned as a set.
#: Any addition fails, whatever it is called, and the failure sends the author
#: to G35 to decide whether it belongs to this stage at all.
_AUTHORIZATION_REFUSAL_REASONS = frozenset({
    # integrity of a pinned record against its chain entry
    "chain_did_not_verify",
    # the stored rows could not be DECODED at all -- a malformed JSON column in
    # a corrupted or tampered ledger. Added on #123 after review found that
    # `verify_chain` and `verify_ledger_file` CRASHED with a raw
    # `json.JSONDecodeError` on such a ledger instead of returning the
    # documented NOT_VERIFIABLE, and the guarded readers handed the same raw
    # error back in place of a typed refusal. Distinct from the chain's own
    # reason above: this is evidence that cannot be read into a shape the hash
    # walk could check.
    "ledger_rows_unreadable",
    "chain_entry_count_wrong",
    "record_differs_from_chain_entry",
    "reverification_required",
    # descriptor binding
    "descriptor_absent",
    "descriptor_field_mismatch",
    "descriptor_missing_action",
    "descriptor_policy_cannot_authorize",
    "descriptor_snapshot_mismatch",
    # re-observation of the live target
    "state_moved_after_approval",
    "target_state_absent",
    "target_state_aspects_differ",
    "target_state_moved_before_approval",
    "target_state_registry_mismatch",
    "target_state_unreadable",
    # the pre-approval receipt
    "pre_approval_receipt_ambiguous",
    "pre_approval_receipt_missing",
    # the decision and the outcome against their chained receipts (F13/F14).
    # Integrity conditions of the authorization stage — "why may this hold
    # not proceed" — alongside record_differs_from_chain_entry, not an
    # execution-stage vocabulary: none of them describes what the sandbox did.
    "decision_entry_missing",
    "decision_differs_from_chain_entry",
    "outcome_entry_missing",
    "outcome_differs_from_chain_entry",
    # the inverse walk (review of #121): a receipt whose row is gone
    "execution_row_missing",
    "hold_row_missing",
    # G24: an authorization is SPENT when it is used. Every one of these
    # answers "why may this authorization not proceed" — the authorization
    # stage's own question — and none of them describes what the sandbox did,
    # which is the line G35 draws and the reason this pin exists.
    #
    # ``execution_outcome_unknown`` is the one worth arguing, because its NAME
    # contains "execution". It is still an authorization condition: it does not
    # report a harness fault or a candidate's fate, it reports that this
    # occurrence was already claimed and the system cannot establish what
    # happened — so the authorization cannot be granted again. A name is not a
    # membership (G25) in this direction too.
    "authorization_already_spent",
    "idempotency_key_mismatch",
    "authorization_not_retryable",
    "idempotency_key_expired",
    "execution_outcome_unknown",
    "spend_record_unreadable",
})


def test_the_authorization_vocabulary_names_no_harness_fault():
    """Half two: ``EXECUTION_REFUSAL_REASONS`` belongs to a different stage.

    G35 says widening THIS set would conflate authorization with execution.
    That argument only holds while the set really contains no execution-stage
    member, so its membership is pinned rather than inferred from spellings —
    see the note above for what the inferred version missed.
    """

    from prometheus_protocol.policy.execution import EXECUTION_REFUSAL_REASONS

    added = EXECUTION_REFUSAL_REASONS - _AUTHORIZATION_REFUSAL_REASONS
    removed = _AUTHORIZATION_REFUSAL_REASONS - EXECUTION_REFUSAL_REASONS

    assert not added, (
        f"EXECUTION_REFUSAL_REASONS gained {sorted(added)}. If these are "
        "authorization conditions, add them to the pin above. If any is an "
        "EXECUTION-stage condition, G35's argument against widening this set "
        "has been overridden and that entry must be updated — F14 reads it."
    )
    assert not removed, (
        f"EXECUTION_REFUSAL_REASONS lost {sorted(removed)}; a shrinking closed "
        "set silently widens what passes unchallenged elsewhere"
    )
    # The count is asserted too, and it is NOT the property — membership is.
    # It is here because G35 quotes a number, and a quoted number that nothing
    # checks is how "nineteen" was written for a set of seventeen.
    assert len(EXECUTION_REFUSAL_REASONS) == 30
    assert "descriptor_absent" in EXECUTION_REFUSAL_REASONS


def test_the_boolean_pair_IS_expressible_which_is_the_other_half():
    """G35 says structurally YES. Asserted, because "half yes" is only honest
    if the yes half is real: the pair must distinguish the two harness faults
    on the live mapping, not merely exist as two fields."""

    setup_timeout = _execute(started_ok=True, candidate_started=False, timed_out=True)
    no_runtime = _execute(started_ok=False, candidate_started=False, timed_out=False)

    assert (setup_timeout.started_ok, setup_timeout.candidate_started) == (True, False)
    assert (no_runtime.started_ok, no_runtime.candidate_started) == (False, False)
    assert not setup_timeout.executed and not no_runtime.executed


# ===========================================================================
# THE FAIL-OPEN DEFAULT ON THE SAME TWO FLAGS
#
# #130 flipped ``stdout_recorded`` to the fail-closed direction after finding
# that a claim true of the FIVE sites passing ``stdout=`` had been made about
# all ELEVEN that construct ``ExecutionResult``. Its own entry names
# ``started_ok`` and ``candidate_started`` as "two facts" and left both
# defaulting ``True``.
#
# Measured on the tree before this change, from the AST of every construction:
#
#     ExecutionResult constructions in src/: 11
#     started_ok:        explicit at 5 sites, INHERITED at 6
#     candidate_started: explicit at 2 sites, INHERITED at 9
#
# and of the thirteen ``_refuse`` calls, NINE inherited at least one
# permissive default — four of them refusals taken before the sandbox is ever
# constructed. The controller persists both flags into the audit ledger
# (``controller.py``, the one call that passes them), so the claim reached the
# audit record.
# ===========================================================================


class _NeverRuns(Sandbox):
    """Not isolating, so ``execute`` refuses BEFORE ``_run``. ``run`` raises:
    if the refusal path ever reached the sandbox this would say so loudly
    rather than letting the probe pass for the wrong reason."""

    name = "never-runs"
    isolating = False

    def run(self, *, argv, workspace, limits):  # pragma: no cover - must not run
        raise AssertionError("the sandbox was invoked on a pre-sandbox refusal path")


def test_a_refusal_taken_BEFORE_the_sandbox_claims_neither_harness_fact():
    """THE REPRODUCTION. Nothing started, so the record must not say it did.

    Observed before the fix::

        started_ok        : True   <- the sandbox was never invoked
        candidate_started : True   <- nothing ran

    The adapter is non-isolating, which ``SandboxExecutor.execute`` refuses
    before constructing anything, and its ``run`` raises — so this cannot pass
    because the sandbox quietly ran and reported success.
    """

    result = SandboxExecutor(sandbox=_NeverRuns()).execute(_approved())

    assert result.refused and not result.executed
    assert result.started_ok is False, (
        "a refusal taken before the sandbox is constructed claimed isolation "
        "started; the default was True and this path inherited it"
    )
    assert result.candidate_started is False, (
        "the same refusal claimed the candidate began"
    )


def test_the_refusal_reaches_the_AUDIT_LEDGER_claiming_nothing():
    """The consequential half: the controller persists both flags.

    ``record_execution`` is three-valued (``None`` = no executor invoked) and
    the controller passes ``result.started_ok``/``result.candidate_started``
    straight through on the one path that calls an executor. A refusal
    inheriting ``True`` therefore wrote ``started_ok=1, candidate_started=1``
    into the ``executions`` table for a run that never happened.
    """

    from prometheus_protocol.execution.controller import ExecutionController
    from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger

    code = "print('RAN')"
    action = ExecutableAction(kind=ACTION_PYTHON_CODE, code=code)
    assessed = carrying(
        Judgment(verdict=Verdict.PASS, confidence=1.0, authoritative=True),
        artifact_sha256=content_hash(code),
    )
    ledger = SqliteLedger(":memory:")
    controller = ExecutionController(
        gate=ActionGate(
            target_canonical="sandbox://test",
            authorizer=ExecutionAuthorizer(lambda: a_policy()),
        ),
        executor=SandboxExecutor(sandbox=_NeverRuns()),
        ledger=ledger,
    )
    controller.submit(
        attempt_id="attempt-1", assessment=assessed, action=action, subject_id="s"
    )

    rows = ledger.executions()
    assert len(rows) == 1, f"expected one execution row, got {len(rows)}"
    row = rows[0]
    assert row["refused"] is True and row["executed"] is False
    assert row["started_ok"] is False, (
        "the audit ledger records that isolation started for a refusal whose "
        "sandbox was never invoked — couldn't-verify persisted as "
        "verified-clean (doctrine #1)"
    )
    assert row["candidate_started"] is False


def test_the_POSITIVE_CONTROL_a_real_run_still_claims_both():
    """The positive control for the two reproductions above (doctrine #4).

    Without this, "no site claims a harness fact" is equally
    consistent with an executor that never claims anything at all, and the
    reproduction above would pass against a record that says nothing ever runs.

    ``_Triple`` is isolating and reports a real started/started/no-timeout run,
    which is the one shape that must still come back claiming both.
    """

    result = _execute(started_ok=True, candidate_started=True, exit_status=0)

    assert result.executed and not result.refused
    assert result.started_ok is True and result.candidate_started is True


def test_the_two_harness_flags_default_to_the_fail_closed_answer():
    """An unset flag must under-claim, never over-claim — #130's rule, applied
    to the two fields its own entry named and did not change."""

    import dataclasses

    from prometheus_protocol.swarm.models import ExecutionResult

    fields = {f.name: f for f in dataclasses.fields(ExecutionResult)}
    assert fields["started_ok"].default is False
    assert fields["candidate_started"].default is False
    bare = ExecutionResult(executed=False, subject_id="s")
    assert bare.started_ok is False and bare.candidate_started is False


#: The forms an argument to ``started_ok`` / ``candidate_started`` may take.
#: An ALLOWLIST, and it has to be one — see ``_measurement_form``.
_MEASUREMENT_FORMS = (
    "fail-closed constant",
    "adapter result attribute",
    "fail-closed parameter pass-through",
    "stored ledger column",
)


def _parameter_default_is_false(flag: str, function: ast.AST | None) -> bool:
    """Does ``flag`` name a parameter of ``function`` whose default is ``False``?

    THE SECOND #131 REVIEW FOUND THAT SPELLING WAS NOT ENOUGH, and it was
    right. ``started_ok=started_ok`` was accepted because the name matched, so
    flipping ``GitBranchDeleteExecutor._refuse``'s own default back to ``True``
    left every call-site shape and the exact census untouched and the rule
    green — while every pre-sandbox refusal claimed isolation had started
    again. Reproduced before this function existed: the mutation was GREEN.

    The pass-through is only a measurement because the parameter it forwards
    defaults to the fail-closed answer and every call to the helper is itself
    in the swept population. That premise is now CHECKED rather than assumed.

    A parameter with NO default is refused too: the flag is then whatever a
    caller passes, which is a claim this function cannot see.
    """

    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False

    arguments = function.args
    for parameter, default in zip(arguments.kwonlyargs, arguments.kw_defaults):
        if parameter.arg == flag:
            return isinstance(default, ast.Constant) and default.value is False

    positional = [*arguments.posonlyargs, *arguments.args]
    offset = len(positional) - len(arguments.defaults)
    for index, parameter in enumerate(positional):
        if parameter.arg == flag:
            if index < offset:
                return False
            default = arguments.defaults[index - offset]
            return isinstance(default, ast.Constant) and default.value is False

    return False


def _measurement_form(
    flag: str, node: ast.expr, enclosing: ast.AST | None = None
) -> str | None:
    """Name the MEASUREMENT this expression is, or ``None`` if it is not one.

    THIS IS AN ALLOWLIST, AND THE FIRST VERSION WAS A DENYLIST OF ONE SHAPE.
    That version asked only "is this the literal ``True``?" and called
    everything else measured — the first review's finding, and it was right.
    ``started_ok=1`` is a different constant with the same truth value;
    ``started_ok=decision.approved`` is an unrelated boolean read off an
    unrelated object; ``started_ok=result.candidate_started`` is the OTHER
    harness fact read off the right object. All three assert a fact nothing
    measured, and all three passed a rule that only knew one way to be wrong.

    A denylist over an open set of expressions cannot be complete, so the
    question is inverted: an argument is measured only if it is one of the
    forms that this tree can show comes from an adapter, a parameter that
    itself defaults fail-closed, or a stored column — and every one of them
    carries THE FLAG'S OWN NAME, so a cross-wired read is refused too.

    ``enclosing`` is the function the argument is written in, and it is
    required for the pass-through form: see ``_parameter_default_is_false``.
    """

    # ``started_ok=False`` — the fail-closed constant, which claims nothing.
    # ``True`` is deliberately not here: it is the hand-written claim this
    # whole entry exists to refuse.
    if isinstance(node, ast.Constant) and node.value is False:
        return "fail-closed constant"

    # ``started_ok=result.started_ok`` — read off the adapter's own result,
    # under the flag's own name.
    if (
        isinstance(node, ast.Attribute)
        and node.attr == flag
        and isinstance(node.value, ast.Name)
        and node.value.id == "result"
    ):
        return "adapter result attribute"

    # ``started_ok=started_ok`` — the enclosing helper's own parameter, passed
    # through under its own name, AND that parameter's default is the literal
    # ``False``. The name alone is not the measurement; the default behind it
    # is (second #131 review).
    if isinstance(node, ast.Name) and node.id == flag:
        if _parameter_default_is_false(flag, enclosing):
            return "fail-closed parameter pass-through"
        return None

    # ``started_ok=bool(row["started_ok"])`` — the column this fact was stored
    # in, under the flag's own name. The ledger replay.
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "bool"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Subscript)
        and isinstance(node.args[0].value, ast.Name)
        and node.args[0].value.id == "row"
        and isinstance(node.args[0].slice, ast.Constant)
        and node.args[0].slice.value == flag
    ):
        return "stored ledger column"

    return None


def _calls_with_enclosing_function(node, current=None):
    """``(enclosing FunctionDef | None, Call)`` for every call under ``node``."""

    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        current = node
    if isinstance(node, ast.Call):
        yield current, node
    for child in ast.iter_child_nodes(node):
        yield from _calls_with_enclosing_function(child, current)


def _harness_flag_arguments():
    """Every ``started_ok`` / ``candidate_started`` argument in ``src/``.

    Derived from the AST rather than hand-listed: a hand-list is an allowlist
    of SITES, and the one thing this rule must not need is a judgement about
    which sites "really ran" — the half Sprint 0 could not derive.

    Each row carries the function the argument is written in, because the
    pass-through form is only a measurement if that function's parameter
    defaults fail-closed.
    """

    src = Path(__file__).resolve().parents[2] / "src"
    flags = ("started_ok", "candidate_started")
    found = []
    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for enclosing, node in _calls_with_enclosing_function(tree):
            called = getattr(node.func, "id", getattr(node.func, "attr", None))
            if called not in ("ExecutionResult", "_refuse"):
                continue
            for keyword in node.keywords:
                if keyword.arg in flags:
                    found.append((
                        f"{path.relative_to(src.parent)}:{node.lineno}:{keyword.arg}",
                        keyword.arg,
                        keyword.value,
                        enclosing,
                    ))
    return found


def test_no_site_may_claim_a_harness_fact_it_did_not_MEASURE():
    """The population rule, derived from the AST rather than hand-listed.

    A site that observed isolation passes the value the ADAPTER reported
    (``result.started_ok``); a site that did not leaves the fail-closed
    default. So a hand-written truthy argument is never correct here: it is a
    claim written at a place that cannot have measured anything, and it is what
    the two pre-fix ``_refuse`` defaults and the git dry-run were.

    The rule is over the SHAPE of the argument AND the default behind it, and
    both are in the tree.
    """

    unrecognised, census = [], {name: 0 for name in _MEASUREMENT_FORMS}
    for where, flag, value, enclosing in _harness_flag_arguments():
        form = _measurement_form(flag, value, enclosing)
        if form is None:
            unrecognised.append(f"{where} = {ast.unparse(value)}")
        else:
            census[form] += 1

    assert sum(census.values()) or unrecognised, (
        "no harness-fact argument found at all: an empty sweep reads as a pass "
        "(doctrine #8), and this rule would then hold vacuously"
    )
    assert unrecognised == [], (
        f"site(s) claiming a harness fact in an unrecognised form: {unrecognised}. "
        "Pass the value the sandbox adapter reported, the stored column, or a "
        "helper parameter that itself defaults False — or leave the fail-closed "
        "default. Anything else is a claim nothing measured."
    )

    # Exact, both directions. A SHRINKING population is the way this rule goes
    # quiet without ever going red: the sites are the thing being constrained,
    # so their disappearance is a change to re-measure deliberately, not a pass.
    assert census == {
        "fail-closed constant": 4,
        "adapter result attribute": 8,
        "fail-closed parameter pass-through": 4,
        "stored ledger column": 2,
    }, f"the harness-fact population changed: {census}"


def test_the_shape_rule_is_not_universally_true():
    """Doctrine #8: the positive control for the sweep above.

    It calls ``_measurement_form`` rather than restating the test, because a
    control that reimplements the rule tests the restatement. Each rejected
    line is a concrete evasion of a rule this replaced: the three the
    literal-``True`` denylist let through, and the pass-through accepted on
    spelling alone while the parameter behind it defaulted ``True``.
    """

    fail_closed = ast.parse(
        "def _refuse(self, d, detail, *, started_ok=False):\n    pass\n"
    ).body[0]
    fail_open = ast.parse(
        "def _refuse(self, d, detail, *, started_ok=True):\n    pass\n"
    ).body[0]
    no_default = ast.parse(
        "def _refuse(self, d, detail, *, started_ok):\n    pass\n"
    ).body[0]

    planted = [
        # Recognised: the four forms the tree actually uses.
        ("started_ok=False", None, "fail-closed constant"),
        ("started_ok=result.started_ok", None, "adapter result attribute"),
        ("started_ok=started_ok", fail_closed, "fail-closed parameter pass-through"),
        ('started_ok=bool(row["started_ok"])', None, "stored ledger column"),
        # Refused: the literal the original rule caught...
        ("started_ok=True", None, None),
        # ...the three it did not...
        ("started_ok=1", None, None),
        ("started_ok=decision.approved", None, None),
        ("started_ok=result.candidate_started", None, None),
        ('started_ok=bool(row["candidate_started"])', None, None),
        # ...and the three the SPELLING rule did not: the same pass-through
        # over a parameter that defaults fail-OPEN, over one with no default at
        # all, and over no enclosing function whatsoever.
        ("started_ok=started_ok", fail_open, None),
        ("started_ok=started_ok", no_default, None),
        ("started_ok=started_ok", None, None),
    ]

    verdicts = []
    for argument, enclosing, _expected in planted:
        call = ast.parse(f"ExecutionResult({argument})").body[0].value
        verdicts.append(_measurement_form("started_ok", call.keywords[0].value, enclosing))

    assert verdicts == [expected for _, _, expected in planted], verdicts

    # The sweep itself must still find a population to constrain (doctrine #8).
    # NOT the exact count: pinning it here made this control redden whenever a
    # construction site changed, which is the SUBJECT moving, not the
    # classifier failing -- a control coupled to the thing it controls for. The
    # exact census is the rule's own assertion above, where it belongs.
    assert _harness_flag_arguments(), (
        "the sweep finds no harness-fact argument at all, so the rule above "
        "holds vacuously and this control proves nothing about it"
    )


def test_the_replay_carries_the_STORED_harness_facts_not_a_default():
    """The third site the default reached, and the least visible.

    ``_returned_prior_result`` rebuilds an ``ExecutionResult`` from a stored
    ``executions`` row. It reconstructed ``executed``, ``refused``,
    ``sandbox_name`` and ``exit_status`` from the row and inherited the two
    harness facts — so every replay asserted isolation had started and the
    candidate had begun, whatever the row said, including rows whose columns
    are ``NULL`` because no executor was ever invoked.
    """

    import inspect

    from prometheus_protocol.execution import controller as controller_module

    source = inspect.getsource(controller_module)
    tree = ast.parse(source)
    replays = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "id", None) == "ExecutionResult"
        and any(
            isinstance(k.value, ast.Constant) and k.value.value is False
            for k in node.keywords
            if k.arg == "stdout_recorded"
        )
    ]
    assert len(replays) == 1, (
        f"expected exactly the one replay construction, found {len(replays)}"
    )
    carried = {
        k.arg: ast.unparse(k.value)
        for k in replays[0].keywords
        if k.arg in ("started_ok", "candidate_started")
    }
    assert carried == {
        "started_ok": "bool(row['started_ok'])",
        "candidate_started": "bool(row['candidate_started'])",
    }, (
        f"the replay does not carry the stored harness facts: {carried}. A "
        "NULL column means no executor was invoked and must read as False, "
        "never as the class default."
    )
