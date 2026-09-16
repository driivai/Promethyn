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
    assert not result.started_ok, (
        "the execution record still claims the run started"
    )


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
