"""The three built-in verifiers, described as conformance cases.

Each of the shipped domains — code (HARD), SQL (HARD), grounding (SOFT) —
fills in a :class:`VerifierCase`. That the three pass :func:`check_verifier`
unchanged is the proof that the extension contract describes the real seam,
not an aspiration. The fault injector for a HARD verifier is ``NullSandbox``
(it refuses to start, so the verifier must ABSTAIN); for the soft grounding
judge it is a provider that raises (any provider failure is "no opinion").
"""

from __future__ import annotations

from typing import Sequence

from prometheus_protocol.conformance.contract import VerifierCase
from prometheus_protocol.core.interfaces import Provider
from prometheus_protocol.core.models import Case, Skill, Tier, Task, Verdict
from prometheus_protocol.sandbox import NullSandbox
from prometheus_protocol.verifier.grounding import GroundingTask, GroundingVerifier
from prometheus_protocol.verifier.runner import SubprocessVerifier
from prometheus_protocol.verifier.sql import SqlTask, SqlVerifier, results_equivalent


# --------------------------------------------------------------------------
# code (HARD, subprocess + hidden cases)
# --------------------------------------------------------------------------

_CODE_TASK = Task(
    id="conformance/add", entry_point="add",
    prompt="Return the sum of two integers.", split="train",
    cases=(Case((2, 3), 5), Case((-1, 1), 0), Case((0, 0), 0)),
)
_CODE_PASS = "def add(a, b):\n    return a + b\n"
_CODE_FAIL = "def add(a, b):\n    return a - b\n"


def _code_adversarial() -> tuple[bool, str]:
    """A candidate that PRINTS a pass but returns wrong answers must FAIL.

    Ground truth is read from a result file the runner writes, never from
    stdout, so a candidate cannot forge a verdict by printing one.
    """

    liar = (
        "print('all tests passed')\n"
        "def add(a, b):\n    return 42\n"
    )
    ev = SubprocessVerifier(memory_mb=0).verify(code=liar, task=_CODE_TASK)
    ok = ev.verdict == Verdict.FAIL
    return ok, (
        "a candidate that prints a fake pass but returns wrong answers is "
        f"FAILed ({ev.verdict.value}; stdout cannot forge a verdict)"
    )


def code_case() -> VerifierCase:
    return VerifierCase(
        name="code (subprocess-tests, HARD)",
        verifier=SubprocessVerifier(memory_mb=0),
        tier=Tier.HARD,
        failclosed=(
            SubprocessVerifier(memory_mb=0, sandbox=NullSandbox()),
            (_CODE_PASS, _CODE_TASK),
        ),
        passing=(_CODE_PASS, _CODE_TASK),
        failing=(_CODE_FAIL, _CODE_TASK),
        adversarial=_code_adversarial,
    )


# --------------------------------------------------------------------------
# SQL (HARD, sandboxed result-equivalence)
# --------------------------------------------------------------------------

_SQL_SCHEMA = "CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER NOT NULL);"
_SQL_FIXTURE = "INSERT INTO t VALUES (1, 10), (2, 20), (3, 30);"
_SQL_TASK = SqlTask(
    id="conformance/sum", prompt="Total of v.",
    schema_sql=_SQL_SCHEMA, fixture_sql=_SQL_FIXTURE,
    reference_query="SELECT SUM(v) FROM t",
)
_SQL_PASS = "SELECT SUM(v) FROM t"
_SQL_FAIL = "SELECT COUNT(v) FROM t"  # right shape, wrong content


def _sql_adversarial() -> tuple[bool, str]:
    """The comparator rejects a right-shape / wrong-content result set.

    The SQL leak surface is the comparator; a coincidentally-shaped answer
    must not read as equivalent. (This is the pure comparator the verifier
    uses, exercised directly — the same adversarial template a new
    comparison-based verifier would supply.)
    """

    ref = {"columns": ["s"], "rows": [[60]]}
    wrong = {"columns": ["s"], "rows": [[3]]}  # COUNT, not SUM
    equal, _ = results_equivalent(ref, wrong)
    return (not equal), (
        "the comparator rejects a right-shape, wrong-content result "
        f"(equivalent={equal}; a coincidental shape is not a pass)"
    )


def sql_case() -> VerifierCase:
    return VerifierCase(
        name="sql (sql-result-equivalence, HARD)",
        verifier=SqlVerifier(),
        tier=Tier.HARD,
        failclosed=(SqlVerifier(sandbox=NullSandbox()), (_SQL_PASS, _SQL_TASK)),
        passing=(_SQL_PASS, _SQL_TASK),
        failing=(_SQL_FAIL, _SQL_TASK),
        adversarial=_sql_adversarial,
    )


# --------------------------------------------------------------------------
# grounding (SOFT, gold-labeled faithfulness) — no runtime needed
# --------------------------------------------------------------------------

_GROUNDING_TASK = GroundingTask(
    id="conformance/g", source="The hall opens at nine and admission is free.",
)
_GROUNDING_CLAIM_PASS = "Admission is free."
_GROUNDING_CLAIM_FAIL = "Admission costs five pounds."


class _ScriptedProvider(Provider):
    """Returns a fixed verdict for a supported claim and its negation."""

    model = "scripted"

    def propose_solution(self, *, prompt, entry_point, skills: Sequence[Skill] = ()):
        raise NotImplementedError

    def assess(self, *, prompt: str, system: str | None = None) -> str:
        if _GROUNDING_CLAIM_FAIL in prompt:
            return "NOT-SUPPORTED 0.9"
        return "SUPPORTED 0.9"


class _RaisingProvider(Provider):
    """A provider whose assess() always fails (ground truth unavailable)."""

    model = "raising"

    def propose_solution(self, *, prompt, entry_point, skills: Sequence[Skill] = ()):
        raise NotImplementedError

    def assess(self, *, prompt: str, system: str | None = None) -> str:
        raise RuntimeError("provider unreachable")


class _GibberishProvider(Provider):
    """A provider that returns prose the strict parser cannot read."""

    model = "gibberish"

    def propose_solution(self, *, prompt, entry_point, skills: Sequence[Skill] = ()):
        raise NotImplementedError

    def assess(self, *, prompt: str, system: str | None = None) -> str:
        return "It seems fine to me, more or less."


def _grounding_adversarial() -> tuple[bool, str]:
    """An unparseable judge reply is an ABSTAIN, never a guessed verdict."""

    ev = GroundingVerifier(_GibberishProvider()).verify(
        code=_GROUNDING_CLAIM_PASS, task=_GROUNDING_TASK
    )
    ok = ev.verdict == Verdict.ABSTAIN
    return ok, (
        "an unparseable judge reply yields "
        f"{ev.verdict.value!r} (ABSTAIN — a verdict is never guessed)"
    )


def grounding_case() -> VerifierCase:
    return VerifierCase(
        name="grounding (grounding-judge, SOFT)",
        verifier=GroundingVerifier(_ScriptedProvider()),
        tier=Tier.SOFT,
        failclosed=(
            GroundingVerifier(_RaisingProvider()),
            (_GROUNDING_CLAIM_PASS, _GROUNDING_TASK),
        ),
        passing=(_GROUNDING_CLAIM_PASS, _GROUNDING_TASK),
        failing=(_GROUNDING_CLAIM_FAIL, _GROUNDING_TASK),
        adversarial=_grounding_adversarial,
    )


def builtin_cases() -> tuple[VerifierCase, ...]:
    """The three shipped verifiers as conformance cases."""

    return (code_case(), sql_case(), grounding_case())
