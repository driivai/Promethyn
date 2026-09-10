"""The PHASE-1.2a revert runner is pinned: drift in EITHER direction FAILs.

Same discipline as the F11, PROM-FIX-B, substrate, PIH-4a, TYPE-GATE, PROD-FIX-1
and PROD-FIX-2 pin tests. Loads the runner as a module and proves, without
executing pytest inside pytest: the mutation list is exactly the pinned size with
distinct names; every mutation's edit target still exists in the function it
rewrites; each selection is non-empty and names a real test file; and the
enforcement refuses a shortfall AND an excess.

It also checks the property specific to this sprint: every mutation must remove
either THE OMISSION RULE, COVERAGE-BEFORE-FUSION, THE R3 LINE, or THE SWARM AS A
CALLER — the four things PHASE-1.2a added. A runner whose mutations no longer
remove one of those is measuring nothing.
"""

from __future__ import annotations

import importlib.util
import inspect
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "phase_1_2a_revert_proofs.py"


@pytest.fixture(scope="module")
def runner():
    sys.path.insert(0, str(REPO / "scripts"))
    try:
        spec = importlib.util.spec_from_file_location("phase_1_2a_revert_proofs", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(REPO / "scripts"))
    return module


def test_the_runner_is_pinned_and_every_target_still_exists(runner):
    assert (runner.EXPECTED_REVERTS, runner.EXPECTED_CALL_FAILURES) == (11, 25)
    plan = runner.mutations()
    assert len(plan) == runner.EXPECTED_REVERTS
    assert len({name for name, *_ in plan}) == len(plan), "duplicate mutation names"
    for name, function, edits, test_file, selection in plan:
        assert (REPO / test_file).exists(), f"{name}: {test_file} does not exist"
        assert selection.strip(), f"{name}: empty -k selection"
        text = textwrap.dedent(inspect.getsource(function))
        for old, _new in edits:
            assert old in text, (
                f"{name}: revert target vanished from {function.__qualname__}: "
                f"{old!r} — this proof would no longer execute"
            )


def test_every_TERM_of_every_selection_actually_selects_tests(runner):
    """Every ``-k`` term must match at least one test — not merely the whole
    expression.

    The weaker check is the one I wrote first, and it is VACUOUS. Selections here
    are disjunctions, so a dead branch of ``"a or b"`` still collects ``b``: the
    proof silently narrows to half of what it names, "no tests ran" never
    appears, and only the aggregate failure count would notice — a count a
    second drifted selection could rebalance. Measured: renaming
    ``eight_state_matrix`` to ``swarm_matrix`` left three selections stale and the
    whole-expression check stayed GREEN on all three.

    This is the allowlist doctrine's own failure, recorded in the threat model:
    a ``-k`` expression is a filter over test NAMES, and a rename is exactly what
    can vary that the filter does not constrain. So the unit checked is the TERM,
    which is the thing that can go stale on its own.

    HOW IT CHECKS, and the limit of that. The names are read out of each file's
    AST, and a term counts as live when it is a substring of a test function's
    name — which is what ``-k`` does for a plain identifier. It does NOT spawn
    pytest. The earlier version ran ``pytest --collect-only`` per term and was
    replaced for one measured reason: 0.14s against 5.23s, plus not wanting a
    pytest session inside a pytest session. It was NOT replaced because it hung.
    Two commits claimed it did — once on CI, once locally — and both were wrong;
    the CI run carrying it went green in 7m43s and the local run was killed at
    about two minutes while running normally. Recorded here because the wrong
    reason is the more memorable one, and the next reader should not inherit it.

    The limit the AST scan buys: a term matching only a ``parametrize`` ID, a
    class name or a file path would be reported as dead. None here is of that
    shape, and a future one should be rewritten rather than have this relaxed —
    the point is that the term names a test.
    """

    import ast
    import re

    def test_names(path: Path) -> list[str]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        return [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test")
        ]

    keywords = {"or", "and", "not"}
    for name, _function, _edits, test_file, selection in runner.mutations():
        terms = [t for t in re.findall(r"\w+", selection) if t not in keywords]
        assert terms, f"{name}: -k {selection!r} has no selectable term"
        names = test_names(REPO / test_file)
        assert names, f"{name}: {test_file} defines no tests at all"
        for term in terms:
            assert any(term in candidate for candidate in names), (
                f"{name}: the term {term!r} in -k {selection!r} matches NOTHING in "
                f"{test_file}. The other terms may still collect, so this proof "
                "would run a NARROWER set than it claims and still look green."
            )


def test_every_mutation_removes_something_phase_1_2a_added(runner):
    installed = (
        "policy.covers(",                 # silence is not permission
        "item.check_id in policy_required",   # requests may only ADD
        "action_class in item.applies_to",    # the empty-requirement floor
        "isinstance(outcome, CoverageRefused)",  # coverage decided BEFORE fusion
        "outcome.decided == Verdict.PASS",       # the acceptance condition
        "saw_fail",                              # a failed required check refuses
        "result.snapshot_digest != digest",      # the binding
        "result.implementation not in permitted",  # permitted implementations
        "result.implementation in answered",       # duplicates never count
        "REFUSED_INCOMPLETE",                      # THE R3 LINE
        "self.code_verifier.verifier_id",          # the swarm as a caller
    )
    for name, _function, edits, _file, _selection in runner.mutations():
        for old, new in edits:
            assert any(marker in old for marker in installed), (
                f"{name}: the reverted text is not something PHASE-1.2a added: {old!r}"
            )
            assert old != new, f"{name}: the mutation changes nothing"


def test_a_shortfall_or_an_excess_fails_the_runner(runner):
    reverts, failures = runner.EXPECTED_REVERTS, runner.EXPECTED_CALL_FAILURES
    runner.enforce_expected(reverts, failures)
    for caught, observed in (
        (reverts - 1, failures),
        (reverts + 1, failures),
        (reverts, failures - 1),
        (reverts, failures + 1),
        (0, 0),
    ):
        with pytest.raises(AssertionError, match="drifted"):
            runner.enforce_expected(caught, observed)


def test_the_runner_covers_all_four_families(runner):
    """A runner that drifted into covering only the easy family would still
    print a reassuring number."""

    names = [name for name, *_ in runner.mutations()]
    assert any(n.startswith("resolver-") for n in names), "no omission-rule mutation"
    assert any(n.startswith("policy-") for n in names), "no policy-floor mutation"
    assert any(n.startswith("bank-") or n.startswith("coverage-") for n in names)
    assert any(n.startswith("swarm-") for n in names), "no swarm-as-caller mutation"
    assert any("absence-satisfy" in n for n in names), "THE R3 LINE is not pinned"


def test_the_runner_states_its_own_limit(runner):
    doc = runner.__doc__ or ""
    for claim in (
        "does NOT prove\nthe mutation set is complete",
        "the count says nothing about semantic\ncoverage",
        "Nor is it externally anchored",
    ):
        assert claim in doc, f"the runner no longer states: {claim!r}"


def test_the_runner_records_the_mutation_that_did_not_work(runner):
    """One plausible mutation produced NO failure and is recorded rather than
    quietly dropped: ``resolver.resolve``'s empty-requirement guard is
    unreachable while the policy floor refuses a covered class with no
    requirement. Keeping the note stops the next reader re-deriving it and
    concluding the guard is stronger than it is."""

    source = inspect.getsource(runner)
    assert "a mutation that did NOT work" in source
    assert "unreachable defence-in-depth" in source
