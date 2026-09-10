"""The PROD-FIX-2 revert runner is pinned: drift in EITHER direction FAILs.

Same discipline as the F11, PROM-FIX-B, substrate, PIH-4a, TYPE-GATE and
PROD-FIX-1 pin tests. Loads ``scripts/prod_fix_2_revert_proofs.py`` as a module
and proves, without executing pytest inside pytest: the mutation list is exactly
the pinned size with distinct names; every mutation's edit target still exists in
the function it rewrites (a vanished target is a proof that has silently stopped
executing); each selection is non-empty and names a test file that exists; and
the enforcement refuses a shortfall AND an excess.

It also checks the property specific to this sprint: every mutation must remove
either a SECRET WRAPPER or a BOUNDED DIAGNOSTIC — the two things PROD-FIX-2
added. A runner whose mutations no longer remove one of those is measuring
nothing, and F8 is precisely the finding where a reassuring number over the
wrong thing is the failure mode.
"""

from __future__ import annotations

import importlib.util
import inspect
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "prod_fix_2_revert_proofs.py"


@pytest.fixture(scope="module")
def runner():
    sys.path.insert(0, str(REPO / "scripts"))
    try:
        spec = importlib.util.spec_from_file_location("prod_fix_2_revert_proofs", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(REPO / "scripts"))
    return module


def test_the_runner_is_pinned_and_every_target_still_exists(runner):
    assert (runner.EXPECTED_REVERTS, runner.EXPECTED_CALL_FAILURES) == (15, 24)
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


def test_every_mutation_removes_something_prod_fix_2_added(runner):
    """Each ``old`` must be one of the two things this sprint installed, and
    each ``new`` must remove it. A mutation that merely edits text proves
    nothing about the fix."""

    installed = (
        "Secret(",                  # the wrapper, at a storage site
        "secret_or_none(",          # the normaliser
        "REDACTED",                 # the wrapper's own rendering
        "return self",              # __deepcopy__ keeping the wrapper
        "Diagnostic(",              # a bounded diagnostic in place of prose
        "REASON_CODES",             # the closed reason set
        "expected is None",         # the context allowlist
        "_is_bare_origin(",         # the endpoint constraint
        "redirect_diagnostic(",     # A5
        "_judgement_detail(",       # A4
        "translated = self._http_failure(",  # A3's call shape
        "body_bytes = len(self._read_bounded(",  # A1: count, not content
    )
    for name, _function, edits, _test_file, _selection in runner.mutations():
        for old, new in edits:
            assert any(marker in old for marker in installed), (
                f"{name}: the reverted text is not something PROD-FIX-2 added: "
                f"{old!r}"
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


def test_the_runner_covers_both_halves_of_the_finding(runner):
    """A runner that drifted into covering only the wrapper — the easy half —
    would still print a reassuring number.

    Both files must be exercised, and neither may collapse to a token presence:
    the wrapper mutations and the vocabulary mutations are separate claims.
    """

    files = {test_file for _, _, _, test_file, _ in runner.mutations()}
    assert files == {runner.SWEEP, runner.SINKS}, files

    wrapper_markers = ("Secret", "secret_or_none", "REDACTED")
    wrapper, vocabulary = 0, 0
    for _name, _function, edits, _file, _selection in runner.mutations():
        joined = "".join(old for old, _new in edits)
        if any(marker in joined for marker in wrapper_markers):
            wrapper += 1
        else:
            vocabulary += 1
    assert wrapper >= 5, f"only {wrapper} wrapper mutations"
    assert vocabulary >= 5, f"only {vocabulary} vocabulary mutations"


def test_the_runner_states_its_own_limit(runner):
    """A count says nothing about semantic coverage, and the runner is editable
    by whoever edits the code it guards. Both must be said where the assurance
    is described."""

    doc = runner.__doc__ or ""
    for claim in (
        "does NOT\nprove the mutation set is complete",
        "the count says nothing about semantic\ncoverage",
        "Nor is it externally anchored",
    ):
        assert claim in doc, f"the runner no longer states: {claim!r}"


def test_the_runner_records_the_mutations_that_did_not_work(runner):
    """Two plausible mutations produced NO failure, and that is a finding about
    the fix, not a gap to paper over.

    Copying a ``Secret`` still yields a ``Secret``, so ``__deepcopy__`` returning
    ``self`` is an identity property rather than a leak guard; and clearing
    ``__context__`` inside ``raise_bounded`` changes nothing when the caller
    honours the contract, because Python never populated it. Both are recorded
    in the runner where the proofs are, so the next reader does not re-derive
    them and quietly conclude the guard is stronger than it is.
    """

    source = inspect.getsource(runner)
    assert "does NOT leak, because the copy is still a" in source
    assert "produced no failure, so it is\n            # not claimed as a proof" in source
    assert "removing that line alone changes nothing" in source
