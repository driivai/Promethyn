"""No module outside the bank computes an authoritative verdict (2d).

WITHOUT THIS, THE POLICY IS A CONVENTION THE FOURTH AGGREGATOR IGNORES. Two
aggregators were reproduced fail-open; the swarm's is now a caller. Nothing
stops a third from being written, and a policy layer that one code path routes
around is a policy layer for the paths that happened to be migrated.

THE FORM, AND WHAT THE PERMITTED SET IS OVER — the doctrine question from
``docs/threat-model.md`` is not "is there a permitted set?" but **what can an
attacker change that this set does not constrain?**

The set here is over **(module, qualified function) pairs that CONSTRUCT an
authoritative Judgment**, with the callee resolved through each module's own
import bindings. That is deliberately not:

* **file paths or basenames** — the Hearth and inline-``# mypy:`` lessons: a path
  sanctioned once is sanctioned forever, and the name is chosen by whoever adds
  the file. A new module at a new path is NOT on this list and fails;
* **identifier spellings** — the expression-narrowing lesson: ``Judgment``,
  ``models.Judgment`` and ``Judgment as J`` are three spellings of one symbol,
  and this sweep resolves all three to ``core.models.Judgment`` before deciding.

WHAT CAN VARY THAT THIS SET DOES NOT CONSTRAIN — named here rather than left to
be found:

1. **A computed flag.** ``Judgment(..., authoritative=flag)`` where ``flag`` is
   not the literal ``True`` is not matched. The sweep reads a literal, because
   deciding a value's truth statically is the halting problem in a costume. The
   second layer is the behavioural proof: the essential regression drives every
   production entry point and requires the refusal, so a computed-flag
   aggregator on a production path shows up as the property no longer holding.
2. **Mutation of an existing Judgment.** ``dataclasses.replace(j,
   authoritative=True)`` reaches the same end by a different call. It IS swept —
   ``replace`` is resolved the same way — but a bespoke copy helper that rebuilds
   the dataclass field by field is not.
3. **Passing an authoritative Judgment onward.** Not construction, and correctly
   not swept: the bank produces one and callers carry it. That is the system
   working.
4. **Adding an entry to the list below.** That is the point: it is a reviewable
   line in a diff with a reason beside it, not a silent capability.

The two layers are not redundant, and the doctrine is explicit that claiming so
without evidence is how this went wrong before. This sweep catches a new
constructor that the behavioural suite would miss because no test drives it yet;
the behavioural suite catches a computed flag this sweep cannot see.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
SRC = REPO / "src" / "prometheus_protocol"

#: The symbol whose construction is restricted, by resolved identity.
_TARGET_MODULE = "prometheus_protocol.core.models"
_TARGET_NAMES = frozenset({"Judgment"})

#: Where an authoritative Judgment may be constructed, as
#: ``module::qualified-function``, each with the reason it is permitted.
_PERMITTED_CONSTRUCTORS: dict[str, str] = {
    "prometheus_protocol.verifier.bank::VerifierBank._authoritative_judgment":
        "THE aggregator. Fusion of authoritative evidence is what this function is.",
    "prometheus_protocol.verifier.bank::VerifierBank.judge_covered":
        "The coverage refusal for a FAILED required check. A failure is a real "
        "answer and is reported as one; it refuses authorization either way.",
    # -------------------------------------------------------------------
    # NOT the bank, and NOT closed by this sprint. Named as an EXPOSURE.
    # -------------------------------------------------------------------
    "prometheus_protocol.tools.git::judgment_for":
        "A SECOND PRODUCER, and a real one: tools/stale_branch_demo.py passes "
        "its Judgment straight into ExecutionController.submit, so a branch "
        "classification authorizes a deletion without the bank or the policy "
        "layer being consulted. It is on this list because removing it is the "
        "NEXT sprint's breaking interface change (a raw authoritative Judgment "
        "must stop being sufficient for authorization), not because it is "
        "acceptable. test_the_exposure_is_real_and_not_theoretical below drives "
        "it, so the entry cannot quietly become stale.",
}


def _source_files() -> list[pathlib.Path]:
    return sorted(p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts)


def _module_name(path: pathlib.Path) -> str:
    rel = path.relative_to(SRC.parent).with_suffix("")
    return str(rel).replace("/", ".").removesuffix(".__init__")


def _resolve_bindings(tree: ast.Module) -> dict[str, str]:
    """Map local names to the symbols they are bound to.

    This is what makes the set over RESOLVED SYMBOLS rather than spellings.
    ``from ...models import Judgment`` binds ``Judgment``; ``import ...models as
    m`` binds ``m`` as a module alias so ``m.Judgment`` resolves too;
    ``from ...models import Judgment as J`` binds ``J``.
    """

    bindings: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                bindings[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                bindings[alias.asname or alias.name] = alias.name
    return bindings


def _callee_symbol(node: ast.Call, bindings: dict[str, str]) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return bindings.get(func.id, func.id)
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        base = bindings.get(func.value.id, func.value.id)
        return f"{base}.{func.attr}"
    return None


def _is_authoritative_literal(node: ast.Call) -> bool:
    for keyword in node.keywords:
        if keyword.arg == "authoritative":
            return isinstance(keyword.value, ast.Constant) and keyword.value.value is True
    return False


def _enclosing(tree: ast.Module, target: ast.Call) -> str:
    """The qualified function a call sits in, for the permitted-set key."""

    best = "<module>"
    stack: list[str] = []

    class _Walk(ast.NodeVisitor):
        def _scope(self, node, name: str) -> None:
            stack.append(name)
            if getattr(node, "lineno", -1) <= target.lineno <= getattr(
                node, "end_lineno", -1
            ):
                nonlocal best
                best = ".".join(stack)
            self.generic_visit(node)
            stack.pop()

        def visit_ClassDef(self, node): self._scope(node, node.name)
        def visit_FunctionDef(self, node): self._scope(node, node.name)
        def visit_AsyncFunctionDef(self, node): self._scope(node, node.name)

    _Walk().visit(tree)
    return best


def _authoritative_constructions() -> dict[str, int]:
    """Every ``Judgment(..., authoritative=True)`` construction in the tree."""

    found: dict[str, int] = {}
    for path in _source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        bindings = _resolve_bindings(tree)
        module = _module_name(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not _is_authoritative_literal(node):
                continue
            symbol = _callee_symbol(node, bindings)
            if symbol is None:
                continue
            constructs_target = symbol in {
                f"{_TARGET_MODULE}.{name}" for name in _TARGET_NAMES
            } or symbol in {"dataclasses.replace", "replace"}
            if not constructs_target:
                continue
            key = f"{module}::{_enclosing(tree, node)}"
            found[key] = found.get(key, 0) + 1
    return found


def test_only_permitted_modules_construct_an_authoritative_verdict():
    found = _authoritative_constructions()
    unpermitted = sorted(set(found) - set(_PERMITTED_CONSTRUCTORS))
    assert unpermitted == [], (
        f"authoritative Judgment constructed outside the permitted set: {unpermitted}. "
        "An authoritative verdict is what authorizes an action; a second place that "
        "computes one is a second aggregator, and the policy layer becomes a "
        "convention it ignores. Route it through VerifierBank.judge_covered, or add "
        "it here WITH the reason it cannot reach authorization."
    )


def test_no_permitted_entry_outlives_the_construction_it_excuses():
    """A sanction for a site that no longer exists is a hole nobody is watching:
    the code moved, the excuse stayed, and the next constructor to land on that
    path is waved through."""

    found = _authoritative_constructions()
    stale = sorted(set(_PERMITTED_CONSTRUCTORS) - set(found))
    assert stale == [], f"permitted entries with no construction behind them: {stale}"


def test_the_sweep_resolves_symbols_not_spellings():
    """The expression-narrowing lesson, asserted directly: three spellings of one
    symbol must all resolve, or the set is over spellings and a rename escapes."""

    source = (
        "from prometheus_protocol.core import models\n"
        "from prometheus_protocol.core.models import Judgment\n"
        "from prometheus_protocol.core.models import Judgment as J\n"
        "a = Judgment(authoritative=True)\n"
        "b = models.Judgment(authoritative=True)\n"
        "c = J(authoritative=True)\n"
    )
    tree = ast.parse(source)
    bindings = _resolve_bindings(tree)
    resolved = [
        _callee_symbol(n, bindings)
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and _is_authoritative_literal(n)
    ]
    assert resolved == [f"{_TARGET_MODULE}.Judgment"] * 3, resolved


def test_the_sweep_is_not_vacuous():
    """A sweep that found nothing would pass every assertion above."""

    found = _authoritative_constructions()
    assert found, "the sweep found no authoritative construction at all"
    assert any(k.startswith("prometheus_protocol.verifier.bank::") for k in found), (
        "the bank's own construction was not found; the sweep is not reaching it"
    )


def test_the_exposure_is_real_and_not_theoretical():
    """The sanctioned second producer, DRIVEN.

    An entry on a permitted list with nothing exercising it decays into a
    sentence nobody rechecks. This asserts the exposure is exactly what the entry
    says: ``judgment_for`` returns an authoritative Judgment that no policy
    resolved and no coverage validated, and the execution controller accepts one.

    When the next sprint closes the unbound-judgment route, THIS test fails and
    the entry above comes off the list. That is the intended way for it to end.
    """

    from prometheus_protocol.core.models import Judgment
    from prometheus_protocol.tools.git import BranchClassification, judgment_for

    judgment, _risk = judgment_for(
        BranchClassification(branch="feature/x", unmerged_commits=0)
    )
    assert isinstance(judgment, Judgment)
    assert judgment.authoritative is True, (
        "if this is no longer authoritative the exposure is closed — remove the "
        "tools.git entry from _PERMITTED_CONSTRUCTORS in the same change"
    )


def test_the_guard_names_what_it_does_not_constrain():
    """The doctrine's requirement: where something an attacker can change remains
    unconstrained, it is named in the guard's own docstring rather than left to
    be found."""

    doc = __doc__ or ""
    for claim in (
        "WHAT CAN VARY THAT THIS SET DOES NOT CONSTRAIN",
        "A computed flag",
        "bespoke copy helper",
    ):
        assert claim in doc, f"the guard no longer states: {claim!r}"


@pytest.mark.parametrize("spelling", ["Judgment", "models.Judgment", "J"])
def test_a_new_constructor_in_any_spelling_would_fail_the_guard(spelling, tmp_path):
    """The property under test is the guard's REACH, proven by construction
    rather than asserted: a module added at a path nobody predicted, using any
    of the three spellings, is not on the list and is therefore caught."""

    source = (
        "from prometheus_protocol.core import models\n"
        "from prometheus_protocol.core.models import Judgment\n"
        "from prometheus_protocol.core.models import Judgment as J\n"
        f"def sneak():\n    return {spelling}(authoritative=True)\n"
    )
    tree = ast.parse(source)
    bindings = _resolve_bindings(tree)
    calls = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and _is_authoritative_literal(n)
    ]
    assert calls, "the fixture built no authoritative construction"
    assert _callee_symbol(calls[0], bindings) == f"{_TARGET_MODULE}.Judgment"
    assert f"<synthetic>::sneak" not in _PERMITTED_CONSTRUCTORS
