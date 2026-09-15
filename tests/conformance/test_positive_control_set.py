"""The positive-control set, named — doctrine #4 made checkable.

"Every negative has a positive control" was doctrine and nothing else: the
tree carried twenty-five tests declaring themselves one, and no record of WHICH
refusal each stood beside. That is the same failure this repository keeps
finding one layer down — a guard whose scope nobody wrote down, so nobody can
say what it covers. A positive control with no named negative proves that
something passes.

`positive_controls.json` is the set. Each entry names the positive, at least
one negative, and the property the PAIR establishes; neither half means much
alone, which is the whole point of pairing them.

WHAT THIS ASSERTS, and the order matters:

1. every registered test — both halves — resolves to a test that actually
   exists and is collected. A registry naming a renamed test is a registry
   that has quietly stopped covering it;
2. every self-declared positive control in the tree is REGISTERED. Without
   this the set could not fall behind the code visibly: someone adds a
   twenty-sixth, nobody registers it, and the file still passes while claiming
   to be the set;
3. no entry lists itself as its own negative, and no entry has an empty
   negative list.

NAMED LIMIT, because this instrument's scope is narrower than it looks. It
checks that the pairs EXIST and are collected. It does not and cannot check
that a negative genuinely exercises the refusal its `property` line claims —
that judgement lives in the tests themselves and in review. This is a registry,
not a semantic verifier, and reading it as coverage would be the same mistake
as reading an accessibility score as coverage.

THE COUNT IS NOT PINNED, deliberately. A pin here would have to move on every
added control, which trains people to update the number without reading the
pairing. Rule 2 is what keeps the set complete; the count is reported, not
enforced.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
REGISTRY = json.loads(
    (Path(__file__).with_name("positive_controls.json")).read_text(encoding="utf-8")
)
CONTROLS: list[dict] = REGISTRY["controls"]


def _tests_in(module: str) -> set[str]:
    path = REPO / module
    if not path.exists():
        return set()
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def rel_of(path: Path) -> str:
    return path.relative_to(REPO).as_posix()


def _declared_positive_controls() -> set[tuple[str, str]]:
    """Every test in the tree that calls itself a positive control."""

    found: set[tuple[str, str]] = set()
    for path in sorted((REPO / "tests").rglob("test_*.py")):
        # This module talks ABOUT positive controls in every docstring it has;
        # scanning itself would register the registry. Excluded by identity,
        # not by a name pattern that a rename would silently break.
        if path.resolve() == Path(__file__).resolve():
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError) as exc:
            # REFUSE, do not narrow. A file this cannot parse is a file whose
            # self-declared controls it cannot see, and the caller's assertion
            # is a SUBTRACTION (`declared - registered`): a smaller `declared`
            # makes it MORE likely to pass, so swallowing the error turns an
            # unreadable test file into a silent all-clear. Found while fixing
            # the same shape in tests/support/positional_sweep.py; the first
            # sweep for it covered tests/support and scripts and missed this
            # one, which is its own small lesson about scoping a sweep.
            raise AssertionError(
                f"the positive-control scan could not parse {rel_of(path)}: "
                f"{exc}. Its population is narrower than the tree, so its "
                "answer is not a measurement of it."
            ) from exc
        rel = path.relative_to(REPO).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test_"):
                continue
            doc = (ast.get_docstring(node) or "").lower()
            if "positive control" in doc or "positive_control" in node.name:
                found.add((rel, node.name))
    return found


def test_the_registry_is_not_empty():
    assert CONTROLS, "an empty registry would make every assertion below vacuous"


@pytest.mark.parametrize(
    "entry", CONTROLS, ids=[f"{c['module'].split('/')[-1]}::{c['positive']}"[:70] for c in CONTROLS]
)
def test_every_registered_pair_resolves_to_collected_tests(entry):
    names = _tests_in(entry["module"])
    assert names, f"{entry['module']} has no tests (moved or renamed?)"
    assert entry["positive"] in names, (
        f"{entry['module']}::{entry['positive']} is registered but does not exist"
    )
    assert entry["negatives"], f"{entry['positive']} is registered with no negative"
    for negative in entry["negatives"]:
        assert negative in names, (
            f"{entry['module']}::{negative} is registered as a negative but does "
            f"not exist"
        )
        assert negative != entry["positive"], "a test cannot be its own negative"
    assert entry["property"].strip(), "every pair states the property it establishes"


def test_every_self_declared_positive_control_is_registered():
    """The rule that stops the set falling behind the tree."""

    registered = {(c["module"], c["positive"]) for c in CONTROLS}
    declared = _declared_positive_controls()
    missing = sorted(declared - registered)
    assert not missing, (
        "these tests declare themselves positive controls but are not in "
        f"positive_controls.json: {missing}"
    )


def test_the_registry_names_no_test_that_stopped_declaring_itself_one():
    """The other direction: a stale entry is as bad as a missing one."""

    registered = {(c["module"], c["positive"]) for c in CONTROLS}
    declared = _declared_positive_controls()
    stale = sorted(registered - declared)
    assert not stale, (
        "these are registered as positive controls but no longer declare "
        f"themselves one: {stale}"
    )
