"""Every proof selector a mutation runner names must be a test that exists.

WHY THIS MODULE EXISTS. A mutation runner names its proof by STRING. Rename the
test and the string still parses, still looks right in review, and selects
nothing — pytest reports no summary, the runner cannot measure a baseline, and
the row proves nothing. Measured on this branch: renaming
``test_an_unreachable_component_reads_as_not_applicable_not_as_a_refusal`` left
``receipt_classification_proofs.py`` pointing at a name that no longer existed,
and the three-version matrix went red on all three Pythons at
``RuntimeError: baseline invalid: ...: (no summary)``.

The runner refusing was correct — a mutation that would silently not apply is a
proof of nothing presented as a proof of safety. What was missing is anything
that says so BEFORE CI: this is a cross-file reference with no compiler and no
import to break.

So the selectors are DERIVED from each runner's own source and checked against
the test names that exist, both read from the tree. Neither side is a list
anyone maintains.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]


def _test_names() -> set[str]:
    """Every test function name in the tree."""

    names: set[str] = set()
    for path in (REPO / "tests").rglob("test_*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                names.add(node.name)
    return names


def _runner_selectors() -> dict[str, set[str]]:
    """Every string a runner uses that LOOKS like a proof selector.

    A string literal beginning ``test_`` inside a runner is either a selector or
    a mutation payload naming one; both must exist, so no distinction is drawn.
    """

    found: dict[str, set[str]] = {}
    for path in sorted((REPO / "scripts").glob("*_proofs.py")):
        selectors = {
            node.value
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith("test_")
            and "::" not in node.value
            and "/" not in node.value
            and node.value.isidentifier()
        }
        if selectors:
            found[path.name] = selectors
    return found


def test_the_runner_population_is_not_empty():
    """Doctrine #8: an instrument that finds nothing reads as a pass."""

    runners = _runner_selectors()
    assert len(runners) >= 1
    assert sum(len(v) for v in runners.values()) > 20, (
        "this sweep found almost no selectors, which means it stopped seeing "
        "them rather than that they stopped existing"
    )


@pytest.mark.parametrize("runner", sorted(_runner_selectors()))
def test_every_selector_a_runner_names_is_a_test_that_exists(runner):
    """Per runner, so a failure names the file to fix."""

    existing = _test_names()
    missing = sorted(_runner_selectors()[runner] - existing)
    assert missing == [], (
        f"{runner} names proof selectors that no longer exist: {missing}. "
        "A renamed test leaves the string valid and the row measuring nothing; "
        "point it at the test that replaced it, or delete the row."
    )
