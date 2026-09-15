"""The membership manifest must name tests that exist, and must be able to say no.

WHY THIS FILE EXISTS RATHER THAN TRUSTING CI. A manifest of names is only worth
something if a rename breaks it LOUDLY and LOCALLY. Without this, renaming a
pinned test passes the whole local suite and refuses three CI jobs ten minutes
later — which is exactly how run 34860607395 went, and the lesson recorded in
G12 was that a pin living only in ``ci.yml`` is a pin nobody can check before
pushing.

WHAT THIS PROVES, and its scope. That every name in
``proof_composition.json`` is a test function that exists in one of the modules
that step collects, and that the checker itself can refuse. It does NOT prove
the named tests are the RIGHT ones to pin — that is a judgement recorded in the
manifest's own prose — and it does not prove the unpinned remainder is
unimportant.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

from check_proof_composition import (  # noqa: E402
    MANIFEST,
    _base_name,
    _module_of,
    check,
    load_manifest,
)

MANIFEST_DATA = load_manifest()
STEPS = MANIFEST_DATA["steps"]


def _module_path(dotted: str) -> Path:
    return REPO / (dotted.replace(".", "/") + ".py")


def _test_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("test_"):
                names.add(node.name)
    return names


@pytest.mark.parametrize("key", sorted(STEPS))
def test_every_pinned_module_exists(key):
    for dotted in STEPS[key]["counts"]:
        assert _module_path(dotted).is_file(), (key, dotted)


@pytest.mark.parametrize("key", sorted(STEPS))
def test_every_required_name_is_a_test_that_exists(key):
    """The rename guard. A pinned name that no longer exists fails HERE, in the
    local suite, instead of refusing three CI jobs after the push."""

    step = STEPS[key]
    available: set[str] = set()
    for dotted in step["counts"]:
        available |= _test_names(_module_path(dotted))

    missing = sorted(name for name in step["required"] if name not in available)
    assert missing == [], (
        f"{key}: proof_composition.json pins names that do not exist in the "
        f"modules this step collects: {missing}"
    )


@pytest.mark.parametrize("key", sorted(STEPS))
def test_the_required_set_is_not_empty_and_not_everything(key):
    """Both ends matter. Empty means the step is count-only again and the
    membership claim is vacuous. Everything means the manifest churns on every
    added test, which is how a pin stops being maintained and starts being
    edited to match whatever ran."""

    step = STEPS[key]
    available: set[str] = set()
    for dotted in step["counts"]:
        available |= _test_names(_module_path(dotted))

    assert step["required"], f"{key}: no names pinned"
    assert len(set(step["required"])) == len(step["required"]), f"{key}: duplicate name"
    assert len(step["required"]) < len(available), (
        f"{key}: every test is pinned; `required` is meant to be the subset whose "
        "substitution would be silent"
    )


@pytest.mark.parametrize("key", sorted(STEPS))
def test_every_step_pins_at_least_one_name_that_is_not_a_refusal(key):
    """Doctrine #4 applied to the manifest: a step naming only refusals is
    consistent with a build that refuses everything, so each step must pin at
    least one name that does not read as a refusal.

    This is a MANIFEST GUARD, not itself one of the paired controls the
    registry tracks — it checks that each step pins one, which is a different
    claim from being one. Named and worded to say so: the registry's collector
    matches on the phrase in a docstring OR on ``positive_control`` in the test
    NAME, and this test was registered as a control it is not until it was
    renamed.
    """

    refusal_words = ("refus", "cannot", "no_", "not_", "never", "invalid",
                     "detected", "breaks", "excess", "shortfall", "lie")
    positives = [
        name for name in STEPS[key]["required"]
        if not any(word in name for word in refusal_words)
    ]
    assert positives, f"{key}: every pinned name reads as a refusal"


def test_the_checker_refuses_a_missing_name(tmp_path):
    """The substitution this whole manifest exists to catch: right counts,
    wrong membership. An instrument that cannot fail reports a pass for every
    input (doctrine #8), so this is the half that proves it can fail."""

    key = sorted(STEPS)[0]
    step = STEPS[key]
    module = next(iter(step["counts"]))
    report = tmp_path / "r.xml"
    # A report carrying the right COUNTS and the wrong MEMBERSHIP: this is the
    # substitution the whole manifest exists to catch.
    rows = "".join(
        f'<testcase classname="{module}" name="benign_filler_{i}"/>'
        for i in range(sum(step["counts"].values()))
    )
    report.write_text(f"<testsuites><testsuite>{rows}</testsuite></testsuites>")
    problems = check(report, key)
    assert any(p.startswith("membership:") for p in problems), problems


def test_the_checker_refuses_an_empty_report(tmp_path):
    """An empty set reads downstream as a pass. Named because this repository
    has shipped that shape before."""

    report = tmp_path / "empty.xml"
    report.write_text("<testsuites><testsuite></testsuite></testsuites>")
    problems = check(report, sorted(STEPS)[0])
    assert problems and "no testcase elements" in problems[0], problems


def test_the_checker_accepts_a_faithful_report(tmp_path):
    """The positive control for the checker. Without it, every refusal above is
    consistent with a checker that refuses everything — a different defect, and
    a worse one, because it would refuse honest builds too."""

    key = sorted(STEPS)[0]
    step = STEPS[key]
    rows = []
    for module, count in step["counts"].items():
        names = sorted(_test_names(_module_path(module)))
        pinned = [n for n in step["required"] if n in names]
        chosen = pinned + [n for n in names if n not in pinned]
        # A module collects MORE cases than it has functions when tests are
        # parametrised, so the synthetic report pads with `name[i]` rows the way
        # pytest reports them. Padding with new function names instead would
        # build a report this repository could never produce.
        while len(chosen) < count:
            chosen.append(f"{names[0]}[pad{len(chosen)}]")
        chosen = chosen[:count]
        assert len(chosen) == count, (module, len(chosen), count)
        rows += [f'<testcase classname="{module}" name="{n}"/>' for n in chosen]
    report = tmp_path / "ok.xml"
    report.write_text(f"<testsuites><testsuite>{''.join(rows)}</testsuite></testsuites>")
    assert check(report, key) == []


def test_a_parametrised_name_still_satisfies_its_pin(tmp_path):
    """`name[param]` matches the base, so re-parametrising a pinned test keeps
    the pin while deleting it breaks it."""

    assert _base_name("test_x[a-b]") == "test_x"
    assert _base_name("test_x") == "test_x"


def test_a_test_inside_a_class_counts_toward_its_module():
    """Two steps put their tests in classes. Counting by raw classname would
    split a module across them, which is why ci.yml needed two different
    matchers before this."""

    assert _module_of("tests.conformance.test_x") == "tests.conformance.test_x"
    assert _module_of("tests.conformance.test_x.TestThing") == "tests.conformance.test_x"


def test_the_manifest_records_what_it_deliberately_left_alone():
    """A named gap is a passing test (doctrine #5). The steps NOT converted are
    recorded with the reason, so "why isn't this one pinned" has an answer that
    is not silence."""

    left = MANIFEST_DATA["_left_as_counts_only"]
    assert len(left) > 1
    for name, reason in left.items():
        if name == "_why":
            continue
        assert len(reason) > 80, f"{name}: the reason is too thin to be a reason"
    assert MANIFEST.is_file()
