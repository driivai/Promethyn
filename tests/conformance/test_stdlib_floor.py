"""No import may need a newer standard library than the declared floor.

WHY THIS EXISTS RATHER THAN A MYPY SETTING. ``mypy.ini`` now pins
``python_version = 3.10``, which is necessary and not sufficient: measured on
this tree, a file importing ``tomllib`` (standard library only from 3.11) passes
the gate WITH the floor pinned, because ``ignore_missing_imports = True`` — set
for genuine third-party packages — also swallows a stdlib module that does not
exist at the target version.

Turning that flag off surfaces 25 first-party module-resolution errors (scripts
and tests importing siblings), none of them third-party. This docstring used
to say silencing those "needs per-module ``[mypy-...]`` sections", which
``test_type_gate.py::test_mypy_ini_has_no_per_module_sections`` forbids. That
claim was WRONG and is withdrawn: measured on this tree, widening ``mypy_path``
to the directories those siblings live in (``scripts``, ``tests/conformance``,
``tests/chokepoint``) resolves all 25 with the flag off — ``Success: no issues
found in 290 source files`` — with no per-module section at all. The change is
recorded in ``docs/OPEN-GAPS.md`` as the closure and deliberately not applied
here, because it re-shapes the type gate's config (an allowlisted file) and
makes the gate depend on every third-party package shipping types, which is a
trade to be made on its own evidence. This check stands beside the gate either
way: it is built over typeshed's table and does not need the flag off.

WHAT IT COVERS AND WHAT IT DOES NOT. It covers STANDARD-LIBRARY MODULE
availability at the floor, and only that. Two limits, each a passing test
below rather than a sentence here: it does not see a third-party package that
is absent or too new at the floor (that is pip's ``requires-python`` and the
3.10 CI job's to catch), and it does not see a SYMBOL added to an existing
stdlib module (``datetime.UTC`` is 3.11+; typeshed's ``VERSIONS`` says
``datetime`` is 3.0+, so ``from datetime import UTC`` passes this check and
fails at import on 3.10).

NOT AN ENUMERATION. The obvious spelling is a hand-kept list of "modules added
after 3.10", which is a list over exactly the thing that varies and goes stale
the first time the standard library grows. This reads typeshed's own ``VERSIONS``
metadata — the table mypy itself uses, shipped with the pinned checker — so the
permitted set is derived from the same source of truth the type gate consults.

The instance this closes: `import tomllib` merged, passed the gate on all three
matrix jobs, and failed at import on the 3.10 job in CI.
"""

from __future__ import annotations

import ast
import pathlib
import re
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
ROOTS = ("src", "scripts", "tests", "harness")


def _declared_floor() -> tuple[int, int]:
    """The floor, read from mypy.ini rather than restated here."""

    text = (REPO / "mypy.ini").read_text(encoding="utf-8")
    match = re.search(r"^python_version\s*=\s*(\d+)\.(\d+)", text, re.M)
    assert match, (
        "mypy.ini has no python_version pin. Without it mypy targets whichever "
        "interpreter runs it, so a 3.11+ symbol passes on a 3.12 runner and "
        "fails at import on the 3.10 one."
    )
    return int(match.group(1)), int(match.group(2))


def _stdlib_minimums() -> dict[str, tuple[int, int]]:
    """Each stdlib top-level module's minimum version, from typeshed."""

    import mypy

    versions = pathlib.Path(mypy.__file__).parent / "typeshed" / "stdlib" / "VERSIONS"
    if not versions.exists():  # pragma: no cover - layout changed
        pytest.fail(f"typeshed VERSIONS not found at {versions}")
    minimums: dict[str, tuple[int, int]] = {}
    for line in versions.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        name, _, span = line.partition(":")
        name = name.strip()
        # TOP-LEVEL ENTRIES ONLY. VERSIONS lists submodules too
        # (``sys._monitoring: 3.12-`` beside ``sys: 3.0-``), and keying both on
        # the top-level name let the last submodule read overwrite the module's
        # own minimum. Measured before this line existed: it reported ``sys`` as
        # needing 3.12 and ``xml`` as needing 3.15, which is how a guard ends up
        # failing on everything and being switched off.
        if "." in name:
            continue
        low = span.strip().split("-")[0].strip()
        parts = low.split(".")
        if len(parts) != 2 or not all(p.isdigit() for p in parts):
            continue
        minimums[name] = (int(parts[0]), int(parts[1]))
    return minimums


def _imported_top_level_modules() -> dict[str, list[str]]:
    """Every top-level module name imported anywhere in the repo's own code."""

    found: dict[str, list[str]] = {}
    for root in ROOTS:
        base = REPO / root
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:  # pragma: no cover - not our concern here
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    # level > 0 is a relative import: not a top-level module.
                    names = [node.module] if node.module and not node.level else []
                else:
                    continue
                for name in names:
                    top = name.split(".")[0]
                    found.setdefault(top, []).append(
                        f"{path.relative_to(REPO)}:{node.lineno}"
                    )
    return found


def test_the_floor_is_pinned_and_matches_the_declared_contract():
    """mypy.ini, requires-python and the CI matrix must name the same floor.

    A Required check with no declared contract behind it is a guard with no
    stated property: if the matrix tests 3.10 and the gate targets 3.12, the
    3.10 job is the only thing standing between a 3.11 symbol and production,
    and it only catches what happens to be imported at runtime.
    """

    floor = _declared_floor()
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")

    requires = re.search(r'requires-python\s*=\s*">=(\d+)\.(\d+)"', pyproject)
    assert requires, "pyproject declares no requires-python"
    assert (int(requires.group(1)), int(requires.group(2))) == floor, (
        f"requires-python floor {requires.groups()} disagrees with the mypy "
        f"floor {floor}"
    )

    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    matrix = re.search(r'python-version:\s*\[([^\]]+)\]', ci)
    assert matrix, "ci.yml declares no python-version matrix"
    versions = sorted(
        tuple(int(p) for p in v.strip().strip('"').split("."))
        for v in matrix.group(1).split(",")
    )
    assert versions[0] == floor, (
        f"the CI matrix's lowest Python {versions[0]} is not the declared floor "
        f"{floor}. Either the matrix tests a version the contract does not "
        "promise, or the contract promises one nothing tests."
    )


def test_no_import_needs_a_newer_stdlib_than_the_floor():
    """The construction fix for the tomllib break, over typeshed's own table."""

    floor = _declared_floor()
    minimums = _stdlib_minimums()
    offenders: list[str] = []
    for module, sites in sorted(_imported_top_level_modules().items()):
        needed = minimums.get(module)
        if needed is not None and needed > floor:
            where = ", ".join(sorted(set(sites))[:4])
            offenders.append(
                f"{module} needs >= {needed[0]}.{needed[1]}, floor is "
                f"{floor[0]}.{floor[1]} — {where}"
            )
    assert offenders == [], (
        "import(s) requiring a newer standard library than the declared floor:\n  "
        + "\n  ".join(offenders)
        + "\nThese pass the type gate (ignore_missing_imports swallows a missing "
        "stdlib module) and fail at import on the floor's interpreter, in CI, "
        "after review. Either raise the floor deliberately in mypy.ini, "
        "requires-python and the CI matrix together, or do not use the module."
    )


def test_the_check_would_catch_tomllib_at_a_3_10_floor():
    """The guard's own control: it must actually fire on the known instance.

    Without this the test above passes trivially the moment the AST walk or the
    typeshed read silently returns nothing — a guard that cannot fail.
    """

    minimums = _stdlib_minimums()
    assert minimums.get("tomllib") == (3, 11), (
        "typeshed no longer reports tomllib as 3.11+; this control has lost its "
        "subject and the check above is unproven"
    )
    assert minimums["tomllib"] > (3, 10)
    # And the walk finds real imports, so an empty result cannot pass as clean.
    imported = _imported_top_level_modules()
    assert "pytest" in imported and "ast" in imported, (
        "the import walk found neither pytest nor ast; it is not reaching the "
        "tree and the check above proves nothing"
    )


# ---------------------------------------------------------------------------
# The guard's SCOPE, as passing tests (docs/OPEN-GAPS.md, "stdlib-floor scope").
# A limit that is only prose erodes: someone reads "no import needs a newer
# stdlib" as "no import breaks on 3.10", and the second is not what is proven.
# ---------------------------------------------------------------------------


def test_named_limit_the_guard_does_NOT_cover_third_party_resolvability():
    """A third-party package is invisible to the guard: typeshed's VERSIONS is
    the standard library's table and has no row for ``psycopg`` or ``pytest``,
    both of which this tree imports. Whether a dependency exists, or is new
    enough, at the floor is decided by pip's ``requires-python`` on the
    dependency and by the 3.10 CI job actually importing it — not here."""

    minimums = _stdlib_minimums()
    imported = _imported_top_level_modules()
    third_party = [name for name in ("psycopg", "pytest", "yaml") if name in imported]
    assert third_party, "the tree imports no third-party module this test knows; re-pick"
    for name in third_party:
        assert name not in minimums, (
            f"typeshed now lists {name!r} as stdlib; this limit has changed shape"
        )


def test_named_limit_the_guard_does_NOT_see_symbol_level_additions():
    """``datetime.UTC`` exists only from 3.11. typeshed's table is per MODULE,
    and ``datetime`` is 3.0+, so an import of the symbol passes the guard at a
    3.10 floor. What catches it is the 3.10 matrix job importing the module.
    Asserted against the table, so the limit is measured rather than assumed."""

    minimums = _stdlib_minimums()
    floor = _declared_floor()
    assert minimums["datetime"] <= floor, "datetime is not older than the floor?"
    # The module-level check has nothing to say about the symbol: the guard's
    # own classification of ``datetime`` is "fine at the floor".
    needed = minimums.get("datetime")
    assert needed is not None and not needed > floor
    # And the symbol really is version-gated, so the limit is a real one.
    import datetime as _datetime

    assert (hasattr(_datetime, "UTC")) == (sys.version_info >= (3, 11))
