#!/usr/bin/env python3
"""The skip set is an allowlist: every skip in a full-suite run must be sanctioned.

WHY. The CI matrix reported ``2372 passed, 23 skipped`` on 3.10, 3.11 and 3.12,
and an identical COUNT says nothing about COMPOSITION: 23 different tests
skipping on each version would print the same three lines and hide two gaps —
a version-gated test nobody knows is gated, and a skip that arrived on one
version with a change nobody noticed. The count was pinned; the set was not.

So the set is pinned here, by NAME, the same way the type-gate proofs are pinned
by name in ``tests/conformance/type_gate_test_manifest.json``: a count catches
deletion, a manifest catches delete-one-add-one. The full-suite step writes a
JUnit report; this reads every skipped test out of it and compares the set
against ``tests/conformance/skip_manifest.txt``:

  * a skip that is NOT in the manifest fails the build — a new skip is
    sanctioned deliberately, with its reason, or the test runs;
  * a manifest entry that did NOT skip fails the build too — either the test
    ran (the entry is stale and must go) or it was deleted/renamed (the
    sanction outlived what it sanctioned);
  * the same manifest is checked on every matrix version, so the three skip
    sets are the same set or the build is red.

The manifest names test ids, one per line, ``#`` for comments. A line may
carry a trailing ``# reason``. Nothing here decides whether a skip is
legitimate; it decides whether it was SANCTIONED, which is the property that
was missing.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = REPO_ROOT / "tests" / "conformance" / "skip_manifest.txt"


def node_id(case: ET.Element) -> str:
    """``path::name`` from a JUnit testcase, in pytest's own spelling.

    JUnit's ``classname`` is the dotted module path (``tests.chokepoint.test_x``),
    or module plus class for a test inside a class. The module half is resolved
    against the tree so a class name is never mistaken for a package.
    """

    classname = case.get("classname") or ""
    name = case.get("name") or ""
    parts = classname.split(".")
    for cut in range(len(parts), 0, -1):
        candidate = REPO_ROOT / (Path(*parts[:cut]).with_suffix(".py"))
        if candidate.is_file():
            rel = candidate.relative_to(REPO_ROOT).as_posix()
            suffix = "::".join(parts[cut:])
            return f"{rel}::{suffix}::{name}" if suffix else f"{rel}::{name}"
    return f"{classname}::{name}"


def skipped_ids(report: Path) -> dict[str, str]:
    cases = list(ET.parse(report).iter("testcase"))
    if not cases:
        raise SystemExit(f"{report}: no testcases at all; refusing to compare an empty run")
    found: dict[str, str] = {}
    for case in cases:
        skipped = case.find("skipped")
        if skipped is not None:
            found[node_id(case)] = skipped.get("message") or ""
    return found


def manifest_ids(path: Path) -> set[str]:
    """Test ids from the manifest. A comment line starts with ``#``; a trailing
    reason is introduced by two spaces and ``#``, so a ``#`` inside a
    parametrised id is never read as one."""

    ids: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.lstrip().startswith("#"):
            continue
        cut = raw.find("  #")
        line = (raw[:cut] if cut >= 0 else raw).strip()
        if line:
            ids.add(line)
    return ids


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("report", help="JUnit XML from the full-suite run")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    args = parser.parse_args(argv)

    observed = skipped_ids(Path(args.report))
    sanctioned = manifest_ids(Path(args.manifest))

    unsanctioned = sorted(set(observed) - sanctioned)
    stale = sorted(sanctioned - set(observed))
    if unsanctioned:
        print(f"skip manifest FAILED: {len(unsanctioned)} skip(s) not sanctioned:")
        for test_id in unsanctioned:
            print(f"  {test_id}  ({observed[test_id][:100]})")
    if stale:
        print(f"skip manifest FAILED: {len(stale)} sanctioned entr{'y' if len(stale) == 1 else 'ies'} did not skip (ran, or no longer exists):")
        for test_id in stale:
            print(f"  {test_id}")
    if unsanctioned or stale:
        print(
            "Sanction a new skip in tests/conformance/skip_manifest.txt WITH its reason, "
            "or make the test run; remove an entry whose test now runs."
        )
        return 1
    print(
        f"skip manifest passed: {len(observed)} skip(s) observed, all {len(sanctioned)} "
        "sanctioned, none stale"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
