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

TWO SECTIONS, because the second rule was measured to be too strong. The
manifest was pinned from a local run and the first CI run of it refused, for a
reason worth keeping: the skip SET is not a property of the tree alone, it is a
property of the tree ON A HOST. Observed (run 34707644343), the same 23 skips
both places, composed differently — ``ubuntu-latest`` ships a container daemon
and runs as an unprivileged user, the local CI-equivalent host has no daemon and
runs as root, so the real-container workspace test RAN there and skipped here
while the cross-user denial test did the exact opposite.

So an entry lives in one of two sections:

  ``[required]`` (the default)
      must skip in every environment. A test that ran makes the entry stale and
      fails the build, as before.

  ``[conditional]``
      skips or runs depending on a named host fact. It must carry
      ``proof: <workflow file> :: <step name>`` — a step in a real workflow that
      runs the test under a ``PROM_REQUIRE_*`` flag, which is what turns a skip
      into a FAILURE there. A conditional sanction whose proof does not resolve,
      or resolves to a step carrying no such flag, fails the build: that is a
      hole, not a sanction. Where the test runs anyway, that is reported, not
      failed.

The manifest names test ids, one per line, ``#`` for comments, ``[section]`` for
a section header. A line may carry a trailing ``# reason``. Nothing here decides
whether a skip is legitimate; it decides whether it was SANCTIONED, which is the
property that was missing.
"""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = REPO_ROOT / "tests" / "conformance" / "skip_manifest.txt"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

REQUIRED = "required"
CONDITIONAL = "conditional"
SECTIONS = (REQUIRED, CONDITIONAL)

#: ``proof: <workflow file> :: <step name>`` inside a conditional entry's reason.
_PROOF = re.compile(r"proof:\s*(?P<workflow>[\w.-]+\.ya?ml)\s*::\s*(?P<step>.+?)\s*$")
#: The flags that turn a skip into a failure. A proof step must set one to "1".
_REQUIRE_FLAG = re.compile(r"^PROM_REQUIRE_[A-Z_]+$")


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


def manifest_entries(path: Path) -> dict[str, tuple[str, str]]:
    """``id -> (section, reason)``.

    A comment line starts with ``#``; a section header is ``[required]`` or
    ``[conditional]`` on its own line; a trailing reason is introduced by two
    spaces and ``#``, so a ``#`` inside a parametrised id is never read as one.
    """

    entries: dict[str, tuple[str, str]] = {}
    section = REQUIRED
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped.startswith("["):
            header = stripped.strip("[]").strip().lower()
            if header not in SECTIONS:
                raise SystemExit(f"{path}: unknown section [{header}]; expected one of {SECTIONS}")
            section = header
            continue
        if raw.lstrip().startswith("#"):
            continue
        cut = raw.find("  #")
        line = (raw[:cut] if cut >= 0 else raw).strip()
        reason = raw[cut + 3 :].strip() if cut >= 0 else ""
        if line:
            entries[line] = (section, reason)
    return entries


def manifest_ids(path: Path) -> set[str]:
    """Every sanctioned id, both sections. Kept for callers that only ask
    whether a skip is sanctioned at all."""

    return set(manifest_entries(path))


def _workflow_steps(workflow: Path) -> dict[str, dict]:
    """``step name -> step`` across every job in a workflow."""

    document = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
    steps: dict[str, dict] = {}
    for job in (document.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            name = step.get("name")
            if name:
                steps[name] = step
    return steps


def proof_problem(test_id: str, reason: str) -> str | None:
    """Why this conditional entry's proof does not hold, or ``None``.

    A conditional sanction says "this skip is acceptable HERE because the test
    is proven THERE". That claim is checked, not taken: the workflow must
    exist, the step must exist in it, and the step must set a ``PROM_REQUIRE_*``
    flag — the mechanism that makes the test FAIL rather than skip in the place
    it is proven. Without the flag the proof step would skip just as quietly as
    the run being excused here.
    """

    match = _PROOF.search(reason)
    if match is None:
        return f"{test_id}: conditional entry carries no `proof: <workflow> :: <step>`"
    workflow = WORKFLOWS / match.group("workflow")
    if not workflow.is_file():
        return f"{test_id}: proof names {match.group('workflow')}, which is not a workflow in .github/workflows"
    steps = _workflow_steps(workflow)
    step_name = match.group("step")
    if step_name not in steps:
        return f"{test_id}: proof names step {step_name!r}, which {match.group('workflow')} does not define"
    env = steps[step_name].get("env") or {}
    flags = [key for key, value in env.items() if _REQUIRE_FLAG.match(str(key)) and str(value) == "1"]
    if not flags:
        return (
            f"{test_id}: proof step {step_name!r} sets no PROM_REQUIRE_* flag, so the test "
            "would skip there too — a sanction with no proof behind it"
        )
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("report", help="JUnit XML from the full-suite run")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    args = parser.parse_args(argv)

    observed = skipped_ids(Path(args.report))
    entries = manifest_entries(Path(args.manifest))

    required = {i for i, (section, _) in entries.items() if section == REQUIRED}
    conditional = {i for i, (section, _) in entries.items() if section == CONDITIONAL}

    unsanctioned = sorted(set(observed) - set(entries))
    stale = sorted(required - set(observed))
    unproven = sorted(
        problem
        for test_id in conditional
        if (problem := proof_problem(test_id, entries[test_id][1])) is not None
    )
    ran_here = sorted(conditional - set(observed))

    if unsanctioned:
        print(f"skip manifest FAILED: {len(unsanctioned)} skip(s) not sanctioned:")
        for test_id in unsanctioned:
            print(f"  {test_id}  ({observed[test_id][:100]})")
    if stale:
        print(f"skip manifest FAILED: {len(stale)} required entr{'y' if len(stale) == 1 else 'ies'} did not skip (ran, or no longer exists):")
        for test_id in stale:
            print(f"  {test_id}")
    if unproven:
        print(f"skip manifest FAILED: {len(unproven)} conditional entr{'y' if len(unproven) == 1 else 'ies'} without a proof:")
        for problem in unproven:
            print(f"  {problem}")
    if unsanctioned or stale or unproven:
        print(
            "Sanction a new skip in tests/conformance/skip_manifest.txt WITH its reason, "
            "or make the test run; remove an entry whose test now runs; a host-dependent "
            "skip belongs in [conditional] with the step that proves it under a "
            "PROM_REQUIRE_* flag."
        )
        return 1
    for test_id in ran_here:
        print(f"skip manifest: conditional entry RAN in this environment: {test_id}")
    print(
        f"skip manifest passed: {len(observed)} skip(s) observed, all sanctioned "
        f"({len(required)} required, {len(conditional)} conditional, {len(ran_here)} of them ran here)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
