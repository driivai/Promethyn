"""Check a JUnit report against a pinned COMPOSITION, not just a count.

WHY. Every proof step in ``ci.yml`` used to assert ``len(cases) == N`` plus a
per-module breakdown. That catches a module that stopped collecting. It does
NOT catch the substitution that matters: delete a load-bearing refusal, add a
benign passing test to the same module, and the total is unchanged. Two sets of
the same size are indistinguishable by count, and where MEMBERSHIP is the
security property, membership is what has to be pinned.

So this checks three things against ``tests/conformance/proof_composition.json``:

1. **counts**, per module — collection loss, unchanged from before;
2. **membership** — every ``(module, name)`` pair in ``required`` ran;
3. **zero skips, failures or errors** — a skipped proof is not a proof.

MEMBERSHIP IS A PAIR, AND THE FIRST VERSION GOT THIS WRONG. It collected
``{name for ...}`` and discarded each testcase's module, so a required name
could be satisfied by a DIFFERENT collected module while the per-module counts
stayed right — rename the pinned proof to a filler, hand its old name to an
unpinned test elsewhere in the same step, and the check passed with the proof
gone. Found by review (PR #108, P2), reproduced, and fixed by keying membership
on ``(module, base name)``. What varies is the pair, so the pin is over the
pair; a name-only pin does not cover what varies, which is this file's own
argument applied to itself.

Names in ``required`` are BASE function names. A parametrised test appears in
JUnit as ``name[param]``, so matching is on the base: re-parametrising a test
keeps the pin, while deleting it — or MOVING it to another module — breaks it.

USAGE::

    python scripts/check_proof_composition.py <junit.xml> <step-key>
"""

from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "tests" / "conformance" / "proof_composition.json"


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _base_name(name: str) -> str:
    """``test_x[param]`` -> ``test_x``."""

    return name.split("[", 1)[0]


def _module_of(classname: str) -> str:
    """The dotted MODULE, dropping a test class if there is one.

    JUnit reports ``tests.conformance.test_x`` for a module-level test and
    ``tests.conformance.test_x.TestSomething`` for one inside a class. Counting
    by classname alone would split a module across its classes, which is how the
    two class-using steps came to need a different matcher from the rest.
    """

    parts = classname.split(".")
    while parts and parts[-1][:1].isupper():
        parts.pop()
    return ".".join(parts)


def check(report: Path, key: str) -> list[str]:
    """Return a list of problems; empty means the composition holds."""

    manifest = load_manifest()
    steps = manifest["steps"]
    if key not in steps:
        return [f"unknown step key {key!r}; known: {sorted(steps)}"]
    step = steps[key]
    problems: list[str] = []

    cases = list(ET.parse(report).iter("testcase"))
    if not cases:
        # An empty report reads downstream as "nothing failed" (doctrine #8).
        return [f"{report} contains no testcase elements at all"]

    observed = Counter(_module_of(c.get("classname", "")) for c in cases)
    for module, expected in step["counts"].items():
        actual = observed.get(module, 0)
        if actual != expected:
            problems.append(f"count: {module} ran {actual}, pinned {expected}")
    unpinned = sorted(set(observed) - set(step["counts"]))
    if unpinned:
        problems.append(f"count: modules in the report but not pinned: {unpinned}")

    # (module, base name). Keyed on the pair because the name alone is not the
    # identity of a proof: the same name in another module is a different test.
    ran = {
        (_module_of(c.get("classname", "")), _base_name(c.get("name", "")))
        for c in cases
    }
    missing = [
        f"{module}::{name}"
        for module, required in step["required"].items()
        for name in required
        if (module, name) not in ran
    ]
    if missing:
        problems.append(
            "membership: pinned proofs that did not run in their own module: "
            + ", ".join(sorted(missing))
        )

    for case in cases:
        for state in ("skipped", "failure", "error"):
            if case.find(state) is not None:
                problems.append(
                    f"{state}: {case.get('classname')}::{case.get('name')}"
                )
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    report, key = Path(argv[1]), argv[2]
    problems = check(report, key)
    if problems:
        print(f"proof composition REFUSED for {key!r}:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    manifest = load_manifest()["steps"][key]
    total = sum(manifest["counts"].values())
    pairs = sum(len(v) for v in manifest["required"].values())
    print(
        f"proof composition OK for {key!r}: {total} proofs across "
        f"{len(manifest['counts'])} module(s), {pairs} pinned by "
        f"(module, name), zero skips/failures/errors"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
