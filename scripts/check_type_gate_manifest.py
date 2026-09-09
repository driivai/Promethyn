"""Every type-gate proof ran, by NAME. Mandatory CI step.

The collection pin this replaces compared COUNTS. An independent review noted
that a count catches deletion but not delete-one-add-one: remove the
planted-defect proof, add a trivial passing test, and the number is unchanged.

So the pin is the manifest — ``tests/conformance/type_gate_test_manifest.json``,
the exact set of test names per module. A removed proof, a renamed one, or an
added one all fail here and have to be reconciled deliberately. Skips, failures
and errors are refused outright: a proof that skipped did not run.

Regenerate deliberately, in the same change that adds or renames a test:
    python scripts/check_type_gate_manifest.py <junit.xml> --update

Run: python scripts/check_type_gate_manifest.py type-gate-proofs.xml
"""

from __future__ import annotations

import collections
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = REPO / "tests" / "conformance" / "type_gate_test_manifest.json"


def observed(report: Path) -> dict[str, list[str]]:
    cases = list(ET.parse(report).iter("testcase"))
    by: dict[str, list[str]] = collections.defaultdict(list)
    for case in cases:
        by[case.get("classname", "").rsplit(".", 1)[-1]].append(case.get("name") or "")
    return {module: sorted(names) for module, names in sorted(by.items())}


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    report = Path(argv[0])
    seen = observed(report)

    if "--update" in argv[1:]:
        MANIFEST.write_text(
            json.dumps(seen, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"manifest updated: {sum(len(v) for v in seen.values())} test(s)")
        return 0

    expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if seen != expected:
        for module in sorted(set(expected) | set(seen)):
            gone = sorted(set(expected.get(module, [])) - set(seen.get(module, [])))
            added = sorted(set(seen.get(module, [])) - set(expected.get(module, [])))
            for name in gone:
                print(f"MISSING  {module}::{name}", file=sys.stderr)
            for name in added:
                print(f"UNPINNED {module}::{name}", file=sys.stderr)
        print(
            "\nthe type-gate proof set does not match the manifest. A proof that "
            "vanished is a guard that stopped guarding; a proof that appeared is "
            "one nobody reviewed. Reconcile with --update in the same change.",
            file=sys.stderr,
        )
        return 1

    cases = list(ET.parse(report).iter("testcase"))
    bad = [
        f"{c.get('classname')}::{c.get('name')}"
        for c in cases
        for tag in ("skipped", "failure", "error")
        if c.find(tag) is not None
    ]
    if bad:
        print("these proofs did not pass cleanly: " + ", ".join(bad), file=sys.stderr)
        return 1

    print(f"type-gate proofs: {len(cases)} test(s), all named in the manifest, zero skips")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
