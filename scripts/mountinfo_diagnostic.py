"""What this host's mount table actually looks like, per row.

Format recognition is expanded from measured data, not from a reading of the
kernel source: the nsfs regression was the first sample from a distribution we
had not looked at. This runs on every Linux CI job and prints the observed
shape — for each row the driver, the format class of its mount root, and
whether the parser reads it — so the next format is added because it was seen,
not because it was guessed.

It is also a gate, not only a report: the directories this checkout actually
uses must classify safe under the strictest policy, and any row the parser
cannot read that is *relevant* to them fails the build here rather than
surprising an operator later.

Run: python scripts/mountinfo_diagnostic.py
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

from prometheus_protocol.chokepoint.substrate import (
    MOUNTINFO_PATH,
    MountEntry,
    SubstratePolicy,
    enforce_substrate,
    parse_mount_table,
    probe_substrate,
)

#: Kernel ``show_path`` labels: nsfs writes ``net:[4026533001]``, and it is not
#: the only driver that can write something that is not a pathname.
LABEL = re.compile(r"[a-z][a-z0-9_]*:\[[0-9]+\]")


def root_format(root: str) -> str:
    """The format class of a mount root, as observed on the wire."""

    if root.endswith("//deleted"):
        return "deleted-suffix"
    if root.startswith("/"):
        return "absolute" if os.path.normpath(root) == root else "unnormalized-absolute"
    if LABEL.fullmatch(root):
        return "kernel-label"
    return "other"


def observed(text: str) -> list[dict[str, object]]:
    """One record per row: driver, root format, and whether it was read."""

    table = parse_mount_table(text)
    read = {entry.mount_id: entry for entry in table.entries}
    rows: list[dict[str, object]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        parts = line.split(" ")
        separator = parts.index("-") if "-" in parts else -1
        root = parts[3] if len(parts) > 4 and separator >= 6 else ""
        driver = parts[separator + 1] if 0 <= separator < len(parts) - 1 else "?"
        entry = read.get(int(parts[0])) if parts and parts[0].isdecimal() else None
        rows.append({
            "line": number,
            "driver": driver,
            "root_format": root_format(root) if root else "unreadable",
            "parsed": isinstance(entry, MountEntry) and entry.mount_point == (
                parts[4] if len(parts) > 4 else None),
        })
    return rows


def main() -> int:
    if not sys.platform.startswith("linux"):
        print(f"mountinfo diagnostic: no mount table on {sys.platform}")
        return 0
    text = Path(MOUNTINFO_PATH).read_text(encoding="utf-8", errors="replace")
    table = parse_mount_table(text)
    rows = observed(text)

    distribution = Counter(
        (str(row["driver"]), str(row["root_format"]), bool(row["parsed"]))
        for row in rows
    )
    print(f"mountinfo: {len(rows)} rows; {len(table.entries)} read, "
          f"{len(table.unparsed)} unread")
    print(f"{'driver':<16} {'root format':<22} {'read':<5} count")
    for (driver, shape, parsed), count in sorted(distribution.items()):
        print(f"{driver:<16} {shape:<22} {str(parsed):<5} {count}")
    for entry in table.unparsed:
        print(f"  UNREAD {entry.describe()}")

    verdicts = []
    for path in (Path.cwd(), Path(tempfile.gettempdir())):
        report = probe_substrate(path)
        summary = report.set_aside_summary()
        print(f"{path}: {report.fs_type} / {report.verdict}"
              + (f"; {summary}" if summary else ""))
        # The gate: this checkout's own directories must verify, and no row
        # relevant to them may be unreadable.
        enforce_substrate(report, SubstratePolicy(require_verified=True))
        verdicts.append({"path": str(path), "fs_type": report.fs_type,
                         "verdict": report.verdict,
                         "set_aside": len(report.set_aside)})

    # One machine-readable line so the distribution can be collected across the
    # whole CI matrix without scraping the table above.
    print("MOUNTINFO_DIAGNOSTIC " + json.dumps({
        "python": ".".join(str(n) for n in sys.version_info[:2]),
        "rows": len(rows),
        "read": len(table.entries),
        "unread": [entry.describe() for entry in table.unparsed],
        "distribution": [
            {"driver": driver, "root_format": shape, "parsed": parsed, "count": count}
            for (driver, shape, parsed), count in sorted(distribution.items())
        ],
        "probes": verdicts,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
