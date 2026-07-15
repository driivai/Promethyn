"""Human and JSON rendering. The human format is the product; keep it exact."""

from __future__ import annotations

import json
import textwrap

from .model import VOID, Finding, ScanResult

_WRAP = 96


def _wrap_block(label: str, text: str) -> list[str]:
    prefix = f"  {label:<10} "
    cont = " " * len(prefix)
    wrapped = textwrap.wrap(text, width=_WRAP, initial_indent=prefix,
                            subsequent_indent=cont) or [prefix.rstrip()]
    return wrapped


def render_finding(f: Finding) -> str:
    lines = [f"{f.id}  {f.verdict}"]
    lines += _wrap_block("guard:", f.guard)
    lines += _wrap_block("mechanism:", f.mechanism)
    lines += _wrap_block("evidence:", f.evidence.summary)
    if f.evidence.searched:
        lines += _wrap_block("", "searched: " + ", ".join(f.evidence.searched))
    if f.evidence.found:
        lines += _wrap_block("", "found: " + ", ".join(f.evidence.found))
    lines += _wrap_block("question:", f.question)
    lines += _wrap_block("fix:", f.fix)
    return "\n".join(lines)


def headline(result: ScanResult) -> str:
    n = result.counts()[VOID]
    return f"{n} guard{'s' if n != 1 else ''} in this repo ha{'ve' if n != 1 else 's'} never been observed to fail."


def render(result: ScanResult, *, suppressed: int = 0) -> str:
    counts = result.counts()
    out = [headline(result), ""]
    for f in result.findings:
        out.append(render_finding(f))
        out.append("")
    out.append(
        f"summary: {counts['VOID']} VOID, {counts['WARN']} WARN, "
        f"{counts['UNKNOWN']} UNKNOWN"
        + (f" ({suppressed} baselined finding(s) suppressed)" if suppressed else "")
    )
    for note in result.notes:
        out.append(f"note: {note}")
    return "\n".join(out) + "\n"


def render_json(result: ScanResult, *, suppressed: int = 0) -> str:
    data = result.to_dict()
    data["baselined_suppressed"] = suppressed
    return json.dumps(data, indent=2, sort_keys=False) + "\n"
