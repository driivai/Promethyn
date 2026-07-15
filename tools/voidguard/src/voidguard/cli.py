"""voidguard scan .  — does your green actually check anything?

Exit codes: 0 clean (no unbaselined findings at/above --fail-on), 1 findings,
2 scanner error. UNKNOWN is a first-class verdict: where static analysis cannot
decide, the scanner says so instead of guessing.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__, baseline as baseline_mod, engine, report
from .model import SEVERITY

_FAIL_LEVELS = {
    "any": 1,       # any finding (VOID, WARN or UNKNOWN)
    "warn": 2,      # WARN or VOID
    "void": 3,      # VOID only
    "never": 99,    # report-only
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="voidguard")
    parser.add_argument("--version", action="version", version=f"voidguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan a checkout for void guards")
    scan_p.add_argument("path", nargs="?", default=".")
    scan_p.add_argument("--json", metavar="FILE", help="write JSON report ('-' = stdout)")
    scan_p.add_argument("--baseline", metavar="FILE", help="suppress acknowledged findings")
    scan_p.add_argument("--fail-on", choices=sorted(_FAIL_LEVELS), default="any",
                        help="lowest verdict that makes the exit code 1 (default: any)")
    scan_p.add_argument("--repo", metavar="OWNER/NAME",
                        help="enable API checks (schedule run history); uses GITHUB_TOKEN")

    base_p = sub.add_parser("baseline", help="write a baseline acknowledging current findings")
    base_p.add_argument("path", nargs="?", default=".")
    base_p.add_argument("-o", "--output", default=".voidguard-baseline.json")

    args = parser.parse_args(argv)
    try:
        return _run(args)
    except KeyboardInterrupt:
        return 2
    except Exception as exc:  # scanner error is a distinct exit code by contract
        print(f"voidguard: scanner error: {exc!r}", file=sys.stderr)
        return 2


def _run(args: argparse.Namespace) -> int:
    probe = None
    if getattr(args, "repo", None):
        from .ghapi import make_schedule_probe
        probe = make_schedule_probe(args.repo)

    result = engine.scan(args.path, schedule_probe=probe)

    if args.command == "baseline":
        baseline_mod.save(args.output, result.findings)
        print(f"voidguard: wrote {args.output} acknowledging "
              f"{len(result.findings)} finding(s)")
        return 0

    suppressed = 0
    if args.baseline:
        known = baseline_mod.load(args.baseline)
        result.findings, suppressed = baseline_mod.split(result.findings, known)

    print(report.render(result, suppressed=suppressed), end="")
    if args.json:
        payload = report.render_json(result, suppressed=suppressed)
        if args.json == "-":
            print(payload, end="")
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(payload)

    threshold = _FAIL_LEVELS[args.fail_on]
    actionable = [f for f in result.findings if SEVERITY[f.verdict] >= threshold]
    return 1 if actionable else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
