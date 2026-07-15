"""Post (or update) the voidguard summary comment on the current PR.

Stdlib only. Uses GITHUB_TOKEN / GITHUB_REPOSITORY / GITHUB_EVENT_PATH from the
Actions environment. Failures print a warning and exit 0 — a broken comment
must never fail a report-only scan.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request

MARKER = "<!-- voidguard-report -->"
ARTICLE = "https://github.com/driivai/promethyn/blob/main/docs/skip-sweep.md"


def _api(url: str, method: str = "GET", body: dict | None = None):
    token = os.environ["GITHUB_TOKEN"]
    req = urllib.request.Request(url, method=method, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "voidguard",
    })
    data = json.dumps(body).encode() if body is not None else None
    with urllib.request.urlopen(req, data=data, timeout=30) as resp:
        return json.loads(resp.read().decode() or "null")


def build_comment(report: dict) -> str:
    counts = report["counts"]
    n = counts["VOID"]
    head = (f"**{n} guard{'s' if n != 1 else ''} in this repo "
            f"ha{'ve' if n != 1 else 's'} never been observed to fail.**")
    lines = [MARKER, head, "",
             f"`voidguard` scan: **{counts['VOID']} VOID**, "
             f"{counts['WARN']} WARN, {counts['UNKNOWN']} UNKNOWN"
             + (f" ({report.get('baselined_suppressed', 0)} baselined)"
                if report.get("baselined_suppressed") else "")]
    findings = report.get("findings", [])
    if findings:
        lines += ["", "| id | verdict | guard | question |", "|---|---|---|---|"]
        for f in findings[:10]:
            guard = f["guard"].replace("|", "\\|")[:70]
            q = f["question"].replace("|", "\\|")[:90]
            lines.append(f"| {f['id']} | {f['verdict']} | `{guard}` | {q} |")
        if len(findings) > 10:
            lines.append(f"| … | | {len(findings) - 10} more in the full report | |")
    lines += ["", "Full report: the `voidguard-report` artifact on this run.",
              "", f"_A guard that has never been observed to fail is a guess, "
              f"not a guard — [the story behind this scanner]({ARTICLE})._"]
    return "\n".join(lines)


def main() -> int:
    try:
        report = json.load(open(sys.argv[1], encoding="utf-8"))
        event = json.load(open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8"))
        pr = event.get("pull_request", {}).get("number")
        if not pr:
            print("voidguard: not a pull_request event; skipping comment")
            return 0
        repo = os.environ["GITHUB_REPOSITORY"]
        body = build_comment(report)
        comments = _api(f"https://api.github.com/repos/{repo}/issues/{pr}/comments")
        mine = next((c for c in comments if MARKER in (c.get("body") or "")), None)
        if mine:
            _api(f"https://api.github.com/repos/{repo}/issues/comments/{mine['id']}",
                 "PATCH", {"body": body})
        else:
            _api(f"https://api.github.com/repos/{repo}/issues/{pr}/comments",
                 "POST", {"body": body})
        print("voidguard: comment posted")
        return 0
    except Exception as exc:
        print(f"voidguard: could not post comment ({exc!r}); the scan itself is unaffected")
        return 0


if __name__ == "__main__":
    sys.exit(main())
