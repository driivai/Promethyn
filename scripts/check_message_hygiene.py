#!/usr/bin/env python3
"""Refuse banned tooling/vendor tokens in commit messages, commit identities and PR text.

WHY A SECOND CHECKER. ``scripts/check_hygiene.py`` scans the TREE: every tracked
file, on every build. It could not see the message that PR #100's squash merge
carried onto ``main``, because a commit message is not a tracked file, and it
cannot see a pull request's body at all. Measured on ``origin/main`` before this
checker existed: eight commits whose messages carry the assistant-session
trailer, one of them also a co-authorship line naming an assistant vendor, and
seventy-four whose messages carry a co-authorship trailer added by the squash
merge itself. Every one of those passed the tree checker, because the tree
checker was never looking there.

The control that existed was "strip the injected footer from the PR body, then
verify by re-reading it". That is vigilance against a merge window the author
does not control — #100 merged nine minutes after it was opened, before the
re-read happened. This is the construction that replaces it: a message carrying
a banned token is REFUSED, by the ``commit-msg`` hook at commit time, by the
``pre-push`` hook at push time, and by CI on the pull request's commits, title
and body. Nothing here strips anything; a refusal says what was found and where.

THE TERMS are the same encoded list the tree checker uses
(``scripts/hygiene_terms.txt``), decoded through ``check_hygiene.load_terms`` so
the two guards cannot disagree about what is banned. That includes the tree
checker's one exclusion (the bare ``cursor``, which collides with ordinary
database-cursor usage).

WHAT THIS CANNOT REFUSE, named rather than implied: the squash-merge commit
GitHub writes onto ``main`` is created AFTER every check has passed, by the
merge button, and it can carry a co-authorship trailer that GitHub adds for any
commit author who is not the merging account. No pre-merge check can refuse a
commit that does not exist yet. On a push to ``main`` this checker runs over
the landed commits and FAILS THE MAIN BUILD if one carries a token — detection
after the fact, loudly, which is the most a workflow can do. The setting that
stops it at the source is the repository's squash-merge message default (and
the merging account's commit email matching the commit author), which is a
repository setting and not something this file can enforce.

Modes::

    --commits <range>       refuse: message, author and committer of every commit in
                            ``git rev-list <range>``
    --message-file <path>   refuse: one commit message (the commit-msg hook's argument)
    --text-file <path>      refuse: arbitrary text (a PR title or body written to a file)
    --history <ref>         SWEEP, never refuses: count, per term, every commit reachable
                            from <ref> that carries it, and list them. This is the
                            measurement PROM-IP Part B (the provenance rewrite) needs.

Exit 1 on any hit in a refusing mode; 0 otherwise.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_hygiene import load_terms  # noqa: E402  - the one shared term list

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Field separator for the log format. Unit-separator bytes cannot appear in a
#: git identity and are not going to appear in a message either.
_SEP = "\x1f"
_END = "\x1e"


def _git(*args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def commits_in(rev_range: str) -> list[tuple[str, str, str, str]]:
    """(sha, author, committer, message) for every commit in ``rev_range``."""

    out = _git(
        "log", rev_range, f"--format=%H{_SEP}%an <%ae>{_SEP}%cn <%ce>{_SEP}%B{_END}"
    )
    commits: list[tuple[str, str, str, str]] = []
    for chunk in out.split(_END):
        chunk = chunk.strip("\n")
        if not chunk.strip():
            continue
        sha, author, committer, message = chunk.split(_SEP, 3)
        commits.append((sha, author, committer, message))
    return commits


def hits_in(text: str, terms: list[str]) -> list[str]:
    lowered = text.lower()
    return [term for term in terms if term in lowered]


def _commit_hits(
    commits: list[tuple[str, str, str, str]], terms: list[str]
) -> list[tuple[str, str, str]]:
    """(sha, where, term) for every banned term in a message or an identity.

    Identities are scanned as well as messages: a committer identity naming a
    vendor's no-reply address is a vendor token in the commit, and it is exactly
    what the harness that made this repository's recent commits wrote on them.
    """

    found: list[tuple[str, str, str]] = []
    for sha, author, committer, message in commits:
        for where, text in (("message", message), ("author", author), ("committer", committer)):
            for term in hits_in(text, terms):
                found.append((sha[:10], where, term))
    return found


def refuse_commits(rev_range: str, terms: list[str]) -> int:
    commits = commits_in(rev_range)
    found = _commit_hits(commits, terms)
    if found:
        print(f"message hygiene FAILED over {rev_range} ({len(commits)} commit(s)):")
        for sha, where, term in found:
            print(f"  {sha} {where}: contains a banned token ({term!r})")
        return 1
    print(
        f"message hygiene passed: {len(commits)} commit(s) in {rev_range}, "
        f"{len(terms)} terms, no banned tokens in any message or identity"
    )
    return 0


def refuse_text(paths: list[Path], terms: list[str]) -> int:
    failed = 0
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        found = hits_in(text, terms)
        if found:
            failed = 1
            print(f"message hygiene FAILED: {path} contains banned token(s) {found}")
        else:
            print(f"message hygiene passed: {path} ({len(text)} chars), no banned tokens")
    return failed


def sweep_history(ref: str, terms: list[str]) -> int:
    commits = commits_in(ref)
    found = _commit_hits(commits, terms)
    by_term: dict[str, set[str]] = {}
    for sha, where, term in found:
        by_term.setdefault(term, set()).add(f"{sha}:{where}")
    print(f"history sweep of {ref}: {len(commits)} commit(s) reachable")
    if not found:
        print("  no commit carries a banned token in its message or identities")
        return 0
    for term in sorted(by_term, key=lambda t: -len(by_term[t])):
        sites = sorted(by_term[term])
        print(f"  {term!r}: {len(sites)} site(s)")
        for site in sites:
            print(f"      {site}")
    carrying = sorted({sha for sha, _, _ in found})
    print(f"  commits carrying at least one term: {len(carrying)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--commits", metavar="RANGE", help="refuse over a rev range")
    parser.add_argument("--message-file", metavar="PATH", help="refuse over one message")
    parser.add_argument(
        "--text-file", metavar="PATH", action="append", default=[],
        help="refuse over arbitrary text; repeatable",
    )
    parser.add_argument("--history", metavar="REF", help="sweep and report, never refuse")
    args = parser.parse_args(argv)
    terms = load_terms()
    if not terms:
        print("no hygiene terms decoded; refusing to report a pass over nothing")
        return 1

    ran = False
    status = 0
    if args.history:
        ran = True
        status |= sweep_history(args.history, terms)
    if args.commits:
        ran = True
        status |= refuse_commits(args.commits, terms)
    if args.message_file:
        ran = True
        status |= refuse_text([Path(args.message_file)], terms)
    if args.text_file:
        ran = True
        status |= refuse_text([Path(p) for p in args.text_file], terms)
    if not ran:
        parser.error("nothing to check: give --commits, --message-file, --text-file or --history")
    return status


if __name__ == "__main__":
    sys.exit(main())
