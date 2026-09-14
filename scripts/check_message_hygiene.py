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

THE COMMIT THAT DOES NOT EXIST YET. The squash-merge commit GitHub writes onto
``main`` is created AFTER every pre-merge check has passed, by the merge button.
The earlier version of this file recorded that as unrefusable and left the
push-to-``main`` run as the only detection — after the fact, with ``main`` red.
That was one measurement short. The composed message is not unknowable; it is
DERIVABLE, and ``--composed`` derives it and checks it before the merge.

Derived from two real squash commits in this repository's own history
(``c846272``, five commits; ``4451aa1``, one), GitHub composes:

* subject — the pull request's title with `` (#<number>)`` appended;
* body — for a single commit, that commit's body verbatim; for several, each
  commit oldest-first as ``* <subject>`` then a blank line then its body;
* trailers — one ``co-author…`` per DISTINCT author/committer identity
  among the squashed commits, excluding the merging account's own.

``tests/conformance/test_composed_message_guard.py`` reconstructs both of those
commits from history and compares byte for byte, so this is a model of the real
artifact rather than a guess about it, and it fails if GitHub's composition
drifts.

THE CO-AUTHORSHIP TRAILER IS AN IDENTITY QUESTION, NOT A STRING ONE. The term
list bans the literal trailer key because an assistant harness writes one
naming its vendor. Measured across all refs (2026-09-14): 90 co-authorship
trailers, of which 89 name ``DriivAIDev <will@driivai.com>`` — this repository's
own author — and ONE names a vendor. That one is independently caught by the
vendor-name terms in the same list, twice. A string-keyed rule that fires 89
times on the repository's own identity is not a guard; it is noise that trains
readers to ignore the signal, and it is what turned ``main`` red on every squash
merge (``docs/OPEN-GAPS.md`` G13).

So the REFUSING modes key on the identity, not the string: a co-authorship
trailer naming an identity in ``PERMITTED_COAUTHORS`` passes; one naming
anything else is refused, and every other term still matches as a plain string
anywhere it appears, identities included. ``--history`` is deliberately NOT
allowlisted — it is a measuring instrument that never refuses, and PROM-IP Part
B needs the raw count.

WHAT REMAINS UNREFUSABLE, named rather than implied: the merging account is not
knowable from a pull-request event, so ``--composed`` assumes the worst case
(every distinct identity becomes a trailer) unless ``--merged-by`` says
otherwise; and a human may edit the squash message in the merge dialog after
this has passed. The push-to-``main`` run remains the backstop for both.

Modes::

    --commits <range>       refuse: message, author and committer of every commit in
                            ``git rev-list <range>``
    --message-file <path>   refuse: one commit message (the commit-msg hook's argument)
    --text-file <path>      refuse: arbitrary text (a PR title or body written to a file)
    --composed <range>      refuse: the squash message GitHub will compose from
                            <range>; needs --pr-number, takes --title and --merged-by
    --history <ref>         SWEEP, never refuses: count, per term, every commit reachable
                            from <ref> that carries it, and list them. This is the
                            measurement PROM-IP Part B (the provenance rewrite) needs.

Exit 1 on any hit in a refusing mode; 0 otherwise.
"""

from __future__ import annotations

import argparse
import base64
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

#: The ONLY identities a ``co-author…`` trailer may name in a refusing
#: mode. An allowlist, not a pattern: the question "is this co-authorship line
#: acceptable" is a question about WHO is named, and the set of acceptable
#: answers is small, known, and written here. Adding an entry is a deliberate
#: act with a reviewer; a vendor identity cannot arrive by matching a shape.
#: Compared case-folded on the whole ``Name <email>`` string.
PERMITTED_COAUTHORS = frozenset({"driivaidev <will@driivai.com>"})

#: The co-authorship trailer key, decoded rather than typed. This file
#: cannot contain the literal: ``scripts/check_hygiene.py`` scans the tree
#: for exactly these terms, and the guard's own source is part of the tree.
#: Same base64 idiom, and same reason, as ``scripts/hygiene_terms.txt``.
_COAUTHOR_PREFIX = base64.b64decode("Y28tYXV0aG9yZWQtYnk=").decode() + ":"

#: The same key as GitHub CAPITALISES it when it writes one. Matching is
#: case-insensitive and uses the lowercase form above; COMPOSING has to
#: reproduce the artifact exactly, and the byte comparison in
#: tests/conformance/test_composed_message_guard.py caught the difference.
_COAUTHOR_TRAILER = _COAUTHOR_PREFIX[0].upper() + _COAUTHOR_PREFIX[1:]

#: What GitHub writes between the last bulleted commit and the trailers when a
#: squash combines MORE THAN ONE commit. Absent from all five source commit
#: bodies of ``c846272`` and present once in the squash, so it is GitHub's, not
#: an author's. NINE hyphens, counted on the real line rather than eyeballed —
#: the first attempt here wrote ten and the byte comparison caught it.
_MULTI_COMMIT_SEPARATOR = "-" * 9 + "\n\n"


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


def _permitted_coauthor_line(line: str) -> bool:
    """True for a ``co-author…`` line naming an allowlisted identity."""

    stripped = line.strip()
    if not stripped.lower().startswith(_COAUTHOR_PREFIX):
        return False
    named = stripped.split(":", 1)[1].strip().casefold()
    return named in PERMITTED_COAUTHORS


def refusable_hits(text: str, terms: list[str]) -> list[str]:
    """``hits_in``, minus co-authorship lines naming an allowlisted identity.

    Only the co-authorship term is treated this way, and only on a line that
    IS such a trailer. Every other term — every vendor name — still matches
    anywhere in the text, including inside a permitted trailer, so a trailer
    reading ``co-author…: <a vendor>`` is refused by the vendor term even
    though the allowlist had nothing to say about it.
    """

    lines = text.splitlines()
    if not any(_permitted_coauthor_line(line) for line in lines):
        return hits_in(text, terms)
    remainder = "\n".join(
        line for line in lines if not _permitted_coauthor_line(line)
    )
    found = hits_in(remainder, terms)
    # The allowlist speaks only for the co-authorship term. If a NON-permitted
    # co-authorship line also exists, the term is back in play.
    return found


def _commit_hits(
    commits: list[tuple[str, str, str, str]],
    terms: list[str],
    *,
    refusing: bool,
) -> list[tuple[str, str, str]]:
    """(sha, where, term) for every banned term in a message or an identity.

    Identities are scanned as well as messages: a committer identity naming a
    vendor's no-reply address is a vendor token in the commit, and it is exactly
    what the harness that made this repository's recent commits wrote on them.
    """

    found: list[tuple[str, str, str]] = []
    match = refusable_hits if refusing else hits_in
    for sha, author, committer, message in commits:
        for where, text in (("message", message), ("author", author), ("committer", committer)):
            for term in match(text, terms):
                found.append((sha[:10], where, term))
    return found


def squashed_commits(rev_range: str) -> list[tuple[str, str, str, str, str]]:
    """(sha, subject, body, author, committer), OLDEST FIRST — squash order."""

    out = _git(
        "log",
        "--reverse",
        rev_range,
        f"--format=%H{_SEP}%s{_SEP}%b{_SEP}%an <%ae>{_SEP}%cn <%ce>{_END}",
    )
    rows: list[tuple[str, str, str, str, str]] = []
    for chunk in out.split(_END):
        if not chunk.strip():
            continue
        sha, subject, body, author, committer = chunk.lstrip("\n").split(_SEP, 4)
        rows.append((sha, subject, body, author, committer))
    return rows


def predicted_coauthors(
    rows: list[tuple[str, str, str, str, str]], merged_by: str | None
) -> list[str]:
    """The identities GitHub will write as trailers, first-seen order.

    Every distinct author and committer among the squashed commits, less the
    merging account's own. ``merged_by`` is not knowable from a pull-request
    event, so the caller that omits it gets the WORST CASE — which is also the
    case this repository has actually merged under twice.
    """

    excluded = merged_by.casefold().strip() if merged_by else None
    seen: list[str] = []
    for _sha, _subject, _body, author, committer in rows:
        for identity in (author, committer):
            if identity.casefold().strip() == excluded:
                continue
            if identity not in seen:
                seen.append(identity)
    return seen


def compose_squash_message(
    rev_range: str,
    pr_number: int,
    *,
    title: str | None = None,
    merged_by: str | None = None,
) -> str:
    """The squash-merge message GitHub will write, derived not guessed.

    Verified byte for byte against ``c846272`` (five commits) and ``4451aa1``
    (one) by ``tests/conformance/test_composed_message_guard.py``. If GitHub
    changes how it composes, that test fails and this stops being a model of
    anything — which is the point of pinning it to real artifacts.
    """

    return compose_from_rows(
        squashed_commits(rev_range),
        pr_number,
        title=title,
        merged_by=merged_by,
        source=rev_range,
    )


def compose_from_rows(
    rows: list[tuple[str, str, str, str, str]],
    pr_number: int,
    *,
    title: str | None = None,
    merged_by: str | None = None,
    source: str = "the given rows",
) -> str:
    """``compose_squash_message`` without the git query, so it can be driven.

    THE SOURCE COMMITS OF A SQUASH DO NOT SURVIVE THE MERGE. Once the branch is
    deleted they are reachable from no ref, so a CI checkout does not have them
    however deep it fetches — measured on run 34860607395, where all three jobs
    refused with ``unknown revision`` on a range this file's own tests pinned.
    Splitting the query off means the composition can be proven against rows
    captured while they existed, and the expected output still read live from
    the squash commit on ``main``, which is permanent.
    """

    if not rows:
        raise SystemExit(f"no commits in {source}: nothing would be squashed")
    subject = f"{title if title is not None else rows[0][1]} (#{pr_number})"
    if len(rows) == 1:
        body = rows[0][2] + "\n"
    else:
        # The ``----------`` rule below is observed from ONE multi-commit
        # squash (``c846272``), which is the only one this repository has.
        # It is written down as what was measured, not as knowledge of
        # GitHub's implementation, and the conformance test is what will
        # notice if the next one disagrees.
        chunks = "\n".join(f"* {row[1]}\n\n{row[2].strip(chr(10))}\n" for row in rows)
        body = chunks + "\n" + _MULTI_COMMIT_SEPARATOR
    trailers = "".join(
        f"{_COAUTHOR_TRAILER} {identity}\n"
        for identity in predicted_coauthors(rows, merged_by)
    )
    return f"{subject}\n\n{body}{trailers}"


def refuse_composed(
    rev_range: str,
    pr_number: int,
    terms: list[str],
    *,
    title: str | None = None,
    merged_by: str | None = None,
) -> int:
    message = compose_squash_message(
        rev_range, pr_number, title=title, merged_by=merged_by
    )
    found = refusable_hits(message, terms)
    rows = squashed_commits(rev_range)
    who = predicted_coauthors(rows, merged_by)
    print(
        f"composed squash message for #{pr_number}: {len(rows)} commit(s) in "
        f"{rev_range}, {len(message)} chars, "
        f"{len(who)} predicted co-authorship trailer(s)"
    )
    for identity in who:
        permitted = identity.casefold() in PERMITTED_COAUTHORS
        print(f"    {'permitted' if permitted else 'NOT PERMITTED'}: {identity}")
    if not found:
        print(
            "message hygiene passed: the message this merge would write carries "
            "no banned token"
        )
        return 0
    print(f"message hygiene FAILED: the composed squash message carries {found}")
    print(
        "  This is the commit the merge button would create. Refusing it here "
        "is the only place it can be refused before it exists."
    )
    if _COAUTHOR_PREFIX.rstrip(":") in found:
        print(
            "  A co-authorship trailer names an identity outside "
            "PERMITTED_COAUTHORS. Either the merge is being made by an account "
            "whose commit email differs from the author's, or an identity was "
            "added that nobody allowlisted."
        )
    return 1


def refuse_commits(rev_range: str, terms: list[str]) -> int:
    commits = commits_in(rev_range)
    found = _commit_hits(commits, terms, refusing=True)
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
        found = refusable_hits(text, terms)
        if found:
            failed = 1
            print(f"message hygiene FAILED: {path} contains banned token(s) {found}")
        else:
            print(f"message hygiene passed: {path} ({len(text)} chars), no banned tokens")
    return failed


def sweep_history(ref: str, terms: list[str]) -> int:
    commits = commits_in(ref)
    found = _commit_hits(commits, terms, refusing=False)
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
    parser.add_argument(
        "--composed", metavar="RANGE",
        help="refuse the squash message GitHub would compose from RANGE",
    )
    parser.add_argument("--pr-number", type=int, help="required with --composed")
    parser.add_argument(
        "--title", help="the pull request's title; defaults to the first commit's subject",
    )
    parser.add_argument(
        "--merged-by", metavar="IDENTITY",
        help=(
            "'Name <email>' of the merging account, whose own identity GitHub "
            "omits from the trailers. Omit for the worst case."
        ),
    )
    args = parser.parse_args(argv)
    if args.composed and args.pr_number is None:
        parser.error("--composed needs --pr-number: the subject carries it")
    terms = load_terms()
    if not terms:
        print("no hygiene terms decoded; refusing to report a pass over nothing")
        return 1

    ran = False
    status = 0
    if args.history:
        ran = True
        status |= sweep_history(args.history, terms)
    if args.composed:
        ran = True
        status |= refuse_composed(
            args.composed, args.pr_number, terms,
            title=args.title, merged_by=args.merged_by,
        )
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
