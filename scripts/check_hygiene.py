#!/usr/bin/env python3
"""Repository hygiene guard.

Fails (non-zero exit) if any tracked text file contains a banned tooling or
vendor token. The banned token list lives base64-encoded in
``scripts/hygiene_terms.txt`` (one encoded token per line) and is decoded at
runtime. Storing it encoded means no committed file in this repository — not
even this checker or the terms file — holds a literal banned token.

Two deliberate exclusions:

  * The terms file itself is never scanned (it would always "match").
  * The bare token "cursor" is excluded from matching: it collides with
    ordinary database- and text-cursor usage. It is kept in the encoded list
    for documentation, then dropped before scanning.
"""

from __future__ import annotations

import base64
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TERMS_FILE = Path(__file__).resolve().parent / "hygiene_terms.txt"

# Tokens that must not drive matching even though they appear in the list.
EXCLUDE_FROM_MATCHING = {"cursor"}


def load_terms() -> list[str]:
    terms: list[str] = []
    for line in TERMS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        decoded = base64.b64decode(line).decode("utf-8").strip().lower()
        if decoded and decoded not in EXCLUDE_FROM_MATCHING:
            terms.append(decoded)
    return terms


def candidate_files() -> list[Path]:
    """Tracked files, plus untracked-but-not-ignored ones (for pre-commit runs)."""

    seen: set[str] = set()
    commands = (
        ["git", "ls-files"],
        ["git", "ls-files", "--others", "--exclude-standard"],
    )
    for command in commands:
        result = subprocess.run(
            command, cwd=REPO_ROOT, capture_output=True, text=True, check=False
        )
        for rel in result.stdout.splitlines():
            rel = rel.strip()
            if rel:
                seen.add(rel)
    return [REPO_ROOT / rel for rel in sorted(seen)]


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None  # unreadable or binary; nothing textual to scan


def main() -> int:
    terms = load_terms()
    terms_rel = TERMS_FILE.relative_to(REPO_ROOT).as_posix()

    hits: list[tuple[str, str]] = []
    scanned = 0
    for path in candidate_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel == terms_rel:
            continue
        text = read_text(path)
        if text is None:
            continue
        scanned += 1
        lowered = text.lower()
        for term in terms:
            if term in lowered:
                hits.append((rel, term))

    if hits:
        print("repository hygiene check FAILED")
        for rel, term in hits:
            print(f"  {rel}: contains a banned token ({term!r})")
        return 1

    print(
        f"repository hygiene check passed: {scanned} files scanned, "
        f"{len(terms)} terms, no banned tokens found"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
