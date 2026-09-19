"""``docs/DOCTRINE.md`` indexes exactly the doctrine numbers the tree cites.

The doctrines were cited by number for weeks and never enumerated; the file
that now indexes them is only as honest as its agreement with the citations.
So both sides are derived: every ``doctrine #N`` in the tree, every ``| N |``
row in the index, and the two must be the same set — a cited number the index
lacks is a reader sent nowhere, an indexed number nothing cites is an
enumeration invented after the fact. Numbers the index marks "never cited"
are exempt in one direction only: they may be indexed uncited, so the gaps in
the numbering are visible rather than papered over.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DOCTRINE = REPO / "docs" / "DOCTRINE.md"
ROOTS = ("docs", "src", "tests", "scripts", ".github")
SUFFIXES = {".md", ".py", ".yml", ".yaml", ".txt", ".json"}

_CITATION = re.compile(r"doctrine #(\d+)", re.IGNORECASE)
_ROW = re.compile(r"^\| (\d+) \| ([^|]+) \|", re.MULTILINE)


def _citations() -> dict[int, list[str]]:
    """``number -> [path:line, ...]`` for every citation outside DOCTRINE.md."""

    found: dict[int, list[str]] = {}
    for root in ROOTS:
        for path in sorted((REPO / root).rglob("*")):
            if path.suffix not in SUFFIXES or not path.is_file() or path == DOCTRINE:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                for match in _CITATION.finditer(line):
                    found.setdefault(int(match.group(1)), []).append(f"{path.relative_to(REPO)}:{number}")
    return found


def _indexed() -> dict[int, str]:
    """``number -> citations cell`` for every row of the index table."""

    return {int(n): cell.strip() for n, cell in _ROW.findall(DOCTRINE.read_text(encoding="utf-8"))}


#: The doctrine numbers the tree CITES, and the numbers the index CARRIES.
#: These differ by design: #3, #6 and #7 are indexed and marked "never cited",
#: which the index is allowed to do in one direction only. Observed at base
#: ce16a19 on 2026-09-19.
CITED_NUMBERS = frozenset({1, 2, 4, 5, 8, 9, 10, 11})
INDEXED_NUMBERS = frozenset({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})


def test_the_tree_cites_doctrines_and_the_index_has_rows():
    """Doctrine #8: an empty derivation on either side reads as agreement."""

    # MEMBERSHIP of the doctrine NUMBERS on each side, not a count of them.
    # Which doctrines the tree cites, and which the index carries, is the
    # property this module exists to keep honest; ``>= 5`` against eight and
    # eleven permitted three and six to disappear. A count also cannot see the
    # substitution that matters here — stop citing #4 and start citing #6, and
    # eight is still eight while the index is wrong about both.
    # The per-number COUNTS are pinned exactly by the test below; this pins the
    # sets those counts are taken over.
    assert set(_citations()) == CITED_NUMBERS, (
        f"the tree cites {sorted(_citations())}, pinned {sorted(CITED_NUMBERS)}"
    )
    assert set(_indexed()) == INDEXED_NUMBERS, (
        f"the index carries {sorted(_indexed())}, pinned {sorted(INDEXED_NUMBERS)}"
    )


def test_every_cited_number_is_indexed_and_every_indexed_number_is_cited_or_marked_uncited():
    cited = _citations()
    indexed = _indexed()
    missing = sorted(set(cited) - set(indexed))
    assert missing == [], f"cited in the tree, absent from docs/DOCTRINE.md: {missing} (first at {[cited[n][0] for n in missing]})"
    invented = sorted(
        n for n, cell in indexed.items()
        if n not in cited and cell not in ("0", "—")
    )
    assert invented == [], f"indexed with a citation count but never cited: {invented}"
    uncited_rows = sorted(n for n, cell in indexed.items() if cell == "0")
    assert all(n not in cited for n in uncited_rows), (
        f"marked 'never cited' but cited: {[n for n in uncited_rows if n in cited]}"
    )


def test_the_citation_counts_in_the_index_are_exactly_the_counts_in_the_tree():
    """Exact, not a floor: the index's numbers are the derivation's numbers or
    the index is a remembered snapshot — the shape doctrine #11 refuses. A new
    citation anywhere reddens this until the table is re-measured, which is
    the cost of a count that is never stale."""

    cited = {n: len(paths) for n, paths in _citations().items()}
    indexed = {n: cell for n, cell in _indexed().items() if cell not in ("0", "—")}
    assert {n: str(count) for n, count in cited.items()} == indexed, (
        f"tree: {dict(sorted(cited.items()))}\nindex: {dict(sorted(indexed.items()))}"
    )


def test_the_written_doctrine_is_present_in_full_and_cited_by_the_tracker():
    """The one doctrine written down so far is #11; its operative sentence is
    here verbatim and the tracker entries that apply it cite it by number."""

    text = DOCTRINE.read_text(encoding="utf-8")
    assert "## Doctrine #11" in text
    assert "comes from the ARTIFACT" in text and "the unfiltered total is reported beside" in text
    assert 11 in _citations(), "nothing in the tree applies doctrine #11 by number"
