"""The open gaps that can be stated as PASSING TESTS — doctrine #5.

``docs/OPEN-GAPS.md`` is the tracker. A gap that lives only in prose has a
countdown; the ones here are pinned so they can close and cannot quietly grow.
Each test names its entry in the tracker. A ratchet moves DOWN only: when a
count falls, lower the pin in the same change; a count that rises fails here.
"""

from __future__ import annotations

import pathlib
import re

from tests.support.positional_sweep import positional_constructions, wide_dataclasses

REPO = pathlib.Path(__file__).resolve().parents[2]
TRACKER = REPO / "docs" / "OPEN-GAPS.md"

#: OPEN-GAPS G2. Positional constructions of wide (>= 6 field) dataclasses, per
#: class, as the sweep observed them on 2026-09-12 after ``Evidence`` and
#: ``Judgment`` became kw_only. The classes are what remains; the numbers may
#: only fall. ``MigrationResult`` and ``ReconciliationResult`` gained a trailing
#: defaulted field this sprint and their positional sites are unchanged.
POSITIONAL_SITES_CEILING: dict[str, int] = {
    "DbTarget": 11,
    "Coverage": 7,
    "GateRead": 7,
    "SubstrateReport": 6,
    "SignEvent": 4,
    "MigrationResult": 2,
    "ReconciliationResult": 2,
    "UnparsedEntry": 2,
    "PagedSignAuditSource": 2,
    "MountEntry": 1,
    "KeyPin": 1,
    "JudgedRow": 1,
    "TrustStats": 1,
}


def test_the_tracker_exists_and_names_every_gap_pinned_here():
    text = TRACKER.read_text(encoding="utf-8")
    for gap in ("G1", "G2", "G3", "G4", "G5"):
        assert re.search(rf"^## {gap}\b", text, re.M), f"docs/OPEN-GAPS.md has no entry {gap}"


def test_positional_construction_of_wide_dataclasses_does_not_grow():
    """G2. The sweep instrument, run live, against the ceiling."""

    wide = wide_dataclasses()
    assert len(wide) >= 40, f"the sweep imported only {len(wide)} wide dataclasses; it is not reaching the package"
    for name in ("Evidence", "Judgment"):
        assert wide[name][1] is True, f"{name} is no longer kw_only; the closed half of G2 reopened"
    hits = positional_constructions(wide)
    grown = {
        name: (len(sites), POSITIONAL_SITES_CEILING.get(name, 0))
        for name, sites in hits.items()
        if len(sites) > POSITIONAL_SITES_CEILING.get(name, 0)
    }
    assert grown == {}, (
        f"positional constructions grew past the ceiling: {grown}. A wide "
        "dataclass built positionally can mis-slot a field without raising; "
        "construct by keyword, or make the class kw_only."
    )
    # And the ratchet is honest: a ceiling with nothing under it is stale.
    stale = sorted(name for name in POSITIONAL_SITES_CEILING if name not in hits)
    assert stale == [], f"ceilings with no sites behind them (lower or remove them): {stale}"


def test_evidence_and_judgment_cannot_be_built_positionally():
    """The closed half of G2, kept closed."""

    import pytest

    from prometheus_protocol.core.models import Evidence, Judgment, Verdict

    # Called through a local name so the sweep in this same file does not count
    # its own control as a positional construction site.
    for cls, positional in ((Evidence, (True, 1, 1, ())), (Judgment, (Verdict.PASS, 1.0, True))):
        with pytest.raises(TypeError):
            cls(*positional)
