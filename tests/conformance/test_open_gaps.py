"""The open gaps that can be stated as PASSING TESTS — doctrine #5.

``docs/OPEN-GAPS.md`` is the tracker. A gap that lives only in prose has a
countdown; the ones here are pinned so they can close and cannot quietly grow.
Each test names its entry in the tracker. A ratchet moves DOWN only: when a
count falls, lower the pin in the same change; a count that rises fails here.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from tests.support.positional_sweep import (
    SweepIncomplete,
    positional_constructions,
    wide_dataclasses,
)

#: Observed 2026-09-15. Was documented as 49, measured 2026-09-12; the tracker's
#: figure was one stale and is corrected with the measurement, not the reverse.
WIDE_DATACLASSES = 50

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
    # PINNED, not a floor. `>= 40` against a population of fifty permitted ten
    # to vanish unnoticed, and the sweep used to let them: it swallowed import
    # errors and reported the remainder as whole. It now raises SweepIncomplete
    # instead, so the population can only move by a real code change — and an
    # exact pin is what turns such a move into a decision rather than a drift.
    assert len(wide) == WIDE_DATACLASSES, (
        f"the sweep measured {len(wide)} wide dataclasses, pinned at "
        f"{WIDE_DATACLASSES}. If a class was added or widened, re-pin here and "
        "in docs/OPEN-GAPS.md G2 with the date. If it FELL, say which class "
        "stopped being wide and why."
    )
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


def test_the_sweep_refuses_a_module_it_cannot_import(monkeypatch):
    """G2's instrument must REFUSE a narrowed population, not report it.

    Probed by making one real module raise on import. Before this change the
    sweep swallowed the error, returned a smaller dict, and the caller's floor
    of `>= 40` let it through — nine could have vanished with nothing red.
    """

    import importlib

    real = importlib.import_module

    def _raise_for_one(name, *args, **kwargs):
        if name == "prometheus_protocol.core.bounds":
            raise ImportError("probe: this module cannot be imported")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(
        "tests.support.positional_sweep.importlib.import_module", _raise_for_one
    )
    with pytest.raises(SweepIncomplete) as refusal:
        wide_dataclasses()
    # It NAMES what it skipped; "something went wrong" would leave the reader
    # unable to tell a broken module from a narrowed sweep.
    assert "prometheus_protocol.core.bounds" in str(refusal.value)


def test_the_sweep_refuses_a_file_it_cannot_parse(tmp_path, monkeypatch):
    """The other half. An unparseable file is a file whose positional
    constructions cannot be seen, so reporting the rest understates the count."""

    import tests.support.positional_sweep as sweep

    root = tmp_path / "src"
    root.mkdir()
    (root / "broken.py").write_text("def (:\n", encoding="utf-8")
    monkeypatch.setattr(sweep, "REPO", tmp_path)
    monkeypatch.setattr(sweep, "ROOTS", ("src",))
    with pytest.raises(SweepIncomplete) as refusal:
        sweep.positional_constructions({"Anything": (6, False)})
    assert "src/broken.py" in str(refusal.value)


def test_the_sweep_does_not_refuse_a_healthy_tree(tmp_path, monkeypatch):
    """The positive control. Without it, both refusals above are consistent
    with a sweep that refuses everything — which would be a different defect
    and would make the instrument useless rather than dishonest."""

    import tests.support.positional_sweep as sweep

    root = tmp_path / "src"
    root.mkdir()
    (root / "fine.py").write_text("x = Anything(1, 2, 3)\n", encoding="utf-8")
    monkeypatch.setattr(sweep, "REPO", tmp_path)
    monkeypatch.setattr(sweep, "ROOTS", ("src",))
    hits = sweep.positional_constructions({"Anything": (6, False)})
    assert hits == {"Anything": ["src/fine.py:1"]}
