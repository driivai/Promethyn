"""Conformance: the gold-set-v3 pilot is well-formed and wires into the harness.

These checks do not (and cannot) validate the gold LABELS — those are a human
reference — but they enforce the structural discipline the protocol requires: 20
items, unique ids, valid gold labels, categories drawn only from the declared
taxonomy, every item carrying its rationale, the ~70% gold-negative ratio the
false-PASS denominator needs, and that the items load into the existing grounding
harness (reference-side only). No model, no sandbox.
"""

from __future__ import annotations

from prometheus_protocol.benchmarks.gold_pilot_v3 import (
    GOLD_PILOT_V3_VERSION,
    SUPPORT_CATEGORIES_V3,
    TRAP_CATEGORIES_V3,
    build_gold_pilot_v3,
    gold_split,
)
from prometheus_protocol.benchmarks.grounding_items import (
    GOLD_LABELS,
    GOLD_NOT_SUPPORTED,
    GOLD_SUPPORTED,
)
from prometheus_protocol.core.models import Verdict


def test_twenty_items_unique_ids():
    items = build_gold_pilot_v3()
    assert len(items) == 20
    assert len({i.item_id for i in items}) == 20
    assert "20 items" in GOLD_PILOT_V3_VERSION


def test_gold_labels_and_categories_are_from_the_declared_taxonomy():
    for it in build_gold_pilot_v3():
        assert it.gold in GOLD_LABELS
        if it.gold == GOLD_NOT_SUPPORTED:
            assert it.category in TRAP_CATEGORIES_V3, it.item_id
        else:
            assert it.category in SUPPORT_CATEGORIES_V3, it.item_id


def test_gold_split_is_14_negative_6_positive():
    # the false-PASS denominator is the gold-negative majority (~70%, like v2)
    assert gold_split() == (14, 6)


def test_every_item_carries_source_claim_and_rationale():
    for it in build_gold_pilot_v3():
        assert it.source.strip(), it.item_id
        assert it.claim.strip(), it.item_id
        assert len(it.note.strip()) >= 20, f"{it.item_id} lacks a real gold rationale"


def test_flagship_unstated_inference_traps_are_present():
    cats = [i.category for i in build_gold_pilot_v3() if i.gold == GOLD_NOT_SUPPORTED]
    # the hardest / most important family must be represented, and broadly
    assert cats.count("unstated-inference") >= 2
    assert len(set(cats)) >= 7, "traps should span most of the taxonomy, not cluster"


def test_pilot_wires_into_the_grounding_harness_reference_side():
    """The gold label occupies the reference position; a scripted judge produces
    one row per item. Proves the pilot loads into the existing harness with no
    change to grounding_eval.py."""

    from prometheus_protocol.benchmarks.grounding_eval import run_grounding_eval
    from prometheus_protocol.core.interfaces import Provider
    from prometheus_protocol.verifier.grounding import GroundingVerifier

    class _AbstainProvider(Provider):
        model = "scripted-abstain"

        def propose_solution(self, *, prompt, entry_point, skills=()):  # pragma: no cover
            raise NotImplementedError

        def assess(self, *, prompt, system=None):
            return "ABSTAIN"

    items = build_gold_pilot_v3()
    rows = run_grounding_eval(items, judge=GroundingVerifier(_AbstainProvider()))
    assert len(rows) == 20
    # gold sits in the reference slot: 14 FAIL (not-supported), 6 PASS (supported)
    refs = [r.reference for r in rows]
    assert refs.count(Verdict.FAIL) == 14 and refs.count(Verdict.PASS) == 6
