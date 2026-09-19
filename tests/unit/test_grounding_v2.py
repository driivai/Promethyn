"""Unit pins for the grounding-v2 item set: composition and label hygiene."""

from __future__ import annotations

from prometheus_protocol.benchmarks.grounding_eval import (
    SCRIPTED_REPLIES_V2,
)
from prometheus_protocol.benchmarks.grounding_items import (
    GOLD_LABELS,
    GOLD_NOT_SUPPORTED,
    GOLD_SUPPORTED,
    build_grounding_items,
)
from prometheus_protocol.benchmarks.grounding_items_v2 import (
    SUPPORT_CATEGORIES_V2,
    TRAP_CATEGORIES_V2,
    build_grounding_items_v2,
)

#: The subtle families this set exists to test (easy-control excluded).
_SUBTLE = tuple(c for c in TRAP_CATEGORIES_V2 if c != "easy-control")


#: The v2 eval set's composition, observed at base ce16a19 on 2026-09-19.
#: Every one of these replaced a floor; re-pin from the observed set in the
#: change that alters it, so a shrinking eval set is a review and not a shrug.
V2_ITEMS = 64
V2_TRAPS = 45
V2_SUPPORTED = 19
V2_ENTAILED_SUBTLE = 6
V2_TRAP_DISTRIBUTION = {
    "causation-from-correlation": 5,
    "easy-control": 4,
    "hedge-stripping": 2,
    "near-miss-aggregation": 7,
    "partial-support": 6,
    "quantifier-drift": 4,
    "scope-creep": 3,
    "temporal-near-miss": 3,
    "unstated-inference": 7,
    "wrong-attribution": 4,
}


def test_v2_composition_is_as_declared():
    items = build_grounding_items_v2()
    # EXACT. ``>= 60`` against 64 let four items leave the eval set silently,
    # and an eval set that quietly shrinks reports a different number for the
    # same model. Counts rather than membership: the item ids are asserted
    # unique below and each item's content is asserted field-by-field
    # elsewhere, so what a floor uniquely failed to protect is the SIZE.
    assert len(items) == V2_ITEMS
    ids = [i.item_id for i in items]
    claims = [i.claim for i in items]
    assert len(set(ids)) == len(ids)
    assert len(set(claims)) == len(claims)  # claims key the scripted judge
    assert all(i.gold in GOLD_LABELS for i in items)

    traps = [i for i in items if i.gold == GOLD_NOT_SUPPORTED]
    supported = [i for i in items if i.gold == GOLD_SUPPORTED]
    # A large false-PASS denominator is the set's reason to exist...
    assert len(traps) > len(supported)   # RELATIONAL: the declared property
    assert len(traps) == V2_TRAPS
    # ...with supported controls big enough to price in false-FAIL.
    assert len(supported) == V2_SUPPORTED
    assert all(i.category in TRAP_CATEGORIES_V2 for i in traps)
    assert all(i.category in SUPPORT_CATEGORIES_V2 for i in supported)
    # Every subtle family is genuinely represented; the easy anchors exist
    # but are a small minority (the ceiling shapes must not dominate).
    by_cat = {c: sum(1 for i in traps if i.category == c) for c in TRAP_CATEGORIES_V2}
    # EXACT DISTRIBUTION, replacing a per-category floor. ``by_cat[c] >= 2``
    # was a floor on each family: the smallest family sat exactly on it while
    # the largest carried seven, so five of the seven could drain out of
    # ``near-miss-aggregation`` with nothing red and the trap mix the set
    # exists to balance would have silently re-weighted.
    assert by_cat == V2_TRAP_DISTRIBUTION, (by_cat, V2_TRAP_DISTRIBUTION)
    for category in _SUBTLE:                 # kept: the property, now implied
        assert by_cat[category] >= 2, category
    assert by_cat["easy-control"] <= len(traps) // 5   # RELATIONAL: a ceiling
    # Hard supported items exist (entailments that need real reading).
    assert sum(1 for i in supported if i.category == "entailed-subtle") == V2_ENTAILED_SUBTLE


def test_v2_labels_carry_auditable_rationales():
    for item in build_grounding_items_v2():
        # Gold is a curated human reference; every label explains itself.
        assert item.note.strip(), item.item_id
        assert item.source.strip() and item.claim.strip()


def test_v2_is_disjoint_from_v1():
    v1 = build_grounding_items()
    v2 = build_grounding_items_v2()
    assert {i.item_id for i in v1}.isdisjoint({i.item_id for i in v2})
    assert {i.claim for i in v1}.isdisjoint({i.claim for i in v2})
    assert {i.source for i in v1}.isdisjoint({i.source for i in v2})


def test_v2_scripted_replies_cover_the_set_exactly():
    ids = {i.item_id for i in build_grounding_items_v2()}
    assert set(SCRIPTED_REPLIES_V2) == ids
