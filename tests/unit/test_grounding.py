"""Unit pins for the grounding verifier's parsers and the gold item set."""

from __future__ import annotations

from prometheus_protocol.benchmarks.grounding_eval import SCRIPTED_REPLIES
from prometheus_protocol.benchmarks.grounding_items import (
    GOLD_LABELS,
    GOLD_NOT_SUPPORTED,
    GOLD_SUPPORTED,
    SUPPORT_CATEGORIES,
    TRAP_CATEGORIES,
    build_grounding_items,
)
from prometheus_protocol.core.models import Verdict
from prometheus_protocol.verifier.grounding import (
    parse_grounding_confidence,
    parse_grounding_verdict,
)


def test_verdict_parser_is_strict():
    assert parse_grounding_verdict("SUPPORTED 0.9") == Verdict.PASS
    assert parse_grounding_verdict("supported") == Verdict.PASS
    assert parse_grounding_verdict("NOT-SUPPORTED 0.8") == Verdict.FAIL
    assert parse_grounding_verdict("Not-Supported.") == Verdict.FAIL
    assert parse_grounding_verdict("ABSTAIN") == Verdict.ABSTAIN
    assert parse_grounding_verdict("  \n SUPPORTED 0.7") == Verdict.PASS
    # Anything else is an abstention — a verdict is never guessed.
    for reply in ("", "NOT", "NOT SUPPORTED 0.8", "unsupported", "TRUE",
                  "The claim is supported by the source."):
        assert parse_grounding_verdict(reply) == Verdict.ABSTAIN, reply


def test_confidence_parser_never_invents_a_number():
    assert parse_grounding_confidence("SUPPORTED 0.85") == 0.85
    assert parse_grounding_confidence("NOT-SUPPORTED 0.7") == 0.7
    assert parse_grounding_confidence("SUPPORTED 1") == 1.0
    assert parse_grounding_confidence("ABSTAIN 0.5") == 0.5
    for unstated in ("SUPPORTED", "SUPPORTED 1.5", "SUPPORTED -0.5",
                     "SUPPORTED 0,9", "SUPPORTED 0.5e-1", "", "0.9"):
        assert parse_grounding_confidence(unstated) is None, unstated


def test_item_set_is_well_formed():
    items = build_grounding_items()
    assert len(items) >= 40
    ids = [i.item_id for i in items]
    claims = [i.claim for i in items]
    assert len(set(ids)) == len(ids)
    assert len(set(claims)) == len(claims)  # claims key the scripted judge
    assert all(i.gold in GOLD_LABELS for i in items)
    supported = [i for i in items if i.gold == GOLD_SUPPORTED]
    traps = [i for i in items if i.gold == GOLD_NOT_SUPPORTED]
    assert len(supported) == 18 and len(traps) == 26
    assert all(i.category in SUPPORT_CATEGORIES for i in supported)
    assert all(i.category in TRAP_CATEGORIES for i in traps)
    # Every trap family in the taxonomy is actually represented.
    assert {i.category for i in traps} == set(TRAP_CATEGORIES)
    assert all(i.source.strip() and i.claim.strip() for i in items)


def test_scripted_replies_cover_the_item_set_exactly():
    ids = {i.item_id for i in build_grounding_items()}
    assert set(SCRIPTED_REPLIES) == ids
