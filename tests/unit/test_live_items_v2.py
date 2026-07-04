"""live-v2 stays valid: authoritative ground truth and pinned composition.

The live-v2 set exists to discriminate between judges, and it is only a valid
measurement instrument while every item has authoritative, sandbox-decided
ground truth. These tests re-derive that in CI (which runs with the isolation
runtime present): all items PASS or FAIL — never abstain — and the composition
the report documents (31 PASS / 51 FAIL over 82 items) is pinned so a future
edit that silently shifts the set's balance or breaks an item is caught here,
not discovered mid-measurement.
"""

from __future__ import annotations

from prometheus_protocol.benchmarks.judge_eval import _MARKER
from prometheus_protocol.benchmarks.live_items import FIXTURE_ACTOR
from prometheus_protocol.benchmarks.live_items_v2 import (
    LIVE_ITEM_SET_VERSION,
    build_live_eval_items,
)
from prometheus_protocol.core.models import Verdict
from prometheus_protocol.verifier.runner import SubprocessVerifier


def test_structure_ids_markers_and_attribution():
    items = build_live_eval_items()
    assert len(items) == 82
    assert "live-v2" in LIVE_ITEM_SET_VERSION and "82" in LIVE_ITEM_SET_VERSION
    ids = [item.item_id for item in items]
    assert len(set(ids)) == len(ids)  # unique ids: the scripted-reply keying rule
    for item in items:
        # The marker is the first line, and nothing else about the item rides
        # in the code the judge sees.
        assert item.code.startswith(f"{_MARKER}{item.item_id}\n")
        assert item.actor_model == FIXTURE_ACTOR  # no fabricated live attribution


def test_every_item_is_authoritative_with_the_pinned_composition():
    reference = SubprocessVerifier(memory_mb=0)
    undecided = []
    verdicts = {Verdict.PASS: 0, Verdict.FAIL: 0}
    for item in build_live_eval_items():
        verdict = reference.verify(code=item.code, task=item.task).verdict
        if verdict in verdicts:
            verdicts[verdict] += 1
        else:
            undecided.append(item.item_id)
    assert not undecided, f"items without authoritative ground truth: {undecided}"
    # The composition the report documents; an item edit that flips a verdict
    # (or a case that stops catching its bug) must fail loudly here.
    assert verdicts[Verdict.PASS] == 31
    assert verdicts[Verdict.FAIL] == 51
