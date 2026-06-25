"""Promotion gate and the held-out firewall.

This is the load-bearing safety module. The firewall invariant is simple to
state and must be true at runtime, not merely in documentation:

    The set of task ids the forge learned from (the *train* split) and the
    set of task ids the gate scores a candidate against (the *held-out*
    split) MUST be disjoint.

If those sets ever intersect, a skill could be promoted because it overfits
the very tasks it was mined from, and the held-out pass rate would no longer
be evidence of generalisation. ``assert_disjoint`` enforces the invariant and
is called on every evaluation; a breach raises ``FirewallError`` and aborts
the cycle rather than silently promoting.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

from prometheus_protocol.core.interfaces import Gate
from prometheus_protocol.core.models import Skill, Task


class FirewallError(AssertionError):
    """Raised when the train and held-out task-id sets intersect."""


def assert_disjoint(
    train_ids: Sequence[str], heldout_ids: Sequence[str]
) -> None:
    """Assert the held-out firewall holds. Raise ``FirewallError`` if not."""

    overlap = set(train_ids) & set(heldout_ids)
    if overlap:
        raise FirewallError(
            "held-out firewall breach: the following task ids appear in both "
            f"the train and held-out splits: {', '.join(sorted(overlap))}"
        )


@dataclass(frozen=True)
class GateDecision:
    """The outcome of scoring one candidate skill."""

    skill_id: str
    promoted: bool
    rate_before: float
    rate_after: float


# A scorer runs the held-out tasks with a candidate skill in context and
# returns the resulting pass rate. The gate stays decoupled from the provider
# and verifier behind this callable.
ScoreFn = Callable[[Sequence[Task], Skill], float]


class PromotionGate(Gate):
    """Promotes a candidate only if it strictly improves the held-out rate."""

    def __init__(self, *, threshold: float = 0.0) -> None:
        self.threshold = threshold

    def evaluate(
        self,
        *,
        candidate: Skill,
        train_ids: Sequence[str],
        heldout_tasks: Sequence[Task],
        score_fn: ScoreFn,
        rate_before: float,
    ) -> GateDecision:
        heldout_ids = [task.id for task in heldout_tasks]
        # The firewall check happens before a single held-out task is scored.
        assert_disjoint(train_ids, heldout_ids)
        rate_after = score_fn(list(heldout_tasks), candidate)
        promoted = (rate_after - rate_before) > self.threshold
        return GateDecision(
            skill_id=candidate.id,
            promoted=promoted,
            rate_before=rate_before,
            rate_after=rate_after,
        )
