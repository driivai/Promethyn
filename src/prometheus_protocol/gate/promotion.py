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

from prometheus_protocol.core.interfaces import Gate, LearnableTask
from prometheus_protocol.core.models import ExecutableAction, Judgment, Skill
from prometheus_protocol.policy.execution import AuthorizedExecution

# The three action-authorization outcomes. ``approve`` executes; ``route`` holds
# the action for a human (a pending action); ``block`` denies it terminally.
# ``approved`` stays the single load-bearing field the executor checks — only an
# ``approve`` outcome sets it True — so the wall is unchanged.
OUTCOME_APPROVE = "approve"
OUTCOME_ROUTE = "route"
OUTCOME_BLOCK = "block"

# Not a gate outcome: the gate never returns this and no GateDecision ever
# carries it. It is the CALLER-side marker for "the verifier could not run, so
# no judgment existed and the action was never submitted for authorization at
# all". Recorded distinctly so a loop that never asked the question is not
# reported as a loop that asked and was denied — the same could-not-run /
# was-denied distinction Unavailable draws one layer down.
OUTCOME_UNAVAILABLE = "unavailable"


class FirewallError(AssertionError):
    """Raised when the train and held-out task-id sets intersect."""


def assert_disjoint(train_ids: Sequence[str], heldout_ids: Sequence[str]) -> None:
    """Assert the held-out firewall holds. Raise ``FirewallError`` if not."""

    overlap = set(train_ids) & set(heldout_ids)
    if overlap:
        raise FirewallError(
            "held-out firewall breach: the following task ids appear in both "
            f"the train and held-out splits: {', '.join(sorted(overlap))}"
        )


@dataclass(frozen=True)
class GateDecision:
    """A gate's decision — the only object that authorizes action or promotion.

    ``approved`` is the single load-bearing field (the executor and the runtime
    check it). The promotion path also records the held-out rates and keeps the
    historical ``promoted``/``skill_id`` aliases; the action-authorization path
    records the subject it authorizes and the judgment it rests on.
    """

    approved: bool
    subject_id: str = ""
    rate_before: float | None = None
    rate_after: float | None = None
    judgment: Judgment | None = None
    reason: str = ""
    # Action-authorization extensions (additive; the promotion path leaves them
    # unset). ``outcome`` distinguishes route from block for a non-approved
    # action; ``action`` is the payload an approved decision authorizes for
    # sandboxed execution. Both default to the legacy shape.
    outcome: str = ""
    action: ExecutableAction | None = None
    # Present on action decisions only.  The executor and human-hold path require
    # this seam-minted proof; promotion decisions deliberately leave it unset.
    authorization: AuthorizedExecution[ExecutableAction] | None = None

    @property
    def promoted(self) -> bool:
        """Backward-compatible alias used by the promotion path."""
        return self.approved

    @property
    def skill_id(self) -> str:
        """Backward-compatible alias used by the promotion path."""
        return self.subject_id

    @property
    def effective_outcome(self) -> str:
        """The action-authorization outcome, derived when not set explicitly.

        A decision built without an explicit outcome (the promotion path, or a
        legacy caller) reads as ``approve`` when approved and ``block``
        otherwise, so ``approved`` remains the single source of truth.
        """

        if self.outcome:
            return self.outcome
        return OUTCOME_APPROVE if self.approved else OUTCOME_BLOCK


# A scorer runs the held-out tasks with a candidate skill in context and
# returns the resulting pass rate. The gate stays decoupled from the provider
# and verifier behind this callable. It scores whatever the loop can run —
# ``LearnableTask``, the shared loop port — not the code domain's concrete
# ``Task``: the SQL and grounding domains have their own task types and the
# gate reads nothing beyond the port.
ScoreFn = Callable[[Sequence[LearnableTask], Skill], float]


class PromotionGate(Gate):
    """Promotes a candidate only if it strictly improves the held-out rate."""

    def __init__(self, *, threshold: float = 0.0) -> None:
        self.threshold = threshold

    def evaluate(
        self,
        *,
        candidate: Skill,
        train_ids: Sequence[str],
        # Only ``task.id`` is read here and the list is forwarded to the
        # caller's score_fn, so the shared loop port is exactly what this needs.
        heldout_tasks: Sequence[LearnableTask],
        score_fn: ScoreFn,
        rate_before: float,
    ) -> GateDecision:
        heldout_ids = [task.id for task in heldout_tasks]
        # The firewall check happens before a single held-out task is scored.
        assert_disjoint(train_ids, heldout_ids)
        rate_after = score_fn(list(heldout_tasks), candidate)
        promoted = (rate_after - rate_before) > self.threshold
        return GateDecision(
            approved=promoted,
            subject_id=candidate.id,
            rate_before=rate_before,
            rate_after=rate_after,
        )
