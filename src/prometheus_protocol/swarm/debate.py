"""Debate layer: select which proposals to verify, and in what order.

Selection only. The debate layer decides where to spend the verification
budget and gathers each selected proposal's checks (its own, plus the skeptic
and policy checks targeting it) into its verification requests. It constructs
no ``Judgment`` and no ``GateDecision``; the ``TestPlan`` it returns carries no
truth or approval field.
"""

from __future__ import annotations

from typing import Sequence

from prometheus_protocol.swarm.models import (
    KIND_CRITIQUE,
    KIND_FORECAST,
    KIND_HYPOTHESIS,
    KIND_OPTION,
    KIND_PROPOSED_ACTION,
    Proposal,
    TestPlan,
    TestPlanEntry,
    VerificationRequest,
)

# Verify the most consequential proposals first; ties break on id for stable,
# deterministic ordering.
_KIND_PRIORITY = {
    KIND_PROPOSED_ACTION: 0,
    KIND_OPTION: 1,
    KIND_HYPOTHESIS: 2,
    KIND_FORECAST: 3,
}


class DebateLayer:
    def select(self, proposals: Sequence[Proposal], budget: int) -> TestPlan:
        primaries = [p for p in proposals if p.kind != KIND_CRITIQUE]
        critiques = [p for p in proposals if p.kind == KIND_CRITIQUE]

        # Map each critique's checks onto the proposal it targets.
        requests_by_target: dict[str, list[VerificationRequest]] = {}
        for critique in critiques:
            for target_id in critique.provenance.inputs:
                for check in critique.falsification_checks:
                    requests_by_target.setdefault(target_id, []).append(
                        VerificationRequest(check=check, requested_by=critique.role_id)
                    )

        ordered = sorted(
            primaries, key=lambda p: (_KIND_PRIORITY.get(p.kind, 99), p.id)
        )
        selected = ordered if (budget is None or budget <= 0) else ordered[:budget]

        entries: list[TestPlanEntry] = []
        for proposal in selected:
            requests = [
                VerificationRequest(check=check, requested_by=proposal.role_id)
                for check in proposal.falsification_checks
            ]
            requests.extend(requests_by_target.get(proposal.id, ()))
            entries.append(
                TestPlanEntry(
                    proposal=proposal, verification_requests=tuple(requests)
                )
            )
        return TestPlan(entries=tuple(entries))
