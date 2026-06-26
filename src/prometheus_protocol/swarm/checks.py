"""Deterministic falsification predicates for the skeleton.

A ``FalsificationCheck`` names one of these predicates; the runtime evaluates it
against a proposal at verification time. Each predicate returns True when the
proposal *survives* the check and False when the check fails (the proposal is
falsified). Unknown predicates fail closed: a check that cannot be evaluated is
treated as failed, so an unverifiable proposal is never authorized.

These are placeholders for the skeleton. Real falsification — executable checks
over live tool output — is follow-up.
"""

from __future__ import annotations

from typing import Callable

from prometheus_protocol.swarm.models import FalsificationCheck, Proposal


def _non_empty_content(proposal: Proposal) -> bool:
    return bool(proposal.content.strip())


def _states_rationale(proposal: Proposal) -> bool:
    return bool(proposal.rationale.strip())


def _policy_compliant(proposal: Proposal) -> bool:
    return "unsafe" not in proposal.content.lower()


PREDICATES: dict[str, Callable[[Proposal], bool]] = {
    "non_empty_content": _non_empty_content,
    "states_rationale": _states_rationale,
    "policy_compliant": _policy_compliant,
}


def predicate_holds(check: FalsificationCheck, proposal: Proposal) -> bool:
    """Evaluate a check against a proposal. Unknown predicates fail closed."""

    predicate = PREDICATES.get(check.predicate)
    if predicate is None:
        return False
    return bool(predicate(proposal))
