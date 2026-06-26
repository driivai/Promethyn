"""Swarm domain objects: the typed proposal / test-plan contract.

The wall is enforced here by construction. A ``Proposal`` and a ``TestPlan``
carry no verdict, confidence-of-correctness, or approval; they are pure
proposer-side artifacts. The first truth-bearing object is a ``Judgment``
(produced only by the verifier bank), and the first action-authorizing object
is a ``GateDecision`` (produced only by the gate) — both reused from their
existing modules, never redefined here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from prometheus_protocol.core.models import Judgment

# Allowed proposal kinds. Only ``proposed_action`` is ever routed to the gate
# and the executor; the rest are reasoning artifacts that are judged but never
# executed.
KIND_HYPOTHESIS = "hypothesis"
KIND_OPTION = "option"
KIND_FORECAST = "forecast"
KIND_CRITIQUE = "critique"
KIND_PROPOSED_ACTION = "proposed_action"
PROPOSAL_KINDS = frozenset(
    {
        KIND_HYPOTHESIS,
        KIND_OPTION,
        KIND_FORECAST,
        KIND_CRITIQUE,
        KIND_PROPOSED_ACTION,
    }
)

RISK_CLASSES = ("low", "medium", "high")


def content_hash(text: str) -> str:
    """Deterministic content hash used for provenance."""

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TaskPacket:
    """The task handed to the swarm. The only input roles ever receive."""

    goal: str
    context: str = ""
    constraints: tuple[str, ...] = ()
    budget: int = 0
    risk_class: str = "low"

    def __post_init__(self) -> None:
        if self.risk_class not in RISK_CLASSES:
            raise ValueError(
                f"unknown risk_class {self.risk_class!r}; expected {RISK_CLASSES}"
            )


@dataclass(frozen=True)
class Provenance:
    """Where a proposal came from: a content hash and the ids it derives from."""

    content_hash: str
    inputs: tuple[str, ...] = ()


@dataclass(frozen=True)
class FalsificationCheck:
    """A concrete check that, if it fails, proves a proposal wrong.

    ``predicate`` names a deterministic predicate evaluated at verification time
    by the runtime. The check itself carries no verdict.
    """

    id: str
    description: str
    predicate: str


@dataclass(frozen=True)
class Proposal:
    """A proposer-side artifact. Carries no verdict, confidence, or approval."""

    id: str
    role_id: str
    kind: str
    content: str
    rationale: str
    provenance: Provenance
    falsification_checks: tuple[FalsificationCheck, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in PROPOSAL_KINDS:
            raise ValueError(
                f"unknown proposal kind {self.kind!r}; expected one of "
                f"{sorted(PROPOSAL_KINDS)}"
            )


@dataclass(frozen=True)
class VerificationRequest:
    """A request to run one check for a proposal, and who asked for it."""

    check: FalsificationCheck
    requested_by: str


@dataclass(frozen=True)
class TestPlanEntry:
    # Not a pytest test class despite the name; opt out of test collection.
    __test__ = False

    proposal: Proposal
    verification_requests: tuple[VerificationRequest, ...]


@dataclass(frozen=True)
class TestPlan:
    """Ordered selection of proposals to verify.

    Deliberately has no verdict/confidence/approval field: a test plan selects
    work for the judge side, it does not certify anything.
    """

    # Not a pytest test class despite the name; opt out of test collection.
    __test__ = False

    entries: tuple[TestPlanEntry, ...]


@dataclass(frozen=True)
class VerifiedProposal:
    """A proposal joined to the judgment the bank reached for it.

    Construct this ONLY on the bank path (the runtime, immediately after
    ``VerifierBank.judge``). It is the proposer-side artifact crossing into the
    judged world; the ``Judgment`` is the first truth-bearing object.
    """

    proposal: Proposal
    judgment: Judgment

    @classmethod
    def from_judgment(cls, proposal: Proposal, judgment: Judgment) -> "VerifiedProposal":
        return cls(proposal=proposal, judgment=judgment)


@dataclass(frozen=True)
class ExecutionResult:
    """The executor's record of acting on an approved decision."""

    executed: bool
    subject_id: str
    detail: str = ""
