"""Swarm runtime: wire proposer side -> judge side -> gate -> executor -> ledger.

This is the only place the crossing happens. Proposals are verified into
``Evidence``, the bank turns evidence into a ``Judgment`` (truth), the gate turns
a judgment into a ``GateDecision`` (authorization), and only an approved
decision reaches the executor. Every step is recorded.
"""

from __future__ import annotations

from dataclasses import dataclass

from prometheus_protocol.core.interfaces import Ledger, Provider, Verifier
from prometheus_protocol.core.models import (
    Attempt,
    Evidence,
    Judgment,
    Task,
    Tier,
    Unavailable,
    Verdict,
    assert_never,
)
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.memory.tiers import MemoryTier
from prometheus_protocol.swarm.checks import predicate_holds
from prometheus_protocol.swarm.debate import DebateLayer
from prometheus_protocol.swarm.executor import Executor
from prometheus_protocol.swarm.models import (
    KIND_PROPOSED_ACTION,
    ExecutionResult,
    Proposal,
    TaskPacket,
    TestPlan,
    TestPlanEntry,
    VerificationRequest,
    VerifiedProposal,
    content_hash,
)
from prometheus_protocol.swarm.synthesis import RoleSynthesisEngine, SwarmConfig
from prometheus_protocol.verifier.bank import VerifierBank

# The deterministic check runner reports under this stable id, at the hard tier
# (surviving concrete falsification checks is an authoritative basis to act, for
# this skeleton; live-tool evidence is follow-up).
CHECK_VERIFIER_ID = "swarm-checks"


@dataclass(frozen=True)
class ChainRecord:
    """The full judged chain for one proposal."""

    proposal: Proposal
    verification_requests: tuple[VerificationRequest, ...]
    #: What the swarm's check verifier produced. ``Unavailable`` when the checks
    #: could not run at all — previously unrepresentable here, which is why the
    #: consumer crashed instead of recording it.
    evidence: Evidence | Unavailable
    #: The proposal joined to the bank's judgment, or ``None`` when the bank
    #: returned ``Unavailable`` and there is no judgment to join it to. A
    #: VerifiedProposal is the first truth-bearing object on this path; building
    #: one without a judgment would be inventing the truth it exists to carry.
    verified: VerifiedProposal | None
    decision: object | None  # GateDecision when the proposal is an action
    execution: ExecutionResult | None


@dataclass(frozen=True)
class SwarmRun:
    packet: TaskPacket
    plan: TestPlan
    records: tuple[ChainRecord, ...]


class SwarmRuntime:
    def __init__(
        self,
        *,
        synthesis: RoleSynthesisEngine,
        debate: DebateLayer,
        bank: VerifierBank,
        gate: ActionGate,
        executor: Executor,
        ledger: Ledger,
        provider: Provider | None = None,
        memory: MemoryTier | None = None,
        code_verifier: Verifier | None = None,
        verifier_id: str = CHECK_VERIFIER_ID,
        tier: Tier = Tier.HARD,
    ) -> None:
        self.synthesis = synthesis
        self.debate = debate
        self.bank = bank
        self.gate = gate
        self.executor = executor
        self.ledger = ledger
        self.provider = provider
        self.memory = memory
        # Runs the Skeptic's executable falsification cases as real HARD
        # verification. When absent, executable checks ABSTAIN (no veto, no
        # spurious pass) and only structural checks apply.
        self.code_verifier = code_verifier
        self.verifier_id = verifier_id
        self.tier = tier
        # Register the check runner so its hard-tier prior applies.
        self.bank.register(verifier_id, tier)

    def run(self, packet: TaskPacket, config: SwarmConfig | None = None) -> SwarmRun:
        swarm = self.synthesis.assemble(packet, config)
        proposals = swarm.propose(packet)
        plan = self.debate.select(proposals, packet.budget)

        packet_id = content_hash(packet.goal)[:12]
        records: list[ChainRecord] = []
        for entry in plan.entries:
            evidence = self._verify(entry)
            judgment = self.bank.judge([evidence])

            decision = None
            execution = None
            verified = None
            if isinstance(judgment, Unavailable):
                # The bank could not reach a judgment. FAIL CLOSED: no
                # VerifiedProposal is built (there is no judgment to carry), the
                # gate is not consulted, and nothing executes. Routing an
                # unavailability to a human is the right answer and is Phase 1.2
                # (the trusted verification-policy work); this sprint will not
                # guess that policy, so the proposal simply does not proceed and
                # the chain records why.
                self._record(packet_id, entry, evidence, judgment, None, None)
                records.append(
                    ChainRecord(
                        proposal=entry.proposal,
                        verification_requests=entry.verification_requests,
                        evidence=evidence,
                        verified=None,
                        decision=None,
                        execution=None,
                    )
                )
                continue
            if isinstance(judgment, Judgment):
                verified = VerifiedProposal.from_judgment(entry.proposal, judgment)
            else:
                assert_never(judgment)

            # Only actions are routed to the gate and the executor.
            if entry.proposal.kind == KIND_PROPOSED_ACTION:
                decision = self.gate.decide(
                    judgment,
                    risk_class=packet.risk_class,
                    subject_id=entry.proposal.id,
                )
                if decision.approved:
                    execution = self.executor.execute(decision)

            self._record(packet_id, entry, evidence, judgment, decision, execution)
            records.append(
                ChainRecord(
                    proposal=entry.proposal,
                    verification_requests=entry.verification_requests,
                    evidence=evidence,
                    verified=verified,
                    decision=decision,
                    execution=execution,
                )
            )
        return SwarmRun(packet=packet, plan=plan, records=tuple(records))

    def _verify(self, entry: TestPlanEntry) -> Evidence | Unavailable:
        requests = entry.verification_requests
        if not requests:
            # Nothing to verify -> no opinion. An unverified proposal can never
            # be authorized.
            return self._abstain("no verification requested")

        # Two check kinds: structural predicates (evaluated in-process) and
        # executable cases (run by the HARD code verifier). Aggregation is a
        # conjunction: the proposal passes only if every check that *could run*
        # passed, so any failing check is a hard veto; if nothing could run the
        # result ABSTAINs (never a silent pass).
        executable = [r.check for r in requests if r.check.cases]
        structural = [r for r in requests if not r.check.cases]

        ran = 0
        failures: list[str] = []

        for request in structural:
            ran += 1
            if not predicate_holds(request.check, entry.proposal):
                failures.append(f"{request.check.id}: {request.check.description}")

        if executable:
            evidence = self._run_executable_checks(entry.proposal, executable)
            if isinstance(evidence, Unavailable):
                # The HARD code verifier could not run the executable cases.
                # FAIL CLOSED: propagate the unavailability rather than letting
                # the structural checks alone decide. Counting it as "did not
                # run" would let a proposal whose executable cases never
                # executed be judged on predicates alone, and the aggregation
                # policy for a partially-unavailable check set is Phase 1.2 —
                # not something to guess here.
                return evidence
            if evidence is not None and evidence.decided != Verdict.ABSTAIN:
                ran += 1
                if evidence.decided != Verdict.PASS:
                    failures.append(f"executable: {evidence.detail or 'cases failed'}")

        if ran == 0:
            return self._abstain("no runnable check (executable checks abstained)")

        verdict = Verdict.PASS if not failures else Verdict.FAIL
        return Evidence(
            passed=(verdict == Verdict.PASS),
            total=ran,
            passed_count=ran - len(failures),
            failures=tuple(failures),
            verifier_id=self.verifier_id,
            verdict=verdict,
            tier=self.tier,
            detail="; ".join(failures),
        )

    def _abstain(self, detail: str) -> Evidence:
        return Evidence(
            passed=False,
            total=0,
            passed_count=0,
            failures=(detail,),
            verifier_id=self.verifier_id,
            verdict=Verdict.ABSTAIN,
            tier=self.tier,
            detail=detail,
        )

    def _run_executable_checks(
        self, proposal, checks
    ) -> Evidence | Unavailable | None:
        """Run pooled executable cases through the HARD code verifier.

        Returns the verifier's Evidence (PASS/FAIL/ABSTAIN); ``Unavailable``
        when the HARD verifier could not run the cases at all; or ``None`` when
        no code verifier is wired or there is nothing runnable — the last two
        are different things and the annotation used to say ``Evidence | None``,
        which was the type-level face of the caller reading ``.verdict`` off an
        object that has none.
        """

        if self.code_verifier is None:
            return None
        entry_point = next((c.entry_point for c in checks if c.entry_point), "")
        cases = tuple(case for check in checks for case in check.cases)
        if not entry_point or not cases:
            return None
        task = Task(
            id=f"swarm/{proposal.id}",
            entry_point=entry_point,
            prompt="",
            split="train",
            cases=cases,
        )
        try:
            return self.code_verifier.verify(code=proposal.content, task=task)
        except Exception:
            return None

    def _record(
        self,
        packet_id: str,
        entry: TestPlanEntry,
        evidence: Evidence | Unavailable,
        judgment: Judgment | Unavailable | None,
        decision,
        execution: ExecutionResult | None,
    ) -> None:
        if decision is None:
            outcome = "judged"
        elif execution is not None:
            outcome = "executed"
        elif decision.approved:
            outcome = "approved"
        else:
            outcome = "rejected"
        # A judgment the bank could not reach is NOT a judgment: the attempt
        # records none. Why it could not is not lost — the evidence field
        # carries the Unavailable and the ledger's `unavailable` discriminator
        # marks the row — so this narrows rather than inventing a placeholder.
        if judgment is None or isinstance(judgment, Unavailable):
            judged: Judgment | None = None
        elif isinstance(judgment, Judgment):
            judged = judgment
        else:
            assert_never(judgment)
        attempt = Attempt(
            task_id=packet_id,
            split="swarm",
            entry_point=entry.proposal.id,
            code=entry.proposal.content,
            evidence=evidence,
            skills_used=(),
            judgment=judged,
        )
        self.ledger.record_attempt(attempt, cycle=0, kind=f"swarm:{outcome}")
        if self.memory is not None:
            self.memory.set(f"swarm:{packet_id}", entry.proposal.id, outcome)
