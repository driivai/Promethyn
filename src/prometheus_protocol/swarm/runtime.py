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
    Unavailability,
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
from prometheus_protocol.policy.coverage import BoundResult
from prometheus_protocol.policy.profile import (
    CHECK_EXECUTABLE_CASES,
    CHECK_STRUCTURAL,
    DEFAULT_PROFILE_ID,
    PolicyError,
    VerificationPolicy,
    load_profile,
)
from prometheus_protocol.policy.resolver import resolve
from prometheus_protocol.policy.snapshot import (
    ACTION_SANDBOX_EXECUTE as _ACTION_SANDBOX_EXECUTE,
    BoundRequirements,
    snapshot_digest,
)
from prometheus_protocol.swarm.synthesis import RoleSynthesisEngine, SwarmConfig
from prometheus_protocol.verifier.bank import VerifierBank

#: The action class every swarm proposal falls under: candidate code runs in the
#: isolated executor, with no privileged target.
#: PHASE-1.2b — re-exported from the policy package, where the closed set and
#: the named classes live together. Kept as a module name here because callers
#: and tests import it from the swarm.
ACTION_SANDBOX_EXECUTE = _ACTION_SANDBOX_EXECUTE

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
        policy: VerificationPolicy | None = None,
        target_canonical: str = "sandbox://swarm",
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
        # verification. When absent, executable checks ABSTAIN — no veto, no
        # spurious pass.
        #
        # This comment used to end "and only structural checks apply". That
        # described the tree before Checkpoint 2 and is now wrong in two ways.
        # First, under the shipped baseline an abstaining REQUIRED check refuses
        # coverage (`coverage.abstained`) rather than falling back to whatever
        # else ran: measured, structural PASS + executable ABSTAIN yields
        # CoverageRefused on `executable.cases`, so verification cannot proceed
        # and the action is never authorized. Second, the baseline's only
        # requirement for `sandbox.execute` IS `executable.cases` — there are no
        # structural requirements for it to fall back TO. Absent a code_verifier
        # the honest description is that this runtime cannot authorize a sandbox
        # execution at all, which is the fail-closed direction.
        self.code_verifier = code_verifier
        self.verifier_id = verifier_id
        self.tier = tier
        # R1 — a policy VALUE, never a module-level constant reached for at the
        # point of use. ``load_profile`` is one supplier of that value; a
        # customer-supplied digest-pinned supplier is a later addition beside it
        # rather than a rewrite of this class.
        self.policy = policy if policy is not None else load_profile(DEFAULT_PROFILE_ID)
        #: The principal this runtime acts against. The swarm executes inside the
        #: sandbox and touches no privileged target, so the canonical form names
        #: the sandbox rather than pretending to a principal it does not have.
        self.target_canonical = target_canonical
        #: Set per entry by ``run`` before ``_verify`` binds anything to it.
        self._snapshot: BoundRequirements | None = None
        # Register the check runner so its hard-tier prior applies.
        self.bank.register(verifier_id, tier)
        if code_verifier is not None:
            # Read straight off the port: ``Verifier`` declares both, so a
            # getattr default here would stand in for an attribute the protocol
            # guarantees — and the type gate refuses a default for exactly that
            # reason.
            self.bank.register(code_verifier.verifier_id, code_verifier.tier)

    def run(self, packet: TaskPacket, config: SwarmConfig | None = None) -> SwarmRun:
        swarm = self.synthesis.assemble(packet, config)
        proposals = swarm.propose(packet)
        plan = self.debate.select(proposals, packet.budget)

        packet_id = content_hash(packet.goal)[:12]
        records: list[ChainRecord] = []
        for entry in plan.entries:
            # PHASE-1.2a — the requirements come from the POLICY and this
            # action, resolved BEFORE anything runs. Resolving first is what
            # makes omission powerless: the requirement set cannot depend on
            # what the plan turned out to contain.
            # ONLY AN ACTION IS AUTHORIZED, so only an action is enforced.
            # A hypothesis or a critique is judged and recorded; it never
            # reaches the gate or the executor, so there is no authorization for
            # a policy to gate. Enforcing an action policy on it would demand
            # executable verification of something that executes nothing —
            # requirements for a consequence that cannot occur.
            if entry.proposal.kind != KIND_PROPOSED_ACTION:
                evidence, _ = self._verify_unenforced(entry)
                judgment = self.bank.judge([evidence])
                verified = None
                if isinstance(judgment, Judgment):
                    verified = VerifiedProposal.from_judgment(entry.proposal, judgment)
                self._record(packet_id, entry, evidence, judgment, None, None)
                records.append(
                    ChainRecord(
                        proposal=entry.proposal,
                        verification_requests=entry.verification_requests,
                        evidence=evidence,
                        verified=verified,
                        decision=None,
                        execution=None,
                    )
                )
                continue

            attempt_id = f"{packet_id}/{entry.proposal.id}"
            try:
                self._snapshot = resolve(
                    self.policy,
                    artifact_sha256=content_hash(entry.proposal.content),
                    target_canonical=self.target_canonical,
                    action_class=ACTION_SANDBOX_EXECUTE,
                    attempt_id=attempt_id,
                )
            except PolicyError as exc:
                # No policy for this action means it cannot be authorized —
                # silence is not permission. Recorded, nothing executed.
                self._snapshot = None
                unresolved = Unavailable(
                    verifier_id="policy-resolver",
                    tier=self.tier,
                    reason=Unavailability.POLICY_REFUSAL,
                    detail=f"verification cannot proceed: {exc}",
                )
                self._record(packet_id, entry, unresolved, unresolved, None, None)
                records.append(
                    ChainRecord(
                        proposal=entry.proposal,
                        verification_requests=entry.verification_requests,
                        evidence=unresolved,
                        verified=None,
                        decision=None,
                        execution=None,
                    )
                )
                continue

            evidence, results = self._verify(entry)
            # PHASE-1.2b — ``assess`` runs the same coverage validation and
            # binds the outcome to the snapshot. The gate takes the assessment;
            # there is no longer a parameter it would accept a bare verdict
            # through, so the swarm cannot reach authorization unbound even by
            # mistake.
            assessment = self.bank.assess(self._snapshot, results)
            judgment = assessment.outcome

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
                    assessment,
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

    def _verify(self, entry: TestPlanEntry) -> tuple[Evidence | Unavailable, list[BoundResult]]:
        """Run the checks and report them SEPARATELY, bound to the snapshot.

        PHASE-1.2a — THE SWARM NO LONGER COMPUTES AN AGGREGATE.

        What this used to do was the reproduced fail-open: it folded structural
        predicates and executable cases into ONE Evidence by counting "checks
        that could run", so a plan whose executable cases never ran was judged on
        predicates alone and a passing predicate became a synthetic HARD PASS.
        The three ways ``_run_executable_checks`` returns ``None`` — no code
        verifier wired, no entry point or cases, an exception swallowed — were
        all indistinguishable from "there was nothing executable to do".

        Now each check kind is reported under its own CHECK IDENTITY, bound to
        the resolved snapshot, and the bank decides coverage. A missing
        executable result is missing: the policy requires ``executable.cases``
        for this action class, and nothing here can shrink that requirement,
        because the requirement never came from the plan.

        The first element of the returned pair is the structural summary kept
        for the CHAIN RECORD — it is what the ledger has always recorded and
        callers still read. It is NOT what authorizes anything.
        """

        requests = entry.verification_requests
        results: list[BoundResult] = []
        if not requests:
            # Nothing requested. This is NOT "nothing required": the policy's
            # requirements exist regardless, so this returns no results and the
            # bank refuses for want of coverage.
            return self._abstain("no verification requested"), results

        executable = [r.check for r in requests if r.check.cases]
        structural = [r for r in requests if not r.check.cases]

        failures: list[str] = []
        for request in structural:
            if not predicate_holds(request.check, entry.proposal):
                failures.append(f"{request.check.id}: {request.check.description}")

        structural_evidence: Evidence | None = None
        if structural:
            verdict = Verdict.PASS if not failures else Verdict.FAIL
            structural_evidence = Evidence(
                passed=(verdict == Verdict.PASS),
                total=len(structural),
                passed_count=len(structural) - len(failures),
                failures=tuple(failures),
                verifier_id=self.verifier_id,
                verdict=verdict,
                tier=self.tier,
                detail="; ".join(failures),
            )
            if self._snapshot is not None:
                results.append(
                    self._bind(
                        self._snapshot,
                        CHECK_STRUCTURAL,
                        self.verifier_id,
                        structural_evidence,
                    )
                )

        reported_unavailable: Unavailable | None = None
        if executable:
            outcome = self._run_executable_checks(entry.proposal, executable)
            if isinstance(outcome, Unavailable):
                # Kept as the CHAIN's reported outcome. Authorization is decided
                # by coverage below, but the record's job is to say what the
                # checks produced, and "the HARD verifier could not run" is the
                # most informative thing that happened.
                reported_unavailable = outcome
            if outcome is not None and self._snapshot is not None and self.code_verifier is not None:
                # Reported under the CODE VERIFIER's own id, not the swarm's: the
                # policy names which implementations may answer ``executable.cases``,
                # and the swarm is not one of them. Claiming otherwise would be the
                # mislabelling the binding check refuses.
                results.append(
                    self._bind(
                        self._snapshot,
                        CHECK_EXECUTABLE_CASES,
                        self.code_verifier.verifier_id,
                        outcome,
                    )
                )
            # ``None`` deliberately produces NO result. A swallowed exception, an
            # unwired verifier and an empty entry point are the same thing from
            # here — the required check has no answer — and the bank refuses on
            # that row rather than this method guessing which it was.

        if reported_unavailable is not None:
            return reported_unavailable, results
        if structural_evidence is not None:
            return structural_evidence, results
        return self._abstain("no structural check ran"), results

    def _verify_unenforced(
        self, entry: TestPlanEntry
    ) -> tuple[Evidence | Unavailable, list[BoundResult]]:
        """``_verify`` for a proposal that authorizes nothing.

        Same checks, no snapshot, no bound results — there is no action to bind
        them to. Kept as a separate entry point rather than a flag so that a
        caller cannot reach the unenforced path for something that IS an action.
        """

        previous, self._snapshot = self._snapshot, None
        try:
            return self._verify(entry)
        finally:
            self._snapshot = previous

    def _bind(
        self,
        snapshot: BoundRequirements,
        check_id: str,
        implementation: str,
        outcome: Evidence | Unavailable,
    ) -> BoundResult:
        return BoundResult(
            check_id=check_id,
            snapshot_digest=snapshot_digest(snapshot),
            implementation=implementation,
            outcome=outcome,
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
