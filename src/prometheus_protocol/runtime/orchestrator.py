"""Orchestration: the baseline run and one learning cycle.

The orchestrator wires the services together but holds no policy of its own
beyond sequencing. Every decision that matters — what passes (verifier), what
gets learned (forge), what gets kept (gate + firewall) — lives in the service
it belongs to.

One learning cycle is:

  1. Measure the held-out pass rate with the registry as it stands.
  2. Propose and verify solutions for the *train* split; collect failures.
  3. Forge candidate skills from the train failures only.
  4. For each candidate, ask the gate to score it on the *held-out* split.
     The gate enforces the firewall and promotes only genuine improvements.
  5. Re-measure the held-out pass rate after promotions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from prometheus_protocol.core.config import Config
from prometheus_protocol.core.interfaces import (
    Gate,
    Ledger,
    Provider,
    Registry,
    Verifier,
)
from prometheus_protocol.core.models import Attempt, Skill, Task, Verdict
from prometheus_protocol.forge.miner import LessonForge
from prometheus_protocol.gate.promotion import GateDecision
from prometheus_protocol.memory.tiers import MemoryTier
from prometheus_protocol.verifier.bank import VerifierBank


@dataclass(frozen=True)
class TaskOutcome:
    task_id: str
    split: str
    passed: bool
    attempt: Attempt


@dataclass(frozen=True)
class RunReport:
    outcomes: tuple[TaskOutcome, ...]

    @property
    def pass_rate(self) -> float:
        if not self.outcomes:
            return 0.0
        passed = sum(1 for o in self.outcomes if o.passed)
        return passed / len(self.outcomes)

    def rate_for(self, split: str) -> float:
        subset = [o for o in self.outcomes if o.split == split]
        if not subset:
            return 0.0
        return sum(1 for o in subset if o.passed) / len(subset)


@dataclass(frozen=True)
class CycleReport:
    cycle: int
    baseline_heldout_rate: float
    mined: tuple[Skill, ...]
    decisions: tuple[GateDecision, ...]
    promoted: tuple[str, ...]
    post_heldout_rate: float

    @property
    def learned(self) -> bool:
        return bool(self.promoted)


class Orchestrator:
    """Sequences provider, verifier, forge, gate, registry, and ledger."""

    def __init__(
        self,
        *,
        provider: Provider,
        verifier: Verifier,
        registry: Registry,
        gate: Gate,
        ledger: Ledger,
        forge: LessonForge | None = None,
        config: Config | None = None,
        memory: MemoryTier | None = None,
        bank: VerifierBank | None = None,
        advisors: Sequence[Verifier] = (),
    ) -> None:
        self.provider = provider
        self.verifier = verifier
        self.registry = registry
        self.gate = gate
        self.ledger = ledger
        self.forge = forge or LessonForge()
        self.config = config or Config()
        self.memory = memory
        # The bank fuses verifier evidence into a judgment. A lone hard verifier
        # never changes the verdict, so the default bank preserves outcomes; it
        # auto-registers each verifier from the tier on its evidence.
        self.bank = bank if bank is not None else VerifierBank()
        # Advisory (e.g. soft model-judge) verifiers run alongside the
        # authoritative verifier. They modulate fused confidence and accrue
        # calibration, but never decide the verdict.
        self.advisors: tuple[Verifier, ...] = tuple(advisors)

    # -- core step ---------------------------------------------------------

    def _skills_for(
        self,
        task: Task,
        extra_skills: Sequence[Skill],
        exclude_ids: Sequence[str],
    ) -> list[Skill]:
        excluded = set(exclude_ids)
        chosen: dict[str, Skill] = {}
        for skill in self.registry.retrieve(task.prompt, k=self.config.retrieval_k):
            if skill.id not in excluded:
                chosen[skill.id] = skill
        for skill in extra_skills:
            if skill.id not in excluded:
                chosen[skill.id] = skill
        return list(chosen.values())

    def run_split(
        self,
        tasks: Sequence[Task],
        *,
        extra_skills: Sequence[Skill] = (),
        exclude_ids: Sequence[str] = (),
        cycle: int = 0,
        kind: str = "run",
    ) -> RunReport:
        outcomes: list[TaskOutcome] = []
        for task in tasks:
            skills = self._skills_for(task, extra_skills, exclude_ids)
            code = self.provider.propose_solution(
                prompt=task.prompt, entry_point=task.entry_point, skills=skills
            )
            evidence = self.verifier.verify(code=code, task=task)
            # Gather advisory verdicts (if any) for the same outcome. The
            # authoritative verifier still decides; advisors only inform
            # confidence and accrue calibration.
            advisory_evidence = [a.verify(code=code, task=task) for a in self.advisors]
            # Route the verdicts through the bank; its judgment is the pass
            # criterion the loop and gate consult. A pass requires a PASS
            # verdict (ABSTAIN, like the old timeout, is not a pass).
            judgment = self.bank.judge([evidence, *advisory_evidence])
            passed = judgment.verdict == Verdict.PASS
            attempt = Attempt(
                task_id=task.id,
                split=task.split,
                entry_point=task.entry_point,
                code=code,
                evidence=evidence,
                skills_used=tuple(skill.id for skill in skills),
                judgment=judgment,
            )
            self.ledger.record_attempt(attempt, cycle=cycle, kind=kind)
            if self.memory is not None:
                self.memory.set(f"cycle:{cycle}", task.id, passed)
            outcomes.append(TaskOutcome(task.id, task.split, passed, attempt))
        return RunReport(tuple(outcomes))

    # -- high-level operations --------------------------------------------

    def baseline(self, tasks: Sequence[Task]) -> RunReport:
        """Run every task once with the registry as it stands."""

        return self.run_split(tasks, cycle=0, kind="baseline")

    def ablation(
        self, heldout_tasks: Sequence[Task], skill_id: str, *, cycle: int = 0
    ) -> float:
        """Held-out contribution of ``skill_id``: rate with it minus rate without."""

        with_skill = self.run_split(
            heldout_tasks, cycle=cycle, kind="ablation-with"
        ).pass_rate
        without_skill = self.run_split(
            heldout_tasks, exclude_ids=[skill_id], cycle=cycle, kind="ablation-without"
        ).pass_rate
        return with_skill - without_skill

    def run_cycle(
        self,
        train_tasks: Sequence[Task],
        heldout_tasks: Sequence[Task],
        *,
        cycle: int = 1,
    ) -> CycleReport:
        train_ids = [task.id for task in train_tasks]

        rate_before = self.run_split(
            heldout_tasks, cycle=cycle, kind="heldout-before"
        ).pass_rate

        train_report = self.run_split(train_tasks, cycle=cycle, kind="train")
        failures = [o.attempt for o in train_report.outcomes if not o.passed]
        tasks_by_id = {task.id: task for task in train_tasks}

        mined = self.forge.mine(failures, tasks_by_id)

        def score_fn(tasks: Sequence[Task], candidate: Skill) -> float:
            return self.run_split(
                tasks, extra_skills=[candidate], cycle=cycle, kind="gate-score"
            ).pass_rate

        decisions: list[GateDecision] = []
        promoted: list[str] = []
        for candidate in mined:
            decision = self.gate.evaluate(
                candidate=candidate,
                train_ids=train_ids,
                heldout_tasks=heldout_tasks,
                score_fn=score_fn,
                rate_before=rate_before,
            )
            decisions.append(decision)
            if decision.promoted:
                self.registry.add(candidate)
                self.ledger.record_promotion(
                    skill_id=candidate.id,
                    action="promote",
                    cycle=cycle,
                    rate_before=decision.rate_before,
                    rate_after=decision.rate_after,
                )
                promoted.append(candidate.id)

        post_rate = self.run_split(
            heldout_tasks, cycle=cycle, kind="heldout-after"
        ).pass_rate

        return CycleReport(
            cycle=cycle,
            baseline_heldout_rate=rate_before,
            mined=tuple(mined),
            decisions=tuple(decisions),
            promoted=tuple(promoted),
            post_heldout_rate=post_rate,
        )
