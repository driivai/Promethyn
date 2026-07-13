"""Immutable data structures shared across the runtime.

These types are intentionally small, hashable where practical, and free of
behaviour. Behaviour lives in the service modules (verifier, registry, forge,
gate, runtime); the models are the wire format that flows between them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Allowed values for ``Task.split``. The whole safety story of the protocol
# rests on these two partitions never mixing (see ``gate`` and ``spec``).
SPLIT_TRAIN = "train"
SPLIT_HELDOUT = "heldout"
SPLITS = (SPLIT_TRAIN, SPLIT_HELDOUT)


class Verdict(str, Enum):
    """A single verifier's call on one attempt.

    ``ABSTAIN`` means the verifier declined to judge; it never contributes to
    fusion or calibration. The values are strings so verdicts serialise
    transparently (for example into the experience ledger's JSON column).
    """

    PASS = "pass"
    FAIL = "fail"
    ABSTAIN = "abstain"


class Tier(str, Enum):
    """How much a verifier is trusted by construction.

    ``HARD`` and ``HUMAN`` are *authoritative*: their verdict decides the
    result and serves as the reference that calibrates everything else.
    ``SOFT`` and ``CONSISTENCY`` are advisory: they must earn trust by agreeing
    with authoritative references before they carry any weight.
    """

    HARD = "hard"
    HUMAN = "human"
    SOFT = "soft"
    CONSISTENCY = "consistency"


class Unavailability(str, Enum):
    """Why a verifier could NOT execute the candidate at all.

    This is not a shade of ``ABSTAIN``. ``ABSTAIN`` is a *verdict* — "I executed
    the candidate and the result is genuinely ambiguous, or the task had nothing
    to check." Unavailability is the *absence* of a verdict — "I could not
    execute the candidate" — which is a fault of the harness or a deliberate
    refusal to run, never the candidate's epistemic ambiguity. The two are kept
    apart by construction (see :class:`Unavailable`); within unavailability the
    two reasons are also kept apart, because they mean different things
    operationally and must never be flattened:

    * ``INFRA_FAULT`` — the isolation runtime failed: no sandbox available, it
      did not start, or the candidate was never confirmed to begin executing. An
      operational fault to repair.
    * ``POLICY_REFUSAL`` — the harness deliberately refused to run: a
      supply-chain guard tripped (for example an unpinned image under a required
      digest pin). Not a fault; a chosen "no".
    """

    INFRA_FAULT = "infra_fault"
    POLICY_REFUSAL = "policy_refusal"


# Tiers whose verdicts are authoritative (decide the result, calibrate others).
AUTHORITATIVE_TIERS = frozenset({Tier.HARD, Tier.HUMAN})


@dataclass(frozen=True)
class Case:
    """A single hidden input/output expectation for a task.

    ``args`` is the positional argument tuple handed to the candidate
    function; ``expected`` is the value it must return. Cases are *hidden*:
    they are handed to the verifier, never to the model provider.
    """

    args: tuple[Any, ...]
    expected: Any


@dataclass(frozen=True)
class Task:
    """A unit of work the runtime tries to solve.

    ``prompt`` and ``entry_point`` are the only fields exposed to a provider.
    ``cases`` and ``cluster`` are evaluation-side metadata and must not leak
    into a proposal request.
    """

    id: str
    entry_point: str
    prompt: str
    split: str
    cases: tuple[Case, ...]
    cluster: str | None = None

    def __post_init__(self) -> None:
        if self.split not in SPLITS:
            raise ValueError(
                f"task {self.id!r} has unknown split {self.split!r}; "
                f"expected one of {SPLITS}"
            )


@dataclass(frozen=True)
class Skill:
    """A reusable lesson, stored on disk as a markdown document.

    ``triggers`` are lowercase keywords that, when present in a task prompt,
    mark the skill as relevant. ``tags`` group related skills (typically by
    the failure cluster that produced them).
    """

    id: str
    title: str
    body: str
    triggers: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    source: str = ""


@dataclass(frozen=True)
class Evidence:
    """The outcome produced by one verifier for one attempt.

    Contract note (additive, pre-1.0): the trailing fields below were added to
    let multiple verifiers' verdicts be fused and ranked. They all have
    defaults, so every existing construction keeps working unchanged. When
    ``verdict`` is left unset it is derived from ``passed`` in ``__post_init__``
    (``PASS``/``FAIL``), so callers that only set ``passed`` still get a
    well-defined verdict. ``tier`` stays ``None`` unless supplied; the verifier
    bank requires a tier on any non-abstaining evidence it is given.
    """

    passed: bool
    total: int
    passed_count: int
    failures: tuple[str, ...] = ()
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    timed_out: bool = False
    # --- verifier-trust fields (additive) ---
    verifier_id: str = ""
    verdict: Verdict | None = None
    tier: Tier | None = None
    cost: float | None = None
    latency_ms: float | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        if self.verdict is None:
            derived = Verdict.PASS if self.passed else Verdict.FAIL
            object.__setattr__(self, "verdict", derived)


@dataclass(frozen=True)
class Unavailable:
    """A verifier that could NOT execute the candidate — the absence of a verdict.

    A HARD verifier's ``verify`` returns :class:`Evidence` ``| Unavailable``; it
    returns this in place of Evidence when the check could not run at all. It
    deliberately has **no** ``verdict`` attribute, so "could not execute" can
    never be read as "executed and abstained": any code that reaches for
    ``.verdict`` on an ``Unavailable`` fails — at type-check time (a static
    checker refuses ``x.verdict`` on ``Evidence | Unavailable`` until the
    ``Unavailable`` branch is narrowed away) and, if that is bypassed, at runtime
    (``AttributeError`` on first touch) — rather than silently comparing unequal
    to every verdict. That is the distinction EX-1 makes unrepresentable
    otherwise: an authoritative verifier that could not run must never degrade
    into an abstention.

    ``tier`` is the tier of the verifier that could not run, so a consumer can
    tell an *authoritative* (HARD/HUMAN) unavailability — which must halt and
    route to a human, never pass — from a merely advisory one. ``reason`` is
    :class:`Unavailability` (INFRA_FAULT vs POLICY_REFUSAL, never flattened).
    ``detail`` is a human diagnostic and is never parsed for meaning.
    """

    verifier_id: str
    tier: Tier
    reason: Unavailability
    detail: str = ""


@dataclass(frozen=True)
class Attempt:
    """One proposal evaluated against one task, with its evidence.

    ``skills_used`` records which skills were in context when the proposal was
    produced; this is what makes ablation and audit possible after the fact.
    ``judgment`` is the fused verdict the verifier bank reached for this
    attempt, when one was computed (optional, for audit).
    """

    task_id: str
    split: str
    entry_point: str
    code: str
    evidence: Evidence
    skills_used: tuple[str, ...] = field(default_factory=tuple)
    judgment: "Judgment | None" = None


@dataclass(frozen=True)
class Judgment:
    """The fused result of weighing several verifiers' evidence.

    ``confidence`` is in [0, 1] and reads as certainty in the reported
    ``verdict``. ``authoritative`` is True when the verdict comes from a
    hard/human reference (and is therefore binding); False when it comes from
    advisory verifiers only. ``contributing`` lists the verifier ids that
    decided the verdict. ``conflict`` is True when an authoritative verifier
    disagreed with the chosen reference verdict.
    """

    verdict: Verdict
    confidence: float
    authoritative: bool
    contributing: tuple[str, ...] = ()
    conflict: bool = False
    detail: str = ""


# Minimal, explicit tool set the executor may act on: in-sandbox code
# execution, plus exactly one narrow external connector — deleting a branch of
# a caller-pinned local git repository. The git action carries only the branch
# name; the repository is bound at executor construction, so an action cannot
# point the tool anywhere else. Each kind is handled by its own executor
# adapter behind the same wall, and an executor refuses every kind it does not
# explicitly support.
ACTION_PYTHON_CODE = "python_code"
ACTION_GIT_DELETE_BRANCH = "git_delete_branch"
EXECUTABLE_ACTION_KINDS = frozenset({ACTION_PYTHON_CODE, ACTION_GIT_DELETE_BRANCH})


@dataclass(frozen=True)
class ExecutableAction:
    """A concrete, side-effecting action authorized for sandboxed execution.

    Like any proposer-side content, an action carries no verdict and no
    approval; it becomes executable only when wrapped in an *approved*
    ``GateDecision``. ``kind`` names the (minimal, explicit) tool; ``code`` is
    the program run inside the sandbox; ``entry_point`` is optional code-domain
    metadata. The executor refuses any unknown kind, and every side-effect runs
    through the sandbox — nothing here reaches the world outside isolation.
    """

    kind: str
    code: str
    entry_point: str = ""

    def __post_init__(self) -> None:
        if self.kind not in EXECUTABLE_ACTION_KINDS:
            raise ValueError(
                f"unknown action kind {self.kind!r}; expected one of "
                f"{sorted(EXECUTABLE_ACTION_KINDS)}"
            )
