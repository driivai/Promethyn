"""Immutable data structures shared across the runtime.

These types are intentionally small, hashable where practical, and free of
behaviour. Behaviour lives in the service modules (verifier, registry, forge,
gate, runtime); the models are the wire format that flows between them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, NoReturn, Sequence


def assert_never(value: NoReturn) -> NoReturn:
    """Exhaustiveness, checked by the type checker rather than remembered.

    Put this in the ``else`` of a union match. Every member the branches above
    narrowed away leaves ``value`` as ``Never`` here, which type-checks; a
    member that is *not* handled leaves a real type and mypy reports it — at
    every consumer, the moment a third member is added to a union. Without it a
    new member falls silently through to whatever the ``else`` does, which for
    ``Evidence | Unavailable`` is exactly the class of defect EX-1 exists to
    make unrepresentable.

    ``typing.assert_never`` is 3.11+, and this repository supports 3.10; the
    ``NoReturn`` parameter is the older idiom mypy special-cases identically.
    """

    raise AssertionError(f"unhandled union member: {value!r}")

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


@dataclass(frozen=True, kw_only=True)
class Evidence:
    """The outcome produced by one verifier for one attempt.

    KEYWORD-ONLY, DELIBERATELY. Fourteen fields, four of them optional and
    sitting between the ones callers actually set, made positional construction
    miscountable in a way nothing caught: ``Evidence(True, 1, 1, (), "runner",
    Verdict.PASS, tier=Tier.HARD)`` reads as though ``"runner"`` is the verifier
    id, and it is ``stdout``. The value lands in a plausible slot, ``verifier_id``
    silently keeps its default, and nothing raises. Measured: that spelling
    appeared in the Checkpoint B proofs and was INVISIBLE, because every path it
    sat on refused before coverage compared the implementation with the evidence.
    The moment a test expected coverage to HOLD it surfaced as
    ``coverage.invalid_evidence`` — "the result names one implementation and the
    evidence another".

    A field this class carries is read by the coverage decision, so a silently
    mis-slotted one is a policy input set by accident. ``kw_only=True`` removes
    the shape rather than the instance: there is no longer a positional form to
    miscount, on any call site, including ones nobody has written yet.

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

    @property
    def decided(self) -> Verdict:
        """The verdict this evidence carries, as a plain :class:`Verdict`.

        ``verdict`` is ``Verdict | None`` because that is the *constructor's*
        contract — a caller may leave it unset and let ``__post_init__`` derive
        it from ``passed``. Every constructed Evidence therefore has one, but
        the field's type cannot say so, and consumers were re-deriving that
        invariant (or reaching for ``.verdict.value`` and being told by the type
        checker that ``None`` has no ``.value``).

        This accessor states the guarantee once and checks it once. It is not a
        default: there is no verdict to invent here, and an Evidence that
        somehow escaped ``__post_init__`` raises rather than answering.
        """

        if self.verdict is None:  # pragma: no cover - __post_init__ prevents it
            raise AssertionError(
                "Evidence without a verdict escaped __post_init__; refusing to "
                "invent one"
            )
        return self.verdict


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
    # An attempt whose verifier could NOT run still happened and still has to be
    # writable to the ledger. Typing this ``Evidence`` alone left callers with
    # nowhere to put an ``Unavailable`` — so the swarm reached for ``.verdict``
    # on one and crashed. "Could not run" is an outcome of an attempt, not the
    # absence of one.
    evidence: Evidence | Unavailable
    skills_used: tuple[str, ...] = field(default_factory=tuple)
    judgment: "Judgment | None" = None


@dataclass(frozen=True, kw_only=True)
class Judgment:
    """The fused result of weighing several verifiers' evidence.

    ``confidence`` is in [0, 1] and reads as certainty in the reported
    ``verdict``. ``authoritative`` is True when the verdict comes from a
    hard/human reference (and is therefore binding); False when it comes from
    advisory verifiers only. ``contributing`` lists the verifier ids that
    decided the verdict. ``conflict`` is True when an authoritative verifier
    disagreed with the chosen reference verdict.

    ``unavailable`` carries any authoritative verifiers that could NOT execute
    while a sibling did produce the verdict. A sibling covering for it does not
    make a could-not-execute a non-event — it is an operational fault every time
    — so it is carried here and never silently dropped at the bank, staying
    available to any consumer that records operational faults. (Persisting it onto
    the execution ledger row is a named follow-up: that serializer lives outside
    this sprint's frozen-file boundary — see docs/skip-sweep.md.)
    """

    verdict: Verdict
    confidence: float
    authoritative: bool
    contributing: tuple[str, ...] = ()
    conflict: bool = False
    detail: str = ""
    unavailable: tuple[Unavailable, ...] = ()


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


def partition_outcomes(
    results: "Sequence[Evidence | Unavailable]",
) -> "tuple[list[Evidence], list[Unavailable]]":
    """Split a batch of outcomes into (ran-and-judged, could-not-run).

    Exhaustively. This exists because the obvious spelling is not:

        decided = [r for r in results if isinstance(r, Evidence)]

    A comprehension that filters *to* one member silently DROPS anything that is
    neither — and drops it with no diagnostic, because a narrowed comprehension
    is well-typed whatever else the union holds. An independent review named
    exactly this: the union has two members today and the narrowing is correct,
    so it is not a runtime defect, but a third member added later would vanish
    out of a quorum instead of failing the build. In a lever whose whole claim is
    "N independent judges agreed", a silently smaller N is the wrong kind of
    wrong.

    Here the loop handles both members and reaches ``assert_never`` for anything
    else, so a third member is a build failure at the one place that would
    otherwise have swallowed it. Callers get both halves and must decide what to
    do with each — there is no default, and no member is dropped for them.
    """

    decided: list[Evidence] = []
    missing: list[Unavailable] = []
    for result in results:
        if isinstance(result, Unavailable):
            missing.append(result)
        elif isinstance(result, Evidence):
            decided.append(result)
        else:
            assert_never(result)
    return decided, missing
