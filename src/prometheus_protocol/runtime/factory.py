"""Composition root: build a fully wired runtime from a :class:`Config`.

Keeping the wiring in one place means the CLI, the example scripts, and the
tests all assemble the same runtime the same way, and the choice of provider
is made by configuration rather than by code edits.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Mapping

from prometheus_protocol.core.anchor_spec import parse_anchor_spec
from prometheus_protocol.core.booleans import parse_env_bool
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.core.bounds import Bound, is_unbounded, resolve_bound
from prometheus_protocol.core.config import PROVIDER_REMOTE, Config
from prometheus_protocol.core.interfaces import Ledger, Provider, Verifier
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.executor import SandboxExecutor
from prometheus_protocol.forge.miner import LessonForge
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import PromotionGate
from prometheus_protocol.ledger.anchor_targets import build_tip_anchor
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.ledger.tip_anchor import TipAnchor
from prometheus_protocol.sandbox import Limits
from prometheus_protocol.memory.tiers import InMemoryTier, MemoryTier
from prometheus_protocol.provider.mock import MOCK_MODEL, MockProvider, SolutionBook
from prometheus_protocol.provider.remote import RemoteModelProvider
from prometheus_protocol.registry.markdown_registry import MarkdownSkillRegistry
from prometheus_protocol.runtime.orchestrator import Orchestrator
from prometheus_protocol.sandbox import build_sandbox
from prometheus_protocol.sandbox.base import Sandbox
from prometheus_protocol.swarm.debate import DebateLayer
from prometheus_protocol.swarm.executor import RecordingExecutor
from prometheus_protocol.swarm.runtime import SwarmRuntime
from prometheus_protocol.swarm.synthesis import RoleSynthesisEngine
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.model_judge import ModelJudgeVerifier
from prometheus_protocol.verifier.runner import SubprocessVerifier
from prometheus_protocol.verifier.store import (
    InMemoryTrustStore,
    SqliteTrustStore,
    TrustStore,
)

if TYPE_CHECKING:  # pragma: no cover
    from prometheus_protocol.policy.profile import VerificationPolicy
    from prometheus_protocol.policy.reobservation import ReObservation, StateObserver
    from prometheus_protocol.tools.git import GitTool

_LOG = logging.getLogger(__name__)


def build_provider(
    config: Config, solution_book: SolutionBook | None = None
) -> Provider:
    """Select the provider named by ``config.provider``.

    For the (default) mock provider, fall back to the shipped example solution
    book when none is supplied, so the offline demo works out of the box.
    """

    if config.provider == PROVIDER_REMOTE:
        return RemoteModelProvider.from_config(config)
    if solution_book is None:
        from prometheus_protocol._examples.python_functions import build_solution_book

        solution_book = build_solution_book()
    return MockProvider(book=solution_book)


# Emitted at most once per process: the correlated-grader notice below is a
# posture report, not a per-build event, so repeated builds stay quiet.
_SHARED_JUDGE_MODEL_WARNED = False


def _actor_model(config: Config) -> str:
    return (config.model or "") if config.provider == PROVIDER_REMOTE else MOCK_MODEL


def _judge_shares_actor_model(config: Config) -> bool:
    """Whether the judge would run on the same model as the actor/roles."""

    return not config.judge_model or config.judge_model == _actor_model(config)


def build_judge_provider(
    config: Config, solution_book: SolutionBook | None = None
) -> Provider:
    """Provider for the soft model-judge.

    Uses an independent judge model whenever ``judge_model`` names one distinct
    from the actor's (reduces correlated error: the same model producing and
    grading inflates agreement). ``judge_api_base`` / ``judge_api_key``
    optionally point the judge at a different gateway; unset, they inherit the
    actor's endpoint. Otherwise the judge reuses the actor provider unchanged —
    and says so loudly, once: a single brain proposing and grading is a
    correlated-grader risk an operator should choose knowingly.
    """

    global _SHARED_JUDGE_MODEL_WARNED
    if not _judge_shares_actor_model(config):
        if config.provider == PROVIDER_REMOTE:
            return RemoteModelProvider(
                api_base=config.judge_api_base or config.api_base or "",
                model=config.judge_model or "",
                # Passed as the Secret it already is: no unwrap-and-rewrap,
                # so there is one fewer frame holding the plaintext (F8).
                api_key=(
                    config.judge_api_key
                    if config.judge_api_key is not None
                    else config.api_key
                ),
                timeout_s=config.request_timeout_s,
                allow_insecure_loopback=config.allow_insecure_loopback,
                max_response_bytes=config.provider_max_response_bytes,
            )
        # Offline: a distinct judge identity gets its own provider instance, so
        # routing is observable in tests. Judge behaviour is unchanged (the mock
        # does not implement assess, so the judge abstains either way).
        return MockProvider(model=config.judge_model or MOCK_MODEL)
    if config.judge_api_base or config.judge_api_key:
        # An endpoint override without an independent judge model is an active
        # misconfiguration; unlike the posture notice below, it fires per build.
        _LOG.warning(
            "PROM_JUDGE_API_BASE/PROM_JUDGE_API_KEY are ignored without an "
            "independent PROM_JUDGE_MODEL; the judge is using the actor's "
            "provider"
        )
    if not _SHARED_JUDGE_MODEL_WARNED:
        _SHARED_JUDGE_MODEL_WARNED = True
        _LOG.warning(
            "the soft judge shares the actor's model (%s): one model is both "
            "proposing and grading, a correlated-grader risk; set "
            "PROM_JUDGE_MODEL to run the judge on an independent model",
            _actor_model(config) or "unset",
        )
    return build_provider(config, solution_book)


def build_sandbox_for(config: Config, *, env=None) -> Sandbox:
    """The sandbox this configuration requests — honoured, or refused.

    Every builder in this module gets its sandbox here, so the two checks that
    turn a requested property into an enforced one happen in exactly one place:

    * the digest-pin requirement is passed through to ``build_sandbox`` (it used
      to be read by nothing — threat model §5, E5-1);
    * a remote provider's output is never executed without isolation. ``auto``
      may fall back to the unsafe adapter when the operator opted in and nothing
      isolating is available; with the mock provider that is a development
      convenience, with a remote model it is the exact threat the sandbox
      exists for, so the combination is refused here as well as at Config load.
    """

    sandbox = build_sandbox(config.sandbox, env=env, require_digest_pin=config.require_digest_pin)
    if config.provider == PROVIDER_REMOTE and not sandbox.isolating:
        raise ConfigError(
            f"provider=remote resolved to the non-isolating {sandbox.name!r} sandbox: "
            "a remote model's output will not be executed without isolation. "
            "Provide an isolating runtime or use the mock provider.",
            reason="unsafe_with_remote",
        )
    return sandbox


#: The environment gate for the ledger anchor requirement, read here as well
#: as by ``Config.from_env`` so it is the OR of its sources: a programmatic
#: ``Config(require_ledger_anchor=False)`` beside the variable does not lower it.
LEDGER_ANCHOR_REQUIRED_ENV = "PROM_REQUIRE_LEDGER_ANCHOR"


def ledger_anchor_required(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return parse_env_bool(
        LEDGER_ANCHOR_REQUIRED_ENV, env.get(LEDGER_ANCHOR_REQUIRED_ENV), default=False
    )


def build_tip_anchor_for(config: Config, *, env: Mapping[str, str] | None = None) -> TipAnchor | None:
    """The anchor target ``config`` names, or ``None`` when unanchored.

    A requirement that cannot be honoured is refused here, not degraded: with
    the anchor required and none configured, or a ``file://`` one (a single
    local file the ledger adversary can rewrite too), this raises rather than
    returning a ledger that quietly lacks its witness. The same rules hold at
    ``Config`` load; this is the runtime half, and the one the environment
    variable reaches.
    """

    required = config.require_ledger_anchor or ledger_anchor_required(env)
    if not config.ledger_anchor:
        if required:
            raise ConfigError(
                "a ledger tip anchor is required "
                f"({LEDGER_ANCHOR_REQUIRED_ENV}=1 or require_ledger_anchor=True) and "
                "none is configured. Set PROM_LEDGER_ANCHOR to worm:///directory "
                "or https://host/path (docs/ledger-integrity.md)."
            )
        return None
    spec = parse_anchor_spec(
        config.ledger_anchor,
        name="ledger_anchor",
        allow_insecure_loopback=config.allow_insecure_loopback,
    )
    if required and not spec.append_only:
        raise ConfigError(
            "a required ledger anchor cannot be honoured by "
            f"{config.ledger_anchor!r}: a single local file is rewritten in place "
            "and is non-protecting. Use worm:// or https://."
        )
    return build_tip_anchor(
        spec,
        token=config.ledger_anchor_token,
        retain_for_s=config.ledger_anchor_retention_days * 86_400.0,
        timeout_s=config.request_timeout_s,
        allow_insecure_loopback=config.allow_insecure_loopback,
    )


def build_ledger(
    config: Config,
    *,
    env: Mapping[str, str] | None = None,
    path: Path | str | None = None,
) -> SqliteLedger:
    """The production ledger, opened with the configured anchor.

    Every builder in this module and every CLI command gets its ledger here, so
    continuous anchoring is a property of the production path rather than an
    option a caller remembers: each audit-chain append writes the tip to the
    target, each verify consults the target's whole history. An unanchored
    file-backed ledger is allowed (development) and warned about; an anchor that
    is a single local file is warned about as non-protecting.
    """

    anchor = build_tip_anchor_for(config, env=env)
    location = config.ledger_path if path is None else path
    if anchor is None:
        if str(location) != ":memory:":
            _LOG.warning(
                "ledger %s has NO tip anchor: a rewrite of the audit chain from "
                "genesis, or its deletion, is undetectable. Set PROM_LEDGER_ANCHOR "
                "to worm:///directory or https://host/path (docs/ledger-integrity.md).",
                location,
            )
    elif not anchor.append_only:
        _LOG.warning(
            "ledger anchor %s is a single local file: NON-PROTECTING against "
            "anyone who can write the ledger host, which is the adversary it "
            "exists for. Development only; production uses worm:// or https://.",
            config.ledger_anchor,
        )
    return SqliteLedger(location, tip_anchor=anchor)


def build_verification_policy(config: Config | None = None) -> "VerificationPolicy":
    """The policy VALUE this configuration selects (PHASE-1.2a, R1).

    The single consumption site for ``Config.verification_profile``, and
    deliberately a function returning a VALUE rather than a constant anyone can
    reach for: a customer-supplied digest-pinned policy becomes another supplier
    of this value, not a rewrite of the resolver, the bank or the swarm.

    An unknown profile raises rather than falling back to a default. A typo in
    the selected profile must never silently authorize under a policy nobody
    chose — that is the omission attack wearing a configuration error.
    """

    from prometheus_protocol.policy.profile import load_profile

    config = config or Config()
    return load_profile(config.verification_profile)


def build_orchestrator(
    config: Config | None = None,
    *,
    solution_book: SolutionBook | None = None,
    memory: MemoryTier | None = None,
) -> Orchestrator:
    config = config or Config()
    # Policy selection is part of supported construction even though this
    # learning orchestrator promotes skills rather than executing an action.
    # Its execution controller/gateway is built separately; an unknown selected
    # profile must nevertheless refuse at the root users call.
    build_verification_policy(config)

    verifier = SubprocessVerifier(
        timeout_s=config.verifier_timeout_s,
        memory_mb=config.verifier_memory_mb,
        cpu_seconds=config.verifier_cpu_seconds,
        max_processes=config.verifier_max_processes,
        sandbox=build_sandbox_for(config),
    )

    # Persist trust alongside the ledger; use an in-memory store when the ledger
    # is itself in-memory (tests). Register the verifier so its hard-tier prior
    # applies from the first judgment.
    # Declared at the seam both branches satisfy: inferring the type from the
    # first branch made the second an "incompatible assignment" for code that
    # was always correct.
    trust_store: TrustStore
    if str(config.ledger_path) == ":memory:":
        trust_store = InMemoryTrustStore()
    else:
        trust_store = SqliteTrustStore(config.trust_store_path)
    bank = VerifierBank(
        trust_store, policy_supplier=lambda: build_verification_policy(config)
    )
    bank.register(verifier.verifier_id, verifier.tier)
    _LOG.info(
        "registered verifier %s (tier=%s)", verifier.verifier_id, verifier.tier.value
    )

    # Optional soft model-judge advisor (off by default). The bank calibrates it
    # against the hard reference; it never decides a verdict.
    advisors: list[Verifier] = []
    if config.enable_model_judge:
        judge = ModelJudgeVerifier(build_judge_provider(config, solution_book))
        bank.register(judge.verifier_id, judge.tier)
        advisors.append(judge)
        _LOG.info(
            "registered advisor %s (tier=%s)", judge.verifier_id, judge.tier.value
        )

    _LOG.info(
        "orchestrator built (provider=%s, ledger=%s)",
        config.provider,
        config.ledger_path,
    )
    return Orchestrator(
        provider=build_provider(config, solution_book),
        verifier=verifier,
        registry=MarkdownSkillRegistry(config.registry_dir),
        gate=PromotionGate(threshold=config.gate_threshold),
        ledger=build_ledger(config),
        forge=LessonForge(),
        config=config,
        memory=memory if memory is not None else InMemoryTier(),
        bank=bank,
        advisors=advisors,
    )


def build_swarm_runtime(
    config: Config | None = None,
    *,
    provider: Provider,
    ledger=None,
    memory: MemoryTier | None = None,
) -> SwarmRuntime:
    """Wire a swarm runtime: model-backed roles, the bank/gate/firewall, a no-op
    executor, and a HARD code verifier that runs the Skeptic's executable cases.

    The roles reason via ``provider`` (capped at ``config.max_role_calls`` calls
    per task). The trusted core — bank fusion, the gate, the held-out firewall,
    and the proposer/judge wall — is reused unchanged, and the executor stays a
    no-op recorder.
    """

    config = config or Config()
    # Declared at the seam both branches satisfy: inferring the type from the
    # first branch made the second an "incompatible assignment" for code that
    # was always correct.
    trust_store: TrustStore
    if str(config.ledger_path) == ":memory:":
        trust_store = InMemoryTrustStore()
    else:
        trust_store = SqliteTrustStore(config.trust_store_path)
    code_verifier = SubprocessVerifier(
        timeout_s=config.verifier_timeout_s,
        memory_mb=config.verifier_memory_mb,
        cpu_seconds=config.verifier_cpu_seconds,
        max_processes=config.verifier_max_processes,
        sandbox=build_sandbox_for(config),
    )
    _LOG.info("swarm runtime built (max_role_calls=%d)", config.max_role_calls)
    policy = build_verification_policy(config)
    from prometheus_protocol.policy.execution import ExecutionAuthorizer
    def supplier() -> VerificationPolicy:
        return build_verification_policy(config)
    return SwarmRuntime(
        synthesis=RoleSynthesisEngine(
            provider=provider, max_role_calls=config.max_role_calls
        ),
        debate=DebateLayer(),
        bank=VerifierBank(trust_store, policy_supplier=supplier),
        gate=ActionGate(
            authorizer=ExecutionAuthorizer(supplier), target_canonical="sandbox://swarm"
        ),
        executor=RecordingExecutor(),
        ledger=ledger if ledger is not None else build_ledger(config),
        provider=provider,
        memory=memory,
        code_verifier=code_verifier,
        policy=policy,
    )


#: The scheme a git principal's canonical target carries. Spelled once: the
#: observer's own binding check compares against the same shape, and two
#: spellings of "is this a git target" is two answers to one question.
GIT_TARGET_PREFIX = "git://"


def build_reobservation(
    *,
    target_canonical: str,
    git_tool: "GitTool | None" = None,
    base_branch: str | None = None,
) -> "ReObservation":
    """The re-observation registry for a composition root, from its TARGET.

    WHY THIS EXISTS AS A FUNCTION rather than a default argument. Every
    composition root must decide, explicitly, which action classes it
    re-observes and why it does not re-observe the rest — and the decision
    depends on what the root's principal IS. A default would make the decision
    once, invisibly, for roots that had not been written yet, which is the
    shape that let re-observation ship unwired: thirty passing proofs, thirteen
    reddening mutations, and no production caller.

    The registry is total over ``ACTION_CLASSES`` by construction, so this
    returns a complete answer or raises. Two reasons are possible for a class
    being out, and they are different facts: ``NOT_THIS_PRINCIPAL`` says this
    deployment's target cannot have that kind of state, and
    ``PHASE_ONE_NOT_COVERED`` says the mechanism does not cover the class yet.
    Both appear verbatim in every hold record the root creates.

    ``git_tool`` lets a root that ALREADY holds a ``GitTool`` pass it, so the
    observer and the merge proof read through one instance — one sandbox, one
    repository, one definition of "unmerged". That is the preferred route and
    ``tools/stale_branch_demo.py`` takes it.

    A ROOT THAT PASSES NO TOOL MUST NAME ITS BASE BRANCH, and this refuses
    rather than guessing. The first version synthesised a ``GitTool`` with
    ``GitTool``'s own default base of ``main``, which was wrong for every
    repository based on anything else: measured on a ``master`` repository, the
    caller's own reader reported ``unmerged_commits = 0`` while the synthesised
    observer could not read ``main`` at all, so it returned ``Unreadable`` and
    EVERY ``branch.delete`` hold was refused at creation. Fail-closed, and a
    total denial of the feature for those deployments.

    The deeper reason it cannot be defaulted: the base branch is not a
    deployment-wide constant, it is *the base the merge proof was evaluated
    against*. An observer reading a different base is the second definition of
    "unmerged" that :class:`GitBranchStateObserver` exists to prevent — the
    state a hold is pinned to would not be the state its evidence describes.
    The factory cannot know that base unless it is told, so it asks.
    """

    from prometheus_protocol.policy.reobservation import (
        NOT_THIS_PRINCIPAL,
        PHASE_ONE_NOT_COVERED,
        ReObservation,
    )
    from prometheus_protocol.policy.snapshot import (
        ACTION_BRANCH_DELETE,
        ACTION_DATABASE_MIGRATE,
        ACTION_SANDBOX_EXECUTE,
    )

    observers: dict[str, "StateObserver"] = {}
    opted_out: dict[str, str] = {
        ACTION_SANDBOX_EXECUTE: PHASE_ONE_NOT_COVERED,
        ACTION_DATABASE_MIGRATE: PHASE_ONE_NOT_COVERED,
    }
    if target_canonical.startswith(GIT_TARGET_PREFIX):
        from prometheus_protocol.tools.git import (
            GitBranchStateObserver,
            GitTool,
            is_usable_branch_name,
        )

        # Narrowed in STATEMENT form. The expression form the type gate refuses
        # would take an argument of a third shape down the else-branch and build
        # a tool for the wrong repository, which is an observer reading a
        # subject the hold was never pinned to.
        tool: "GitTool"
        if git_tool is not None:
            # The proof's own reader. If a base branch is ALSO named it must be
            # that tool's, or the two disagree about the subject and the caller
            # is told rather than one silently winning.
            if base_branch is not None and base_branch != git_tool.base_branch:
                raise ConfigError(
                    f"re-observation was given a GitTool based on "
                    f"{git_tool.base_branch!r} and a base_branch of "
                    f"{base_branch!r}. Those are two definitions of 'unmerged' "
                    "for one hold. Pass the tool alone, or pass a base branch "
                    "that matches it.",
                    reason="reobservation_base_branch_conflict",
                )
            tool = git_tool
        elif base_branch is None:
            raise ConfigError(
                f"re-observation was asked to observe the git principal "
                f"{target_canonical!r} but was given neither a GitTool nor a "
                "base_branch. It will not guess: an observer reading a base "
                "the merge proof did not use is a second definition of "
                "'unmerged', and a wrong guess refuses every branch.delete "
                "hold at creation. Pass the reader the proof uses, or name the "
                "base branch.",
                reason="reobservation_base_branch_unknown",
            )
        else:
            tool = GitTool(
                repo_path=target_canonical[len(GIT_TARGET_PREFIX) :],
                base_branch=base_branch,
            )
        # VALIDATED HERE, whichever route supplied it, because an UNUSABLE base
        # reproduces exactly the delayed denial the refusal above exists to
        # remove. Measured: an empty, whitespace-only or dash-leading base
        # builds a registry that looks configured, and then ``GitTool.rev``
        # refuses the name, the observer returns ``Unreadable`` naming
        # ``base_tip``, and EVERY branch.delete hold is refused at creation as
        # ``target_state_unreadable`` — pointing at the repository rather than
        # at the wiring, which is where the defect is.
        #
        # Both routes, not just the synthesised one: a supplied ``GitTool``
        # carrying an unusable base fails the same way, and checking one route
        # while trusting the other is the asymmetry this check exists to close.
        if not is_usable_branch_name(tool.base_branch):
            raise ConfigError(
                f"re-observation was given the base branch "
                f"{tool.base_branch!r} for {target_canonical!r}, which this "
                "tool will not read. An unusable base builds a registry that "
                "looks configured and then refuses every branch.delete hold at "
                "creation, blaming the repository for a wiring error",
                reason="reobservation_base_branch_unusable",
            )
        observers[ACTION_BRANCH_DELETE] = GitBranchStateObserver(tool)
    else:
        opted_out[ACTION_BRANCH_DELETE] = NOT_THIS_PRINCIPAL
    return ReObservation(observers=observers, opted_out=opted_out)


def build_execution_controller(
    config: Config | None = None, *, ledger: Ledger | None = None,
    target_canonical: str = "sandbox://execution",
    base_branch: str | None = None,
) -> ExecutionController:
    """Wire the live-execution path: routing gate -> human hold -> sandbox executor.

    The action gate runs in routing mode (low-confidence and high-risk actions
    halt for a human), and the executor runs every side-effect through the
    configured isolating sandbox — fail-closed if none is available. The bank,
    the firewall, the proposer/judge wall, and verdict semantics are untouched:
    this only turns the executor real and adds the human halt.
    """

    config = config or Config()
    # NOT resolved here. A bound is carried to the adapter that builds the
    # command and resolved there, because the three substrates do not agree on
    # what a zero means: the container runtime reads it through a 16 MiB floor
    # (core/bounds.py). Resolving at this composition root is the flattening
    # that produced PR #106's P1.
    memory_mb = config.verifier_memory_mb
    if is_unbounded(memory_mb):
        memory_bytes: Bound = memory_mb
    else:
        memory_bytes = resolve_bound(memory_mb) * 1024 * 1024
    limits = Limits(
        wall_time_s=config.verifier_timeout_s,
        cpu_time_s=config.verifier_cpu_seconds,
        memory_bytes=memory_bytes,
        max_processes=config.verifier_max_processes,
    )
    _LOG.info("execution controller built (escalate_below=%.2f)", config.escalate_below)
    # Resolve at the composition root so an unknown profile refuses startup,
    # then supply a fresh resolution to every authorization attempt.
    build_verification_policy(config)
    from prometheus_protocol.policy.execution import ExecutionAuthorizer
    return ExecutionController(
        gate=ActionGate(
            escalate_below=config.escalate_below,
            route_high_risk=True,
            authorizer=ExecutionAuthorizer(lambda: build_verification_policy(config)),
            target_canonical=target_canonical,
        ),
        executor=SandboxExecutor(sandbox=build_sandbox_for(config), limits=limits),
        ledger=ledger if ledger is not None else build_ledger(config),
        ttl_seconds=config.pending_ttl_seconds,
        # WIRED HERE, at the root, because an argument no production caller
        # passes is a feature that does not exist. This is the root the CLI's
        # ``approve`` and ``retry-execution`` commands build, so it is the path
        # a human's decision actually travels.
        # ``base_branch`` is threaded, not defaulted. For a ``git://`` target
        # it is required and this refuses without it — see
        # ``build_reobservation``. For every other target it is unused.
        reobservation=build_reobservation(
            target_canonical=target_canonical, base_branch=base_branch
        ),
    )


def build_workflow_runtime(
    config: Config | None = None, *, ledger: SqliteLedger | None = None
):
    """Build workflow assessment and execution with one selected-policy supplier."""

    from prometheus_protocol.orchestration.gateway import ActionGateway
    from prometheus_protocol.orchestration.runtime import WorkflowRuntime

    config = config or Config()
    selected = build_verification_policy(config)
    shared_ledger = ledger if ledger is not None else SqliteLedger(config.ledger_path)
    target = "sandbox://workflow"
    controller = build_execution_controller(
        config, ledger=shared_ledger, target_canonical=target
    )
    return WorkflowRuntime(
        bank=VerifierBank(
            policy_supplier=lambda: build_verification_policy(config)
        ),
        gateway=ActionGateway(controller.submit),
        ledger=shared_ledger,
        policy=selected,
        target_canonical=target,
    )
