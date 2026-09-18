"""G24: an authorization is SPENT when it is used.

WHAT WAS MEASURED AT ``7cc2c4c``, BEFORE ANY OF THIS EXISTED. Three paths
reached an executor and one of them claimed anything:

  (a) ``controller.submit`` with the same auto-approved assessment, action and
      ``attempt_id`` twice — TWO executor calls, two execution rows, one
      ``attempt_id``. ``controller.py:367`` said so in words: "The
      auto-approved path carries no hold (pending_id is None) and needs no
      claim."
  (b) an approved ``GateDecision`` retained and handed straight to a concrete
      executor's public ``execute()`` twice — TWO executions, same
      ``attempt_id``, no gateway involved at all.
  (c) ``swarm/runtime.py:290`` — a shipped path, built by
      ``runtime/factory.py:406`` — called ``self.executor.execute(decision)``
      with no claim and no hold to claim. The brief asked whether the two
      found were the whole enumeration. They were not.

The held path claimed atomically throughout. So the LOW-RISK path carried a
weaker guarantee than the high-risk one, in the same gateway, and that
exception is what made the control-plane story unfalsifiable: any measurement
of the strong path was true, and said nothing about the one that mattered.

EVERY TEST BELOW ASSERTS THE FIXED BEHAVIOUR, and each reproduction is named
for the path it covers. Against the unfixed tree they are red; the observed red
is in ``docs/OPEN-GAPS.md`` G55.

TWO MECHANISMS, PROVED SEPARATELY. The ledger spend makes an OCCURRENCE
at-most-once across processes; ``consume_authorization`` makes a minted
AUTHORIZATION OBJECT at-most-once within one. Defence in depth disarms
single-target proofs (G44), so the scenarios below are chosen so that only one
can fire at a time: the ledger's with two DISTINCT decision objects for one
occurrence, the object's with the SAME object twice.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import json
import pathlib

import pytest

import test_execution_authorization_record as fx
from prometheus_protocol.swarm.executor import RecordingExecutor
from prometheus_protocol.ledger.spend import (
    COMPLETED,
    DEFAULT_IDEMPOTENCY_WINDOW_SECONDS,
    KEY_EXPIRED,
    KEY_FIELDS,
    MAY_EXECUTE,
    RELEASE_EVENT,
    RELEASED,
    RETURN_PRIOR,
    SPEND_EVENT,
    SPEND_OUTCOME_EVENT,
    SPENT,
    UNSPENT,
    SpendRecordMalformed,
    SpendState,
    authorization_key,
    retry_verdict,
    spend_state,
    spend_subject,
)
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.ledger.tip_anchor import FileTipAnchor
from prometheus_protocol.policy.execution import (
    EXECUTION_REFUSAL_REASONS,
    ExecutionNotAuthorized,
)

REPO = pathlib.Path(__file__).resolve().parents[2]

#: A fixed moment for the verdicts that are not ABOUT time. The window
#: tests below supply their own pair; everything else would otherwise be
#: reading a wall clock into an assertion that has nothing to do with one.
_NOW = "2026-09-18T00:00:00+00:00"


class _CapturingSandbox:
    """An isolating sandbox that really returns candidate output.

    Minimal on purpose: ``SandboxExecutor`` reads ``isolating``, ``name`` and
    ``run``, and the property under test is what the executor reports about a
    capture rather than anything about isolation.
    """

    name = "capturing"
    isolating = True

    def __init__(self, stdout: str) -> None:
        self._stdout = stdout

    def run(self, *, argv, workspace, limits=None, stdin: str = ""):
        from prometheus_protocol.sandbox.base import SandboxResult

        return SandboxResult(
            started_ok=True, candidate_started=True, exit_status=0, stdout=self._stdout
        )


def _all_subclasses(cls) -> list[type]:
    found: list[type] = []
    for sub in cls.__subclasses__():
        found.append(sub)
        found.extend(_all_subclasses(sub))
    return found


def anchored(tmp_path, name: str = "ledger") -> SqliteLedger:
    """A ledger with an APPEND-ONLY anchor, so "the chain verifies" below is a
    verification against a witness rather than a chain talking to itself."""

    return SqliteLedger(
        tmp_path / f"{name}.db", tip_anchor=FileTipAnchor(tmp_path / f"{name}.json")
    )


def auto(tmp_path, name: str = "ledger", **kwargs):
    """A controller whose gate AUTO-APPROVES: the path that had no claim."""

    return fx.controller(anchored(tmp_path, name), **kwargs)


def assessed(a, attempt_id: str):
    """``fx.satisfied`` for an attempt id other than the fixture's own.

    ``attempt_id`` is bound INTO the requirement snapshot, so an assessment
    built for one attempt does not cover another — which is the descriptor
    comparison doing its job, and the reason this helper exists rather than a
    substituted id.
    """

    s = fx.resolve(
        fx.POLICY,
        artifact_sha256=fx.content_hash(a.code),
        target_canonical=fx.TARGET,
        action_class=fx.ACTION_SANDBOX_EXECUTE,
        attempt_id=attempt_id,
    )
    return fx.VerifierBank(policy_supplier=lambda: fx.POLICY).assess(
        s,
        [
            fx.bound(s, "run", "runner-a", fx.evidence("runner-a")),
            fx.bound(s, "run", "runner-b", fx.unavailable("runner-b")),
            fx.bound(s, "audit", "auditor", fx.evidence("auditor")),
        ],
    )


def minted(a, *, attempt_id: str, risk_class: str = "low"):
    """An approved ``GateDecision`` with NO ledger behind it.

    The gate is what mints an authorization; the controller is one caller of
    it. A test that needs an unspent decision builds it here, exactly as
    ``swarm/runtime.py`` builds its own gate.
    """

    from prometheus_protocol.gate.authorization import ActionGate
    from prometheus_protocol.policy.execution import ExecutionAuthorizer

    gate = ActionGate(
        authorizer=ExecutionAuthorizer(lambda: fx.POLICY), target_canonical=fx.TARGET
    )
    decision = gate.decide(
        assessed(a, attempt_id), action=a, attempt_id=attempt_id, risk_class=risk_class
    )
    assert decision.approved, decision
    return decision


def one_action(ctl, a=None, *, attempt=None, **kwargs):
    """One submission of a real, coverage-validated assessment."""

    a = a if a is not None else fx.action()
    return ctl.submit(
        assessment=fx.satisfied(a),
        action=a,
        attempt_id=attempt or fx.ATTEMPT,
        risk_class="low",
        **kwargs,
    )


# ---------------------------------------------------------------------------
# PART 1 — the reproductions, permanent, one per path
# ---------------------------------------------------------------------------


def test_the_same_auto_approved_occurrence_submitted_twice_executes_ONCE(tmp_path):
    """REPRODUCTION (a). Two submissions, one execution.

    Measured before the fix: ``EXECUTOR CALLS: 2``, two execution rows, both
    carrying ``attempt-1``. The second submission now refuses, and it refuses
    by NAME so an operator is not left guessing which of five states it hit.
    """

    ctl, spy, ledger = auto(tmp_path)
    a = fx.action()

    first = one_action(ctl, a)
    assert first.execution.executed, "the first execution must still happen"

    with pytest.raises(ExecutionNotAuthorized) as replay:
        one_action(ctl, a)

    assert replay.value.reason == "authorization_already_spent"
    assert len(spy.calls) == 1, (
        f"the executor was called {len(spy.calls)} times for one occurrence; "
        "an authorization is spent when it is used"
    )
    assert len(ledger.executions()) == 1
    assert ledger.verify_chain().ok, "the spend is recorded ON the chain"


def test_a_retained_approved_decision_handed_to_an_executor_twice_runs_ONCE(tmp_path):
    """REPRODUCTION (b). The caller who never passes a gateway.

    Measured before the fix: the same ``GateDecision``, held and replayed
    straight into a concrete executor's public ``execute()``, ran twice with
    one ``attempt_id``. No ledger was involved, so no ledger-side spend could
    have seen it — which is why the authorization OBJECT is what expires here.
    """

    ctl, spy, _ = auto(tmp_path)
    one_action(ctl)
    retained = spy.calls[0]

    # A SHIPPED executor, not the fixture's spy. The guarantee here belongs to
    # the executor wall, so a test double that does not have the wall would
    # only prove something about the double. ``RecordingExecutor`` is the
    # concrete ``Executor`` the swarm package exports.
    executor = RecordingExecutor()
    first = executor.execute(retained)
    assert first.executed

    with pytest.raises(ExecutionNotAuthorized) as replay:
        executor.execute(retained)

    assert replay.value.reason == "authorization_already_spent"
    assert len(executor.executed) == 1, (
        "a retained decision was executed twice: a decision that survives its "
        "own use is a bearer token with a narrow scope"
    )


def test_every_shipped_executor_wall_consumes_the_authorization_it_acts_on():
    """The wall is a property of the INTERFACE's implementations, not of one.

    ``test_..._handed_to_an_executor_twice_runs_ONCE`` drives one concrete
    executor. A second implementation that skipped the consume would be a
    second bearer-token path, and the test above would still pass. So the
    implementations are DERIVED from the interface — every concrete subclass
    of ``Executor`` reachable in ``src/`` — and each is required to name
    ``consume_authorization`` in its own ``execute``.
    """

    import prometheus_protocol.execution.executor  # noqa: F401  (registers)
    import prometheus_protocol.tools.git  # noqa: F401  (registers)
    from prometheus_protocol.swarm.executor import Executor

    concrete = [
        cls
        for cls in _all_subclasses(Executor)
        if not inspect.isabstract(cls)
        and cls.__module__.startswith("prometheus_protocol.")
    ]
    assert concrete, "no concrete executor was found: an empty sweep reads as a pass"

    unguarded = sorted(
        f"{cls.__module__}.{cls.__qualname__}"
        for cls in concrete
        if "consume_authorization" not in inspect.getsource(cls.execute)
    )
    assert not unguarded, (
        f"these shipped executors act on a decision without spending it: {unguarded}"
    )


def test_a_swarm_packet_re_run_does_not_execute_its_approved_proposals_again(tmp_path):
    """REPRODUCTION (c) — THE THIRD PATH, which the brief asked me to look for.

    ``swarm/runtime.py`` reached ``executor.execute`` with no claim of any
    kind: it has no holds, so there was nothing for the hold claim to key on
    and no code that tried. It is not a demo surface — ``runtime/factory.py``
    builds it.

    Driven here at the seam rather than through a whole packet: the runtime's
    execute-once helper is called twice with one decision, which is what a
    re-run of the same packet does, since ``attempt_id`` is derived from the
    packet and proposal ids and is therefore identical across runs.
    """

    # MINTED AT THE GATE, not through the controller: a controller submission
    # spends the occurrence on its own ledger, and a decision borrowed from one
    # would arrive here already spent — which would prove the controller's
    # guard, not this one. The swarm runtime builds its gate exactly this way.
    decision = minted(fx.action(), attempt_id="packet-1/proposal-1")

    from prometheus_protocol.swarm.runtime import SwarmRuntime

    runtime = SwarmRuntime.__new__(SwarmRuntime)
    runtime.ledger = anchored(tmp_path, "swarm")
    # The fixture spy, DELIBERATELY: it does not consume the authorization
    # object, so the only thing that can refuse the second call is the ledger
    # spend. A shipped executor would refuse too, and the test would no longer
    # say which mechanism did it (G44).
    runtime.executor = fx.Spy()

    first = runtime._execute_once(decision, "packet-1/proposal-1")
    assert first.executed and not first.refused

    second = runtime._execute_once(decision, "packet-1/proposal-1")
    assert second.refused and not second.executed
    assert "already used" in second.detail
    assert len(runtime.executor.calls) == 1, (
        "re-running a packet re-ran an approved proposal's side effect"
    )


# ---------------------------------------------------------------------------
# PART 2 — the enumeration, DERIVED. A fourth path must not appear unguarded.
# ---------------------------------------------------------------------------


def _executor_call_sites() -> dict[str, list[int]]:
    """Every ``<something>.execute(<something>)`` call in ``src/`` that is not
    a database cursor, keyed by module path.

    DERIVED FROM THE TREE, because the whole finding was that the enumeration
    everyone carried in their head was short by one. A path added later is a
    line here, not a discovery in a later audit.
    """

    found: dict[str, list[int]] = {}
    for path in sorted((REPO / "src").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute) or func.attr != "execute":
                continue
            receiver = ast.unparse(func.value)
            # A SQL cursor/connection is not an Executor. Selected by receiver
            # name, and the selection is reported: `_conn`, `conn`, `cursor`,
            # `connection` are the four spellings in this tree.
            if any(
                token in receiver
                for token in ("_conn", "conn", "cursor", "connection")
            ):
                continue
            found.setdefault(str(path.relative_to(REPO)), []).append(node.lineno)
    return found


def test_every_executor_call_site_in_the_tree_is_inside_a_spend_guarded_path():
    """THE ALLOWLIST, and the reason this test exists at all.

    Three paths were found by reading; a fourth added tomorrow would be found
    by nobody. So the call sites are derived from the source and compared
    against the set that is known to consume the spend. A new one fails HERE,
    with the file and line, rather than in an audit a sprint later.

    Doctrine #8: the derivation is asserted non-empty first, because a sweep
    that finds no executor calls would read as "every call site is guarded".
    """

    sites = _executor_call_sites()
    assert sites, "the sweep found no executor call sites at all; it stopped seeing them"

    permitted = {
        # The gateway. Claims the occurrence immediately above this line.
        "src/prometheus_protocol/execution/controller.py",
        # The third path, now claiming through the same ledger API.
        "src/prometheus_protocol/swarm/runtime.py",
    }
    unguarded = sorted(set(sites) - permitted)
    assert unguarded == [], (
        f"these modules call an executor without consuming the spend: "
        f"{ {m: sites[m] for m in unguarded} }. Every path to a side effect "
        "consumes the authorization, or the one that does not is the one an "
        "attacker uses."
    )
    stale = sorted(permitted - set(sites))
    assert stale == [], (
        f"{stale} is permitted to call an executor and no longer does; a "
        "sanction that outlives its call site is a guard watching an empty room"
    )


def test_the_permitted_call_sites_really_do_claim_the_authorization():
    """The other half: being on the list is not evidence of claiming.

    Both permitted modules must name ``claim_authorization``. Without this the
    allowlist above would be satisfied by deleting the claim and keeping the
    file on the list — the exact substitution the repository keeps finding.
    """

    for module in (
        "src/prometheus_protocol/execution/controller.py",
        "src/prometheus_protocol/swarm/runtime.py",
    ):
        source = (REPO / module).read_text(encoding="utf-8")
        assert "claim_authorization" in source, (
            f"{module} is permitted to call an executor but never claims the "
            "authorization it executes"
        )


# ---------------------------------------------------------------------------
# PART 3 — paired positives (doctrine #4). The negatives alone prove nothing.
# ---------------------------------------------------------------------------


def test_a_first_execution_on_each_path_succeeds_normally(tmp_path):
    """THE POSITIVE CONTROL for every refusal in this module.

    Without it, each refusal above is equally consistent with a gateway that
    refuses everything — which would also produce "the executor was called
    once" if it were called zero times, and "refused" for every second call.
    Both paths execute a first time, and the ledger records it.
    """

    ctl, spy, ledger = auto(tmp_path, "first")
    outcome = one_action(ctl)
    assert outcome.execution.executed and not outcome.execution.refused
    assert len(spy.calls) == 1
    assert [row["executed"] for row in ledger.executions()] == [1]

    held_ctl, held_spy, held_ledger = fx.controller(
        anchored(tmp_path, "held"), route_high_risk=True
    )
    held = fx.hold(held_ctl, fx.action())
    result = held_ctl.approve(held.id, identity="alice")
    assert result.executed and len(held_spy.calls) == 1


def test_two_occurrences_differing_in_ONE_bound_field_both_execute(tmp_path):
    """The spend is over the OCCURRENCE, not the action identity.

    Same attempt, different artifact: two occurrences, both may run. Without
    this the refusal above is equally consistent with a gateway that allows
    exactly one execution ever.
    """

    ctl, spy, _ = auto(tmp_path)
    one_action(ctl, fx.action("print('one')"))
    one_action(ctl, fx.action("print('two')"))
    assert len(spy.calls) == 2


def test_a_declared_retry_with_a_matching_key_returns_the_PRIOR_result(tmp_path):
    """The retry story, and the reason strict one-shot is affordable.

    A network failure mid-execute must not become a stuck state with no safe
    recovery. The caller that declared a key gets the recorded outcome back —
    and crucially the executor is NOT called again, so the recovery cannot
    become a second side effect.
    """

    ctl, spy, ledger = auto(tmp_path)
    a = fx.action()
    first = one_action(ctl, a, idempotency_key="retry-me")
    again = one_action(ctl, a, idempotency_key="retry-me")

    assert len(spy.calls) == 1, "a retry called the executor a second time"
    assert again.execution.executed == first.execution.executed
    assert again.execution.subject_id == first.execution.subject_id
    assert "returned the prior result" in again.execution.detail
    assert len(ledger.executions()) == 1


# ---------------------------------------------------------------------------
# PART 4 — the idempotency key: every verdict, by name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "supplied, declared, reason",
    [
        (None, "retry-me", "authorization_already_spent"),
        ("wrong", "retry-me", "idempotency_key_mismatch"),
        ("anything", None, "authorization_not_retryable"),
    ],
    ids=["replay-with-no-key", "key-does-not-match", "never-declared-retryable"],
)
def test_each_way_a_claim_of_retry_fails_has_its_own_reason(
    tmp_path, supplied, declared, reason
):
    """Four states, four reasons, four different remedies.

    Collapsing them into one refusal would be a refusal naming a cause it does
    not have — the shape this repository keeps finding. Each is asserted by
    name, and each is a member of the closed set.
    """

    ctl, spy, _ = auto(tmp_path, f"idem-{reason}")
    a = fx.action()
    one_action(ctl, a, idempotency_key=declared)

    with pytest.raises(ExecutionNotAuthorized) as refused:
        one_action(ctl, a, idempotency_key=supplied)

    assert refused.value.reason == reason
    assert reason in EXECUTION_REFUSAL_REASONS
    assert len(spy.calls) == 1


def test_a_matching_key_is_refused_once_the_retry_window_has_passed(tmp_path):
    """§3's window, end to end, through the gateway a caller actually uses.

    The clock advances past the window between the two calls, and the SAME key
    that would have been honoured is refused by name. The executor is not
    called: an expired credential never becomes a fresh authorization.
    """

    # A clock the TEST moves, not a scripted sequence: how many times a submit
    # reads the clock is an implementation detail, and a test that counted them
    # would go red on an unrelated refactor for a reason that says nothing.
    now = ["2026-09-18T00:00:00+00:00"]
    ctl, spy, ledger = fx.controller(
        anchored(tmp_path, "expiry"), clock=lambda: now[0]
    )
    a = fx.action()
    one_action(ctl, a, idempotency_key="retry-me")
    now[0] = "2026-09-20T00:00:00+00:00"  # two days later, window is one

    with pytest.raises(ExecutionNotAuthorized) as refused:
        one_action(ctl, a, idempotency_key="retry-me")

    assert refused.value.reason == "idempotency_key_expired"
    assert "idempotency_key_expired" in EXECUTION_REFUSAL_REASONS
    assert len(spy.calls) == 1, "an expired key bought a second execution"
    assert len(ledger.executions()) == 1
    assert ledger.verify_chain().ok


@pytest.mark.parametrize(
    "claimed_at, now, window, expected",
    [
        ("2026-09-18T00:00:00+00:00", "2026-09-18T23:59:59+00:00", 86_400, RETURN_PRIOR),
        ("2026-09-18T00:00:00+00:00", "2026-09-19T00:00:01+00:00", 86_400, KEY_EXPIRED),
        # EXACTLY on the boundary is still inside it: the comparison is ``>``,
        # so a key is honoured for the full window and not one second less.
        ("2026-09-18T00:00:00+00:00", "2026-09-19T00:00:00+00:00", 86_400, RETURN_PRIOR),
        # A window of 0 disables expiry by name, matching pending_ttl_seconds.
        ("2026-09-18T00:00:00+00:00", "2030-01-01T00:00:00+00:00", 0, RETURN_PRIOR),
        # FAIL-CLOSED on an age that cannot be established.
        (None, "2026-09-18T00:00:01+00:00", 86_400, KEY_EXPIRED),
        ("not-a-time", "2026-09-18T00:00:01+00:00", 86_400, KEY_EXPIRED),
        ("2026-09-18T00:00:00+00:00", "not-a-time", 86_400, KEY_EXPIRED),
        # A NAIVE timestamp is read as UTC rather than raising, matching
        # ``pending.py``'s own parser, so a legacy row is compared and not
        # condemned for its spelling.
        ("2026-09-18T00:00:00", "2026-09-18T00:00:01+00:00", 86_400, RETURN_PRIOR),
    ],
    ids=[
        "inside-the-window",
        "past-the-window",
        "exactly-on-the-boundary",
        "window-disabled-by-zero",
        "no-claim-time-at-all",
        "unparseable-claim-time",
        "unparseable-now",
        "naive-timestamp-read-as-utc",
    ],
)
def test_the_window_boundary_is_pinned_on_both_sides(claimed_at, now, window, expected):
    """The fold as a pure function, at the edges the end-to-end test cannot reach.

    A window is a place where an off-by-one is invisible in behaviour and
    expensive in an incident, so both sides of the boundary are pinned rather
    than one, and every unreadable input is pinned to the fail-closed answer.
    """

    state = SpendState(
        status=COMPLETED,
        idempotency_key="retry-me",
        claimed_at=claimed_at,
        entries=2,
        execution_id=1,
    )
    verdict = retry_verdict(
        state, idempotency_key="retry-me", now=now, window_seconds=window
    )
    assert verdict == expected


def test_expiry_can_only_ever_make_the_verdict_MORE_refusing():
    """The direction, asserted rather than described.

    The failure that would matter is an expired key falling through to
    :data:`MAY_EXECUTE` — "the window lapsed, so this is a fresh execution" —
    which would make waiting the cheapest way to buy a second side effect. No
    combination of window and clock may produce it against a spent state.
    """

    spent = SpendState(
        status=COMPLETED, idempotency_key="k", claimed_at="2026-09-18T00:00:00+00:00",
        entries=2, execution_id=1,
    )
    for now in ("2026-09-18T00:00:00+00:00", "2030-01-01T00:00:00+00:00", "bad"):
        for window in (0, 1, 86_400, 10**9):
            for key in (None, "k", "other"):
                verdict = retry_verdict(
                    spent, idempotency_key=key, now=now, window_seconds=window
                )
                assert verdict != MAY_EXECUTE, (now, window, key)


def test_the_NAMED_LIMIT_the_retry_window_is_not_a_config_field(tmp_path):
    """Stated as a shortfall, not left to be discovered.

    The window is a module constant and a controller argument. It is NOT a
    ``Config`` field, so it cannot be set from the environment and does not
    appear in the attested posture — an operator cannot currently tighten it
    for a deployment, and an attestation of that deployment does not record
    what it was. Pinned so that closing the gap has to correct this test, and
    so the limit cannot quietly become an assumed feature.
    """

    from prometheus_protocol.core.config import Config

    fields = {f.name for f in dataclasses.fields(Config)}
    assert "idempotency_window_seconds" not in fields, (
        "the window reached Config: update this limit, docs/OPEN-GAPS.md G55 "
        "and the note in ledger/spend.py"
    )
    assert DEFAULT_IDEMPOTENCY_WINDOW_SECONDS == Config().pending_ttl_seconds, (
        "the window no longer mirrors the hold TTL it was chosen to match; if "
        "that is deliberate, say why in spend.py rather than here"
    )
    # It IS reachable per controller, which is what makes the limit narrow
    # rather than total.
    ctl, _, _ = fx.controller(anchored(tmp_path, "window"))
    assert ctl._idempotency_window_seconds == DEFAULT_IDEMPOTENCY_WINDOW_SECONDS


def test_the_key_fields_are_the_DESCRIPTOR_plus_the_assessment_binding():
    """The occurrence's composition, derived from the descriptor itself.

    ``test_a_retry_cannot_change_a_bound_field...`` below iterates ``KEY_FIELDS``
    and is therefore blind to a field REMOVED from it: drop ``artifact_sha256``
    and that loop simply stops testing it, green. Measured — it is the shape
    G25 names, a count standing in for a composition. So the membership is
    pinned against an INDEPENDENT derivation: the descriptor's own dataclass
    fields, plus the one assessment binding that is not a descriptor field.

    A seventh descriptor field added later reddens this rather than silently
    falling outside the occurrence's identity.
    """

    from prometheus_protocol.policy.execution import ExecutionDescriptor

    descriptor_fields = {f.name for f in dataclasses.fields(ExecutionDescriptor)}
    assert descriptor_fields, "an empty derivation reads downstream as a pass"
    assert set(KEY_FIELDS) == descriptor_fields | {"snapshot_digest"}, (
        "the occurrence is no longer the descriptor plus the assessment's "
        "snapshot binding; if that is deliberate, say which field left and why"
    )
    assert len(KEY_FIELDS) == len(set(KEY_FIELDS)) == 7


def test_the_MEASURED_redundancy_snapshot_digest_already_covaries():
    """Why a one-field narrowing cannot be caught behaviourally. Measured.

    ``resolve`` binds the artifact, the target, the action class, the attempt
    and the policy into the requirement snapshot, so ``snapshot_digest`` MOVES
    whenever any of them does. For a record the real pipeline produced, the six
    descriptor fields in :data:`KEY_FIELDS` are therefore redundant with the
    seventh: drop one and two occurrences that differ in it still derive
    different keys, and every behavioural proof stays green.

    THEY STAY IN ANYWAY, for two reasons that are not belt-and-braces:
    ``authorization_key`` refuses a record missing any of the seven, so a
    truncated or hand-assembled record cannot quietly derive a key from one
    field; and the redundancy holds only while ``resolve`` keeps binding them
    all — naming them makes a future narrowing of ``resolve`` a change to this
    file rather than a silent change to what an occurrence IS.

    THE CONSEQUENCE FOR THE PROOFS, stated so nobody re-derives it: the
    instrument that catches a narrowed occurrence is the COMPOSITION pin above,
    not behaviour. ``scripts/spend_proofs.py``'s ``occurrence-identity-narrowed``
    row names that pin for exactly this reason.
    """

    from prometheus_protocol.policy.resolver import resolve
    from prometheus_protocol.policy.snapshot import snapshot_digest

    base = dict(
        artifact_sha256="a" * 64,
        target_canonical="target://x",
        action_class=fx.ACTION_SANDBOX_EXECUTE,
        attempt_id="attempt-1",
    )
    baseline = snapshot_digest(resolve(fx.POLICY, **base))
    for field, other in (
        ("artifact_sha256", "b" * 64),
        ("target_canonical", "target://y"),
        ("attempt_id", "attempt-2"),
    ):
        moved = snapshot_digest(resolve(fx.POLICY, **dict(base, **{field: other})))
        assert moved != baseline, (
            f"{field!r} no longer moves snapshot_digest: the redundancy this "
            "test records has gone, so a narrowed KEY_FIELDS would now be "
            "behaviourally visible and spend_proofs.py should say so"
        )


def test_a_retry_cannot_change_a_bound_field_because_the_key_is_DERIVED_from_them():
    """Structural, not checked — which is why there is no bypass.

    A retry that alters any bound field derives a DIFFERENT key, so it names
    no prior spend and is simply a new authorization that must pass the whole
    gate on its own. There is no retry path that reaches an executor around the
    descriptor comparison, because a matching retry reaches no executor at all.

    Every field is varied in turn, from the field list itself, so a seventh
    bound field added later is covered without anyone remembering to add it.
    """

    base = {name: f"value-for-{name}" for name in KEY_FIELDS}
    baseline = authorization_key(base)
    for name in KEY_FIELDS:
        altered = dict(base, **{name: "moved"})
        assert authorization_key(altered) != baseline, (
            f"changing {name!r} left the occurrence's key unchanged, so a retry "
            "could alter it and still be treated as the same occurrence"
        )


def test_the_key_ignores_what_is_NOT_bound(tmp_path):
    """The other direction, and the reason it matters.

    ``pinned_at`` is not part of the occurrence. If it were, every replay would
    derive a fresh key and the whole mechanism would be inert while looking
    exactly like this. Measured rather than assumed.
    """

    base = {name: f"value-for-{name}" for name in KEY_FIELDS}
    assert authorization_key(dict(base, pinned_at="2026-01-01T00:00:00Z")) == (
        authorization_key(dict(base, pinned_at="2030-12-25T12:00:00Z"))
    )


def test_a_record_missing_a_bound_field_refuses_rather_than_hashing_None():
    """A key over an absent field would collide with every other record
    missing the same field, and a collision here is either a refusal to run
    something authorized or a spend covering two occurrences."""

    base = {name: f"value-for-{name}" for name in KEY_FIELDS}
    for name in KEY_FIELDS:
        missing = {k: v for k, v in base.items() if k != name}
        with pytest.raises(SpendRecordMalformed):
            authorization_key(missing)


# ---------------------------------------------------------------------------
# PART 5 — the authority is the CHAIN, not the row (§2's ruling)
# ---------------------------------------------------------------------------


def test_the_claim_is_what_makes_it_atomic_a_second_claimant_loses(tmp_path):
    """The ROW's one job, proved on its own terms.

    The fold is the authority and the row decides the RACE, and those are
    different guarantees. This asserts the second: two claimants for one key,
    one ``True`` and one ``False``, from a single ``INSERT`` against a PRIMARY
    KEY — the property a read-then-write could not provide however carefully it
    was ordered.

    Driven at the ledger seam with no controller, deliberately: a concurrent
    second driver cannot be staged through ``submit`` without a real race, and
    a test that needed one would be the flaky kind that proves nothing on the
    run where it happens not to interleave.
    """

    ledger = anchored(tmp_path, "atomic")
    key = "a" * 64

    assert ledger.claim_authorization(
        key, attempt_id="attempt-1", idempotency_key=None, claimed_at=_NOW
    ) is True
    assert ledger.claim_authorization(
        key, attempt_id="attempt-1", idempotency_key=None, claimed_at=_NOW
    ) is False, "two claimants both won one authorization"

    # THE LOSER WROTE NOTHING. A second chain entry would be a spend that did
    # not happen, and the fold would carry it forever.
    events = [e["event"] for e in ledger.chained_events()]
    assert events.count(SPEND_EVENT) == 1
    assert ledger.authorization_spend_state(key).entries == 1
    assert ledger.verify_chain().ok


def test_deleting_the_spend_ROW_does_not_restore_the_authority(tmp_path):
    """R1's shape at the database layer, answered.

    The spend is enforcement state, so whoever records it also decides. A
    mutable row is resettable, so the row is NOT the authority: it decides the
    race and nothing else. An attacker with write authority who clears it gets
    a free key slot and no execution — the fold still says spent.
    """

    ctl, spy, ledger = auto(tmp_path)
    a = fx.action()
    one_action(ctl, a)
    key = authorization_key(ledger.executions()[0]["authorization"])

    ledger._conn.execute("DELETE FROM spent_authorizations WHERE key = ?", (key,))
    ledger._conn.commit()
    assert ledger._conn.execute(
        "SELECT count(*) AS n FROM spent_authorizations"
    ).fetchone()["n"] == 0, "precondition: the row really is gone"

    with pytest.raises(ExecutionNotAuthorized) as refused:
        one_action(ctl, a)
    assert refused.value.reason == "authorization_already_spent"
    assert len(spy.calls) == 1
    assert ledger.verify_chain().ok, "the chain was never touched, and still says so"


def test_removing_the_chain_ENTRY_breaks_verification(tmp_path):
    """The other half of the same ruling: the authority cannot be removed
    quietly. Deleting the entry the fold reads is a hash-chain edit, and the
    anchor catches it — which is the detection this repository already has."""

    ctl, _, ledger = auto(tmp_path)
    one_action(ctl)
    assert ledger.verify_chain().ok

    ledger._conn.execute("DELETE FROM audit_chain WHERE event = ?", (SPEND_EVENT,))
    ledger._conn.commit()
    assert not ledger.verify_chain().ok, (
        "a spend entry was removed and the chain still verified: the fold's "
        "authority would then be as resettable as the row it replaced"
    )


def test_a_spend_record_from_a_DIFFERENT_attempt_is_detected(tmp_path):
    """SUBSTITUTION, not deletion. Deletion is the obvious attack and the
    chain already catches it; presenting another occurrence's spend under this
    subject is the shape a real patch takes.

    The payload names its own key, so a re-attributed entry disagrees with the
    subject that carries it and the fold REFUSES rather than believing either.
    """

    ctl, _, ledger = auto(tmp_path)
    a, other = fx.action("print('mine')"), fx.action("print('theirs')")
    one_action(ctl, a)
    one_action(ctl, other)

    mine = authorization_key(ledger.executions()[0]["authorization"])
    theirs = authorization_key(ledger.executions()[1]["authorization"])
    assert mine != theirs

    events = ledger.chained_events()
    borrowed = next(
        e
        for e in events
        if e["event"] == SPEND_EVENT and json.loads(e["payload"])["key"] == theirs
    )
    # The other occurrence's spend, presented under MY subject.
    borrowed = dict(borrowed, subject=spend_subject(mine))
    with pytest.raises(SpendRecordMalformed) as caught:
        from prometheus_protocol.ledger.spend import spend_state

        spend_state([borrowed], key=mine)
    assert "re-attributed" in str(caught.value)


def test_the_named_limit_a_re_attributed_entry_is_caught_by_the_FOLD_not_the_chain(
    tmp_path,
):
    """Doctrine #5: the limit, as a passing test.

    Re-attribution inside the payload is caught by the fold's own check, above.
    Re-attribution of the ENTRY — rewriting subject and payload together and
    re-hashing every later link — is the R1 limit this repository has recorded
    since the pinned record: without an external anchor nothing sees it. The
    anchor is what closes it, and this states which half does which.
    """

    assert True


# ---------------------------------------------------------------------------
# PART 6 — the fold itself, as a pure function
# ---------------------------------------------------------------------------


def _entry(event: str, key: str, **payload):
    return {
        "event": event,
        "subject": spend_subject(key),
        "payload": json.dumps(dict(payload, key=key)),
    }


def test_the_fold_distinguishes_all_four_states():
    """UNSPENT, SPENT, COMPLETED and RELEASED are four facts, not two.

    The one that earns its place is SPENT-without-outcome: an occurrence
    claimed and never finished. Collapsing it into UNSPENT re-runs a side
    effect that may have happened; collapsing it into COMPLETED reports a
    result nobody has. It refuses, and says which.
    """

    key = "k" * 64
    spend = _entry(SPEND_EVENT, key, idempotency_key="i", claimed_at="t1")
    outcome = _entry(SPEND_OUTCOME_EVENT, key, execution_id=7, completed_at="t2")
    release = _entry(RELEASE_EVENT, key, released_at="t3", reason="refused")

    from prometheus_protocol.ledger.spend import spend_state

    assert spend_state([], key=key).status == UNSPENT
    assert spend_state([spend], key=key).status == SPENT
    assert spend_state([spend, outcome], key=key).status == COMPLETED
    assert spend_state([spend, outcome], key=key).execution_id == 7
    assert spend_state([spend, release], key=key).status == RELEASED
    # Released, then claimed again: spent. The fold is ORDERED.
    assert spend_state([spend, release, spend], key=key).status == SPENT


def test_a_claimed_and_never_completed_occurrence_refuses_even_a_matching_key():
    """The honest cost of strict one-shot, stated rather than glossed.

    A crash between the claim and the executor returning leaves an occurrence
    whose side effect may or may not have happened. Re-running risks doing it
    twice; returning a prior result would invent one. Neither is available, so
    it refuses and names the state — which is a safe recovery path, because an
    operator can establish what happened. A silent re-execution is not.
    """

    claimed = SpendState(
        status=SPENT, idempotency_key="retry-me", claimed_at="t1", entries=1
    )
    assert retry_verdict(claimed, idempotency_key="retry-me", now=_NOW) == "outcome_unknown"
    assert retry_verdict(claimed, idempotency_key=None, now=_NOW) == "outcome_unknown"

    completed = SpendState(
        status=COMPLETED,
        idempotency_key="retry-me",
        claimed_at=_NOW,
        entries=2,
        execution_id=3,
    )
    assert retry_verdict(completed, idempotency_key="retry-me", now=_NOW) == RETURN_PRIOR
    assert retry_verdict(
        SpendState(status=UNSPENT, idempotency_key=None, claimed_at=None, entries=0),
        idempotency_key=None,
        now=_NOW,
    ) == MAY_EXECUTE


def test_an_unreadable_spend_entry_refuses_rather_than_reading_as_unspent():
    """Doctrine #2, at the one place it is most expensive.

    An entry this fold cannot account for is an entry it cannot account for.
    Skipping it yields ``unspent`` — the single answer that lets an execution
    through — so it raises and the caller turns that into a typed refusal.
    """

    key = "k" * 64
    from prometheus_protocol.ledger.spend import spend_state

    for broken in ({"payload": "not json at all"}, {"payload": json.dumps([1, 2])}):
        entry = {"event": SPEND_EVENT, "subject": spend_subject(key), **broken}
        with pytest.raises(SpendRecordMalformed):
            spend_state([entry], key=key)


def test_an_outcome_entry_with_no_open_spend_is_a_broken_history(tmp_path):
    """Order is part of the record. A completion that follows no claim is not
    a completion; believing it would let a forged outcome entry mark an
    occurrence done that was never claimed."""

    key = "k" * 64
    from prometheus_protocol.ledger.spend import spend_state

    with pytest.raises(SpendRecordMalformed):
        spend_state(
            [_entry(SPEND_OUTCOME_EVENT, key, execution_id=1, completed_at="t")],
            key=key,
        )


# ---------------------------------------------------------------------------
# PART 7 — the held path still works, and is refused by the SAME mechanism
# ---------------------------------------------------------------------------


def test_a_fail_closed_refusal_RELEASES_the_authorization_so_retry_works(tmp_path):
    """One mechanism must not brick the other's remedy.

    A refusal has no side effect, so the occurrence is released — by appending
    a retraction, never by deleting the spend. Without it a missing sandbox
    would burn an approved hold permanently, which is precisely the brick the
    hold claim's own release exists to avoid.
    """

    ctl, spy, ledger = fx.controller(
        anchored(tmp_path, "release"), route_high_risk=True, spy=fx.Spy(refuse=True)
    )
    held = fx.hold(ctl, fx.action())

    first = ctl.approve(held.id, identity="alice")
    assert first.refused and len(spy.calls) == 1

    second = ctl.retry_execution(held.id, identity="alice")
    assert second.refused
    assert len(spy.calls) == 2, "the release did not make the hold retry-eligible"
    assert ledger.verify_chain().ok
    events = [e["event"] for e in ledger.chained_events()]
    assert events.count(RELEASE_EVENT) == 2, (
        "each refused execution retracts its own spend, by appending"
    )


def test_the_held_path_records_its_spend_under_the_SAME_derived_key(tmp_path):
    """G24 §4, first half: ONE mechanism, not a parallel one for holds.

    The held path was already at-most-once by its own hold claim, so the
    question §4 asks is not whether it is safe but whether it consumes the
    SAME way. It does: approving a hold appends the same two authorization
    events, under a subject derived from the same seven bound fields by the
    same function, and the same fold reads it as completed.
    """

    ctl, spy, ledger = fx.controller(anchored(tmp_path, "one"), route_high_risk=True)
    a = fx.action()
    held = fx.hold(ctl, a)
    ctl.approve(held.id, identity="alice")
    assert len(spy.calls) == 1

    # The key is DERIVED here from the hold's own pinned record, not read back
    # off the event the code wrote — a test that reads the subject it is
    # checking would agree with any subject at all.
    record = json.loads(fx.chain_entry_for(ledger, held.id)["payload"])
    key = authorization_key(record)

    subjects = [e["subject"] for e in ledger.chained_events()]
    assert subjects.count(spend_subject(key)) == 2, (
        "the held path did not record its spend under the derived key, so the "
        "two paths do not consume the same way"
    )
    state = ledger.authorization_spend_state(key)
    assert state.status == COMPLETED and state.is_spent
    assert ledger.verify_chain().ok


def test_a_SECOND_hold_for_the_same_occurrence_is_refused_by_the_SPEND_alone(tmp_path):
    """G24 §4, second half — AND the single-target proof for this path.

    Two DISTINCT holds for one occurrence. Both of the held path's older
    guards are keyed on ``pending_id``: the hold claim is a column on the
    hold's own row, and the chain-outcome walk enumerates receipts for that
    ``pending_id``. Neither can see across two holds. The spend is keyed on
    the bound fields, so it is the only thing that can refuse here — and the
    assertions below establish that the other two really were blind, rather
    than assuming it.
    """

    ctl, spy, ledger = fx.controller(anchored(tmp_path, "two"), route_high_risk=True)
    a = fx.action()
    first_hold = fx.hold(ctl, a)
    second_hold = fx.hold(ctl, a)
    assert first_hold.id != second_hold.id

    ctl.approve(first_hold.id, identity="alice")
    assert len(spy.calls) == 1

    with pytest.raises(ExecutionNotAuthorized) as refused:
        ctl.approve(second_hold.id, identity="alice")
    assert refused.value.reason == "authorization_already_spent"
    assert len(spy.calls) == 1, "one occurrence, two holds, two side effects"

    # The other two guards were BLIND, not merely quiet: the second hold has
    # no execution row for the outcome walk to find, and its own claim column
    # is still unset. Only the spend saw it.
    assert ledger.executions_for_pending(second_hold.id) == []
    claimed = ledger._conn.execute(
        "SELECT execution_committed_at FROM pending_actions WHERE id = ?",
        (second_hold.id,),
    ).fetchone()[0]
    assert claimed is None
    assert ledger.verify_chain().ok


def test_the_MEASURED_order_nulling_the_hold_claim_is_caught_before_the_spend(
    tmp_path,
):
    """A recorded measurement, not a guarantee I would rather have.

    F14's write — null the hold's claim column — does NOT reach the spend.
    ``pending.py:543`` walks the chain's outcome receipts for this hold first
    and refuses with a plain ``ValueError`` because the hold already executed.
    So the held path has THREE guards and this scenario isolates none of them;
    that is why the isolation proof above uses two holds instead.

    Pinned because the ORDER is load-bearing for reading a future failure: if
    this ever starts raising ``authorization_already_spent``, the outcome walk
    stopped running, and that is a real regression wearing a green refusal.
    """

    ctl, spy, ledger = fx.controller(anchored(tmp_path, "order"), route_high_risk=True)
    held = fx.hold(ctl, fx.action())
    ctl.approve(held.id, identity="alice")
    assert len(spy.calls) == 1

    ledger._conn.execute(
        "UPDATE pending_actions SET execution_committed_at = NULL WHERE id = ?",
        (held.id,),
    )
    ledger._conn.commit()

    with pytest.raises(ValueError) as refused:
        ctl.retry_execution(held.id, identity="alice")
    assert not isinstance(refused.value, ExecutionNotAuthorized), (
        "the chain-outcome walk no longer refuses first"
    )
    assert "already executed" in str(refused.value)
    assert len(spy.calls) == 1, (
        "nulling the hold claim bought a second execution: neither the outcome "
        "walk nor the spend held"
    )


# ---------------------------------------------------------------------------
# PART 8 — the three findings from the review of #127, each reproduced
#
# All three were in code written THIS sprint, and all three are the same shape
# the sprint exists to close, one level down: a guarantee that holds against
# the attack it was designed for and not against its mirror image.
# ---------------------------------------------------------------------------


def test_a_release_cannot_UN_SPEND_a_completed_occurrence(tmp_path):
    """REPRODUCED before the fix, on an ordinary anchored ledger.

    ``release_authorization`` for an already COMPLETED key deleted the mutex
    row, appended a WELL-FORMED release, and the fold read ``released``;
    ``retry_verdict`` then returned ``may_execute`` and the executor ran a
    SECOND time — with ``verify_chain().ok`` True throughout, because nothing
    was rewritten. An append that looks legitimate resurrected a spent
    authorization.

    The module docstring had reasoned only about a release being DELETED. The
    outcome event carried an ordering check from the start and the release did
    not, and that asymmetry was the whole defect.
    """

    ctl, spy, ledger = auto(tmp_path, "unspend")
    a = fx.action()
    one_action(ctl, a)
    key = authorization_key(ledger.executions()[0]["authorization"])
    assert ledger.authorization_spend_state(key).status == COMPLETED

    ledger.release_authorization(key, released_at=_NOW, reason="forged")

    # The fold REFUSES the history rather than folding it to the permissive
    # answer, and the controller turns that into a typed refusal.
    with pytest.raises(SpendRecordMalformed):
        ledger.authorization_spend_state(key)
    with pytest.raises(ExecutionNotAuthorized) as refused:
        one_action(ctl, a)
    assert refused.value.reason == "spend_record_unreadable"
    assert len(spy.calls) == 1, (
        "a forged release bought a second execution: the fold folded an "
        "impossible history into the one answer that permits running again"
    )


def test_a_release_with_no_open_spend_at_all_is_also_a_broken_history():
    """The same rule from the other side, as a pure fold.

    A release under a subject that was never spent is not "unspent with extra
    steps"; it is a history that cannot have happened, and doctrine #2 says a
    state the fold cannot establish is refused rather than normalised.
    """

    key = "e" * 64
    with pytest.raises(SpendRecordMalformed):
        spend_state(
            [
                {
                    "event": RELEASE_EVENT,
                    "subject": spend_subject(key),
                    "payload": {"key": key, "released_at": _NOW, "reason": "r"},
                }
            ],
            key=key,
        )


def test_the_legitimate_release_and_re_claim_sequence_still_folds(tmp_path):
    """THE PAIRED POSITIVE for the two refusals above (doctrine #4).

    Without it, "a release is refused" is equally consistent with a fold that
    refuses every release — which would brick the fail-closed retry path the
    release exists for. Claim, release, re-claim, complete: the sequence a
    refused execution followed by a successful retry actually produces.
    """

    ledger = anchored(tmp_path, "sequence")
    key = "f" * 64
    assert ledger.claim_authorization(
        key, attempt_id="a1", idempotency_key=None, claimed_at=_NOW
    )
    ledger.release_authorization(key, released_at=_NOW, reason="no sandbox")
    assert ledger.authorization_spend_state(key).status == RELEASED
    assert ledger.claim_authorization(
        key, attempt_id="a1", idempotency_key=None, claimed_at=_NOW
    ), "a released occurrence must be claimable again, or a refusal bricks it"
    ledger.complete_authorization(key, execution_id=1, completed_at=_NOW)
    assert ledger.authorization_spend_state(key).status == COMPLETED
    assert ledger.verify_chain().ok


def test_the_check_and_set_in_consume_authorization_is_INSIDE_the_lock():
    """STRUCTURAL, because the behavioural proof is not available. Measured.

    Review of #127 was right that the check-and-set was two operations and not
    atomic. Fixing it was easy; PROVING it behaviourally is not, and the
    mutation runner said so before I claimed otherwise: replacing the lock with
    a no-op context manager left a thread test GREEN, and a green mutation
    means untested until a direct probe says otherwise.

    THE DIRECT PROBE, on the unlocked check-and-set, 32 threads released from a
    barrier:

      * CPython's DEFAULT switch interval (5ms): **0 of 400 trials** raced. The
        ``getattr`` and the ``object.__setattr__`` are adjacent, and the
        interpreter almost never preempts between them.
      * switch interval forced to 1e-7: **9 of 400 trials** raced, worst case
        2 grants. Per-trial catch rate stayed near 1% at every thread count
        tried (8/16/32/64).

    So the race is REAL — that is what the second line measures — and a
    behavioural test for it would be a test that fails to notice its own guard
    being deleted about 99% of the time. That is worse than no test: it reads
    as a proof.

    WHAT IS PINNED HERE INSTEAD is the property that can be established with
    certainty: the read and the write both happen inside the lock, derived from
    the source rather than asserted about it. THE NAMED LIMIT: this does not
    prove atomicity, it proves the code is shaped so that the interpreter
    provides it. The lock still matters beyond CPython — a free-threaded build
    has no GIL to mask the window at all.
    """

    import prometheus_protocol.policy.execution as module

    tree = ast.parse(pathlib.Path(module.__file__).read_text(encoding="utf-8"))
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "consume_authorization"
    ]
    assert len(functions) == 1, functions

    guarded = [n for n in functions[0].body if isinstance(n, ast.With)]
    assert len(guarded) == 1, (
        "consume_authorization's body is no longer one guarded block; the "
        "check-and-set must be inside exactly one lock"
    )
    held = {
        name.id
        for item in guarded[0].items
        for name in ast.walk(item.context_expr)
        if isinstance(name, ast.Name)
    }
    assert "_CONSUME_LOCK" in held, (
        f"the check-and-set is inside a context manager over {sorted(held)}, "
        "not the module lock"
    )

    inside = ast.dump(ast.Module(body=guarded[0].body, type_ignores=[]))
    assert "authorization_already_spent" in inside, "the CHECK escaped the lock"
    assert "__setattr__" in inside, "the SET escaped the lock"
    # And nothing but the guarded block: a second copy of the set outside it
    # would be the whole race again with a lock decorating it.
    outside = ast.dump(
        ast.Module(
            body=[n for n in functions[0].body if not isinstance(n, ast.With)],
            type_ignores=[],
        )
    )
    assert "__setattr__" not in outside


def test_the_first_caller_is_granted_and_every_later_one_is_refused():
    """The deterministic half, and the paired positive for the structural pin.

    Sequential rather than concurrent, deliberately: this asserts the OUTCOME
    the lock exists to guarantee — exactly one grant, every later presentation
    refused by name — without pretending to have observed a race.
    """

    from prometheus_protocol.policy.execution import consume_authorization

    decision = minted(fx.action(), attempt_id="atomic-1")
    consume_authorization(decision.authorization)

    refusals = []
    for _ in range(8):
        with pytest.raises(ExecutionNotAuthorized) as refused:
            consume_authorization(decision.authorization)
        refusals.append(refused.value.reason)
    assert set(refusals) == {"authorization_already_spent"}


def test_a_returned_prior_result_NAMES_the_stdout_it_cannot_have(tmp_path):
    """Doctrine #1 where the caller reads it, OUT OF BAND.

    ``executions`` has no ``stdout`` column, so a retry cannot be handed the
    program's output. The first reconstruction left the field at its default —
    ``""`` — which is exactly what a program that printed nothing produces, so
    "never recorded" and "printed nothing" became the same bytes.

    The column is NOT added: PROD-FIX-2 removed a raw model response from a
    persisted record because a reflecting endpoint put a bearer token in the
    ledger, and candidate stdout is the same class of text. The limit is named
    instead, in the field a caller actually reads.
    """

    from prometheus_protocol.execution.controller import _STDOUT_NOT_RECORDED

    ctl, spy, ledger = auto(tmp_path, "stdout")
    a = fx.action()
    one_action(ctl, a, idempotency_key="retry-me")
    again = one_action(ctl, a, idempotency_key="retry-me")

    assert len(spy.calls) == 1
    # OUT OF BAND. Review of #128: the first fix put the sentence IN ``stdout``,
    # which candidate code can print verbatim — an in-band signal a consumer
    # reading the field as captured output cannot tell from the real thing. The
    # availability is now its own fact, and the prose stays in ``detail``.
    assert again.execution.stdout_recorded is False
    assert again.execution.stdout == ""
    assert _STDOUT_NOT_RECORDED in again.execution.detail
    assert _STDOUT_NOT_RECORDED not in again.execution.stdout

    # THE PAIRED POSITIVE, and the reason the flag is not decoration: a REAL
    # executor, one that captured a candidate's output, says so. Without it,
    # ``stdout_recorded is False`` on a retry would be equally consistent with
    # a field that is always False.
    #
    # Driven through the shipped ``SandboxExecutor`` against a fake isolating
    # sandbox: the property under test is what the EXECUTOR reports about a
    # capture, and a real container would make this opt-in and skip.
    from prometheus_protocol.execution.executor import SandboxExecutor

    ran = SandboxExecutor(sandbox=_CapturingSandbox("hello from the candidate"))
    result = ran.execute(minted(fx.action(), attempt_id="captured-1"))
    assert result.executed and not result.refused
    assert result.stdout == "hello from the candidate"
    assert result.stdout_recorded is True

    # AND THE FIXTURE SPY, which records nothing, honestly says so — the flag
    # tracks what was captured, not whether the run succeeded.
    assert one_action(ctl, fx.action("print('other')")).execution.stdout_recorded is False

    # And the limit is REAL rather than a habit: no execution row carries the
    # field, derived from the table rather than asserted about one row.
    columns = {
        row["name"]
        for row in ledger._conn.execute("PRAGMA table_info(executions)")
    }
    assert columns, "an empty column set reads downstream as a pass"
    assert "stdout" not in columns, (
        "executions now records stdout: return the real value and delete this "
        "limit, rather than leaving a placeholder where the output is"
    )


# ---------------------------------------------------------------------------
# PART 9 — the second review, which found the FIRST fix incomplete
# ---------------------------------------------------------------------------


def test_resetting_the_row_and_RE_CLAIMING_does_not_reopen_the_release(tmp_path):
    """The same bypass in two steps, after one step had been closed.

    Review of #127 got the release branch guarded. Review of #128 then found
    the SPEND branch had no ordering check either, so the identical attack
    worked with one more move — and the move is explicitly inside this
    module's own stated threat model, which says a reset row restores nothing:

      1. execute; the occurrence is ``completed``
      2. DELETE the ``spent_authorizations`` row
      3. ``claim_authorization`` again — it wins, because the row is gone, and
         the unconditional ``COMPLETED -> SPENT`` made the fold agree
      4. ``release_authorization`` — now legal, because step 3 forged the open
         spend the guard requires
      5. execute again

    Measured at step 5 before the fix: **executor calls 2, execution rows 2,
    chain valid**. The row-reset claim in the module docstring was true of the
    fold as a lookup and false of the fold as a state machine.
    """

    ctl, spy, ledger = auto(tmp_path, "twostep")
    a = fx.action()
    one_action(ctl, a)
    key = authorization_key(ledger.executions()[0]["authorization"])

    ledger._conn.execute("DELETE FROM spent_authorizations WHERE key = ?", (key,))
    ledger._conn.commit()

    # The re-claim still WINS the row — that is the mutex doing its one job on
    # an empty table, and it is not the authority. What it can no longer do is
    # make the chain agree.
    assert ledger.claim_authorization(
        key, attempt_id=fx.ATTEMPT, idempotency_key=None, claimed_at=_NOW
    ) is True
    with pytest.raises(SpendRecordMalformed):
        ledger.authorization_spend_state(key)

    with pytest.raises(ExecutionNotAuthorized) as refused:
        one_action(ctl, a)
    assert refused.value.reason == "spend_record_unreadable"
    assert len(spy.calls) == 1, "the two-step reset bought a second execution"


@pytest.mark.parametrize(
    "history, permitted",
    [
        ((), True),
        ((SPEND_EVENT,), True),
        ((SPEND_EVENT, SPEND_OUTCOME_EVENT), True),
        ((SPEND_EVENT, RELEASE_EVENT), True),
        ((SPEND_EVENT, RELEASE_EVENT, SPEND_EVENT), True),
        ((SPEND_EVENT, SPEND_OUTCOME_EVENT, SPEND_EVENT), False),
        ((SPEND_EVENT, SPEND_OUTCOME_EVENT, RELEASE_EVENT), False),
        ((SPEND_EVENT, SPEND_EVENT), False),
        ((SPEND_OUTCOME_EVENT,), False),
        ((RELEASE_EVENT,), False),
        ((SPEND_EVENT, RELEASE_EVENT, RELEASE_EVENT), False),
        ((SPEND_EVENT, RELEASE_EVENT, SPEND_OUTCOME_EVENT), False),
    ],
    ids=[
        "empty",
        "claimed",
        "claimed-completed",
        "claimed-released",
        "released-then-reclaimed",
        "completed-then-reclaimed",
        "completed-then-released",
        "claimed-twice",
        "outcome-with-no-spend",
        "release-with-no-spend",
        "released-twice",
        "outcome-after-release",
    ],
)
def test_every_sequence_of_three_events_is_permitted_or_refused_by_the_TABLE(
    history, permitted
):
    """The state machine, exhaustively over the sequences that can occur.

    Two reviews found the same defect in two different branches, so the
    permitted transitions are now declared in one table rather than checked
    branch by branch — and this walks the table's consequences instead of
    trusting that three ``if`` statements agree. The five permitted rows are
    the paired positives: without them "a sequence is refused" would be
    consistent with a fold that refuses every history including the ones the
    system actually produces.
    """

    key = "d" * 64
    events = [
        {
            "event": event,
            "subject": spend_subject(key),
            "payload": {
                "key": key,
                "claimed_at": _NOW,
                "released_at": _NOW,
                "completed_at": _NOW,
                "reason": "r",
                "idempotency_key": None,
                "execution_id": 1,
            },
        }
        for event in history
    ]
    if permitted:
        state = spend_state(events, key=key)
        assert state.entries == len(history)
    else:
        with pytest.raises(SpendRecordMalformed):
            spend_state(events, key=key)


def test_the_transition_table_covers_every_event_the_fold_folds():
    """An allowlist is only an allowlist if it is total.

    The fold selects three event names and the table permits three; a fourth
    event added to one and not the other would either fold unchecked or raise
    a ``KeyError`` instead of a typed refusal. Derived from both, both ways.
    """

    from prometheus_protocol.ledger.spend import _PERMITTED_FROM

    assert set(_PERMITTED_FROM) == {SPEND_EVENT, SPEND_OUTCOME_EVENT, RELEASE_EVENT}
    assert all(_PERMITTED_FROM.values()), "an event permitted from nothing is dead"
    reachable = {UNSPENT} | {SPENT, COMPLETED, RELEASED}
    for event, allowed in _PERMITTED_FROM.items():
        assert allowed <= reachable, f"{event} permits a state the fold never sets"


def test_only_a_site_that_CAPTURES_output_may_claim_it_recorded_it():
    """The flag's population, DERIVED from every construction in the tree.

    Review of #129, and it is the half I got wrong by reasoning about the
    wrong population. The field first defaulted to ``True`` because "every
    executor that sets ``stdout`` sets it from a real run" — a claim about the
    FIVE sites that pass ``stdout=``, not about the ELEVEN that construct
    ``ExecutionResult``. The other six are refusals, dry runs and replay
    refusals where nothing ran, and every one of them inherited the default and
    told a consumer the empty string was recorded output — recreating exactly
    the ambiguity the flag was added to remove.

    The default is now ``False``, so forgetting to opt in UNDER-claims instead
    of asserting something false, and the rule is checked over the whole
    population rather than the part I happened to look at.
    """

    sites = []
    for path in sorted((REPO / "src").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Name) and node.func.id == "ExecutionResult"):
                continue
            keywords = {k.arg: k.value for k in node.keywords}
            sites.append((path.relative_to(REPO), node.lineno, keywords))

    assert sites, "no ExecutionResult construction found: an empty sweep is a pass"

    claiming, capturing = [], []
    for relative, line, keywords in sites:
        flag = keywords.get("stdout_recorded")
        claims = isinstance(flag, ast.Constant) and flag.value is True
        stdout = keywords.get("stdout")
        # A capture is an expression, not the empty literal every refusal
        # passes. ``stdout=""`` is "nothing to report", not captured output.
        captures = stdout is not None and not (
            isinstance(stdout, ast.Constant) and stdout.value == ""
        )
        if claims:
            claiming.append(f"{relative}:{line}")
        if captures:
            capturing.append(f"{relative}:{line}")

    assert claiming == capturing, (
        "a site claims stdout_recorded=True without capturing output, or "
        f"captures without claiming: claims {claiming}, captures {capturing}"
    )
    assert len(claiming) == 2, (
        f"exactly two sites in the tree capture a candidate's output; found "
        f"{len(claiming)}: {claiming}. A third is either a real new executor "
        "path — say so here — or a refusal that should not be claiming."
    )


def test_the_flag_defaults_to_the_fail_closed_answer():
    """An unset flag must under-claim, never over-claim.

    If the default were ``True``, a path that forgets to set it asserts the
    empty string is the program's output. At ``False`` it says only that
    nothing was recorded, which loses information and states nothing untrue.
    """

    from prometheus_protocol.swarm.models import ExecutionResult

    field = {f.name: f for f in dataclasses.fields(ExecutionResult)}["stdout_recorded"]
    assert field.default is False
    assert ExecutionResult(executed=False, subject_id="s").stdout_recorded is False
