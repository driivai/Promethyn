"""The grounding loop: what closes, what structurally cannot, and who decides.

This demo runs claims through the REAL chain — grounding judge, verifier
bank, action gate, execution controller, sandbox executor, ledger — in the
first domain with NO HARD VERIFIER. It demonstrates the structural finding of
the grounding sprint:

* **A soft-only judgment can never authorize an action.** The bank marks any
  judgment grounded only in SOFT evidence non-authoritative, and the gate
  blocks every non-authoritative judgment — no matter how confident the
  grounding judge sounds. There is nothing to configure and nothing to
  bypass; autonomy without authoritative truth is not reachable in this
  architecture. The human backstop is therefore not a policy choice in this
  domain — it is the only path to action at all.
* **The human is the authoritative tier.** A human grounding review enters as
  ``Tier.HUMAN`` evidence; the bank fuses it with the judge's advisory
  evidence, the human decides the verdict, and the judge is CALIBRATED
  against the human's decision — exactly as the sandbox calibrates the code
  judge. Over time the judge earns advisory weight; it never earns authority.
* **Everything is recorded.** The blocked soft-only attempt, the human
  decision, the executed publish, and the blocked ungrounded claim all land
  in the same ledger the other domains use.

The model is FROZEN and offline: the proposer's claims and the judge's
replies are scripted (an honest simulation, as in every offline demo). The
verdict fusion, the gate decisions, the sandboxed execution, and the ledger
rows are all real.
"""

from __future__ import annotations

import argparse
from typing import Callable, Sequence

from prometheus_protocol.benchmarks.grounding_eval import (
    ScriptedGroundingJudgeProvider,
)
from prometheus_protocol.benchmarks.grounding_items import (
    build_grounding_items,
    task_for,
)
from prometheus_protocol.core.models import (
    ACTION_PYTHON_CODE,
    Evidence,
    ExecutableAction,
    Tier,
    Unavailable,
    Verdict,
)
from prometheus_protocol.core.reporting import render_judgment, render_outcome
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.executor import SandboxExecutor
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.sandbox import NamespaceSandbox
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.grounding import GroundingVerifier
from prometheus_protocol.policy.coverage import BoundResult
from prometheus_protocol.policy.profile import PolicyRequirement, VerificationPolicy
from prometheus_protocol.policy.resolver import resolve
from prometheus_protocol.policy.snapshot import ACTION_SANDBOX_EXECUTE, snapshot_digest
from prometheus_protocol.swarm.models import content_hash


# ---------------------------------------------------------------------------
# PHASE-1.2b — the demos go through the policy layer, like everything else.
# ---------------------------------------------------------------------------

def _demo_policy(check_id: str, *implementations: str) -> VerificationPolicy:
    """A policy VALUE naming this demo's own verifiers (R1).

    A demo is a deployment like any other: it decides which implementations may
    satisfy its requirements. Naming them here is that decision made explicitly,
    and it is what lets the demo authorize anything at all now that a raw
    verdict cannot.
    """

    return VerificationPolicy(
        policy_id="demo",
        version=1,
        requirements=(
            PolicyRequirement(
                check_id=check_id,
                permitted=tuple(implementations),
                applies_to=(ACTION_SANDBOX_EXECUTE,),
            ),
        ),
        require_verification=(ACTION_SANDBOX_EXECUTE,),
    )


def _assess(bank, policy, check_id, outcomes, *, subject_id: str, artifact: str):
    """Resolve, bind every outcome to the snapshot, and let the bank decide."""

    snapshot = resolve(
        policy,
        artifact_sha256=content_hash(artifact),
        target_canonical="sandbox://demo",
        action_class=ACTION_SANDBOX_EXECUTE,
        attempt_id=subject_id,
    )
    digest = snapshot_digest(snapshot)
    return bank.assess(snapshot, [
        BoundResult(
            check_id=check_id,
            snapshot_digest=digest,
            implementation=outcome.verifier_id,
            outcome=outcome,
        )
        for outcome in outcomes
    ])


HUMAN_REVIEWER_ID = "human-grounding-review"

#: The demo's scripted judge replies, keyed by item id (see grounding_items):
#: a confident SUPPORTED on the grounded claim, a confident NOT-SUPPORTED on
#: the unstated-causation trap, and a malformed reply that parses to ABSTAIN.
_DEMO_REPLIES = {
    "g01": "SUPPORTED 0.9",
    "g06": "NOT-SUPPORTED 0.85",
    "g33": "The claim seems fine to me.",
}


def human_review(verdict: Verdict, *, reviewer: str, note: str) -> Evidence:
    """A human grounding decision as authoritative HUMAN-tier evidence."""

    return Evidence(
        passed=(verdict == Verdict.PASS),
        total=1,
        passed_count=1 if verdict == Verdict.PASS else 0,
        failures=() if verdict == Verdict.PASS else (note,),
        verifier_id=HUMAN_REVIEWER_ID,
        verdict=verdict,
        tier=Tier.HUMAN,
        detail=f"{reviewer}: {note}",
    )


def _publish_action(claim: str) -> ExecutableAction:
    """The downstream action a grounded claim would authorize: publish it."""

    return ExecutableAction(
        kind=ACTION_PYTHON_CODE, code=f"print({claim!r})"
    )


def run_loop(*, out: Callable[[str], None] = print) -> dict:
    items = {i.item_id: i for i in build_grounding_items()}
    grounded = items["g01"]        # gold: supported (free admission)
    ungrounded = items["g06"]      # gold: not-supported (unstated causation)
    unparseable = items["g33"]     # judge reply will be malformed

    judge = GroundingVerifier(
        ScriptedGroundingJudgeProvider(list(items.values()), _DEMO_REPLIES)
    )
    bank = VerifierBank()
    bank.register(judge.verifier_id, judge.tier)
    bank.register(HUMAN_REVIEWER_ID, Tier.HUMAN)
    policy = _demo_policy("grounding.claim", judge.verifier_id, HUMAN_REVIEWER_ID)
    ledger = SqliteLedger(":memory:")
    controller = ExecutionController(
        gate=ActionGate(escalate_below=0.75, route_high_risk=True),
        executor=SandboxExecutor(),
        ledger=ledger,
    )
    summary: dict = {}

    out("=== beat 1: the judge alone — confident, and still not enough ===")
    out(f"[loop] claim   : {grounded.claim!r}")
    soft = judge.verify(code=grounded.claim, task=task_for(grounded))
    out(f"[loop] judge   : {render_outcome(soft)} (SOFT tier)")
    assessment = _assess(bank, policy, "grounding.claim", [soft],
                         subject_id=f"publish:{grounded.item_id}", artifact=grounded.claim)
    judgment = assessment.outcome
    out(f"[loop] bank    : {render_judgment(judgment)}")
    if isinstance(judgment, Unavailable):
        # PHASE-1.2b — falls THROUGH rather than returning. Coverage can now
        # refuse a beat (an unavailable or abstaining required check), and a
        # return here would abandon the remaining beats and the ledger audit.
        # Every beat renders; each records its own outcome.
        out("[loop] gate    : NOT SUBMITTED — there is no judgment to authorize on")
        summary["soft_only"] = {"outcome": "unavailable", "executed": False}
    else:
        if bank.needs_escalation(judgment):
            out("[loop] bank    : advisory judgment below the escalation bar -> "
                "human review is required")
        outcome = controller.submit(
            assessment=assessment,
            action=_publish_action(grounded.claim),
            risk_class="medium",
            subject_id=f"publish:{grounded.item_id}",
        )
        out(f"[loop] gate    : {outcome.outcome.upper()} — {outcome.decision.reason}")
        out("[loop] executed: never (soft-only evidence cannot authorize — "
            "structural, not configured)")
        summary["soft_only"] = {
            "outcome": outcome.outcome,
            "executed": bool(outcome.execution and outcome.execution.executed),
        }

    out("")
    out("=== beat 2: a human grounding review unlocks the loop ===")
    human = human_review(
        Verdict.PASS, reviewer="demo-operator",
        note="claim is entailed by the source (admission is free)",
    )
    assessment = _assess(bank, policy, "grounding.claim", [soft, human],
                         subject_id=f"publish:{grounded.item_id}", artifact=grounded.claim)
    fused = assessment.outcome
    out(f"[loop] human   : {human.decided.value} (HUMAN tier, authoritative)")
    out(f"[loop] bank    : {render_judgment(fused)} "
        f"(judge calibrated against the human decision)")
    if isinstance(fused, Unavailable):
        # PHASE-1.2b — falls THROUGH rather than returning, so every beat
        # renders and the ledger audit still runs.
        out("[loop] gate    : NOT SUBMITTED — there is no judgment to authorize on")
        summary["human_unlocked"] = {"outcome": "unavailable", "executed": False}
        execution, executed = None, False
    else:
        outcome = controller.submit(
            assessment=assessment,
            action=_publish_action(grounded.claim),
            risk_class="medium",
            subject_id=f"publish:{grounded.item_id}",
        )
        execution = outcome.execution
        executed = execution is not None and execution.executed
        out(f"[loop] gate    : {outcome.outcome.upper()} — {outcome.decision.reason}")
        if execution is not None and execution.executed:
            out(f"[loop] publish : executed in sandbox "
                f"'{execution.sandbox_name}' (exit {execution.exit_status})")
            out(f"[loop] output  : {execution.stdout.strip()!r}")
        summary["human_unlocked"] = {"outcome": outcome.outcome, "executed": executed}

    out("")
    out("=== beat 3: an ungrounded claim — judge flags it, human confirms ===")
    out(f"[loop] claim   : {ungrounded.claim!r}")
    soft_bad = judge.verify(code=ungrounded.claim, task=task_for(ungrounded))
    out(f"[loop] judge   : {render_outcome(soft_bad)} (SOFT tier)")
    human_bad = human_review(
        Verdict.FAIL, reviewer="demo-operator",
        note="the source states no cause for the closure",
    )
    assessment = _assess(bank, policy, "grounding.claim", [soft_bad, human_bad],
                         subject_id=f"publish:{ungrounded.item_id}", artifact=ungrounded.claim)
    fused_bad = assessment.outcome
    out(f"[loop] bank    : {render_judgment(fused_bad)}")
    if isinstance(fused_bad, Unavailable):
        # PHASE-1.2b — falls THROUGH rather than returning, so every beat
        # renders and the ledger audit still runs.
        out("[loop] gate    : NOT SUBMITTED — there is no judgment to authorize on")
        summary["ungrounded"] = {"outcome": "unavailable", "executed": False}
    else:
        outcome = controller.submit(
            assessment=assessment,
            action=_publish_action(ungrounded.claim),
            risk_class="medium",
            subject_id=f"publish:{ungrounded.item_id}",
        )
        out(f"[loop] gate    : {outcome.outcome.upper()} — {outcome.decision.reason}")
        summary["ungrounded"] = {
            "outcome": outcome.outcome,
            "executed": bool(outcome.execution and outcome.execution.executed),
        }

    out("")
    out("=== beat 4: a malformed judge reply is an abstention, not a verdict ===")
    soft_abstain = judge.verify(code=unparseable.claim, task=task_for(unparseable))
    out(f"[loop] judge   : {render_outcome(soft_abstain)} — reply was not a verdict")
    assessment = _assess(bank, policy, "grounding.claim", [soft_abstain],
                         subject_id=f"publish:{unparseable.item_id}", artifact=unparseable.claim)
    judgment_abstain = assessment.outcome
    if isinstance(judgment_abstain, Unavailable):
        # PHASE-1.2b — falls THROUGH to the audit rather than returning here.
        # The early return predated coverage, when this branch was unreachable
        # in the happy path; now it is the expected outcome for beat 4, and
        # returning would skip the ledger audit the demo exists to show.
        out("[loop] gate    : NOT SUBMITTED — the required check abstained, so "
            "there is no satisfactory result to authorize on")
        summary["abstain"] = {"outcome": "unavailable", "executed": False}
    else:
        outcome = controller.submit(
            assessment=assessment,
            action=_publish_action(unparseable.claim),
            risk_class="medium",
            subject_id=f"publish:{unparseable.item_id}",
        )
        out(f"[loop] gate    : {outcome.outcome.upper()} — {outcome.decision.reason}")
        summary["abstain"] = {
            "outcome": outcome.outcome,
            "executed": bool(outcome.execution and outcome.execution.executed),
        }

    out("")
    out("=== audit (from the ledger, not from memory) ===")
    executions = ledger.executions()
    executed_n = sum(1 for row in executions if row["executed"])
    out(f"[audit] executions recorded: {len(executions)} "
        f"(executed {executed_n}, blocked {len(executions) - executed_n})")
    summary["executions"] = len(executions)
    summary["executed_total"] = executed_n
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m prometheus_protocol.benchmarks.grounding_loop_demo",
        description="Grounding: soft judge advises, human decides, gate enforces.",
    )
    parser.parse_args(argv)
    if not NamespaceSandbox.available():
        print("[demo] the namespace isolation runtime is unavailable; the "
              "publish beat cannot run sandboxed, so the demo refuses to run.")
        return 1
    summary = run_loop()
    ok = (
        summary["soft_only"] == {"outcome": "block", "executed": False}
        and summary["human_unlocked"]["executed"] is True
        and summary["ungrounded"] == {"outcome": "block", "executed": False}
        # PHASE-1.2b — an abstention now refuses at COVERAGE rather than at the
        # gate. The required check produced no satisfactory result, so there is
        # nothing to authorize on and the gate is never consulted. Same
        # end state (nothing published), one decision earlier, and recorded as
        # unavailable rather than as a policy denial.
        and summary["abstain"] == {"outcome": "unavailable", "executed": False}
        and summary["executed_total"] == 1
    )
    print("[demo] " + (
        "grounding loop demonstrated: soft-only blocked, human unlocked, "
        "ungrounded blocked, abstain refused before the gate" if ok
        else "UNEXPECTED OUTCOME (see above)"
    ))
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover - exercised via main() in tests
    raise SystemExit(main())
