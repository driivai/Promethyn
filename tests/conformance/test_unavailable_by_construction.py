"""EX-1: could-not-execute is a distinct TYPE, not an abstention.

Two by-construction guarantees. Each **fails against main**, where a HARD verifier
that could not run returned ``Verdict.ABSTAIN`` and the bank aggregated around it:

1. A backend that cannot start the candidate makes the HARD verifier return an
   :class:`Unavailable` — never ``Verdict.ABSTAIN``. This is caught cold from a
   STUB sandbox, with no real container: it is exactly the failure the
   ``container-sandbox.yml`` job surfaced on a real runner (the bootstrap was
   unreadable, so ``candidate_started`` was false and a crash classified ABSTAIN),
   proven here deterministically without a daemon.
2. The bank cannot aggregate an ``Unavailable`` into a verdict. An authoritative
   verifier that could not execute is not evidence: a SOFT verdict must never
   silently stand in for it, so the bank returns the ``Unavailable``, never a
   fused advisory ``Judgment``.

The distinction is enforced by the type system too (an ``Unavailable`` has no
``verdict`` attribute — see the Hearth mypy gate), so these runtime tests and the
static gate defend the same property from both sides.
"""

from __future__ import annotations

from prometheus_protocol.core.models import (
    Case,
    Evidence,
    Task,
    Tier,
    Unavailability,
    Unavailable,
    Verdict,
)
from prometheus_protocol.sandbox import Limits
from prometheus_protocol.sandbox.base import Sandbox, SandboxResult
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.runner import SubprocessVerifier

_TASK = Task(id="t/u", entry_point="f", prompt="", split="train", cases=(Case((1,), 1),))
_OK = "def f(n):\n    return n\n"


class _CannotStartSandbox(Sandbox):
    """A STUB reporting isolation never started — no real container required."""

    name = "cannot-start"
    isolating = True

    def run(
        self, *, argv, workspace, limits: Limits = Limits(), stdin: str = ""
    ) -> SandboxResult:
        return SandboxResult(started_ok=False, detail="stub: isolation did not start")


def test_backend_that_cannot_start_returns_unavailable_never_abstain():
    outcome = SubprocessVerifier(memory_mb=0, sandbox=_CannotStartSandbox()).verify(
        code=_OK, task=_TASK
    )
    # By construction: a could-not-execute outcome carries NO verdict at all, so it
    # can never be an ABSTAIN (or any verdict). Against main this was
    # Verdict.ABSTAIN wearing the HARD tier tag — a HARD verifier degrading into
    # "no opinion" while it never executed.
    assert isinstance(outcome, Unavailable)
    assert outcome.tier == Tier.HARD
    assert outcome.reason == Unavailability.INFRA_FAULT
    assert not hasattr(outcome, "verdict")


def test_bank_cannot_aggregate_an_unavailable_into_a_verdict():
    unavailable = Unavailable(
        verifier_id="subprocess-tests",
        tier=Tier.HARD,
        reason=Unavailability.INFRA_FAULT,
        detail="could not run",
    )
    soft_pass = Evidence(
        passed=True,
        total=1,
        passed_count=1,
        verifier_id="soft",
        verdict=Verdict.PASS,
        tier=Tier.SOFT,
    )
    bank = VerifierBank()
    bank.register("subprocess-tests", Tier.HARD)
    bank.register("soft", Tier.SOFT)
    # The authoritative verifier could not run. A SOFT PASS must NOT stand in for
    # it: the bank returns the Unavailable, not a fused advisory Judgment(PASS).
    # Against main, the ABSTAIN was dropped (bank.py) and the SOFT verdict silently
    # decided the judgment.
    judgment = bank.judge([unavailable, soft_pass])
    assert isinstance(judgment, Unavailable)
    assert not hasattr(judgment, "verdict")

    # A pure could-not-execute list is itself an Unavailable, never a Judgment.
    assert isinstance(bank.judge([unavailable]), Unavailable)
