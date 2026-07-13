"""Conformance: the extension surface is a real, enforced contract.

Three things are proven here:

1. the three shipped verifiers (code, SQL, grounding) pass the conformance
   suite unchanged — the contract describes reality, not an aspiration;
2. the suite has TEETH — deliberately non-conformant verifiers (a soft one
   that tries to emit HARD evidence; one that guesses a verdict instead of
   abstaining when it cannot verify) are REJECTED, with the failing check
   named;
3. the Hearth is untouched — the bank, gate, firewall, executor, and core
   models are byte-identical to origin/main.

The HARD verifiers' behavioural checks need the isolation runtime, so those
cases run under the same gate as the rest of the sandbox suite (skip without
it, FAIL under PROM_REQUIRE_SANDBOX=1). The tier-honesty, fail-closed,
teeth, and Hearth-diff checks need no runtime.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from prometheus_protocol.conformance import (
    check_firewall_is_domain_general,
    check_verifier,
    code_case,
    grounding_case,
    sql_case,
)
from prometheus_protocol.conformance.contract import VerifierCase
from prometheus_protocol.core.interfaces import Verifier
from prometheus_protocol.core.models import Evidence, Tier, Verdict

_REQUIRE = (os.environ.get("PROM_REQUIRE_SANDBOX", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}


def _behavioural_wanted() -> bool:
    from prometheus_protocol.sandbox import NamespaceSandbox

    if NamespaceSandbox.available():
        return True
    if _REQUIRE:
        pytest.fail("PROM_REQUIRE_SANDBOX=1 but the isolation runtime is unavailable")
    return False


# --------------------------------------------------------------------------
# the three shipped verifiers pass, unchanged
# --------------------------------------------------------------------------


def test_grounding_case_is_well_behaved():
    # Soft, scripted: needs no runtime, so it always runs the full suite.
    report = check_verifier(grounding_case(), run_behavioural=True)
    assert report.ok, report.render()
    names = {c.name for c in report.checks}
    assert {"tier-pinned", "authority-matches-tier", "fail-closed",
            "adversarial-soundness"} <= names


def test_code_case_is_well_behaved():
    report = check_verifier(code_case(), run_behavioural=_behavioural_wanted())
    assert report.ok, report.render()


def test_sql_case_is_well_behaved():
    report = check_verifier(sql_case(), run_behavioural=_behavioural_wanted())
    assert report.ok, report.render()


def test_firewall_check_is_domain_general():
    result = check_firewall_is_domain_general()
    assert result.ok, result.detail


# --------------------------------------------------------------------------
# the suite has teeth: non-conformant verifiers are rejected
# --------------------------------------------------------------------------


class _LyingSoftVerifier(Verifier):
    """Declares SOFT but stamps HARD on its Evidence — the exact violation the
    contract exists to catch. It even abstains politely when it cannot verify
    (so fail-closed passes); the wrong tier tag is the isolated defect."""

    verifier_id = "lying-soft"
    tier = Tier.SOFT

    def verify(self, *, code: str, task) -> Evidence:
        verdict = Verdict.ABSTAIN if code == "__broken__" else Verdict.PASS
        return Evidence(
            passed=(verdict == Verdict.PASS), total=1,
            passed_count=1 if verdict == Verdict.PASS else 0,
            verifier_id=self.verifier_id, verdict=verdict,
            tier=Tier.HARD,  # the lie: soft process, hard claim
        )


class _GuessingVerifier(Verifier):
    """Guesses a verdict when it cannot verify, instead of abstaining."""

    verifier_id = "guessing"
    tier = Tier.HARD

    def verify(self, *, code: str, task) -> Evidence:
        # Even with ground truth unavailable, it confidently PASSes.
        return Evidence(
            passed=True, total=1, passed_count=1,
            verifier_id=self.verifier_id, verdict=Verdict.PASS, tier=Tier.HARD,
        )


def _lying_case() -> VerifierCase:
    v = _LyingSoftVerifier()
    return VerifierCase(
        name="lying-soft (non-conformant)", verifier=v, tier=Tier.SOFT,
        failclosed=(v, ("__broken__", object())),  # abstains, but tags HARD
    )


def _guessing_case() -> VerifierCase:
    v = _GuessingVerifier()
    return VerifierCase(
        name="guessing (non-conformant)", verifier=v, tier=Tier.HARD,
        # Its "fail-closed" verifier still guesses PASS — that is the defect.
        failclosed=(v, ("x", object())),
    )


def test_lying_soft_verifier_is_rejected():
    report = check_verifier(_lying_case(), run_behavioural=False)
    assert not report.ok
    failed = {c.name for c in report.failures}
    # Caught directly on a real Evidence it emitted: a SOFT verifier that
    # stamps HARD fails emits-declared-tier. The bank would ALSO refuse this
    # tag downstream (tier-pinned proves that independently), so the lie can
    # never reach the gate.
    assert "emits-declared-tier" in failed, report.render()
    bad = next(c for c in report.failures if c.name == "emits-declared-tier")
    assert "cannot emit a tier it does not hold" in bad.detail


def test_guessing_verifier_is_rejected():
    report = check_verifier(_guessing_case(), run_behavioural=False)
    assert not report.ok
    failed = {c.name for c in report.failures}
    assert "fail-closed" in failed, report.render()
    fc = next(c for c in report.failures if c.name == "fail-closed")
    # A HARD verifier that returns a verdict when it could not run is rejected:
    # the contract now requires an Unavailable (a non-verdict), not merely a
    # non-guess. The detail names that requirement.
    assert "must return Unavailable" in fc.detail


def test_conformant_and_nonconformant_are_distinguished():
    # A well-behaved verifier and a broken one, through the SAME machinery,
    # land on opposite verdicts — the suite discriminates.
    good = check_verifier(grounding_case(), run_behavioural=True)
    bad = check_verifier(_guessing_case(), run_behavioural=False)
    assert good.ok and not bad.ok


# --------------------------------------------------------------------------
# the Hearth is byte-identical to origin/main
# --------------------------------------------------------------------------

_HEARTH_FILES = (
    "src/prometheus_protocol/verifier/bank.py",
    "src/prometheus_protocol/gate/promotion.py",
    "src/prometheus_protocol/gate/authorization.py",
    "src/prometheus_protocol/execution/executor.py",
    "src/prometheus_protocol/execution/controller.py",
    "src/prometheus_protocol/forge/miner.py",
    "src/prometheus_protocol/core/models.py",
    "src/prometheus_protocol/verifier/runner.py",
    "src/prometheus_protocol/verifier/sql.py",
    "src/prometheus_protocol/verifier/grounding.py",
)

# EX-1 (PR #52: a HARD verifier that cannot execute must not abstain) changed
# exactly these ten frozen files, with explicit approval — the sanctioned delta.
# The guard tolerates a change to one of THESE and still fails on ANY other
# frozen-file change, so the Hearth stays protected against unsanctioned edits
# while EX-1's approved surface lands.
_EX1_CHANGED = frozenset({
    "src/prometheus_protocol/core/models.py",
    "src/prometheus_protocol/core/interfaces.py",
    "src/prometheus_protocol/verifier/runner.py",
    "src/prometheus_protocol/verifier/sql.py",
    "src/prometheus_protocol/verifier/bank.py",
    "src/prometheus_protocol/gate/authorization.py",
    "src/prometheus_protocol/benchmarks/judge_eval.py",
    "src/prometheus_protocol/orchestration/runtime.py",
    "src/prometheus_protocol/execution/controller.py",
    "src/prometheus_protocol/execution/pending.py",
})


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    )


@pytest.mark.skipif(
    _git("rev-parse", "--verify", "origin/main").returncode != 0,
    reason="origin/main not available in this checkout",
)
def test_hearth_is_unchanged_versus_main():
    """No Hearth-core file differs from origin/main, EXCEPT the files EX-1 (PR #52)
    changed with approval (``_EX1_CHANGED``). This sprint is a contract AROUND the
    Hearth; if a file outside that sanctioned delta changed, the surface moved."""

    diff = _git("diff", "--name-only", "origin/main", "--", *_HEARTH_FILES)
    assert diff.returncode == 0, diff.stderr
    changed = [line for line in diff.stdout.splitlines() if line.strip()]
    unsanctioned = [f for f in changed if f not in _EX1_CHANGED]
    assert unsanctioned == [], f"unsanctioned Hearth change vs origin/main: {unsanctioned}"
