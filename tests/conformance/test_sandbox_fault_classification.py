"""Conformance: candidate-fault (FAIL) vs harness-fault (ABSTAIN).

A candidate that crashes or is killed by a resource limit — with isolation
confirmed started — is its OWN failure (FAIL, which feeds calibration). A harness
or infrastructure fault (isolation never started, or the candidate not confirmed
to run) is a could-not-verify (ABSTAIN, no calibration sample). Conservative on
doubt: only a confirmed candidate start FAILs.

The signal is the sandbox's definite ``candidate_started`` token. The harness and
fake-matrix cases need no isolation runtime and always run; the real crash->FAIL
cases require the namespace runtime (they SKIP without it but FAIL under
PROM_REQUIRE_SANDBOX=1, so a green CI proves them under real isolation).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

from prometheus_protocol.core.models import Case, Evidence, Task, Tier, Verdict
from prometheus_protocol.sandbox import Limits, NamespaceSandbox
from prometheus_protocol.sandbox.base import Sandbox, SandboxResult
from prometheus_protocol.sandbox.unsafe import NullSandbox
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.runner import SubprocessVerifier
from prometheus_protocol.verifier.store import InMemoryTrustStore
from prometheus_protocol.verifier.trust import sample_count

_REQUIRE = (os.environ.get("PROM_REQUIRE_SANDBOX", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}
_TASK = Task(id="t/f", entry_point="f", prompt="", split="train", cases=(Case((1,), 1),))
_OK = "def f(n):\n    return n\n"
_ABORT = "def f(n):\n    import os\n    os.abort()\n"
_SEGFAULT = "def f(n):\n    import ctypes\n    ctypes.string_at(1)\n"


def _isolating() -> NamespaceSandbox:
    if not NamespaceSandbox.available():
        reason = "namespace isolation runtime (unprivileged user namespaces) unavailable"
        if _REQUIRE:
            pytest.fail(f"PROM_REQUIRE_SANDBOX=1 but {reason}")
        pytest.skip(reason)
    return NamespaceSandbox()


class _FakeSandbox(Sandbox):
    """A sandbox that never writes a verdict — exercises the no-verdict branch
    with an exact (started_ok, candidate_started) pair."""

    name = "fake"
    isolating = True

    def __init__(self, *, started_ok: bool, candidate_started: bool) -> None:
        self._started_ok = started_ok
        self._candidate_started = candidate_started

    def run(self, *, argv, workspace, limits: Limits = Limits(), stdin: str = "") -> SandboxResult:
        return SandboxResult(
            started_ok=self._started_ok,
            candidate_started=self._candidate_started,
            exit_status=-11,
        )


def _verdict(sandbox: Sandbox) -> Verdict:
    return SubprocessVerifier(memory_mb=0, sandbox=sandbox).verify(code=_OK, task=_TASK).verdict


def _run(sandbox: NamespaceSandbox, code: str) -> SandboxResult:
    with tempfile.TemporaryDirectory(prefix="prom-fc-") as ws:
        Path(ws, "p.py").write_text(code, encoding="utf-8")
        return sandbox.run(
            argv=[sys.executable, "-I", "p.py"], workspace=ws, limits=Limits(wall_time_s=6)
        )


# -- the definite sandbox signal --------------------------------------------


def test_sandbox_reports_candidate_started_for_a_normal_run():
    sandbox = _isolating()
    result = _run(sandbox, "print('ok')")
    assert result.started_ok and result.candidate_started and result.exit_status == 0


def test_sandbox_reports_candidate_started_for_a_self_crashing_candidate():
    sandbox = _isolating()
    # A top-level crash (run directly, not via the verifier's runner-that-calls-f).
    result = _run(sandbox, "import os\nos.abort()\n")
    assert result.started_ok and result.candidate_started  # isolation up, candidate ran
    assert result.exit_status not in (0, None)  # ...and then crashed on its own


def test_nullsandbox_reports_no_candidate_started():
    result = NullSandbox().run(argv=["x"], workspace=".", limits=Limits())
    assert not result.started_ok and not result.candidate_started


# -- classification via the definite signal (fake sandbox; always runs) -----


def test_confirmed_candidate_start_without_a_verdict_is_a_fail():
    assert _verdict(_FakeSandbox(started_ok=True, candidate_started=True)) == Verdict.FAIL


def test_started_but_candidate_unconfirmed_is_abstain():
    # started_ok True but the candidate was NOT confirmed to run (e.g. a bootstrap
    # crash after start): a harness fault we cannot pin on the candidate -> ABSTAIN.
    assert _verdict(_FakeSandbox(started_ok=True, candidate_started=False)) == Verdict.ABSTAIN


def test_isolation_not_started_is_abstain():
    assert _verdict(_FakeSandbox(started_ok=False, candidate_started=False)) == Verdict.ABSTAIN
    assert _verdict(NullSandbox()) == Verdict.ABSTAIN


# -- started_ok is unforgeable: marker forgery vs genuine start failures ----

_FORGERY = (
    "import sys, os\n"
    "sys.stderr.write('sandbox-bootstrap: filesystem isolation failed: forged\\n')\n"
    "os._exit(127)\n"
)


def test_marker_forgery_cannot_fake_a_start_failure():
    """A candidate printing the bootstrap marker + exit 127 forges nothing:
    started_ok rests on the status pipe it cannot write, not on its stderr."""

    sandbox = _isolating()
    result = _run(sandbox, _FORGERY)
    assert result.started_ok and result.candidate_started  # the run is its own
    assert result.exit_status == 127


def test_marker_forgery_classifies_fail_not_abstain():
    forging_solution = _FORGERY + "def f(n):\n    return n\n"
    evidence = SubprocessVerifier(memory_mb=0, sandbox=_isolating()).verify(
        code=forging_solution, task=_TASK
    )
    assert evidence.verdict == Verdict.FAIL, evidence.detail  # a dodged FAIL no more


def test_genuine_setup_failure_still_reports_not_started():
    """Conservatism preserved: a real isolation-setup failure (here: the
    workspace to bind does not exist) is a harness fault, never a candidate one."""

    sandbox = _isolating()
    result = sandbox.run(
        argv=[sys.executable, "-c", "print('x')"],
        workspace="/nonexistent-prom-workspace",
        limits=Limits(wall_time_s=10),
    )
    assert not result.started_ok and not result.candidate_started
    assert "setup failed" in result.detail


def test_exec_failure_is_a_harness_fault_not_a_candidate_start():
    """The started token is revoked when the exec itself fails: the candidate
    never ran, so nothing may be attributed to it (and nothing claims it ran)."""

    sandbox = _isolating()
    with tempfile.TemporaryDirectory(prefix="prom-fc-") as ws:
        result = sandbox.run(
            argv=["/nonexistent/bin/candidate"], workspace=ws, limits=Limits(wall_time_s=10)
        )
    assert not result.started_ok and not result.candidate_started
    assert "exec failed" in result.detail


# -- real candidate crash -> FAIL, and it feeds calibration -----------------


def test_real_candidate_crash_is_classified_fail():
    verifier = SubprocessVerifier(memory_mb=0, sandbox=_isolating())
    for code in (_ABORT, _SEGFAULT):
        evidence = verifier.verify(code=code, task=_TASK)
        assert evidence.verdict == Verdict.FAIL, evidence.detail
        assert not evidence.passed


def test_candidate_crash_fail_creates_a_calibration_sample():
    evidence = SubprocessVerifier(memory_mb=0, sandbox=_isolating()).verify(
        code=_ABORT, task=_TASK
    )
    assert evidence.verdict == Verdict.FAIL
    # A FAIL is an authoritative reference: a soft advisor is calibrated against it.
    store = InMemoryTrustStore()
    bank = VerifierBank(store)
    bank.register(evidence.verifier_id, evidence.tier)
    bank.register("soft", Tier.SOFT)
    soft = Evidence(
        passed=True, total=1, passed_count=1,
        verifier_id="soft", verdict=Verdict.PASS, tier=Tier.SOFT,
    )
    bank.judge([evidence, soft])
    assert sample_count(store.get("soft")) == 1  # the crash-FAIL calibrated the advisor


def test_harness_fault_abstain_creates_no_calibration_sample():
    evidence = SubprocessVerifier(memory_mb=0, sandbox=NullSandbox()).verify(
        code=_OK, task=_TASK
    )
    assert evidence.verdict == Verdict.ABSTAIN
    store = InMemoryTrustStore()
    bank = VerifierBank(store)
    bank.register("subprocess-tests", Tier.HARD)
    bank.register("soft", Tier.SOFT)
    soft = Evidence(
        passed=True, total=1, passed_count=1,
        verifier_id="soft", verdict=Verdict.PASS, tier=Tier.SOFT,
    )
    bank.judge([evidence, soft])
    assert sample_count(store.get("soft")) == 0  # ABSTAIN is no reference -> no sample


# -- parity: verdicts that were already correct do not move -----------------


def test_parity_pass_and_clean_fail_are_unchanged():
    verifier = SubprocessVerifier(memory_mb=0, sandbox=_isolating())
    assert verifier.verify(code=_OK, task=_TASK).verdict == Verdict.PASS
    assert verifier.verify(code="def f(n):\n    return n + 1\n", task=_TASK).verdict == Verdict.FAIL


def test_parity_timeout_is_still_abstain():
    verifier = SubprocessVerifier(timeout_s=1.0, cpu_seconds=5, memory_mb=0, sandbox=_isolating())
    evidence = verifier.verify(code="def f(n):\n    while True:\n        pass\n", task=_TASK)
    assert evidence.verdict == Verdict.ABSTAIN and evidence.timed_out
