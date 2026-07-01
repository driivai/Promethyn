"""Conformance: container image provenance (digest-pin enforcement).

A bare image tag can be silently repointed at a different image after it was
vetted (a supply-chain substitution). Under ``PROM_REQUIRE_DIGEST_PIN`` the
container adapter REFUSES a bare-tag image outright — fail-closed — while a
digest-pinned image is allowed. The flag is off by default so dev keeps its
convenience; with it off, behaviour is unchanged (a bare tag still runs, with
the standing warning). None of this loosens anything: a refusal is
``started_ok=False``, which the verifier treats as could-not-verify (ABSTAIN),
never a pass or a fail.

These need no container runtime — the pin is checked before the runtime probe —
so they always run, in CI and locally.
"""

from __future__ import annotations

from prometheus_protocol.core.config import Config
from prometheus_protocol.core.models import Case, Task, Verdict
from prometheus_protocol.sandbox import Limits
from prometheus_protocol.sandbox.container import ContainerSandbox, is_digest_pinned
from prometheus_protocol.verifier.runner import SubprocessVerifier

_BARE = "python:3.12-slim"
_PINNED = "python:3.12-slim@sha256:" + "a" * 64
_TASK = Task(id="t/f", entry_point="f", prompt="", split="train", cases=(Case((1,), 1),))
_OK = "def f(n):\n    return n\n"


def _refused_for_pin(res) -> bool:
    return not res.started_ok and "not digest-pinned" in (res.detail or "")


# -- the pure provenance predicate ------------------------------------------


def test_is_digest_pinned_predicate():
    assert is_digest_pinned("img@sha256:" + "0" * 64) is True
    assert is_digest_pinned("python:3.12-slim") is False
    assert is_digest_pinned("python:latest") is False


# -- enforcement: bare tag refused, digest-pinned allowed --------------------


def test_bare_tag_is_refused_under_digest_pin():
    # runtime forced present so the refusal is proven to precede the runtime use.
    sandbox = ContainerSandbox(runtime="docker", image=_BARE, require_digest_pin=True)
    res = sandbox.run(argv=["python", "-c", "print(1)"], workspace="/tmp")
    assert _refused_for_pin(res)


def test_digest_pinned_image_is_not_refused_by_the_pin_gate():
    # A pinned image passes the provenance gate; whatever happens next is a
    # downstream result, never the pin refusal.
    sandbox = ContainerSandbox(runtime="docker", image=_PINNED, require_digest_pin=True)
    res = sandbox.run(argv=["python", "-c", "print(1)"], workspace="/tmp")
    assert not _refused_for_pin(res)


# -- default off preserves behaviour ----------------------------------------


def test_default_off_does_not_refuse_a_bare_tag():
    sandbox = ContainerSandbox(runtime="docker", image=_BARE)  # flag defaults off
    assert sandbox.require_digest_pin is False
    res = sandbox.run(argv=["python", "-c", "print(1)"], workspace="/tmp")
    assert not _refused_for_pin(res)


def test_require_digest_pin_resolves_from_env(monkeypatch):
    monkeypatch.setenv("PROM_REQUIRE_DIGEST_PIN", "1")
    assert ContainerSandbox(runtime="docker", image=_BARE).require_digest_pin is True
    monkeypatch.delenv("PROM_REQUIRE_DIGEST_PIN", raising=False)
    assert ContainerSandbox(runtime="docker", image=_BARE).require_digest_pin is False


def test_config_exposes_require_digest_pin():
    assert Config.from_env({}).require_digest_pin is False
    assert Config.from_env({"PROM_REQUIRE_DIGEST_PIN": "1"}).require_digest_pin is True


# -- fail-closed preserved: a refusal ABSTAINs, never passes or fails --------


def test_digest_pin_refusal_flows_through_verifier_as_abstain():
    # The tightening keeps the fail-closed guarantee: a refused image is a
    # could-not-verify, so the verifier ABSTAINs (no pass, no fail, no sample).
    sandbox = ContainerSandbox(runtime="docker", image=_BARE, require_digest_pin=True)
    evidence = SubprocessVerifier(memory_mb=0, sandbox=sandbox).verify(code=_OK, task=_TASK)
    assert evidence.verdict == Verdict.ABSTAIN


# -- the container adapter reports the stronger (cgroup) lever ----------------


def test_container_reports_cgroup_limiter_on_a_completed_run():
    # A container refused for provenance never ran, so it does not claim a lever;
    # the limiter default is the conservative rlimit.
    sandbox = ContainerSandbox(runtime="docker", image=_BARE, require_digest_pin=True)
    res = sandbox.run(argv=["python", "-c", "print(1)"], workspace="/tmp")
    assert res.limiter == "rlimit"  # refused before running: no lever claimed
