"""UNBOUNDED must reach every adapter's command, and never become a number.

THE FINDING THIS CLOSES (Codex review on PR #106, P1). ``UNBOUNDED`` was
resolved to ``0`` at the composition root, before any adapter saw it.
``ContainerSandbox`` then coerced the memory limit with
``max(bytes, 16 * 1024 * 1024)`` and emitted ``--memory`` unconditionally, so
the posture an operator NAMED as "no cap" arrived at the container runtime as a
**16 MiB cap** — the tightest in the tree — while the namespace and unsafe
adapters correctly imposed nothing. One flattening point, three substrates that
disagree about what a zero means.

WHY THESE TESTS ASSERT ON THE COMMAND, NOT ON A RETURN CODE. A run that
succeeds tells you the cap was not hit on that machine, on that day, with that
candidate. It does not tell you which cap was imposed. The original defect was
invisible to every outcome-shaped test in this repository and would have stayed
invisible: a 16 MiB container kills a candidate that a 256 MiB one runs, but so
does a bad candidate, and the exit status is the same. The argv is the only
place the posture is stated.

THE CLASS, NOT THE INSTANCE. ``ADAPTER_PROBES`` covers every concrete
:class:`Sandbox` in the package and a guard fails if one is added without an
answer here, so the next adapter — or the next coercion in an existing one —
cannot reintroduce the flattening quietly. That is the ruling: fixing
``ContainerSandbox.run`` alone would fix this instance and leave the shape.

WHAT IS NOT PROVEN HERE. That the runtime honours a flag it is given. These
tests establish what this repository asks for; whether Docker or Podman then
enforces it is a deployment property, and ``test_sandbox_container_signal.py``
is where a real container is driven under ``PROM_REQUIRE_CONTAINER=1``.
"""

from __future__ import annotations

import pkgutil
import importlib
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

import prometheus_protocol.sandbox as sandbox_package
from prometheus_protocol.core.bounds import UNBOUNDED
from prometheus_protocol.sandbox.base import Limits, Sandbox
from prometheus_protocol.sandbox.container import ContainerSandbox
from prometheus_protocol.sandbox.namespace import NamespaceSandbox
from prometheus_protocol.sandbox.unsafe import NullSandbox, UnsafeLocalSandbox

_PINNED = "example.invalid/img@sha256:" + "0" * 64


class _Recorded(Exception):
    """Raised once the command is captured, so nothing is actually executed."""

    def __init__(self, command: list[str]) -> None:
        super().__init__("captured")
        self.command = command


def _capture(monkeypatch, module_name: str) -> list[list[str]]:
    """Capture the argv an adapter builds, without running it."""

    captured: list[list[str]] = []
    module = importlib.import_module(module_name)

    def _fake_run(command, *a, **kw):
        captured.append(list(command))
        raise _Recorded(list(command))

    monkeypatch.setattr(module.subprocess, "run", _fake_run)
    return captured


def _drive(sandbox: Sandbox, limits: Limits) -> None:
    with tempfile.TemporaryDirectory(prefix="prom-cmd-") as workspace:
        Path(workspace, "prog.py").write_text("print('x')\n", encoding="utf-8")
        try:
            sandbox.run(
                argv=[sys.executable, "-I", "prog.py"],
                workspace=workspace,
                limits=limits,
            )
        except _Recorded:
            pass


def _container_command(monkeypatch, limits: Limits) -> list[str]:
    captured = _capture(monkeypatch, "prometheus_protocol.sandbox.container")
    _drive(ContainerSandbox(runtime="/bin/true", image=_PINNED), limits)
    assert captured, "the container adapter built no command"
    return captured[0]


def _namespace_command(monkeypatch, limits: Limits) -> list[str]:
    captured = _capture(monkeypatch, "prometheus_protocol.sandbox.namespace")
    # The cgroup lever writes to the host cgroup tree when one is available;
    # neutralized so this test measures the COMMAND on every machine.
    import prometheus_protocol.sandbox.namespace as ns

    monkeypatch.setattr(ns, "create_pids_cgroup", lambda **kw: None)
    _drive(NamespaceSandbox(), limits)
    assert captured, "the namespace adapter built no command"
    return captured[0]


def _unsafe_rlimits(monkeypatch, limits: Limits) -> dict[int, int]:
    """The rlimits the unsafe adapter's own preexec closure would set.

    The closure is captured and then CALLED with ``resource.setrlimit``
    recording rather than applying, so this measures the adapter's real code
    path and not a re-implementation of it.
    """

    import resource

    holder: dict[str, object] = {}

    def _fake_run(command, *a, **kw):
        holder["preexec"] = kw.get("preexec_fn")
        raise _Recorded(list(command))

    import prometheus_protocol.sandbox.unsafe as uns

    monkeypatch.setattr(uns.subprocess, "run", _fake_run)
    _drive(UnsafeLocalSandbox(), limits)

    applied: dict[int, int] = {}
    monkeypatch.setattr(
        resource, "setrlimit", lambda which, pair: applied.__setitem__(which, pair[0])
    )
    preexec = holder.get("preexec")
    if callable(preexec):
        preexec()
    return applied


# ===========================================================================
# The registry, and the guard that keeps it total
# ===========================================================================

#: Every concrete adapter, and whether it constructs a resource-limited command
#: at all. ``NullSandbox`` refuses to run rather than running without limits, so
#: it has no command to inspect — recorded rather than omitted, because an
#: adapter quietly missing from this table is the gap the table exists to close.
ADAPTER_PROBES = {
    "ContainerSandbox": "command",
    "NamespaceSandbox": "command",
    "UnsafeLocalSandbox": "rlimits",
    "NullSandbox": "imposes-nothing-and-runs-nothing",
}


def _concrete_sandboxes() -> set[str]:
    for module in pkgutil.iter_modules(sandbox_package.__path__):
        try:
            importlib.import_module(f"prometheus_protocol.sandbox.{module.name}")
        except Exception:  # pragma: no cover - an optional adapter's deps
            continue

    def _subclasses(cls):
        for child in cls.__subclasses__():
            yield child
            yield from _subclasses(child)

    # Scoped to the SHIPPED package. Test doubles subclass Sandbox too, and a
    # collector that counted them would make this guard fail for every stub
    # anyone writes — measured: run alone this file passed, and under the full
    # suite it found four test fakes. An instrument whose answer depends on
    # what else was imported is not measuring the tree.
    return {
        cls.__name__
        for cls in _subclasses(Sandbox)
        if cls.__module__.startswith("prometheus_protocol.")
    }


def test_every_concrete_adapter_is_answered_for_here():
    """THE CLASS-LEVEL RATCHET. A new adapter cannot be added without saying
    what it does with an unbounded bound — which is the only thing that stops
    the next one reintroducing a coercion the way the container one did."""

    discovered = _concrete_sandboxes()
    assert discovered, "the collector found no adapters at all"
    unanswered = sorted(discovered - set(ADAPTER_PROBES))
    assert unanswered == [], (
        f"sandbox adapters with no unbounded answer in this file: {unanswered}"
    )
    stale = sorted(set(ADAPTER_PROBES) - discovered)
    assert stale == [], f"answered here but no longer an adapter: {stale}"


def test_the_adapter_collector_is_not_universally_true():
    """The positive control for the guard above. An instrument returning an
    empty set reads downstream as a pass (doctrine #8), and an empty
    ``_concrete_sandboxes`` would make the subtraction empty and the test
    green for every adapter at once."""

    discovered = _concrete_sandboxes()
    assert "ContainerSandbox" in discovered
    assert "NotASandboxAdapterXyz" not in discovered


# ===========================================================================
# Container — the substrate the finding was about
# ===========================================================================


def test_container_omits_the_memory_flags_entirely_when_unbounded(monkeypatch):
    """The fix, asserted on the argv. Not "the value is large" — ABSENT: there
    is no number that means "no cap" to a container runtime, so a command that
    still carried ``--memory`` would still be imposing one."""

    command = _container_command(
        monkeypatch, Limits(wall_time_s=30, memory_bytes=UNBOUNDED)
    )
    assert "--memory" not in command, command
    assert "--memory-swap" not in command, command


def test_container_emits_the_exact_cap_it_was_given(monkeypatch):
    """The positive control (doctrine #4). Without it, the absence above is
    equally consistent with an adapter that never caps memory at all — which
    would be a worse defect than the one being fixed."""

    command = _container_command(
        monkeypatch, Limits(wall_time_s=30, memory_bytes=256 * 1024 * 1024)
    )
    assert "--memory" in command
    assert command[command.index("--memory") + 1] == str(256 * 1024 * 1024)
    assert command[command.index("--memory-swap") + 1] == str(256 * 1024 * 1024)


def test_container_still_floors_a_cap_too_small_for_the_runtime(monkeypatch):
    """The floor is kept for the case it was written for. A caller who asks for
    1 MiB gets 16 MiB, because the runtime refuses less — and that is a
    different thing from a caller who asked for no cap at all. Conflating the
    two is precisely what produced the finding."""

    command = _container_command(
        monkeypatch, Limits(wall_time_s=30, memory_bytes=1024 * 1024)
    )
    assert command[command.index("--memory") + 1] == str(16 * 1024 * 1024)


def test_container_zero_is_not_read_as_unbounded(monkeypatch):
    """A bare ``0`` reaching this adapter is a caller's zero, not a posture, and
    it gets the floor. An adapter guessing that zero means "no cap" would
    reintroduce the flattening from the other direction."""

    command = _container_command(monkeypatch, Limits(wall_time_s=30, memory_bytes=0))
    assert command[command.index("--memory") + 1] == str(16 * 1024 * 1024)


def test_container_pids_limit_says_unlimited_explicitly(monkeypatch):
    """``--pids-limit 0`` happened to mean unlimited to the runtime. Incidental
    correctness is one coercion away from inverting, exactly as the memory floor
    did, so the unbounded process cap now emits the documented ``-1``."""

    unbounded = _container_command(
        monkeypatch, Limits(wall_time_s=30, memory_bytes=UNBOUNDED,
                            max_processes=UNBOUNDED)
    )
    assert unbounded[unbounded.index("--pids-limit") + 1] == "-1"

    bounded = _container_command(
        monkeypatch, Limits(wall_time_s=30, memory_bytes=UNBOUNDED, max_processes=32)
    )
    assert bounded[bounded.index("--pids-limit") + 1] == "32"


# ===========================================================================
# Namespace and unsafe — the substrates that were already right
# ===========================================================================


def test_namespace_passes_zero_for_an_unbounded_bound(monkeypatch):
    """On this substrate the bootstrap and the cgroup writer both read ``0`` as
    "impose nothing", so resolving to zero AT THE ARGV LINE is correct. The
    point of the change is not that every adapter now does the same thing — it
    is that each one decides for itself, at its own command."""

    command = _namespace_command(
        monkeypatch,
        Limits(wall_time_s=30, memory_bytes=UNBOUNDED, cpu_time_s=UNBOUNDED,
               max_processes=UNBOUNDED),
    )
    # argv: unshare … bootstrap workspace memory cpu procs fsize statusfd -- …
    bootstrap_args = command[command.index("--") - 5:command.index("--")]
    assert bootstrap_args[0] == "0", command
    assert bootstrap_args[1] == "0", command
    assert bootstrap_args[2] == "0", command


def test_namespace_passes_the_exact_caps_it_was_given(monkeypatch):
    """The positive control for the substrate."""

    command = _namespace_command(
        monkeypatch,
        Limits(wall_time_s=30, memory_bytes=64 * 1024 * 1024, cpu_time_s=7,
               max_processes=11),
    )
    bootstrap_args = command[command.index("--") - 5:command.index("--")]
    assert bootstrap_args[0] == str(64 * 1024 * 1024), command
    assert bootstrap_args[1] == "7", command
    assert bootstrap_args[2] == "11", command


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX rlimits only")
def test_unsafe_sets_no_address_space_or_cpu_rlimit_when_unbounded(monkeypatch):
    """Driven through the adapter's OWN preexec closure, with setrlimit
    recording instead of applying."""

    import resource

    applied = _unsafe_rlimits(
        monkeypatch, Limits(wall_time_s=30, memory_bytes=UNBOUNDED,
                            cpu_time_s=UNBOUNDED)
    )
    assert resource.RLIMIT_AS not in applied, applied
    assert resource.RLIMIT_CPU not in applied, applied
    # The file-size cap is unconditional and must survive: "unbounded memory"
    # is not "unbounded everything".
    assert resource.RLIMIT_FSIZE in applied, applied


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX rlimits only")
def test_unsafe_sets_the_exact_rlimits_it_was_given(monkeypatch):
    """The positive control (doctrine #4): without it, the absence above is
    consistent with an adapter that sets no rlimits at all."""

    import resource

    applied = _unsafe_rlimits(
        monkeypatch, Limits(wall_time_s=30, memory_bytes=64 * 1024 * 1024,
                            cpu_time_s=7)
    )
    assert applied[resource.RLIMIT_AS] == 64 * 1024 * 1024
    assert applied[resource.RLIMIT_CPU] == 7


def test_null_sandbox_runs_nothing_rather_than_running_unlimited():
    """The fourth adapter's answer, asserted rather than assumed. It has no
    command because it refuses to execute — which is the fail-closed posture,
    not an unbounded one."""

    with tempfile.TemporaryDirectory(prefix="prom-null-") as workspace:
        result = NullSandbox().run(
            argv=[sys.executable, "-c", "print(1)"],
            workspace=workspace,
            limits=Limits(wall_time_s=30, memory_bytes=UNBOUNDED),
        )
    assert result.started_ok is False
    assert result.candidate_started is False


# ===========================================================================
# The class-level property, stated once over every substrate
# ===========================================================================


@pytest.mark.parametrize("adapter", ["container", "namespace"])
def test_no_adapter_turns_an_unbounded_bound_into_a_finite_number(monkeypatch, adapter):
    """THE CLASS. Under a fully unbounded Limits, no command may carry a
    positive number derived from one of the three caps.

    ``0`` is permitted (it is how two substrates spell "impose nothing"); a
    POSITIVE number is not, because there is no positive number that means
    unbounded on any of them. A future ``max(..., floor)`` on any bound, in any
    adapter, produces exactly such a number and fails here.
    """

    limits = Limits(
        wall_time_s=30, memory_bytes=UNBOUNDED, cpu_time_s=UNBOUNDED,
        max_processes=UNBOUNDED,
    )
    if adapter == "container":
        command = _container_command(monkeypatch, limits)
        # Flags whose value is derived from a cap. --cpus is excluded and that
        # exclusion is the subject of OPEN-GAPS G22: it is a hardcoded RATE,
        # not an expression of cpu_time_s, which this substrate does not carry
        # at all.
        for flag in ("--memory", "--memory-swap"):
            assert flag not in command, (flag, command)
        assert command[command.index("--pids-limit") + 1] == "-1", command
    else:
        command = _namespace_command(monkeypatch, limits)
        bootstrap_args = command[command.index("--") - 5:command.index("--")]
        for value in bootstrap_args[:3]:
            assert int(value) == 0, (value, command)


def test_the_posture_record_matches_what_the_container_actually_runs(monkeypatch):
    """An attestation that records a posture the run did not have is worse than
    no attestation: it is a signed statement that something else happened.

    Measured before the fix: the record said ``verifier_memory_mb='unbounded'``
    while the command carried ``--memory 16777216``. The record was accurate
    about the CONFIGURATION and wrong about the RUN, which is the half that
    matters to anyone reading it afterwards.
    """

    from prometheus_protocol.attestation.runtime import resolve_posture
    from prometheus_protocol.chokepoint.signer import LocalHmacSigner
    from prometheus_protocol.core.config import Config
    from prometheus_protocol.runtime.factory import build_execution_controller

    config = Config(
        ledger_path=":memory:", sandbox="container", verifier_memory_mb=UNBOUNDED
    )
    posture = resolve_posture(config, signer=LocalHmacSigner(b"k" * 32), env={})
    assert posture.verifier_memory_mb == UNBOUNDED

    limits = build_execution_controller(config)._executor._limits
    assert limits.memory_bytes == UNBOUNDED, "flattened before the adapter again"
    command = _container_command(monkeypatch, limits)
    assert "--memory" not in command, (
        "the record attests 'unbounded' and the command imposes a cap: "
        f"{command}"
    )


def test_the_posture_record_also_matches_a_bounded_run(monkeypatch):
    """The positive control. Without it the agreement above is consistent with
    a record that says 'unbounded' for every configuration."""

    from prometheus_protocol.attestation.runtime import resolve_posture
    from prometheus_protocol.chokepoint.signer import LocalHmacSigner
    from prometheus_protocol.core.config import Config
    from prometheus_protocol.runtime.factory import build_execution_controller

    config = Config(
        ledger_path=":memory:", sandbox="container", verifier_memory_mb=64
    )
    posture = resolve_posture(config, signer=LocalHmacSigner(b"k" * 32), env={})
    assert posture.verifier_memory_mb == 64

    limits = build_execution_controller(config)._executor._limits
    command = _container_command(monkeypatch, limits)
    assert command[command.index("--memory") + 1] == str(64 * 1024 * 1024)


def test_the_finite_number_check_can_fail(monkeypatch):
    """Positive control for the class-level test: the same assertions applied to
    a BOUNDED Limits must find the finite numbers, or the check above is
    passing because it looks in the wrong place."""

    command = _container_command(
        monkeypatch,
        Limits(wall_time_s=30, memory_bytes=64 * 1024 * 1024, max_processes=8),
    )
    assert "--memory" in command
    assert int(command[command.index("--memory") + 1]) > 0
    assert int(command[command.index("--pids-limit") + 1]) == 8
