"""Unit tests for the best-effort cgroup process/resource limiter.

These exercise the module's *defensive* contract with a fake cgroup filesystem:
any failure returns ``None`` or does nothing and never raises, so the limiter
can only add containment on top of the always-present rlimit floor. The
end-to-end success path (a real cgroup capping a real fork bomb) is proven by
the INV-SANDBOX-3 conformance test under a real isolation runtime.
"""

from __future__ import annotations

import os
from pathlib import Path

from prometheus_protocol.sandbox import cgroup as cg


# -- create_pids_cgroup: defensive None-returns ------------------------------


def test_nonpositive_pids_max_returns_none():
    # A disabled process cap is not a cgroup we should create.
    assert cg.create_pids_cgroup(pids_max=0, memory_bytes=0, cpu_seconds=0) is None
    assert cg.create_pids_cgroup(pids_max=-1, memory_bytes=0, cpu_seconds=0) is None


def test_no_writable_cgroup_returns_none(tmp_path, monkeypatch):
    # A bare root with neither a v2 controllers file nor a v1 pids controller:
    # nothing to use, so fall through to the rlimit floor (None).
    monkeypatch.setattr(cg, "_CG_ROOT", tmp_path)
    assert cg.create_pids_cgroup(pids_max=16, memory_bytes=0, cpu_seconds=0) is None


def test_mkdir_without_pids_max_is_not_mistaken_for_a_cgroup(tmp_path, monkeypatch):
    # Regression: a plain writable dir under a fake "pids" root lets mkdir succeed,
    # but the child has no pids.max — it is NOT a real cgroup. The limiter must
    # detect this (pids.max absent) and return None rather than a false positive.
    v1 = tmp_path / "pids"
    v1.mkdir()
    (v1 / "cgroup.procs").write_text("")  # makes the v1 controller "present"
    monkeypatch.setattr(cg, "_CG_ROOT", tmp_path)
    assert cg.create_pids_cgroup(pids_max=16, memory_bytes=0, cpu_seconds=0) is None
    # ...and it left no scoped cgroup dir behind.
    assert list(v1.iterdir()) == [v1 / "cgroup.procs"]


# -- _v2_self_dir: the pids controller must be available ---------------------


def test_v2_self_dir_none_when_pids_controller_absent(tmp_path, monkeypatch):
    (tmp_path / "cgroup.controllers").write_text("cpu memory")  # no "pids"
    monkeypatch.setattr(cg, "_CG_ROOT", tmp_path)
    assert cg._v2_self_dir() is None


def test_v2_self_dir_none_when_no_controllers_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cg, "_CG_ROOT", tmp_path)  # empty root, no controllers file
    assert cg._v2_self_dir() is None


# -- PidsCgroup.hit_limit: the unforgeable enforcement signal -----------------


def _pids_cgroup(path: Path) -> cg.PidsCgroup:
    return cg.PidsCgroup(path, kind="v1")


def test_hit_limit_true_when_max_counter_positive(tmp_path):
    (tmp_path / "pids.events").write_text("max 3\n")
    assert _pids_cgroup(tmp_path).hit_limit() is True


def test_hit_limit_false_when_max_counter_zero(tmp_path):
    (tmp_path / "pids.events").write_text("max 0\n")
    assert _pids_cgroup(tmp_path).hit_limit() is False


def test_hit_limit_false_when_events_file_missing(tmp_path):
    assert _pids_cgroup(tmp_path).hit_limit() is False


def test_hit_limit_false_on_malformed_events(tmp_path):
    (tmp_path / "pids.events").write_text("max notanumber\n")
    assert _pids_cgroup(tmp_path).hit_limit() is False


# -- join_current_process: best-effort, never raises -------------------------


def test_join_writes_pid_into_procs_file(tmp_path):
    procs = tmp_path / "cgroup.procs"
    procs.write_text("")
    cg.join_current_process(str(procs))
    assert procs.read_text().strip() == str(os.getpid())


def test_join_is_silent_when_path_missing(tmp_path):
    # A non-existent procs path must not raise: the rlimit floor still applies.
    cg.join_current_process(str(tmp_path / "does" / "not" / "exist"))


# -- close: removable only once empty, best-effort ---------------------------


def test_close_removes_empty_cgroup_dir(tmp_path):
    scoped = tmp_path / "prom-sbox-1-abcd1234"
    scoped.mkdir()
    _pids_cgroup(scoped).close()
    assert not scoped.exists()


def test_close_is_silent_on_nonempty_or_missing_dir(tmp_path):
    scoped = tmp_path / "prom-sbox-1-abcd1234"
    scoped.mkdir()
    (scoped / "leftover").write_text("x")  # non-empty: rmdir fails, must not raise
    _pids_cgroup(scoped).close()
    assert scoped.exists()
    # A never-created dir also closes silently.
    _pids_cgroup(tmp_path / "never").close()
