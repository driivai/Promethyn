"""Conformance: the runner zone grants no more than it must (threat model §2).

Attacker 2 is the runner host — either compromised, or simply holding more
standing authority than the job needs. Full host compromise is out of scope and
stays out of scope: root on the box owns the credential, the signing key and the
ledger, and nothing here changes that. What these tests hold to account is the
blast radius *before* that point, and specifically the things an ordinary
unprivileged local account could reach with no vulnerability at all.

Two defects this pins down, both from a single ``chmod(workspace, 0o777)``:

* the agent's workspace was world-readable and world-writable, so any local user
  could read it and — the sharper edge — rewrite an artifact in the window
  between it being written and being hashed;
* handed a *shared* directory, that same line re-permissioned it. The
  repository's own provenance tests passed ``workspace="/tmp"``, so every run of
  the suite took the sticky bit off the machine's ``/tmp``
  (``drwxrwxrwt`` to ``drwxrwxrwx``), which lets any local user delete or rename
  anyone else's files there. Measured on the pre-fix code, not deduced.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile

import pytest

from prometheus_protocol.sandbox.base import CANDIDATE_ENV_KEYS, Limits, candidate_env
from prometheus_protocol.sandbox.container import (
    CONTAINER_UID,
    WORKSPACE_MODE,
    ContainerSandbox,
    prepare_workspace,
)
from prometheus_protocol.sandbox.namespace import NamespaceSandbox
from prometheus_protocol.sandbox.unsafe import UnsafeLocalSandbox

_REQUIRE_CONTAINER = (os.environ.get("PROM_REQUIRE_CONTAINER", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}
_REQUIRE_PRIVILEGED = (os.environ.get("PROM_REQUIRE_PRIVILEGED", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}

#: A uid that is neither root nor the container user, standing in for "some other
#: local account". 1 is ``daemon`` on every mainstream distribution.
OTHER_UID = 1
OTHER_GID = 1

CANARY = "prom-attacker2-canary-4b19d7e0c3a85f26"


# ---------------------------------------------------------------------------
# 1. The workspace is never opened to the world
# ---------------------------------------------------------------------------


def test_workspace_is_owner_only_after_preparation(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    os.chmod(workspace, 0o777)  # start from the old, wrong state

    user, error = prepare_workspace(workspace)

    assert user is not None, f"preparation refused a private directory: {error}"
    mode = stat.S_IMODE(os.stat(workspace).st_mode)
    assert mode == WORKSPACE_MODE, f"expected {WORKSPACE_MODE:04o}, got {mode:04o}"
    assert mode & 0o077 == 0, "the workspace grants group or other access"


def test_preparation_reports_a_user_matching_who_owns_the_workspace(tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()

    user, error = prepare_workspace(workspace)
    assert user is not None, error

    owner = os.stat(workspace).st_uid
    assert user.split(":")[0] == str(owner), (
        "the container would run as a user that does not own the workspace, "
        "which is exactly the mismatch the 0777 chmod was papering over"
    )
    if os.getuid() == 0:
        assert owner == CONTAINER_UID, "a privileged runner should hand the workspace over"


# ---------------------------------------------------------------------------
# 2. A shared directory is refused, not re-permissioned
# ---------------------------------------------------------------------------


def test_a_shared_sticky_directory_is_refused(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o1777)  # a /tmp-shaped drop-box
    before = stat.S_IMODE(os.stat(shared).st_mode)

    user, error = prepare_workspace(shared)

    assert user is None, "a shared sticky directory was accepted as a workspace"
    assert "shared" in error
    after = stat.S_IMODE(os.stat(shared).st_mode)
    assert after == before, "the refusal still altered the directory"
    assert after & stat.S_ISVTX, "the sticky bit was stripped from a shared directory"


def test_the_real_tmp_is_refused_and_untouched():
    """The specific regression: the suite must never re-permission /tmp."""

    before = stat.S_IMODE(os.stat("/tmp").st_mode)
    if not before & stat.S_ISVTX:
        pytest.skip("/tmp is not sticky on this host; nothing to protect")

    user, error = prepare_workspace("/tmp")

    assert user is None, "/tmp was accepted as a per-run workspace"
    after = stat.S_IMODE(os.stat("/tmp").st_mode)
    assert after == before, f"/tmp changed from {before:04o} to {after:04o}"
    assert after & stat.S_ISVTX, "the sticky bit was stripped from /tmp"


def test_a_non_directory_is_refused(tmp_path):
    regular = tmp_path / "not-a-dir"
    regular.write_text("x", encoding="utf-8")
    user, error = prepare_workspace(regular)
    assert user is None and "directory" in error


# ---------------------------------------------------------------------------
# 3. Another local account really cannot get in
# ---------------------------------------------------------------------------


def _access_as_other_user(workspace: str) -> dict[str, str]:
    """Fork, drop to an unrelated uid, and report what it could do.

    Requires privilege to drop privilege, so it runs only as root. That is not a
    gap in the proof so much as a limit of where it can execute: the mode
    assertions above hold everywhere, and this turns them into an observed
    denial wherever the test can actually become another user.
    """

    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # child
        os.close(read_fd)
        results = []
        try:
            os.setgroups([])
            os.setgid(OTHER_GID)
            os.setuid(OTHER_UID)
            for label, action in (
                ("list", lambda: os.listdir(workspace)),
                ("read", lambda: open(os.path.join(workspace, "secret.txt"), "rb").read()),
                ("write", lambda: open(os.path.join(workspace, "planted.sql"), "w")),
            ):
                try:
                    action()
                    results.append(f"{label}=ALLOWED")
                except OSError as exc:
                    results.append(f"{label}=DENIED:{type(exc).__name__}")
            os.write(write_fd, ";".join(results).encode())
        except Exception as exc:  # noqa: BLE001 - report, never hang the parent
            os.write(write_fd, f"setup=FAILED:{type(exc).__name__}".encode())
        finally:
            os.close(write_fd)
            os._exit(0)

    os.close(write_fd)
    raw = b""
    while True:
        chunk = os.read(read_fd, 4096)
        if not chunk:
            break
        raw += chunk
    os.close(read_fd)
    os.waitpid(pid, 0)
    return dict(item.split("=", 1) for item in raw.decode().split(";") if "=" in item)


def test_another_local_user_cannot_read_or_write_the_workspace():
    # Becoming another account requires privilege, so this cannot run everywhere.
    # A security test that quietly skips is a void guard, and this repository has
    # already been bitten by one (threat model §1, A1-4), so CI runs this file
    # once under sudo with PROM_REQUIRE_PRIVILEGED=1 — and then a skip is a
    # failure instead of a silence.
    if os.getuid() != 0:
        if _REQUIRE_PRIVILEGED:
            pytest.fail(
                "PROM_REQUIRE_PRIVILEGED=1 but this is not running as root, so the "
                "cross-user denial was never actually observed"
            )
        pytest.skip("dropping to another uid requires privilege")

    # Build the tree here rather than under ``tmp_path``: pytest's directory is
    # nested under a per-user root that other accounts cannot traverse, so a
    # denial there would be a property of the fixture, not of the workspace. The
    # parents are deliberately traversable so the only thing being measured is
    # the workspace's own mode.
    root = tempfile.mkdtemp(prefix="prom-priv-")
    try:
        os.chmod(root, 0o755)
        workspace = os.path.join(root, "ws")
        os.mkdir(workspace)
        with open(os.path.join(workspace, "secret.txt"), "w", encoding="utf-8") as handle:
            handle.write(CANARY)
        os.chmod(os.path.join(workspace, "secret.txt"), 0o644)

        # Positive control: while the directory is world-open, the other user CAN
        # reach it. Without this, "denied" might mean the fixture never worked.
        os.chmod(workspace, 0o777)
        before = _access_as_other_user(workspace)
        assert before.get("read") == "ALLOWED", (
            f"the control never reached a world-open workspace: {before}"
        )
        assert before.get("write") == "ALLOWED", before
        os.unlink(os.path.join(workspace, "planted.sql"))

        user, error = prepare_workspace(workspace)
        assert user is not None, error

        after = _access_as_other_user(workspace)
        for action in ("list", "read", "write"):
            assert after.get(action, "").startswith("DENIED"), (
                f"another local user could still {action} the workspace: {after}"
            )
    finally:
        subprocess.run(["rm", "-rf", root], check=False)


# ---------------------------------------------------------------------------
# 4. No adapter hands a candidate the runner's environment
# ---------------------------------------------------------------------------


_ENV_PROBE = """
import os
print("KEYS|" + ",".join(sorted(os.environ)))
print("CANARY|" + ("FOUND" if any("CANARY_VALUE" in v for v in os.environ.values()) else "absent"))
"""


def _run_env_probe(sandbox, tmp_path) -> dict[str, str]:
    workspace = tmp_path / f"ws-{sandbox.name}"
    workspace.mkdir()
    (workspace / "probe.py").write_text(_ENV_PROBE.replace("CANARY_VALUE", CANARY), encoding="utf-8")
    result = sandbox.run(
        argv=[sys.executable, "-I", "probe.py"],
        workspace=workspace,
        limits=Limits(wall_time_s=60, memory_bytes=0),
    )
    assert result.started_ok and result.exit_status == 0, (
        f"{sandbox.name} probe did not run: {result.detail} / {result.stderr}"
    )
    return dict(
        line.split("|", 1) for line in result.stdout.strip().splitlines() if "|" in line
    )


@pytest.fixture
def planted_secret(monkeypatch):
    monkeypatch.setenv("PROM_CHOKEPOINT_KEY", CANARY)
    monkeypatch.setenv("PGPASSWORD", CANARY)


def test_the_unsafe_adapter_also_withholds_the_runner_environment(planted_secret, tmp_path):
    """The A1-1 lesson generalized: it was one call site, and there was a second.

    ``UnsafeLocalSandbox`` isolates nothing by design — but it still executed
    candidate code with the runner's whole environment, signing key included.
    Dev-only is not a reason to leak a production key that happens to be exported
    in the same shell.
    """

    # Positive control: the canary really is in this process's environment.
    control = subprocess.run(
        [sys.executable, "-c", "import os; print(os.environ.get('PROM_CHOKEPOINT_KEY', ''))"],
        capture_output=True, text=True, timeout=60,
    )
    assert control.stdout.strip() == CANARY, "the canary was never planted"

    parsed = _run_env_probe(UnsafeLocalSandbox(), tmp_path)
    assert parsed["CANARY"] == "absent", "the signing key reached an unsafe-adapter candidate"
    assert set(parsed["KEYS"].split(",")) == set(CANDIDATE_ENV_KEYS)


def test_the_namespace_adapter_withholds_the_runner_environment(planted_secret, tmp_path):
    if not NamespaceSandbox.available():
        pytest.skip("namespace isolation runtime unavailable")
    parsed = _run_env_probe(NamespaceSandbox(), tmp_path)
    assert parsed["CANARY"] == "absent"
    assert set(parsed["KEYS"].split(",")) == set(CANDIDATE_ENV_KEYS)


def test_the_constructed_environment_carries_nothing_secret_shaped():
    built = candidate_env("/some/workspace")
    assert set(built) == set(CANDIDATE_ENV_KEYS)
    for name in ("PROM_CHOKEPOINT_KEY", "PGPASSWORD", "AWS_SECRET_ACCESS_KEY"):
        assert name not in built


# ---------------------------------------------------------------------------
# 5. Against a real container runtime
# ---------------------------------------------------------------------------


def _container_or_skip() -> ContainerSandbox:
    sandbox = ContainerSandbox()
    if not ContainerSandbox.available():
        if _REQUIRE_CONTAINER:
            pytest.fail("PROM_REQUIRE_CONTAINER=1 but no container runtime is usable")
        pytest.skip("no container runtime available")
    return sandbox


def test_real_container_workspace_stays_owner_only_and_still_works():
    """End-to-end: the candidate reads its code and writes its results, and the
    workspace never becomes world-anything."""

    sandbox = _container_or_skip()
    with tempfile.TemporaryDirectory(prefix="prom-priv-") as workspace:
        code = os.path.join(workspace, "task.py")
        with open(code, "w", encoding="utf-8") as handle:
            handle.write(
                "open('result.txt', 'w').write('written-by-candidate')\n"
                "print('candidate-ran')\n"
            )
        os.chmod(code, 0o644)
        result = sandbox.run(
            argv=["python", "task.py"],
            workspace=workspace,
            limits=Limits(wall_time_s=180, memory_bytes=0),
        )
        assert result.started_ok, f"container run failed: {result.detail} / {result.stderr}"
        assert "candidate-ran" in result.stdout, result.stdout
        produced = os.path.join(workspace, "result.txt")
        assert os.path.exists(produced), "the candidate could not write to its workspace"

        mode = stat.S_IMODE(os.stat(workspace).st_mode)
        assert mode & 0o077 == 0, f"workspace is group/other accessible: {mode:04o}"
