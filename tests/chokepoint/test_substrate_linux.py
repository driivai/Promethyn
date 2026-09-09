"""Real file mounts in disposable Linux namespaces. Fail, never skip.

No privileged mount operation touches the host namespace. No injected mount
table or probe: identity comes from actual fstat, fdinfo and mountinfo. Overlay
is the real unverified negative control; native network types have unit cases.
"""

import json
import os
import subprocess
import sys

import pytest


PROBE = r'''
import json, os, sqlite3, subprocess, sys
from pathlib import Path
from prometheus_protocol.chokepoint.substrate import (
    probe_substrate, probe_opened_substrate, probe_file_substrate, classify_path,
    parse_mountinfo, enforce_substrate, SubstratePolicy)
from prometheus_protocol.chokepoint.runner import ConsumedApprovals
from prometheus_protocol.chokepoint.authorization_journal import AuthorizationJournal
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.core.errors import ConfigError

root, case = Path(sys.argv[1]), sys.argv[2]
policy = SubstratePolicy(require_verified=True)
assert probe_substrate(root).verdict == "safe", "local-directory positive control failed"
def mount(*args):
    subprocess.run(["mount", *map(str, args)], check=True, capture_output=True, timeout=10)
def bind(source, target):
    target.touch(mode=0o600)
    mount("--bind", source, target)
def reject(call):
    try:
        call()
    except ConfigError:
        return
    raise AssertionError("unverified opened object was accepted")

if case in {"database_file", "journal_file", "hidden_descendant"}:
    lower, upper, work, overlay = [root / name for name in ("lower", "upper", "work", "overlay")]
    for path in (lower, upper, work, overlay):
        path.mkdir(mode=0o700)
    (lower / "private").mkdir(mode=0o700)
    mount("-t", "overlay", "overlay", "-o", f"lowerdir={lower},upperdir={upper},workdir={work}", overlay)
    assert probe_substrate(overlay).fs_type == "overlay"

if case == "database_file":
    source, target = overlay / "store.db", root / "mounted.db"
    source.touch(mode=0o600)
    bind(source, target)
    assert probe_substrate(target.parent).verdict == "safe"
    fd = os.open(target, os.O_RDONLY)
    try:
        report = probe_opened_substrate(fd)
        assert report.fs_type == "overlay" and report.verdict == "unknown"
        assert report.device == os.fstat(fd).st_dev != target.parent.stat().st_dev
    finally:
        os.close(fd)
    reject(lambda: ConsumedApprovals(target, substrate_policy=policy))
    assert source.stat().st_size == 0, "SQLite must not initialize a refused store"

elif case == "journal_file":
    source, target = overlay / "audit.db", root / "mounted-audit.db"
    SqliteLedger.private(source).close()
    bind(source, target)
    ledger = SqliteLedger(target)
    try:
        assert probe_file_substrate(target).fs_type == "overlay"
        reject(lambda: AuthorizationJournal(ledger, substrate_policy=policy))
        assert ledger.chained_events() == []
    finally:
        ledger.close()

elif case == "lock_file_alias":
    # FIX-B has no companion lock: a separately mounted alias of the store is
    # a separately mounted lock object. Its mount ID differs; its inode does not.
    original, alias = root / "original.db", root / "lock-alias.db"
    first = ConsumedApprovals(original, substrate_policy=policy)
    try:
        bind(original, alias)
        second = ConsumedApprovals(alias, substrate_policy=policy)
        try:
            a = probe_opened_substrate(first._guard_fd)
            b = probe_opened_substrate(second._guard_fd)
            assert a.mount_id != b.mount_id and a.device == b.device and a.inode == b.inode
            assert first.lock_id == second.lock_id and alias.stat().st_nlink == 1
            with first.execution_guard() as held:
                assert held
                child = subprocess.run([sys.executable, "-c", """
import sys
from prometheus_protocol.chokepoint.runner import ConsumedApprovals
from prometheus_protocol.chokepoint.substrate import SubstratePolicy
store = ConsumedApprovals(sys.argv[1], substrate_policy=SubstratePolicy(require_verified=True))
try:
    with store.execution_guard() as held:
        print('owned' if held else 'busy')
finally:
    store.close()
""", str(alias)], capture_output=True, text=True, timeout=10)
                assert child.returncode == 0 and child.stdout.strip() == "busy", child.stderr
            with second.execution_guard() as held:
                assert held, "positive control after release"
        finally:
            second.close()
    finally:
        first.close()

elif case == "hidden_descendant":
    parent = root / "srv"
    parent.mkdir(mode=0o700)
    mount("-t", "tmpfs", "tmpfs", parent)
    (parent / "private").mkdir(mode=0o700)
    mount("-t", "tmpfs", "tmpfs", parent / "private")
    mount("--bind", overlay, parent)
    table = Path('/proc/self/mountinfo').read_text()
    report = classify_path(str(parent / "private"), table)
    assert report.fs_type == "overlay" and report.verdict == "unknown", report
    reject(lambda: ConsumedApprovals(parent / "private" / "db", substrate_policy=policy))

elif case == "journal_posix_lock":
    path = root / "audit.db"
    ledger = SqliteLedger.private(path)
    try:
        journal = AuthorizationJournal(ledger, substrate_policy=policy)
        ledger._conn.execute("BEGIN IMMEDIATE")
        journal._check_path()  # closing an ordinary read fd here would drop the POSIX locks
        child = subprocess.run([sys.executable, "-c", """
import sqlite3, sys
db = sqlite3.connect(sys.argv[1], timeout=0.1)
try:
    db.execute('BEGIN IMMEDIATE')
except sqlite3.OperationalError as exc:
    assert 'locked' in str(exc)
    print('blocked')
else:
    print('acquired')
finally:
    db.close()
""", str(path)], capture_output=True, text=True, timeout=10)
        assert child.returncode == 0 and child.stdout.strip() == "blocked", child.stderr
        ledger._conn.rollback()
        assert journal.records() == []
    finally:
        ledger.close()

elif case == "namespace_file":
    target = root / "namespace"
    bind(Path("/proc/self/ns/net"), target)
    entries = parse_mountinfo(Path("/proc/self/mountinfo").read_text())
    matching = [e for e in entries if e.mount_point == str(target)]
    assert len(matching) == 1
    assert matching[0].fs_type == "nsfs" and matching[0].root.startswith("net:[")
    fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
    try:
        report = probe_opened_substrate(fd)
        assert (report.fs_type, report.verdict, report.mount_id) == ("nsfs", "unknown", matching[0].mount_id)
        reject(lambda: enforce_substrate(report, policy))
    finally:
        os.close(fd)
    # A namespace file elsewhere must not poison the entire mount table.
    store = ConsumedApprovals(root / "local.db", substrate_policy=policy)
    try:
        assert store.claim("namespace-positive-control", "now")
        with store.execution_guard() as held:
            assert held
    finally:
        store.close()
else:
    raise AssertionError(case)
print(json.dumps({"case": case, "passed": True}))
'''


@pytest.mark.parametrize("case", ["database_file", "journal_file", "lock_file_alias",
                                  "hidden_descendant", "journal_posix_lock", "namespace_file"])
def test_linux_opened_substrate(case, tmp_path):
    assert sys.platform.startswith("linux"), "Linux mount integration is required, not skipped"
    command = ["unshare", "--mount", "--propagation", "private"]
    if os.geteuid() != 0:
        command += ["--user", "--map-root-user"]
    if case == "namespace_file":
        command += ["--net"]
    result = subprocess.run(command + [sys.executable, "-c", PROBE, str(tmp_path), case],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout.strip().splitlines()[-1]) == {"case": case, "passed": True}
