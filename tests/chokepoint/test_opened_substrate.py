"""Opened-object and topology guards. Synthetic metadata, no platform skips.

These unit tests distinguish the queried object and model missing metadata;
real mounts/descriptor identities are exercised by the Linux integration job.
"""

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from prometheus_protocol.chokepoint import substrate as s
from prometheus_protocol.chokepoint import runner as r
from prometheus_protocol.core.errors import ConfigError

HIDDEN = """10 10 8:1 / / rw - ext4 /dev/vda1 rw
20 10 8:2 / /srv rw - ext4 /dev/vdb1 rw
21 20 0:31 / /srv/private rw - tmpfs tmpfs rw
30 20 0:32 / /srv rw - nfs4 server:/shared rw
"""


def metadata(info, *, fs="nfs4", mount_id=40, path="/independent-file"):
    return ("10 10 0:1 / / rw - ext4 root rw\n"
            f"{mount_id} 10 {os.major(info.st_dev)}:{os.minor(info.st_dev)} "
            f"/source {path} rw - {fs} device rw\n")


def safe(path):
    return s.SubstrateReport(str(path), s.SUBSTRATE_SAFE, "ext4", "/", "unit fixture")


@pytest.mark.parametrize("order", ["forward", "reverse", "mixed"])
def test_hidden_descendant_is_not_visible(order):
    rows = HIDDEN.splitlines()
    if order == "reverse":
        rows.reverse()
    if order == "mixed":
        rows = [rows[i] for i in (2, 0, 3, 1)]
    report = s.classify_path("/srv/private/store.db", "\n".join(rows))
    assert (report.verdict, report.mount_id, report.fs_type) == ("unsafe", 30, "nfs4")
    with pytest.raises(ConfigError, match="no opt-out"):
        s.enforce_substrate(report, s.SubstratePolicy(require_verified=True))


def test_topology_fields_are_retained():
    entries = s.parse_mountinfo(HIDDEN)
    assert [(e.mount_id, e.parent_id, e.device) for e in entries] == [
        (10, 10, (8, 1)), (20, 10, (8, 2)), (21, 20, (0, 31)), (30, 20, (0, 32))]
    assert entries[2].root == "/"


@pytest.mark.parametrize("kind", ["net", "mnt", "user", "pid", "time"])
def test_namespace_root_label_preserves_local_and_namespace_identity(kind):
    # Linux nsfs_show_path emits a label, not a pathname. Docker's service
    # network namespace mounts add this shape to otherwise local CI hosts.
    label = f"{kind}:[4026533001]"
    point = "/run/docker/netns/service"
    table = ("10 1 8:1 / / rw - ext4 /dev/root rw\n"
             f"50 10 0:4 {label} {point} rw - nsfs nsfs rw\n")
    local = s.classify_path("/tmp/private/store.db", table)
    assert (local.verdict, local.mount_id) == ("safe", 10)
    entries = s.parse_mountinfo(table)
    assert [(e.mount_id, e.root) for e in entries] == [(10, "/"), (50, label)]
    info = SimpleNamespace(st_dev=os.makedev(8, 1), st_ino=42)
    opened = s.classify_opened(info, "mnt_id: 10", table)
    assert (opened.verdict, opened.mount_id) == ("safe", 10)
    # Do not "fix" compatibility by discarding the namespace entry or treating
    # it as local storage. Both pathname and exact descriptor lookup retain it.
    namespace = s.classify_path(point, table)
    ns_info = SimpleNamespace(st_dev=os.makedev(0, 4), st_ino=4026533001)
    ns_opened = s.classify_opened(ns_info, "mnt_id: 50", table)
    for report in (namespace, ns_opened):
        assert (report.verdict, report.fs_type, report.mount_id) == ("unknown", "nsfs", 50)
        with pytest.raises(ConfigError):
            s.enforce_substrate(report, s.SubstratePolicy(require_verified=True))


@pytest.mark.parametrize("root,point,driver,located", [
    ("net:[oops]", "/run/ns", "nsfs", True),
    ("net:[123]junk", "/run/ns", "nsfs", True),
    ("net:[１２３]", "/run/ns", "nsfs", True),
    ("net:[123]", "/run/ns", "ext4", True),
    ("net:[123]", "run/ns", "nsfs", False),
    ("relative", "/run/ns", "nsfs", True),
])
def test_namespace_metadata_does_not_weaken_validation(root, point, driver, located):
    """Recognition stays exact: none of these is read as a mount identity.

    Relevance scoping (SUBSTRATE-ROBUST) changed only *where* an unread row
    matters, never whether a malformed root is accepted as a valid one. The
    row is recorded unread; it refuses on its own mount point, and where its
    location is not readable at all it refuses everywhere.
    """
    table = ("10 1 8:1 / / rw - ext4 /dev/root rw\n"
             f"50 10 0:4 {root} {point} rw - {driver} source rw\n")
    parsed = s.parse_mount_table(table)
    assert [e.mount_id for e in parsed.entries] == [10], "malformed row was accepted"
    assert len(parsed.unparsed) == 1
    with pytest.raises(ValueError, match="unreadable mount table row"):
        s.parse_mountinfo(table)
    assert s.classify_path("/run/ns/store.db", table).verdict == "unknown"
    elsewhere = s.classify_path("/tmp/store.db", table)
    assert elsewhere.verdict == ("safe" if located else "unknown")
    assert [e.mount_point for e in elsewhere.set_aside] == ([point] if located else [])
    # The descriptor join is keyed to identity: this row named mount 50, so it
    # is not mount 10 — and it is exactly the row that mount 50 would need.
    info = SimpleNamespace(st_dev=os.makedev(8, 1), st_ino=42)
    assert s.classify_opened(info, "mnt_id: 10", table).verdict == "safe"
    assert s.classify_opened(info, "mnt_id: 50", table).verdict == "unknown"


@pytest.mark.parametrize("table", [
    HIDDEN + "30 20 0:32 / /srv rw - ext4 wrong rw\n",
    HIDDEN + "99 10 0:99 / /srv rw - ext4 ambiguous rw\n",
    HIDDEN.replace("20 10", "20 21"),
    HIDDEN.replace("30 20", "30 999"),
    HIDDEN.replace("10 10 8:1 / /", "10 999 8:1 / /outside"),
    HIDDEN + "malformed line\n",
])
def test_unresolvable_topology_refuses(table):
    report = s.classify_path("/srv/private", table)
    assert report.verdict == "unknown"
    with pytest.raises(ConfigError):
        s.enforce_substrate(report, s.SubstratePolicy(require_verified=True))


def test_visible_local_descendant_positive_control():
    table = HIDDEN + "31 30 0:55 / /srv/private rw - tmpfs local rw\n"
    report = s.classify_path("/srv/private/store", table)
    assert (report.verdict, report.mount_id) == ("safe", 31)
    s.enforce_substrate(report, s.SubstratePolicy(require_verified=True))


@pytest.mark.parametrize("fdinfo", ["", "mnt_id: nope", "mnt_id: 40\nmnt_id: 40", "mnt_id: 99"])
def test_missing_or_ambiguous_descriptor_mount_refuses(fdinfo):
    info = SimpleNamespace(st_dev=os.makedev(8, 1), st_ino=42)
    report = s.classify_opened(info, fdinfo, metadata(info, fs="ext4"))
    assert report.verdict == "unknown"
    with pytest.raises(ConfigError):
        s.enforce_substrate(report, s.SubstratePolicy())


def test_descriptor_device_mismatch_refuses():
    info = SimpleNamespace(st_dev=os.makedev(8, 1), st_ino=42)
    table = metadata(SimpleNamespace(st_dev=os.makedev(8, 2)), fs="ext4")
    assert s.classify_opened(info, "mnt_id: 40", table).verdict == "unknown"


@pytest.mark.parametrize("fs,verdict", [("ext4", "safe"), ("nfs4", "unsafe"), ("overlay", "unknown")])
def test_descriptor_identity_not_path_or_device_alone(tmp_path, fs, verdict):
    path = tmp_path / "db"
    path.touch(mode=0o600)
    fd = os.open(path, os.O_RDONLY)
    try:
        info = os.fstat(fd)
        table = metadata(info, fs=fs) + metadata(info, fs="ext4", mount_id=41).splitlines()[1] + "\n"
        report = s.classify_opened(info, "mnt_id: 40", table)
        assert (report.verdict, report.mount_id, report.device, report.inode) == (
            verdict, 40, info.st_dev, info.st_ino)
    finally:
        os.close(fd)


@pytest.mark.parametrize("missing", ["none", "fdinfo", "mountinfo"])
def test_real_descriptor_probe_reads_both_metadata_sources(tmp_path, monkeypatch, missing):
    path = tmp_path / "db"
    path.touch(mode=0o600)
    fd = os.open(path, os.O_RDONLY)
    seen = []
    def read(path, **kwargs):
        seen.append(str(path))
        if str(path) == f"/proc/self/fdinfo/{fd}":
            if missing == "fdinfo":
                raise OSError("fixture unavailable")
            return "mnt_id: 40\n"
        assert str(path) == s.MOUNTINFO_PATH
        if missing == "mountinfo":
            raise OSError("fixture unavailable")
        return metadata(os.fstat(fd))
    try:
        with monkeypatch.context() as patch:
            patch.setattr(s.sys, "platform", "linux")
            patch.setattr(Path, "read_text", read)
            report = s.probe_opened_substrate(fd)
        assert report.verdict == ("unsafe" if missing == "none" else "unknown")
        assert seen[0] == f"/proc/self/fdinfo/{fd}"
    finally:
        os.close(fd)


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("fs", ["nfs4", "overlay"])
def test_opened_store_refuses_despite_safe_parent(tmp_path, existing, fs):
    path = tmp_path / "store.db"
    if existing:
        path.touch(mode=0o600)
    def preflight(queried):
        assert Path(queried) == path.parent
        return safe(queried)
    seen = []
    def opened(fd):
        info = os.fstat(fd)
        assert (info.st_dev, info.st_ino) == (path.stat().st_dev, path.stat().st_ino)
        seen.append(fd)
        return s.classify_opened(info, "mnt_id: 40", metadata(info, fs=fs))
    with pytest.raises(ConfigError):
        r.ConsumedApprovals(path, substrate_policy=s.SubstratePolicy(require_verified=True),
                            probe=preflight, opened_probe=opened)
    assert seen and path.stat().st_size == 0, "refuse before SQLite initialization"
    with pytest.raises(OSError):
        os.fstat(seen[0])


@pytest.mark.parametrize("reopen", [False, True])
def test_held_lock_object_is_reinspected(tmp_path, monkeypatch, reopen):
    path = tmp_path / "store.db"
    state = {"fs": "ext4", "calls": 0}
    def opened(fd):
        state["calls"] += 1
        info = os.fstat(fd)
        if state["calls"] > 1:
            assert (info.st_dev, info.st_ino) == store.identity
        return s.classify_opened(info, "mnt_id: 40", metadata(info, fs=state["fs"]))
    store = r.ConsumedApprovals(path, substrate_policy=s.SubstratePolicy(require_verified=True),
                                probe=lambda p: safe(p), opened_probe=opened)
    # Unit-check gating before flock, not macOS/Linux flock equivalence.
    flock_calls = []
    try:
        with monkeypatch.context() as patch:
            patch.setattr(r.sys, "platform", "linux")
            patch.setattr(r, "fcntl", SimpleNamespace(LOCK_EX=2, LOCK_NB=4, LOCK_UN=8,
                                                       flock=lambda *a: flock_calls.append(a)))
            with store.execution_guard() as held:
                assert held
            flock_calls.clear()
            state["fs"] = "nfs4"
            if reopen:
                store._guard_pid = -1
            with pytest.raises(r._OwnershipUnavailable):
                with store.execution_guard():
                    pytest.fail("unsafe lock reached execution")
            assert flock_calls == []
    finally:
        store.close()


@pytest.mark.parametrize("field", ["require_verified", "allow_unverified"])
@pytest.mark.parametrize("value", ["false", 1, None])
def test_direct_policy_uses_strict_booleans(field, value):
    with pytest.raises(ConfigError):
        s.SubstratePolicy(**{field: value})


def test_journal_inspection_uses_o_path_and_closes(tmp_path, monkeypatch):
    path = tmp_path / "journal.db"
    path.touch(mode=0o600)
    fd = os.open(path, os.O_RDONLY)
    # Assert the syscall contract on any host; Linux integration below proves
    # that these flags actually preserve a live SQLite transaction's locks.
    def open_path(queried, flags):
        assert queried == path
        assert flags & os.O_PATH and flags & os.O_NOFOLLOW and flags & os.O_CLOEXEC
        return fd
    try:
        with monkeypatch.context() as patch:
            patch.setattr(s.sys, "platform", "linux")
            patch.setattr(os, "O_PATH", 0x200000, raising=False)
            patch.setattr(os, "open", open_path)
            patch.setattr(s, "probe_opened_substrate", lambda held: safe(str(held)))
            assert s.probe_file_substrate(path).verdict == "safe"
        with pytest.raises(OSError):
            os.fstat(fd)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


@pytest.mark.parametrize("failure", ["placement", "identity"])
def test_journal_rechecks_before_operation(tmp_path, monkeypatch, failure):
    from prometheus_protocol.chokepoint import authorization_journal as j
    from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
    ledger = SqliteLedger.private(tmp_path / "journal.db")
    path = Path(ledger.path).absolute()
    state = {"failed": False}
    def inspect(queried):
        assert queried == path
        info = path.stat()
        changed = state["failed"]
        return s.SubstrateReport(str(path), "unsafe" if changed and failure == "placement" else "safe",
                                 "nfs4" if changed else "ext4", "/", "unit fixture",
                                 info.st_dev, info.st_ino + (1 if changed and failure == "identity" else 0))
    monkeypatch.setattr(j, "probe_file_substrate", inspect)
    try:
        journal = j.AuthorizationJournal(ledger, substrate_policy=s.SubstratePolicy(require_verified=True))
        assert journal.records() == []
        state["failed"] = True
        with pytest.raises(j.AuthorizationUnavailable):
            journal.records()
    finally:
        ledger.close()


def test_requirement_does_not_hide_invalid_opt_out_source():
    with pytest.raises(ConfigError):
        s.resolve_substrate_policy(SimpleNamespace(allow_unverified_substrate=True),
                                   env={"PROM_ALLOW_UNVERIFIED_SUBSTRATE": "tru"})
