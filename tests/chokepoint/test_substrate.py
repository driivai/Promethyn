"""F3 rework, part one: the execution guard's substrate is checked, not assumed.

The guard is an flock beside the consumed-approval store, which is mutual
exclusion only on a local filesystem of one host. Before this, that was a
sentence in ``docs/chokepoint-threat-model.md``; now the store probes its
filesystem before it creates anything and refuses a network filesystem
outright, and an unidentified one unless the operator explicitly opts out.

No test here mounts anything. The classification is driven by a mount table
the test supplies (``classify_path``) or by a probe the test injects into the
store, so an NFS mount is simulated exactly and CI never depends on one. The
positive controls run the real probe against this checkout, so a CI runner on
an unexpected filesystem fails legibly instead of failing every store.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import pytest
from f11_support import authorization_context

from prometheus_protocol.chokepoint import (
    SUBSTRATE_SAFE,
    SUBSTRATE_UNKNOWN,
    SUBSTRATE_UNSAFE,
    UNVERIFIED_SUBSTRATE_ALLOWED_ENV,
    VERIFIED_SUBSTRATE_REQUIRED_ENV,
    RECEIPT_NOT_FOUND,
    ConsumedApprovals,
    DbTarget,
    MigrationRunnerConfig,
    ReceiptStatus,
    SubstratePolicy,
    SubstrateReport,
    build_migration_runtime,
    classify_path,
    probe_substrate,
    resolve_substrate_policy,
)
from prometheus_protocol.chokepoint import substrate as substrate_module
from prometheus_protocol.chokepoint.signer import LocalHmacSigner
from prometheus_protocol.core.config import SECURITY_FIELDS, Config
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger

KEY = b"substrate-test-key-32-bytes-minimum!"
SUBSTRATE_LOGGER = "prometheus_protocol.chokepoint.substrate"


def table(*mounts: tuple[str, str]) -> str:
    """Chronological mounts with actual parent relationships and hidden trees.

    Keep hidden entries in mountinfo but remove them from the path-resolution
    view used to parent subsequent mounts. No production resolver is used.
    """

    lines: list[str] = []
    visible: dict[str, object] = {}
    if not mounts or mounts[0][0] != "/":
        mounts = (("/", "ext4"), *mounts)
    for index, (mount_point, fs_type) in enumerate(mounts, start=20):
        ancestors = [p for p in visible if p == "/" or mount_point == p
                     or mount_point.startswith(p.rstrip("/") + "/")]
        parent = visible[max(ancestors, key=len)] if ancestors else index
        lines.append(
            f"{index} {parent} 0:{index} / {mount_point} rw,relatime shared:{index} - "
            f"{fs_type} source-{index} rw"
        )
        visible = {p: ident for p, ident in visible.items()
                   if not (p == mount_point or p.startswith(mount_point.rstrip("/") + "/"))}
        visible[mount_point] = index
    return "\n".join(lines) + "\n"


def report(verdict: str, fs_type: str | None = "nfs4") -> SubstrateReport:
    return SubstrateReport(
        path="/srv/store",
        verdict=verdict,
        fs_type=fs_type,
        mount_point="/srv" if fs_type else None,
        detail=f"synthetic {verdict} substrate",
    )


def probe_returning(fixed: SubstrateReport, expected: Path):
    def probe(path):
        assert Path(path) == expected, "wrong preflight object"
        return fixed
    return probe


def opened_probe(fixed: SubstrateReport, expected: Path):
    def probe(fd):
        info, wanted = os.fstat(fd), expected.stat()
        assert (info.st_dev, info.st_ino) == (wanted.st_dev, wanted.st_ino), "wrong opened object"
        return fixed
    return probe


def target() -> DbTarget:
    return DbTarget("localhost", 5432, "appdb", "migrator", "synthetic-secret")


# ---------------------------------------------------------------------------
# 1. Classification: named filesystems, most specific mount, kernel escaping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fs_type",
    ["nfs", "nfs4", "cifs", "smb3", "9p", "virtiofs", "vboxsf", "ceph", "gfs2",
     "ocfs2", "lustre", "afs", "fuse.sshfs", "fuse.glusterfs", "fuse.s3fs"],
)
def test_network_and_host_shared_filesystems_are_unsafe(fs_type):
    verdict = classify_path("/mnt/shared/store", table(("/", "ext4"), ("/mnt/shared", fs_type)))
    assert verdict.verdict == SUBSTRATE_UNSAFE
    assert verdict.fs_type == fs_type and verdict.mount_point == "/mnt/shared"
    assert "other hosts" in verdict.detail


@pytest.mark.parametrize("fs_type", ["ext4", "ext3", "xfs", "btrfs", "tmpfs", "f2fs", "zfs"])
def test_local_filesystems_are_safe(fs_type):
    verdict = classify_path("/var/lib/store", table(("/", fs_type)))
    assert verdict.verdict == SUBSTRATE_SAFE and verdict.fs_type == fs_type


@pytest.mark.parametrize(
    "fs_type,phrase",
    [("overlay", "layered"), ("fuse", "userspace"), ("fuse.encfs", "userspace"),
     ("fuseblk", "not a filesystem this runner knows"), ("newfs", "not a filesystem this runner knows")],
)
def test_layered_userspace_and_unknown_filesystems_are_unknown_never_safe(fs_type, phrase):
    verdict = classify_path("/data/store", table(("/", "ext4"), ("/data", fs_type)))
    assert verdict.verdict == SUBSTRATE_UNKNOWN and phrase in verdict.detail


def test_the_most_specific_mount_decides():
    mounts = table(("/", "ext4"), ("/mnt", "nfs4"), ("/mnt/local", "xfs"))
    assert classify_path("/mnt/local/store", mounts).fs_type == "xfs"
    assert classify_path("/mnt/other/store", mounts).verdict == SUBSTRATE_UNSAFE
    assert classify_path("/mnt", mounts).verdict == SUBSTRATE_UNSAFE
    assert classify_path("/mntx/store", mounts).fs_type == "ext4"  # prefix, not path component
    assert classify_path("/var/lib/store", mounts).verdict == SUBSTRATE_SAFE


def test_an_overmount_shadows_the_mount_beneath_it():
    assert classify_path("/data/s", table(("/data", "nfs4"), ("/data", "ext4"))).verdict == SUBSTRATE_SAFE
    assert classify_path("/data/s", table(("/data", "ext4"), ("/data", "nfs4"))).verdict == SUBSTRATE_UNSAFE


def test_escaped_mount_points_and_malformed_lines():
    mounts = (
        "21 23 0:21 / /mnt/net\\040share rw - nfs4 nas:/export rw\n"
        "23 23 0:23 / / rw - ext4 /dev/root rw\n"
    )
    assert classify_path("/mnt/net share/store", mounts).verdict == SUBSTRATE_UNSAFE
    assert classify_path("/mnt/net share/store", mounts).mount_point == "/mnt/net share"
    assert classify_path("/home/store", mounts).verdict == SUBSTRATE_SAFE
    assert classify_path("/home/store", mounts + "malformed line\n").verdict == SUBSTRATE_UNKNOWN


def test_no_covering_mount_is_unknown():
    verdict = classify_path("/srv/store", "20 1 0:20 / /mnt rw - ext4 source rw\n")
    assert verdict.verdict == SUBSTRATE_UNKNOWN and verdict.fs_type is None


def test_the_real_probe_reports_this_checkout(tmp_path):
    """Positive control for the probe itself. On Linux the mount table is
    readable and names a filesystem; elsewhere the probe says so, as unknown."""

    verdict = probe_substrate(tmp_path / "does-not-exist-yet" / "store.db")
    assert verdict.verdict in {SUBSTRATE_SAFE, SUBSTRATE_UNSAFE, SUBSTRATE_UNKNOWN}
    if sys.platform.startswith("linux"):
        assert verdict.fs_type is not None and verdict.mount_point is not None
        assert verdict.path == str(tmp_path.resolve())
    else:
        assert verdict.verdict == SUBSTRATE_UNKNOWN and verdict.fs_type is None


def test_an_unreadable_mount_table_is_unknown_not_safe(monkeypatch, tmp_path):
    monkeypatch.setattr(substrate_module, "MOUNTINFO_PATH", str(tmp_path / "absent"))
    monkeypatch.setattr(substrate_module.sys, "platform", "linux")
    verdict = probe_substrate(tmp_path)
    assert verdict.verdict == SUBSTRATE_UNKNOWN and "could not be read" in verdict.detail


# ---------------------------------------------------------------------------
# 2. The store refuses: unsafe always, unknown by default
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "policy",
    [SubstratePolicy(), SubstratePolicy(allow_unverified=True), SubstratePolicy(require_verified=True)],
    ids=["default", "opt-out-set", "required"],
)
def test_an_unsafe_substrate_refuses_construction_and_creates_nothing(tmp_path, policy):
    store = tmp_path / "shared" / "store.db"
    with pytest.raises(ConfigError, match="no opt-out for a known-unsafe substrate"):
        ConsumedApprovals(store, substrate_policy=policy, probe=probe_returning(report(SUBSTRATE_UNSAFE), store.parent))
    assert not store.parent.exists(), "nothing of the runner's may be left on a refused substrate"


def test_an_unsafe_substrate_ignores_the_environment_opt_out(tmp_path):
    with pytest.raises(ConfigError, match="cannot host the execution guard"):
        ConsumedApprovals(
            tmp_path / "store.db",
            env={UNVERIFIED_SUBSTRATE_ALLOWED_ENV: "1"},
            probe=probe_returning(report(SUBSTRATE_UNSAFE), tmp_path),
        )


def test_an_unknown_substrate_is_refused_by_default(tmp_path):
    store = tmp_path / "somewhere" / "store.db"
    with pytest.raises(ConfigError, match="Couldn't-verify is not verified-safe") as refusal:
        ConsumedApprovals(store, env={}, probe=probe_returning(report(SUBSTRATE_UNKNOWN, "overlay"), store.parent))
    assert UNVERIFIED_SUBSTRATE_ALLOWED_ENV in str(refusal.value)
    assert not store.parent.exists()


@pytest.mark.parametrize("source", ["policy", "environment"])
def test_an_unknown_substrate_proceeds_only_on_the_explicit_opt_out_and_warns(tmp_path, caplog, source):
    caplog.set_level(logging.WARNING, logger=SUBSTRATE_LOGGER)
    probe = probe_returning(report(SUBSTRATE_UNKNOWN, "overlay"), tmp_path)
    inspect = opened_probe(report(SUBSTRATE_SAFE, "ext4"), tmp_path / "store.db")
    if source == "policy":
        store = ConsumedApprovals(tmp_path / "store.db", substrate_policy=SubstratePolicy(allow_unverified=True), probe=probe, opened_probe=inspect)
    else:
        store = ConsumedApprovals(tmp_path / "store.db", env={UNVERIFIED_SUBSTRATE_ALLOWED_ENV: "yes"}, probe=probe, opened_probe=inspect)
    try:
        assert store.substrate.verdict == SUBSTRATE_SAFE  # actual object, not preflight cache
        assert store.claim("nonce-1", "now") and not store.claim("nonce-1", "now")
    finally:
        store.close()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING and r.name == SUBSTRATE_LOGGER]
    assert len(warnings) == 1, "the opt-out must be logged, every time"
    text = warnings[0].getMessage()
    assert "UNVERIFIED" in text and "UNPROVEN" in text and UNVERIFIED_SUBSTRATE_ALLOWED_ENV in text
    assert "overlay" in text


def test_the_requirement_withdraws_the_opt_out(tmp_path):
    probe = probe_returning(report(SUBSTRATE_UNKNOWN, "overlay"), tmp_path)
    with pytest.raises(ConfigError, match="require_verified_substrate=True cannot be honoured"):
        ConsumedApprovals(tmp_path / "store.db", substrate_policy=SubstratePolicy(require_verified=True), probe=probe)
    # Raised in the environment, it withdraws an opt-out set in a runner config.
    with pytest.raises(ConfigError, match="alongside allow_unverified_substrate"):
        resolve_substrate_policy(
            MigrationRunnerConfig(target=target(), signing_key=KEY, approval_store_path=tmp_path / "s", allow_unverified_substrate=True),
            env={VERIFIED_SUBSTRATE_REQUIRED_ENV: "1"},
        )


@pytest.mark.parametrize(
    "policy", [SubstratePolicy(), SubstratePolicy(require_verified=True), SubstratePolicy(allow_unverified=True)],
    ids=["default", "required", "opt-out-set"],
)
def test_a_safe_substrate_constructs_normally_under_every_policy(tmp_path, caplog, policy):
    """The positive control: the check refuses the wrong thing, not everything."""

    caplog.set_level(logging.WARNING, logger=SUBSTRATE_LOGGER)
    safe = report(SUBSTRATE_SAFE, "ext4")
    store = ConsumedApprovals(tmp_path / "store.db", substrate_policy=policy,
                             probe=probe_returning(safe, tmp_path),
                             opened_probe=opened_probe(safe, tmp_path / "store.db"))
    try:
        assert store.substrate.verdict == SUBSTRATE_SAFE
        if sys.platform.startswith("linux"):
            with store.execution_guard() as owned:
                assert owned
        else:
            from prometheus_protocol.chokepoint.runner import _OwnershipUnavailable
            with pytest.raises(_OwnershipUnavailable, match="_PlatformUnsupported"):
                with store.execution_guard():
                    pytest.fail("non-Linux execution is not supported")
    finally:
        store.close()
    assert not [r for r in caplog.records if r.name == SUBSTRATE_LOGGER]


def test_the_real_probe_on_this_checkout_constructs_or_refuses_honestly(tmp_path):
    """Under the real probe, with no opt-out: a safe filesystem constructs (the
    CI runner's), an unknown one refuses. Nothing in between."""

    verdict = probe_substrate(tmp_path)
    if verdict.verdict == SUBSTRATE_SAFE:
        ConsumedApprovals(tmp_path / "store.db", env={}).close()
    else:
        with pytest.raises(ConfigError):
            ConsumedApprovals(tmp_path / "store.db", env={})


# ---------------------------------------------------------------------------
# 3. The two settings: OR of sources, coherent, declared, consumed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "runner_flag,settings_flag,env_value,expected",
    [(False, False, None, False), (True, False, None, True), (False, True, None, True),
     (False, False, "1", True), (False, False, "0", False), (False, False, "true", True)],
    ids=["none", "runner-config", "config", "env", "env-off", "env-word"],
)
def test_the_requirement_is_the_or_of_its_sources(tmp_path, runner_flag, settings_flag, env_value, expected):
    config = MigrationRunnerConfig(
        target=target(), signing_key=KEY, approval_store_path=tmp_path / "s",
        require_verified_substrate=runner_flag,
    )
    env = {} if env_value is None else {VERIFIED_SUBSTRATE_REQUIRED_ENV: env_value}
    policy = resolve_substrate_policy(config, settings=Config(require_verified_substrate=settings_flag), env=env)
    assert policy.require_verified is expected
    # A programmatic False beside the variable does not lower it.
    if env_value == "1":
        assert resolve_substrate_policy(config, settings=Config(require_verified_substrate=False), env=env).require_verified


def test_the_opt_out_is_honoured_from_any_source(tmp_path):
    base = dict(target=target(), signing_key=KEY, approval_store_path=tmp_path / "s")
    assert resolve_substrate_policy(MigrationRunnerConfig(**base, allow_unverified_substrate=True), env={}).allow_unverified
    assert resolve_substrate_policy(MigrationRunnerConfig(**base), settings=Config(allow_unverified_substrate=True), env={}).allow_unverified
    assert resolve_substrate_policy(MigrationRunnerConfig(**base), env={UNVERIFIED_SUBSTRATE_ALLOWED_ENV: "on"}).allow_unverified
    assert not resolve_substrate_policy(MigrationRunnerConfig(**base), env={}).allow_unverified


def test_the_incoherent_pair_is_refused_at_every_layer(tmp_path):
    with pytest.raises(ConfigError, match="would never take effect"):
        Config(require_verified_substrate=True, allow_unverified_substrate=True)
    with pytest.raises(ConfigError, match="would never take effect"):
        Config.from_env({VERIFIED_SUBSTRATE_REQUIRED_ENV: "1", UNVERIFIED_SUBSTRATE_ALLOWED_ENV: "1"})
    with pytest.raises(ConfigError, match="would never take effect"):
        MigrationRunnerConfig(
            target=target(), signing_key=KEY, approval_store_path=tmp_path / "s",
            require_verified_substrate=True, allow_unverified_substrate=True,
        )
    with pytest.raises(ConfigError, match="would never take effect"):
        resolve_substrate_policy(env={VERIFIED_SUBSTRATE_REQUIRED_ENV: "1", UNVERIFIED_SUBSTRATE_ALLOWED_ENV: "1"})


def test_both_settings_are_declared_security_fields_read_from_the_environment():
    assert "require_verified_substrate" in SECURITY_FIELDS
    assert "allow_unverified_substrate" in SECURITY_FIELDS
    assert Config().require_verified_substrate is False and Config().allow_unverified_substrate is False
    assert Config.from_env({VERIFIED_SUBSTRATE_REQUIRED_ENV: "1"}).require_verified_substrate is True
    assert Config.from_env({UNVERIFIED_SUBSTRATE_ALLOWED_ENV: "1"}).allow_unverified_substrate is True


# ---------------------------------------------------------------------------
# 4. Through the production builder
# ---------------------------------------------------------------------------


class _SpyExecutor:
    """A ``MigrationExecutor`` that records the call and touches no database.

    A real class with the protocol's signature, not a ``lambda *a``: the point
    of these spies is to prove a refusal never reaches the DB, and a spy whose
    shape does not match the port could stop being called for a reason the test
    would read as success. Structural typing does the rest — no cast.
    """

    def __init__(self, calls: list) -> None:
        self._calls = calls

    def __call__(
        self, sql: str, target: DbTarget, execution_id: str, artifact_sha256: str
    ) -> tuple[bool, str]:
        self._calls.append((sql, target, execution_id, artifact_sha256))
        # Legacy (False, detail) is UNKNOWN, never proof of rollback — which is
        # the honest answer for a spy that ran no SQL at all.
        return False, "spy executor: no SQL was run"


class _SpyReceiptLookup:
    """A ``ReceiptLookup`` that records the call and reports nothing found."""

    def __init__(self, calls: list) -> None:
        self._calls = calls

    def __call__(
        self, execution_id: str, artifact_sha256: str, target: DbTarget
    ) -> ReceiptStatus:
        self._calls.append((execution_id, artifact_sha256, target))
        return ReceiptStatus(state=RECEIPT_NOT_FOUND, detail="spy: no receipt")


def _build(tmp_path, monkeypatch, verdict: str, fs_type: str, **config_flags):
    monkeypatch.setattr("prometheus_protocol.chokepoint.runner.probe_substrate",
                        probe_returning(report(SUBSTRATE_SAFE, "ext4"), tmp_path / "chokepoint"))
    monkeypatch.setattr("prometheus_protocol.chokepoint.runner.probe_opened_substrate",
                        opened_probe(report(verdict, fs_type), tmp_path / "chokepoint" / "store.db"))
    monkeypatch.setattr("prometheus_protocol.chokepoint.authorization_journal.probe_file_substrate",
                        probe_returning(report(SUBSTRATE_SAFE, "ext4"), tmp_path / "audit.db"))
    calls: list[object] = []
    ledger = SqliteLedger.private(tmp_path / "audit.db")
    config = MigrationRunnerConfig(
        target=target(), signing_key=KEY, approval_store_path=tmp_path / "chokepoint" / "store.db",
    )
    settings = Config(**config_flags) if config_flags else None
    return ledger, calls, lambda: build_migration_runtime(
        config, audit=ledger, authorization=authorization_context(LocalHmacSigner(KEY)),
        executor=_SpyExecutor(calls), receipt_lookup=_SpyReceiptLookup(calls),
        settings=settings, env={},
    )


def test_the_builder_refuses_an_unsafe_opened_store_before_sqlite(tmp_path, monkeypatch):
    ledger, calls, build = _build(tmp_path, monkeypatch, SUBSTRATE_UNSAFE, "nfs4")
    with pytest.raises(ConfigError, match="nfs4"):
        build()
    assert calls == [] and (tmp_path / "chokepoint" / "store.db").stat().st_size == 0
    ledger.close()


def test_the_builder_refuses_an_unknown_substrate_unless_config_opts_out(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.WARNING, logger=SUBSTRATE_LOGGER)
    ledger, calls, build = _build(tmp_path, monkeypatch, SUBSTRATE_UNKNOWN, "overlay")
    with pytest.raises(ConfigError, match="could not be verified"):
        build()
    ledger.close()

    ledger, calls, build = _build(tmp_path, monkeypatch, SUBSTRATE_UNKNOWN, "overlay", allow_unverified_substrate=True)
    runtime = build()
    try:
        assert runtime.runner._consumed.substrate.verdict == SUBSTRATE_UNKNOWN
    finally:
        runtime.close()
        ledger.close()
    assert any("UNPROVEN" in r.getMessage() for r in caplog.records if r.name == SUBSTRATE_LOGGER)


def test_the_builder_honours_the_requirement_from_config(tmp_path, monkeypatch):
    ledger, calls, build = _build(tmp_path, monkeypatch, SUBSTRATE_UNKNOWN, "overlay", require_verified_substrate=True)
    with pytest.raises(ConfigError, match="require_verified_substrate=True cannot be honoured"):
        build()
    ledger.close()
    ledger, calls, build = _build(tmp_path, monkeypatch, SUBSTRATE_SAFE, "ext4", require_verified_substrate=True)
    build().close()
    ledger.close()
