"""Swap-after-hash: a migration file rewritten between approval and execution.

Attacker 2's sharpest local move. An approval binds the SHA-256 of the artifact
it authorizes, which is airtight for *content* — and worth nothing if what
travels to the executor is a **path**. Approve `ALTER TABLE`, rewrite the file to
`DROP TABLE`, execute: the approval is still valid, because nobody re-reads the
bytes it was minted for.

The defence is structural rather than a check: :class:`MigrationArtifact` holds
the SQL it was built from and hashes that same string, so the executed artifact
is the hashed artifact by construction. :meth:`MigrationArtifact.from_path` is
the safe way in — one descriptor, opened ``O_NOFOLLOW``, ``fstat``-ed and read
through, so nothing swapped in at the path afterwards can reach the result.

Each test performs the attack for real and then asserts what actually ran.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

import pytest

from prometheus_protocol.chokepoint import (
    ApprovalAuthority,
    BrokeredMigrationRunner,
    ConsumedApprovals,
    DbTarget,
    MigrationArtifact,
    RECEIPT_NOT_FOUND,
    ReceiptStatus,
)
from prometheus_protocol.core.models import Judgment, Verdict

BENIGN = "ALTER TABLE accounts ADD COLUMN note text;\n"
HOSTILE = "DROP TABLE accounts;\n"


class _SpyExecutor:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, sql, target, execution_id, artifact_sha256):
        self.calls.append(sql)
        return True, "spy applied"


class _Audit:
    def __init__(self) -> None:
        self.seq = 0
        self.events: list[dict[str, object]] = []

    def record_chained(self, **event) -> int:
        self.seq += 1
        self.events.append({"seq": self.seq, **event})
        return self.seq

    def chained_events(self) -> list[dict[str, object]]:
        return list(self.events)

    def verify_chain(self):
        return type("Verification", (), {"ok": True})()


def _target() -> DbTarget:
    return DbTarget(host="127.0.0.1", port=5432, dbname="appdb",
                    user="migrator", password="secret")


def _pass_judgment() -> Judgment:
    return Judgment(verdict=Verdict.PASS, confidence=1.0, authoritative=True,
                    contributing=("hard-check",))


def _runner(authority, target, spy, store_path):
    return BrokeredMigrationRunner(
        authority=authority, target=target, consumed=ConsumedApprovals(store_path),
        executor=spy,
        receipt_lookup=lambda execution_id, artifact_sha256, bound: ReceiptStatus(
            RECEIPT_NOT_FOUND
        ),
        audit=_Audit(), clock=lambda: 1000.0,
    )


@pytest.fixture
def migration_file(tmp_path) -> Path:
    path = tmp_path / "0007_add_note.sql"
    path.write_text(BENIGN, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# The attack, end to end through the runner
# ---------------------------------------------------------------------------


def test_rewriting_the_file_after_approval_does_not_change_what_executes(
    migration_file, tmp_path
):
    artifact = MigrationArtifact.from_path(migration_file)
    authority = ApprovalAuthority()
    target = _target()
    approval = authority.authorize(
        _pass_judgment(), artifact=artifact, target=target.identity, now=1000.0
    )
    assert approval is not None

    # THE ATTACK: a local adversary rewrites the approved file in place.
    migration_file.write_text(HOSTILE, encoding="utf-8")
    assert migration_file.read_text(encoding="utf-8") == HOSTILE, "the attack did not land"

    spy = _SpyExecutor()
    result = _runner(authority, target, spy, tmp_path / "consumed.db").execute(
        approval=approval, artifact=artifact
    )

    assert result.executed, f"the authorized migration did not run: {result.reason}"
    assert spy.calls == [BENIGN], "the rewritten file reached the database"
    assert HOSTILE not in spy.calls


def test_replacing_the_file_by_rename_does_not_change_what_executes(
    migration_file, tmp_path
):
    """Rename-over is the swap that beats in-place checks: the inode changes, so
    anything comparing sizes or mtimes on the path is looking at a new file."""

    artifact = MigrationArtifact.from_path(migration_file)
    original_inode = artifact.source.inode

    replacement = tmp_path / "hostile.sql"
    replacement.write_text(HOSTILE, encoding="utf-8")
    os.replace(replacement, migration_file)

    assert os.stat(migration_file).st_ino != original_inode, "the rename did not land"
    assert artifact.sql == BENIGN
    assert artifact.sha256 == MigrationArtifact(BENIGN).sha256


def test_the_attack_lands_against_a_path_carrying_design(migration_file, tmp_path):
    """The attack is real — shown by simulating the design that would fall to it.

    Without this, every assertion above could pass simply because the swap never
    worked. Here a deliberately naive flow carries the *path* and re-reads it at
    execution, exactly as a straightforward implementation would; the hostile SQL
    reaches the executor under a valid approval. The same swap against the real
    flow, in the tests above, does not.
    """

    artifact = MigrationArtifact.from_path(migration_file)
    authority = ApprovalAuthority()
    target = _target()
    approval = authority.authorize(
        _pass_judgment(), artifact=artifact, target=target.identity, now=1000.0
    )
    assert approval is not None

    migration_file.write_text(HOSTILE, encoding="utf-8")

    # The naive design: hold the path, re-read at execution time.
    naive_sql = migration_file.read_text(encoding="utf-8")
    spy = _SpyExecutor()
    spy(naive_sql, target, "exec-1", approval.artifact_sha256)

    assert spy.calls == [HOSTILE], "the simulated naive flow did not reproduce the attack"
    assert approval.artifact_sha256 == MigrationArtifact(BENIGN).sha256, (
        "the approval still names the benign hash while hostile SQL executed — "
        "the binding cannot see a substitution it never re-checks"
    )


def test_the_approval_would_still_verify_against_the_swapped_file(migration_file):
    """Why holding the bytes matters: the approval itself cannot catch this.

    It binds a hash, and the hash it binds is still the benign one — so a
    path-based flow re-reading at execution would run the hostile SQL under a
    perfectly valid approval. The binding is not the defence here; not carrying a
    path is.
    """

    artifact = MigrationArtifact.from_path(migration_file)
    authority = ApprovalAuthority()
    target = _target()
    approval = authority.authorize(
        _pass_judgment(), artifact=artifact, target=target.identity, now=1000.0
    )
    migration_file.write_text(HOSTILE, encoding="utf-8")

    # The approval still verifies — against the artifact we hold, which is benign.
    assert authority.verify(approval, artifact=artifact,
                            target=target.identity, now=1000.0).ok
    # And re-reading the path now yields a DIFFERENT hash, which is precisely the
    # substitution a path-carrying design would have executed.
    swapped = MigrationArtifact.from_path(migration_file)
    assert swapped.sha256 != artifact.sha256


# ---------------------------------------------------------------------------
# Tamper evidence: the swap cannot change execution, but it is still reported
# ---------------------------------------------------------------------------


def test_an_untampered_file_reports_as_matching(migration_file):
    artifact = MigrationArtifact.from_path(migration_file)
    assert artifact.source_still_matches() is True


def test_a_tampered_file_is_reported(migration_file):
    artifact = MigrationArtifact.from_path(migration_file)
    migration_file.write_text(HOSTILE, encoding="utf-8")
    assert artifact.source_still_matches() is False


def test_a_deleted_file_is_reported_rather_than_raising(migration_file):
    artifact = MigrationArtifact.from_path(migration_file)
    migration_file.unlink()
    assert artifact.source_still_matches() is False


def test_an_in_memory_artifact_reports_no_source(tmp_path):
    assert MigrationArtifact(BENIGN).source_still_matches() is None


def test_source_is_not_part_of_artifact_identity(migration_file):
    """An artifact read from disk is the same artifact as the SQL in memory —
    otherwise ingestion would change a hash that is supposed to be content-only."""

    from_disk = MigrationArtifact.from_path(migration_file)
    in_memory = MigrationArtifact(BENIGN)
    assert from_disk == in_memory
    assert from_disk.sha256 == in_memory.sha256


# ---------------------------------------------------------------------------
# Ingestion refuses what it must not read
# ---------------------------------------------------------------------------


def test_a_symlink_at_the_path_is_refused(migration_file, tmp_path):
    """``O_NOFOLLOW``: swapping a symlink in at the approved path must not
    redirect the read to another file."""

    elsewhere = tmp_path / "elsewhere.sql"
    elsewhere.write_text(HOSTILE, encoding="utf-8")
    link = tmp_path / "link.sql"
    link.symlink_to(elsewhere)

    with pytest.raises(OSError):
        MigrationArtifact.from_path(link)


def test_a_fifo_is_refused_rather_than_blocking(tmp_path):
    """A FIFO at the path would block the read forever. Regular files only."""

    path = tmp_path / "pipe.sql"
    try:
        os.mkfifo(path)
    except (OSError, AttributeError):
        pytest.skip("cannot create a FIFO here")
    # Opened non-blocking so the refusal is reached rather than hanging on open.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        assert stat.S_ISFIFO(os.fstat(descriptor).st_mode)
    finally:
        os.close(descriptor)

    with pytest.raises((ValueError, OSError)):
        MigrationArtifact.from_path(path)


def test_a_directory_is_refused(tmp_path):
    with pytest.raises((ValueError, OSError, IsADirectoryError)):
        MigrationArtifact.from_path(tmp_path)


def test_non_utf8_content_is_refused(tmp_path):
    path = tmp_path / "binary.sql"
    path.write_bytes(b"\xff\xfe\x00garbage")
    with pytest.raises(ValueError):
        MigrationArtifact.from_path(path)


def test_an_oversized_file_is_refused(tmp_path, monkeypatch):
    from prometheus_protocol.chokepoint import approval as approval_module

    monkeypatch.setattr(approval_module, "MAX_ARTIFACT_BYTES", 64)
    path = tmp_path / "big.sql"
    path.write_text("x" * 128, encoding="utf-8")
    with pytest.raises(ValueError):
        MigrationArtifact.from_path(path)


def test_the_recorded_source_describes_the_file_actually_read(migration_file):
    artifact = MigrationArtifact.from_path(migration_file)
    info = os.stat(migration_file)
    assert artifact.source is not None
    assert artifact.source.inode == info.st_ino
    assert artifact.source.device == info.st_dev
    assert artifact.source.size == len(BENIGN.encode("utf-8"))
    assert artifact.source.path == os.fspath(migration_file)
