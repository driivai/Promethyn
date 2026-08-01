"""Chokepoint authorization: every binding proven to BLOCK, not just allow.

These use a spy executor, so each refusal is proven to reject the migration
*before any DB contact* (the spy records whether it was ever called). No live
database is needed; the live end-to-end run is in ``test_migration_live.py``.
"""

from __future__ import annotations

import dataclasses

import pytest

from prometheus_protocol.chokepoint import (
    ApprovalAuthority,
    ARTIFACT_MISMATCH,
    BrokeredMigrationRunner,
    ConsumedApprovals,
    DbTarget,
    EXPIRED,
    INVALID_SIGNATURE,
    MigrationArtifact,
    REPLAY,
    TARGET_MISMATCH,
)
from prometheus_protocol.core.models import (
    Judgment,
    Tier,
    Unavailability,
    Unavailable,
    Verdict,
)


class _SpyExecutor:
    """Records every DB touch. A refusal must leave ``calls`` empty."""

    def __init__(self, ok: bool = True) -> None:
        self.calls: list[str] = []
        self._ok = ok

    def __call__(self, sql: str, target) -> tuple[bool, str]:
        self.calls.append(sql)
        return self._ok, "spy applied"


def _clock():
    """A mutable clock: ``t[0]`` is 'now'; tests advance it."""
    t = [1000.0]
    return t, (lambda: t[0])


def _target() -> DbTarget:
    return DbTarget(host="127.0.0.1", port=5432, dbname="appdb",
                    user="migrator", password="secret")


def _pass_judgment() -> Judgment:
    return Judgment(verdict=Verdict.PASS, confidence=1.0, authoritative=True,
                    contributing=("hard-check",))


def _runner(authority, target, spy, clock):
    return BrokeredMigrationRunner(
        authority=authority, target=target, consumed=ConsumedApprovals(),
        executor=spy, clock=clock,
    )


# -- happy path: the capability, used once, works -----------------------------

def test_happy_path_executes_once():
    t, clock = _clock()
    auth = ApprovalAuthority()
    target = _target()
    art = MigrationArtifact("CREATE TABLE t (id int);")
    spy = _SpyExecutor()
    runner = _runner(auth, target, spy, clock)

    approval = auth.authorize(_pass_judgment(), artifact=art,
                              target=target.identity, now=clock())
    assert approval is not None
    result = runner.execute(approval=approval, artifact=art)
    assert result.executed and not result.refused
    assert spy.calls == [art.sql]  # touched the DB exactly once, with the right SQL


# -- P5 replay: a used approval fails, and never re-touches the DB ------------

def test_replay_fails():
    t, clock = _clock()
    auth = ApprovalAuthority()
    target = _target()
    art = MigrationArtifact("DROP TABLE users;")
    spy = _SpyExecutor()
    runner = _runner(auth, target, spy, clock)
    approval = auth.authorize(_pass_judgment(), artifact=art,
                              target=target.identity, now=clock())

    first = runner.execute(approval=approval, artifact=art)
    second = runner.execute(approval=approval, artifact=art)

    assert first.executed
    assert second.refused and second.reason == REPLAY
    assert spy.calls == [art.sql]  # the DB was touched ONCE, not twice


# -- P3 swap: approval for A, artifact B submitted → refused, DB untouched ----

def test_swap_fails():
    t, clock = _clock()
    auth = ApprovalAuthority()
    target = _target()
    approved = MigrationArtifact("ALTER TABLE t ADD COLUMN ok int;")
    swapped = MigrationArtifact("DROP TABLE t;")  # a different, hostile artifact
    spy = _SpyExecutor()
    runner = _runner(auth, target, spy, clock)
    approval = auth.authorize(_pass_judgment(), artifact=approved,
                              target=target.identity, now=clock())

    result = runner.execute(approval=approval, artifact=swapped)

    assert result.refused and result.reason == ARTIFACT_MISMATCH
    assert spy.calls == []  # hostile artifact never reached the DB


# -- P4 wrong target: approval for X, runner bound to Y → refused ------------

def test_wrong_target_fails():
    t, clock = _clock()
    auth = ApprovalAuthority()
    runner_target = _target()  # appdb@127.0.0.1:5432
    art = MigrationArtifact("TRUNCATE audit;")
    spy = _SpyExecutor()
    runner = _runner(auth, runner_target, spy, clock)

    # Mint an approval bound to a DIFFERENT target.
    approval = auth.mint(artifact_sha256=art.sha256,
                         target="otherdb@10.0.0.9:5432", now=clock())
    result = runner.execute(approval=approval, artifact=art)

    assert result.refused and result.reason == TARGET_MISMATCH
    assert spy.calls == []


# -- P6 expiry: past the TTL → refused ---------------------------------------

def test_expired_fails():
    t, clock = _clock()
    auth = ApprovalAuthority()
    target = _target()
    art = MigrationArtifact("VACUUM FULL;")
    spy = _SpyExecutor()
    runner = _runner(auth, target, spy, clock)
    approval = auth.authorize(_pass_judgment(), artifact=art,
                              target=target.identity, now=clock(), ttl_seconds=90.0)

    t[0] += 91.0  # advance past the 90s window
    result = runner.execute(approval=approval, artifact=art)

    assert result.refused and result.reason == EXPIRED
    assert spy.calls == []


def test_valid_within_ttl_but_expired_one_second_later():
    # Boundary: usable at t+89, refused at t+91 — the window is real.
    t, clock = _clock()
    auth = ApprovalAuthority()
    target = _target()
    art = MigrationArtifact("CREATE INDEX i ON t (id);")
    approval = auth.authorize(_pass_judgment(), artifact=art,
                              target=target.identity, now=clock(), ttl_seconds=90.0)

    spy_ok = _SpyExecutor()
    r_ok = _runner(auth, target, spy_ok, clock)
    t[0] += 89.0
    assert r_ok.execute(approval=approval, artifact=art).executed

    # A fresh approval, checked just past expiry, is refused.
    approval2 = auth.authorize(_pass_judgment(), artifact=art,
                               target=target.identity, now=1000.0, ttl_seconds=90.0)
    spy_no = _SpyExecutor()
    r_no = _runner(auth, target, spy_no, clock)
    t[0] = 1000.0 + 91.0
    res = r_no.execute(approval=approval2, artifact=art)
    assert res.refused and res.reason == EXPIRED and spy_no.calls == []


# -- P7 forgery: an agent without the key cannot mint or alter an approval ----

def test_forged_mac_fails():
    t, clock = _clock()
    auth = ApprovalAuthority()  # runner-zone key the agent does not have
    target = _target()
    art = MigrationArtifact("GRANT ALL ON DATABASE appdb TO attacker;")
    spy = _SpyExecutor()
    runner = _runner(auth, target, spy, clock)

    # Agent fabricates an approval with a made-up MAC (it has no key).
    forged = auth.mint(artifact_sha256=art.sha256, target=target.identity, now=clock())
    forged = dataclasses.replace(forged, mac="deadbeef" * 8)
    result = runner.execute(approval=forged, artifact=art)

    assert result.refused and result.reason == INVALID_SIGNATURE
    assert spy.calls == []


def test_tampered_field_fails():
    # Take a genuine approval and edit a bound field: the MAC no longer matches.
    t, clock = _clock()
    auth = ApprovalAuthority()
    target = _target()
    art = MigrationArtifact("DELETE FROM ledger;")
    spy = _SpyExecutor()
    runner = _runner(auth, target, spy, clock)
    good = auth.mint(artifact_sha256=art.sha256, target=target.identity, now=clock())

    # Extend the expiry to defeat the TTL — but the MAC covers expiry.
    tampered = dataclasses.replace(good, expires_at=good.expires_at + 10_000.0)
    result = runner.execute(approval=tampered, artifact=art)

    assert result.refused and result.reason == INVALID_SIGNATURE
    assert spy.calls == []


def test_wrong_key_cannot_verify():
    # An approval minted by a DIFFERENT authority (different key) is rejected —
    # the runner trusts only its own key.
    t, clock = _clock()
    runner_auth = ApprovalAuthority(key=b"the-runner-zone-key-32-bytes-long!!")
    attacker_auth = ApprovalAuthority(key=b"an-attacker-guessed-key-32-bytes!!!!")
    target = _target()
    art = MigrationArtifact("DROP DATABASE appdb;")
    spy = _SpyExecutor()
    runner = _runner(runner_auth, target, spy, clock)

    approval = attacker_auth.mint(artifact_sha256=art.sha256,
                                  target=target.identity, now=clock())
    result = runner.execute(approval=approval, artifact=art)
    assert result.refused and result.reason == INVALID_SIGNATURE
    assert spy.calls == []


# -- P8 fail-closed: no authoritative PASS → no capability at all -------------

def test_unavailable_yields_no_approval():
    auth = ApprovalAuthority()
    art = MigrationArtifact("CREATE TABLE t (id int);")
    unavailable = Unavailable(verifier_id="subprocess-tests", tier=Tier.HARD,
                              reason=Unavailability.INFRA_FAULT, detail="sandbox down")
    approval = auth.authorize(unavailable, artifact=art,
                              target="appdb@h:5432", now=1000.0)
    assert approval is None  # a check that could not run mints nothing


def test_fail_verdict_yields_no_approval():
    auth = ApprovalAuthority()
    art = MigrationArtifact("CREATE TABLE t (id int);")
    fail = Judgment(verdict=Verdict.FAIL, confidence=1.0, authoritative=True)
    assert auth.authorize(fail, artifact=art, target="appdb@h:5432", now=1000.0) is None


def test_non_authoritative_pass_yields_no_approval():
    auth = ApprovalAuthority()
    art = MigrationArtifact("CREATE TABLE t (id int);")
    soft_pass = Judgment(verdict=Verdict.PASS, confidence=0.99, authoritative=False)
    assert auth.authorize(soft_pass, artifact=art, target="appdb@h:5432", now=1000.0) is None


def test_abstain_yields_no_approval():
    auth = ApprovalAuthority()
    art = MigrationArtifact("CREATE TABLE t (id int);")
    abstain = Judgment(verdict=Verdict.ABSTAIN, confidence=0.0, authoritative=True)
    assert auth.authorize(abstain, artifact=art, target="appdb@h:5432", now=1000.0) is None
