#!/usr/bin/env python3
"""Promethyn enforcement demo — the credential-brokered migration chokepoint.

Runs the whole enforcement story against the REAL chokepoint and a REAL
PostgreSQL — nothing mocked:

  1. an agent tries to reach the DB to run the migration itself  -> no path
  2. a valid, approved migration                                -> runs once
  3. replay the same approval                                   -> refused
  4. swap a hostile artifact under a valid approval             -> refused
  5. a forged approval                                          -> refused
  6. the hash-chained ledger of every decision                  -> VALID,
     then a tampered entry                                      -> BROKEN

It needs a PostgreSQL reachable via the PROM_CHOKEPOINT_PG_* environment (see
demo/README.md). If none is configured/reachable it prints setup instructions
and exits WITHOUT faking success. Step 1's live isolation needs the namespace
sandbox (unprivileged user namespaces); where that is unavailable it says so and
points at the committed proof rather than pretending.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
import sys
import tempfile
import time

from prometheus_protocol.chokepoint import (
    DbTarget,
    MigrationArtifact,
    MigrationRunnerConfig,
    build_migration_runtime,
    postgres_executor,
)
from prometheus_protocol.core.models import Judgment, Verdict
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger

BAR = "=" * 72


def line(text: str = "") -> None:
    print(text, flush=True)


def step(n: int, title: str) -> None:
    line()
    line(f"STEP {n}: {title}")


def _psql(target: DbTarget, sql: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PGPASSWORD"] = target.password
    env["PGCONNECT_TIMEOUT"] = "8"
    return subprocess.run(
        [shutil.which("psql") or "/usr/bin/psql", "-h", target.host, "-p", str(target.port),
         "-U", target.user, "-d", target.dbname, "-tAc", sql],
        capture_output=True, text=True, env=env, timeout=30, check=False,
    )


def _target_from_env() -> DbTarget | None:
    host = os.environ.get("PROM_CHOKEPOINT_PG_HOST")
    if not host:
        return None
    return DbTarget(
        host=host,
        port=int(os.environ.get("PROM_CHOKEPOINT_PG_PORT", "5432")),
        dbname=os.environ.get("PROM_CHOKEPOINT_PG_DB", "appdb"),
        user=os.environ.get("PROM_CHOKEPOINT_PG_USER", "migrator"),
        password=os.environ.get("PROM_CHOKEPOINT_PG_PASSWORD", ""),
        schema=os.environ.get("PROM_CHOKEPOINT_PG_SCHEMA", "public"),
    )


_SETUP = """\
This demo runs against a REAL PostgreSQL — it will not fake a result.

Point it at a database by exporting:

  export PROM_CHOKEPOINT_PG_HOST=127.0.0.1
  export PROM_CHOKEPOINT_PG_PORT=55432
  export PROM_CHOKEPOINT_PG_DB=appdb
  export PROM_CHOKEPOINT_PG_USER=migrator
  export PROM_CHOKEPOINT_PG_SCHEMA=public
  export PROM_CHOKEPOINT_PG_PASSWORD=...              # the credential the RUNNER holds
  export PROM_CHOKEPOINT_KEY=<64 hex characters>      # stable approval signing key
  export PROM_CHOKEPOINT_APPROVAL_DB=.prometheus/chokepoint-consumed.db
  export PROM_CHOKEPOINT_PG_SOCKDIR=/home/pgproxy/sock  # optional; enables the
                                                        # Unix-socket attack in step 1

Any PostgreSQL the migrator role can log into works. A throwaway local cluster
whose socket lives under a sandbox-hidden path (e.g. /home/<user>/sock) makes
step 1's isolation strongest; see demo/README.md for the exact commands.
"""


def require_db() -> DbTarget:
    target = _target_from_env()
    if target is None:
        line(_SETUP)
        line("PROM_CHOKEPOINT_PG_HOST is not set — nothing to run against. Exiting.")
        sys.exit(2)
    probe = _psql(target, "select 1")
    if probe.returncode != 0:
        line(_SETUP)
        line("Configured, but the database is not reachable:")
        line("  " + (probe.stderr or "").strip().splitlines()[0] if probe.stderr.strip()
             else "  (no response)")
        sys.exit(2)
    return target


def require_signing_key() -> bytes:
    raw = os.environ.get("PROM_CHOKEPOINT_KEY", "")
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        key = b""
    if len(key) < 32:
        line(_SETUP)
        line("PROM_CHOKEPOINT_KEY must contain at least 64 hexadecimal characters.")
        line("Generate one once, store it as a secret, and reuse it across restarts.")
        sys.exit(2)
    return key


# --------------------------------------------------------------------------
# STEP 1 — an agent, in its sandbox, tries to reach the DB itself
# --------------------------------------------------------------------------

_ATTACK = '''
import socket
HOST, PORT, SOCKFILE = {host!r}, {port}, {sockfile!r}

def attempt(name, fn):
    try:
        fn()
        print(name + "|REACHED")
    except Exception as e:
        print(name + "|BLOCKED|" + type(e).__name__ + ": " + str(e)[:60])

def tcp():
    s = socket.create_connection((HOST, PORT), timeout=5); s.close()

def unix():
    if not SOCKFILE:
        raise FileNotFoundError("no socket path provided")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(5)
    s.connect(SOCKFILE); s.close()

attempt("raw-TCP", tcp)
attempt("raw-unix-socket", unix)
ifs = [l.split(":")[0].strip() for l in open("/proc/net/dev").read().splitlines()[2:] if ":" in l]
print("ifaces|" + ",".join(ifs))
'''


def step1_direct_attempt(target: DbTarget) -> None:
    step(1, "the agent tries to reach the database itself (no credential, no path)")
    try:
        from prometheus_protocol.sandbox.base import Limits
        from prometheus_protocol.sandbox.namespace import NamespaceSandbox
    except Exception:
        NamespaceSandbox = None  # type: ignore[assignment]

    if NamespaceSandbox is None or not NamespaceSandbox.available():
        line("  (skipped live) the namespace sandbox (unprivileged user namespaces)")
        line("  is unavailable here. The same proof — six paths, all closed — is the")
        line("  committed test tests/chokepoint/test_isolation.py. Continuing.")
        return

    sockdir = os.environ.get("PROM_CHOKEPOINT_PG_SOCKDIR", "")
    sockfile = f"{sockdir}/.s.PGSQL.{target.port}" if sockdir else ""
    src = _ATTACK.format(host=target.host, port=target.port, sockfile=sockfile)
    with tempfile.TemporaryDirectory(prefix="prom-demo-") as ws:
        with open(os.path.join(ws, "attack.py"), "w") as fh:
            fh.write(src)
        r = NamespaceSandbox().run(
            argv=[sys.executable, "-I", "attack.py"], workspace=ws,
            limits=Limits(wall_time_s=30, memory_bytes=0, cpu_time_s=25, max_processes=64),
        )
    parsed = dict(l.split("|", 1) for l in r.stdout.strip().splitlines() if "|" in l)
    for label in ("raw-TCP", "raw-unix-socket"):
        outcome = parsed.get(label, "n/a")
        line(f"    {label:<18} {outcome}")
    line(f"    interfaces visible inside the sandbox: {parsed.get('ifaces', '?')}")
    reached = [k for k, v in parsed.items() if v.startswith("REACHED")]
    if reached:
        line(f"  UNEXPECTED: the agent reached the DB via {reached} — isolation failed!")
    else:
        line("  RESULT: the agent has NO path to the database. It can only propose.")


# --------------------------------------------------------------------------
# STEPS 2-6 — the brokered runner, real approvals, real migration, real ledger
# --------------------------------------------------------------------------

def _passing_judgment() -> Judgment:
    return Judgment(verdict=Verdict.PASS, confidence=1.0, authoritative=True,
                    contributing=("hard-merge-check",))


def run_chokepoint(target: DbTarget, signing_key: bytes) -> None:
    # The gate and the runner share one authority (one signing key) — the trusted
    # zone. The agent never holds it. The receipt ledger is fresh for the demo;
    # spent approvals are durable so a restart cannot revive a capability.
    ledger = SqliteLedger(":memory:")
    runtime = build_migration_runtime(
        MigrationRunnerConfig(
            target=target,
            signing_key=signing_key,
            approval_store_path=os.environ.get(
                "PROM_CHOKEPOINT_APPROVAL_DB",
                ".prometheus/chokepoint-consumed.db",
            ),
        ),
        audit=ledger,
        executor=postgres_executor,
        clock=time.time,
    )
    authority = runtime.authority
    runner = runtime.runner
    tbl = f"demo_migration_{int(time.time())}"
    artifact = MigrationArtifact(f"CREATE TABLE {tbl} (id int, note text);")

    try:
        # STEP 2 — a valid, approved migration runs exactly once.
        step(2, "an APPROVED migration runs (once)")
        ledger.record_chained(event="authorize", subject=target.identity.canonical,
                             payload={"artifact_sha256": artifact.sha256[:16]},
                             created_at=repr(time.time()))
        approval = authority.authorize(_passing_judgment(), artifact=artifact,
                                       target=target.identity, now=time.time())
        before = _psql(target, f"SELECT to_regclass('{tbl}') IS NULL").stdout.strip()
        res = runner.execute(approval=approval, artifact=artifact)
        after = _psql(target, f"SELECT to_regclass('{tbl}') IS NOT NULL").stdout.strip()
        line(f"    table absent before: {before == 't'}   executed: {res.executed}   "
             f"table present after: {after == 't'}")
        line(f"  RESULT: {res.detail}")

        # STEP 3 — replay the same approval.
        step(3, "REPLAY the same approval")
        res = runner.execute(approval=approval, artifact=artifact)
        count = _psql(target, f"SELECT count(*) FROM pg_tables WHERE tablename='{tbl}'").stdout.strip()
        line(f"    refused: {res.refused}   reason: {res.reason}   "
             f"table still exists exactly once: {count == '1'}")
        line(f"  RESULT: {res.detail}")

        # STEP 4 — swap a hostile artifact under a (different) valid approval.
        step(4, "SWAP a hostile artifact under a valid approval")
        benign = MigrationArtifact(f"CREATE TABLE {tbl}_side (id int);")
        approval_b = authority.authorize(_passing_judgment(), artifact=benign,
                                         target=target.identity, now=time.time())
        hostile = MigrationArtifact(f"DROP TABLE {tbl};")
        res = runner.execute(approval=approval_b, artifact=hostile)
        survived = _psql(target, f"SELECT to_regclass('{tbl}') IS NOT NULL").stdout.strip()
        line(f"    refused: {res.refused}   reason: {res.reason}   "
             f"target table survived: {survived == 't'}")
        line(f"  RESULT: {res.detail}")

        # STEP 5 — a forged approval (no signing key).
        step(5, "a FORGED approval (the agent has no signing key)")
        forged = authority.mint(artifact_sha256=hostile.sha256,
                                target=target.identity, now=time.time())
        forged = dataclasses.replace(forged, mac="deadbeef" * 8)
        res = runner.execute(approval=forged, artifact=hostile)
        line(f"    refused: {res.refused}   reason: {res.reason}")
        line(f"  RESULT: {res.detail}")

        # STEP 6 — the tamper-evident ledger of every decision.
        step(6, "the tamper-evident ledger of every decision")
        for e in ledger.chained_events():
            payload = e["payload"]
            line(f"    #{e['seq']}  {e['event']:<10} {payload}")
        v = ledger.verify_chain()
        line(f"  verify_chain(): {v.render()}")
        line("  now an adversary edits one entry to hide the replay attempt...")
        ledger._conn.execute("UPDATE audit_chain SET event='authorize' WHERE seq=4")
        ledger._conn.commit()
        v2 = ledger.verify_chain()
        line(f"  verify_chain(): {v2.render()}")
        line("  RESULT: the tamper is detected — the receipt cannot be quietly rewritten.")
    finally:
        _psql(target, f"DROP TABLE IF EXISTS {tbl}")
        _psql(target, f"DROP TABLE IF EXISTS {tbl}_side")
        runtime.close()
        ledger.close()


def main() -> int:
    line(BAR)
    line("  PROMETHYN — credential-brokered migration chokepoint (live demo)")
    line(BAR)
    target = require_db()
    signing_key = require_signing_key()
    line(f"  target: {target.identity}   (the runner holds the credential; the agent does not)")
    step1_direct_attempt(target)
    run_chokepoint(target, signing_key)
    line()
    line(BAR)
    line("  The agent never held the credential. Only approved, verified, single-use,")
    line("  correctly-bound actions ran — each one recorded in a tamper-evident receipt.")
    line(BAR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
