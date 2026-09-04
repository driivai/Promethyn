"""The load-bearing chokepoint property: from the agent's sandboxed context the
target DB is unreachable by EVERY path — TCP and Unix socket, raw and via psql
and via a pg driver. If any one path were open, the gate would be theater.

Two things make a "blocked" result mean something here:

* a **positive control** — the same coordinates are proven REACHABLE from
  outside the sandbox first, so the run cannot pass merely because the database
  is down; and
* proof the candidate **actually executed inside real isolation** — only ``lo``
  is visible, and the socket path does not exist there.

Socket coverage is conditional on ``PROM_CHOKEPOINT_PG_SOCKDIR`` naming a real
socket directory, which a containerised CI database does not have (its socket
lives inside its own container). The TCP paths still run against the real
database; the socket paths are covered unconditionally, with their own listeners
and positive controls, by ``test_agent_zone_containment.py``. Requiring a socket
directory to run *anything* is what previously made this whole proof skip in CI —
the workflow sets that variable nowhere — so the gate is now per-path.
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile

import pytest

from prometheus_protocol.sandbox.base import Limits
from prometheus_protocol.sandbox.namespace import NamespaceSandbox

_REQUIRE = (os.environ.get("PROM_REQUIRE_PG", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}

_TCP_PATHS = ("psql-tcp", "raw-tcp", "psycopg-tcp")
_SOCKET_PATHS = ("psql-sock", "raw-sock", "psycopg-sock")


def _need():
    host = os.environ.get("PROM_CHOKEPOINT_PG_HOST")
    if not host:
        if _REQUIRE:
            pytest.fail("PROM_REQUIRE_PG=1 but PROM_CHOKEPOINT_PG_HOST is unset")
        pytest.skip("no configured DB coordinates for the isolation proof")
    if not NamespaceSandbox.available():
        if _REQUIRE:
            pytest.fail("PROM_REQUIRE_PG=1 but the namespace sandbox is unavailable")
        pytest.skip("namespace isolation runtime unavailable")
    port = int(os.environ.get("PROM_CHOKEPOINT_PG_PORT", "5432"))
    sockdir = os.environ.get("PROM_CHOKEPOINT_PG_SOCKDIR") or ""
    if sockdir and not os.path.exists(os.path.join(sockdir, f".s.PGSQL.{port}")):
        sockdir = ""  # configured but not actually present; do not pretend to test it
    return host, port, sockdir


_CANDIDATE = '''
import socket, subprocess, os
HOST, PORT, SOCKDIR = {host!r}, {port}, {sockdir!r}
SOCKFILE = f"{{SOCKDIR}}/.s.PGSQL.{{PORT}}" if SOCKDIR else ""
env = dict(os.environ); env["PGCONNECT_TIMEOUT"] = "5"

def out(tag, blocked, d): print(f"{{tag}}|{{'BLOCKED' if blocked else 'REACHED'}}|{{d}}")

try:
    r = subprocess.run(["/usr/bin/psql","-h",HOST,"-p",str(PORT),"-U","migrator","-d","appdb","-c","select 1"],
                       capture_output=True, text=True, env=env, timeout=20)
    out("psql-tcp", r.returncode != 0, "")
except Exception as e: out("psql-tcp", True, type(e).__name__)
try:
    s = socket.create_connection((HOST, PORT), timeout=5); s.close(); out("raw-tcp", False, "")
except Exception as e: out("raw-tcp", True, type(e).__name__)
try:
    import psycopg
except ImportError:
    psycopg = None
if psycopg is None:
    out("psycopg-tcp", True, "no-driver")
else:
    try:
        psycopg.connect(host=HOST, port=PORT, user="migrator", password="x", dbname="appdb", connect_timeout=5).close(); out("psycopg-tcp", False, "")
    except Exception as e: out("psycopg-tcp", True, type(e).__name__)

if SOCKDIR:
    try:
        r = subprocess.run(["/usr/bin/psql","-h",SOCKDIR,"-p",str(PORT),"-U","migrator","-d","appdb","-c","select 1"],
                           capture_output=True, text=True, env=env, timeout=20)
        out("psql-sock", r.returncode != 0, "")
    except Exception as e: out("psql-sock", True, type(e).__name__)
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(5); s.connect(SOCKFILE); s.close(); out("raw-sock", False, "")
    except Exception as e: out("raw-sock", True, type(e).__name__)
    if psycopg is None:
        out("psycopg-sock", True, "no-driver")
    else:
        try:
            psycopg.connect(host=SOCKDIR, port=PORT, user="migrator", password="x", dbname="appdb", connect_timeout=5).close(); out("psycopg-sock", False, "")
        except Exception as e: out("psycopg-sock", True, type(e).__name__)
    print("SOCKEXISTS|" + str(os.path.exists(SOCKFILE)))

ifs = [l.split(":")[0].strip() for l in open("/proc/net/dev").read().splitlines()[2:] if ":" in l]
print("IFACES|" + ",".join(ifs))
'''


def _reachable_outside(host: str, port: int) -> bool:
    """Positive control: the database really is listening from the test's own
    context. Without this, every path below could read BLOCKED simply because
    nothing was there — isolation unproven, the assertion still green."""

    try:
        sock = socket.create_connection((host, port), timeout=10)
    except OSError:
        return False
    sock.close()
    return True


def test_agent_cannot_reach_db_by_any_path():
    host, port, sockdir = _need()

    assert _reachable_outside(host, port), (
        f"the DB at {host}:{port} is not reachable from OUTSIDE the sandbox either — "
        "a 'blocked' result would prove nothing about isolation"
    )

    src = _CANDIDATE.format(host=host, port=port, sockdir=sockdir)
    with tempfile.TemporaryDirectory(prefix="prom-isotest-") as ws:
        open(os.path.join(ws, "attack.py"), "w").write(src)
        r = NamespaceSandbox().run(
            argv=[sys.executable, "-I", "attack.py"], workspace=ws,
            limits=Limits(wall_time_s=60, memory_bytes=0, cpu_time_s=50, max_processes=256),
        )

    # The candidate genuinely ran inside real isolation (not a trivial no-op):
    assert r.started_ok and r.exit_status == 0, f"candidate did not run: {r.detail} / {r.stderr}"
    parsed = {}
    for ln in r.stdout.strip().splitlines():
        parts = ln.split("|")
        parsed[parts[0]] = parts[1] if len(parts) > 1 else ""

    # Proof the candidate was truly isolated: only loopback is visible.
    assert parsed.get("IFACES") == "lo", f"expected only lo, got {parsed.get('IFACES')!r}"

    expected = list(_TCP_PATHS)
    if sockdir:
        expected += list(_SOCKET_PATHS)
        assert parsed.get("SOCKEXISTS") == "False", "the DB socket must not be visible in the sandbox"

    # EVERY covered connection path blocked. One uncovered path = theater.
    for path in expected:
        assert parsed.get(path) == "BLOCKED", f"path {path} was not blocked: {parsed.get(path)!r}"


def test_socket_paths_are_covered_somewhere():
    """If this run had no real socket directory, the socket paths must still be
    proven — by the DB-independent containment suite. Assert that file exists and
    names them, so deleting it cannot silently drop the coverage this test
    delegates."""

    here = os.path.dirname(__file__)
    companion = os.path.join(here, "test_agent_zone_containment.py")
    assert os.path.exists(companion), "the unconditional socket-path proof is missing"
    body = open(companion, encoding="utf-8").read()
    for marker in ("/run/postgresql", "/tmp", "abstract"):
        assert marker in body, f"socket coverage for {marker} is not present"
