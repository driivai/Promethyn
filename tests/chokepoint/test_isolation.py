"""The load-bearing chokepoint property: from the agent's sandboxed context the
target DB is unreachable by EVERY path — TCP and Unix socket, raw and via psql
and via a pg driver. If any one path were open, the gate would be theater.

Gated on the namespace sandbox being functional AND a configured DB whose socket
directory is under a sandbox-hidden path (``/home`` or ``/root``). Skips locally
without them; FAILS under ``PROM_REQUIRE_PG=1`` so it is never a silent skip.

The test defeats the trivial-false-pass ("everything looked blocked because the
candidate never ran") by asserting the candidate actually executed inside real
isolation: only ``lo`` is visible and the socket path does not exist there.
"""

from __future__ import annotations

import os
import sys
import tempfile

import pytest

from prometheus_protocol.sandbox.base import Limits
from prometheus_protocol.sandbox.namespace import NamespaceSandbox

_REQUIRE = (os.environ.get("PROM_REQUIRE_PG", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}


def _need():
    host = os.environ.get("PROM_CHOKEPOINT_PG_HOST")
    sockdir = os.environ.get("PROM_CHOKEPOINT_PG_SOCKDIR")
    if not host or not sockdir:
        if _REQUIRE:
            pytest.fail("PROM_REQUIRE_PG=1 but PROM_CHOKEPOINT_PG_HOST/SOCKDIR unset")
        pytest.skip("no configured DB coordinates for the isolation proof")
    if not NamespaceSandbox.available():
        if _REQUIRE:
            pytest.fail("PROM_REQUIRE_PG=1 but the namespace sandbox is unavailable")
        pytest.skip("namespace isolation runtime unavailable")
    return host, int(os.environ.get("PROM_CHOKEPOINT_PG_PORT", "5432")), sockdir


_CANDIDATE = '''
import socket, subprocess, os
HOST, PORT, SOCKDIR = {host!r}, {port}, {sockdir!r}
SOCKFILE = f"{{SOCKDIR}}/.s.PGSQL.{{PORT}}"
env = dict(os.environ); env["PGCONNECT_TIMEOUT"] = "5"

def out(tag, blocked, d): print(f"{{tag}}|{{'BLOCKED' if blocked else 'REACHED'}}|{{d}}")

try:
    r = subprocess.run(["/usr/bin/psql","-h",HOST,"-p",str(PORT),"-U","migrator","-d","appdb","-c","select 1"],
                       capture_output=True, text=True, env=env, timeout=20)
    out("psql-tcp", r.returncode != 0, "")
except Exception as e: out("psql-tcp", True, type(e).__name__)
try:
    r = subprocess.run(["/usr/bin/psql","-h",SOCKDIR,"-p",str(PORT),"-U","migrator","-d","appdb","-c","select 1"],
                       capture_output=True, text=True, env=env, timeout=20)
    out("psql-sock", r.returncode != 0, "")
except Exception as e: out("psql-sock", True, type(e).__name__)
try:
    s = socket.create_connection((HOST, PORT), timeout=5); s.close(); out("raw-tcp", False, "")
except Exception as e: out("raw-tcp", True, type(e).__name__)
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(5); s.connect(SOCKFILE); s.close(); out("raw-sock", False, "")
except Exception as e: out("raw-sock", True, type(e).__name__)
try:
    import psycopg
    try:
        psycopg.connect(host=HOST, port=PORT, user="migrator", password="x", dbname="appdb", connect_timeout=5).close(); out("psycopg-tcp", False, "")
    except Exception as e: out("psycopg-tcp", True, type(e).__name__)
    try:
        psycopg.connect(host=SOCKDIR, port=PORT, user="migrator", password="x", dbname="appdb", connect_timeout=5).close(); out("psycopg-sock", False, "")
    except Exception as e: out("psycopg-sock", True, type(e).__name__)
except ImportError:
    out("psycopg-tcp", True, "no-driver"); out("psycopg-sock", True, "no-driver")

ifs = [l.split(":")[0].strip() for l in open("/proc/net/dev").read().splitlines()[2:] if ":" in l]
print("IFACES|" + ",".join(ifs))
print("SOCKEXISTS|" + str(os.path.exists(SOCKFILE)))
'''


def test_agent_cannot_reach_db_by_any_path():
    host, port, sockdir = _need()
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

    # Proof the candidate was truly isolated: only loopback, and no socket visible.
    assert parsed.get("IFACES") == "lo", f"expected only lo, got {parsed.get('IFACES')!r}"
    assert parsed.get("SOCKEXISTS") == "False", "the DB socket must not be visible in the sandbox"

    # EVERY connection path blocked. One uncovered path = theater.
    for path in ("psql-tcp", "psql-sock", "raw-tcp", "raw-sock", "psycopg-tcp", "psycopg-sock"):
        assert parsed.get(path) == "BLOCKED", f"path {path} was not blocked: {parsed.get(path)!r}"
