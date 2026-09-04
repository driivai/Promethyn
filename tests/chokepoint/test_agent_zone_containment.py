"""What the sandboxed agent can reach — proven, not assumed (PROM-HARDEN-MAX, attacker 1).

``test_isolation.py`` proves the six DB connection paths against a *configured*
PostgreSQL, and skips without one — so it never ran in CI (the workflow sets
``PROM_CHOKEPOINT_PG_HOST`` only for the migration step, and
``PROM_CHOKEPOINT_PG_SOCKDIR`` nowhere at all). This file needs no database: it
stands up its own listeners at the stock socket locations and probes the
containment properties directly, so the chokepoint's load-bearing claim is
checked on every run.

It covers the paths that were **open** before this sprint, each proven by
running the probe and reading the result:

* the approval **signing key** and DB password reached the agent through the
  inherited process environment — an agent holding ``PROM_CHOKEPOINT_KEY`` mints
  its own approvals, so the gate falls without a packet being sent;
* a Unix socket at either **stock PostgreSQL location** (``/tmp``,
  ``/run/postgresql``) was connectable — a socket is a filesystem object and does
  not traverse the network namespace, so ``--net`` never touched it;
* the host's **procfs** was mounted, exposing host PIDs and the command lines of
  runner-zone processes, where credentials passed as arguments are readable.

**Every negative has a positive control.** "Blocked" is worthless if the thing
was never reachable to begin with, or if the probe never ran: each test first
proves the target IS reachable from outside the sandbox (or that the canary IS
in the parent environment), and asserts the candidate actually executed. A test
that passes because nothing happened is the void guard this project exists to
name.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import uuid
from pathlib import Path

import pytest

from prometheus_protocol.sandbox.base import Limits
from prometheus_protocol.sandbox.namespace import NamespaceSandbox

_REQUIRE = (os.environ.get("PROM_REQUIRE_SANDBOX", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}

# A value that appears nowhere else, so finding it is unambiguous evidence of a
# leak rather than a coincidental substring match.
CANARY = "prom-harden-max-canary-8f3d1c7a9e2b4506"

# Stock PostgreSQL socket directories. The port suffix is deliberately off the
# default so a real PostgreSQL on the host cannot collide with the fixture — the
# *directory* is what the containment claim is about, not the filename.
_SOCKET_DIRS = ("/tmp", "/run/postgresql", "/var/run/postgresql", "/var/tmp", "/dev/shm")
_SOCKET_NAME = ".s.PGSQL.59432"


@pytest.fixture(autouse=True)
def _require_sandbox():
    if not NamespaceSandbox.available():
        if _REQUIRE:
            pytest.fail("PROM_REQUIRE_SANDBOX=1 but the namespace sandbox is unavailable")
        pytest.skip("namespace isolation runtime unavailable")


def run_candidate(source: str, files: dict[str, str] | None = None) -> dict[str, str]:
    """Run ``source`` inside the sandbox; return its ``tag|value`` lines parsed.

    Asserts the candidate genuinely ran: a harness fault that produced no output
    would otherwise read as "nothing was reachable".
    """

    with tempfile.TemporaryDirectory(prefix="prom-containment-") as ws:
        Path(ws, "probe.py").write_text(source, encoding="utf-8")
        for name, body in (files or {}).items():
            Path(ws, name).write_text(body, encoding="utf-8")
        result = NamespaceSandbox().run(
            argv=[sys.executable, "-I", "probe.py"],
            workspace=ws,
            limits=Limits(wall_time_s=90, memory_bytes=0, cpu_time_s=60, max_processes=256),
        )
    assert result.started_ok and result.exit_status == 0, (
        f"probe did not run inside the sandbox: {result.detail} / {result.stderr}"
    )
    parsed: dict[str, str] = {}
    for line in result.stdout.strip().splitlines():
        tag, _, value = line.partition("|")
        parsed[tag] = value
    assert parsed, f"probe produced no output: {result.stdout!r} / {result.stderr!r}"
    return parsed


def run_unsandboxed(source: str, files: dict[str, str] | None = None) -> dict[str, str]:
    """The positive control: the same probe with no isolation at all."""

    with tempfile.TemporaryDirectory(prefix="prom-control-") as ws:
        Path(ws, "probe.py").write_text(source, encoding="utf-8")
        for name, body in (files or {}).items():
            Path(ws, name).write_text(body, encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "probe.py"], cwd=ws, capture_output=True, text=True, timeout=90,
        )
    assert proc.returncode == 0, f"control probe failed: {proc.stderr}"
    parsed: dict[str, str] = {}
    for line in proc.stdout.strip().splitlines():
        tag, _, value = line.partition("|")
        parsed[tag] = value
    return parsed


# --------------------------------------------------------------------------
# 1. Credentials in the environment — the total-bypass path
# --------------------------------------------------------------------------

_ENV_PROBE = """
import os
for name in ("PROM_CHOKEPOINT_KEY", "PGPASSWORD", "PROM_CANARY"):
    value = os.environ.get(name)
    print("%s|%s" % (name, value if value else "<absent>"))
try:
    raw = open("/proc/self/environ", "rb").read().decode("utf-8", "replace")
except OSError as exc:
    raw = "<unreadable: %s>" % type(exc).__name__
print("PROC_SELF_ENVIRON_HAS_CANARY|%s" % ("yes" if "CANARY_VALUE" in raw else "no"))
print("ENVIRON_KEYS|%s" % ",".join(sorted(os.environ)))
"""


@pytest.fixture
def _planted_secrets(monkeypatch):
    """Put the runner-zone secrets in this process's environment, as a deployment
    following ``demo/README.md`` (``export PROM_CHOKEPOINT_KEY=...``) would."""

    monkeypatch.setenv("PROM_CHOKEPOINT_KEY", CANARY)
    monkeypatch.setenv("PGPASSWORD", CANARY)
    monkeypatch.setenv("PROM_CANARY", CANARY)


def test_the_signing_key_does_not_reach_the_agent_environment(_planted_secrets):
    source = _ENV_PROBE.replace("CANARY_VALUE", CANARY)

    # Positive control: the secrets ARE in the parent environment, so an
    # inheriting child sees them. Without this the assertions below could pass
    # simply because nothing was ever planted.
    control = run_unsandboxed(source)
    assert control["PROM_CHOKEPOINT_KEY"] == CANARY, "control did not inherit the key"
    assert control["PROC_SELF_ENVIRON_HAS_CANARY"] == "yes"

    inside = run_candidate(source)
    assert inside["PROM_CHOKEPOINT_KEY"] == "<absent>", "the approval signing key leaked to the agent"
    assert inside["PGPASSWORD"] == "<absent>", "the database password leaked to the agent"
    assert inside["PROM_CANARY"] == "<absent>"
    assert inside["PROC_SELF_ENVIRON_HAS_CANARY"] == "no", "the key leaked via /proc/self/environ"


def test_the_agent_environment_is_built_not_filtered(_planted_secrets):
    """No inherited variables at all — an allowlist that grew a hole would still
    pass a "specific secrets absent" test, so assert the whole set."""

    inside = run_candidate(_ENV_PROBE.replace("CANARY_VALUE", CANARY))
    keys = set(inside["ENVIRON_KEYS"].split(",")) - {""}
    assert keys == {"PATH", "HOME", "TMPDIR", "PWD", "LANG", "LC_ALL"}, (
        f"the agent environment must be constructed, not inherited; got {sorted(keys)}"
    )


def test_no_value_from_the_parent_environment_survives(_planted_secrets):
    inside = run_candidate(_ENV_PROBE.replace("CANARY_VALUE", CANARY))
    assert CANARY not in inside["ENVIRON_KEYS"]


# --------------------------------------------------------------------------
# 2. Unix domain sockets at the stock PostgreSQL locations
# --------------------------------------------------------------------------

class _SocketFixture:
    """Real listeners at stock socket paths, plus an abstract-namespace one."""

    def __init__(self) -> None:
        self.paths: list[str] = []
        # Unique per instance: an abstract name is a process-global rendezvous,
        # so a fixed one collides with any still-closing listener from a previous
        # test and turns a real result into a fixture error.
        self.abstract = "\0%s-%d-%s" % (CANARY, os.getpid(), uuid.uuid4().hex)
        self._servers: list[socket.socket] = []

    def start(self) -> None:
        for directory in _SOCKET_DIRS:
            path = os.path.join(directory, _SOCKET_NAME)
            try:
                os.makedirs(directory, exist_ok=True)
                if os.path.exists(path):
                    os.unlink(path)
                server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                server.bind(path)
                server.listen(8)
            except OSError:
                continue  # unwritable on this host; other locations still cover it
            self._servers.append(server)
            self.paths.append(path)
        abstract = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        abstract.bind(self.abstract)
        abstract.listen(8)
        self._servers.append(abstract)
        for server in self._servers:
            threading.Thread(target=self._serve, args=(server,), daemon=True).start()

    @staticmethod
    def _serve(server: socket.socket) -> None:
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            try:
                conn.sendall(CANARY.encode())
            finally:
                conn.close()

    def reachable(self, address) -> bool:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(5)
        try:
            client.connect(address)
            return client.recv(64) == CANARY.encode()
        except OSError:
            return False
        finally:
            client.close()

    def stop(self) -> None:
        for server in self._servers:
            server.close()
        for path in self.paths:
            try:
                os.unlink(path)
            except OSError:
                pass


@pytest.fixture
def sockets():
    fixture = _SocketFixture()
    try:
        # start() inside the guard: a partial start still gets torn down, so a
        # half-bound fixture cannot leak sockets into the next test.
        fixture.start()
        yield fixture
    finally:
        fixture.stop()


_SOCKET_PROBE = """
import socket
def probe(tag, address):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    try:
        client.connect(address)
        data = client.recv(64)
        print("%s|REACHED:%s" % (tag, data.decode("utf-8", "replace")))
    except OSError as exc:
        print("%s|BLOCKED:%s" % (tag, type(exc).__name__))
    finally:
        client.close()
for path in PATHS:
    probe(path, path)
probe("abstract", ABSTRACT)
"""


def _socket_source(fixture: _SocketFixture) -> str:
    return (
        f"PATHS = {fixture.paths!r}\nABSTRACT = {fixture.abstract!r}\n" + _SOCKET_PROBE
    )


def test_stock_postgres_socket_locations_are_unreachable(sockets):
    assert sockets.paths, "no stock socket location was writable; the test proved nothing"

    # Positive control: every listener really is live and serving from here.
    for path in sockets.paths:
        assert sockets.reachable(path), f"fixture socket {path} was not reachable outside"

    inside = run_candidate(_socket_source(sockets))
    for path in sockets.paths:
        assert inside[path].startswith("BLOCKED"), (
            f"the agent connected to a Unix socket at the stock location {path}: {inside[path]}"
        )


def test_abstract_namespace_sockets_are_unreachable(sockets):
    """Abstract sockets have no filesystem object, so hiding directories cannot
    stop them — they are scoped to the network namespace instead."""

    assert sockets.reachable(sockets.abstract), "the abstract listener was not reachable outside"
    inside = run_candidate(_socket_source(sockets))
    assert inside["abstract"].startswith("BLOCKED"), inside["abstract"]


def test_the_socket_files_are_not_even_visible(sockets):
    """Defence in depth: connection refused would be enough, but the paths should
    not resolve at all — so a later listener at the same path cannot be reached."""

    source = "PATHS = %r\n%s" % (
        sockets.paths,
        "import os\nfor p in PATHS:\n    print('%s|%s' % (p, os.path.exists(p)))\n",
    )
    inside = run_candidate(source)
    for path in sockets.paths:
        assert inside[path] == "False", f"{path} is visible inside the sandbox"


# --------------------------------------------------------------------------
# 3. procfs — host PIDs and runner-zone command lines
# --------------------------------------------------------------------------

_PROC_PROBE = """
import glob, os
pids = sorted(int(os.path.basename(p)) for p in glob.glob("/proc/[0-9]*"))
print("PID_COUNT|%d" % len(pids))
print("MAX_PID|%d" % (max(pids) if pids else 0))
found = 0
for path in glob.glob("/proc/[0-9]*/cmdline"):
    try:
        if b"CANARY_VALUE" in open(path, "rb").read():
            found += 1
    except OSError:
        pass
print("CMDLINE_LEAK|%d" % found)
victim = int(open("victim.txt").read().strip())
try:
    data = open("/proc/%d/environ" % victim, "rb").read()
    print("VICTIM_ENVIRON|%s" % ("LEAKED" if b"CANARY_VALUE" in data else "readable-clean"))
except OSError as exc:
    print("VICTIM_ENVIRON|BLOCKED:%s" % type(exc).__name__)
try:
    open("/proc/%d/mem" % victim, "rb").read(16)
    print("VICTIM_MEM|READABLE")
except OSError as exc:
    print("VICTIM_MEM|BLOCKED:%s" % type(exc).__name__)
"""


@pytest.fixture
def victim():
    """A runner-zone process carrying the canary in BOTH its command line and its
    environment — the two places a credential realistically sits."""

    env = dict(os.environ)
    env["PROM_CHOKEPOINT_KEY"] = CANARY
    proc = subprocess.Popen(
        [sys.executable, "-c", "import sys, time; time.sleep(180)", f"--password={CANARY}"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield proc
    finally:
        proc.kill()
        proc.wait(timeout=30)


def test_host_processes_and_their_command_lines_are_hidden(victim):
    source = _PROC_PROBE.replace("CANARY_VALUE", CANARY)
    files = {"victim.txt": str(victim.pid)}

    # Positive control: unsandboxed, the canary IS readable off the host procfs.
    control = run_unsandboxed(source, files)
    assert int(control["CMDLINE_LEAK"]) >= 1, "control did not see the canary command line"

    inside = run_candidate(source, files)
    assert inside["CMDLINE_LEAK"] == "0", "a runner-zone command line leaked into the agent"
    assert int(control["PID_COUNT"]) > int(inside["PID_COUNT"]), (
        "the sandbox saw as many processes as the host — /proc is not namespaced"
    )
    assert int(inside["MAX_PID"]) < int(control["MAX_PID"]), "host PIDs are visible in the sandbox"
    assert not inside["VICTIM_ENVIRON"].startswith("LEAKED"), inside["VICTIM_ENVIRON"]
    assert inside["VICTIM_MEM"].startswith("BLOCKED"), inside["VICTIM_MEM"]


# --------------------------------------------------------------------------
# 4. Network egress, including the name-resolution path
# --------------------------------------------------------------------------

_EGRESS_PROBE = """
import socket
try:
    print("DNS|REACHED:%s" % socket.gethostbyname("example.com"))
except OSError as exc:
    print("DNS|BLOCKED:%s" % type(exc).__name__)
for tag, kind in (("UDP", socket.SOCK_DGRAM), ("TCP", socket.SOCK_STREAM)):
    sock = socket.socket(socket.AF_INET, kind)
    sock.settimeout(5)
    try:
        sock.connect(("8.8.8.8", 53))
        print("%s|REACHED" % tag)
    except OSError as exc:
        print("%s|BLOCKED:%s" % (tag, type(exc).__name__))
    finally:
        sock.close()
interfaces = [
    line.split(":")[0].strip()
    for line in open("/proc/net/dev").read().splitlines()[2:]
    if ":" in line
]
print("INTERFACES|%s" % ",".join(sorted(interfaces)))
"""


def test_no_network_egress_including_dns(sockets):
    inside = run_candidate(_EGRESS_PROBE)
    assert inside["DNS"].startswith("BLOCKED"), inside["DNS"]
    assert inside["UDP"].startswith("BLOCKED"), inside["UDP"]
    assert inside["TCP"].startswith("BLOCKED"), inside["TCP"]
    assert inside["INTERFACES"] == "lo", f"expected loopback only, got {inside['INTERFACES']!r}"


# --------------------------------------------------------------------------
# 5. The signing key, by every path at once
# --------------------------------------------------------------------------

_SWEEP_PROBE = """
import glob, os
# Assembled from halves so this file does not itself contain the needle — the
# sweep reads every file it can, and a self-match would be a false positive that
# masks whether anything real leaked.
NEEDLE = "NEEDLE_HEAD" + "NEEDLE_TAIL"
NEEDLE_BYTES = NEEDLE.encode()
hits = []
if any(NEEDLE in v for v in os.environ.values()):
    hits.append("environ")
for path in ("/proc/self/environ", "/proc/self/cmdline"):
    try:
        if NEEDLE_BYTES in open(path, "rb").read():
            hits.append(path)
    except OSError:
        pass
for pattern in ("/proc/[0-9]*/environ", "/proc/[0-9]*/cmdline"):
    for path in glob.glob(pattern):
        try:
            if NEEDLE_BYTES in open(path, "rb").read():
                hits.append(path)
        except OSError:
            pass
# The directories a leaked credential would plausibly land in, plus the
# workspace itself. Bounded: /proc, /sys and the read-only system trees are
# excluded and the sweep stops at a file budget, so it cannot outrun the
# sandbox's wall clock (an expired probe would report no hits and read as clean).
BUDGET = 6000
scanned = 0
roots = ["/etc", "/tmp", "/var/tmp", "/dev/shm", "/run", "/var/run", "/home", "/root",
         os.getcwd(), os.path.expanduser("~")]
for root in roots:
    if scanned >= BUDGET:
        break
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath.startswith(("/proc", "/sys")):
            dirnames[:] = []
            continue
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > 1_000_000:
                    continue
                scanned += 1
                if NEEDLE_BYTES in open(full, "rb").read():
                    hits.append(full)
            except OSError:
                pass
        if scanned >= BUDGET:
            break
print("SCANNED|%d" % scanned)
print("HITS|%s" % ";".join(sorted(set(hits))))
"""


def test_the_signing_key_is_unreachable_by_every_inspected_path(_planted_secrets, victim):
    """Environment, own procfs entries, every other process's procfs entries, and
    a filesystem sweep of everything the agent can see."""

    half = len(CANARY) // 2
    source = _SWEEP_PROBE.replace("NEEDLE_HEAD", CANARY[:half]).replace(
        "NEEDLE_TAIL", CANARY[half:]
    )

    # Positive control: the sweep DOES find the key when nothing isolates it, so
    # an empty result inside is a property of the sandbox and not of the sweep.
    control = run_unsandboxed(source)
    assert control["HITS"], "the control sweep found nothing — the probe is not searching"

    inside = run_candidate(source)
    assert int(inside["SCANNED"]) > 0, "the sweep scanned no files; it proved nothing"
    assert inside["HITS"] == "", f"the approval signing key is reachable at: {inside['HITS']}"
