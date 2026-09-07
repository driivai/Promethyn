"""F6: one deadline across DNS, connect, TLS, headers, framing and bodies."""

from __future__ import annotations

import http.client
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from prometheus_protocol.core import _deadline
from prometheus_protocol.core.transport import _HTTPSConnection
from prometheus_protocol.ledger.anchor_http import HttpAppendOnlyLog
from prometheus_protocol.ledger.anchor_targets import LogTipAnchor
from prometheus_protocol.ledger.audit_chain import NOT_VERIFIABLE
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.ledger.tip_anchor import AnchorUnavailable
from prometheus_protocol.provider.remote import (
    ProviderTimeout,
    ProviderTransportError,
    RemoteModelProvider,
)

BODY = b'{"entries":[],"choices":[{"message":{"content":"PASS"}}]}'
BUDGET = 0.4
# Scheduling/teardown slack, not another socket timeout. An old header drip
# lasts >2 seconds; every gap is only 50 ms, inside the inactivity timeout.
CEILING = BUDGET + 0.6


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        try:
            if server.mode == "tls":
                server.phase.set()
                while self.request.recv(4096):
                    pass
                server.disconnected.set()
                return
            with self.request.makefile("rb") as incoming:
                first = incoming.readline()
                length = 0
                while True:
                    line = incoming.readline()
                    if line in (b"\r\n", b""):
                        break
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1])
                incoming.read(length)
            server.requests.append(first)
            server.phase.set()
            status = b"500 Error" if server.mode.startswith("error_") else b"200 OK"
            fixed = b"HTTP/1.1 " + status + b"\r\nContent-Length: %d\r\n" % len(BODY)
            chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            mode = server.mode
            if mode == "ok":
                self.request.sendall(fixed + b"\r\n" + BODY)
                return
            if mode == "status":
                prefix, drip = b"", b"HTTP/1.1 200 " + b"x" * 45 + b"\r\n\r\n"
            elif mode in {"headers", "error_headers", "proxy"}:
                prefix, drip = b"HTTP/1.1 " + status + b"\r\nX-Slow: ", b"x" * 45 + b"\r\n\r\n"
            elif mode in {"body", "error_body"}:
                prefix, drip = fixed + b"\r\n", BODY
            elif mode == "chunk_size":
                prefix, drip = chunked + b"1;extension=", b"x" * 45 + b"\r\nx\r\n0\r\n\r\n"
            elif mode == "trailer":
                prefix = chunked + b"%x\r\n" % len(BODY) + BODY + b"\r\n0\r\nX-Slow: "
                drip = b"x" * 45 + b"\r\n\r\n"
            elif mode == "shared_budget":
                # Each wait fits individually, but their sum exceeds BUDGET.
                server.stop.wait(BUDGET * 0.65)
                self.request.sendall(fixed + b"\r\n")
                server.stop.wait(BUDGET * 0.65)
                self.request.sendall(BODY)
                return
            else:
                raise AssertionError(mode)
            self.request.sendall(prefix)
            for byte in drip:
                self.request.sendall(bytes([byte]))
                if server.stop.wait(0.05):
                    return
        except (BrokenPipeError, ConnectionResetError):
            server.disconnected.set()


@pytest.fixture
def endpoint():
    made = []

    def make(mode):
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
        server.daemon_threads = True
        server.mode = mode
        server.phase = threading.Event()
        server.stop = threading.Event()
        server.disconnected = threading.Event()
        server.requests = []
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        made.append((server, thread))
        scheme = "https" if mode == "tls" else "http"
        server.url = f"{scheme}://127.0.0.1:{server.server_address[1]}"
        return server

    yield make
    for server, thread in made:
        server.stop.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _client(kind, url, budget=BUDGET):
    if kind == "anchor":
        return HttpAppendOnlyLog(url, token="anchor-deadline-canary", timeout_s=budget,
                                 allow_insecure_loopback=True)
    return RemoteModelProvider(api_base=url, model="m", api_key="provider-deadline-canary",
                               timeout_s=budget, allow_insecure_loopback=True)


def _call(client):
    if isinstance(client, HttpAppendOnlyLog):
        return client.entries()
    return client.assess(prompt="x")


@pytest.mark.parametrize("kind", ["anchor", "provider"])
@pytest.mark.parametrize("mode", ["status", "headers", "error_headers", "body", "error_body",
                                  "chunk_size", "trailer", "tls", "shared_budget"])
def test_every_network_phase_uses_the_same_deadline(endpoint, kind, mode):
    server = endpoint(mode)
    client = _client(kind, server.url)
    started = time.monotonic()
    with pytest.raises(AnchorUnavailable if kind == "anchor" else ProviderTimeout):
        _call(client)
    assert time.monotonic() - started < CEILING
    assert server.phase.is_set(), "must exercise the selected phase, not fail during startup"
    if mode != "shared_budget":
        assert server.disconnected.wait(1), "timed-out connection was not closed"


def _legacy_tunnel(self):
    """Reproduce Python 3.10's missing response.close() on every interpreter.

    Keep the response in the exception traceback, as urllib's error chaining
    does. This is a cleanup regression shim, not a replacement protocol parser.
    """
    self.send(b"CONNECT %s:%d HTTP/1.0\r\n\r\n" % (
        self._tunnel_host.encode("ascii"), self._tunnel_port,
    ))
    response = self.response_class(self.sock, method=self._method)
    _, code, _ = response._read_status()
    if code != 200:
        self.close()
        raise OSError("proxy refused CONNECT")
    while response.fp.readline(65537) not in (b"\r\n", b"\n", b""):
        pass


@pytest.mark.parametrize("kind", ["anchor", "provider"])
@pytest.mark.parametrize("legacy_cleanup", [False, True], ids=["native", "python310_cleanup"])
def test_proxy_connect_headers_are_also_deadlined(endpoint, monkeypatch, kind, legacy_cleanup):
    if legacy_cleanup:
        monkeypatch.setattr(http.client.HTTPConnection, "_tunnel", _legacy_tunnel)
    server = endpoint("proxy")
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                 "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("https_proxy", server.url)
    monkeypatch.setenv("no_proxy", "")
    client = _client(kind, "https://deadline-origin.invalid")
    started = time.monotonic()
    with pytest.raises(AnchorUnavailable if kind == "anchor" else ProviderTimeout):
        _call(client)
    assert time.monotonic() - started < CEILING
    assert server.requests[0].startswith(b"CONNECT deadline-origin.invalid:443 ")
    assert server.disconnected.wait(1)


def test_direct_connection_closes_on_proxy_timeout_even_with_live_traceback(endpoint, monkeypatch):
    monkeypatch.setattr(http.client.HTTPConnection, "_tunnel", _legacy_tunnel)
    server = endpoint("proxy")
    conn = _HTTPSConnection("127.0.0.1", port=server.server_address[1], timeout=BUDGET,
                            deadline=time.monotonic() + BUDGET)
    conn.set_tunnel("deadline-origin.invalid", 443)
    try:
        with pytest.raises(TimeoutError) as failure:
            conn.connect()
        assert failure.value.__traceback__ is not None
        assert conn.sock is None
        assert server.disconnected.wait(1)
    finally:
        conn.close()


@pytest.mark.parametrize("reply", [b"HTTP/1.0 200 OK\r\n\r\n",
                                  b"HTTP/1.0 407 Proxy Authentication Required\r\n\r\n",
                                  b"invalid-status\r\n"])
def test_tunnel_response_is_closed_and_factory_restored_on_every_exit(monkeypatch, reply):
    monkeypatch.setattr(http.client.HTTPConnection, "_tunnel", _legacy_tunnel)
    responses = []

    class ObservedResponse(http.client.HTTPResponse):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            responses.append(self)

    conn = _HTTPSConnection("proxy.invalid", timeout=2, deadline=time.monotonic() + 2)
    conn.set_tunnel("origin.invalid", 443)
    conn.response_class = ObservedResponse
    sender, peer = socket.socketpair()
    conn.sock = _deadline.DeadlineSocket(sender, time.monotonic() + 2)
    peer.sendall(reply)
    try:
        if reply.startswith(b"HTTP/1.0 200"):
            conn._tunnel()
            # Releasing the temporary response must not close the successful
            # tunnel's underlying socket before TLS can take ownership of it.
            conn.sock.sendall(b"still-open")
        else:
            with pytest.raises((OSError, http.client.HTTPException)):
                conn._tunnel()
        assert responses and all(response.closed for response in responses)
        assert conn.response_class is ObservedResponse
    finally:
        for response in responses:
            response.close()
        conn.close()
        peer.close()


def test_slow_anchor_is_not_a_valid_ledger(tmp_path, endpoint):
    ledger = SqliteLedger(tmp_path / "audit.db", tip_anchor=LogTipAnchor(
        _client("anchor", endpoint("headers").url),
    ))
    try:
        started = time.monotonic()
        result = ledger.verify_chain()
        assert result.status == NOT_VERIFIABLE and not result.ok
        assert time.monotonic() - started < CEILING
    finally:
        ledger.close()


def test_concurrent_requests_do_not_share_deadlines_or_cancel_each_other(endpoint):
    slow = _client("provider", endpoint("headers").url)
    fast = _client("provider", endpoint("ok").url, budget=2)
    with ThreadPoolExecutor(max_workers=2) as pool:
        stuck = pool.submit(_call, slow)
        healthy = pool.submit(_call, fast)
        assert healthy.result(timeout=3) == "PASS"
        with pytest.raises(ProviderTimeout):
            stuck.result(timeout=3)
    assert _call(fast) == "PASS"


@pytest.mark.parametrize("kind", ["anchor", "provider"])
def test_system_hostname_resolution_and_healthy_response_still_work(endpoint, kind):
    url = endpoint("ok").url.replace("127.0.0.1", "localhost")
    assert _call(_client(kind, url, budget=2)) == ([] if kind == "anchor" else "PASS")


@pytest.mark.parametrize("kind", ["anchor", "provider"])
def test_stalled_dns_is_killed_reaped_and_cannot_continue(tmp_path, monkeypatch, kind):
    started_file = tmp_path / "started"
    late_file = tmp_path / "late"
    code = ("import sys,time; from pathlib import Path; sys.stdin.buffer.read(); "
            f"Path({str(started_file)!r}).touch(); time.sleep(5); "
            f"Path({str(late_file)!r}).touch()")
    monkeypatch.setattr(_deadline, "_resolver_command", lambda: [sys.executable, "-I", "-c", code])
    processes = []
    original = subprocess.Popen

    def launch(*args, **kwargs):
        process = original(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(_deadline.subprocess, "Popen", launch)
    client = _client(kind, "http://127.0.0.1:9")
    for _ in range(3):
        started = time.monotonic()
        with pytest.raises(AnchorUnavailable if kind == "anchor" else ProviderTimeout):
            _call(client)
        assert time.monotonic() - started < CEILING
    assert started_file.exists()
    assert not late_file.exists()
    assert len(processes) == 3
    for process in processes:
        assert process.poll() is not None
        with pytest.raises(ProcessLookupError):
            os.kill(process.pid, 0)


def test_resolver_has_no_ambient_credentials_or_inheritable_descriptor(tmp_path, monkeypatch):
    for name in ("PROM_APPROVAL_SIGNING_KEY", "PROM_API_KEY", "PROM_LEDGER_ANCHOR_TOKEN",
                 "PGPASSWORD", "PYTHONPATH", "PYTHONSTARTUP"):
        monkeypatch.setenv(name, "dns-inheritance-secret-canary")
    with (tmp_path / "secret").open("wb") as secret:
        os.set_inheritable(secret.fileno(), True)
        inode = os.fstat(secret.fileno()).st_ino
        code = f'''
import json,os,socket,sys
assert not any(k in os.environ for k in (
    "PROM_APPROVAL_SIGNING_KEY", "PROM_API_KEY", "PROM_LEDGER_ANCHOR_TOKEN",
    "PGPASSWORD", "PYTHONPATH", "PYTHONSTARTUP"))
try:
    inherited = os.fstat({secret.fileno()}).st_ino == {inode}
except OSError:
    inherited = False
assert not inherited
raw = sys.stdin.buffer.read()
assert b"canary" not in raw
host,port = json.loads(raw)
print(json.dumps(socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)))
'''
        monkeypatch.setattr(_deadline, "_resolver_command",
                            lambda: [sys.executable, "-I", "-c", code])
        assert _deadline.resolve("127.0.0.1", 80, time.monotonic() + 2)


@pytest.mark.parametrize("kind", ["anchor", "provider"])
def test_resolver_failure_is_not_a_success_or_a_fallback(endpoint, monkeypatch, kind):
    monkeypatch.setattr(_deadline, "_resolver_command",
                        lambda: [sys.executable, "-I", "-c", "raise SystemExit(1)"])
    server = endpoint("ok")
    client = _client(kind, server.url)
    with pytest.raises(AnchorUnavailable if kind == "anchor" else ProviderTransportError):
        _call(client)
    assert server.requests == []


@pytest.mark.parametrize("budget", [-1, 0])
def test_already_expired_deadline_never_starts_dns(monkeypatch, budget):
    def forbidden(*args, **kwargs):
        raise AssertionError("expired operation launched a resolver")

    monkeypatch.setattr(_deadline.subprocess, "Popen", forbidden)
    with pytest.raises(TimeoutError):
        _deadline.resolve("127.0.0.1", 80, time.monotonic() + budget)


def test_address_attempts_share_one_connect_budget(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(_deadline.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(_deadline, "resolve", lambda *args: [
        [socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ["127.0.0.1", 80]],
    ] * 3)
    sockets = []

    class FakeSocket:
        closed = False

        def __init__(self, *args):
            sockets.append(self)

        def settimeout(self, value):
            self.timeout = value

        def connect(self, address):
            clock[0] += 0.6
            raise OSError("connection failed")

        def close(self):
            self.closed = True

    monkeypatch.setattr(_deadline.socket, "socket", FakeSocket)
    with pytest.raises(TimeoutError):
        _deadline.connect(("example.invalid", 80), 101.0)
    assert [item.timeout for item in sockets] == pytest.approx([1.0, 0.4])
    assert all(item.closed for item in sockets)


def test_request_write_is_bounded_and_does_not_restart_the_budget():
    sender, receiver = socket.socketpair()
    try:
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        started = time.monotonic()
        stream = _deadline.DeadlineSocket(sender, started + BUDGET)
        with pytest.raises(TimeoutError):
            stream.sendall(b"x" * (4 * 1024 * 1024))
        assert time.monotonic() - started < CEILING
    finally:
        sender.close()
        receiver.close()
