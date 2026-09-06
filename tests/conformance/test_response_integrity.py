"""F5: complete JSON is not evidence of a completely received HTTP message.

Exercise the real shared HTTP decoder through BOTH credentialed clients.
These are framing tests, not proof of a whole-exchange deadline (F6).
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from prometheus_protocol.core.transport import build_opener, read_bounded
from prometheus_protocol.ledger.anchor_http import HttpAppendOnlyLog
from prometheus_protocol.ledger.anchor_targets import LogTipAnchor
from prometheus_protocol.ledger.audit_chain import NOT_VERIFIABLE, VALID
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.ledger.tip_anchor import AnchorUnavailable
from prometheus_protocol.provider.remote import (
    ProviderHTTPError,
    ProviderTransportError,
    RemoteModelProvider,
)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        # Deliberately bypass response-header helpers so malformed framing is
        # preserved verbatim. Explicit close makes truncation deterministic.
        self.wfile.write(
            f"HTTP/1.1 {self.server.status} Test\r\nConnection: close\r\n".encode()
            + self.server.wire
        )
        self.wfile.flush()
        self.close_connection = True

    do_POST = do_GET


@pytest.fixture
def endpoint():
    servers = []

    def make(wire, status=200):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        server.daemon_threads = True
        server.wire = wire
        server.status = status
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True,
        )
        thread.start()
        servers.append((server, thread))
        return f"http://127.0.0.1:{server.server_port}"

    yield make
    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


BODY = b'{"entries":[],"choices":[{"message":{"content":"PASS"}}]}'


def _wire(mode, body=BODY):
    size = str(len(body)).encode()
    chunk = b"%x\r\n" % len(body) + body + b"\r\n"
    if mode == "length":
        return b"Content-Length: " + size + b"\r\n\r\n" + body
    if mode == "short_length":
        return b"Content-Length: " + str(len(body) + 100).encode() + b"\r\n\r\n" + body
    if mode == "zero_length":
        return b"Content-Length: 0\r\n\r\n"
    if mode == "close_delimited":
        return b"\r\n" + body
    if mode in {"duplicate_length", "conflicting_length", "length_and_chunked"}:
        second = {
            "duplicate_length": b"Content-Length: " + size,
            "conflicting_length": b"Content-Length: 900",
            "length_and_chunked": b"Transfer-Encoding: chunked",
        }[mode]
        return b"Content-Length: " + size + b"\r\n" + second + b"\r\n\r\n" + body
    if mode.startswith("length_"):
        value = {"length_negative": b"-1", "length_signed": b"+" + size,
                 "length_list": size + b", " + size, "length_text": b"bad",
                 "length_empty": b"", "length_huge_digits": b"9" * 5000}[mode]
        return b"Content-Length: " + value + b"\r\n\r\n" + body
    if mode == "unsupported_encoding":
        return b"Transfer-Encoding: gzip\r\n\r\n" + body
    if mode == "duplicate_encoding":
        return b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk
    framing = {
        "chunked": chunk + b"0\r\n\r\n",
        "multiple_chunks": b"".join(b"1\r\n" + bytes([byte]) + b"\r\n" for byte in body)
                           + b"0\r\n\r\n",
        "chunked_extensions": b'%x; name="value";flag\r\n' % len(body) + body
                              + b"\r\n0\r\nX-Checksum: abc\r\n\r\n",
        "missing_zero_chunk": chunk,
        "missing_final_crlf": chunk + b"0\r\n",
        "bare_lf_final": chunk + b"0\r\n\n",
        "unterminated_trailer": chunk + b"0\r\nX-Checksum: abc\r\n",
        "invalid_trailer": chunk + b"0\r\nnot-a-header\r\n\r\n",
        "framing_trailer": chunk + b"0\r\nContent-Length: 0\r\n\r\n",
        "oversized_trailer": chunk + b"0\r\nX-Large: " + b"a" * 8192 + b"\r\n\r\n",
        "excessive_trailers": chunk + b"0\r\n" + (b"X: " + b"a" * 1000 + b"\r\n") * 70
                              + b"\r\n",
        "invalid_chunk_crlf": chunk[:-2] + b"XX0\r\n\r\n",
        "short_chunk": b"%x\r\n" % (len(body) + 1) + body,
        "negative_chunk": b"-1\r\n" + body,
        "signed_chunk": b"+" + chunk + b"0\r\n\r\n",
        "bare_lf_size": chunk.replace(b"\r\n", b"\n", 1) + b"0\r\n\r\n",
        "bad_extension": b"%x;=invalid\r\n" % len(body) + body + b"\r\n0\r\n\r\n",
    }[mode]
    return b"Transfer-Encoding: chunked\r\n\r\n" + framing


def _read(client, url):
    if client == "anchor":
        return HttpAppendOnlyLog(url, allow_insecure_loopback=True, timeout_s=2).entries()
    provider = RemoteModelProvider(
        api_base=url, model="m", api_key="framing-test-canary", timeout_s=2,
        allow_insecure_loopback=True,
    )
    return provider._post("/chat/completions", {"messages": []})


@pytest.mark.parametrize("client", ["anchor", "provider"])
@pytest.mark.parametrize("mode", [
    "short_length", "duplicate_length", "conflicting_length", "length_and_chunked",
    "length_negative", "length_signed", "length_list", "length_text", "length_empty",
    "length_huge_digits", "unsupported_encoding", "duplicate_encoding", "missing_zero_chunk",
    "missing_final_crlf", "bare_lf_final", "unterminated_trailer", "invalid_trailer",
    "framing_trailer", "oversized_trailer", "excessive_trailers", "invalid_chunk_crlf",
    "short_chunk", "negative_chunk", "signed_chunk", "bare_lf_size", "bad_extension",
])
def test_incomplete_or_ambiguous_response_is_not_parsed(endpoint, client, mode):
    error = AnchorUnavailable if client == "anchor" else ProviderTransportError
    with pytest.raises(error):
        _read(client, endpoint(_wire(mode)))


@pytest.mark.parametrize("client", ["anchor", "provider"])
@pytest.mark.parametrize("mode", ["length", "chunked", "multiple_chunks", "chunked_extensions",
                                  "close_delimited"])
def test_complete_response_positive_controls(endpoint, client, mode):
    result = _read(client, endpoint(_wire(mode)))
    assert result == [] if client == "anchor" else result["choices"][0]["message"]["content"] == "PASS"


def test_zero_length_is_complete_at_transport_layer(endpoint):
    opener, _ = build_opener()
    with opener.open(endpoint(_wire("zero_length")), timeout=2) as response:
        assert read_bounded(response, time.monotonic() + 2, limit=1024, timeout_s=2) == b""


@pytest.mark.parametrize("client", ["anchor", "provider"])
@pytest.mark.parametrize("mode", ["short_length", "missing_final_crlf", "invalid_chunk_crlf"])
def test_incomplete_error_body_is_refused_and_closed(endpoint, monkeypatch, client, mode):
    import urllib.error

    closed = []
    original_close = urllib.error.HTTPError.close

    def close(error):
        original_close(error)
        closed.append(error.closed)

    monkeypatch.setattr(urllib.error.HTTPError, "close", close)
    error = AnchorUnavailable if client == "anchor" else ProviderHTTPError
    with pytest.raises(error, match="error body not read"):
        _read(client, endpoint(_wire(mode), status=500))
    assert closed and all(closed)


@pytest.mark.parametrize("mode", ["short_length", "missing_final_crlf", "invalid_chunk_crlf"])
def test_incomplete_empty_history_is_not_verified_clean(tmp_path, endpoint, mode):
    url = endpoint(_wire(mode, b'{"entries":[]}'))
    anchor = LogTipAnchor(HttpAppendOnlyLog(url, allow_insecure_loopback=True, timeout_s=2))
    ledger = SqliteLedger(tmp_path / "audit.db", tip_anchor=anchor)
    try:
        result = ledger.verify_chain()
        assert result.status == NOT_VERIFIABLE and not result.ok
    finally:
        ledger.close()


def test_complete_empty_history_can_verify_empty_ledger(tmp_path, endpoint):
    url = endpoint(_wire("length", b'{"entries":[]}'))
    ledger = SqliteLedger(tmp_path / "audit.db", tip_anchor=LogTipAnchor(
        HttpAppendOnlyLog(url, allow_insecure_loopback=True, timeout_s=2),
    ))
    try:
        assert ledger.verify_chain().status == VALID
    finally:
        ledger.close()
