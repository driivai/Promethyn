"""Finding 3 (PROM-FIX-B part 3): raw header syntax is validated before any
framing is trusted, in the one transport both credentialed clients share.

The independent review reproduced this with real sockets: a header line
without a colon made the permissive parser drop every later header,
Content-Length included; the strict framing check then saw no declared
length, accepted EOF framing, and a 57-byte body declared as 10000 returned
clean — an empty anchor history verified VALID and a provider reply verified
PASS. Every case here goes through a real socket and both clients, the
review's own wire first. Positive controls come first in each group.

Honest scope: rejecting invalid status and header lines, an unterminated
header block, and every parser defect closes the demonstrated case. It is
not proof of complete strict-header validation; the documents say so.
"""

from __future__ import annotations

import email.errors
import email.parser
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from prometheus_protocol.core import transport
from prometheus_protocol.core.transport import MalformedResponseHeaders
from prometheus_protocol.ledger.anchor_http import HttpAppendOnlyLog
from prometheus_protocol.ledger.anchor_targets import LogTipAnchor
from prometheus_protocol.ledger.audit_chain import NOT_VERIFIABLE, VALID
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.ledger.tip_anchor import AnchorUnavailable
from prometheus_protocol.provider.remote import ProviderMalformedResponse, RemoteModelProvider

BODY = b'{"entries":[],"choices":[{"message":{"content":"PASS"}}]}'
assert len(BODY) == 57  # the review's 57-byte body
OK = b"HTTP/1.1 200 OK\r\n"


class _RawServer(ThreadingHTTPServer):
    """The raw-bytes endpoint, with the field the handler reads DECLARED."""

    raw: bytes


class _RawHandler(BaseHTTPRequestHandler):
    #: Only ever constructed by _RawServer.
    server: "_RawServer"

    """Answers every request with the server's raw bytes, status line included,
    then closes: nothing is normalised between the test and the socket."""

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.wfile.write(self.server.raw)
        self.wfile.flush()
        self.close_connection = True

    do_POST = do_GET


@pytest.fixture
def endpoint():
    servers = []

    def make(raw: bytes) -> str:
        server = _RawServer(("127.0.0.1", 0), _RawHandler)
        server.daemon_threads = True
        server.raw = raw
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        servers.append((server, thread))
        return f"http://127.0.0.1:{server.server_port}"

    yield make
    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def anchor(url):
    return HttpAppendOnlyLog(url, allow_insecure_loopback=True, timeout_s=2)


def provider(url):
    return RemoteModelProvider(
        api_base=url, model="m", api_key="header-test-canary", timeout_s=2, allow_insecure_loopback=True,
    )


def defects_of(header_block: bytes) -> set[str]:
    """What email.parser — the parser http.client delegates to — records for
    this block: the defect classes the raw check must pre-empt."""

    message = email.parser.BytesParser().parsebytes(header_block)
    return {type(defect).__name__ for defect in message.defects}


# ---------------------------------------------------------------------------
# 0. Positive controls: well-formed responses still succeed, both clients
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("wire", [
    OK + b"Content-Length: 57\r\n\r\n" + BODY,
    OK + b"Transfer-Encoding: chunked\r\n\r\n39\r\n" + BODY + b"\r\n0\r\n\r\n",
    b"HTTP/1.1 200\r\nContent-Length: 57\r\n\r\n" + BODY,               # reason phrase is optional
    b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n" + BODY,             # close-delimited stays supported
    OK + b"X-Empty:\r\nX-Text: caf\xe9 \t ok\r\nContent-Length: 57\r\n\r\n" + BODY,  # empty value, obs-text
    OK + b"Content-Length: 57\r\nX-Padded:   spaced   \r\n\r\n" + BODY,
], ids=["length", "chunked", "no-reason", "close-delimited", "empty-and-obs-text", "padded-value"])
def test_well_formed_responses_still_succeed(endpoint, wire):
    url = endpoint(wire)
    assert anchor(url).entries() == []
    assert provider(url)._post("/chat/completions", {"messages": []})["choices"][0]["message"]["content"] == "PASS"


def test_ninety_nine_header_lines_still_work(endpoint):
    """http.client's own limit is 100 lines counting the terminating blank
    line, so 99 header lines is the most a response may carry."""

    url = endpoint(OK + b"".join(b"X-%d: v\r\n" % i for i in range(98)) + b"Content-Length: 57\r\n\r\n" + BODY)
    assert anchor(url).entries() == []


# ---------------------------------------------------------------------------
# 1. The review's reproduction, on both clients, through to the verdicts
# ---------------------------------------------------------------------------

REVIEW_WIRE = OK + b"X-Bad line without colon\r\nContent-Length: 10000\r\n\r\n" + BODY


def test_the_review_wire_is_the_defect_it_says_it_is():
    block = b"X-Bad line without colon\r\nContent-Length: 10000\r\n\r\n"
    assert "MissingHeaderBodySeparatorDefect" in defects_of(block)
    # And it is exactly what made the old path fail open: the parser sees no
    # Content-Length at all once the colonless line is reached.
    assert email.parser.BytesParser().parsebytes(block).get("Content-Length") is None


def test_review_reproduction_anchor_history_is_not_verifiable_never_valid(endpoint, tmp_path):
    url = endpoint(REVIEW_WIRE)
    with pytest.raises(AnchorUnavailable, match="malformed HTTP response"):
        anchor(url).entries()
    ledger = SqliteLedger(tmp_path / "ledger.db", tip_anchor=LogTipAnchor(anchor(url)))
    try:
        verification = ledger.verify_chain()
    finally:
        ledger.close()
    assert verification.status == NOT_VERIFIABLE
    assert verification.status != VALID and not verification.ok


def test_review_reproduction_provider_reply_is_malformed_never_pass(endpoint):
    url = endpoint(REVIEW_WIRE)
    with pytest.raises(ProviderMalformedResponse, match="malformed HTTP response"):
        provider(url).assess(prompt="judge this")
    with pytest.raises(ProviderMalformedResponse):
        provider(url).generate(prompt="say PASS")


# ---------------------------------------------------------------------------
# 2. Every defect class, and every raw-syntax violation, on both clients
# ---------------------------------------------------------------------------

MALFORMED = {
    # email.parser defects a header block can carry (the class is asserted)
    "colonless": (b"X-Bad line without colon\r\nContent-Length: 10000\r\n\r\n", "MissingHeaderBodySeparatorDefect"),
    "continuation_first": (b" X: y\r\nContent-Length: 10000\r\n\r\n", "FirstHeaderLineIsContinuationDefect"),
    "envelope_header": (b"X: y\r\nFrom nobody\r\nContent-Length: 10000\r\n\r\n", "MisplacedEnvelopeHeaderDefect"),
    # raw-syntax violations email.parser accepts silently (no defect recorded)
    "obsolete_folding": (b"X: a\r\n b\r\nContent-Length: 10000\r\n\r\n", None),
    "space_before_colon": (b"Content-Length : 10000\r\n\r\n", None),
    "empty_field_name": (b": v\r\nContent-Length: 10000\r\n\r\n", None),
    "control_character": (b"X: a\x01b\r\nContent-Length: 10000\r\n\r\n", None),
    "nul_byte": (b"X: a\x00b\r\nContent-Length: 10000\r\n\r\n", None),
    "bare_cr": (b"X: a\rb\r\nContent-Length: 10000\r\n\r\n", None),
    "bare_lf_terminators": (b"Content-Length: 10000\n\n", None),
    "unterminated_block": (b"Content-Length: 10000\r\n", None),
    "oversized_line": (b"X: " + b"a" * 9000 + b"\r\nContent-Length: 10000\r\n\r\n", None),
    "too_many_headers": (b"".join(b"X-%d: v\r\n" % i for i in range(101)) + b"Content-Length: 10000\r\n\r\n", None),
}


@pytest.mark.parametrize("client", ["anchor", "provider"])
@pytest.mark.parametrize("case", sorted(MALFORMED))
def test_malformed_headers_are_a_typed_failure_never_a_clean_read(endpoint, client, case):
    block, defect = MALFORMED[case]
    if defect is not None:
        assert defect in defects_of(block), f"{case} no longer produces {defect}"
    url = endpoint(OK + block + BODY)
    if client == "anchor":
        with pytest.raises(AnchorUnavailable, match="malformed HTTP response"):
            anchor(url).entries()
    else:
        with pytest.raises(ProviderMalformedResponse, match="malformed HTTP response"):
            provider(url)._post("/chat/completions", {"messages": []})


@pytest.mark.parametrize("client", ["anchor", "provider"])
@pytest.mark.parametrize("status", [
    b"HTTP/1.1 abc OK\r\n", b"HTTP/2 200 OK\r\n", b"HTTP/1.1 200 OK\n", b"HTTP/1.1  200 OK\r\n",
    b"HTTP/1.1 200 O\x00K\r\n", b"200 OK\r\n",
], ids=["non-numeric", "http2", "bare-lf", "double-space", "nul-in-reason", "no-version"])
def test_malformed_status_lines_are_refused(endpoint, client, status):
    url = endpoint(status + b"Content-Length: 57\r\n\r\n" + BODY)
    if client == "anchor":
        with pytest.raises(AnchorUnavailable):
            anchor(url).entries()
    else:
        with pytest.raises(ProviderMalformedResponse):
            provider(url)._post("/chat/completions", {"messages": []})


@pytest.mark.parametrize("client", ["anchor", "provider"])
def test_a_header_block_the_connection_closes_inside_is_refused_as_malformed(endpoint, client):
    """Complete header termination before any framing is trusted: a server
    that closes after a valid header line and no blank line never declared
    anything, and the refusal says so — it is not read as a short body."""

    url = endpoint(OK + b"Content-Length: 10000\r\n")
    if client == "anchor":
        with pytest.raises(AnchorUnavailable, match="never terminated"):
            anchor(url).entries()
    else:
        with pytest.raises(ProviderMalformedResponse, match="never terminated"):
            provider(url)._post("/chat/completions", {"messages": []})


def test_the_parser_defect_check_stands_on_its_own(endpoint, monkeypatch):
    """The second line of defence: with the raw line checks switched off, a
    block that email.parser records a defect for is still refused."""

    monkeypatch.setattr(transport, "_HEADER_LINE", re.compile(rb"[^\n]*\n"))
    monkeypatch.setattr(transport, "_STATUS_LINE", re.compile(rb"[^\n]*\n"))
    url = endpoint(REVIEW_WIRE)
    with pytest.raises(AnchorUnavailable, match="parser defects: MissingHeaderBodySeparatorDefect"):
        anchor(url).entries()


def test_the_raw_check_stands_on_its_own(endpoint, monkeypatch):
    """And the first: a violation email.parser accepts silently (obsolete
    folding) is refused by the raw check alone."""

    url = endpoint(OK + b"X: a\r\n b\r\nContent-Length: 10000\r\n\r\n" + BODY)
    assert defects_of(b"X: a\r\n b\r\nContent-Length: 10000\r\n\r\n") == set()
    with pytest.raises(AnchorUnavailable, match="malformed header line"):
        anchor(url).entries()


def test_the_refusal_names_no_wire_content():
    """Messages are fixed strings: an attacker-chosen header is never echoed."""

    reader = transport._StrictHeaderReader(_Lines([b"HTTP/1.1 200 OK\r\n", b"X-secret-canary line\r\n"]))
    reader.readline()
    with pytest.raises(MalformedResponseHeaders) as refusal:
        reader.readline()
    assert "canary" not in str(refusal.value)


class _Lines:
    def __init__(self, lines):
        self._lines = list(lines)

    def readline(self, limit=-1):
        return self._lines.pop(0) if self._lines else b""
