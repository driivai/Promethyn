"""Bounded, deadlined, redirect-refusing HTTP — one reader for every client.

The transport adversary (``docs/threat-model.md`` §4) was answered once, in
``provider/remote.py``: redirects refused because ``urllib`` re-sends the
``Authorization`` header wherever a ``302`` points; every body read in bounded
chunks with deadline checks; a body over the ceiling refused outright rather
than truncated and parsed. The external ledger anchor (§3, PIH-1) is a second
credentialed client, and a second copy of those disciplines is a second place
for them to drift. They live here instead, and both clients call them.

F4/F5 require complete, unambiguous supported response framing. F6 carries one
monotonic deadline through a killable DNS resolver, TCP attempts, TLS, writes,
and reads below buffering (including proxy CONNECT, headers and chunk metadata).
No timed-out resolver thread is abandoned. Scheduling and OS startup/cleanup
can add overhead; this is not a hard real-time guarantee against a stalled OS.

Callers keep their own exception hierarchies — a provider caller catches
``ProviderTimeout``, an anchor caller catches ``AnchorUnavailable`` — so the
reader takes the classes to raise as a :class:`TransportErrors` bundle rather
than forcing one hierarchy on everyone.
"""

from __future__ import annotations

import http.client
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

from prometheus_protocol.core._deadline import DeadlineSocket, connect, remaining
from prometheus_protocol.core.validation import require_positive

#: One receive per read call (``read1``); the deadline is checked between them.
READ_CHUNK = 64 * 1024


class TransportError(RuntimeError):
    """The connection failed or broke: refused, reset, closed mid-body."""


class TransportTimeout(TransportError):
    """The endpoint did not answer, or did not finish, within the deadline."""


class TLSFailure(TransportError):
    """The TLS handshake or certificate verification failed."""


class RedirectRefused(TransportError):
    """The endpoint tried to redirect; a credentialed request never follows."""


class ResponseTooLarge(TransportError):
    """The body exceeded the ceiling. Nothing was parsed."""


class MalformedResponse(TransportError):
    """The response's raw HTTP syntax was invalid before any framing could be
    trusted: a status or header line that is not one, or a header block the
    connection closed inside of. Nothing after it was parsed."""


@dataclass(frozen=True)
class TransportErrors:
    """The exception classes one client wants raised for each failure kind.

    Each must accept a single message argument. A client with its own
    hierarchy passes its subclasses; the defaults are the generic ones above.
    """

    transport: type[Exception] = TransportError
    timeout: type[Exception] = TransportTimeout
    tls: type[Exception] = TLSFailure
    redirect: type[Exception] = RedirectRefused
    too_large: type[Exception] = ResponseTooLarge
    malformed: type[Exception] = MalformedResponse


DEFAULT_ERRORS = TransportErrors()


def origin_only(url: str) -> str:
    """Scheme and host of an attacker-supplied URL, for a message. Nothing else
    from it is repeated."""

    try:
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.hostname}"
    except ValueError:
        return "<unparseable url>"


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Every redirect is refused, whatever the target.

    ``urllib`` copies the request headers — ``Authorization`` included — onto the
    redirected request, and turns a ``POST`` into a ``GET``. A network adversary
    who can inject one ``302`` therefore collects the bearer token at any origin
    they name, over any scheme. An endpoint that redirects is misconfigured; an
    endpoint that redirects a credentialed request is a leak.
    """

    def __init__(self, errors: TransportErrors = DEFAULT_ERRORS) -> None:
        super().__init__()
        self._errors = errors

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise self._errors.redirect(
            f"endpoint answered HTTP {code} redirecting to {origin_only(newurl)}; "
            "redirects are refused because the request carries a credential"
        )


def _header_values(stream, name: str) -> list[str]:
    headers = getattr(stream, "headers", None)
    if headers is None:
        return []
    if hasattr(headers, "get_all"):
        return headers.get_all(name, [])
    value = headers.get(name)
    return [] if value is None else [value]


def declared_length(stream) -> int | None:
    """Validate supported framing, refusing ambiguous or malformed lengths."""

    lengths = _header_values(stream, "Content-Length")
    encodings = _header_values(stream, "Transfer-Encoding")
    if encodings and (
        lengths or len(encodings) != 1 or encodings[0].strip().lower() != "chunked"
    ):
        raise http.client.HTTPException("unsupported or ambiguous response framing")
    if not lengths:
        return None
    if (len(lengths) != 1 or len(lengths[0].strip()) > 20
            or re.fullmatch(r"[0-9]+", lengths[0].strip()) is None):
        raise http.client.HTTPException("invalid or repeated Content-Length")
    try:
        return int(lengths[0].strip())
    except ValueError as exc:
        raise http.client.HTTPException("invalid Content-Length") from exc


# CPython's chunk decoder accepts EOF in place of the final trailer terminator
# and discards the two bytes after each chunk without checking they are CRLF.
# Override those boundaries; retain read1's one-body-receive behaviour.
_TOKEN = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_QUOTED = rb'"(?:[\t !#-\[\]-~\x80-\xff]|\\[\t -~\x80-\xff])*"'
_CHUNK_LINE = re.compile(
    rb"([0-9A-Fa-f]+)(?:[ \t]*;[ \t]*" + _TOKEN
    + rb"(?:[ \t]*=[ \t]*(?:" + _TOKEN + rb"|" + _QUOTED + rb"))?)*\r\n"
)
_TRAILER_LINE = re.compile(_TOKEN + rb":[\t\x20-\x7e\x80-\xff]*\r\n")
_FRAMING_LINE_LIMIT = 8192
_TRAILER_LIMIT = 64 * 1024

# Raw header syntax is validated BEFORE http.client's permissive parser sees a
# line (independent review, finding 3). That parser hands the header block to
# email.parser, which treats a line without a colon — and everything after it,
# Content-Length included — as BODY and records the fact only as a "defect";
# the message then looked close-delimited and a truncated body read as
# complete. Every status line and header line is matched here first, and the
# header block must end with its blank line before any framing is trusted.
# A header line is ``token ":" field-value CRLF`` with no leading whitespace
# (no obsolete folding), no bare CR or LF, and no control characters; the
# status line is ``HTTP/1.x SP 3DIGIT [SP reason] CRLF``. Lines are capped at
# the framing line limit and the block at 64 KiB / 100 lines.
_STATUS_LINE = re.compile(rb"HTTP/1\.[01] [0-9]{3}(?: [\t\x20-\x7e\x80-\xff]*)?\r\n")
_HEADER_LINE = re.compile(_TOKEN + rb":[\t\x20-\x7e\x80-\xff]*\r\n")
_HEADER_BLOCK_LIMIT = 64 * 1024
_HEADER_LINE_COUNT_LIMIT = 100


class MalformedResponseHeaders(http.client.HTTPException):
    """A status or header line that is not one, or a header block the
    connection closed inside of. Raised below ``http.client`` so it surfaces
    from ``opener.open()`` and is classified as the client's ``malformed``
    error. Its messages are fixed strings: nothing from the wire is echoed."""


class _StrictHeaderReader:
    """The response stream for the duration of ``begin()``: every line that
    ``http.client`` reads for the status line and headers passes through here
    first, and a line that is not a valid status or header line, or a block
    the connection closes inside of, is refused before the parser sees it."""

    def __init__(self, raw) -> None:
        self._raw = raw
        self._expect_status = True
        self._lines = 0
        self._bytes = 0

    def readline(self, limit: int = -1) -> bytes:
        line = self._raw.readline(_FRAMING_LINE_LIMIT + 1)
        if self._expect_status:
            if not line:
                # http.client reports an empty status line as RemoteDisconnected.
                return line
            if len(line) > _FRAMING_LINE_LIMIT or _STATUS_LINE.fullmatch(line) is None:
                raise MalformedResponseHeaders("malformed status line")
            self._expect_status = False
            self._lines = 0
            self._bytes = 0
            return line
        if not line:
            raise MalformedResponseHeaders(
                "connection closed inside the response headers; the header block "
                "was never terminated"
            )
        if line == b"\r\n":
            # End of this block. A 1xx block may be followed by another status.
            self._expect_status = True
            return line
        self._lines += 1
        self._bytes += len(line)
        if (
            len(line) > _FRAMING_LINE_LIMIT
            or self._lines > _HEADER_LINE_COUNT_LIMIT
            or self._bytes > _HEADER_BLOCK_LIMIT
        ):
            raise MalformedResponseHeaders("response headers exceed framing limit")
        if _HEADER_LINE.fullmatch(line) is None:
            raise MalformedResponseHeaders(
                "malformed header line: not a field name, a colon and a value "
                "ending in CRLF (obsolete folding, a bare CR or LF, a control "
                "character or a missing colon)"
            )
        return line

    def __getattr__(self, name: str):
        return getattr(self._raw, name)


class _StrictHTTPResponse(http.client.HTTPResponse):
    def begin(self) -> None:
        if self.headers is not None:
            return
        raw = self.fp
        reader = _StrictHeaderReader(raw)
        self.fp = reader
        try:
            # Explicit base call rather than zero-argument super(): the revert
            # runner re-compiles this method from source, and a __class__ cell
            # would make the mutated code object differ in free variables.
            http.client.HTTPResponse.begin(self)
        finally:
            # http.client may have closed and dropped the stream (HEAD, 1xx
            # handling); only restore what it still holds.
            if self.fp is reader:
                self.fp = raw
        # Second line of defence: whatever the parser flagged is a refusal.
        # With the raw check above this should never trigger; it is kept so
        # the two checks fail independently.
        defects = list(getattr(self.headers, "defects", None) or ())
        if defects:
            raise MalformedResponseHeaders(
                "response headers carry parser defects: "
                + ", ".join(sorted({type(defect).__name__ for defect in defects}))
            )
        declared_length(self)
        if _header_values(self, "Transfer-Encoding"):
            self.chunked = True
            self.chunk_left = None
            self.length = None

    def _read_next_chunk_size(self):
        line = self.fp.readline(_FRAMING_LINE_LIMIT + 1)
        match = _CHUNK_LINE.fullmatch(line)
        if len(line) > _FRAMING_LINE_LIMIT or match is None:
            raise http.client.HTTPException("invalid or incomplete chunk-size line")
        return int(match.group(1), 16)

    def _read_and_discard_trailer(self):
        total = 0
        while True:
            line = self.fp.readline(_FRAMING_LINE_LIMIT + 1)
            total += len(line)
            if total > _TRAILER_LIMIT or len(line) > _FRAMING_LINE_LIMIT:
                raise http.client.HTTPException("response trailers exceed framing limit")
            if line == b"\r\n":
                return
            if _TRAILER_LINE.fullmatch(line) is None:
                raise http.client.HTTPException("invalid or incomplete response trailer")
            if line.split(b":", 1)[0].lower() in {b"content-length", b"transfer-encoding"}:
                raise http.client.HTTPException("framing field in response trailer")

    def _get_chunk_left(self):
        chunk_left = self.chunk_left
        if not chunk_left:
            if chunk_left is not None and self._safe_read(2) != b"\r\n":
                raise http.client.HTTPException("invalid chunk terminator")
            chunk_left = self._read_next_chunk_size()
            if chunk_left == 0:
                self._read_and_discard_trailer()
                self._close_conn()
                chunk_left = None
            self.chunk_left = chunk_left
        return chunk_left


class _HTTPConnection(http.client.HTTPConnection):
    response_class = _StrictHTTPResponse

    def __init__(self, *args, deadline: float, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = lambda address, timeout, source_address: connect(
            address, deadline, source_address,
        )


class _HTTPSConnection(http.client.HTTPSConnection):
    response_class = _StrictHTTPResponse

    def __init__(self, *args, deadline: float, **kwargs):
        super().__init__(*args, **kwargs)
        self._deadline = deadline
        self._create_connection = lambda address, timeout, source_address: connect(
            address, deadline, source_address,
        )

    def _tunnel(self):
        # Python 3.10's _tunnel does not close its temporary HTTPResponse.
        # A retained timeout traceback then holds a makefile reference open,
        # so socket.close() alone cannot release the connection. Keep the
        # interpreter's CONNECT parser, but own its response lifecycle here.
        response_factory = self.response_class
        responses = []

        def tracked_response(*args, **kwargs):
            response = response_factory(*args, **kwargs)
            responses.append(response)
            return response

        self.response_class = tracked_response
        try:
            return super()._tunnel()
        finally:
            self.response_class = response_factory
            for response in responses:
                response.close()

    def connect(self):
        try:
            # Own cleanup for TCP/CONNECT failures as well as TLS failures,
            # including direct callers without urllib's outer error handler.
            http.client.HTTPConnection.connect(self)
            raw = self.sock.socket
            raw.settimeout(remaining(self._deadline))
            tls = self._context.wrap_socket(
                raw, server_hostname=self._tunnel_host or self.host,
                do_handshake_on_connect=False,
            )
            # Own the SSL socket before handshaking, so errors close it too.
            self.sock = DeadlineSocket(tls, self._deadline)
            tls.settimeout(remaining(self._deadline))
            tls.do_handshake()
            remaining(self._deadline)
        except BaseException:
            self.close()
            raise


class DeadlineRequest(urllib.request.Request):
    """A request carrying F6's single monotonic deadline for the whole exchange.

    The deadline used to be stashed on a plain ``Request`` as ``_prom_deadline``
    and read back with a ``getattr`` probe: an attribute the type checker knew
    nothing about at either end, so a typo in the name on the producing side
    would have silently reverted every call to per-operation timeouts — the
    exact defect F6 exists to remove. Declaring the carrier makes both ends
    checkable.
    """

    #: Monotonic instant the whole exchange must finish by, or ``None`` to fall
    #: back to the request's own timeout.
    prom_deadline: float | None = None


def _request_deadline(req: urllib.request.Request) -> float:
    deadline = req.prom_deadline if isinstance(req, DeadlineRequest) else None
    if deadline is None:
        deadline = time.monotonic() + require_positive(req.timeout, name="HTTP timeout")
    remaining(deadline)
    return deadline


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_HTTPConnection, req, deadline=_request_deadline(req))


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(
            _HTTPSConnection, req, context=self._context, deadline=_request_deadline(req),
        )


def build_opener(
    errors: TransportErrors = DEFAULT_ERRORS,
) -> tuple[urllib.request.OpenerDirector, ssl.SSLContext]:
    """An opener that verifies certificates and refuses redirects.

    The context is built explicitly and returned so a caller can expose it: the
    default context verifies the chain and checks the hostname, and an attribute
    a test reads is a fact where "the library default does that" is a claim.
    """

    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        _HTTPHandler(), _HTTPSHandler(context=context), RefuseRedirects(errors)
    )
    return opener, context


def socket_of(stream):
    """The underlying socket of an ``http.client`` response, if reachable.

    CPython keeps it at ``response.fp.raw._sock``. That is an implementation
    detail, so its absence is tolerated; its presence lets the per-read timeout
    shrink to the deadline. The production response also carries its own
    deadline below buffering, so error wrappers need not expose this attribute
    for header/framing/body timeouts to remain enforced.
    """

    raw = getattr(getattr(stream, "fp", None), "raw", None)
    sock = getattr(raw, "_sock", None)
    return sock if hasattr(sock, "settimeout") else None


def classify_url_error(
    exc: urllib.error.URLError, errors: TransportErrors = DEFAULT_ERRORS
) -> Exception:
    """The distinct exception for a ``URLError``: TLS, timeout, or transport."""

    reason = getattr(exc, "reason", None)
    if isinstance(reason, ssl.SSLError):
        return errors.tls(f"TLS failure: {reason}")
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return errors.timeout("endpoint did not answer within the deadline")
    return errors.transport(f"could not reach endpoint: {reason}")


def classify_open_error(
    exc: BaseException, *, timeout_s: float, errors: TransportErrors = DEFAULT_ERRORS
) -> Exception | None:
    """The distinct exception for a failure of ``opener.open``, or ``None`` when
    ``exc`` is not a transport failure (an ``HTTPError`` is the caller's to read
    under its own bounds, and anything else is not this layer's)."""

    if isinstance(exc, urllib.error.HTTPError):
        return None
    if isinstance(exc, urllib.error.URLError):
        return classify_url_error(exc, errors)
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return errors.timeout(f"endpoint did not answer within {timeout_s}s")
    if isinstance(exc, ssl.SSLError):
        return errors.tls(f"TLS failure: {exc}")
    if isinstance(exc, MalformedResponseHeaders):
        return errors.malformed(f"malformed HTTP response: {exc}")
    if isinstance(exc, (http.client.HTTPException, OSError)):
        return errors.transport(f"could not reach endpoint: {exc}")
    return None


def read_bounded(
    stream,
    deadline: float,
    *,
    limit: int,
    timeout_s: float,
    errors: TransportErrors = DEFAULT_ERRORS,
) -> bytes:
    """Read a body in chunks, under ``limit`` bytes and before ``deadline``.

    A body that exceeds the limit is refused, not truncated: a truncated body
    that happens to parse — a complete JSON object followed by padding, say —
    would be reported as a normal answer, which is the void guard this function
    exists to avoid. Both exits are distinct exceptions.
    """

    try:
        declared = declared_length(stream)
    except http.client.HTTPException as exc:
        raise errors.transport(str(exc)) from exc
    if declared is not None and declared > limit:
        raise errors.too_large(
            f"endpoint declared a {declared}-byte body; the ceiling is {limit} bytes"
        )
    sock = socket_of(stream)
    # ``read1`` returns after ONE receive; ``read(n)`` on a chunked body loops
    # over chunks until n bytes or EOF, so a server dripping one byte per chunk
    # would hold a single read() open for the whole body and the deadline check
    # below would never run. Measured: a 4-second drip ran to completion against
    # a 1-second deadline with read(). read1 is what makes "check the clock
    # between reads" actually mean something.
    read_once = getattr(stream, "read1", None) or stream.read
    chunks: list[bytes] = []
    total = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise errors.timeout(
                f"response not complete within {timeout_s}s ({total} bytes received)"
            )
        if sock is not None:
            # Tighten the per-read timeout to what is left of the deadline so a
            # body drip cannot stretch one receive past it. The production
            # socket reader also checks below buffering for headers/metadata.
            try:
                sock.settimeout(min(remaining, timeout_s))
            except OSError:
                sock = None
        try:
            chunk = read_once(min(READ_CHUNK, limit - total + 1))
        except (socket.timeout, TimeoutError) as exc:
            raise errors.timeout(
                f"response stalled; not complete within {timeout_s}s "
                f"({total} bytes received)"
            ) from exc
        except http.client.IncompleteRead as exc:
            raise errors.transport(f"connection closed mid-body after {total} bytes") from exc
        except ssl.SSLError as exc:
            raise errors.tls(f"TLS failure while reading: {exc}") from exc
        except (http.client.HTTPException, OSError) as exc:
            raise errors.transport(f"read failed: {exc}") from exc
        if not chunk:
            if declared is not None and total != declared:
                raise errors.transport(
                    f"incomplete response: expected {declared} bytes, received {total}"
                )
            break
        total += len(chunk)
        if total > limit:
            raise errors.too_large(
                f"response exceeded {limit} bytes; refusing to parse a partial "
                "body as if it were complete"
            )
        chunks.append(chunk)
    return b"".join(chunks)
