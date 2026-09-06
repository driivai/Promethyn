"""Bounded, deadlined, redirect-refusing HTTP — one reader for every client.

The transport adversary (``docs/threat-model.md`` §4) was answered once, in
``provider/remote.py``: redirects refused because ``urllib`` re-sends the
``Authorization`` header wherever a ``302`` points; every body read in bounded
chunks under a *total* deadline; a body over the ceiling refused outright rather
than truncated and parsed. The external ledger anchor (§3, PIH-1) is a second
credentialed client, and a second copy of those disciplines is a second place
for them to drift. They live here instead, and both clients call them.

Callers keep their own exception hierarchies — a provider caller catches
``ProviderTimeout``, an anchor caller catches ``AnchorUnavailable`` — so the
reader takes the classes to raise as a :class:`TransportErrors` bundle rather
than forcing one hierarchy on everyone.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

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
        urllib.request.HTTPSHandler(context=context), RefuseRedirects(errors)
    )
    return opener, context


def declared_length(stream) -> int | None:
    headers = getattr(stream, "headers", None)
    value = headers.get("Content-Length") if headers is not None else None
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def socket_of(stream):
    """The underlying socket of an ``http.client`` response, if reachable.

    CPython keeps it at ``response.fp.raw._sock``. That is an implementation
    detail, so its absence is tolerated (the deadline check still bounds the
    total); its presence lets the per-read timeout shrink to the deadline.
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

    declared = declared_length(stream)
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
            # drip cannot stretch one read past it. Best effort: the deadline
            # check above still bounds the total to at most one extra
            # ``timeout_s`` if the socket cannot be reached.
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
            break
        total += len(chunk)
        if total > limit:
            raise errors.too_large(
                f"response exceeded {limit} bytes; refusing to parse a partial "
                "body as if it were complete"
            )
        chunks.append(chunk)
    return b"".join(chunks)
