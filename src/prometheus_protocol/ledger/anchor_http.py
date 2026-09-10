"""A remote append-only log over HTTPS — the anchor target on another party's
host.

The wire protocol is three requests, small enough that a witness service is a
few dozen lines behind any web framework, and any transparency-log-style
service can front it:

``POST <url>``
    Body: one anchor record, ``{"version": 1, "seq": N, "entry_hash": "…"}``.
    Reply: ``{"index": k}`` with 200 or 201, where k is a non-negative integer.
    Success also requires GET history to return the exact canonical submitted
    record at k. The log appends; it never edits.

``GET <url>``
    Reply: ``{"entries": [record, …]}``, oldest first — the whole history.

``GET <url>/latest``
    Reply: ``{"entry": record}`` or ``{"entry": null}``.

The ledger host holds a credential that may only ``POST`` and ``GET``; the log
is protecting exactly when the party running it is not the party running the
ledger host. The host's credential can append a forged record — the verifier
then reports the conflict — but cannot delete an honest one. The log's own
operator can, and that is the stated residual.

This is the second credentialed client in the codebase, so it carries the same
transport disciplines as the first (``core/transport.py``): ``https://``
required for any remote host, redirects refused, body reads with deadline
checks and a size ceiling, and transport failures surfaced as
:class:`AnchorUnavailable` — never a partial read parsed as a shorter history,
never a swallowed error. Nothing from the endpoint is trusted for its
*meaning*: a record it returns is validated field by field, and its content is
only ever pinned against the chain.

Read-back requires read-after-write consistency; it does not prove physical
durability or protect against a dishonest log operator. Each request has one
monotonic deadline across DNS, TCP/TLS, writes, headers, framing and body. An
append and its confirmation are separate requests with separate budgets.
"""

from __future__ import annotations

import json
import logging
import math
import time
import urllib.error
import urllib.request

from prometheus_protocol.core.diagnostics import (
    Diagnostic,
    http_reason,
    origin_of,
    raise_bounded,
)
from prometheus_protocol.core.endpoint import validate_endpoint
from prometheus_protocol.core.secrets import Secret, secret_or_none
from prometheus_protocol.core.transport import (
    DeadlineRequest,
    TransportErrors,
    build_opener,
    classify_open_error,
    read_bounded,
)
from prometheus_protocol.core.validation import require_int_in_range, require_positive
from prometheus_protocol.ledger.audit_chain import canonical_json
from prometheus_protocol.ledger.tip_anchor import AnchorUnavailable

_LOG = logging.getLogger(__name__)

#: Ceiling on a history read. One record is about a hundred bytes; this is
#: room for several hundred thousand appends, and the scaling limit is named
#: in ``docs/ledger-integrity.md``.
DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024 * 1024
_ERROR_BODY_BYTES = 64 * 1024

#: Every transport failure is the one thing the ledger needs to know: the
#: anchor is unavailable. The message says which kind.
_ERRORS = TransportErrors(
    transport=AnchorUnavailable,
    timeout=AnchorUnavailable,
    tls=AnchorUnavailable,
    redirect=AnchorUnavailable,
    too_large=AnchorUnavailable,
    malformed=AnchorUnavailable,
)


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non-finite JSON number")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite JSON number")
    return result


def _json_object(raw: bytes) -> dict:
    try:
        data = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_reject_constant, parse_float=_finite_float,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise AnchorUnavailable("anchor log record or response is not unambiguous JSON") from exc
    if not isinstance(data, dict):
        raise AnchorUnavailable("anchor log returned JSON that is not an object")
    return data


class HttpAppendOnlyLog:
    """The :class:`~prometheus_protocol.ledger.anchor_targets.AppendOnlyLog`
    port over the wire protocol above."""

    def __init__(
        self,
        url: str,
        *,
        token: str | Secret | None = None,
        timeout_s: float = 10.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        allow_insecure_loopback: bool = False,
    ) -> None:
        # Refused here, before any request exists, not at request time when the
        # header has already been built.
        self.url = validate_endpoint(
            url, name="ledger_anchor", allow_insecure_loopback=allow_insecure_loopback
        ).rstrip("/")
        # F8/A2 — STORED as a Secret, whatever it arrived as. A raw attribute
        # renders through `vars(log)` however careful __repr__ is.
        self._token = secret_or_none(token)
        self.timeout_s = require_positive(timeout_s, name="timeout_s")
        self.max_response_bytes = require_int_in_range(
            max_response_bytes, name="max_response_bytes", minimum=1024, maximum=1 << 30
        )
        self._opener, self._ssl_context = build_opener(_ERRORS)

    # -- the port ------------------------------------------------------------

    def append(self, record: bytes) -> int:
        # Bind the acknowledgement to the canonical object actually sent. An
        # index alone (even a plausible one) is not evidence of an append.
        body = self._record_bytes(_json_object(bytes(record)), where="append")
        data = self._exchange("POST", self.url, body=body)
        index = data.get("index")
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise AnchorUnavailable("anchor log returned no valid append index")
        records = self.entries()
        if index >= len(records) or records[index] != body:
            raise AnchorUnavailable("anchor log append was not confirmed at its returned index")
        return index

    def entries(self) -> list[bytes]:
        data = self._exchange("GET", self.url)
        entries = data.get("entries")
        if not isinstance(entries, list):
            raise AnchorUnavailable("anchor log returned no 'entries' list")
        return [self._record_bytes(entry, where=f"entries[{i}]") for i, entry in enumerate(entries)]

    def latest(self) -> bytes | None:
        data = self._exchange("GET", self.url + "/latest")
        if "entry" not in data:
            raise AnchorUnavailable("anchor log returned no 'entry' field")
        entry = data["entry"]
        return None if entry is None else self._record_bytes(entry, where="latest")

    @staticmethod
    def _record_bytes(entry: object, *, where: str) -> bytes:
        if not isinstance(entry, dict):
            raise AnchorUnavailable(f"anchor log {where} is not a record object")
        try:
            return canonical_json(entry).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise AnchorUnavailable("anchor log record cannot be canonically encoded") from exc

    # -- transport -----------------------------------------------------------

    def _exchange(self, method: str, url: str, *, body: bytes | None = None) -> dict:
        # F8/C — this line used to claim "the token is never logged". True of
        # this line, false of the module: the token reached diagnostics through
        # the failure path, which quoted the anchor's response body, not through
        # the logger. What holds now is that `self._token` is a `Secret` (no
        # rendering path emits it) and that every failure below is built from a
        # bounded Diagnostic, so no upstream byte becomes a message. The
        # residual is `reveal()` below: the plaintext is in this frame and in
        # the request headers, in use.
        _LOG.debug("%s %s", method, url)
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self._token is not None:
            headers["Authorization"] = f"Bearer {self._token.reveal()}"
        request = DeadlineRequest(url, data=body, headers=headers, method=method)

        # One monotonic deadline for DNS, TCP/TLS, writes, headers and body.
        # Pass it to the transport before opener.open begins network work.
        deadline = time.monotonic() + self.timeout_s
        request.prom_deadline = deadline
        try:
            response = self._opener.open(request, timeout=self.timeout_s)
        # F8/A1+A3 — same two rules as ``provider/remote.py``: a bounded
        # diagnostic instead of a quoted body, and a raise OUTSIDE the except
        # block so ``raise_bounded`` can sever __context__. The old message
        # pasted 500 characters of the anchor's error body into an
        # AnchorUnavailable that reaches chain-verification diagnostics — "the
        # configured tip anchor could not be read: ... Bearer <token>".
        except AnchorUnavailable:
            raise
        except urllib.error.HTTPError as exc:
            translated: Exception | None = self._http_failure(exc, deadline)
        except Exception as exc:
            classified = classify_open_error(exc, timeout_s=self.timeout_s, errors=_ERRORS)
            if classified is None:
                raise
            translated = classified
        else:
            translated = None
        if translated is not None:
            raise_bounded(translated)

        with response:
            if response.status not in ({200, 201} if method == "POST" else {200}):
                # Not ``http_reason``: a 202 is a well-formed answer that this
                # protocol does not accept, which is a different thing from a
                # malformed one and an operator needs to tell them apart.
                raise AnchorUnavailable(
                    Diagnostic(
                        "unexpected_status",
                        {"status": int(response.status), **self._where(method)},
                    ).message()
                )
            raw = read_bounded(
                response, deadline, limit=self.max_response_bytes,
                timeout_s=self.timeout_s, errors=_ERRORS,
            )
        return _json_object(raw)

    def _where(self, method: str) -> dict[str, object]:
        """Bounded context: the CONFIGURED anchor origin and what we were doing."""

        return {
            "endpoint": origin_of(self.url),
            "operation": "anchor.write" if method == "POST" else "anchor.read",
        }

    def _http_failure(self, exc: "urllib.error.HTTPError", deadline: float) -> Exception:
        """An HTTP status from the anchor, as a bounded diagnostic.

        The body is still drained under bounds — an error page can be a bomb,
        and an undrained one leaks a connection — and none of it is kept. An
        unreadable body reports no ``bytes_read``, which is how an operator
        tells "the anchor answered 500 with a page" from "the anchor answered
        500 and the body was malformed too".
        """

        body_bytes = -1
        try:
            body_bytes = len(read_bounded(
                exc, deadline, limit=_ERROR_BODY_BYTES, timeout_s=self.timeout_s,
                errors=_ERRORS,
            ))
        except AnchorUnavailable:
            body_bytes = -1
        finally:
            exc.close()

        context: dict[str, object] = {"status": int(exc.code)}
        if body_bytes >= 0:
            context["bytes_read"] = body_bytes
        return AnchorUnavailable(
            Diagnostic(http_reason(exc.code), context).message()
        )
