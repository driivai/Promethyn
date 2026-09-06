"""A remote append-only log over HTTPS — the anchor target on another party's
host.

The wire protocol is three requests, small enough that a witness service is a
few dozen lines behind any web framework, and any transparency-log-style
service can front it:

``POST <url>``
    Body: one anchor record, ``{"version": 1, "seq": N, "entry_hash": "…"}``.
    Reply: ``{"index": k}`` with 200 or 201. The log appends; it never edits.

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
required for any remote host, redirects refused, every body read under a total
deadline and a size ceiling, and every failure surfaced as
:class:`AnchorUnavailable` — never a partial read parsed as a shorter history,
never a swallowed error. Nothing from the endpoint is trusted for its
*meaning*: a record it returns is validated field by field, and its content is
only ever pinned against the chain.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request

from prometheus_protocol.core.endpoint import validate_endpoint
from prometheus_protocol.core.transport import (
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
)


class HttpAppendOnlyLog:
    """The :class:`~prometheus_protocol.ledger.anchor_targets.AppendOnlyLog`
    port over the wire protocol above."""

    def __init__(
        self,
        url: str,
        *,
        token: str | None = None,
        timeout_s: float = 10.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        allow_insecure_loopback: bool = False,
    ) -> None:
        # Refused here, before any request exists, not at request time when the
        # header has already been built.
        self.url = validate_endpoint(
            url, name="ledger_anchor", allow_insecure_loopback=allow_insecure_loopback
        ).rstrip("/")
        self._token = token
        self.timeout_s = require_positive(timeout_s, name="timeout_s")
        self.max_response_bytes = require_int_in_range(
            max_response_bytes, name="max_response_bytes", minimum=1024, maximum=1 << 30
        )
        self._opener, self._ssl_context = build_opener(_ERRORS)

    # -- the port ------------------------------------------------------------

    def append(self, record: bytes) -> int:
        data = self._exchange("POST", self.url, body=bytes(record))
        index = data.get("index")
        return index if isinstance(index, int) and not isinstance(index, bool) else -1

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
        return canonical_json(entry).encode("utf-8")

    # -- transport -----------------------------------------------------------

    def _exchange(self, method: str, url: str, *, body: bytes | None = None) -> dict:
        # The URL only — the token is never logged.
        _LOG.debug("%s %s", method, url)
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)

        # One deadline for the whole exchange; ``timeout=`` alone is per socket
        # operation, and the deadline is what bounds the total.
        deadline = time.monotonic() + self.timeout_s
        try:
            response = self._opener.open(request, timeout=self.timeout_s)
        except AnchorUnavailable:
            raise
        except urllib.error.HTTPError as exc:
            try:
                quoted = read_bounded(
                    exc, deadline, limit=_ERROR_BODY_BYTES, timeout_s=self.timeout_s,
                    errors=_ERRORS,
                )
                detail = quoted.decode("utf-8", "replace")[:500]
            except AnchorUnavailable as inner:
                detail = f"<error body not read: {inner}>"
            raise AnchorUnavailable(
                f"anchor log returned HTTP {exc.code} to {method}: {detail}"
            ) from exc
        except Exception as exc:
            classified = classify_open_error(exc, timeout_s=self.timeout_s, errors=_ERRORS)
            if classified is None:
                raise
            raise classified from exc

        with response:
            raw = read_bounded(
                response, deadline, limit=self.max_response_bytes,
                timeout_s=self.timeout_s, errors=_ERRORS,
            )
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise AnchorUnavailable(f"anchor log returned a non-JSON body: {exc}") from exc
        if not isinstance(data, dict):
            raise AnchorUnavailable("anchor log returned JSON that is not an object")
        return data
