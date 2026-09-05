"""Configuration-driven remote model boundary.

``RemoteModelProvider`` is the production proposer. It is vendor-neutral by
construction:

  * It is configured entirely from the environment (``PROM_API_BASE``,
    ``PROM_MODEL``, ``PROM_API_KEY``) via :class:`Config`.
  * It speaks the common chat-completions request contract as JSON over the
    standard-library HTTP client, so it has no third-party dependency.
  * It contains no brand strings or hosted-endpoint defaults. Point it at any
    gateway that accepts the chat-completions request shape.

The request is deterministic where the endpoint allows it (temperature 0).

This is the ONLY place Promethyn opens a network connection, so the transport
adversary (``docs/threat-model.md`` §4) is answered here, once, for every
credentialed call — the proposer, the judge, and the swarm roles all pass
through :meth:`RemoteModelProvider._post`:

* the endpoint is validated at construction — ``https://`` for any remote host,
  plaintext only to loopback and only with a loud opt-out
  (``core/endpoint.py``);
* redirects are **refused**, because ``urllib`` re-sends the ``Authorization``
  header to wherever a ``302`` points, including a plaintext host on another
  origin — a scheme check at construction does nothing about that;
* certificates are verified with an explicit default context, exposed so a test
  can assert ``CERT_REQUIRED`` rather than trust the library default;
* every body is read in bounded chunks under a **total** deadline, and a body
  that exceeds the ceiling is refused outright — never truncated and parsed,
  since a truncated response that happens to parse is indistinguishable from a
  complete one;
* every transport failure is a distinct :class:`ProviderError` subclass, so a
  caller can tell a timeout from a refused certificate from a response bomb, and
  none of them escapes as a raw ``socket`` or ``http.client`` exception.
"""

from __future__ import annotations

import http.client
import json
import logging
import socket
import ssl
import time
import urllib.error
import urllib.request
from typing import Sequence
from urllib.parse import urlsplit

from prometheus_protocol.core.config import Config
from prometheus_protocol.core.endpoint import validate_endpoint
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.core.interfaces import Provider
from prometheus_protocol.core.models import Skill
from prometheus_protocol.core.validation import require_int_in_range, require_positive

_LOG = logging.getLogger(__name__)

#: Ceiling on a provider response body. A chat completion is kilobytes; this
#: leaves three orders of magnitude of headroom and still stops a response bomb
#: at a size a process can absorb without notice.
DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
#: Bounds on the configurable ceiling: below the floor nothing real fits, above
#: the cap the ceiling no longer bounds anything.
MIN_MAX_RESPONSE_BYTES = 1024
MAX_MAX_RESPONSE_BYTES = 1 << 30
#: An HTTP error body is only ever quoted, so it needs far less room.
_ERROR_BODY_BYTES = 64 * 1024
_READ_CHUNK = 64 * 1024

_DEFAULT_SYSTEM_PROMPT = (
    "You write small, correct Python functions. Reply with only the function "
    "source code, defining exactly the requested function, and nothing else."
)

_DEFAULT_ASSESS_SYSTEM_PROMPT = (
    "You are a strict, independent reviewer. Decide whether the candidate "
    "solution satisfies the task. Reply with exactly one word: PASS, FAIL, or "
    "ABSTAIN. Answer ABSTAIN if you cannot decide."
)

_DEFAULT_GENERATE_SYSTEM_PROMPT = (
    "You are a careful reasoning assistant. Answer the request directly and "
    "concisely, following any output format the request specifies."
)


class ProviderError(RuntimeError):
    """Raised when the remote endpoint cannot be reached or returns bad data.

    The base of a small hierarchy. Catch this to handle "the provider did not
    give a usable answer" as one case; catch a subclass to react to the specific
    failure. Nothing below is ever a silent default — every one is raised.
    """


class ProviderTransportError(ProviderError):
    """The connection failed or broke: refused, reset, closed mid-body."""


class ProviderTimeout(ProviderTransportError):
    """The endpoint did not answer, or did not finish, within the deadline.

    Covers the slow drip as well as the dead socket: the deadline is on the
    whole exchange, not on each read.
    """


class ProviderTLSError(ProviderTransportError):
    """The TLS handshake or certificate verification failed."""


class ProviderRedirectRefused(ProviderTransportError):
    """The endpoint tried to redirect; a credentialed request never follows."""


class ProviderResponseTooLarge(ProviderError):
    """The body exceeded the ceiling. Nothing was parsed."""


class ProviderHTTPError(ProviderError):
    """The endpoint answered with a non-2xx status."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class ProviderMalformedResponse(ProviderError):
    """A complete body that is not UTF-8 JSON in the expected shape."""


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Every redirect is refused, whatever the target.

    ``urllib`` copies the request headers — ``Authorization`` included — onto the
    redirected request, and turns a ``POST`` into a ``GET``. A network adversary
    who can inject one ``302`` therefore collects the bearer token at any origin
    they name, over any scheme. An API base that redirects is misconfigured; an
    API base that redirects a credentialed request is a leak.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise ProviderRedirectRefused(
            f"endpoint answered HTTP {code} redirecting to {_origin_only(newurl)}; "
            "redirects are refused because the request carries a credential"
        )


def _origin_only(url: str) -> str:
    """Scheme and host of an attacker-supplied URL, for a message. Nothing else
    from it is repeated."""

    try:
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.hostname}"
    except ValueError:
        return "<unparseable url>"


class RemoteModelProvider(Provider):
    """Speaks the chat-completions request contract over stdlib HTTP."""

    def __init__(
        self,
        *,
        api_base: str,
        model: str,
        api_key: str | None = None,
        timeout_s: float = 30.0,
        system_prompt: str = _DEFAULT_SYSTEM_PROMPT,
        assess_temperature: float = 0.0,
        allow_insecure_loopback: bool = False,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        if not api_base:
            raise ConfigError("api_base is required (set PROM_API_BASE)")
        if not model:
            raise ConfigError("model is required (set PROM_MODEL)")
        # Refused here, before any request exists, not at request time when the
        # header has already been built.
        self.api_base = validate_endpoint(
            api_base, name="api_base", allow_insecure_loopback=allow_insecure_loopback
        ).rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout_s = require_positive(timeout_s, name="timeout_s")
        self.max_response_bytes = require_int_in_range(
            max_response_bytes,
            name="max_response_bytes",
            minimum=MIN_MAX_RESPONSE_BYTES,
            maximum=MAX_MAX_RESPONSE_BYTES,
        )
        self.system_prompt = system_prompt
        # Sampling temperature for the advisory `assess`/`generate` path only.
        # Default 0.0 leaves the request byte-identical to before; a positive
        # value lets the self-consistency lever draw varied judge samples. The
        # proposer path stays temperature 0 regardless (determinism there is a
        # correctness property, not a lever).
        self.assess_temperature = assess_temperature
        # Explicit so it can be asserted: the default context verifies the chain
        # and checks the hostname. Relying on "the library default does that" is
        # a claim; an attribute a test reads is a fact.
        self._ssl_context = ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ssl_context),
            _RefuseRedirects(),
        )

    @classmethod
    def from_config(cls, config: Config) -> "RemoteModelProvider":
        return cls(
            api_base=config.api_base or "",
            model=config.model or "",
            api_key=config.api_key,
            timeout_s=config.request_timeout_s,
            allow_insecure_loopback=config.allow_insecure_loopback,
            max_response_bytes=config.provider_max_response_bytes,
        )

    def propose_solution(
        self,
        *,
        prompt: str,
        entry_point: str,
        skills: Sequence[Skill] = (),
    ) -> str:
        payload = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": _build_user_message(prompt, entry_point, skills)},
            ],
        }
        data = self._post("/chat/completions", payload)
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderMalformedResponse(f"unexpected response shape: {exc}") from exc
        return _extract_code(content)

    def assess(self, *, prompt: str, system: str | None = None) -> str:
        return self._complete(prompt, system or _DEFAULT_ASSESS_SYSTEM_PROMPT)

    def generate(self, *, prompt: str, system: str | None = None) -> str:
        return self._complete(prompt, system or _DEFAULT_GENERATE_SYSTEM_PROMPT)

    def _complete(self, prompt: str, system: str) -> str:
        payload = {
            "model": self.model,
            # 0.0 normalises to integer 0 so the default request is byte-identical
            # to before this knob existed; a positive value enables judge sampling.
            "temperature": self.assess_temperature or 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }
        data = self._post("/chat/completions", payload)
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderMalformedResponse(f"unexpected response shape: {exc}") from exc
        if not isinstance(content, str):
            raise ProviderMalformedResponse("response content is not a string")
        return content

    # -- transport ---------------------------------------------------------

    def _post(self, path: str, payload: dict) -> dict:
        url = self.api_base + path
        # Endpoint and model only — the API key is never logged.
        _LOG.debug("POST %s (model=%s)", url, self.model)
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")

        # One deadline for the whole exchange. ``timeout=`` alone is per socket
        # operation, so a server that sends a byte just inside it, forever, is
        # never timed out; the deadline is what bounds the total.
        deadline = time.monotonic() + self.timeout_s
        try:
            response = self._opener.open(request, timeout=self.timeout_s)
        except ProviderError:
            raise
        except urllib.error.HTTPError as exc:
            # The error body is quoted in the message, so it is read under the
            # same bounds as a success body: an error page can be a bomb too.
            try:
                quoted = self._read_bounded(exc, deadline, limit=_ERROR_BODY_BYTES)
                detail = quoted.decode("utf-8", "replace")[:500]
            except ProviderError as inner:
                detail = f"<error body not read: {type(inner).__name__}>"
            raise ProviderHTTPError(
                exc.code, f"endpoint returned HTTP {exc.code}: {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            raise _classify_url_error(exc) from exc
        except (socket.timeout, TimeoutError) as exc:
            raise ProviderTimeout(f"endpoint did not answer within {self.timeout_s}s") from exc
        except ssl.SSLError as exc:
            raise ProviderTLSError(f"TLS failure: {exc}") from exc
        except (http.client.HTTPException, OSError) as exc:
            raise ProviderTransportError(f"could not reach endpoint: {exc}") from exc

        with response:
            raw = self._read_bounded(response, deadline, limit=self.max_response_bytes)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProviderMalformedResponse("endpoint returned a non-UTF-8 body") from exc
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ProviderMalformedResponse(f"endpoint returned non-JSON body: {exc}") from exc
        if not isinstance(data, dict):
            raise ProviderMalformedResponse("endpoint returned JSON that is not an object")
        return data

    def _read_bounded(self, stream, deadline: float, *, limit: int) -> bytes:
        """Read a body in chunks, under ``limit`` bytes and before ``deadline``.

        A body that exceeds the limit is refused, not truncated: a truncated body
        that happens to parse — a complete JSON object followed by padding, say —
        would be reported as a normal answer, which is the void guard this method
        exists to avoid. Both exits are distinct exceptions.
        """

        declared = _declared_length(stream)
        if declared is not None and declared > limit:
            raise ProviderResponseTooLarge(
                f"endpoint declared a {declared}-byte body; the ceiling is {limit} bytes"
            )
        sock = _socket_of(stream)
        # ``read1`` returns after ONE receive; ``read(n)`` on a chunked body loops
        # over chunks until n bytes or EOF, so a server dripping one byte per
        # chunk would hold a single read() open for the whole body and the
        # deadline check below would never run. Measured: a 4-second drip ran to
        # completion against a 1-second deadline with read(). read1 is what makes
        # "check the clock between reads" actually mean something.
        read_once = getattr(stream, "read1", None) or stream.read
        chunks: list[bytes] = []
        total = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProviderTimeout(
                    f"response not complete within {self.timeout_s}s "
                    f"({total} bytes received)"
                )
            if sock is not None:
                # Tighten the per-read timeout to what is left of the deadline so
                # a drip cannot stretch one read past it. Best effort: the deadline
                # check above still bounds the total to at most one extra
                # ``timeout_s`` if the socket cannot be reached.
                try:
                    sock.settimeout(min(remaining, self.timeout_s))
                except OSError:
                    sock = None
            try:
                chunk = read_once(min(_READ_CHUNK, limit - total + 1))
            except (socket.timeout, TimeoutError) as exc:
                raise ProviderTimeout(
                    f"response stalled; not complete within {self.timeout_s}s "
                    f"({total} bytes received)"
                ) from exc
            except http.client.IncompleteRead as exc:
                raise ProviderTransportError(
                    f"connection closed mid-body after {total} bytes"
                ) from exc
            except ssl.SSLError as exc:
                raise ProviderTLSError(f"TLS failure while reading: {exc}") from exc
            except (http.client.HTTPException, OSError) as exc:
                raise ProviderTransportError(f"read failed: {exc}") from exc
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ProviderResponseTooLarge(
                    f"response exceeded {limit} bytes; refusing to parse a partial "
                    "body as if it were complete"
                )
            chunks.append(chunk)
        return b"".join(chunks)


def _declared_length(stream) -> int | None:
    headers = getattr(stream, "headers", None)
    value = headers.get("Content-Length") if headers is not None else None
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _socket_of(stream):
    """The underlying socket of an ``http.client`` response, if reachable.

    CPython keeps it at ``response.fp.raw._sock``. That is an implementation
    detail, so its absence is tolerated (the deadline check still bounds the
    total); its presence lets the per-read timeout shrink to the deadline.
    """

    raw = getattr(getattr(stream, "fp", None), "raw", None)
    sock = getattr(raw, "_sock", None)
    return sock if hasattr(sock, "settimeout") else None


def _classify_url_error(exc: urllib.error.URLError) -> ProviderError:
    reason = getattr(exc, "reason", None)
    if isinstance(reason, ssl.SSLError):
        return ProviderTLSError(f"TLS failure: {reason}")
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return ProviderTimeout("endpoint did not answer within the deadline")
    return ProviderTransportError(f"could not reach endpoint: {reason}")


def _build_user_message(
    prompt: str, entry_point: str, skills: Sequence[Skill]
) -> str:
    parts: list[str] = []
    if skills:
        parts.append("Relevant lessons learned from earlier work:")
        for skill in skills:
            parts.append(f"\n## {skill.title}\n{skill.body}")
        parts.append("")
    parts.append(prompt)
    parts.append(f"\nDefine a function named `{entry_point}`.")
    return "\n".join(parts)


def _extract_code(content: str) -> str:
    """Pull a code block out of a chat response, tolerating prose around it."""

    text = content.strip()
    fence = "```"
    if fence not in text:
        return text
    segments = text.split(fence)
    # Fenced blocks are the odd-indexed segments. Prefer the first non-empty.
    for segment in segments[1::2]:
        block = segment
        # Drop an optional language tag on the opening fence line.
        newline = block.find("\n")
        if newline != -1 and " " not in block[:newline].strip():
            block = block[newline + 1:]
        block = block.strip()
        if block:
            return block
    return text
