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

Every model call Promethyn makes — the proposer, the judge, and the swarm
roles — passes through :meth:`RemoteModelProvider._post`, so the transport
adversary (``docs/threat-model.md`` §4) is answered here for all of them. The
disciplines themselves live in ``core/transport.py``, shared with the external
ledger anchor (§3), which is the only other credentialed client:

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

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Sequence

from prometheus_protocol.core.config import Config
from prometheus_protocol.core.endpoint import validate_endpoint
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.core.interfaces import Provider
from prometheus_protocol.core.models import Skill
from prometheus_protocol.core.transport import (
    TransportErrors,
    build_opener,
    classify_open_error,
    read_bounded,
)
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


#: The provider's own classes for each transport failure, so a caller keeps
#: catching ``ProviderTimeout`` and friends while the mechanics are shared.
_ERRORS = TransportErrors(
    transport=ProviderTransportError,
    timeout=ProviderTimeout,
    tls=ProviderTLSError,
    redirect=ProviderRedirectRefused,
    too_large=ProviderResponseTooLarge,
)


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
        self._opener, self._ssl_context = build_opener(_ERRORS)

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

        # One monotonic deadline for DNS, TCP/TLS, writes, headers and body.
        # Pass it to the transport before opener.open begins network work.
        deadline = time.monotonic() + self.timeout_s
        request._prom_deadline = deadline
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
            except ProviderTimeout:
                raise
            except ProviderError as inner:
                detail = f"<error body not read: {type(inner).__name__}>"
            finally:
                exc.close()
            raise ProviderHTTPError(
                exc.code, f"endpoint returned HTTP {exc.code}: {detail}"
            ) from exc
        except Exception as exc:
            classified = classify_open_error(exc, timeout_s=self.timeout_s, errors=_ERRORS)
            if classified is None:
                raise
            raise classified from exc

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
        """Read a body under ``limit`` bytes and before ``deadline``; refused,
        never truncated, past either (``core/transport.py``)."""

        return read_bounded(
            stream, deadline, limit=limit, timeout_s=self.timeout_s, errors=_ERRORS
        )


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
