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
from prometheus_protocol.core.diagnostics import (
    Diagnostic,
    decoder_diagnostic,
    http_reason,
    origin_of,
    raise_bounded,
)
from prometheus_protocol.core.endpoint import validate_endpoint
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.core.interfaces import Provider
from prometheus_protocol.core.models import Skill
from prometheus_protocol.core.secrets import Secret, secret_or_none
from prometheus_protocol.core.transport import (
    DeadlineRequest,
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
    malformed=ProviderMalformedResponse,
)


class RemoteModelProvider(Provider):
    """Speaks the chat-completions request contract over stdlib HTTP."""

    def __init__(
        self,
        *,
        api_base: str,
        model: str,
        api_key: str | Secret | None = None,
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
        # F8/A2 — STORED as a Secret, whatever it arrived as. This class has no
        # custom __repr__ to defeat, so before this the key rendered through
        # `vars(provider)` and any json.dumps of it. A plain class is not
        # covered by the dataclass-field discovery sweep, which is why the
        # sweep now also reads assignments (test_secret_canary_sweep.py).
        self.api_key = secret_or_none(api_key)
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
            # Passed as the Secret it already is; no unwrap-and-rewrap, so
            # there is one fewer frame holding the plaintext.
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
        except (KeyError, IndexError, TypeError):
            # The exception text is not quoted: a KeyError's str is the missing
            # key, which is ours, but an IndexError's or TypeError's can quote a
            # value the endpoint chose.
            shape_failure: ProviderMalformedResponse | None = ProviderMalformedResponse(
                Diagnostic("response_shape", self._where()).message()
            )
        else:
            shape_failure = None
        if shape_failure is not None:
            raise_bounded(shape_failure)
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
        except (KeyError, IndexError, TypeError):
            shape_failure: ProviderMalformedResponse | None = ProviderMalformedResponse(
                Diagnostic("response_shape", self._where()).message()
            )
        else:
            shape_failure = None
        if shape_failure is not None:
            raise_bounded(shape_failure)
        if not isinstance(content, str):
            raise ProviderMalformedResponse(
                Diagnostic("content_not_string", self._where()).message()
            )
        return content

    # -- transport ---------------------------------------------------------

    def _post(self, path: str, payload: dict) -> dict:
        url = self.api_base + path
        # F8/C — this line used to claim "the API key is never logged", which
        # was true of THIS line and false of the module. The log statement was
        # never where the credential went; the exception path was, because the
        # failure message quoted the endpoint's response body and an endpoint
        # that echoes Authorization put the bearer token straight into it.
        #
        # What holds now, and what does not:
        #   * this line names the endpoint and the model, and nothing else;
        #   * `self.api_key` is a `Secret`, so no rendering of it — repr, str,
        #     f-string, asdict, vars, json.dumps — can emit the value, and a
        #     credential-shaped field added to this class later that is NOT a
        #     Secret fails the discovery sweep in test_secret_canary_sweep.py;
        #   * the failure paths below build messages from a bounded Diagnostic,
        #     so no upstream byte reaches a log record, an exception message or
        #     an evidence record at all.
        # The residual is `reveal()` on the next lines: the plaintext exists in
        # this frame and in the request headers, and travels under TLS to the
        # configured endpoint. That is the credential being USED, and no
        # redaction discipline removes it.
        _LOG.debug("POST %s (model=%s)", url, self.model)
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key is not None:
            headers["Authorization"] = f"Bearer {self.api_key.reveal()}"
        request = DeadlineRequest(url, data=body, headers=headers, method="POST")

        # One monotonic deadline for DNS, TCP/TLS, writes, headers and body.
        # Pass it to the transport before opener.open begins network work.
        deadline = time.monotonic() + self.timeout_s
        request.prom_deadline = deadline
        # F8/A1+A3 — TRANSLATE INSIDE the handler, RAISE OUTSIDE it. Two rules
        # are at work and both are load-bearing:
        #
        #   * the message is built from a bounded Diagnostic, never from bytes
        #     the endpoint sent. The old code quoted 500 characters of the error
        #     body, so an endpoint that echoes the Authorization header put the
        #     bearer token into the exception message — and from there into logs,
        #     Unavailable.detail and the ledger;
        #   * the raise happens after the except block has ended, so
        #     ``raise_bounded`` can sever __context__. ``raise ... from exc`` kept
        #     the HTTPError — with its headers object and its url — reachable on
        #     the chain, and ``from None`` would not have severed it either.
        translated: Exception | None = None
        try:
            response = self._opener.open(request, timeout=self.timeout_s)
        except ProviderError:
            # Already bounded by this layer on the way up.
            raise
        except urllib.error.HTTPError as exc:
            translated = self._http_failure(exc, deadline)
        except Exception as exc:
            classified = classify_open_error(exc, timeout_s=self.timeout_s, errors=_ERRORS)
            if classified is None:
                raise
            translated = classified
        if translated is not None:
            raise_bounded(translated)

        with response:
            raw = self._read_bounded(response, deadline, limit=self.max_response_bytes)

        failure: Exception | None = None
        text = ""
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            # The undecodable bytes are NOT quoted: a length is enough to tell
            # "the endpoint sent binary" from "the endpoint sent nothing".
            failure = ProviderMalformedResponse(
                Diagnostic("body_not_utf8", {"bytes_read": len(raw), **self._where()})
                .message()
            )
        if failure is not None:
            raise_bounded(failure)

        data: object = None
        try:
            data = json.loads(text)
        except ValueError as exc:
            # F8/A6 — the DECODER OBJECT never surfaces. json.JSONDecodeError
            # carries ``.doc``, the entire document; ``str(exc)`` happens to show
            # only a position, which is why chaining it looked harmless. The
            # position and the length are integers this side computed.
            failure = ProviderMalformedResponse(
                decoder_diagnostic(exc, document_bytes=len(raw)).message()
            )
        if failure is not None:
            raise_bounded(failure)

        if not isinstance(data, dict):
            raise ProviderMalformedResponse(
                Diagnostic("body_not_object", {"bytes_read": len(raw), **self._where()})
                .message()
            )
        return data

    def _where(self) -> dict[str, object]:
        """The bounded context every diagnostic from this provider carries.

        The CONFIGURED origin — set by the operator, never a host that arrived in
        a response — plus a literal operation label. Together they let an
        operator say WHICH provider failed and doing WHAT, which is most of what
        the quoted body used to be doing.
        """

        return {"endpoint": origin_of(self.api_base), "operation": "chat.completions"}

    def _http_failure(self, exc: "urllib.error.HTTPError", deadline: float) -> Exception:
        """Translate an HTTP error status into a bounded diagnostic.

        The error body is still READ under the same bounds as a success body —
        an error page can be a bomb too, and leaving it undrained would leak a
        connection — but NONE of it is kept. Only the count survives, and the
        count is a number this process incremented.
        """

        body_bytes = -1
        timed_out = False
        try:
            body_bytes = len(self._read_bounded(exc, deadline, limit=_ERROR_BODY_BYTES))
        except ProviderTimeout:
            timed_out = True
        except ProviderError:
            body_bytes = -1
        finally:
            exc.close()

        if timed_out:
            # A deadline that passed while draining an error body is a timeout,
            # and it is reported as one rather than as the status.
            return ProviderTimeout(
                Diagnostic("timeout", {"status": int(exc.code), **self._where()}).message()
            )
        context: dict[str, object] = {"status": int(exc.code), **self._where()}
        if body_bytes >= 0:
            context["bytes_read"] = body_bytes
        return ProviderHTTPError(exc.code, Diagnostic(http_reason(exc.code), context).message())

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
