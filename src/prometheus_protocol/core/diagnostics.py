"""A bounded vocabulary for describing an external failure.

F8's root cause has two halves. One is that credentials were held as plain
strings (``core/secrets.py``). The other is this one: **raw upstream text was
interpolated into public diagnostics**. An HTTP error body, a header value, a
redirect target, a decoder exception, a driver message — each was pasted into an
exception message, a ``detail`` field, or a persisted record. A reflecting
endpoint that echoes the ``Authorization`` header therefore put the bearer token
into the diagnostic, and the diagnostic went to logs, to ``Evidence.detail``, and
to the ledger.

Patching the known sinks is the denylist trap this repository has been bitten by
five times. The sink nobody enumerated leaks the next secret. So the rule is
stated positively and enforced at the boundary:

    **A public diagnostic is built from a REASON CODE drawn from a closed set,
    plus context this side of the boundary computed — never from bytes the
    other side sent.**

WHAT COUNTS AS PERMITTED CONTEXT. Values the local process computed or observed
about the exchange, which an attacker cannot choose the CONTENT of:

* ``status`` — the HTTP status code, an integer this process read off the status
  line and validated as an integer;
* ``bytes_read`` / ``limit_bytes`` — counters this process incremented;
* ``elapsed_ms`` — measured locally;
* ``position`` / ``document_bytes`` — a decoder offset and a length, both
  integers, never the document;
* ``incident`` — a local identifier, derived below, that correlates a
  diagnostic with a log line without carrying anything from upstream;
* ``endpoint`` — the CONFIGURED endpoint's origin, which the operator set, never
  a host that arrived in a response;
* ``operation`` — a literal from :data:`PERMITTED_OPERATIONS`, written here;
* ``tls_reason`` / ``verify_code`` — OpenSSL's symbolic error reason and X509
  verification code. Both come from OpenSSL's own closed tables rather than from
  anything the peer composed, and ``tls_reason`` is shape-checked here so the
  key cannot become a text channel even if some handler put prose on the
  attribute. They are kept because collapsing every TLS failure into one code
  loses the distinction an operator acts on — an expired certificate, a hostname
  mismatch and a plaintext server need different responses.

An attacker influences WHETHER a code fires and WHAT the integers are. They
cannot influence the alphabet. That is the difference between a bounded
vocabulary and a scrubber: a scrubber must recognise the secret, and it will not
recognise the next one.

WHERE RAW UPSTREAM TEXT IS RETAINED: NOWHERE. There is no debug channel that
keeps the body, no "verbose mode" that prints it, and no field on the exception
holding it. This was a deliberate choice over the alternative (retain it behind
an access control), because a retained body is a body that some future log
handler, crash reporter or ``repr`` will find — which is precisely how the
twenty-five sinks came to exist. The cost is real and is stated in
``docs/ledger-integrity.md``: an operator debugging a malformed upstream
response gets a status, a length and a reason code, and must reproduce the call
against the endpoint themselves to see its body.

DIAGNOSTICS MUST STILL BE USEFUL. A reason code with no context is a different
failure mode, not a fix. The closed set below is deliberately fine-grained
enough that an operator can tell a 401 from a timeout from an oversized response
from a malformed body without ever seeing upstream bytes, and
``test_diagnostics_stay_useful`` asserts exactly that distinction survives.
"""

from __future__ import annotations

import hashlib
import re
import ssl
from dataclasses import dataclass, field
from typing import Any, Mapping

# ---------------------------------------------------------------------------
# The closed set
# ---------------------------------------------------------------------------

#: Every reason a bounded diagnostic may give. CLOSED: a value outside this set
#: is refused by :class:`Diagnostic`, so a new failure mode has to be named here
#: deliberately rather than described in prose that might quote upstream bytes.
#:
#: Grouped by what an operator would do about it, because that is the property
#: that has to survive the loss of the raw text.
REASON_CODES: frozenset[str] = frozenset({
    # -- the endpoint answered, with a refusal we understand -----------------
    "http_unauthorized",       # 401 — the credential was rejected
    "http_forbidden",          # 403 — authenticated but not permitted
    "http_not_found",          # 404 — the path is wrong
    "http_rate_limited",       # 429 — back off
    "http_client_error",       # any other 4xx
    "http_server_error",       # any 5xx — upstream's problem, retry may help
    # -- the exchange did not complete ---------------------------------------
    "timeout",                 # the deadline passed
    "tls_failure",             # certificate or handshake
    "connect_failure",         # DNS, refused, reset
    "redirect_refused",        # the endpoint tried to move a credentialed request
    "response_too_large",      # the body exceeded the ceiling; nothing parsed
    "malformed_http",          # the raw HTTP syntax was invalid
    "unexpected_status",       # a status this protocol does not accept here —
                               # e.g. an anchor answering 202 to a write it must
                               # either commit (200/201) or refuse. Distinct from
                               # malformed_http on purpose: the response was
                               # well-formed, the CONTRACT was not met.
    # -- the endpoint answered, and we could not use the answer ---------------
    "body_not_utf8",           # bytes that are not text
    "body_not_json",           # text that is not JSON
    "body_not_object",         # JSON that is not an object
    "response_shape",          # an object missing the fields the protocol needs
    "content_not_string",      # a field that must be text is not
    # -- local refusals ------------------------------------------------------
    "config_refused",          # this side would not make the call
    "unavailable",             # a dependency could not run
})

#: Reason codes an operator should read as "upstream is or may be healthy; the
#: failure is on this side or in the contract". Used by the CLI to colour advice
#: and asserted by the usefulness test, so the grouping is a property, not a
#: comment.
LOCAL_REASONS: frozenset[str] = frozenset({
    "config_refused", "redirect_refused", "response_too_large",
})

_HTTP_REASONS: dict[int, str] = {
    401: "http_unauthorized",
    403: "http_forbidden",
    404: "http_not_found",
    429: "http_rate_limited",
}


def http_reason(status: int) -> str:
    """The reason code for an HTTP status, from the status ALONE."""

    if not isinstance(status, int) or isinstance(status, bool):
        return "malformed_http"
    named = _HTTP_REASONS.get(status)
    if named is not None:
        return named
    if 400 <= status < 500:
        return "http_client_error"
    if 500 <= status < 600:
        return "http_server_error"
    return "malformed_http"


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------

#: The ONLY context keys a diagnostic may carry, and the type each must be.
#: Every one is computed on this side of the boundary. An unlisted key is
#: refused rather than rendered — which is what makes this an allowlist over the
#: thing that varies (the context payload) rather than over the message text.
PERMITTED_CONTEXT: dict[str, type] = {
    "status": int,
    "bytes_read": int,
    "limit_bytes": int,
    "elapsed_ms": int,
    "position": int,
    "document_bytes": int,
    "attempt": int,
    "verify_code": int,     # OpenSSL's X509 verification code — a closed table
    "endpoint": str,        # the CONFIGURED origin — validated as a bare origin
    "operation": str,       # a local literal, from PERMITTED_OPERATIONS
    "incident": str,        # local correlation id from ``incident_id`` — hex only
    "tls_reason": str,      # OpenSSL's symbolic reason — SHOUTY_SNAKE, closed set
}

#: The four string-valued context keys are the only place a caller could smuggle
#: upstream text in, so each is constrained: ``endpoint`` must be an origin the
#: operator configured, ``operation`` must come from this frozen set, ``incident``
#: is hex from :func:`incident_id`, and ``tls_reason`` must match
#: :data:`_TLS_REASON`.
PERMITTED_OPERATIONS: frozenset[str] = frozenset({
    "chat.completions", "anchor.read", "anchor.write", "anchor.verify",
    "attestation.publish", "attestation.verify", "signer.sign",
    "judge.assess", "grounding.assess", "migration.execute", "reconcile",
    "config.load", "unspecified",
})


#: An OpenSSL symbolic error reason (``CERTIFICATE_VERIFY_FAILED``,
#: ``TLSV1_ALERT_PROTOCOL_VERSION``, ``WRONG_VERSION_NUMBER``). CPython fills
#: ``SSLError.reason`` from OpenSSL's own table, so it is a closed vocabulary
#: rather than composed text — but this codebase does not trust that by
#: reputation: the shape is enforced here, so even a handler that put something
#: else on the attribute could not turn this key into a text channel.
_TLS_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


class UnboundedDiagnostic(ValueError):
    """A diagnostic was built from something outside the vocabulary."""


@dataclass(frozen=True)
class Diagnostic:
    """One bounded description of an external failure.

    Immutable, and it holds no upstream bytes — there is no field it could hide
    them in. ``message()`` is the only rendering, and it is built from the reason
    code and the permitted context alone.
    """

    reason: str
    context: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.reason not in REASON_CODES:
            raise UnboundedDiagnostic(
                f"{self.reason!r} is not a reason code. The set is closed: add a "
                "code deliberately rather than describing the failure in prose, "
                "because prose is where upstream bytes get in."
            )
        for key, value in self.context.items():
            expected = PERMITTED_CONTEXT.get(key)
            if expected is None:
                raise UnboundedDiagnostic(
                    f"{key!r} is not permitted diagnostic context. Permitted: "
                    f"{sorted(PERMITTED_CONTEXT)}. Anything else risks carrying "
                    "bytes the other side chose."
                )
            if isinstance(value, bool) or not isinstance(value, expected):
                raise UnboundedDiagnostic(
                    f"diagnostic context {key!r} must be {expected.__name__}, "
                    f"got {type(value).__name__}"
                )
            if key == "operation" and value not in PERMITTED_OPERATIONS:
                raise UnboundedDiagnostic(
                    f"operation {value!r} is not one of {sorted(PERMITTED_OPERATIONS)}"
                )
            if key == "incident" and (
                len(str(value)) != 12
                or any(c not in "0123456789abcdef" for c in str(value))
            ):
                raise UnboundedDiagnostic(
                    "diagnostic incident must be a 12-character hex id from "
                    "incident_id(); a free-form string here would be a channel "
                    "for upstream text"
                )
            if key == "tls_reason" and not _TLS_REASON.match(str(value)):
                raise UnboundedDiagnostic(
                    "diagnostic tls_reason must be an OpenSSL symbolic reason "
                    "(A-Z, digits and underscores); the SSLError's MESSAGE is "
                    "not one, and can name the certificate the peer presented"
                )
            if key == "endpoint" and not _is_bare_origin(str(value)):
                raise UnboundedDiagnostic(
                    "diagnostic endpoint must be a bare configured origin "
                    "(scheme://host[:port]) with no path, query or userinfo; a "
                    "host that arrived in a response is attacker-chosen and must "
                    "never appear in a diagnostic"
                )

    def message(self) -> str:
        """The whole public rendering. Stable, greppable, upstream-free."""

        parts = [self.reason]
        for key in sorted(self.context):
            parts.append(f"{key}={self.context[key]}")
        return " ".join(parts)

    def as_payload(self) -> dict[str, Any]:
        """For a persisted record. Same content, structured."""

        return {"reason": self.reason, **dict(self.context)}


def _is_bare_origin(value: str) -> bool:
    """``https://host[:port]`` and nothing else.

    The endpoint in a diagnostic is the one the OPERATOR configured, so that a
    reader can tell which of several providers failed. It is checked to be a
    bare origin so that this key cannot become a way to pass a redirect target,
    a path carrying a token, or a query string through the vocabulary.
    """

    from urllib.parse import urlsplit

    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return False
    if parts.username is not None or parts.password is not None:
        return False
    return value == f"{parts.scheme}://{parts.netloc}" or value == f"{parts.scheme}://{parts.netloc}/"


def origin_of(url: str) -> str:
    """The bare origin of a CONFIGURED url, for use as diagnostic context.

    Only ever applied to a url this side owns. Never to a redirect target: see
    :func:`redirect_diagnostic`.
    """

    from urllib.parse import urlsplit

    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def incident_id(*parts: object) -> str:
    """A short local identifier correlating a diagnostic with a log line.

    Derived from LOCAL values only. It is not a hash of the upstream body —
    that would be a covert channel for the body's content, and a short hash of a
    guessable body is reversible.
    """

    digest = hashlib.sha256("\x00".join(str(p) for p in parts).encode("utf-8"))
    return digest.hexdigest()[:12]


# ---------------------------------------------------------------------------
# Raising, with the chain severed
# ---------------------------------------------------------------------------


def raise_bounded(exc: BaseException) -> "None":
    """Raise ``exc`` with ``__cause__`` and ``__context__`` severed.

    **``raise ... from None`` is not enough, and this is measured.** ``from
    None`` sets ``__suppress_context__ = True`` and clears ``__cause__``, but
    leaves ``__context__`` POINTING AT the original exception::

        >>> exc.__suppress_context__      # True
        >>> exc.__cause__ is None         # True
        >>> exc.__context__ is None       # False   <-- still there
        >>> CANARY in str(exc.__context__)   # True

    What ``__suppress_context__`` actually achieves is narrower than the review
    assumed and narrower than "the cause is erased": ``traceback.format_exception``
    honours it, so the DEFAULT rendering does not show the context. Measured, the
    canary does NOT appear in ``format_exception`` output. But the reference is
    live, so anything that walks the chain itself — a log formatter that follows
    ``__cause__ or __context__``, an error-reporting SDK, ``repr`` on the chain,
    a debugger — still reaches it.

    So this severs the reference instead of suppressing its rendering.

    **IT MUST BE CALLED WITH NO EXCEPTION BEING HANDLED.** Python sets
    ``__context__`` at RAISE time from whatever is currently being handled, so
    clearing the field inside an ``except`` block and raising there re-populates
    it immediately — verified. The shape that works, and the one the call sites
    below use, is: translate inside the ``except``, bind the result, and raise
    AFTER the block has ended::

        translated = None
        try:
            ...
        except SomeError:
            translated = BoundedError(...)
        if translated is not None:
            raise_bounded(translated)

    Python deletes the ``as`` name at the end of an ``except`` block, so by the
    time ``raise_bounded`` runs the original exception is not a live local in the
    raising frame either — checked by walking ``tb_frame.f_locals`` along the
    resulting traceback.

    THE RESIDUAL. This severs the chain from the raised exception. It cannot
    reach a frame that still holds the raw value in a local of its own further up
    the stack — if a caller bound the response body to a variable that is still
    in scope, a debugger or a frame-inspecting crash reporter can read it from
    there. Nothing in Python prevents that, and the mitigation is the other half
    of this sprint: the body is not bound to a long-lived name anywhere on these
    paths.

    **WHICH HALF IS LOAD-BEARING — measured, not assumed.** The three
    assignments below are NOT what makes the chain clean. Removing
    ``__context__ = None`` and re-running the sweep changes nothing, because
    when the caller honours the contract there is no exception being handled and
    Python never populates ``__context__` in the first place. The revert runner
    records this: that mutation produced no failure, so it is not claimed as a
    proof, and the mutation that IS pinned moves a real call site's raise back
    inside its ``except``.

    The assignments stay because they cost nothing and they bound the damage
    when a future caller ignores the contract. Calling them the fix would be an
    overclaim; the fix is the shape of the call.
    """

    exc.__cause__ = None
    exc.__context__ = None
    exc.__suppress_context__ = True
    raise exc


def redirect_diagnostic(status: int, *, endpoint: str) -> Diagnostic:
    """A refused redirect, reported WITHOUT the target.

    The attacker chooses the ``Location`` header, hostname included, so
    stripping the path and query is not enough — ``origin_only(newurl)`` still
    published an attacker-chosen host into an exception message that reached
    logs. A redirect refusal therefore names the CONFIGURED endpoint (which the
    operator set) and the status, and says nothing about where the endpoint
    tried to send the request.

    HOW AN OPERATOR DIAGNOSES IT ANYWAY: the reason code says a redirect was
    refused and the status distinguishes 301/302/303/307/308; the endpoint names
    which configured target did it. Curling that endpoint shows the ``Location``
    directly, from a context where it is not being written into this process's
    logs. That is a deliberate trade — the target is exactly the field an
    attacker controls, so it is the one field that must not be echoed.
    """

    return Diagnostic(
        "redirect_refused", {"status": int(status), "endpoint": endpoint}
    )


def tls_diagnostic(exc: "ssl.SSLError") -> Diagnostic:
    """A TLS failure, reported by OpenSSL's own symbolic reason.

    "``tls_failure`` and nothing else" was the first version of this, and it is
    a different failure mode rather than a fix. An expired certificate, a
    hostname that does not match, a self-signed chain, a protocol-version
    mismatch and a plaintext server answering an ``https`` request all demand
    DIFFERENT actions from an operator, and collapsing them loses the only
    signal that says which.

    What is kept is bounded: ``SSLError.reason`` is a symbolic constant CPython
    fills from OpenSSL's table (``CERTIFICATE_VERIFY_FAILED``,
    ``WRONG_VERSION_NUMBER``), and ``SSLCertVerificationError.verify_code`` is
    an integer from the X509 table. Both are alphabets neither the peer nor an
    attacker composes.

    What is DROPPED is ``str(exc)`` and ``verify_message``. The message reads
    "certificate verify failed: self-signed certificate (_ssl.c:1016)" — prose,
    and for a hostname mismatch it names the identities the PEER PRESENTED,
    which is attacker-chosen content of exactly the kind A5 refuses for redirect
    targets. The symbolic reason says mismatch; the peer's claimed names are not
    needed to act on it, and are visible to an operator who curls the endpoint.
    """

    # Narrowed with isinstance rather than reached with a getattr default: the
    # type gate refuses a default standing in for a union-distinguishing
    # attribute, and `reason` is one of them (an ``Unavailable`` has a `reason`
    # too). Naming the exception type says which `reason` this is.
    context: dict[str, Any] = {}
    reason = exc.reason
    if isinstance(reason, str) and _TLS_REASON.match(reason):
        context["tls_reason"] = reason
    if isinstance(exc, ssl.SSLCertVerificationError):
        code = exc.verify_code
        if isinstance(code, int) and not isinstance(code, bool):
            context["verify_code"] = code
    return Diagnostic("tls_failure", context)


def decoder_diagnostic(exc: BaseException, *, document_bytes: int) -> Diagnostic:
    """A decode failure, reported as a position and a length.

    ``json.JSONDecodeError`` carries ``.doc`` — the ENTIRE document — alongside
    the position. ``str(exc)`` happens not to include it (measured: the message
    is "Expecting value: line 1 column 1 (char 0)"), which is why this leak was
    easy to miss; but the object does, so surfacing the exception, chaining it,
    or reading its attributes publishes the document. Nothing here touches
    ``.doc``: the position is an integer this decoder computed, and the length is
    a count this process took.
    """

    position = getattr(exc, "pos", None)
    context: dict[str, Any] = {"document_bytes": int(document_bytes)}
    if isinstance(position, int) and not isinstance(position, bool):
        context["position"] = position
    return Diagnostic("body_not_json", context)
