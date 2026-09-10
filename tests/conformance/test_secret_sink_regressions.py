"""One named test per sink the independent review reproduced, so a regression
names its site.

The canary sweep beside this file proves ABSENCE across discovered surfaces.
That is the load-bearing guarantee, and it is deliberately structural: it does
not know what a "sink" is, only what a surface is. The cost of that generality is
diagnosis — a sweep failure says "the canary is in the ledger file", not "the
judge went back to writing the raw reply".

So each reproduced sink also has a test of its own here. If one comes back, the
failure names it.

These are REGRESSION tests: each asserts the fixed behaviour, and each carries
the original defect in its docstring so the shape is not lost.
"""

from __future__ import annotations

import dataclasses
import json
import traceback

import pytest

from prometheus_protocol.core.config import Config
from prometheus_protocol.core.diagnostics import (
    Diagnostic,
    LOCAL_REASONS,
    REASON_CODES,
    UnboundedDiagnostic,
    decoder_diagnostic,
    http_reason,
    raise_bounded,
    redirect_diagnostic,
)
from prometheus_protocol.chokepoint.runner import DbTarget

CANARY = "CANARY-sink-regression-9c4e1f7b"


# ---------------------------------------------------------------------------
# secret-bearing types
# ---------------------------------------------------------------------------


def test_sink_config_repr_str_and_fstring():
    """REPRODUCED: "Config repr / str / f-string: all render api_key,
    judge_api_key, ledger_anchor_token"."""

    config = Config(
        api_key=CANARY, judge_api_key=CANARY,
        ledger_anchor_token=CANARY, config_attestation_token=CANARY,
    )
    assert CANARY not in repr(config)
    assert CANARY not in str(config)
    assert CANARY not in f"{config}"
    assert CANARY not in "%s" % (config,)
    assert CANARY not in format(config)


def test_sink_config_asdict_and_vars_to_json():
    """REPRODUCED: "asdict(Config) and vars(Config) -> JSON: render them even
    when repr=False is set". They do — ``asdict`` never consulted ``field.repr``
    — which is why the fix is a wrapper type and not a field option."""

    config = Config(api_key=CANARY, ledger_anchor_token=CANARY)
    assert CANARY not in json.dumps(dataclasses.asdict(config), default=str)
    assert CANARY not in json.dumps(vars(config), default=str)
    # And plain json.dumps refuses outright rather than emitting anything.
    with pytest.raises(TypeError):
        json.dumps(dataclasses.asdict(config))


def test_sink_dbtarget_asdict_despite_repr_false():
    """REPRODUCED: "DbTarget: repr=False and str suppress the password, but
    asdict STILL exposes it". This is the case that proves the whole approach:
    two correct per-path opt-outs, one uncovered path, credential out."""

    target = DbTarget("db.internal", 5432, "appdb", "migrator", CANARY)
    assert CANARY not in repr(target)          # repr=False worked before, too
    assert CANARY not in str(target)           # __str__ worked before, too
    assert CANARY not in json.dumps(dataclasses.asdict(target), default=str)
    assert CANARY not in json.dumps(vars(target), default=str)
    assert target.resolve_password() == CANARY  # and it still works


# ---------------------------------------------------------------------------
# exception chaining
# ---------------------------------------------------------------------------


def test_sink_raise_from_none_does_not_clear_context():
    """REPRODUCED: "``raise ... from None`` does NOT erase __context__ — the
    suppressed cause is still reachable".

    Confirmed, WITH a correction to what it means. ``from None`` clears
    ``__cause__`` and sets ``__suppress_context__``, and ``traceback.
    format_exception`` HONOURS that flag — so the default rendering is clean and
    the review's "still rendered by traceback machinery" is not what happens.
    What remains is the live REFERENCE, which anything walking the chain itself
    reaches.
    """

    try:
        try:
            raise ValueError(f"upstream said Bearer {CANARY}")
        except ValueError:
            raise RuntimeError("bounded") from None
    except RuntimeError as exc:
        assert exc.__cause__ is None
        assert exc.__suppress_context__ is True
        # The correction: the default rendering IS clean...
        rendered = "".join(
            traceback.format_exception(type(exc), exc, exc.__traceback__)
        )
        assert CANARY not in rendered
        # ...and the reference is NOT severed, which is the actual defect.
        assert exc.__context__ is not None
        assert CANARY in str(exc.__context__)


def test_sink_raise_bounded_severs_the_chain():
    """The fix. ``raise_bounded`` clears both links, and must be called with no
    exception being handled — Python re-populates ``__context__`` at raise time
    from whatever is currently in flight."""

    def boundary():
        translated = None
        try:
            raise ValueError(f"upstream said Bearer {CANARY}")
        except ValueError:
            translated = RuntimeError("http_unauthorized status=401")
        if translated is not None:
            raise_bounded(translated)

    with pytest.raises(RuntimeError) as caught:
        boundary()

    exc = caught.value
    assert exc.__cause__ is None
    assert exc.__context__ is None, "the chain was not severed"

    walked, current, guard = [], exc, 0
    while current is not None and guard < 10:
        walked.append(repr(current))
        current = current.__cause__ or current.__context__
        guard += 1
    assert CANARY not in "\n".join(walked)
    assert CANARY not in "".join(
        traceback.format_exception(type(exc), exc, exc.__traceback__)
    )


def test_sink_raise_bounded_inside_an_except_block_would_not_work():
    """The trap this API exists to avoid, asserted so nobody "simplifies" it.

    Clearing the fields and raising INSIDE the ``except`` block does not help:
    the raise re-populates ``__context__``.
    """

    def wrong():
        try:
            raise ValueError(f"Bearer {CANARY}")
        except ValueError:
            exc = RuntimeError("bounded")
            exc.__context__ = None
            raise exc  # still inside the handler

    with pytest.raises(RuntimeError) as caught:
        wrong()
    assert caught.value.__context__ is not None, (
        "Python no longer re-populates __context__ at raise time; re-derive "
        "raise_bounded's contract against whatever it does now"
    )


# ---------------------------------------------------------------------------
# decoder and redirect
# ---------------------------------------------------------------------------


def test_sink_jsondecodeerror_doc_holds_the_whole_document():
    """REPRODUCED: "JSONDecodeError.doc retains the ENTIRE document even when
    the message shows only a position"."""

    document = '{"pad": "' + "x" * 200 + '", "leak": "' + CANARY + '"} junk'
    try:
        json.loads(document)
    except json.JSONDecodeError as exc:
        # The premise: str() is clean, the OBJECT is not.
        assert CANARY not in str(exc)
        assert CANARY in exc.doc
        # The fix: the diagnostic reads the position and the length, never .doc.
        diagnostic = decoder_diagnostic(exc, document_bytes=len(document))
        assert CANARY not in diagnostic.message()
        assert CANARY not in repr(diagnostic)
        assert diagnostic.reason == "body_not_json"
        assert diagnostic.context["document_bytes"] == len(document)
        assert "position" in diagnostic.context
    else:  # pragma: no cover
        pytest.fail("the document parsed; re-derive this test")


def test_sink_redirect_diagnostic_carries_no_attacker_host():
    """REPRODUCED: "the attacker controls the HOSTNAME, so stripping path and
    query is insufficient".

    The refusal names the CONFIGURED endpoint and the status. It does not name
    the target in any form — not the host, not the origin, not a hash of it.
    """

    diagnostic = redirect_diagnostic(302, endpoint="https://api.example")
    message = diagnostic.message()
    assert CANARY not in message
    assert "api.example" in message, "the operator must know WHICH endpoint"
    assert "status=302" in message, "301 vs 302 vs 307 is a real distinction"
    # There is no field it could hide in.
    assert set(diagnostic.context) == {"status", "endpoint"}


# ---------------------------------------------------------------------------
# the vocabulary refuses what it is not
# ---------------------------------------------------------------------------


def test_the_reason_code_set_is_closed():
    with pytest.raises(UnboundedDiagnostic, match="not a reason code"):
        Diagnostic("endpoint returned: " + CANARY)


def test_diagnostic_context_is_an_allowlist_not_a_denylist():
    """A key nobody thought of is refused BY NOT BEING LISTED — the discipline
    five earlier sprints arrived at the hard way."""

    with pytest.raises(UnboundedDiagnostic, match="not permitted"):
        Diagnostic("timeout", {"upstream_body": CANARY})
    with pytest.raises(UnboundedDiagnostic, match="not permitted"):
        Diagnostic("timeout", {"detail": CANARY})
    with pytest.raises(UnboundedDiagnostic, match="not permitted"):
        Diagnostic("timeout", {"response_header": CANARY})


def test_the_two_string_context_keys_cannot_smuggle_upstream_text():
    """``endpoint`` and ``operation`` are the only string-valued context keys,
    so they are the only place upstream text could enter. Both are constrained."""

    with pytest.raises(UnboundedDiagnostic, match="bare configured origin"):
        Diagnostic("timeout", {"endpoint": f"https://{CANARY}.example/path?k=v"})
    with pytest.raises(UnboundedDiagnostic, match="bare configured origin"):
        Diagnostic("timeout", {"endpoint": f"https://user:{CANARY}@api.example"})
    with pytest.raises(UnboundedDiagnostic, match="not one of"):
        Diagnostic("timeout", {"operation": CANARY})
    with pytest.raises(UnboundedDiagnostic, match="12-character hex"):
        Diagnostic("timeout", {"incident": CANARY})


# ---------------------------------------------------------------------------
# RULE: diagnostics must remain USEFUL
# ---------------------------------------------------------------------------


def test_diagnostics_stay_useful_an_operator_can_still_triage():
    """A reason code with no context is a different failure, not a fix.

    The distinctions an operator acts on must survive the loss of the upstream
    text. Each pair below is a decision an on-call engineer makes differently,
    and each must be distinguishable from the diagnostic ALONE.
    """

    def message(reason, context=None):
        return Diagnostic(reason, context or {}).message()

    unauthorized = message("http_unauthorized", {"status": 401})
    timeout = message("timeout", {"elapsed_ms": 30_000})
    too_large = message("response_too_large", {"bytes_read": 5_000_000, "limit_bytes": 4_194_304})
    server = message("http_server_error", {"status": 503})
    malformed = message("body_not_json", {"position": 17, "document_bytes": 900})

    # 1. A rejected credential is not a timeout.
    assert unauthorized != timeout
    assert "401" in unauthorized and "unauthorized" in unauthorized
    # 2. A timeout says HOW LONG it waited.
    assert "elapsed_ms=30000" in timeout
    # 3. An oversized response says by how much, so the operator can judge
    #    whether to raise the ceiling or investigate the endpoint.
    assert "bytes_read=5000000" in too_large and "limit_bytes=4194304" in too_large
    # 4. Upstream's fault is distinguishable from ours.
    assert "server_error" in server and "503" in server
    assert server != unauthorized
    # 5. A malformed body says WHERE it broke and how big it was.
    assert "position=17" in malformed and "document_bytes=900" in malformed

    # 6. And "is this my problem or theirs" is answerable structurally, not by
    #    reading prose.
    assert "response_too_large" in LOCAL_REASONS
    assert "http_server_error" not in LOCAL_REASONS


def test_a_tls_failure_keeps_the_distinction_an_operator_acts_on():
    """The usefulness rule, applied to the branch that nearly lost it.

    The first version of the A1 fix returned a bare ``tls_failure`` for every
    TLS error. That is a different failure mode, not a fix: an expired
    certificate, a hostname mismatch, a self-signed chain and a plaintext server
    answering ``https`` demand different actions, and one code cannot say which.

    What is kept is OpenSSL's symbolic reason and X509 verify code — closed
    tables. What is dropped is the message, which is prose and, for a hostname
    mismatch, names the identities the PEER presented.
    """

    import ssl

    from prometheus_protocol.core.diagnostics import tls_diagnostic

    verify_failed = ssl.SSLCertVerificationError(1, "certificate verify failed")
    verify_failed.reason = "CERTIFICATE_VERIFY_FAILED"
    verify_failed.verify_code = 18  # self-signed, from OpenSSL's X509 table
    message = tls_diagnostic(verify_failed).message()
    assert "tls_failure" in message
    assert "tls_reason=CERTIFICATE_VERIFY_FAILED" in message
    assert "verify_code=18" in message

    wrong_version = ssl.SSLError(1, "wrong version number")
    wrong_version.reason = "WRONG_VERSION_NUMBER"
    other = tls_diagnostic(wrong_version).message()
    assert "tls_reason=WRONG_VERSION_NUMBER" in other
    assert other != message, "a plaintext server is not an untrusted certificate"

    # The prose is gone, and a reason that is NOT a symbolic constant is refused
    # rather than passed through — so this key cannot become a text channel.
    prose = ssl.SSLError(1, "x")
    prose.reason = f"certificate verify failed: {CANARY}"
    clean = tls_diagnostic(prose)
    assert CANARY not in clean.message()
    assert "tls_reason" not in clean.context
    with pytest.raises(UnboundedDiagnostic, match="symbolic reason"):
        Diagnostic("tls_failure", {"tls_reason": f"peer said {CANARY}"})


def test_a_real_self_signed_certificate_reaches_the_bounded_diagnostic():
    """Not a hand-built exception: a real handshake against a real server whose
    certificate no trust store knows, driven through the real classifier."""

    import shutil
    import socket
    import ssl
    import subprocess
    import tempfile
    import threading
    import urllib.error
    import urllib.request
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from pathlib import Path

    from prometheus_protocol.core.transport import classify_url_error

    if shutil.which("openssl") is None:  # pragma: no cover - CI has openssl
        pytest.skip("openssl unavailable for a real certificate")

    with tempfile.TemporaryDirectory() as where:
        key, cert = Path(where) / "k.pem", Path(where) / "c.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cert), "-days", "1",
             "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
            check=True, capture_output=True, timeout=120,
        )
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(str(cert), str(key))

        class _Quiet(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                return

            def do_GET(self) -> None:  # pragma: no cover - never reached
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Quiet)
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"https://127.0.0.1:{server.server_address[1]}/"
            with pytest.raises(urllib.error.URLError) as caught:
                urllib.request.urlopen(url, timeout=10)
            translated = classify_url_error(caught.value)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    text = str(translated)
    assert "tls_failure" in text
    assert "tls_reason=CERTIFICATE_VERIFY_FAILED" in text, text
    assert "verify_code=" in text, text
    # And the prose OpenSSL wrote is not repeated.
    assert "_ssl.c" not in text and "self-signed" not in text.lower(), text
    assert socket  # the import is load-bearing for the server above


def test_every_http_status_class_maps_to_a_distinguishable_reason():
    assert http_reason(401) == "http_unauthorized"
    assert http_reason(403) == "http_forbidden"
    assert http_reason(404) == "http_not_found"
    assert http_reason(429) == "http_rate_limited"
    assert http_reason(418) == "http_client_error"
    assert http_reason(503) == "http_server_error"
    # The four named codes are the ones with distinct operator responses:
    # rotate the credential, fix permissions, fix the path, back off.
    assert len({http_reason(s) for s in (401, 403, 404, 429)}) == 4
    assert http_reason(401) != http_reason(403) != http_reason(429)


def test_the_reason_code_set_is_small_enough_to_read_and_large_enough_to_triage():
    """A closed set nobody can read is a closed set nobody maintains."""

    assert 15 <= len(REASON_CODES) <= 40, sorted(REASON_CODES)
    assert LOCAL_REASONS <= REASON_CODES
