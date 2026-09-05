"""The transport adversary (threat model §4): every property proven against a
real socket, with the attack performed rather than described.

Promethyn opens exactly one kind of network connection — ``RemoteModelProvider``
posting to a chat-completions endpoint — and the proposer, the judge and the
swarm roles all go through it. So this file is the whole sweep. Each test stands
up a real local HTTP (or TLS) server that misbehaves in one specific way and
asserts what the provider does about it.

Four findings drove it, each measured on the pre-fix code:

* ``http://`` with an API key was accepted at construction, so a typo in
  ``PROM_API_BASE`` sent ``Authorization: Bearer <key>`` in cleartext;
* the bearer token was **re-sent to whatever origin a 302 pointed at** — so a
  scheme check on the configured URL alone would have closed nothing;
* a response bomb was read whole (262 MB, 525 MB peak) and escaped as a raw
  ``IncompleteRead``;
* a server dripping one byte at a time ran six times past the configured
  timeout, because ``timeout=`` bounds each read, not the exchange.

**Every negative has a positive control.** A working endpoint yields a verdict,
the self-signed certificate that the provider refuses is proven to be served
correctly by two clients that trust it, and the redirect server is proven to
have received the request it refused to follow.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
import tracemalloc
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from prometheus_protocol.core.config import Config
from prometheus_protocol.core.endpoint import INSECURE_LOOPBACK_ENV, validate_endpoint
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.core.models import (
    Case,
    Evidence,
    Judgment,
    Task,
    Tier,
    Unavailability,
    Unavailable,
    Verdict,
)
from prometheus_protocol.provider.remote import (
    ProviderError,
    ProviderHTTPError,
    ProviderMalformedResponse,
    ProviderRedirectRefused,
    ProviderResponseTooLarge,
    ProviderTimeout,
    ProviderTLSError,
    ProviderTransportError,
    RemoteModelProvider,
)
from prometheus_protocol.verifier import trust
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.model_judge import ModelJudgeVerifier

_REQUIRE = (os.environ.get("PROM_REQUIRE_SANDBOX", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}

KEY = "prom-attacker4-bearer-canary-77e1c0d3"
PASS_BODY = json.dumps({"choices": [{"message": {"content": "PASS"}}]}).encode()
TASK = Task(id="t/f", entry_point="f", prompt="implement f", split="train",
            cases=(Case(args=(1,), expected=2),))
ONE_MIB = 1024 * 1024


# ---------------------------------------------------------------------------
# A misbehaving endpoint, one behaviour per instance
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):  # keep pytest output clean
        pass

    def _drain(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)

    def _fixed(self, status: int, body: bytes, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _chunked_start(self, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

    def _chunk(self, data: bytes):
        self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
        self.wfile.flush()

    def do_POST(self):
        self._drain()
        server = self.server
        server.seen.append(dict(self.headers))
        mode = server.mode
        try:
            if mode == "ok":
                self._fixed(200, PASS_BODY)
            elif mode == "redirect":
                self.send_response(302)
                self.send_header(
                    "Location", f"http://127.0.0.1:{server.target}/chat/completions"
                )
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif mode == "bomb":
                self._chunked_start()
                block = b'"' + b"A" * 65536 + b'"'
                for _ in range(4000):  # ~256 MB if anyone keeps reading
                    self._chunk(block)
            elif mode == "declared_big":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(10**9))
                self.end_headers()
                self.wfile.write(b"{")
            elif mode == "padded":
                # A COMPLETE, valid answer saying PASS ... followed by padding that
                # takes the whole body past the ceiling. A reader that truncates
                # at the ceiling and parses would report a normal PASS.
                self._chunked_start()
                self._chunk(PASS_BODY)
                for _ in range(24):
                    self._chunk(b" " * 65536)  # 1.5 MiB of whitespace
                self.wfile.write(b"0\r\n\r\n")
            elif mode == "drip":
                self._chunked_start()
                for _ in range(16):  # 16 x 0.25s = 4s, every gap inside a 1s timeout
                    self._chunk(b"x")
                    time.sleep(0.25)
                self.wfile.write(b"0\r\n\r\n")
            elif mode == "hang":
                time.sleep(20)
            elif mode == "http500":
                self._fixed(500, b'{"error":"upstream exploded"}')
            elif mode == "http500_bomb":
                self._chunked_start(500)
                block = b"E" * 65536
                for _ in range(4000):
                    self._chunk(block)
            elif mode == "nonjson":
                self._fixed(200, b"<html>maintenance</html>", "text/html")
            elif mode == "badshape":
                self._fixed(200, b'{"unexpected": true}')
            elif mode == "notutf8":
                self._fixed(200, b"\xff\xfe\xfd")
            elif mode == "notobject":
                self._fixed(200, b"[1, 2, 3]")
            else:
                raise AssertionError(f"unknown mode {mode!r}")
        except (BrokenPipeError, ConnectionResetError):
            pass  # the client hung up on us, which for several modes is the point

    do_GET = do_POST  # urllib turns a redirected POST into a GET


class _Endpoint:
    def __init__(self, mode: str, *, target: int | None = None, tls_context=None):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.daemon_threads = True
        self.server.mode = mode
        self.server.target = target
        self.server.seen = []
        if tls_context is not None:
            self.server.socket = tls_context.wrap_socket(self.server.socket, server_side=True)
        self.scheme = "https" if tls_context is not None else "http"
        # A short poll interval so shutdown() below returns promptly.
        threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        ).start()

    @property
    def port(self) -> int:
        return self.server.server_port

    @property
    def base(self) -> str:
        return f"{self.scheme}://127.0.0.1:{self.port}"

    @property
    def seen(self) -> list:
        return self.server.seen

    def close(self):
        # shutdown() BEFORE server_close(): closing the listening socket under a
        # live serve_forever loop leaves that daemon thread polling a closed fd —
        # poll returns POLLNVAL at once, accept() raises, and the loop spins with
        # no wait, for the rest of the process. Fifty of those made every test
        # collected after this file run four times slower. Measured, not guessed.
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def endpoint():
    made: list[_Endpoint] = []

    def make(mode: str, **kw) -> _Endpoint:
        item = _Endpoint(mode, **kw)
        made.append(item)
        return item

    yield make
    for item in made:
        item.close()


def _provider(base: str, **overrides) -> RemoteModelProvider:
    kwargs = dict(api_base=base, model="m", api_key=KEY, timeout_s=5.0,
                  allow_insecure_loopback=True)
    kwargs.update(overrides)
    return RemoteModelProvider(**kwargs)


def _closed_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


# ===========================================================================
# 1. TLS is required wherever a credential could go
# ===========================================================================


def test_remote_plaintext_with_a_credential_is_refused_at_construction():
    with pytest.raises(ConfigError, match="cleartext"):
        RemoteModelProvider(api_base="http://api.example.invalid/v1", model="m", api_key=KEY)


def test_remote_plaintext_without_a_credential_is_refused_too():
    """An unauthenticated plaintext judge lets the network ANSWER the judge."""

    with pytest.raises(ConfigError):
        RemoteModelProvider(api_base="http://api.example.invalid/v1", model="m")


def test_the_loopback_opt_out_does_not_extend_to_a_remote_host():
    with pytest.raises(ConfigError, match="no opt-out for a remote"):
        RemoteModelProvider(
            api_base="http://api.example.invalid/v1", model="m", api_key=KEY,
            allow_insecure_loopback=True,
        )


def test_loopback_plaintext_is_refused_without_the_opt_out():
    with pytest.raises(ConfigError, match=INSECURE_LOOPBACK_ENV):
        RemoteModelProvider(api_base="http://127.0.0.1:8000", model="m", api_key=KEY)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "[::1]", "127.9.9.9"])
def test_loopback_plaintext_with_the_opt_out_is_allowed_and_logged(host, caplog):
    with caplog.at_level(logging.WARNING, logger="prometheus_protocol.core.endpoint"):
        provider = RemoteModelProvider(
            api_base=f"http://{host}:8000", model="m", api_key=KEY,
            allow_insecure_loopback=True,
        )
    assert provider.api_base.startswith("http://")
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "the plaintext opt-out was silent"
    assert "PLAINTEXT" in warnings[0].getMessage()
    assert INSECURE_LOOPBACK_ENV in warnings[0].getMessage()


def test_https_to_any_host_is_accepted_without_the_opt_out():
    RemoteModelProvider(api_base="https://api.example.invalid/v1", model="m", api_key=KEY)


@pytest.mark.parametrize(
    "url",
    ["file:///etc/passwd", "ftp://api.example.invalid/", "api.example.invalid/v1",
     "https:///v1", "https://user:secret@api.example.invalid/v1",
     "https://api.example.invalid/v1?key=abc", "https://api.example.invalid/v1#frag"],
)
def test_non_https_and_malformed_bases_are_refused(url):
    with pytest.raises(ConfigError):
        validate_endpoint(url, name="api_base")


def test_a_credential_embedded_in_the_url_is_refused_because_urls_are_logged():
    with pytest.raises(ConfigError, match="logs"):
        validate_endpoint("https://user:secret@api.example.invalid/v1", name="api_base")


# -- the same rule at Config load -------------------------------------------


@pytest.mark.parametrize("field", ["api_base", "judge_api_base"])
def test_config_refuses_a_remote_plaintext_endpoint(field):
    with pytest.raises(ConfigError):
        Config(**{field: "http://api.example.invalid/v1"})


def test_config_from_env_refuses_a_remote_plaintext_endpoint():
    with pytest.raises(ConfigError):
        Config.from_env({"PROM_API_BASE": "http://api.example.invalid/v1", "PROM_API_KEY": KEY})


def test_config_from_env_allows_loopback_only_with_the_opt_out():
    with pytest.raises(ConfigError):
        Config.from_env({"PROM_API_BASE": "http://127.0.0.1:8000"})
    config = Config.from_env(
        {"PROM_API_BASE": "http://127.0.0.1:8000", INSECURE_LOOPBACK_ENV: "1"}
    )
    assert config.allow_insecure_loopback is True


def test_config_accepts_https_endpoints():
    Config(api_base="https://api.example.invalid/v1", judge_api_base="https://judge.example.invalid")


# -- certificates are verified, and redirects never carry the token ----------


def test_the_tls_context_verifies_certificates_and_hostnames():
    provider = RemoteModelProvider(api_base="https://api.example.invalid", model="m")
    assert provider._ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert provider._ssl_context.check_hostname is True


@pytest.fixture(scope="module")
def self_signed(tmp_path_factory) -> tuple[Path, Path]:
    """A certificate no trust store knows, valid for 127.0.0.1."""

    if shutil.which("openssl") is None:
        if _REQUIRE:
            pytest.fail("PROM_REQUIRE_SANDBOX=1 but openssl is unavailable for the TLS proof")
        pytest.skip("openssl unavailable")
    where = tmp_path_factory.mktemp("tls")
    key, cert = where / "key.pem", where / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(cert), "-days", "1", "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True, timeout=120,
    )
    return key, cert


def test_a_self_signed_certificate_is_refused(endpoint, self_signed):
    key, cert = self_signed
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(cert), str(key))
    tls = endpoint("ok", tls_context=server_context)

    # Positive controls FIRST: the server is real and serves the answer to a
    # client that skips verification, and to a client that trusts this cert.
    # Without these, "refused" could just mean the server was broken.
    lax = ssl.create_default_context()
    lax.check_hostname = False
    lax.verify_mode = ssl.CERT_NONE
    request = urllib.request.Request(
        tls.base + "/chat/completions", data=b"{}", method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5, context=lax) as response:
        assert json.loads(response.read())["choices"][0]["message"]["content"] == "PASS"
    trusting = ssl.create_default_context(cafile=str(cert))
    with urllib.request.urlopen(request, timeout=5, context=trusting) as response:
        assert response.status == 200

    # The provider, which trusts only the system store, refuses it — distinctly.
    provider = _provider(tls.base)
    with pytest.raises(ProviderTLSError):
        provider.assess(prompt="x")


def test_https_to_a_plaintext_server_is_a_tls_error_not_a_verdict(endpoint):
    plain = endpoint("ok")
    provider = _provider(f"https://127.0.0.1:{plain.port}")
    with pytest.raises(ProviderTLSError):
        provider.assess(prompt="x")


def test_a_redirect_is_refused_and_the_token_never_reaches_the_target(endpoint):
    """The finding a scheme check misses: urllib copies Authorization onto the
    redirected request. Measured on the pre-fix code, the token arrived at the
    redirect target. Now nothing arrives there at all."""

    target = endpoint("ok")
    hop = endpoint("redirect", target=target.port)
    provider = _provider(hop.base)

    with pytest.raises(ProviderRedirectRefused) as excinfo:
        provider.assess(prompt="x")

    assert hop.seen, "the request never reached the redirecting server (control)"
    assert target.seen == [], "a request — with or without the token — followed the redirect"
    assert KEY not in str(excinfo.value), "the message quoted the credential"
    assert "Location" not in str(excinfo.value)


def test_the_redirect_refusal_message_does_not_repeat_the_target_url(endpoint):
    target = endpoint("ok")
    hop = endpoint("redirect", target=target.port)
    with pytest.raises(ProviderRedirectRefused) as excinfo:
        _provider(hop.base).assess(prompt="x")
    # Origin only: an attacker-chosen Location must not be echoed with its path.
    assert "/chat/completions" not in str(excinfo.value)


# ===========================================================================
# 2. Every body is read under a ceiling and a total deadline
# ===========================================================================


def test_a_response_bomb_is_refused_at_the_ceiling_with_bounded_memory(endpoint):
    bomb = endpoint("bomb")
    provider = _provider(bomb.base, max_response_bytes=ONE_MIB)
    tracemalloc.start()
    try:
        with pytest.raises(ProviderResponseTooLarge):
            provider.assess(prompt="x")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    # The pre-fix read peaked at ~525 MB. The bound is the ceiling plus one chunk
    # plus interpreter noise; 32 MB is generous and still an order of magnitude
    # below what an unbounded read reached in the first three seconds.
    assert peak < 32 * ONE_MIB, f"peak memory {peak / ONE_MIB:.0f} MB — the read is not bounded"


def test_a_declared_oversize_body_is_refused_before_a_byte_is_read(endpoint):
    big = endpoint("declared_big")
    with pytest.raises(ProviderResponseTooLarge, match="declared"):
        _provider(big.base, max_response_bytes=ONE_MIB).assess(prompt="x")


def test_an_oversized_body_is_never_parsed_as_if_it_were_complete(endpoint):
    """The void guard, made concrete. The first bytes are a complete, valid
    answer saying PASS; the rest is padding past the ceiling. A reader that
    truncated at the ceiling and parsed would return PASS and nobody would know
    the response was not what the endpoint sent."""

    padded = endpoint("padded")
    provider = _provider(padded.base, max_response_bytes=ONE_MIB)

    # Premise: the truncated prefix really does parse as a normal PASS.
    prefix = PASS_BODY + b" " * (ONE_MIB - len(PASS_BODY))
    assert json.loads(prefix)["choices"][0]["message"]["content"] == "PASS"

    with pytest.raises(ProviderResponseTooLarge):
        provider.assess(prompt="x")


def test_a_slow_drip_is_bounded_by_the_total_deadline(endpoint):
    """Pre-fix: a byte every 0.5s ran 6s against ``timeout_s=1``, because the
    timeout applied to each read. The deadline is on the whole exchange."""

    drip = endpoint("drip")
    provider = _provider(drip.base, timeout_s=1.0)
    started = time.monotonic()
    with pytest.raises(ProviderTimeout):
        provider.assess(prompt="x")
    elapsed = time.monotonic() - started
    assert elapsed < 2.5, f"the drip held the reader for {elapsed:.1f}s against a 1s deadline"


def test_a_server_that_never_answers_times_out_distinctly(endpoint):
    hang = endpoint("hang")
    provider = _provider(hang.base, timeout_s=1.0)
    started = time.monotonic()
    with pytest.raises(ProviderTimeout):
        provider.assess(prompt="x")
    assert time.monotonic() - started < 2.5


def test_an_error_body_is_read_under_the_same_bounds(endpoint):
    """Fix the class: the quoted body of an HTTP error was read whole too."""

    bomb = endpoint("http500_bomb")
    provider = _provider(bomb.base)
    tracemalloc.start()
    try:
        with pytest.raises(ProviderHTTPError) as excinfo:
            provider.assess(prompt="x")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert excinfo.value.status == 500
    assert peak < 32 * ONE_MIB


def test_the_ceiling_is_validated_like_every_other_numeric_setting():
    for bad in (0, -1, 512, 1 << 31):
        with pytest.raises((ValueError, TypeError)):
            RemoteModelProvider(api_base="https://x", model="m", max_response_bytes=bad)
    for bad in (float("nan"), float("inf"), 0.0, -1.0):
        with pytest.raises((ValueError, TypeError)):
            RemoteModelProvider(api_base="https://x", model="m", timeout_s=bad)


# ===========================================================================
# 3. Transport failures are distinct, and never a verdict
# ===========================================================================


_FAILURES = [
    ("http500", ProviderHTTPError),
    ("nonjson", ProviderMalformedResponse),
    ("badshape", ProviderMalformedResponse),
    ("notutf8", ProviderMalformedResponse),
    ("notobject", ProviderMalformedResponse),
    ("bomb", ProviderResponseTooLarge),
    ("declared_big", ProviderResponseTooLarge),
    ("hang", ProviderTimeout),
    ("drip", ProviderTimeout),
]


@pytest.mark.parametrize("mode,expected", _FAILURES, ids=[m for m, _ in _FAILURES])
def test_each_failure_is_its_own_provider_error(endpoint, mode, expected):
    bad = endpoint(mode)
    provider = _provider(bad.base, timeout_s=1.0, max_response_bytes=ONE_MIB)
    with pytest.raises(expected) as excinfo:
        provider.assess(prompt="x")
    assert isinstance(excinfo.value, ProviderError), "every failure is a ProviderError"


def test_connection_refused_is_a_transport_error():
    provider = _provider(f"http://127.0.0.1:{_closed_port()}")
    with pytest.raises(ProviderTransportError):
        provider.assess(prompt="x")


def test_no_raw_socket_or_http_client_exception_escapes(endpoint):
    """Pre-fix the bomb escaped as ``http.client.IncompleteRead``. Nothing that
    is not a ProviderError may leave ``_post``."""

    import http.client

    for mode in ("bomb", "drip", "hang", "notutf8"):
        bad = endpoint(mode)
        try:
            _provider(bad.base, timeout_s=1.0, max_response_bytes=ONE_MIB).assess(prompt="x")
        except ProviderError:
            continue
        except (http.client.HTTPException, OSError, ValueError) as exc:
            pytest.fail(f"{mode}: a raw {type(exc).__name__} escaped the provider")
        pytest.fail(f"{mode}: the call returned instead of failing")


def test_the_error_classes_are_distinct():
    classes = [ProviderTransportError, ProviderTimeout, ProviderTLSError,
               ProviderRedirectRefused, ProviderResponseTooLarge, ProviderHTTPError,
               ProviderMalformedResponse]
    for cls in classes:
        assert issubclass(cls, ProviderError)
    leaves = [ProviderTimeout, ProviderTLSError, ProviderRedirectRefused,
              ProviderResponseTooLarge, ProviderHTTPError, ProviderMalformedResponse]
    for one in leaves:
        for other in leaves:
            if one is not other:
                assert not issubclass(one, other)


# -- through the judge: could-not-run, never an opinion -----------------------


def test_a_working_endpoint_still_yields_a_verdict(endpoint):
    """Positive control for everything below: the harness produces Evidence."""

    good = endpoint("ok")
    result = ModelJudgeVerifier(_provider(good.base)).verify(code="x", task=TASK)
    assert isinstance(result, Evidence)
    assert result.verdict == Verdict.PASS
    assert good.seen[0].get("Authorization") == f"Bearer {KEY}"


@pytest.mark.parametrize("mode", [m for m, _ in _FAILURES] + ["redirect_to_nowhere"])
def test_a_transport_failure_is_unavailable_not_a_verdict(endpoint, mode):
    if mode == "redirect_to_nowhere":
        bad = endpoint("redirect", target=_closed_port())
    else:
        bad = endpoint(mode)
    judge = ModelJudgeVerifier(_provider(bad.base, timeout_s=1.0, max_response_bytes=ONE_MIB))

    result = judge.verify(code="x", task=TASK)

    assert isinstance(result, Unavailable), f"{mode}: reported as {type(result).__name__}"
    assert result.reason == Unavailability.INFRA_FAULT
    assert result.tier == Tier.SOFT
    assert not hasattr(result, "verdict"), "an Unavailable must carry no verdict"
    assert "could not run" in result.detail


def test_a_transport_failure_never_becomes_pass_through_the_bank(endpoint):
    dead = endpoint("hang")
    judge = ModelJudgeVerifier(_provider(dead.base, timeout_s=1.0))
    unavailable = judge.verify(code="x", task=TASK)
    assert isinstance(unavailable, Unavailable)

    bank = VerifierBank()
    bank.register("subprocess-tests", Tier.HARD)
    bank.register(judge.verifier_id, Tier.SOFT)

    # Alone: nothing to go on. A non-authoritative abstention, never a PASS.
    alone = bank.judge([unavailable])
    assert isinstance(alone, Judgment)
    assert alone.verdict != Verdict.PASS
    assert alone.authoritative is False

    # Beside an authoritative PASS: the hard verdict decides, and the judge that
    # never ran contributes NO calibration sample — it did not abstain, it did
    # not run.
    hard = Evidence(passed=True, total=1, passed_count=1, verifier_id="subprocess-tests",
                    verdict=Verdict.PASS, tier=Tier.HARD)
    fused = bank.judge([hard, unavailable])
    assert isinstance(fused, Judgment) and fused.verdict == Verdict.PASS
    stats = bank._store.get(judge.verifier_id)
    assert stats is None or trust.sample_count(stats) == 0


def test_a_model_that_says_abstain_is_still_an_abstain(endpoint):
    """The distinction cuts both ways: a model that RAN and declined is an
    opinion (ABSTAIN), not a could-not-run."""

    good = endpoint("ok")
    provider = _provider(good.base)
    provider.assess = lambda *, prompt, system=None: "ABSTAIN"  # the model answered
    result = ModelJudgeVerifier(provider).verify(code="x", task=TASK)
    assert isinstance(result, Evidence)
    assert result.verdict == Verdict.ABSTAIN
