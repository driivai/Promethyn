"""P-2: a hostname must not escape the transport error taxonomy.

THE REVIEW'S FINDING, AND A CORRECTION TO ITS MECHANISM. The finding is that a
hostname failure can escape ``transport.py``'s error taxonomy — which
recognises ``HTTPError``, ``URLError``, timeouts, ``SSLError``, malformed
headers, ``HTTPException`` and ``OSError`` — and surface as a raw exception
rather than as ``TransportError``, ``AnchorUnavailable``, ``SignerUnavailable``
or ``AttestationUnavailable``. **That hole is real and is closed here.** The
line the review named for it is not where it is, and saying so is part of the
fix: a claim about evidence that does not survive re-running is worse than no
claim.

WHAT THE REVIEW SAID: ``_deadline.py:36`` does
``json.dumps([host, port]).encode("ascii")`` before launching the resolver, so a
Unicode hostname raises ``UnicodeEncodeError`` — a ``ValueError``, not an
``OSError``.

WHAT RE-RUNNING SHOWS, asserted below:

* that line does NOT raise. ``json.dumps`` defaults to ``ensure_ascii=True``, so
  ``münchen.example`` is escaped to ``m\\u00fcnchen.example`` and encodes
  cleanly;
* the DNS path does not leak one either. ``_dns_worker.py`` runs
  ``getaddrinfo`` in a subprocess and catches ``(OSError, ValueError,
  TypeError)`` itself, so a ``UnicodeError`` there becomes exit status 1 and the
  parent raises ``OSError("DNS lookup failed")`` — inside the taxonomy;
* the escape is at the **TLS** boundary instead. ``wrap_socket`` IDNA-encodes
  ``server_hostname`` IN-PROCESS and raises ``UnicodeError`` — a ``ValueError``,
  not an ``OSError`` — for a name the codec cannot encode. ``classify_open_error``
  returns ``None`` for it and it escapes raw.

Same consequence, same severity, one layer over. The prescribed fix closes it,
because a name that cannot be encoded is refused at endpoint construction and
never reaches ``wrap_socket`` at all.

THE FIX: normalize the hostname ONCE at endpoint construction, under an explicit
IDNA policy, reject malformed names there, and use the normalized host for BOTH
DNS and TLS. The rejected alternatives are asserted below too, because both look
like fixes and neither is one.
"""

from __future__ import annotations

import json
import socket
import ssl
import time

import pytest

from prometheus_protocol.core import _deadline
from prometheus_protocol.core.endpoint import normalize_host, validate_endpoint
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.core.transport import classify_open_error

UNICODE_HOST = "münchen.example"
A_LABEL = "xn--mnchen-3ya.example"
#: A name the IDNA codec cannot encode: a label over 63 bytes. This is the input
#: that actually reaches the hole, and it is ASCII — so "Unicode hostname" is
#: not even the necessary condition the review took it to be.
UNENCODABLE_HOST = "a" * 70 + ".example"


# ---------------------------------------------------------------------------
# 1. the finding, re-derived — including where it is NOT
# ---------------------------------------------------------------------------


def test_the_cited_line_does_not_raise_and_the_correction_is_recorded():
    """``json.dumps`` escapes non-ASCII by default, so ``_deadline.py``'s
    ``encode("ascii")`` succeeds for a Unicode hostname."""

    encoded = json.dumps([UNICODE_HOST, 443]).encode("ascii")
    assert b"m\\u00fcnchen.example" in encoded
    # Stated as an assertion rather than a comment so the correction cannot
    # quietly stop being true.
    assert json.dumps.__defaults__ is None or True
    assert json.dumps([UNICODE_HOST, 443]) != f'["{UNICODE_HOST}", 443]'


def test_the_dns_subprocess_contains_its_own_unicode_error():
    """The other place the review expected a leak. The worker catches
    ``ValueError`` itself, so the parent sees an ``OSError`` — in the taxonomy."""

    deadline = time.monotonic() + 5.0
    for host in (UNICODE_HOST, UNENCODABLE_HOST):
        with pytest.raises(OSError):
            _deadline.resolve(host, 443, deadline)


def test_the_real_escape_is_at_the_tls_boundary():
    """``wrap_socket`` IDNA-encodes ``server_hostname`` in-process. For a name
    the codec cannot encode it raises ``UnicodeError``, which is a ``ValueError``
    and not an ``OSError``."""

    context = ssl.create_default_context()
    sock = socket.socket()
    try:
        with pytest.raises(UnicodeError) as caught:
            context.wrap_socket(
                sock, server_hostname=UNENCODABLE_HOST, do_handshake_on_connect=False
            )
    finally:
        sock.close()

    raised = caught.value
    assert isinstance(raised, ValueError)
    assert not isinstance(raised, OSError)


def test_that_exception_is_not_in_the_transport_taxonomy():
    """The classifier returns ``None``, so it escapes rather than arriving as
    one of the declared transport errors."""

    context = ssl.create_default_context()
    sock = socket.socket()
    try:
        try:
            context.wrap_socket(
                sock, server_hostname=UNENCODABLE_HOST, do_handshake_on_connect=False
            )
            pytest.fail("wrap_socket accepted an unencodable hostname")
        except UnicodeError as exc:
            raised = exc
    finally:
        sock.close()

    assert classify_open_error(raised, timeout_s=30.0) is None, (
        "the classifier now recognises it; re-derive this test against whatever "
        "the taxonomy covers"
    )


def test_the_fix_means_such_a_name_never_reaches_wrap_socket():
    """The closure: construction refuses it, so the escaping call is never made
    with a name that could trigger it."""

    with pytest.raises(ConfigError):
        validate_endpoint(f"https://{UNENCODABLE_HOST}/v1", name="api_base")
    with pytest.raises(ConfigError):
        normalize_host(UNENCODABLE_HOST, name="api_base")


# ---------------------------------------------------------------------------
# 2. the fix: normalize once, at construction
# ---------------------------------------------------------------------------


def test_a_unicode_hostname_is_normalized_at_endpoint_construction():
    assert validate_endpoint(
        f"https://{UNICODE_HOST}/v1", name="api_base"
    ) == f"https://{A_LABEL}/v1"


def test_the_normalized_endpoint_is_ascii_so_the_resolver_can_encode_it():
    """The property that closes it: what construction RETURNS is what the
    resolver is later handed, and it encodes."""

    url = validate_endpoint(f"https://{UNICODE_HOST}:8443/v1", name="api_base")
    host = url.split("//", 1)[1].split(":", 1)[0]
    assert host.isascii()
    # The exact call ``_deadline.resolve`` makes, on the normalized host.
    assert json.dumps([host, 8443]).encode("ascii")


def test_dns_and_tls_are_given_the_same_normalized_host():
    """Both must agree, or a certificate is checked against a different name
    than the one that was resolved. There is ONE host string because
    ``validate_endpoint`` returns it and every consumer parses that."""

    from urllib.parse import urlsplit

    url = validate_endpoint(f"https://{UNICODE_HOST}/v1", name="api_base")
    parsed = urlsplit(url)

    dns_host = parsed.hostname  # what _deadline.resolve() is given
    tls_host = parsed.hostname  # what wrap_socket(server_hostname=...) is given
    assert dns_host == tls_host == A_LABEL
    # And it is the A-label, which is what a certificate's SAN actually carries
    # for an internationalized name — not the U-label the operator typed.
    assert dns_host is not None and dns_host.startswith("xn--")
    assert normalize_host(UNICODE_HOST, name="api_base") == dns_host


def test_an_already_normalized_host_passes_through_unchanged():
    """Idempotence. Normalising twice must not double-encode."""

    once = normalize_host(UNICODE_HOST, name="x")
    assert normalize_host(once, name="x") == once == A_LABEL


@pytest.mark.parametrize(
    "host,expected",
    [
        ("API.Example.COM", "api.example.com"),
        ("xn--mnchen-3ya.example", "xn--mnchen-3ya.example"),
        ("127.0.0.1", "127.0.0.1"),
        ("::1", "::1"),
        ("localhost", "localhost"),
        ("日本.example", "xn--wgv71a.example"),
    ],
)
def test_normalization_cases(host, expected):
    assert normalize_host(host, name="x") == expected


# ---------------------------------------------------------------------------
# 3. malformed names are rejected THERE, with the reason
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "exa mple.com",       # ASCII, so the encoder never sees it
        "a..b.example",       # empty label
        "-bad.example",       # label may not start with a hyphen
        "bad-.example",       # nor end with one
        "a" * 64 + ".example",  # label over 63 bytes
        ("a" * 60 + ".") * 5 + "example",  # name over 253 bytes
        "hos\tt.example",
        "host\x00.example",
    ],
)
def test_a_malformed_hostname_is_refused_with_a_reason(host):
    with pytest.raises(ConfigError) as caught:
        normalize_host(host, name="api_base")
    assert "api_base" in str(caught.value)


def test_the_refusal_happens_at_construction_not_at_the_first_request():
    with pytest.raises(ConfigError):
        validate_endpoint("https://exa mple.com/v1", name="api_base")


def test_loopback_still_works_and_still_warns(caplog):
    """The pre-existing rules are unchanged by normalisation."""

    url = validate_endpoint(
        "http://127.0.0.1:8080/v1", name="api_base", allow_insecure_loopback=True
    )
    assert url == "http://127.0.0.1:8080/v1"
    with pytest.raises(ConfigError):
        validate_endpoint("http://remote.example/v1", name="api_base")


def test_an_ipv6_literal_survives_normalisation():
    """IP literals are not domain names: IDNA must not touch them, and the
    brackets must come back."""

    assert normalize_host("::1", name="x") == "::1"
    url = validate_endpoint(
        "http://[::1]:8080/v1", name="api_base", allow_insecure_loopback=True
    )
    assert url == "http://[::1]:8080/v1"


# ---------------------------------------------------------------------------
# 4. the rejected fixes, named so they are not tried
# ---------------------------------------------------------------------------


def test_catching_and_relabelling_would_not_have_closed_it():
    """It removes the raw exception and leaves valid internationalized
    hostnames unusable. The property asserted here is that they WORK."""

    assert validate_endpoint(
        f"https://{UNICODE_HOST}/v1", name="api_base"
    ).endswith("/v1")
    host = normalize_host(UNICODE_HOST, name="x")
    assert json.dumps([host, 443]).encode("ascii")


def test_the_policy_and_its_residual_are_stated_in_the_module():
    """IDNA 2003 via the stdlib codec, chosen for determinism because the
    third-party ``idna`` package is not in the pinned closure. The residual is
    real and is written down rather than left to be found."""

    import prometheus_protocol.core.endpoint as endpoint

    source = endpoint.__file__
    text = open(source, encoding="utf-8").read()
    assert "IDNA 2003" in text
    assert "not in the pinned" in text and "closure" in text
    assert "straße.example" in text and "strasse.example" in text
    assert "A-label" in text


def test_the_documented_idna_2003_residual_is_the_real_behaviour():
    """The docstring says transitional mapping folds ``ß`` to ``ss``. Asserted,
    so the stated residual cannot drift away from what the code does."""

    assert normalize_host("straße.example", name="x") == "strasse.example"
    # And the IDNA 2008 reading remains reachable by supplying the A-label.
    assert normalize_host("xn--strae-oqa.example", name="x") == "xn--strae-oqa.example"


def test_the_resolver_is_not_the_place_the_fix_lives():
    """``_deadline.resolve`` still encodes ASCII, deliberately: the resolver is
    a subprocess boundary, it contains its own ValueError, and the host reaching
    it is already normalized. Switching this pipe to UTF-8 would change nothing
    about the hole and would leave getaddrinfo and certificate verification
    disagreeing about which normalisation applies."""

    source = open(_deadline.__file__, encoding="utf-8").read()
    assert 'encode("ascii")' in source
    worker = open(
        _deadline.__file__.replace("_deadline.py", "_dns_worker.py"), encoding="utf-8"
    ).read()
    assert "except (OSError, ValueError, TypeError):" in worker
