"""Endpoint validation: a credential never leaves over plaintext.

The remote provider sends ``Authorization: Bearer <key>`` to whatever
``api_base`` it was given. Given ``http://``, that header crosses the network in
the clear, readable by anything on the path — and nothing refused it. A single
typo in ``PROM_API_BASE`` published the production key to the network. This
module makes the refusal happen where it can still help: at configuration and
construction time, before a request exists.

Two properties, both enforced here rather than at each call site:

* **Remote endpoints must be ``https://``.** Not only credentialed ones. An
  unauthenticated ``http://`` provider lets a network adversary *answer* the
  judge — return ``PASS`` to everything — which is a different attack on the
  same trust, so the rule is one rule.
* **Loopback may opt out, loudly.** ``http://127.0.0.1:…`` for a local model
  gateway is a real development need. It is allowed only when the host is a
  loopback address AND ``allow_insecure_loopback`` is set, and it logs a WARNING
  at construction every time. It is never allowed for any other host — there is
  no opt-out for a remote plaintext endpoint at all.

Loopback is decided from the URL's literal host — an address in ``127/8`` or
``::1``, or the name ``localhost`` — and never by DNS resolution, since a
resolver is exactly what a network adversary can influence. The ``localhost``
literal trusts ``/etc/hosts``, which is the host's to keep honest (threat model
§2), not the network's.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from urllib.parse import SplitResult, urlsplit, urlunsplit

from prometheus_protocol.core.errors import ConfigError

_LOG = logging.getLogger(__name__)

#: The environment variable that enables the loopback-only plaintext opt-out.
INSECURE_LOOPBACK_ENV = "PROM_ALLOW_INSECURE_LOOPBACK"

_SECURE_SCHEMES = frozenset({"https"})
_PLAINTEXT_SCHEMES = frozenset({"http"})


#: P-2. A hostname failure can escape ``transport.py``'s error taxonomy — which
#: recognises ``HTTPError``, ``URLError``, timeouts, SSL errors, malformed
#: headers, ``HTTPException`` and ``OSError`` — and surface as a raw exception
#: instead of ``TransportError``, ``AnchorUnavailable``, ``SignerUnavailable`` or
#: ``AttestationUnavailable``. It fails CLOSED, by crashing, but a crash outside
#: the structured path can abort startup, attestation, reconciliation or an
#: operator command.
#:
#: WHERE IT ACTUALLY IS, corrected from the review that found it. The review
#: pointed at ``_deadline.resolve``'s ``json.dumps([host, port]).encode("ascii")``
#: raising ``UnicodeEncodeError`` on a Unicode hostname. Re-run, that line does
#: not raise: ``json.dumps`` defaults to ``ensure_ascii=True`` and escapes the
#: name. Nor does the DNS path leak one — ``_dns_worker.py`` runs ``getaddrinfo``
#: in a subprocess and catches ``(OSError, ValueError, TypeError)`` itself, so
#: the parent sees ``OSError("DNS lookup failed")``.
#:
#: The escape is at the **TLS** boundary. ``ssl.wrap_socket`` IDNA-encodes
#: ``server_hostname`` IN-PROCESS and raises ``UnicodeError`` — a ``ValueError``,
#: not an ``OSError`` — for a name the codec cannot encode, and
#: ``classify_open_error`` returns ``None`` for it. The triggering input need not
#: even be Unicode: an ASCII label over 63 bytes does it. Same hole, same
#: severity, one layer over from where it was reported.
#:
#: THE POLICY, applied ONCE here at construction rather than at each use:
#:
#: * a hostname is normalised to its **IDNA A-label** form (``münchen.example``
#:   becomes ``xn--mnchen-3ya.example``), which is ASCII and is what both
#:   ``getaddrinfo`` and certificate hostname verification actually compare;
#: * a name that IDNA cannot encode, and any ASCII name that is not a legal
#:   hostname, are REJECTED HERE with the reason, instead of becoming an
#:   unclassified exception at the first request;
#: * the encoder is the STANDARD LIBRARY's ``idna`` codec, deliberately, because
#:   it is the same in every environment this ships to. The third-party ``idna``
#:   package implements UTS-46 and would be better, but it is not in the pinned
#:   closure, and a normalisation that differs between a developer's machine and
#:   CI is worse than one that is limited and predictable.
#:
#: THE RESIDUAL, stated rather than discovered. The stdlib codec is IDNA 2003
#: with nameprep, not UTS-46/IDNA 2008. Two consequences, both real:
#:
#: * ``straße.example`` maps to ``strasse.example`` (transitional mapping),
#:   whereas UTS-46 non-transitional would give ``xn--strae-oqa.example``. Those
#:   are different names. A deployment that needs the IDNA 2008 reading of such
#:   a name must supply the A-label directly — which passes through unchanged;
#: * a handful of names that IDNA 2008 permits and IDNA 2003 does not are
#:   refused here. They are refused with a reason at construction, not crashed
#:   on at request time, which is the property P-2 is about.
#:
#: The normalised host is what the endpoint returns, so DNS and TLS agree by
#: construction: there is one host string, produced once. Catching
#: ``UnicodeEncodeError`` at the resolver and relabelling it would remove the raw
#: exception and still leave valid internationalized hostnames unusable, and
#: switching the resolver pipe to UTF-8 alone would leave ``getaddrinfo`` and
#: certificate verification disagreeing about which normalisation applies.
#: A legal hostname label once IDNA encoding has run. Underscore is permitted
#: because internal names use it and refusing it here would break deployments
#: for no security gain; whitespace, control characters and everything else are
#: refused.
_HOSTNAME_LABEL = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?")

_IDNA_MAX_LABEL = 63
_IDNA_MAX_NAME = 253


def normalize_host(host: str, *, name: str) -> str:
    """The IDNA A-label form of ``host``, or ``ConfigError`` with the reason.

    Returns ASCII, always: an IP literal and an already-ASCII name pass through
    unchanged (lowercased), and a Unicode name is encoded. Nothing downstream
    then has to decide which form it is holding.
    """

    if not isinstance(host, str) or not host:
        raise ConfigError(f"{name} has no host")
    # IP literals are not domain names and must not go through IDNA: ``::1``
    # has no labels, and ``encodings.idna`` would reject it.
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        return host.lower()

    if host.isascii():
        candidate = host.lower()
    else:
        try:
            candidate = host.encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError) as exc:
            raise ConfigError(
                f"{name} host {host!r} is not a usable internationalized "
                f"domain name ({exc}). It cannot be resolved and cannot be "
                "matched against a certificate, so it is refused here rather "
                "than raising an unclassified UnicodeEncodeError at the first "
                "request, outside the transport error taxonomy."
            ) from exc

    if not candidate.isascii():
        raise ConfigError(f"{name} host {host!r} did not normalize to ASCII")
    if len(candidate) > _IDNA_MAX_NAME:
        raise ConfigError(
            f"{name} host is {len(candidate)} bytes after IDNA encoding; the "
            f"maximum is {_IDNA_MAX_NAME}"
        )
    # Malformed ASCII names are refused HERE too. ``exa mple.com`` is ASCII, so
    # the encoder never sees it, and it would otherwise travel all the way to
    # getaddrinfo before failing.
    labels = candidate.rstrip(".").split(".")
    for label in labels:
        if not label:
            raise ConfigError(
                f"{name} host {host!r} has an empty label; it is not a "
                "resolvable hostname"
            )
        if len(label) > _IDNA_MAX_LABEL:
            raise ConfigError(
                f"{name} host has a {len(label)}-byte label after IDNA "
                f"encoding; the maximum is {_IDNA_MAX_LABEL}"
            )
        if not _HOSTNAME_LABEL.fullmatch(label):
            raise ConfigError(
                f"{name} host {host!r} contains {label!r}, which is not a legal "
                "hostname label (letters, digits, hyphen and underscore only)"
            )
    return candidate


def is_loopback_host(host: str | None) -> bool:
    """True for ``localhost``, any ``127.0.0.0/8`` address, or ``::1``.

    Decided from the literal only. Nothing here resolves a name.
    """

    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_endpoint(
    url: str, *, name: str, allow_insecure_loopback: bool = False
) -> str:
    """Return ``url`` if it may carry a credential, else raise ``ConfigError``.

    Rejected outright: a non-``http(s)`` scheme (``file://`` would read the
    local disk through the same client), a missing host, credentials embedded in
    the URL (they would be logged with it), and a query or fragment on what is
    supposed to be a base. ``http://`` is rejected for every host except a
    loopback literal with the opt-out set, and that case is logged.
    """

    if not isinstance(url, str) or not url.strip():
        raise ConfigError(f"{name} must be a non-empty URL")
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()

    if scheme not in _SECURE_SCHEMES | _PLAINTEXT_SCHEMES:
        raise ConfigError(
            f"{name} must use https:// (got scheme {parts.scheme!r} in {url!r})"
        )
    if not parts.hostname:
        raise ConfigError(f"{name} has no host: {url!r}")
    # P-2 — normalize ONCE, here. Everything downstream (DNS, TLS) uses the
    # value this function returns, so the two cannot disagree about which form
    # of the name they are checking.
    host = normalize_host(parts.hostname, name=name)
    if parts.username is not None or parts.password is not None:
        raise ConfigError(
            f"{name} must not embed credentials in the URL; they would be "
            "written to logs alongside it"
        )
    if parts.query or parts.fragment:
        raise ConfigError(f"{name} must be a base URL without a query or fragment")

    if scheme in _PLAINTEXT_SCHEMES:
        if not is_loopback_host(host):
            raise ConfigError(
                f"{name} is http:// to a remote host ({host}); a "
                "credential sent there crosses the network in cleartext. Use "
                "https://. There is no opt-out for a remote plaintext endpoint."
            )
        if not allow_insecure_loopback:
            raise ConfigError(
                f"{name} is http:// to loopback; set {INSECURE_LOOPBACK_ENV}=1 "
                "to allow plaintext to a local gateway (development only)"
            )
        _LOG.warning(
            "%s uses PLAINTEXT http:// to loopback host %s — credentials to this "
            "endpoint are not encrypted in transit. Allowed only because %s is "
            "set; never use this for a remote host.",
            name, host, INSECURE_LOOPBACK_ENV,
        )
    return _with_host(parts, host)


def _with_host(parts: SplitResult, host: str) -> str:
    """Rebuild the base URL carrying the NORMALIZED host.

    Returning the operator's original string would leave a Unicode hostname in
    the value every caller goes on to use, which is the whole of P-2: the
    normalisation has to be the thing that is handed on, not a check performed
    beside it. Userinfo, query and fragment are already refused above, so the
    reconstruction is scheme, authority and path only.
    """

    authority = f"[{host}]" if ":" in host else host
    if parts.port is not None:
        authority = f"{authority}:{parts.port}"
    return urlunsplit((parts.scheme.lower(), authority, parts.path, "", ""))
