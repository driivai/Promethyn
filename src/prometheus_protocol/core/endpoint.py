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
from urllib.parse import urlsplit

from prometheus_protocol.core.errors import ConfigError

_LOG = logging.getLogger(__name__)

#: The environment variable that enables the loopback-only plaintext opt-out.
INSECURE_LOOPBACK_ENV = "PROM_ALLOW_INSECURE_LOOPBACK"

_SECURE_SCHEMES = frozenset({"https"})
_PLAINTEXT_SCHEMES = frozenset({"http"})


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
    if parts.username is not None or parts.password is not None:
        raise ConfigError(
            f"{name} must not embed credentials in the URL; they would be "
            "written to logs alongside it"
        )
    if parts.query or parts.fragment:
        raise ConfigError(f"{name} must be a base URL without a query or fragment")

    if scheme in _PLAINTEXT_SCHEMES:
        if not is_loopback_host(parts.hostname):
            raise ConfigError(
                f"{name} is http:// to a remote host ({parts.hostname}); a "
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
            name, parts.hostname, INSECURE_LOOPBACK_ENV,
        )
    return url.strip()
