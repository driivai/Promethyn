"""Where the ledger tip is anchored — parsed once, refused early.

``PROM_LEDGER_ANCHOR`` names the target the audit chain's tip is written to
after every append (``docs/ledger-integrity.md``). Three forms:

``file:///absolute/path/tip.json``
    One mutable file, rewritten in place. **Non-protecting.** It keeps no
    history and refuses nothing: whoever can rewrite the ledger can rewrite it
    in the same breath. Development only; the runtime warns when it is used.

``worm:///absolute/directory``
    One immutable record per anchored tip, created and never overwritten or
    deleted by this code, in a directory. Protecting exactly when the directory
    is a write-once medium (a WORM volume or an object-locked bucket mounted
    with retention in force); on an ordinary filesystem it is as rewritable as
    the ledger.

``https://host/path``
    A remote append-only log the ledger host can only append to. Protecting
    exactly when the log is run by a party the ledger-host adversary is not —
    another account, another team, a transparency log. Plaintext is refused to
    any host but loopback, and to loopback only with the same opt-out as every
    other credentialed endpoint (``core/endpoint.py``).

The parse lives in ``core`` rather than ``ledger`` so :class:`Config` can refuse
a malformed or incoherent value at load, before a ledger exists; the ledger
package builds the target from the parsed spec.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from prometheus_protocol.core.endpoint import validate_endpoint
from prometheus_protocol.core.errors import ConfigError

ANCHOR_FILE = "file"
ANCHOR_WORM = "worm"
ANCHOR_LOG = "log"

_LOCAL_SCHEMES = {ANCHOR_FILE: ANCHOR_FILE, ANCHOR_WORM: ANCHOR_WORM}
_REMOTE_SCHEMES = frozenset({"https", "http"})


@dataclass(frozen=True)
class AnchorSpec:
    """A parsed anchor target: which kind, and the path or URL it points at."""

    kind: str
    target: str

    @property
    def append_only(self) -> bool:
        """Whether the target keeps every anchored tip as its own immutable
        record. The single-file target does not; it is the theatre case."""

        return self.kind != ANCHOR_FILE


def parse_anchor_spec(
    spec: str, *, name: str = "ledger_anchor", allow_insecure_loopback: bool = False
) -> AnchorSpec:
    """Parse ``spec`` or raise :class:`ConfigError` naming what is wrong.

    Local targets must be absolute paths. Remote targets go through the same
    endpoint rule as every credentialed URL: ``https://`` for a remote host,
    ``http://`` only to loopback and only with the opt-out.
    """

    if not isinstance(spec, str) or not spec.strip():
        raise ConfigError(f"{name} must be a non-empty file://, worm:// or https:// URL")
    text = spec.strip()
    parts = urlsplit(text)
    scheme = parts.scheme.lower()

    if scheme in _LOCAL_SCHEMES:
        if parts.netloc not in ("", "localhost"):
            raise ConfigError(
                f"{name}: {scheme}:// takes an absolute local path, not a host "
                f"(got {parts.netloc!r}); write {scheme}:///path"
            )
        if parts.query or parts.fragment:
            raise ConfigError(f"{name}: {scheme}:// takes a plain path, no query or fragment")
        path = unquote(parts.path)
        if not path.startswith("/") or path == "/":
            raise ConfigError(
                f"{name}: {scheme}:// needs an absolute path (got {path!r}); "
                f"write {scheme}:///absolute/path"
            )
        return AnchorSpec(_LOCAL_SCHEMES[scheme], path)

    if scheme in _REMOTE_SCHEMES:
        validated = validate_endpoint(
            text, name=name, allow_insecure_loopback=allow_insecure_loopback
        )
        return AnchorSpec(ANCHOR_LOG, validated.rstrip("/"))

    raise ConfigError(
        f"{name} has unsupported scheme {parts.scheme!r}; expected file:///path "
        "(development, non-protecting), worm:///directory or https://host/path"
    )
