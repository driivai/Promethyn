"""Domain error types raised at the runtime's I/O boundaries.

These are the typed, user-facing errors the runtime raises when an edge
operation cannot proceed (a misconfigured provider, an unreadable state file).
They exist so that callers — notably the CLI — can present a clean, actionable
message instead of a raw library traceback. Each error names the resource at
fault and, where useful, suggests a recovery; none of them carry secrets.

``ConfigError`` is also a :class:`ValueError` so that existing call sites that
already raise ``ValueError`` for bad configuration keep their type while gaining
a domain marker.
"""

from __future__ import annotations


class PrometheusError(Exception):
    """Base class for every domain error raised by the runtime."""


class StateError(PrometheusError):
    """A persistent state file could not be opened or is unusable.

    Raised when a SQLite-backed store (the experience ledger or the verifier
    trust store) cannot be opened — typically because the file is corrupt, is
    not a database, or is locked by another process. The message names the
    offending path and suggests removing or repairing it.
    """


class ConfigError(PrometheusError, ValueError):
    """The runtime was asked to start with invalid or missing configuration."""
