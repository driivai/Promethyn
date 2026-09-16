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


#: The closed set of reasons a configuration refusal can carry.
#:
#: WHY A TYPED REASON. Eight tests asserted these refusals with
#: ``pytest.raises(ConfigError, match="...")``. Measured 2026-09-14: stripping
#: every ``match=`` left all eight GREEN, so each proved only that SOME
#: ConfigError was raised — a reworded diagnostic would have converted eight
#: reason-assertions into existence-assertions and nothing would have said so
#: (``docs/OPEN-GAPS.md`` G19). This is the second time a message-keyed
#: assertion has been the weak link; the platform gate's repr matching was the
#: first, and the pinned-record ruling nearly closed on the same evidence.
#:
#: A closed set rather than free text: the point is that a test can name the
#: reason it expects and be wrong if a different one fires.
CONFIG_REFUSAL_REASONS: frozenset[str] = frozenset({
    "digest_pin_unhonourable",   # pinning asked of an adapter that runs no image
    "no_container_runtime",      # pinning asked, auto, nothing that can pin
    "unsafe_not_opted_in",       # the unsafe adapter without the explicit opt-in
    "unknown_sandbox",           # a sandbox name outside the known set
    "unsafe_with_remote",        # a non-isolating adapter beside a remote provider
    "deny_network_unhonourable", # network access asked of a non-isolating adapter
    "substrate_requirement_contradiction",  # require_verified + allow_unverified
    "bound_zero_is_not_unbounded",  # a 0/negative where unbounded must be named
    "unknown_unbounded_spelling",   # a bound that is neither positive nor named
    "reobservation_registry_discarded",  # a registry the supplied service would not use
    "reobservation_base_branch_unknown",   # a git principal with no reader and no base
    "reobservation_base_branch_conflict",  # a supplied reader and base that disagree
    "reobservation_base_branch_unusable",  # a base this tool would refuse to read
})


class ConfigError(PrometheusError, ValueError):
    """The runtime was asked to start with invalid or missing configuration.

    ``reason`` is optional and, when set, comes from
    :data:`CONFIG_REFUSAL_REASONS`. It is not required: most configuration
    refusals in this tree are unambiguous at their call site and adding a
    reason to every one of them would be ceremony. It exists so that a test
    asserting WHICH refusal fired can do so structurally.
    """

    def __init__(self, *args: object, reason: str | None = None) -> None:
        super().__init__(*args)
        if reason is not None and reason not in CONFIG_REFUSAL_REASONS:
            raise ValueError(
                f"{reason!r} is not a known configuration refusal reason; "
                f"add it to CONFIG_REFUSAL_REASONS deliberately. Known: "
                f"{sorted(CONFIG_REFUSAL_REASONS)}"
            )
        self.reason = reason
