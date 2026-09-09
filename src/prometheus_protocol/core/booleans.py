"""One strict boolean parser for every security setting (F9, PROM-FIX-B).

Every boolean security setting in this repository used to be read by a
truth-set test — ``value.strip().lower() in {"1", "true", "yes", "on"}`` —
copied into seven modules and a dozen test files. That parser has two
fail-open shapes, both reproduced by the independent review:

* a *present but misspelled* value is silently ``False``:
  ``PROM_REQUIRE_VERIFIED_SUBSTRATE=tru`` withdrew nothing, and a CI gate
  flag with a typo turned "fail, do not skip" back into a silent skip;
* a *programmatic* value is coerced with ``bool()``:
  ``allow_unverified_substrate="false"`` enabled the opt-out, and the warning
  then called it "the explicit opt-out".

This module is the single parser, and the rules are:

* **Absent is distinct from present-and-invalid.** ``None`` (the variable is
  not set) takes the caller's default. A value that is set must be one of the
  enumerated true words or false words, after stripping surrounding
  whitespace and lowercasing; anything else — ``tru``, ``y``, ``t``,
  ``enabled``, an empty string — is a misconfiguration the operator must see,
  and is refused with :class:`ConfigError`. It is never read as ``False``.
* **Programmatic settings are actual booleans.** A ``str``, ``int`` or
  ``None`` where a boolean security field is expected is a :class:`ConfigError`,
  not a coercion.

A conformance test sweeps the source and test trees for the old truth-set
pattern so that a parser fixed at one site cannot reappear at another.
"""

from __future__ import annotations

from prometheus_protocol.core.errors import ConfigError

TRUE_WORDS: frozenset[str] = frozenset({"1", "true", "yes", "on"})
FALSE_WORDS: frozenset[str] = frozenset({"0", "false", "no", "off"})


def parse_env_bool(name: str, value: str | None, *, default: bool) -> bool:
    """Parse an environment variable's value strictly.

    ``value`` is the raw variable (``None`` when unset). Unset takes
    ``default``. Set must be one of ``1/true/yes/on`` or ``0/false/no/off``,
    case-insensitive with surrounding whitespace ignored; any other value is
    refused, never defaulted.
    """

    if type(default) is not bool:
        raise ConfigError(f"default for {name} must be a bool, got {type(default).__name__}")
    if value is None:
        return default
    if not isinstance(value, str):
        raise ConfigError(
            f"{name} must be read from the environment as a string, got "
            f"{type(value).__name__}"
        )
    word = value.strip().lower()
    if word in TRUE_WORDS:
        return True
    if word in FALSE_WORDS:
        return False
    raise ConfigError(
        f"{name}={value!r} is not a boolean: set one of "
        f"{'/'.join(sorted(TRUE_WORDS))} or {'/'.join(sorted(FALSE_WORDS))}, "
        f"or unset it to take the default ({default}). A value this setting "
        "does not recognise is refused, not read as false."
    )


def require_bool(value: object, *, name: str) -> bool:
    """A programmatic boolean setting must be an actual ``bool``.

    ``"false"`` is a non-empty string and therefore truthy; ``0`` and ``None``
    are falsy. None of them is a boolean security setting, so all of them are
    refused rather than coerced.
    """

    if type(value) is not bool:
        raise ConfigError(
            f"{name} must be True or False, got {type(value).__name__} {value!r}; "
            "a string, number or None is refused rather than coerced"
        )
    return value
