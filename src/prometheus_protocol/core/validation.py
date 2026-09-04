"""Finite-range validation for security-relevant numeric configuration.

A float can be ``nan`` or ``inf``, and both slide straight through the ordinary
comparisons a guard is written with. That is not a curiosity — it is a way to
switch a check off while leaving it in place, which is precisely the failure this
project is named for:

* a timeout of ``inf`` never fires, so a bounded run becomes unbounded;
* a threshold of ``nan`` makes ``confidence < threshold`` **always False**, so an
  escalation gate silently never escalates — no error, no log, just a guard that
  has stopped guarding;
* a negative TTL hits a ``<= 0`` branch that means "disabled" and turns expiry
  off;
* a negative size or process cap disables the cap it was supposed to impose.

Every one of those reads as a working configuration. The values are therefore
rejected where they enter, at construction, rather than trusted to be sensible
at each of the places they are later compared.

Each helper returns the value so it can be used inline, and raises ``ValueError``
or ``TypeError`` — never silently clamps. Clamping would hide a misconfiguration
that the operator needs to see.
"""

from __future__ import annotations

import math

__all__ = [
    "require_finite",
    "require_positive",
    "require_non_negative",
    "require_range",
    "require_unit_interval",
    "require_int_in_range",
    "require_positive_int",
    "require_non_negative_int",
]


def _as_number(value: object, *, name: str) -> float:
    # bool is an int subclass; accepting True as 1 second would be a quiet
    # nonsense, so it is refused explicitly.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number, got {type(value).__name__}")
    return float(value)


def require_finite(value: object, *, name: str) -> float:
    """Reject NaN and infinities. The load-bearing one."""

    number = _as_number(value, name=name)
    if not math.isfinite(number):
        raise ValueError(
            f"{name} must be a finite number, got {number!r}: a non-finite "
            "value disables the comparison it is used in rather than failing"
        )
    return number


def require_positive(value: object, *, name: str) -> float:
    number = require_finite(value, name=name)
    if number <= 0:
        raise ValueError(f"{name} must be greater than zero, got {number!r}")
    return number


def require_non_negative(value: object, *, name: str) -> float:
    number = require_finite(value, name=name)
    if number < 0:
        raise ValueError(f"{name} must not be negative, got {number!r}")
    return number


def require_range(
    value: object, *, name: str, minimum: float, maximum: float
) -> float:
    """Finite and within an inclusive range."""

    number = require_finite(value, name=name)
    if not minimum <= number <= maximum:
        raise ValueError(
            f"{name} must be between {minimum} and {maximum} inclusive, got {number!r}"
        )
    return number


def require_unit_interval(value: object, *, name: str) -> float:
    """A probability or confidence threshold: finite and within ``[0, 1]``.

    A threshold outside that range is not a stricter or looser setting, it is a
    constant answer — ``2.0`` escalates everything, ``-1.0`` escalates nothing —
    and either way the value being compared stops mattering.
    """

    number = require_finite(value, name=name)
    if not 0.0 <= number <= 1.0:
        raise ValueError(f"{name} must be between 0.0 and 1.0 inclusive, got {number!r}")
    return number


def require_int_in_range(
    value: object, *, name: str, minimum: int, maximum: int | None = None
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer, got {type(value).__name__}")
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}, got {value!r}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be at most {maximum}, got {value!r}")
    return value


def require_positive_int(value: object, *, name: str, maximum: int | None = None) -> int:
    return require_int_in_range(value, name=name, minimum=1, maximum=maximum)


def require_non_negative_int(value: object, *, name: str, maximum: int | None = None) -> int:
    return require_int_in_range(value, name=name, minimum=0, maximum=maximum)
