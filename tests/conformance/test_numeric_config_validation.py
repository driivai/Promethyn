"""Numeric security settings are finite, ranged and correctly signed.

``float("nan")`` and ``float("inf")`` are ordinary Python values that ``float()``
returns for the strings ``"nan"`` and ``"inf"`` — so an environment variable can
carry either into a configuration object. Both then slide through the
comparisons a guard is written with, and switch it off without breaking it:

* ``timeout=inf`` never fires, so a bounded sandbox run becomes unbounded;
* ``confidence < nan`` is **always False**, so an escalation threshold of ``nan``
  leaves the human-review gate in place and permanently non-escalating;
* a negative TTL lands in the ``<= 0`` branch that means "expiry disabled";
* a negative size or process cap disables the cap it was meant to impose.

None of those raise. Each one reads as a working configuration and is a guard
that has quietly stopped guarding — this project's own definition of a void
guard, reachable by a typo in a deployment variable.

Every field is checked against every class of bad value, and — just as
importantly — against the boundary values that must still be **accepted**, so
the validation cannot be "fixed" by rejecting everything.
"""

from __future__ import annotations

import math

import pytest

from prometheus_protocol.core.config import Config
from prometheus_protocol.execution.pending import PendingActionService
from prometheus_protocol.sandbox.base import Limits
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.runner import SubprocessVerifier
from prometheus_protocol.verifier.sql import SqlVerifier

NAN = float("nan")
INF = float("inf")
NEG_INF = float("-inf")

# (field, value, why it is nonsense)
_REJECTED_LIMITS = [
    ("wall_time_s", NAN, "a NaN timeout never fires"),
    ("wall_time_s", INF, "an infinite timeout never fires"),
    ("wall_time_s", NEG_INF, "negative infinity is not a duration"),
    ("wall_time_s", -5.0, "a negative timeout is not a duration"),
    ("wall_time_s", 0.0, "a zero timeout bounds nothing"),
    ("cpu_time_s", -1, "a negative cpu cap disables the cap"),
    ("memory_bytes", -1, "a negative memory cap disables the cap"),
    ("max_processes", -3, "a negative process cap disables the cap"),
    ("max_output_bytes", 0, "capturing zero output is not a limit"),
    ("max_output_bytes", -1, "a negative output cap is meaningless"),
]

_REJECTED_CONFIG = [
    ("verifier_timeout_s", NAN, "a NaN verifier timeout never fires"),
    ("verifier_timeout_s", INF, "an infinite verifier timeout never fires"),
    ("verifier_timeout_s", -1.0, "a negative timeout is not a duration"),
    ("verifier_timeout_s", 0.0, "a zero timeout bounds nothing"),
    ("verifier_memory_mb", -1, "a negative memory cap disables the cap"),
    ("verifier_cpu_seconds", -1, "a negative cpu cap disables the cap"),
    ("verifier_max_processes", -1, "a negative process cap disables the cap"),
    ("gate_threshold", NAN, "every comparison against NaN is False"),
    ("gate_threshold", INF, "an infinite threshold passes nothing"),
    ("gate_threshold", 1.5, "a confidence threshold above 1 is a constant answer"),
    ("gate_threshold", -0.5, "a confidence threshold below 0 is a constant answer"),
    ("retrieval_k", -1, "a negative retrieval count is meaningless"),
    ("escalate_below", NAN, "NaN leaves the escalation gate permanently closed"),
    ("escalate_below", INF, "an infinite threshold escalates everything"),
    ("escalate_below", 5.0, "a threshold above 1 escalates everything"),
    ("escalate_below", -1.0, "a threshold below 0 escalates nothing"),
    ("pending_ttl_seconds", -1, "a negative TTL silently disables expiry"),
    ("max_role_calls", 0, "a swarm that may make no calls cannot run"),
    ("max_role_calls", -1, "a negative call budget is meaningless"),
    ("request_timeout_s", NAN, "a NaN request timeout never fires"),
    ("request_timeout_s", INF, "an infinite request timeout never fires"),
    ("request_timeout_s", 0.0, "a zero timeout bounds nothing"),
    ("judge_temperature", NAN, "NaN is not a sampling temperature"),
    ("judge_temperature", INF, "infinity is not a sampling temperature"),
    ("judge_temperature", -3.0, "a negative sampling temperature is meaningless"),
]


# ---------------------------------------------------------------------------
# Sandbox containment bounds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field,value,why", _REJECTED_LIMITS,
                         ids=[f"{f}={v}" for f, v, _ in _REJECTED_LIMITS])
def test_limits_rejects_nonsense(field, value, why):
    with pytest.raises((ValueError, TypeError)):
        Limits(**{field: value})


def test_limits_accepts_the_values_the_codebase_actually_uses():
    """The validation must not be satisfied by rejecting everything."""

    assert Limits().wall_time_s == 5.0
    Limits(wall_time_s=60, memory_bytes=0, cpu_time_s=50, max_processes=256)
    Limits(wall_time_s=20.0, cpu_time_s=10, memory_bytes=0, max_processes=32)
    Limits(wall_time_s=0.001)  # small but positive is a real choice


def test_limits_keeps_the_documented_zero_disables_readings():
    """``0`` means "no cap" for cpu/memory/processes in the adapters. That is
    existing documented behaviour and is deliberately preserved — only negatives,
    which reached the same branch by accident, are now refused."""

    limits = Limits(cpu_time_s=0, memory_bytes=0, max_processes=0)
    assert (limits.cpu_time_s, limits.memory_bytes, limits.max_processes) == (0, 0, 0)


def test_limits_rejects_a_bool_masquerading_as_a_number():
    with pytest.raises(TypeError):
        Limits(cpu_time_s=True)


# ---------------------------------------------------------------------------
# Deployment configuration
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field,value,why", _REJECTED_CONFIG,
                         ids=[f"{f}={v}" for f, v, _ in _REJECTED_CONFIG])
def test_config_rejects_nonsense(field, value, why):
    with pytest.raises((ValueError, TypeError)):
        Config(**{field: value})


def test_config_accepts_its_own_defaults_and_boundaries():
    Config()
    Config(escalate_below=0.0)
    Config(escalate_below=1.0)
    Config(gate_threshold=0.0)
    Config(gate_threshold=1.0)
    Config(judge_temperature=0.0)
    Config(judge_temperature=2.0)
    Config(pending_ttl_seconds=0)  # documented: disables expiry
    Config(retrieval_k=0)
    Config(max_role_calls=1)


@pytest.mark.parametrize(
    "variable,value",
    [("PROM_VERIFIER_TIMEOUT_S", "nan"), ("PROM_VERIFIER_TIMEOUT_S", "inf"),
     ("PROM_ESCALATE_BELOW", "nan"), ("PROM_ESCALATE_BELOW", "-1"),
     ("PROM_JUDGE_TEMPERATURE", "inf")],
)
def test_a_nonsense_environment_variable_is_refused_at_load(variable, value):
    """The realistic delivery path: a typo or a copied value in a deployment
    environment. ``float("nan")`` succeeds, so only validation catches it."""

    with pytest.raises((ValueError, TypeError)):
        Config.from_env({variable: value})


def test_from_env_still_loads_a_sane_environment():
    config = Config.from_env(
        {"PROM_VERIFIER_TIMEOUT_S": "12.5", "PROM_ESCALATE_BELOW": "0.5",
         "PROM_PENDING_TTL": "0"}
    )
    assert config.verifier_timeout_s == 12.5
    assert config.escalate_below == 0.5
    assert config.pending_ttl_seconds == 0


# ---------------------------------------------------------------------------
# The components that take numbers directly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [NAN, INF, 2.0, -1.0])
def test_verifier_bank_rejects_an_out_of_range_escalation_threshold(value):
    with pytest.raises((ValueError, TypeError)):
        VerifierBank(escalate_below=value)


@pytest.mark.parametrize("value", [0.0, 0.75, 1.0])
def test_verifier_bank_accepts_real_thresholds(value):
    assert VerifierBank(escalate_below=value).escalate_below == value


@pytest.mark.parametrize(
    "field,value",
    [("timeout_s", NAN), ("timeout_s", INF), ("timeout_s", 0.0), ("timeout_s", -1.0),
     ("memory_mb", -1), ("cpu_seconds", -1), ("max_processes", -1)],
)
def test_subprocess_verifier_rejects_nonsense(field, value):
    with pytest.raises((ValueError, TypeError)):
        SubprocessVerifier(**{field: value})


@pytest.mark.parametrize("value", [NAN, INF, 0.0, -1.0])
def test_sql_verifier_rejects_a_nonsense_timeout(value):
    with pytest.raises((ValueError, TypeError)):
        SqlVerifier(timeout_s=value)


@pytest.mark.parametrize("value", [-1, -86_400])
def test_pending_action_service_rejects_a_negative_ttl(value):
    with pytest.raises((ValueError, TypeError)):
        PendingActionService(ledger=None, ttl_seconds=value)


def test_pending_action_service_keeps_zero_as_disable():
    service = PendingActionService(ledger=None, ttl_seconds=0)
    assert service is not None


# ---------------------------------------------------------------------------
# The helpers themselves
# ---------------------------------------------------------------------------


def test_validation_never_silently_clamps():
    """Clamping would hide the misconfiguration the operator needs to see."""

    from prometheus_protocol.core.validation import require_unit_interval

    with pytest.raises(ValueError):
        require_unit_interval(1.5, name="threshold")
    assert require_unit_interval(0.5, name="threshold") == 0.5


def test_nan_really_does_defeat_an_unvalidated_comparison():
    """The premise, demonstrated rather than asserted: this is *why* the
    validation exists, and if NaN comparisons ever stopped behaving this way the
    reasoning above would need revisiting."""

    threshold = NAN
    assert (0.1 < threshold) is False
    assert (0.9 < threshold) is False
    assert math.isnan(threshold)
