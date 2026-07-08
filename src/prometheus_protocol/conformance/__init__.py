"""The verifier extension contract and its conformance suite.

Public surface for anyone extending Promethyn with a new domain verifier:

* :class:`VerifierCase` — describe your verifier.
* :func:`check_verifier` — mechanically check it against the contract.
* :func:`check_firewall_is_domain_general` — the held-out firewall guarantee.
* :func:`builtin_cases` — the three shipped verifiers, which pass unchanged.

See ``docs/extending-promethyn.md`` for the guide, and run the suite with
``python -m prometheus_protocol.conformance``.
"""

from __future__ import annotations

from prometheus_protocol.conformance.cases import (
    builtin_cases,
    code_case,
    grounding_case,
    sql_case,
)
from prometheus_protocol.conformance.contract import (
    AdversarialProbe,
    CheckResult,
    ConformanceReport,
    Example,
    VerifierCase,
    check_firewall_is_domain_general,
    check_verifier,
)

__all__ = [
    "VerifierCase",
    "Example",
    "AdversarialProbe",
    "CheckResult",
    "ConformanceReport",
    "check_verifier",
    "check_firewall_is_domain_general",
    "builtin_cases",
    "code_case",
    "sql_case",
    "grounding_case",
]
