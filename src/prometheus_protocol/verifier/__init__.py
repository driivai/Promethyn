"""Verification subsystem.

Beyond the sandboxed test-runner verifier, this package provides verifier-trust
ranking: a calibrated trust model, trust-weighted evidence fusion, and a bank
that fuses many verifiers' verdicts into one judgment and ranks verifiers by
trustworthiness.
"""

from prometheus_protocol.verifier.aggregate import fuse, p_pass, total_log_odds
from prometheus_protocol.verifier.bank import RankEntry, VerifierBank
from prometheus_protocol.verifier.runner import SubprocessVerifier
from prometheus_protocol.verifier.store import (
    InMemoryTrustStore,
    SqliteTrustStore,
    TrustStore,
)
from prometheus_protocol.verifier.trust import (
    TIER_PRIORS,
    TrustStats,
    log_lr,
    sample_count,
    updated,
    youden,
)

__all__ = [
    "SubprocessVerifier",
    "VerifierBank",
    "RankEntry",
    "TrustStore",
    "InMemoryTrustStore",
    "SqliteTrustStore",
    "TrustStats",
    "TIER_PRIORS",
    "fuse",
    "p_pass",
    "total_log_odds",
    "log_lr",
    "sample_count",
    "updated",
    "youden",
]
