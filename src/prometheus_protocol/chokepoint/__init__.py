"""The credential-brokered migration chokepoint.

A destructive migration becomes a real chokepoint: the agent lacks the authority
to run it, and a Promethyn-controlled runner exclusively holds it. See
``docs/chokepoint-threat-model.md``.
"""

from prometheus_protocol.chokepoint.approval import (
    Approval,
    ApprovalAuthority,
    ARTIFACT_MISMATCH,
    DEFAULT_TTL_SECONDS,
    EXPIRED,
    INVALID_SIGNATURE,
    MigrationArtifact,
    TARGET_MISMATCH,
    VerifyResult,
    artifact_hash,
)
from prometheus_protocol.chokepoint.runner import (
    REPLAY,
    BrokeredMigrationRunner,
    ConsumedApprovals,
    DbTarget,
    MigrationResult,
    psql_executor,
)

__all__ = [
    "Approval", "ApprovalAuthority", "MigrationArtifact", "VerifyResult",
    "artifact_hash", "DEFAULT_TTL_SECONDS",
    "INVALID_SIGNATURE", "ARTIFACT_MISMATCH", "TARGET_MISMATCH", "EXPIRED", "REPLAY",
    "BrokeredMigrationRunner", "ConsumedApprovals", "DbTarget", "MigrationResult",
    "psql_executor",
]
