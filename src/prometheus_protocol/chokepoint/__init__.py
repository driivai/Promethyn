"""The credential-brokered migration chokepoint.

A destructive migration becomes a real chokepoint: the agent lacks the authority
to run it, and a Promethyn-controlled runner exclusively holds it. See
``docs/chokepoint-threat-model.md``.
"""

from prometheus_protocol.chokepoint.approval import (
    APPROVAL_VERSION,
    ARTIFACT_MISMATCH,
    DEFAULT_TTL_SECONDS,
    EXPIRED,
    INVALID_SIGNATURE,
    INVALID_TIME,
    TARGET_MISMATCH,
    Approval,
    ApprovalAuthority,
    MigrationArtifact,
    MigrationTarget,
    VerifyResult,
    artifact_hash,
)
from prometheus_protocol.chokepoint.runner import (
    AUDIT_OUTCOME_UNAVAILABLE,
    AUDIT_UNAVAILABLE,
    REPLAY,
    STORE_UNAVAILABLE,
    BrokeredMigrationRunner,
    ConsumedApprovals,
    DbTarget,
    MigrationResult,
    MigrationRunnerConfig,
    MigrationRuntime,
    build_migration_runner,
    build_migration_runtime,
    postgres_executor,
    psql_executor,
)

__all__ = [
    "APPROVAL_VERSION",
    "ARTIFACT_MISMATCH",
    "AUDIT_OUTCOME_UNAVAILABLE",
    "AUDIT_UNAVAILABLE",
    "DEFAULT_TTL_SECONDS",
    "EXPIRED",
    "INVALID_SIGNATURE",
    "INVALID_TIME",
    "REPLAY",
    "STORE_UNAVAILABLE",
    "TARGET_MISMATCH",
    "Approval",
    "ApprovalAuthority",
    "BrokeredMigrationRunner",
    "ConsumedApprovals",
    "DbTarget",
    "MigrationArtifact",
    "MigrationResult",
    "MigrationRunnerConfig",
    "MigrationRuntime",
    "MigrationTarget",
    "VerifyResult",
    "artifact_hash",
    "build_migration_runner",
    "build_migration_runtime",
    "postgres_executor",
    "psql_executor",
]
