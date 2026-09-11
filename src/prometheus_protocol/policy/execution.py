"""The one trusted seam between policy assessment and consequential execution.

An assessment describes the snapshot it was minted from.  This module proves
that snapshot is the one the deployment's *currently selected* policy resolves
for the concrete action about to run.  Recomputing the supplied snapshot would
only authenticate a self-consistent weakening; this seam deliberately resolves
the selected policy again.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import TYPE_CHECKING, Generic, Protocol, TypeVar

if TYPE_CHECKING:
    from prometheus_protocol.core.models import Judgment, Unavailable

from prometheus_protocol.core.models import (
    ACTION_GIT_DELETE_BRANCH,
    ACTION_PYTHON_CODE,
    ExecutableAction,
)
from prometheus_protocol.policy.assessment import PolicyAssessment, require_assessment
from prometheus_protocol.policy.profile import VerificationPolicy, policy_digest
from prometheus_protocol.policy.resolver import resolve
from prometheus_protocol.policy.snapshot import (
    ACTION_BRANCH_DELETE,
    ACTION_SANDBOX_EXECUTE,
    _identity,
    snapshot_digest,
)


class ExecutionNotAuthorized(ValueError):
    """The assessment is not bound to the selected policy and concrete action."""


class PolicySupplier(Protocol):
    """Trusted composition-root answer to “which policy is selected now?”"""

    def __call__(self) -> VerificationPolicy: ...


_ACTION_CLASS_FOR_KIND = {
    ACTION_PYTHON_CODE: ACTION_SANDBOX_EXECUTE,
    ACTION_GIT_DELETE_BRANCH: ACTION_BRANCH_DELETE,
}


@dataclass(frozen=True)
class ExecutionDescriptor:
    artifact_sha256: str
    action_class: str
    target_canonical: str
    policy_id: str
    policy_digest: str
    attempt_id: str

    def __post_init__(self) -> None:
        for name in (
            "artifact_sha256",
            "action_class",
            "target_canonical",
            "policy_id",
            "policy_digest",
            "attempt_id",
        ):
            object.__setattr__(self, name, _identity(getattr(self, name), what=name))


_AUTHORIZED = object()
ActionT = TypeVar("ActionT")


@dataclass(frozen=True)
class AuthorizedExecution(Generic[ActionT]):
    """A descriptor, assessment and concrete action validated by this seam."""

    descriptor: ExecutionDescriptor
    assessment: PolicyAssessment
    action: ActionT
    _validated: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._validated is not _AUTHORIZED:
            raise ExecutionNotAuthorized(
                "AuthorizedExecution values are minted only by ExecutionAuthorizer"
            )
        object.__setattr__(self, "_validated", None)


def action_class_of(action: ExecutableAction) -> str:
    if not isinstance(action, ExecutableAction):
        raise ExecutionNotAuthorized("execution requires an ExecutableAction")
    try:
        return _ACTION_CLASS_FOR_KIND[action.kind]
    except KeyError:
        raise ExecutionNotAuthorized(
            f"action kind {action.kind!r} has no trusted consequence class"
        ) from None


def artifact_digest_of(action: ExecutableAction) -> str:
    if not isinstance(action, ExecutableAction):
        raise ExecutionNotAuthorized("execution requires an ExecutableAction")
    return hashlib.sha256(action.code.encode("utf-8")).hexdigest()


class ExecutionAuthorizer:
    """Re-resolve the selected policy and bind an assessment to one action."""

    def __init__(self, supplier: PolicySupplier) -> None:
        self._supplier = supplier

    def authorize(
        self,
        assessment: PolicyAssessment,
        *,
        action: ExecutableAction,
        target_canonical: str,
        attempt_id: str,
    ) -> AuthorizedExecution[ExecutableAction]:
        return self.authorize_context(
            assessment,
            artifact_sha256=artifact_digest_of(action),
            action_class=action_class_of(action),
            target_canonical=target_canonical,
            attempt_id=attempt_id,
            action=action,
        )

    def authorize_context(
        self,
        assessment: PolicyAssessment,
        *,
        artifact_sha256: str,
        action_class: str,
        target_canonical: str,
        attempt_id: str,
        action: ActionT,
    ) -> AuthorizedExecution[ActionT]:
        """Authorize a non-``ExecutableAction`` consequence (currently migrations)."""

        assessment = require_assessment(
            assessment, surface="ExecutionAuthorizer.authorize"
        )
        policy = self._supplier()
        descriptor = ExecutionDescriptor(
            artifact_sha256=artifact_sha256,
            action_class=action_class,
            target_canonical=target_canonical,
            policy_id=policy.policy_id,
            policy_digest=policy_digest(policy),
            attempt_id=attempt_id,
        )
        # Re-resolve from the trusted policy value.  Do not reconstruct or
        # re-digest the caller's BoundRequirements snapshot.
        try:
            expected = resolve(
                policy,
                artifact_sha256=descriptor.artifact_sha256,
                target_canonical=descriptor.target_canonical,
                action_class=descriptor.action_class,
                attempt_id=descriptor.attempt_id,
            )
        except ValueError as exc:
            raise ExecutionNotAuthorized(
                "selected policy cannot authorize the execution descriptor"
            ) from exc
        if snapshot_digest(expected) != assessment.snapshot_digest:
            raise ExecutionNotAuthorized(
                "assessment does not cover the requirements re-resolved from the selected policy"
            )
        for name in (
            "artifact_sha256",
            "action_class",
            "target_canonical",
            "policy_id",
            "policy_digest",
            "attempt_id",
        ):
            if getattr(assessment, name) != getattr(descriptor, name):
                raise ExecutionNotAuthorized(
                    f"assessment {name} does not match execution descriptor"
                )
        return AuthorizedExecution(descriptor, assessment, action, _AUTHORIZED)

    def revalidate(
        self, authorization: AuthorizedExecution[ActionT]
    ) -> AuthorizedExecution[ActionT]:
        if not isinstance(authorization, AuthorizedExecution):
            raise ExecutionNotAuthorized("execution carries no validated descriptor")
        d = authorization.descriptor
        return self.authorize_context(
            authorization.assessment,
            artifact_sha256=d.artifact_sha256,
            action_class=d.action_class,
            action=authorization.action,
            target_canonical=d.target_canonical,
            attempt_id=d.attempt_id,
        )

    def restore_persisted(
        self,
        record: dict[str, str],
        *,
        outcome: "Judgment | Unavailable",
        action: ExecutableAction,
        target_canonical: str,
        attempt_id: str,
    ) -> AuthorizedExecution[ExecutableAction]:
        """Decode a hold only inside the seam and immediately re-authorize it."""

        from prometheus_protocol.policy.assessment import _restore_persisted

        assessment = _restore_persisted(
            snapshot_digest=record["snapshot_digest"],
            policy_id=record["policy_id"],
            policy_digest=record["policy_digest"],
            action_class=record["action_class"],
            attempt_id=record["attempt_id"],
            artifact_sha256=record["artifact_sha256"],
            target_canonical=record["target_canonical"],
            outcome=outcome,
        )
        return self.authorize(
            assessment,
            action=action,
            target_canonical=target_canonical,
            attempt_id=attempt_id,
        )


def profile_supplier(profile_id: str) -> PolicySupplier:
    """A non-caching supplier for a committed profile selected at a root."""

    from prometheus_protocol.policy.profile import load_profile

    _identity(profile_id, what="profile_id")
    return lambda: load_profile(profile_id)
