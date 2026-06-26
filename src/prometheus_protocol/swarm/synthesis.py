"""Role synthesis: assemble a swarm with non-removable mandatory roles.

Optional roles may be selected per task. The ``Skeptic`` and
``PolicyReviewer`` are injected by the framework and cannot be removed by
config or by the swarm.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from prometheus_protocol.swarm.models import Proposal, TaskPacket
from prometheus_protocol.swarm.roles import (
    PolicyReviewer,
    ProposerContext,
    Role,
    Skeptic,
    default_optional_roles,
)


@dataclass(frozen=True)
class SwarmConfig:
    """Per-task role configuration. Cannot disable mandatory roles."""

    enabled_optional_roles: tuple[str, ...] | None = None  # None = all optional
    disabled_roles: frozenset[str] = field(default_factory=frozenset)


class Swarm:
    """An assembled set of roles, with a fixed mandatory core."""

    def __init__(self, roles: Sequence[Role], mandatory_ids: frozenset[str]) -> None:
        self._roles = tuple(roles)
        self._mandatory_ids = frozenset(mandatory_ids)

    @property
    def roles(self) -> tuple[Role, ...]:
        return self._roles

    @property
    def mandatory_ids(self) -> frozenset[str]:
        return self._mandatory_ids

    def role_ids(self) -> tuple[str, ...]:
        return tuple(role.id for role in self._roles)

    def remove(self, role_id: str) -> "Swarm":
        if role_id in self._mandatory_ids:
            raise ValueError(
                f"role {role_id!r} is mandatory and cannot be removed"
            )
        return Swarm(
            [role for role in self._roles if role.id != role_id],
            self._mandatory_ids,
        )

    def propose(self, packet: TaskPacket) -> list[Proposal]:
        """Run optional roles first, then the mandatory roles with full context."""

        proposals: list[Proposal] = []

        def context() -> ProposerContext:
            return ProposerContext(packet=packet, proposals=tuple(proposals))

        for role in self._roles:
            if role.id in self._mandatory_ids:
                continue
            proposals.extend(role.propose(packet, context()))
        for role in self._roles:
            if role.id not in self._mandatory_ids:
                continue
            proposals.extend(role.propose(packet, context()))
        return proposals


class RoleSynthesisEngine:
    """Builds a :class:`Swarm`, always injecting the mandatory roles."""

    def __init__(
        self,
        optional_roles: Sequence[Role] | None = None,
        *,
        skeptic: Role | None = None,
        policy_reviewer: Role | None = None,
    ) -> None:
        self._optional = (
            list(optional_roles)
            if optional_roles is not None
            else default_optional_roles()
        )
        self._skeptic = skeptic if skeptic is not None else Skeptic()
        self._policy_reviewer = (
            policy_reviewer if policy_reviewer is not None else PolicyReviewer()
        )

    def assemble(self, packet: TaskPacket, config: SwarmConfig | None = None) -> Swarm:
        config = config or SwarmConfig()
        optional = [
            role
            for role in self._optional
            if (
                config.enabled_optional_roles is None
                or role.id in config.enabled_optional_roles
            )
            and role.id not in config.disabled_roles
        ]
        # The mandatory roles are appended unconditionally — config cannot omit
        # or forbid them.
        roles = optional + [self._skeptic, self._policy_reviewer]
        mandatory_ids = frozenset({self._skeptic.id, self._policy_reviewer.id})
        return Swarm(roles, mandatory_ids)
