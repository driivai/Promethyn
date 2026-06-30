"""Role synthesis: assemble a swarm with non-removable mandatory roles.

Optional roles may be selected per task. The ``Skeptic`` and
``PolicyReviewer`` are injected by the framework and cannot be removed by
config or by the swarm.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from prometheus_protocol.core.interfaces import Provider
from prometheus_protocol.swarm.models import Proposal, TaskPacket
from prometheus_protocol.swarm.roles import (
    PolicyReviewer,
    ProposerContext,
    Role,
    Skeptic,
    default_optional_roles,
)

# Modest default cap on provider calls per swarm task (mirrors Config default).
DEFAULT_MAX_ROLE_CALLS = 16


class _CallBudget:
    """A per-task counter of provider calls. ``limit <= 0`` means unlimited."""

    def __init__(self, limit: int = DEFAULT_MAX_ROLE_CALLS) -> None:
        self.limit = limit
        self.used = 0

    def reset(self) -> None:
        self.used = 0

    def take(self) -> bool:
        if self.limit > 0 and self.used >= self.limit:
            return False
        self.used += 1
        return True


class _BudgetedProvider(Provider):
    """Wraps a provider so every generation/proposal call draws on a budget.

    When the budget is exhausted the call returns an empty string, so the
    calling role simply produces no further proposal (graceful degradation) and
    a task can never make unbounded provider calls.
    """

    def __init__(self, inner: Provider, budget: _CallBudget) -> None:
        self._inner = inner
        self._budget = budget

    def propose_solution(self, *, prompt, entry_point, skills=()):
        if not self._budget.take():
            return ""
        return self._inner.propose_solution(
            prompt=prompt, entry_point=entry_point, skills=skills
        )

    def generate(self, *, prompt, system=None):
        if not self._budget.take():
            return ""
        return self._inner.generate(prompt=prompt, system=system)

    def assess(self, *, prompt, system=None):
        return self._inner.assess(prompt=prompt, system=system)


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
        provider: Provider | None = None,
        max_role_calls: int = DEFAULT_MAX_ROLE_CALLS,
        skeptic: Role | None = None,
        policy_reviewer: Role | None = None,
    ) -> None:
        # One budget shared by the engine's default roles, reset per task.
        self._budget = _CallBudget(max_role_calls)
        budgeted = (
            _BudgetedProvider(provider, self._budget) if provider is not None else None
        )
        self._optional = (
            list(optional_roles)
            if optional_roles is not None
            else default_optional_roles(budgeted)
        )
        self._skeptic = skeptic if skeptic is not None else Skeptic(budgeted)
        self._policy_reviewer = (
            policy_reviewer if policy_reviewer is not None else PolicyReviewer()
        )

    def assemble(self, packet: TaskPacket, config: SwarmConfig | None = None) -> Swarm:
        config = config or SwarmConfig()
        # Fresh per-task budget so a task cannot make unbounded provider calls.
        self._budget.reset()
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
