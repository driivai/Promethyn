"""Gate: promotion and action-authorization decisions, plus the firewall."""

from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import (
    FirewallError,
    GateDecision,
    PromotionGate,
    assert_disjoint,
)

__all__ = [
    "ActionGate",
    "FirewallError",
    "GateDecision",
    "PromotionGate",
    "assert_disjoint",
]
