"""Sandbox package: run untrusted code under isolation.

The :class:`Sandbox` port is the trusted-core safety boundary; the adapters are
swappable mechanisms. See ``docs/sandbox.md`` and the INV-SANDBOX conformance
tests.
"""

from __future__ import annotations

from prometheus_protocol.sandbox.base import Limits, Sandbox, SandboxResult
from prometheus_protocol.sandbox.container import ContainerSandbox
from prometheus_protocol.sandbox.factory import (
    SANDBOX_AUTO,
    build_sandbox,
    unsafe_exec_allowed,
)
from prometheus_protocol.sandbox.namespace import NamespaceSandbox
from prometheus_protocol.sandbox.unsafe import NullSandbox, UnsafeLocalSandbox

__all__ = [
    "Sandbox",
    "SandboxResult",
    "Limits",
    "NamespaceSandbox",
    "ContainerSandbox",
    "UnsafeLocalSandbox",
    "NullSandbox",
    "build_sandbox",
    "unsafe_exec_allowed",
    "SANDBOX_AUTO",
]
