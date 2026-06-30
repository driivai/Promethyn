"""Select the sandbox adapter, honouring the mandatory-isolation guarantee.

The default (``auto``) picks the best *functioning* isolating adapter and never
the unsafe runner. The unsafe runner is reachable only with an explicit
``PROM_ALLOW_UNSAFE_EXEC=1`` opt-in. When nothing isolating is available and
unsafe was not opted into, a :class:`NullSandbox` is returned so the default
path refuses to run untrusted code unsandboxed (it ABSTAINs) rather than running
it in the clear.
"""

from __future__ import annotations

import logging
import os
from typing import Mapping

from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.sandbox.base import Sandbox
from prometheus_protocol.sandbox.container import ContainerSandbox
from prometheus_protocol.sandbox.namespace import NamespaceSandbox
from prometheus_protocol.sandbox.unsafe import NullSandbox, UnsafeLocalSandbox

_LOG = logging.getLogger(__name__)

SANDBOX_AUTO = "auto"
_ISOLATING = {
    NamespaceSandbox.name: NamespaceSandbox,
    ContainerSandbox.name: ContainerSandbox,
}


def unsafe_exec_allowed(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return (env.get("PROM_ALLOW_UNSAFE_EXEC", "") or "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def build_sandbox(
    name: str | None = None, *, env: Mapping[str, str] | None = None
) -> Sandbox:
    """Build the configured sandbox. ``name`` defaults to ``PROM_SANDBOX``/auto."""

    env = os.environ if env is None else env
    name = (name or env.get("PROM_SANDBOX", SANDBOX_AUTO) or SANDBOX_AUTO).strip().lower()
    allow_unsafe = unsafe_exec_allowed(env)

    if name == UnsafeLocalSandbox.name:
        if not allow_unsafe:
            raise ConfigError(
                "the unsafe sandbox runs untrusted code without isolation and "
                "requires PROM_ALLOW_UNSAFE_EXEC=1 to select"
            )
        _LOG.warning("sandbox=unsafe selected explicitly (no isolation)")
        return UnsafeLocalSandbox()

    if name in _ISOLATING:
        return _ISOLATING[name]()

    if name != SANDBOX_AUTO:
        raise ConfigError(
            f"unknown sandbox {name!r}; expected one of "
            f"auto, {NamespaceSandbox.name}, {ContainerSandbox.name}, unsafe"
        )

    # auto: prefer a functioning isolating adapter; never silently unsafe.
    for adapter in (NamespaceSandbox, ContainerSandbox):
        if adapter.available():
            _LOG.info("sandbox=auto selected %s", adapter.name)
            return adapter()
    if allow_unsafe:
        _LOG.warning("no isolating runtime available; falling back to unsafe (opt-in)")
        return UnsafeLocalSandbox()
    _LOG.error("no isolating sandbox runtime available; candidate code will ABSTAIN")
    return NullSandbox()
