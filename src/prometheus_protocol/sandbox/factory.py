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


_TRUE = {"1", "true", "yes", "on"}


def unsafe_exec_allowed(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return (env.get("PROM_ALLOW_UNSAFE_EXEC", "") or "").strip().lower() in _TRUE


def digest_pin_required(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return (env.get("PROM_REQUIRE_DIGEST_PIN", "") or "").strip().lower() in _TRUE


def build_sandbox(
    name: str | None = None,
    *,
    env: Mapping[str, str] | None = None,
    require_digest_pin: bool | None = None,
) -> Sandbox:
    """Build the configured sandbox, or REFUSE if a requirement cannot be met.

    ``name`` defaults to ``PROM_SANDBOX``/auto. ``require_digest_pin`` is the
    requirement from :class:`Config`; the environment (``PROM_REQUIRE_DIGEST_PIN``)
    is the other source. **A security requirement is the OR of its sources**:
    either can raise it, neither can lower the other. Before this the Config
    field was read by nothing at all — ``Config(require_digest_pin=True)`` built
    a container sandbox that reported ``False`` — a control present, plausible,
    and wired to nothing (threat model §5, E5-1).

    The principle this encodes, stated once: **a requested security property
    that cannot be honoured is refused, never degraded.** Digest pinning is a
    property of a container image. Asked for it with an adapter that runs no
    image (namespace, unsafe), or under ``auto`` with no container runtime to
    select, the only honest answer is a ``ConfigError`` at construction — not a
    sandbox that quietly lacks what was asked for.
    """

    env = os.environ if env is None else env
    name = (name or env.get("PROM_SANDBOX", SANDBOX_AUTO) or SANDBOX_AUTO).strip().lower()
    allow_unsafe = unsafe_exec_allowed(env)
    pin_required = bool(require_digest_pin) or digest_pin_required(env)

    if name == UnsafeLocalSandbox.name:
        if pin_required:
            raise ConfigError(
                "require_digest_pin is set, and the unsafe sandbox runs no image "
                "to pin: the requirement cannot be honoured, so it is refused "
                "rather than dropped. Select sandbox=container or withdraw it."
            )
        if not allow_unsafe:
            raise ConfigError(
                "the unsafe sandbox runs untrusted code without isolation and "
                "requires PROM_ALLOW_UNSAFE_EXEC=1 to select"
            )
        _LOG.warning("sandbox=unsafe selected explicitly (no isolation)")
        return UnsafeLocalSandbox()

    if name == ContainerSandbox.name:
        return ContainerSandbox(require_digest_pin=pin_required)

    if name == NamespaceSandbox.name:
        if pin_required:
            raise ConfigError(
                "require_digest_pin is set, and the namespace sandbox runs the "
                "host interpreter, not an image: the requirement cannot be "
                "honoured, so it is refused rather than dropped. Select "
                "sandbox=container or withdraw it."
            )
        return NamespaceSandbox()

    if name != SANDBOX_AUTO:
        raise ConfigError(
            f"unknown sandbox {name!r}; expected one of "
            f"auto, {NamespaceSandbox.name}, {ContainerSandbox.name}, unsafe"
        )

    if pin_required:
        # The requirement decides the adapter: only the container adapter can
        # honour it, so auto may not prefer namespace here, and may not fall
        # through to anything else if no container runtime is present.
        if ContainerSandbox.available():
            _LOG.info("sandbox=auto selected container (digest pinning required)")
            return ContainerSandbox(require_digest_pin=True)
        raise ConfigError(
            "require_digest_pin is set but no container runtime is available; "
            "refusing to fall back to an adapter that cannot honour it"
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
