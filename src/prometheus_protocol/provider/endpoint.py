"""Re-export: the endpoint rule lives in ``core`` so ``Config`` can enforce it
without importing the provider package (which imports ``Config``)."""

from prometheus_protocol.core.endpoint import (  # noqa: F401
    INSECURE_LOOPBACK_ENV,
    is_loopback_host,
    validate_endpoint,
)

__all__ = ["INSECURE_LOOPBACK_ENV", "is_loopback_host", "validate_endpoint"]
