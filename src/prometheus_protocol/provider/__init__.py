"""Provider boundary: the vendor-neutral seam where a model plugs in."""

from prometheus_protocol.provider.mock import MockProvider, MockSolution
from prometheus_protocol.provider.remote import ProviderError, RemoteModelProvider

__all__ = [
    "MockProvider",
    "MockSolution",
    "ProviderError",
    "RemoteModelProvider",
]
