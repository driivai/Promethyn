"""Scoped memory tiers.

Memory is organised into named *scopes* (for example ``"run"``, ``"cycle"``,
or a task id). Each scope is an independent key/value namespace. The interface
is intentionally small; the default implementation keeps everything in
process memory. Durable tiers (file- or database-backed) can implement the
same ``MemoryTier`` contract without changing callers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Iterator


class MemoryTier(ABC):
    """A scoped key/value store."""

    @abstractmethod
    def get(self, scope: str, key: str, default: Any = None) -> Any:
        raise NotImplementedError

    @abstractmethod
    def set(self, scope: str, key: str, value: Any) -> None:
        raise NotImplementedError

    @abstractmethod
    def items(self, scope: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def scopes(self) -> Iterator[str]:
        raise NotImplementedError

    @abstractmethod
    def clear(self, scope: str | None = None) -> None:
        raise NotImplementedError


class InMemoryTier(MemoryTier):
    """Minimal in-process implementation of :class:`MemoryTier`."""

    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}

    def get(self, scope: str, key: str, default: Any = None) -> Any:
        return self._store.get(scope, {}).get(key, default)

    def set(self, scope: str, key: str, value: Any) -> None:
        self._store.setdefault(scope, {})[key] = value

    def items(self, scope: str) -> dict[str, Any]:
        return dict(self._store.get(scope, {}))

    def scopes(self) -> Iterator[str]:
        return iter(tuple(self._store.keys()))

    def clear(self, scope: str | None = None) -> None:
        if scope is None:
            self._store.clear()
        else:
            self._store.pop(scope, None)
