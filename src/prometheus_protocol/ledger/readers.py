"""Apply the authoritative-read boundary from the ledger's declared API.

There is no caller-name registry. A newly declared public method or property,
including one invoked through an alias, receives the same boundary.
Missing return annotations refuse class construction rather than silently
creating an unclassified public API. Private diagnostic sources and marked
writers are deliberate trust-boundary exceptions, not authoritative readers.
"""

from __future__ import annotations

import inspect
from functools import wraps
from typing import Any, Callable, TypeVar, get_type_hints

LedgerType = TypeVar("LedgerType", bound=type)


def writes_ledger(function: Callable[..., Any]) -> Callable[..., Any]:
    """An explicit mutation/resource-lifecycle API, not a source of evidence."""
    setattr(function, "__ledger_writer__", True)
    return function


def unverified_diagnostic(function: Callable[..., Any]) -> Callable[..., Any]:
    """An explicitly non-authoritative utility, verifier, or construction API."""
    setattr(function, "__ledger_diagnostic__", True)
    return function


def reader_methods(cls: type) -> tuple[str, ...]:
    """Derive readers from the public API; new scalar readers are covered too."""
    readers = []
    for name in dir(cls):
        if name.startswith("_"):
            continue
        descriptor = inspect.getattr_static(cls, name)
        if isinstance(descriptor, property):
            function = descriptor.fget
        elif isinstance(descriptor, (classmethod, staticmethod)):
            function = descriptor.__func__
        else:
            function = descriptor
        if getattr(function, "__ledger_writer__", False) or getattr(function, "__ledger_diagnostic__", False):
            continue
        if not inspect.isfunction(function):
            # A wrapper/descriptor is not a passive class constant. Silently
            # ignoring cached_property, lru_cache, or another callable here
            # would create an unguarded reader. Refuse unsupported shapes;
            # do not assume that their eventual result was read eagerly.
            if (
                isinstance(descriptor, (property, classmethod, staticmethod))
                or callable(descriptor)
                or hasattr(type(descriptor), "__get__")
            ):
                raise TypeError(f"unsupported public ledger reader shape: {cls.__name__}.{name}")
            continue
        annotations = get_type_hints(function)
        if "return" not in annotations:
            raise TypeError(f"unclassified public ledger API: {cls.__name__}.{name}")
        if isinstance(descriptor, (classmethod, staticmethod)) or inspect.isgeneratorfunction(function) or inspect.iscoroutinefunction(function):
            raise TypeError(f"unsupported deferred/static ledger reader: {cls.__name__}.{name}")
        readers.append(name)
    return tuple(readers)


def _wrap_reader(function: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(function)
    def checked(self: Any, *args: Any, **kwargs: Any) -> Any:
        return self._authoritative_read(function, args, kwargs)
    setattr(checked, "__authoritative_reader__", True)
    return checked


def guard_readers(cls: LedgerType) -> LedgerType:
    """Install guards on the derived population, including future subclass APIs."""
    for name in reader_methods(cls):
        descriptor = inspect.getattr_static(cls, name)
        if isinstance(descriptor, property):
            function = descriptor.fget
        else:
            function = descriptor
        if function is None:
            raise TypeError(f"ledger reader has no getter: {cls.__name__}.{name}")
        if getattr(function, "__authoritative_reader__", False):
            continue
        checked = _wrap_reader(function)
        if isinstance(descriptor, property):
            setattr(cls, name, property(checked, descriptor.fset, descriptor.fdel, descriptor.__doc__))
        else:
            setattr(cls, name, checked)
    return cls
