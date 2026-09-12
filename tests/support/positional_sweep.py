"""The positional-construction sweep, as an instrument the tests can run.

The defect it looks for is the one measured in ``test_execution_descriptor.py``:
``Evidence(True, 1, 1, (), "runner", Verdict.PASS, tier=...)`` reads as though
``"runner"`` is the verifier id. It is not — it is ``stdout`` — because four
optional fields sit between. Nothing raises; the value lands somewhere plausible
and the mistake is invisible wherever the path refuses before the mis-set field
is read.

A field COUNT is the right threshold, not a name list: what makes the class of
bug possible is enough positional slots for one to be miscounted. ``Evidence``
and ``Judgment`` are now ``kw_only`` and cannot be constructed this way at all;
the classes that still can are recorded in ``docs/OPEN-GAPS.md`` and ratcheted
by ``tests/conformance/test_open_gaps.py`` so the count can fall and not rise.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib
import pathlib
import pkgutil

REPO = pathlib.Path(__file__).resolve().parents[2]
WIDE = 6  # fields; at or above this, positional construction is miscountable
ROOTS = ("src", "tests", "scripts", "harness")


def wide_dataclasses() -> dict[str, tuple[int, bool]]:
    """``{class name: (field count, kw_only)}`` for every dataclass of WIDE or
    more fields in the shipped package. Modules that cannot be imported here
    are skipped, and the caller decides whether that is acceptable."""

    import prometheus_protocol

    found: dict[str, tuple[int, bool]] = {}
    for module in pkgutil.walk_packages(
        prometheus_protocol.__path__, prefix="prometheus_protocol."
    ):
        try:
            loaded = importlib.import_module(module.name)
        except Exception:  # noqa: BLE001 - an unimportable module is skipped, counted by the caller
            continue
        for obj in vars(loaded).values():
            if isinstance(obj, type) and dataclasses.is_dataclass(obj):
                fields = dataclasses.fields(obj)
                if len(fields) >= WIDE:
                    # Per FIELD: ``__dataclass_params__`` does not carry
                    # ``kw_only`` on 3.10/3.11 (measured: AttributeError), but
                    # every ``Field`` does, and a class is keyword-only for
                    # construction when every init field is.
                    kw_only = all(f.kw_only for f in fields if f.init)
                    found[obj.__name__] = (len(fields), kw_only)
    return found


def positional_constructions(wide: dict[str, tuple[int, bool]]) -> dict[str, list[str]]:
    """``{class name: ["path:line", ...]}`` for every call of a wide dataclass
    that passes at least one positional argument, across the repo's own code."""

    hits: dict[str, list[str]] = {}
    for root in ROOTS:
        base = REPO / root
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = (
                    func.id
                    if isinstance(func, ast.Name)
                    else func.attr if isinstance(func, ast.Attribute) else None
                )
                if name in wide and node.args:
                    hits.setdefault(name, []).append(
                        f"{path.relative_to(REPO).as_posix()}:{node.lineno}"
                    )
    return hits
