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

BOTH HALVES REFUSE RATHER THAN NARROW. See :class:`SweepIncomplete`.
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


class SweepIncomplete(RuntimeError):
    """The sweep could not measure its whole population.

    RAISED, NEVER SWALLOWED, and that is the entire point of this class. Both
    halves of this module used to continue past what they could not read — a
    bare ``except Exception: continue`` around the import, and an
    ``except SyntaxError: continue`` around the parse. Either one removes files
    from the measured population while the instrument goes on reporting the
    REMAINDER as though it were the whole, so a sweep that silently saw thirty
    of fifty modules returns a smaller answer and no warning. Combined with a
    floor assertion (``>= 40`` against a population of fifty), nine modules
    could vanish without anything going red.

    This is the fifth instance of the measurement-population class in this arc
    and the second inside a tool written to check other tools. The rule the
    others produced applies here too: an instrument that cannot see its whole
    subject must say so, not return a smaller number.
    """


def wide_dataclasses() -> dict[str, tuple[int, bool]]:
    """``{class name: (field count, kw_only)}`` for every dataclass of WIDE or
    more fields in the shipped package.

    Raises :class:`SweepIncomplete`, naming every module, if any module of the
    package cannot be imported. A narrowed population is not a result.
    """

    import prometheus_protocol

    found: dict[str, tuple[int, bool]] = {}
    unreadable: list[str] = []
    for module in pkgutil.walk_packages(
        prometheus_protocol.__path__, prefix="prometheus_protocol."
    ):
        try:
            loaded = importlib.import_module(module.name)
        except Exception as exc:  # noqa: BLE001 - recorded and refused below
            unreadable.append(f"{module.name}: {type(exc).__name__}: {exc}")
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
    if unreadable:
        raise SweepIncomplete(
            "the positional sweep could not import "
            f"{len(unreadable)} module(s), so its population is narrower than "
            "the package and its answer is not a measurement of it:\n  "
            + "\n  ".join(sorted(unreadable))
        )
    return found


def positional_constructions(wide: dict[str, tuple[int, bool]]) -> dict[str, list[str]]:
    """``{class name: ["path:line", ...]}`` for every call of a wide dataclass
    that passes at least one positional argument, across the repo's own code."""

    hits: dict[str, list[str]] = {}
    unreadable: list[str] = []
    for root in ROOTS:
        base = REPO / root
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeDecodeError, OSError) as exc:
                unreadable.append(f"{path.relative_to(REPO).as_posix()}: {exc}")
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
    if unreadable:
        raise SweepIncomplete(
            f"the positional sweep could not parse {len(unreadable)} file(s); a "
            "file it cannot read is a file whose positional constructions it "
            "cannot see, and reporting the rest would understate the count:\n  "
            + "\n  ".join(sorted(unreadable))
        )
    return hits
