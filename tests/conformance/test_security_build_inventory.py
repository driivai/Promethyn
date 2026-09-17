"""Derive the Config-bearing assembly inventory across the shipped package.

This is a discovery/classification guard, not a second runtime guard. Public
module functions accepting Config (including import/type aliases and renamed
parameters), MigrationRunnerConfig, or parameters named config/settings must
be guarded roots or explicitly partial components. Constructor spelling is
irrelevant to discovering those functions. Components returning a discovered
root's runtime class are refused, including simple aliases and assigned values.

Limits are deliberate: arbitrary unannotated parameters named otherwise,
methods/private functions, dynamic code and interprocedural return inference
are outside this static inventory. The actual build guard checks live objects;
this inventory does not claim to prove what arbitrary Python means.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import types
from pathlib import Path

import pytest

from prometheus_protocol.runtime.security_build import (
    component_builder,
    install_build_guards,
)

SRC = Path(__file__).resolve().parents[2] / "src" / "prometheus_protocol"
_CONFIG_TYPES = frozenset({
    "prometheus_protocol.core.config.Config",
    "prometheus_protocol.chokepoint.runner.MigrationRunnerConfig",
})


def _symbol(node: ast.AST | None, bindings: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return bindings.get(node.id)
    if isinstance(node, ast.Attribute):
        base = _symbol(node.value, bindings)
        return f"{base}.{node.attr}" if base else None
    return None


def _scoped_nodes(tree: ast.AST):
    """Do not let another function's imports overwrite this scope's bindings."""
    pending = [tree]
    while pending:
        node = pending.pop()
        yield node
        if node is not tree and isinstance(node, (
            ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda
        )):
            continue
        pending.extend(reversed(list(ast.iter_child_nodes(node))))


def _bindings(tree: ast.AST, module: str, initial=None) -> dict[str, str]:
    result = dict(initial or {})
    for node in _scoped_nodes(tree):
        if isinstance(node, ast.ImportFrom):
            imported = node.module or ""
            if node.level:
                imported = importlib.util.resolve_name(
                    "." * node.level + imported, module.rsplit(".", 1)[0]
                )
            for alias in node.names:
                result[alias.asname or alias.name] = f"{imported}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                result[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ClassDef):
            result[node.name] = f"{module}.{node.name}"
    # Resolve simple assignment aliases to a fixed point, not one source-order
    # pass. This is name binding only; branch feasibility is not claimed.
    aliases = [n for n in _scoped_nodes(tree) if isinstance(n, (ast.Assign, ast.AnnAssign))]
    for _ in range(len(aliases) + 1):
        changed = False
        for node in aliases:
            symbol = _symbol(node.value, result)
            if symbol:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and result.get(target.id) != symbol:
                        result[target.id] = symbol
                        changed = True
        if not changed:
            break
    return result


def _config_parameter(node: ast.arg, bindings: dict[str, str]) -> bool:
    if node.arg in {"config", "settings"}:
        return True
    annotation: ast.AST | None = node.annotation
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        annotation = ast.parse(annotation.value, mode="eval")
    return annotation is not None and any(
        _symbol(part, bindings) in _CONFIG_TYPES for part in ast.walk(annotation)
    )


def _config_functions(source: str, module: str):
    tree = ast.parse(source)
    bindings = _bindings(tree, module)
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name.startswith("_"):
            continue
        parameters = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        if any(_config_parameter(argument, bindings) for argument in parameters):
            yield node, _bindings(node, module, bindings)


def _return_products(node, bindings: dict[str, str]) -> set[str]:
    assigned: dict[str, str] = {}
    for part in ast.walk(node):
        if isinstance(part, (ast.Assign, ast.AnnAssign)) and isinstance(part.value, ast.Call):
            symbol = _symbol(part.value.func, bindings)
            if symbol:
                targets = part.targets if isinstance(part, ast.Assign) else [part.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        assigned[target.id] = symbol
    products: set[str] = set()
    for part in ast.walk(node):
        if not isinstance(part, ast.Return):
            continue
        symbol = None
        if isinstance(part.value, ast.Call):
            symbol = _symbol(part.value.func, bindings)
        elif isinstance(part.value, ast.Name):
            symbol = assigned.get(part.value.id)
        if symbol:
            products.add(symbol)
    return products


def _module_inventory(source: str, module: types.ModuleType, runtime_types: set[str]):
    problems = []
    for node, bindings in _config_functions(source, module.__name__):
        function = getattr(module, node.name, None)
        guarded = inspect.isfunction(function) and getattr(function, "_security_root", False)
        partial = inspect.isfunction(function) and getattr(function, "_security_component", False)
        location = f"{module.__name__}:{node.lineno}:{node.name}"
        if not (guarded or partial):
            problems.append(f"{location}: unclassified Config-bearing function")
        elif guarded and partial:
            problems.append(f"{location}: contradictory root/component classification")
        elif partial and _return_products(node, bindings) & runtime_types:
            problems.append(f"{location}: component returns a production runtime")
    return problems


def _package_inventory():
    sources = []
    runtime_types: set[str] = set()
    for path in sorted(SRC.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        relative = path.relative_to(SRC).with_suffix("")
        parts = relative.parts[:-1] if relative.name == "__init__" else relative.parts
        name = ".".join(("prometheus_protocol", *parts))
        candidates = list(_config_functions(source, name))
        if not candidates:
            continue
        module = importlib.import_module(name)
        sources.append((source, module))
        for node, bindings in candidates:
            function = getattr(module, node.name, None)
            if getattr(function, "_security_root", False):
                runtime_types.update(_return_products(node, bindings))
    return sources, runtime_types


def test_every_config_bearing_public_assembly_is_classified_across_the_package():
    sources, runtime_types = _package_inventory()
    assert sources and runtime_types, "an empty inventory proves nothing"
    problems = [
        problem for source, module in sources
        for problem in _module_inventory(source, module, runtime_types)
    ]
    assert problems == []


@pytest.mark.parametrize("annotation", [
    "from prometheus_protocol.core.config import Config as Cfg\n",
    "import prometheus_protocol.core.config as configuration\nCfg = configuration.Config\n",
    "from prometheus_protocol.core.config import Config\nCfg = Config\n",
    "from typing import TypeAlias\nfrom prometheus_protocol.core.config import Config\nCfg: TypeAlias = Config\n",
])
def test_renamed_config_parameter_and_type_aliases_are_discovered(annotation):
    source = annotation + "def assemble(options: Cfg | None = None):\n    return object()\n"
    assert [node.name for node, _ in _config_functions(source, "new_module")] == ["assemble"]


def test_unannotated_config_or_settings_parameter_still_requires_classification():
    source = "def one(config):\n    pass\ndef two(settings):\n    pass\n"
    assert [node.name for node, _ in _config_functions(source, "new_module")] == ["one", "two"]


def test_another_function_cannot_substitute_the_config_alias_binding():
    source = '''from prometheus_protocol.core.config import Config as Cfg
def assemble(options: Cfg):
    return object()
def unrelated():
    from pathlib import Path as Cfg
    return Cfg(".")
'''
    assert [node.name for node, _ in _config_functions(source, "new_module")] == ["assemble"]


_NEW_ROOT = '''from prometheus_protocol.core.config import Config as Cfg
from prometheus_protocol.execution.controller import ExecutionController as AliasedController
def assemble(options: Cfg):
    registry = None
    return AliasedController(gate=object(), executor=object(), ledger=object(), reobservation=registry)
'''


def test_new_module_with_aliased_constructor_cannot_omit_guard_installation():
    module = types.ModuleType("prometheus_protocol.new_unwired_root")
    exec(_NEW_ROOT, module.__dict__)
    problems = _module_inventory(_NEW_ROOT, module, set())
    assert len(problems) == 1
    assert "unclassified Config-bearing function" in problems[0]


def test_new_module_with_aliased_constructor_is_classified_when_guard_installed():
    module = types.ModuleType("prometheus_protocol.new_guarded_root")
    exec(_NEW_ROOT, module.__dict__)
    install_build_guards(module.__dict__)
    assert _module_inventory(_NEW_ROOT, module, set()) == []


@pytest.mark.parametrize("assigned", [False, True])
def test_component_annotation_cannot_hide_an_aliased_runtime_return(assigned):
    source = _NEW_ROOT.replace("def assemble", "@component_builder\ndef assemble")
    if assigned:
        source = source.replace("return AliasedController(", "runtime: AliasedController = AliasedController(")
        source += "    return runtime\n"
    module = types.ModuleType("prometheus_protocol.fake_component")
    module.component_builder = component_builder
    exec(source, module.__dict__)
    runtime_types = {"prometheus_protocol.execution.controller.ExecutionController"}
    problems = _module_inventory(source, module, runtime_types)
    assert len(problems) == 1
    assert "component returns a production runtime" in problems[0]


def test_a_real_partial_component_is_permitted():
    source = "@component_builder\ndef assemble(config):\n    return object()\n"
    module = types.ModuleType("prometheus_protocol.partial_component")
    module.component_builder = component_builder
    exec(source, module.__dict__)
    assert _module_inventory(source, module, set()) == []


def test_plain_unannotated_options_parameter_is_a_named_inventory_limit():
    source = "def assemble(options):\n    return object()\n"
    assert list(_config_functions(source, "new_module")) == []
