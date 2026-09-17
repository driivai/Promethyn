# Reachability inventory: measured scope and proof record

This is the source-inventory companion to `runtime/security_build.py`, not a
claim that arbitrary Python programs can be statically proved safe. The review
checkout started at `9141936ea474c6ad7c0b41509b964814344f59b9`. These measurements
were made on the uncommitted reachability change, using Python 3.12 on macOS;
they are not Linux, PostgreSQL, isolation, or final-PR-head results.

## What the instrument discovers

`tests/conformance/test_security_build_inventory.py` scans every Python file
under `src/prometheus_protocol`, not a list of production-root names. A public,
module-level function enters the inventory if a parameter is annotated with
`Config` or `MigrationRunnerConfig`, or is named `config` or `settings`.
Annotations resolve through imported aliases, dotted module aliases, simple
assignment aliases (including `Cfg: TypeAlias = Config`), unions and string
annotations. Parameter names can differ.

The inventory imports only modules containing candidate functions and inspects
the callable's actual root/component marker. It does not infer installation
from a source string that happens to mention the installer. A newly added module
with a Config-bearing public function therefore cannot omit guard installation
without this test failing. An explicitly partial component cannot directly
return a discovered production runtime class under another constructor spelling
or through a simple assigned result. The runtime-class population comes from
guarded roots' return constructions, not a parallel list of root function names.

### Limits first, not an implied universal result

- An unannotated parameter called `options`, arbitrary dynamically constructed
  annotations, methods, private functions, generated code and public functions
  taking neither configuration type nor either fallback name are outside this
  discovery envelope. The untyped-`options` limit is a passing test, not a claim
  that the function is safe.
- `Config` and `MigrationRunnerConfig` are the recognized configuration types.
  A new unrelated configuration class needs explicit discovery support. Runtime
  `Config` subclasses are checked dynamically by the build guard; this source
  scanner does not infer arbitrary subclass or type-alias computations.
- Component classification is trusted. The return check catches direct or
  simply assigned runtime construction, including aliases; it is not
  interprocedural proof over helper calls, closures, reflection or arbitrary
  return-value computation. Future partial builders must be reviewed as such.
- Source name resolution is scope-aware, but not a complete Python data-flow
  analysis. Within one scope it does not prove branch feasibility or arbitrary
  mutation of bindings. The live-object build checks, not this inventory,
  decide whether a reached supported root applied a requested property.
- A program that deliberately discards its requested configuration, replaces
  trusted guard code or lies in an adapter is not an in-process security boundary
  this guard claims to withstand.

## A weakness found in the first draft, and the correction

The first collector used `ast.walk` for the whole module when resolving import
bindings. That also visited imports inside unrelated functions. Consequently,
an unrelated `from pathlib import Path as Cfg` could replace the binding for a
module-level `Config as Cfg` and make an `options: Cfg` root undiscovered.
**Any claim that the first draft's alias handling was cross-context-safe is
withdrawn.** `_scoped_nodes` now stops at other function/class scopes, and
`test_another_function_cannot_substitute_the_config_alias_binding` permanently
reproduces the substitution. Restoring the broad traversal failed that exact
test; removing its assertion while keeping the mutation passed.

## Observed run

Command from the dedicated checkout:

```sh
.venv/bin/python -m pytest -q tests/conformance/test_security_build_inventory.py
```

Literal summary after adding the scope-substitution and annotated-assignment
regressions:

```text
13 passed in 0.16s
```

The earlier ten- and eleven-case results described earlier test populations;
neither is the count to pin for this version. No test was skipped in this run.

## Mutation and second-order results

Every mutation below ran inside `scripts/mutation_worktree.py` using
`MutationWorktree(include_dirty=True)`. Only the named test was selected. The
first column names a concrete edit; the test names below are all in
`tests/conformance/test_security_build_inventory.py`.

| Edit | Named test | Observed first order | Same mutation, property assertions removed |
|---|---|---|---|
| Delete factory `install_build_guards(globals())` | `test_every_config_bearing_public_assembly_is_classified_across_the_package` | `1 failed in 0.23s` | `1 passed in 0.20s` |
| Replace annotation identity-membership expression with `False` | `test_renamed_config_parameter_and_type_aliases_are_discovered` | `4 failed in 0.01s` | `4 passed in 0.01s` |
| Replace config/settings parameter-name fallback with `if False:` | `test_unannotated_config_or_settings_parameter_still_requires_classification` | `1 failed in 0.01s` | `1 passed in 0.01s` |
| Delete the unclassified-function diagnostic append | `test_new_module_with_aliased_constructor_cannot_omit_guard_installation` | `1 failed in 0.01s` | `1 passed in 0.01s` |
| Substitute original callable for `guarded_root(function)` in installer | `test_new_module_with_aliased_constructor_is_classified_when_guard_installed` | `1 failed in 0.01s` | `1 passed in 0.01s` |
| Delete the component-returning-runtime condition | `test_component_annotation_cannot_hide_an_aliased_runtime_return` | `2 failed in 0.01s` | `2 passed in 0.01s` |
| Substitute `partial = False` for actual component-marker inspection | `test_a_real_partial_component_is_permitted` | `1 failed in 0.01s` | `1 passed in 0.01s` |
| Make every parameter satisfy the name fallback (`if True:`) | `test_plain_unannotated_options_parameter_is_a_named_inventory_limit` | `1 failed in 0.01s` | `1 passed in 0.01s` |
| Restore cross-scope `ast.walk(tree)` for import bindings | `test_another_function_cannot_substitute_the_config_alias_binding` | `1 failed in 0.01s` | `1 passed in 0.01s` |

These results distinguish the negative cases from their positive controls:
removing the classification mechanism is caught by the negatives; making it
refuse a legitimate component or failing to mark an installed root is caught by
the positives. After the relevant assertions were removed, no selected proof
still failed. That is observed assertion sensitivity, not proof that every
conceivable weakening has been enumerated.

### Exact harness pattern and edits

This is the pattern used for each row; `old`, `new`, `test` and `assertion` are
the source text named by that row. The complete scope-substitution invocation
is shown rather than implying a source edit was applied to the primary tree:

```python
import sys
sys.path.insert(0, "scripts")
from mutation_worktree import MutationWorktree

p = "tests/conformance/test_security_build_inventory.py"
t = p + "::test_another_function_cannot_substitute_the_config_alias_binding"
with MutationWorktree(include_dirty=True) as wt:
    wt.apply(p, "for node in _scoped_nodes(tree):", "for node in ast.walk(tree):")
    print("cross-context-alias-binding-substitution:", wt.pytest([t]))
    wt.apply(
        p,
        '    assert [node.name for node, _ in _config_functions(source, "new_module")] == ["assemble"]\n\n\n_NEW_ROOT',
        '    pass\n\n\n_NEW_ROOT',
    )
    print("cross-context-second-order:", wt.pytest([t]))
```

Literal output:

```text
cross-context-alias-binding-substitution: (['tests/conformance/test_security_build_inventory.py::test_another_function_cannot_substitute_the_config_alias_binding'], '1 failed in 0.01s')
cross-context-second-order: ([], '1 passed in 0.01s')
```

## New module, not merely another root in an existing module

A separate probe created `runtime/new_aliased_root.py` **only inside the
throwaway worktree**, with these exact contents (written with `apply_patch`):

```python
from prometheus_protocol.core.config import Config as Cfg
from prometheus_protocol.execution.controller import ExecutionController as ControllerAlias


def assemble(options: Cfg):
    registry = None
    return ControllerAlias(
        gate=object(), executor=object(), ledger=object(), reobservation=registry
    )
```

The constructor is aliased; the parameter is renamed; the registry is indirectly
None. The inventory does not execute this invalid fixture or claim that its
components work. It catches the missing assembly classification independently
of those constructor arguments.

The running worktree session used this command, paused while the new file was
patched under the printed worktree path, then resumed with Enter:

```sh
.venv/bin/python -c 'import sys; sys.path.insert(0, "scripts"); from mutation_worktree import MutationWorktree; p="tests/conformance/test_security_build_inventory.py"; t=p+"::test_every_config_bearing_public_assembly_is_classified_across_the_package"; wt=MutationWorktree(include_dirty=True); wt.__enter__(); print("WORKTREE",wt.path,flush=True); input("Apply new module then Enter: "); print("aliased-new-module-omits-guard:",wt.pytest([t]),flush=True); wt.apply(p,"    assert problems == []\n","    pass\n"); print("aliased-new-module-second-order:",wt.pytest([t]),flush=True); wt.__exit__(None,None,None)'
```

Literal result lines:

```text
aliased-new-module-omits-guard: (['tests/conformance/test_security_build_inventory.py::test_every_config_bearing_public_assembly_is_classified_across_the_package'], '1 failed in 0.22s')
aliased-new-module-second-order: ([], '1 passed in 0.20s')
```

The disposable worktree and synthetic module were removed by the harness. They
were not added to the primary checkout.

## Unavailable-reason correction: which assertion carries which half

`gate/authorization.py` formerly emitted "routed to a human" for an unavailable
check, although the controller halts without an approvable hold. The existing
`TestThePositiveControl.test_a_refused_coverage_still_refuses_after_all_this`
in `test_unbound_authorization_closed.py` now checks the correct positive
wording, rejects the old misleading wording, and checks no pending hold exists.
That module ran as `18 passed in 0.04s` after the change.

In disposable mutation worktrees, targeting only that test:

- Substituting `f"routed to a human"` for `f"halted without an approvable hold"`
  yielded `1 failed in 0.02s`. Removing only the positive-wording assertion
  **still failed**: the separate assertion forbidding the old wording carries
  the substitution half. Removing both wording assertions yielded
  `1 passed in 0.02s`; the controller still does not create a hold, but the
  inaccurate diagnostic is no longer tested.
- Deleting that halt suffix (`f""`) yielded `1 failed in 0.02s`. Removing the
  positive-wording assertion while retaining the deletion yielded
  `1 passed in 0.02s`. The negative-wording assertion does not prove that an
  informative halt reason was emitted. It only excludes the misleading claim.

These are diagnostic-truthfulness proofs, not new evidence that the whole
authorization mechanism is correct. The existing executor/no-hold assertions
carry that distinct behavior, and they are not substitutes for the wording.
