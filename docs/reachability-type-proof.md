# F10: exact type population — observed evidence

This is a count check, not a file-identity manifest or a forgery detector.
Exchanging one checked file for another preserves a count. The separate
whole-tree `mypy.ini` guard controls the declared trees; neither guard can
protect itself from someone allowed to rewrite both implementation and tests.

## Baseline and correction to the brief

The sprint brief described a 320-file pin with tolerance two. At the checked
base, `9141936ea474c6ad7c0b41509b964814344f59b9`,
`scripts/type_gate.py` actually pinned **326 with tolerance two**, admitting
324 and every larger value. The receipt checker imported that same minimum.
The defect was reproduced; the historical numbers were not assumed.

Permanent tests were added **before changing either comparison**, in the
existing `tests/conformance/test_type_gate.py` module:

- `test_type_gate_requires_exact_checked_population`: calls the actual runner
  `main()`, supplying a controlled clean mypy result. Checks exit status,
  receipt existence/content, and the refusal diagnostic.
- `test_type_receipt_requires_exact_checked_population`: calls the separate
  mandatory receipt checker `main()` against a real temporary receipt, checking
  its exit status and diagnostic. It does not merely trust the runner.

Each exercises offsets `[-2, -1, 0, 1, 2]` from the pin; zero is the paired
positive. Before the fix, the literal pytest summary was:

```text
8 failed, 2 passed, 28 deselected in 0.13s
```

The failure messages for **both** entry points were:

```text
AssertionError: checked=324, exact=326, exit=0
AssertionError: checked=325, exact=326, exit=0
AssertionError: checked=327, exact=326, exit=0
AssertionError: checked=328, exact=326, exit=0
```

After changing both entry points to exact equality, the targeted run (including
the existing clean-summary parsing check) printed:

```text
11 passed, 27 deselected in 0.04s
```

The old test named `test_the_gate_runner_refuses_a_run_that_checked_too_few_files`
did **not run the gate**. It inspected a floor constant and the success-line
regex. It could not distinguish the permissive comparison from the fixed one.
That test has been replaced, not retained as evidence of refusal.

The actual tree was measured using mypy 2.3.1 and Python 3.12.14. An intermediate
whole-tree run during parallel implementation printed:

```text
Success: no issues found in 328 source files
38 passed in 5.25s
```

These are checkpoint measurements, not predictions of the final merged module
population. The shipping pin must be updated from the final whole-tree run
after all sprint modules are present. No tolerance remains in either entry
point. The oldest supported **mypy version** floor is a different concept from
the removed file-count floor. That secondary job previously invoked bare mypy;
it now invokes the same `scripts/type_gate.py` entry point under the floor
interpreter, so it cannot silently bypass the exact population check.

`test_checker_floor_uses_the_same_population_gate[0/1]` exercises successful and
refused gate exits, requires the floor interpreter rather than the reference
interpreter, and checks refusal propagation. Before routing the job through
the common entry point, both cases failed:

```text
2 failed, 38 deselected in 0.05s
```

Afterward the F10 population, summary, and floor-routing tests together printed:

```text
13 passed, 27 deselected in 0.03s
```

Collection then observed exactly **40 tests** in `test_type_gate.py`, and the
CI name manifest was reconciled to those actual collected names. Its earlier
population was 28, not an estimated count.

Once the seven new Python files were present (two production modules, three
conformance modules, and two mutation runners), the whole-tree check observed
333 and the pin was updated to **333**, then the actual gate and receipt checker
were rerun:

```text
Success: no issues found in 333 source files
[type-gate] OK — 333 files checked; receipt written to type-gate-receipt.json
type gate receipt OK: mypy 2.3.1 (compiled: yes) on python 3.12.14 checked 333 files against mypy.ini
```

The separate reachability proof step was also measured before pinning:

```text
68 passed in 0.93s
proof composition OK for 'reachability': 68 proofs across 3 module(s), 25 pinned by (module, name), zero skips/failures/errors
```

Its module populations are 26 build, 11 inventory, and 31 reader cases. The
existing collection guard caught the inventory's increase from 10 to 11 before
the pin was changed; it was rerun after the new observed output, not adjusted
from an estimate.

A later two-case migration-startup proof then increased the build module from
26 to 28. The new combined run printed `70 passed in 0.86s`; only then was the
composition pin changed to **28/11/31**, with the migration proof's base name
included in the required membership. The 68-case result above is retained as
an intermediate measurement, not presented as the final population.

After review-driven default, variadic-argument, environment-anchor and inventory
binding regressions were added, the frozen proof collection was measured again:

```text
77 passed in 0.94s
```

That checkpoint's composition pin was **33 build / 13 inventory / 31 reader cases**,
with the added regression names required in their owning modules. These
test additions did not add Python modules; the observed type population remains
333. The historical 68- and 70-case checkpoints are not the shipping pin.

At that source checkpoint, the actual gate and receipt checker were
rerun successfully at 333. The complete CI type-proof group (the union-handling,
type-gate, and revert-pin modules) then produced:

```text
68 passed in 7.38s
type-gate proofs: 68 test(s), all named in the manifest, zero skips
proof composition OK for 'reachability': 77 proofs across 3 module(s), 31 pinned by (module, name), zero skips/failures/errors
```

An additional self-review regression then proved that an unused signer argument
cannot satisfy the custody obligation when no attestation uses it. After the
fix, the combined run printed `78 passed in 0.91s`. That checkpoint's composition pin
was **34 build / 13 inventory / 31 reader cases**, with the new custody
proof also required by name. The earlier 77-case result remains a checkpoint,
not a claim about the final population.

The final review then added regressions for nested configuration substitution,
policy substitution at the bank/execution-authorizer joins, opaque external
subclasses, and unsupported cached reader descriptors. The measured focused
result was:

```text
89 passed in 0.86s
```

The shipping composition pin is **43 build / 13 inventory / 33 reader cases**.
Each newly added critical regression is required by its owning module and base
test name. The earlier 78-case result is also retained only as a checkpoint.
The actual whole-tree type gate and receipt checker were rerun after these
changes and both passed at **333 source files**; no new module was added by
these additional cases.

## Executed first-order mutations

All mutations used `scripts/mutation_worktree.py`, with `include_dirty=True`
because the tests and fixes were not yet committed. Nothing was mutated in the
primary checkout. The baseline inside that disposable tree was:

```text
baseline 10 passed, 28 deselected in 0.03s RED= []
```

In the table, `runner` means
`test_type_gate_requires_exact_checked_population`; `receipt` means
`test_type_receipt_requires_exact_checked_population`. Every node is in
`tests/conformance/test_type_gate.py`. Brackets are the actual parametrized
node suffixes. The table records the observed result, not an expected count.

| Mutated mechanism | Mutation | Red nodes | Literal result summary |
| --- | --- | --- | --- |
| Runner | Delete comparison (`if False`) | `[-2] [-1] [1] [2]` | `4 failed, 1 passed, 33 deselected in 0.03s` |
| Runner | Replace `!=` with `<` | `[1] [2]` | `2 failed, 3 passed, 33 deselected in 0.03s` |
| Runner | Replace `!=` with `>` | `[-2] [-1]` | `2 failed, 3 passed, 33 deselected in 0.03s` |
| Runner | Replace observed count with configured pin | `[-2] [-1] [1] [2]` | `4 failed, 1 passed, 33 deselected in 0.03s` |
| Runner | Refuse everything (`if True`) | `[0]` | `1 failed, 4 passed, 33 deselected in 0.03s` |
| Receipt | Delete comparison (`if False`) | `[-2] [-1] [1] [2]` | `4 failed, 1 passed, 33 deselected in 0.03s` |
| Receipt | Replace `!=` with `<` | `[1] [2]` | `2 failed, 3 passed, 33 deselected in 0.03s` |
| Receipt | Replace `!=` with `>` | `[-2] [-1]` | `2 failed, 3 passed, 33 deselected in 0.03s` |
| Receipt | Replace receipt count with configured pin | `[-2] [-1] [1] [2]` | `4 failed, 1 passed, 33 deselected in 0.03s` |
| Receipt | Refuse everything (`if True`) | `[0]` | `1 failed, 4 passed, 33 deselected in 0.03s` |

The substitution rows matter: a count from configuration is not a count
observed from mypy or the receipt. Equality after replacing the observed side
with the expected side is an empty assertion. The tests refuse that spelling.
The unconditional-refusal rows establish the paired positive rather than
letting “always fail” stand in for a functioning exact gate.

## Second-order probes of both new proofs

These also ran through `MutationWorktree`, not in-place edits.

| Proof mutation | Runner proof result | Receipt proof result |
| --- | --- | --- |
| Delete the proof's primary `assert result == ...`, while also deleting the production comparison | `4 failed, 1 passed, 33 deselected in 0.03s` | `4 failed, 1 passed, 33 deselected in 0.03s` |
| Replace the actual `main()` call with a hand-written expected-result oracle, `result = (0 if offset == 0 else 1)` | `5 failed, 33 deselected in 0.04s` | `5 failed, 33 deselected in 0.03s` |

The first probe leaves the four negative nodes red: the runner's receipt
side-effect and refusal output, and the receipt checker's refusal output,
independently carry the negative half. Zero remains green because removing a
rejection should not invalidate a correctly sized run.

The second probe leaves **every node** red: replacing actual execution with a
prediction cannot produce the required receipt or the entry point's emitted
diagnostic. The positive half matters here as well as refusal. None of these
four probed mutations survived. This is not a claim that all conceivable proof
rewrites fail; deleting every oracle or forging both output and result is
outside what these tests prove.

### Supported-checker routing proof

The subsequently added floor-routing proof was also mutated in a disposable
worktree. `[0]` is the successful gate exit and `[1]` is a refusal.

| Mutation | Observed red nodes | Literal result |
| --- | --- | --- |
| Bypass common gate with bare mypy | `[0] [1]` | `2 failed, 38 deselected in 0.03s` |
| Substitute the reference interpreter for the floor interpreter | `[0] [1]` | `2 failed, 38 deselected in 0.03s` |
| Delete propagation of the gate's refusal | `[1]` | `1 failed, 1 passed, 38 deselected in 0.04s` |
| Delete routing-count assertion and also bypass common gate | `[0] [1]` | `2 failed, 38 deselected in 0.03s` |
| Replace real wrapper call with predicted exit value | `[0] [1]` | `2 failed, 38 deselected in 0.03s` |
| Delete exit-propagation assertion and also delete propagation in the wrapper | none | `2 passed, 38 deselected in 0.03s` |

The last second-order mutation **survives**. The return-status assertion carries
the refusal-propagation half; the remaining routing/interpreter assertions
cannot establish that a correctly invoked gate's refusal reaches the caller.
That assertion has therefore been retained and the surviving half is reported,
not hidden behind the other green probes. The routing-count deletion is caught
by the independent exact interpreter-list assertion. The predicted-result
substitution cannot produce the observed invocation list.

## No transient mutation in the primary tree

The pre-existing planted-union proof created its temporary source file in the
primary checkout. During a parallel snapshot that file was copied as if it were
an ordinary untracked change; the copied suite correctly refused to clobber it.
Those snapshot failures are not credited as mutation kills or type defects.
`_planted_defect` now uses `MutationWorktree(include_dirty=True)`, and both the
real gate and independent direct-mypy control execute against that disposable
tree. `test_the_planted_defect_is_removed_afterwards` checks the primary path
is absent even while the disposable defect exists and checks its removal after
the context exits. No production-path source file is planted by these tests.

The isolation change and strengthened existing proof were probed too, each in
a fresh outer `MutationWorktree` so even a deliberately incorrect inner plant
could not touch the real primary checkout:

| Mutation | Red proof | Literal result |
| --- | --- | --- |
| Plant into the caller's checkout instead of the inner disposable checkout | `test_the_planted_defect_is_removed_afterwards` | `1 failed, 39 deselected in 0.16s` |
| Substitute benign `pass` for the planted union defect | `test_a_planted_union_defect_still_fails_the_gate` | `1 failed, 39 deselected in 2.16s` |
| Delete the proof's path-identity assertion and plant into the caller's checkout | `test_the_planted_defect_is_removed_afterwards` | `1 failed, 39 deselected in 0.16s` |
| Substitute an unrelated absent path in the in-context absence assertion and plant into the caller's checkout | `test_the_planted_defect_is_removed_afterwards` | `1 failed, 39 deselected in 0.16s` |

The two isolation assertions carry independent halves: pathname identity and
the primary path's actual absence. Removing/substituting either alone does not
erase the test's ability to detect this planted-location regression.

## Bytecode measurement correction

An initial rapid mutation run reused a worktree and changed `<` to `>` without
changing the file size. One row repeated the previous mutation's red-node set,
consistent with same-timestamp/size bytecode reuse. **That row is withdrawn.**
The entire first-order run above was repeated in a fresh disposable worktree
with `PYTHONDONTWRITEBYTECODE=1` set before any imports. The second-order runs
also used that setting. The repeated output correctly distinguishes negative
from positive offsets. A mutation harness that resolves the right source path
still needs to avoid stale bytecode when reusing a checkout.

## Commands and mutation method

The regular checks are:

```sh
PYTHONPATH=src .venv/bin/python -m mypy --config-file mypy.ini
PYTHONPATH=src .venv/bin/python -m pytest -q --tb=short -p no:cacheprovider tests/conformance/test_type_gate.py
```

Each mutation used this shape; the exact substitutions are enumerated above:

```python
import os
import sys

os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.path.insert(0, "scripts")
from mutation_worktree import MutationWorktree

with MutationWorktree(include_dirty=True) as tree:
    tree.apply(
        "scripts/type_gate.py",
        "if checked != EXPECTED_CHECKED_FILES:",
        "if checked < EXPECTED_CHECKED_FILES:",
    )
    red, summary = tree.pytest(
        ["tests/conformance/test_type_gate.py"],
        "-k", "test_type_gate_requires_exact_checked_population",
    )
    print(summary, red)
    assert red and "failed" in summary and "error" not in summary
```

The receipt counterpart changes the condition
`if type(checked) is not int or checked != EXPECTED_CHECKED_FILES:` in
`scripts/check_type_gate_receipt.py`, selecting the receipt test. The
cross-context substitutions replace `checked = int(match.group(1))` or
`checked = receipt.get("checked_files", 0)` with
`checked = EXPECTED_CHECKED_FILES`. Between mutations, `tree.revert()` restores
the disposable tree. Second-order probes replace only the selected test's
function body; they remove its three-line return-status assertion or substitute
the `main()` call described in the table. Collection/import errors and missing
summaries are not counted as successful mutation kills.
