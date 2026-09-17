# Persisted obligations and authoritative readers — F3

## Limits first

This is a boundary on the shipped `SqliteLedger` public reader API, not a
Python sandbox. Trusted code can still use the private `_conn` or
`_receipt_source()` diagnostic interface, monkeypatch methods, mislabel a new
reader as a writer/diagnostic, or introduce a different ledger implementation.
Those are outside this derivation and require review. A self-consistent whole
chain rewrite is still undetectable without an independently protected anchor.
The guard validates the stored snapshot, not the semantics of an arbitrary new
projection: trusted code returning a fabricated value or another data source's
value is not proven correct merely because its local ledger verifies.
The guard does not claim that every column in SQLite is receipted: decision
and outcome fields are derived from `DecisionRecord` and `OutcomeRecord`, and
the persisted authorization/observation obligation is compared with its
`pending.hold` receipt. Existing unreceipted columns remain outside that
coverage.

Every guarded read checks the whole snapshot. This costs a full receipt/hash
walk, plus anchor-history I/O when configured; it is intentionally not a
constant-time read or a cache. Corruption of one protected row can refuse an
otherwise unrelated read. Legacy execution rows without receipts also refuse
authoritative reading. `verify_chain`, `verify_receipts`, and
`verify_ledger_file` remain diagnostic APIs: they report their scoped verdicts
rather than presenting an invalid row as authoritative evidence.

## What changed

Before this change, `PendingActionService._compare_now` returned `matched`
immediately when the *current* registry was `None`, without honoring the
persisted hold's observed state. An observed hold reopened without its
registry could execute on stale evidence. The permanent regression is
`test_F3_observed_hold_reopened_without_registry_records_unavailable_and_refuses`.
Before the fix, its literal result was:

```text
E       Failed: DID NOT RAISE StateUnreadable
1 failed, 1 passed in 0.46s
```

The paired positive was present in that run. The fixture creates real Git
state, records a hold at state A, advances the branch to B, closes the ledger,
and reopens it through a different controller/SQLite connection with no
registry. The executor is a spy: this measures reachability of execution, not
operating-system isolation.

Now the persisted observed pin establishes the obligation. A missing registry
produces an `unavailable` observation with `registry_unavailable`, chains that
receipt, and refuses approval with `StateUnreadable`. An existing registry
that opts the class out also records an unavailable observation before its
distinct `StateUnobservable` refusal. Neither is recorded as a target move.
The hold remains pending on a pre-approval refusal. A working registry still
approves unchanged state and records both comparisons.

## The reader boundary and its derivation

`ledger/readers.py:reader_methods` derives the population from the actual public
class API. It is not a list of caller names or constructor spellings.
`guard_readers` wraps plain public instance methods and Python properties by default;
`SqliteLedger.__init_subclass__` applies it to new subclass APIs. An aliased
constructor, an aliased bound method, and scalar-returning readers all receive
the same guard. Missing return annotations refuse class construction;
unclassified static, coroutine, and generator readers refuse too. Other public
callable/descriptor shapes also refuse class construction unless explicitly
marked as a trusted writer/diagnostic. Inert class constants are not readers.

Explicit writer and diagnostic metadata exempt mutation/forensic APIs. These
exemptions are part of the trusted implementation, not permissions an
untrusted action supplies. The earlier design based only on dictionary return
annotations is withdrawn: it would have missed a future `-> bool` reader.
The implementation instead guards new supported public methods/properties,
including scalar projections, and refuses unsupported shapes.

### Final-review correction: wrapped descriptors were not covered

The initial implementation silently skipped any public member that was not a
plain function or a Python property getter. A `functools.cached_property` and a
`functools.cache`-wrapped method therefore escaped the derived population.
The earlier broad claim that every public method/property was guarded was too
strong and is withdrawn. A read-only probe added a future subclass with a
cached scalar SQL projection, created a genuine completed execution, changed
its stored `executed` flag to false, and accessed both the cached projection
and the ordinary guarded reader. The literal output was:

```text
ran_in_derived_readers= False
tampered_cached_property= False
normal_reader= ExecutionNotAuthorized
```

The fix refuses unsupported public descriptor/callable shapes at class
construction instead of silently skipping them. It does not attempt to make
caching safe by verifying just the first evaluation. Two permanent cases use
the standard-library `cached_property` and `cache` wrappers and require
`TypeError: unsupported public ledger reader shape: FutureLedger.outcome`.
The ordinary method/property positives remain covered. This refusal is not a
claim to validate arbitrary custom descriptor semantics or explicitly exempt
trusted code.

`SqliteLedger._authoritative_read` obtains the returned result and its
diagnostic snapshot under one SQLite savepoint, then verifies chain/anchor and
receipt bindings before returning. Verification consumes private diagnostic
snapshots, avoiding recursive reliance on the public guard. Receipt checking
walks both directions, so deleting a row is not an empty successful read, and
compares identities as well as values, so assigning an outcome to another
hold is not a successful read in a new context. The full hold authorization is
compared to its chain entry, including its observation obligation.

The reflected current population is exactly these 11 methods:

```text
attempts, authoritative_pass_below, chained_events, executions,
executions_below_confidence, executions_for_pending, human_decisions,
pending_action, pending_actions, promotions, workflow_steps
```

This means every production caller of these APIs, including a future caller
or alias, inherits their refusal. It does not assert that a separate future
storage implementation or a new private SQL reader is covered automatically.

## Measured proofs

Run `python scripts/reachability_reader_proofs.py`. All mutations use
`scripts/mutation_worktree.py`; the primary checkout is never weakened.
Observed before publication on the implementation tree:

| Probe | Literal summary |
| --- | --- |
| baseline | `33 passed in 1.09s` |
| restore F3 permissive `None` | `1 failed, 32 passed in 0.74s` |
| delete reader guard installation | `31 failed, 2 passed in 0.77s` |
| substitute an unrelated empty snapshot as authority | `28 failed, 5 passed in 0.66s` |
| replace reader derivation with current hand list | `4 failed, 29 passed in 0.69s` |
| delete unsupported-reader refusal | `2 failed, 31 passed in 0.72s` |
| classify the unsupported reader using another API's diagnostic metadata | `2 failed, 31 passed in 0.71s` |

The hand-list mutation specifically reddens the future aliased direct-SQL
reader (deletion and substitution) and the new scalar method/property probes.
Every current reader is tested with a genuine ledger first, then an outcome
row deletion and a cross-hold substitution. Separate tests erase/substitute
the persisted observation obligation. Both unsupported-shape mutations redden
the `cache` and `cached_property` cases; the substitution deliberately borrows
`chain_tip`'s diagnostic classification for the new `outcome` API.

Second order: the script removes **every `assert`** from the new proof module
and reruns all six mutations. Observed summaries, respectively, were
`1 failed, 32 passed in 0.68s`, `31 failed, 2 passed in 0.67s`,
`28 failed, 5 passed in 0.88s`, `4 failed, 29 passed in 0.68s`,
`2 failed, 31 passed in 0.69s`, and `2 failed, 31 passed in 0.70s`.
These surviving negative halves are carried by `pytest.raises`: they still
prove refusal/type, **not** the exact reason, recorded receipt, zero executor
calls, identity binding details, or the positive's returned values. Those
stronger halves live in the removed assertions and are not claimed to survive
their deletion. The script reports this distinction rather than treating an
unchanged red count as proof that the deleted assertions were redundant.

Focused existing authorization/decision/outcome, retry, routing, and expiry
compatibility run: `142 passed, 4 skipped in 1.22s`. The four skips required
namespace isolation unavailable on the local macOS host; this is not a claim
that the Linux/live-isolation paths ran locally. Tests that intentionally
inspect forged raw rows now use the explicit diagnostic snapshot; ordinary
readers refusing those rows is the behavior under test, not a test workaround.

The ledger-chain/external-anchor regression run with localhost fixture access
enabled was `156 passed, 11 skipped in 11.41s`; those skips were the existing
Linux-only substrate/ownership probes on macOS.
