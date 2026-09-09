# Opened-store substrate and mount visibility: 1A/1B

Base: `11176aa37fe1831e0111f6becd92f1064104b659` (main at branch creation).
Branch: `hardening/opened-substrate-1a-1b`.

Validation snapshot: implemented and locally tested; **Linux validation was
still outstanding at this checkpoint**. The local host is macOS, not a Linux
integration environment. Direct authenticated Git push was unavailable. The
owner subsequently authorized the connector's default author and committer
for this PR only, overriding the earlier identity requirement. Publication is
through that connector; no merge or auto-merge is authorized. Consult the PR's
checks for validation results after this local checkpoint.

## 1. Opened objects and preflight

`ConsumedApprovals` retains parent preflight before creation, then opens its
persistent guard descriptor before SQLite initialization. `probe_opened_substrate`
joins the held descriptor's `fstat().st_dev` to its exact `/proc/self/fdinfo/FD`
`mnt_id` and that entry in `/proc/self/mountinfo`. Device-only matching or a
pathname prefix cannot substitute for this join. The descriptor's device/inode
must also be the store identity checked by PROM-FIX-B.

There is no separate companion lock in current main. PROM-FIX-B locks this
same store inode with Linux `flock`, and records its device/inode lock identity.
This change classifies that object before SQLite opens and reinspects it before
each execution guard acquisition, including a fork reopening the descriptor.
A file bind alias can have a different mount ID while sharing the same
device/inode and therefore the same execution lock.

Parent preflight remains conservative even for existing files and accounts for
SQLite sidecar placement. A preflight refusal creates nothing. An opened-object
refusal may leave an empty newly created file, but no SQLite initialization.

`AuthorizationJournal` inspects its existing file, not its parent, with Linux
`O_PATH | O_NOFOLLOW | O_CLOEXEC`. Device/inode must still match the journal's
recorded identity. Inspections surround per-operation SQLite opens. Closing an
extra ordinary descriptor can drop process-owned SQLite POSIX locks; `O_PATH`
avoids that side effect. The real lock-preservation integration is still pending.
The kernel's `filp_flush` excludes `FMODE_PATH` from `locks_remove_posix`
([Linux source](https://github.com/torvalds/linux/blob/master/fs/open.c)).

Missing, inconsistent or ambiguous metadata is unverified. Known unsafe
filesystems have no opt-out. Unknown results require the existing explicit
opt-out, logged on each accepted inspection. Environment settings use
PROM-FIX-B's strict parser; programmatic and direct policy fields require actual
booleans. All sources are validated, including later sources after an earlier
true value. Simultaneous requirement and opt-out is refused.

## 2. Mount visibility

`MountEntry` retains mount ID, parent ID, device, mount root, mount point and
driver. Parsing rejects malformed identities, duplicates and parent cycles.
The preflight resolver starts at one visible root and follows the nearest
covering child, including same-path stacks. A parent overmount hides the lower
mount's descendants. It does not select the globally longest prefix or use
input order as a tiebreaker.

For the review topology (20 at `/srv`, 21 under 20 at `/srv/private`, 30 over
20 at `/srv`), lookup selects 30, not hidden 21. Forward, reverse and shuffled
table orders all return unsafe/NFS. A new child actually under 30 is a positive
control and remains visible. Ambiguous roots/children and disconnected covering
mounts produce unknown, not a guessed winner.

An already-open descriptor may legitimately reference a now-hidden mount; its
exact mount ID, not its old pathname, determines the opened-object inspection.

## 3. Repaired fixtures

| Fixture before | Fixture now | Executed regression evidence |
| --- | --- | --- |
| Every synthetic mount had parent ID 1 | Independent fixture builder assigns topology-aware parents; explicit hidden descendants include real stacks | Restoring longest-prefix lookup causes 3 call failures; accepting a competing child causes 1 |
| Store/builder probe returned one answer regardless of queried object | Directory probe asserts the requested directory; descriptor probe checks the actual file's device/inode; safe parent and unsafe file are distinct | Bypassing the opened-store check causes 4 constructor failures and 3 builder failures |
| Private journal test covered permissions, not a separately mounted file | New local/network/unknown file-mount cases assert the exact journal pathname, not its local parent | Replacing the journal query with its parent causes 3 failures; dropping enforcement causes 2 |

Ordinary local files, visible local descendants, safe descriptor identities and
successful journal reads are positive controls. Refusing every object does not
satisfy these tests.

## 4. Required Linux integration

`test_substrate_linux.py` contains five cases, collected locally but **not
executed on this host**. Every case requires Linux and a disposable private
mount namespace; missing support fails instead of skipping. No injected mount
table or probe is used inside these cases.

1. `database_file`: an overlay-backed regular file bind-mounted into a verified
   local directory is refused before SQLite initialization.
2. `journal_file`: a private overlay-backed journal file separately mounted
   beneath a local parent is refused for issuance.
3. `lock_file_alias`: a separately bind-mounted store/lock alias has a different
   mount ID but the same lock identity; a fresh subprocess cannot acquire it
   while held, and it can be acquired after release.
4. `hidden_descendant`: real child mounts hidden by a parent overmount classify
   as the visible overlay, not the hidden local descendant.
5. `journal_posix_lock`: journal inspection must not let another subprocess
   acquire a SQLite write transaction held by this process.

Overlay is the real unknown-substrate negative control, not a claim of live NFS
coverage. Known network drivers are covered by synthetic tests. All five cases
are mandatory in each Linux matrix job and again collected by the full suite.

## 5. Executed guard-revert evidence

Command: `PYTHONPATH=src python scripts/substrate_revert_proofs.py`.
The existing runner replaces function code in memory, executes selected tests,
requires call-phase failures rather than collection errors/skips, and restores
the original code. Production source files are not rewritten by the proof.

| Guard mutation | Observed call failures |
| --- | ---: |
| Hidden mount: restore global longest prefix | 3 |
| Ambiguous children: accept the first | 1 |
| Remove descriptor device agreement | 1 |
| Ignore descriptor mount ID | 3 |
| Remove opened-store enforcement, constructor tests | 4 |
| Remove opened-store enforcement, builder tests | 3 |
| Remove held-lock reinspection enforcement | 1 |
| Query journal parent | 3 |
| Treat unknown opened identity as safe | 4 |
| Remove journal substrate enforcement | 2 |
| Remove journal opened-inode agreement | 1 |
| Replace journal O_PATH with ordinary read descriptor | 1 |
| Remove direct policy boolean validation | 6 |
| Treat unreadable descriptor metadata as safe | 2 |
| Remove per-operation journal reinspection | 2 |
| Short-circuit later policy source validation | 1 |
| **Total: 16 mutations** | **38** |

Final output: `16 reverts caught; 38 call-phase failures; zero errors/skips; pinned 16 / 38`.
Both constants and live mutation targets are checked in
`test_substrate_revert_pins.py`; either a shortfall or excess fails the build.
PROM-FIX-B's separate existing pins were not changed.

## 6. Documentation and residuals

`docs/threat-model.md` now states: “The 1A/1B follow-up replaces parent-only
classification with inspection of the opened store descriptor, which is also
the execution-lock object”. `docs/chokepoint-threat-model.md` describes the
device/mount join, hidden descendants and how the inspected inode composes
with PROM-FIX-B. Its former claim that every refusal creates nothing now
distinguishes parent refusal from opened-object refusal.

`docs/authorization-record.md` describes the actual journal object inspection,
O_PATH lock behavior and the boundary between issuance tests and Linux-only
execution controls. Source docstrings were aligned with these changes.

Named residuals:

- Kernel/proc metadata, parent directories and mount namespace remain trusted.
  Metadata outside the current namespace, malformed topology and contradictory
  device identity are unverified, not inferred safe.
- SQLite still opens by pathname. Inspection and SQLite's open are not one
  atomic VFS operation; privileged remount/path replacement during operation is
  outside this guarantee. Storage must remain stable while runners exist.
- Driver recognition does not prove truthful fsync, power-loss durability,
  exclusive block-device access or multi-host coordination. tmpfs/ramfs are
  recognized for locking but volatile; persistent storage is required for
  replay protection across reboot. The unknown opt-out proves none of these.
- Non-Linux descriptor inspection is unverified. Execution/recovery guards
  remain Linux-only even under that opt-out.
- A bare `SqliteLedger` or custom audit sink does not acquire the issuance
  journal's policy automatically. Independent stores are not one execution lock.
- No live network-filesystem integration was run, and the five new real Linux
  cases remain unexecuted pending CI.

## 7. Validation and publication status

Local Python 3.12/macOS results:

- Exact new/updated substrate gate: **97 passed**, zero skips/errors/failures
  (`test_substrate`: 57; `test_opened_substrate`: 38; new pin tests: 2).
- Broader run including strict booleans, existing pins and all three F11 files:
  **516 passed, 11 failed, zero skips**. All 11 failures have exactly the same
  test identities as an untouched export of base main, which produced
  **265 passed, 11 failed** across the three F11 files. They exercise execution
  or recovery, which refuses on macOS with `_PlatformUnsupported`. This is not
  a green full-suite result and was not weakened into skips.
- New mutation runner: **16 / 38**, zero errors/skips.
- Type gate: **22 source files**, no issues. Hygiene, IP consistency and
  whitespace checks passed. Source/test/script compilation and the isolated
  source-distribution and wheel build passed.
- Clean source exports scanned using the unchanged scanner pin
  `d371f9cd18eb880b3e49336134c476136ee515d2`: base and branch both report
  **0 VOID / 3 WARN / 2 UNKNOWN**, with zero baselined suppressions. The WARNs
  concern PostgreSQL service variables; the UNKNOWNs concern dynamic skip
  conditions and scheduled-run history. Finding identities and fingerprints
  are unchanged. No suppression or baseline was added.

| Required remote job | Status | Executed suite count |
| --- | --- | --- |
| Linux CI / Python 3.10 | Not run at local checkpoint; see PR checks | Unavailable at checkpoint |
| Linux CI / Python 3.11 | Not run at local checkpoint; see PR checks | Unavailable at checkpoint |
| Linux CI / Python 3.12 | Not run at local checkpoint; see PR checks | Unavailable at checkpoint |
| Remote voidguard | Not run at local checkpoint; see PR checks | Local counts above only |

At the initial checkpoint, the workflow enforced exact collection
(57 + 38 + 2), 16/38 mutation pins and five real Linux cases with zero skips.
The follow-up below extends those pins. Configuration is not execution evidence.
The Linux matrix must run on the published PR before claiming those requirements
are satisfied. The owner's publication authorization does not waive validation
or authorize merging.

## 8. Linux compatibility follow-up

The first PR run (34309448542) failed on all three Python versions during the
F11 step: 19 failures, 156 passes and 104 setup errors per job. The mount-table
preflight returned unknown, so the guard refused rather than bypassing checks.
The later real-mount integrations did not run.

An independent local reproduction isolated a valid kernel format omitted from
the fixtures: an `nsfs` mount root such as `net:[4026533001]`, used for mounted
namespace files. Adding that unrelated mount to a simple ext4 table changed
the store's classification from safe to unknown. Linux supplies this label
through `nsfs_show_path`, rather than an ordinary absolute root pathname
([kernel source](https://github.com/torvalds/linux/blob/master/fs/nsfs.c)).

The correction recognizes that label syntax only for `nsfs`. Entries are not
discarded, nsfs is not added to the safe list, mount-point validation remains
strict, and descriptor device/mount identity still has to agree. Unrecognized
root formats continue to refuse. The next CI run prints the observed namespace
labels and checks the real workspace and temporary-directory mount metadata
before the F11 tests, to confirm the runner's actual compatibility.

Eleven new unit cases were executed before the fix: the five valid namespace
formats failed, while all six malformed/wrong-driver/wrong-mount-point controls
passed. The fixed implementation passes both sets. A sixth mandatory Linux
integration creates a real mounted network-namespace file, verifies that this
object remains unverified, then constructs and locks an ordinary local store
beside it. It creates its own network and mount namespaces; no host mount is
changed. Its real Linux execution remains pending the new CI run.

Four additional executed mutations catch restoring pathname-only validation
(5 call failures), removing the nsfs-driver restriction (1), accepting malformed
labels (4), and discarding namespace entries (5). The new exact pins are
**20 mutations / 53 call-phase failures**, with no errors or skips. The focused
collection pin becomes **57 + 49 + 2 = 108**, and Linux integration requires
**six** cases. The original 16/38 evidence above is the historical checkpoint,
not the current pin.
