"""The Hearth ledger: the SANCTIONED CONTENT of every frozen file.

WHAT THIS REPLACES, AND WHY. Four conformance modules froze the Hearth by
diffing the working tree against ``origin/main`` and rejecting any changed path
that was not in a permitted set — ``_EX1_CHANGED | _HARDEN4_CHANGED |
_TYPE_GATE_CHANGED``. That has the shape of an allowlist and none of the effect,
because the permitted set was over PATHS while what varies is CONTENT. Two
consequences, both real and both found by independent review:

1. **A file sanctioned once was sanctioned forever.** ``gate/authorization.py``
   entered ``_EX1_CHANGED`` in PR #52. From that moment every future edit to the
   authorization gate — the single component that decides whether an action is
   permitted — was invisible to all four guards. Not "reviewed and allowed":
   invisible. The same held for the other nine EX-1 files, the two HARDEN-4
   files and the two TYPE-GATE files.

2. **On main the guard asserted nothing at all.** ``git diff origin/main`` is
   empty once the remote ref points at the same commit, so the moment a sprint
   merged, its Hearth guard went vacuous — passing not because the Hearth was
   intact but because there was nothing to compare. The guard was loudest
   exactly when it was least needed and silent afterwards.

WHAT THIS IS INSTEAD. A digest per protected file, of the content that is
sanctioned. The guard hashes the file on disk and compares. Any edit to any
protected file fails, ``gate/authorization.py`` included, until the digest here
is updated in the same change — which puts the new content in the diff, next to
the reason for it, where a reviewer sees it. A file that was sanctioned once is
not sanctioned forever; a specific STATE was sanctioned, and it stays sanctioned
only while it is that state.

WHAT THE PERMITTED SET IS OVER: the bytes of each protected file. What varies is
the bytes, and every one of them is covered — that is what a digest is.

WHAT CAN STILL VARY THAT THIS DOES NOT CONSTRAIN, stated rather than left to be
found:

* **The file list.** Deleting an entry from a guard's tuple would unfreeze that
  file. ``test_hearth_ledger.py`` pins the union of all four tuples against this
  ledger's key set and against a count, so a dropped file fails.
* **This ledger itself.** Whoever can edit the Hearth can edit these digests.
  That is true of every in-repository guard and is not fixable from inside the
  repository; what the ledger buys is that the edit is a visible, reviewable line
  in the same diff, which the path sets did not buy. (See §"receipt" in
  ``scripts/type_gate.py`` for the same limit stated about the type gate.)
* **Semantics.** A digest proves the bytes are unchanged, not that they are
  correct. The behavioural suites are what prove the Hearth still does its job.

There is deliberately NO git in this module. The comparison reference is the
ledger, not a remote branch, so the guard asserts exactly as much in a fresh
clone, in a worktree, on a feature branch, and on main after merge. The four
guards no longer carry ``skipif origin/main is unresolvable`` — that skip was how
they silently stopped running under a shallow checkout, and it is gone with the
dependency that required it.
"""

from __future__ import annotations

import hashlib
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[2]

#: The Hearth core as ``test_composition.py`` freezes it: the trusted verifier,
#: gate and execution path, plus the orchestration skeleton from PR #46.
COMPOSITION_FILES = (
    "src/prometheus_protocol/verifier/bank.py",
    "src/prometheus_protocol/verifier/aggregate.py",
    "src/prometheus_protocol/verifier/trust.py",
    "src/prometheus_protocol/gate/promotion.py",
    "src/prometheus_protocol/gate/authorization.py",
    "src/prometheus_protocol/execution/executor.py",
    "src/prometheus_protocol/execution/controller.py",
    "src/prometheus_protocol/execution/pending.py",
    "src/prometheus_protocol/forge/miner.py",
    "src/prometheus_protocol/core/models.py",
    "src/prometheus_protocol/core/interfaces.py",
    "src/prometheus_protocol/orchestration/runtime.py",
    "src/prometheus_protocol/orchestration/gateway.py",
    "src/prometheus_protocol/orchestration/messages.py",
    "src/prometheus_protocol/orchestration/workflow.py",
)

#: What ``test_extension_surface.py`` freezes: the Hearth plus the three
#: verifiers a new domain plugs in beside.
EXTENSION_SURFACE_FILES = (
    "src/prometheus_protocol/verifier/bank.py",
    "src/prometheus_protocol/gate/promotion.py",
    "src/prometheus_protocol/gate/authorization.py",
    "src/prometheus_protocol/execution/executor.py",
    "src/prometheus_protocol/execution/controller.py",
    "src/prometheus_protocol/forge/miner.py",
    "src/prometheus_protocol/core/models.py",
    "src/prometheus_protocol/verifier/runner.py",
    "src/prometheus_protocol/verifier/sql.py",
    "src/prometheus_protocol/verifier/grounding.py",
)

#: What ``test_orchestration.py`` freezes: the Hearth core the orchestration
#: layer must not reach into.
ORCHESTRATION_FILES = (
    "src/prometheus_protocol/verifier/bank.py",
    "src/prometheus_protocol/gate/promotion.py",
    "src/prometheus_protocol/gate/authorization.py",
    "src/prometheus_protocol/execution/executor.py",
    "src/prometheus_protocol/execution/controller.py",
    "src/prometheus_protocol/execution/pending.py",
    "src/prometheus_protocol/forge/miner.py",
    "src/prometheus_protocol/core/models.py",
    "src/prometheus_protocol/core/interfaces.py",
)

#: What ``test_soft_levers.py`` freezes: the Hearth plus the DEFAULT soft-judge
#: path, because the levers are opt-in wrappers and not edits to it.
SOFT_LEVER_FILES = (
    "src/prometheus_protocol/verifier/bank.py",
    "src/prometheus_protocol/verifier/aggregate.py",
    "src/prometheus_protocol/verifier/trust.py",
    "src/prometheus_protocol/gate/promotion.py",
    "src/prometheus_protocol/gate/authorization.py",
    "src/prometheus_protocol/execution/executor.py",
    "src/prometheus_protocol/execution/controller.py",
    "src/prometheus_protocol/forge/miner.py",
    "src/prometheus_protocol/core/models.py",
    "src/prometheus_protocol/core/interfaces.py",
    "src/prometheus_protocol/verifier/model_judge.py",
    "src/prometheus_protocol/verifier/grounding.py",
    "src/prometheus_protocol/benchmarks/judge_eval.py",
    "src/prometheus_protocol/benchmarks/grounding_eval.py",
)

#: Every protected file, across all four guards. Pinned by count in
#: ``test_hearth_ledger.py`` so shrinking a guard's tuple cannot pass unnoticed.
PROTECTED_FILES = tuple(sorted(
    set(COMPOSITION_FILES)
    | set(EXTENSION_SURFACE_FILES)
    | set(ORCHESTRATION_FILES)
    | set(SOFT_LEVER_FILES)
))

EXPECTED_PROTECTED_FILES = 21

#: SHA-256 of the sanctioned content of each protected file.
#:
#: The sanctioned state is the one on main at d0819bb, which is the accumulation
#: of the deltas the four guards used to name by path:
#:
#: * **EX-1 (PR #52)** — a HARD verifier that cannot execute must not abstain.
#:   Changed ``core/models.py``, ``core/interfaces.py``, ``verifier/runner.py``,
#:   ``verifier/sql.py``, ``verifier/bank.py``, ``gate/authorization.py``,
#:   ``benchmarks/judge_eval.py``, ``orchestration/runtime.py``,
#:   ``execution/controller.py``, ``execution/pending.py``.
#: * **PROM-HARDEN-MAX attacker 4** — a provider that cannot be reached returns
#:   ``Unavailable``, not an ``ABSTAIN`` Evidence. Changed
#:   ``verifier/model_judge.py`` and ``verifier/grounding.py``.
#: * **TYPE-GATE** — ``gate/promotion.py`` (``ScoreFn`` corrected to
#:   ``Sequence[LearnableTask]``, which the gate already forwarded, plus the
#:   caller-side ``OUTCOME_UNAVAILABLE`` marker the gate never returns;
#:   ``approved``, the one field the executor reads, untouched);
#:   ``benchmarks/grounding_eval.py`` (a ``.verdict`` read off an
#:   ``Evidence | Unavailable`` replaced by ``judged=None`` +
#:   ``judge_unavailable=True``); ``verifier/bank.py`` (four ratcheted
#:   ``# type: ignore[arg-type]`` replaced by ``Evidence.decided``, which states
#:   the ``__post_init__`` guarantee the ``Verdict | None`` field type could not
#:   — the fused verdict, the confidence arithmetic and the calibration writes
#:   unchanged).
#:
#: * **PROD-FIX-2 (F8)** — ``verifier/model_judge.py``. Two changes, both about
#:   what reaches a PERSISTED record. On the SUCCESS path the judge wrote the
#:   RAW MODEL RESPONSE into ``Evidence.detail``, so an endpoint reflecting the
#:   Authorization header put a bearer token into the ledger with a PASS beside
#:   it; it now writes a bounded classification (the parsed verdict and the
#:   response length). On the failure path the ``Unavailable.detail`` quoted the
#:   provider exception's text; it now names a reason code and the exception
#:   TYPE. The judge's decision logic — the prompt, ``_parse_verdict``, the
#:   Evidence fields the bank reads — is untouched.
#:
#:   ``benchmarks/judge_eval.py`` changed with it, and had to: ``parse_confidence``
#:   read the confidence back OUT of the raw reply, so the calibration metrics
#:   depended on the remote text this sprint removes. The confidence is now
#:   parsed at the judge and carried as an explicit field; this function reads
#:   that field, and still reads the legacy first-line form for any custom
#:   verifier that writes a reply into ``detail``. No metric changed.
#:
#:
#: * **PHASE-1.2a (the trusted verification-policy model)** — ``verifier/bank.py``.
#:   The sprint the net-diff-empty guard was holding this file for. ``judge`` is
#:   UNCHANGED — the decision surface in ``bank_decision_surface.json`` did not
#:   move by a single row, and that is the point: fusion was not re-tuned. What is
#:   added is ``judge_covered``, a NEW entry point in front of it that validates
#:   required coverage against the resolved policy snapshot BEFORE fusing, and
#:   refuses when a required check has no valid, satisfactory, correctly bound
#:   result. ``judge`` remains for callers that have not migrated, which is a
#:   NAMED EXPOSURE rather than an oversight: closing it means a raw
#:   ``Judgment(PASS, authoritative=True)`` must stop being sufficient for
#:   authorization, a breaking interface change and the next sprint's subject.
#:
#:
#: * **PHASE-1.2b (closing the downstream bypass)** — five files, one change.
#:   Checkpoint 2 built coverage enforcement and named its own exposure: a raw
#:   authoritative ``Judgment`` still authorized. Four surfaces took one and asked
#:   it a question a ``Judgment`` can answer with no policy ever resolved, so the
#:   system was policy-enforced on the migrated paths and unenforced everywhere
#:   else. Each of these files loses the parameter an unbound verdict arrived
#:   through, and gains one that takes a ``PolicyAssessment`` instead:
#:
#:   - ``verifier/bank.py`` — ADDS ``assess``, which wraps what ``judge_covered``
#:     already returned in a snapshot-bound assessment. ``judge`` and
#:     ``judge_covered`` are untouched; the 240-row decision surface does not move.
#:   - ``gate/authorization.py`` — ``ActionGate.decide`` takes an assessment.
#:   - ``execution/controller.py`` — ``submit`` takes ``assessment=``. The old
#:     ``judgment=`` keyword is REMOVED rather than deprecated: leaving it would
#:     leave the bypass reachable by a caller that never migrated.
#:   - ``orchestration/gateway.py`` — ``route_action`` and the ``SubmitFn``
#:     protocol carry an assessment. The gateway still authorizes nothing.
#:   - ``orchestration/runtime.py`` — resolves a snapshot per action and binds the
#:     grader's evidence, so a caller-chosen grader can no longer authorize a
#:     sandbox execution by being present.
#:
#:
#: * **PHASE-1.2c COMMIT ONE (correcting the docstrings)** —
#:   ``gate/authorization.py`` and ``execution/controller.py``. **Comment-only.
#:   No statement, signature, parameter or branch changed in either file**; both
#:   diffs are additions to a docstring. They are here because an independent
#:   review found the docstrings claiming properties the code does not have, and
#:   a false claim in the file a reader opens first is the failure mode this
#:   repository keeps correcting — so it is corrected BEFORE the sprint that
#:   makes the claims true, not in the same commit.
#:
#:   - ``gate/authorization.py`` — ``ActionGate.decide`` now records that it
#:     reads ``assessment.outcome`` and NOTHING else: ``action`` is never
#:     compared with ``artifact_sha256`` or ``action_class``, and
#:     ``snapshot_digest`` is compared with nothing. Measured: an assessment for
#:     artifact A approves code B, and a ``sandbox.execute`` assessment approves
#:     a ``git_delete_branch``.
#:   - ``execution/controller.py`` — ``submit`` now records that it is one door
#:     and not the door. ``PendingActionService.hold`` takes a ``GateDecision``
#:     and no assessment; measured, a routed decision carrying
#:     ``Judgment(FAIL, 1.0, authoritative=True)`` is held, approved and
#:     executed (one executor call).
#:
#:   The digests move because the bytes moved. Nothing either file DOES moved,
#:   which is the whole reason this sanction is a small one.
#:
#: Those sprints are why these bytes are what they are. They do NOT license the
#: next edit to the same files: updating a digest below is a fresh decision, and
#: the reason for it belongs beside it.
DIGESTS: dict[str, str] = {
    "src/prometheus_protocol/benchmarks/grounding_eval.py":
        "c60d17487aabd916fa79d57f5ddcdf301813186e704a937081d92db191143d01",
    "src/prometheus_protocol/benchmarks/judge_eval.py":
        "25430b5645aff6f655cfaccf33edd9e1cea3e5b4d0c62ef7f23183d9da9f3866",
    "src/prometheus_protocol/core/interfaces.py":
        "ae8009021b8f604d69646f1097d6f47900a2305b765b5e8e12ffa73ac7968d15",
    "src/prometheus_protocol/core/models.py":
        "1355a91dfdbc0cd1ad4e3f12c9d4bb02b0548858973e1b583a82daebbc61e48c",
    "src/prometheus_protocol/execution/controller.py":
        "c0d2ece310a3d96c7405d18e2973bace2b93acac55666a180c29a8a86a71b5fb",
    "src/prometheus_protocol/execution/executor.py":
        "41f01a1c4e08826fe81fb738de882bdfaa73a26184b1391ff4a016a9daba85a5",
    "src/prometheus_protocol/execution/pending.py":
        "4316a1eab626c4e5dff58415870216f9acf069aebbbc9f576970747ae279934f",
    "src/prometheus_protocol/forge/miner.py":
        "b0e2a53440df5b38a1031cc9648e19b3f9df20081ee34d4e035beda2b6973a29",
    "src/prometheus_protocol/gate/authorization.py":
        "1c35a59f34459fbd1de358425712b7d021f577af718050ef4b8d328a4fd067e6",
    "src/prometheus_protocol/gate/promotion.py":
        "4c66123b363dbfe663707442761717bae3a69a8e7b0192413170ed8dbebecb22",
    "src/prometheus_protocol/orchestration/gateway.py":
        "b59813d5b42bad12b83329b7b2e0d68db4591b465546bf9aab5ecb6863cbd4bc",
    "src/prometheus_protocol/orchestration/messages.py":
        "bf2d1ff2e986c97aa4bc9c832f0cc18c1950740213dae6c4dc061e84e1073e1e",
    "src/prometheus_protocol/orchestration/runtime.py":
        "c8b1daeef56c92a95a7d4ae6917362920f90dd254370c3b75aeb3b12ee552540",
    "src/prometheus_protocol/orchestration/workflow.py":
        "5192847972a44f58d52f838db294c3cdc801d97e1b4bb7bc144fc808fef30e3b",
    "src/prometheus_protocol/verifier/aggregate.py":
        "5963bb6b4047c0ec2c900b10187e861ad95541dca87c0b98bdb5db34dcd1c37c",
    "src/prometheus_protocol/verifier/bank.py":
        "643d7394e0c8932f1598738365ac9f0539a0820f5c452326155ca5dcd42a6f2d",
    "src/prometheus_protocol/verifier/grounding.py":
        "edb44c93c371cbf4a5099e607f4de0332d1bb902d47913bdd3708d5be1b4da3f",
    "src/prometheus_protocol/verifier/model_judge.py":
        "bd0c73eea1f36e81bd5fdff7d2734b6c8d9b11580f700e08ce52f40ba3600937",
    "src/prometheus_protocol/verifier/runner.py":
        "4d7f810f2cc019593ef388792a992903de75b89525130723d8fb72e2ec234e96",
    "src/prometheus_protocol/verifier/sql.py":
        "4a01962dc971c7426a72a5a26e6645cf64bc786aae9c5c87f5aa319b463a3a6b",
    "src/prometheus_protocol/verifier/trust.py":
        "e043b87e1b03613a18e7fa9ec037759f8049ca731b7cbe9d5bbac7622322792e",
}


def digest_of(relative_path: str, root: pathlib.Path | None = None) -> str:
    """SHA-256 of a protected file's bytes, read from ``root`` (default: repo)."""

    return hashlib.sha256(((root or REPO) / relative_path).read_bytes()).hexdigest()


def unsanctioned_changes(
    paths: tuple[str, ...], root: pathlib.Path | None = None
) -> list[str]:
    """Every protected file in ``paths`` whose content is not the sanctioned one.

    ``root`` exists so the guard can be pointed at a synthetic tree and PROVED to
    report a change — see ``test_the_ledger_actually_detects_a_changed_file``. A
    guard that cannot be shown to fire is a guard nobody has checked.
    """

    findings = []
    for relative_path in paths:
        sanctioned = DIGESTS.get(relative_path)
        if sanctioned is None:
            findings.append(
                f"{relative_path}: protected but absent from the ledger — add its "
                "sanctioned digest, do not drop it from the guard"
            )
            continue
        actual = digest_of(relative_path, root)
        if actual != sanctioned:
            findings.append(
                f"{relative_path}: content is {actual[:16]}…, sanctioned state is "
                f"{sanctioned[:16]}…"
            )
    return findings


UNSANCTIONED_MESSAGE = (
    "A frozen file's content is not the sanctioned content. This is not a "
    "diff against a branch — it is the bytes on disk against the bytes this "
    "repository agreed to. If the change is intended, update the digest in "
    "tests/conformance/hearth_ledger.py in THIS change, with the reason beside "
    "it, so the new content is reviewed rather than inherited. Adding the path "
    "to a permitted list is what this replaced: it sanctioned the file forever "
    "instead of sanctioning a state."
)
