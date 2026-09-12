"""The execution authorization record: what a decision was made under, persisted.

WHY. Enforcement without a record decides correctly and cannot show that it
did. The execution descriptor seam re-resolves the selected policy and refuses
a mismatch, so a decision is MADE under a known policy; until this record
nothing persisted WHICH policy, WHICH requirements, or WHAT answered them, so
no after-the-fact review could tell a correctly resolved authorization from a
weakened one that happened to match. Measured before this module existed:
``pending_actions.authorization`` held seven identity fields and no
requirements, and ``executions`` held the ``Judgment`` and no authorization at
all — the row recording that a side effect happened said nothing about what
authorized it.

THE RECORD. One versioned JSON object, written to ``pending_actions.authorization``
at hold creation (and never rewritten) and to ``executions.authorization`` for
every executor outcome — executed, refused, blocked and unavailable alike::

    {
      "record_version": 1,
      "snapshot_digest": "<64 hex>", "attempt_id": "...",
      "policy_id": "...", "policy_digest": "<64 hex>", "policy_version": 1,
      "action_class": "...", "artifact_sha256": "<64 hex>", "target_canonical": "...",
      "requirements": [{"check_id": "...", "permitted": ["..."]}],       # R5
      "coverage": {                                                        # R6
        "recorded": true,
        "answered_by": {"<check_id>": "<implementation>"},
        "unavailable": [{"check_id": "...", "implementation": "..."}],
        "refusal": null | {"reason": "coverage.<row>", "check_id": "...", "detail": "..."},
        "outcome_kind": "judgment" | "unavailable",
        "verdict": "pass" | "fail" | "abstain" | null, "confidence": 0.95 | null,
        "contributing": ["..."], "unavailable_reason": null | "infra_fault" | "policy_refusal",
        "detail": "..."
      },
      "pinned_at": "<ISO-8601>"
    }

Every value is read off the seam-minted ``AuthorizedExecution`` — the
requirements and policy version off the seam's OWN re-resolution of the
selected policy, the coverage report off the assessment the bank minted —
and never off anything a caller supplied.

TWO DECISIONS WORTH ARGUING WITH.

* **Requirements are stored, not recomputed.** A reader could re-resolve the
  policy named by ``policy_id``/``policy_digest``. That works only while that
  policy is still retrievable, which is exactly the case a rotation breaks —
  and the rotated case is when a reviewer most needs to know what was
  required. Storing them moves the record's integrity from re-resolution to
  the record's own tamper-evidence, which is why a hold's record is bound into
  the audit chain (``execution/pending.py``): a JSON column alone is not a
  record anyone should trust.
* **``policy_version`` is carried beside ``policy_digest``.** The digest is the
  authority; the version is the human handle. A reviewer reading a year-old
  row should not have to resolve a hex string to know it was baseline v1 or
  v4. The redundancy is checkable: the digest commits to the version.

WHAT WAS IN THE APPROVED SCHEMA AND IS NOT HERE. ``policy_epoch``, the "opaque
rotation marker". It had no source independent of ``policy_digest`` — the
supplier hands over a policy VALUE and nothing else — so it would have been a
field that records nothing, which is this repository's own definition of a
void guard. The rotation marker IS ``policy_digest``; ``policy_version`` is
its handle. Recorded here rather than quietly dropped.

WHAT THE RECORD STILL DOES NOT DO, named rather than implied:

* It records what the policy REQUIRED and what ANSWERED. It does not record
  the evidence itself; a reviewer still cannot re-run the check from the row.
* ``answered_by`` names the implementation the coverage layer credited. It
  does not prove that implementation is what actually ran — that is the
  tier-provenance residual, and registration remains the control.
* Nothing here measures the running code. A modified interpreter writes the
  same row.
"""

from __future__ import annotations

from typing import Any, Mapping

from prometheus_protocol.core.models import Judgment
from prometheus_protocol.policy.assessment import CoverageReport
from prometheus_protocol.policy.execution import AuthorizedExecution
from prometheus_protocol.policy.snapshot import BoundRequirement

#: The record's shape. A reader tells which shape it is looking at from this,
#: not by inferring from which keys happen to be present. A row without it is
#: a pre-record blob and is refused as re-verification required.
RECORD_VERSION = 1

#: The audit-chain event under which a hold's record is bound (subject
#: ``pending:<id>``). Approval requires exactly one such entry, matching the
#: row, on a chain that verifies.
PINNED_HOLD_EVENT = "pending.hold"


def authorization_record(
    authorization: AuthorizedExecution[Any], *, pinned_at: str
) -> dict[str, Any]:
    """The record for a seam-minted authorization. ``pinned_at`` is the hold's
    creation time for a hold, and the authorization time for an execution row
    that came from no hold."""

    descriptor = authorization.descriptor
    assessment = authorization.assessment
    outcome = assessment.outcome
    report = assessment.coverage
    # Narrowed in statement position, once: the repository's type gate refuses
    # an isinstance in a ternary, because an expression-position narrowing on
    # a two-member union is exactly where a third member would vanish silently.
    verdict: str | None = None
    confidence: float | None = None
    contributing: list[str] = []
    unavailable_reason: str | None = None
    if isinstance(outcome, Judgment):
        judged = True
        verdict = outcome.verdict.value
        confidence = outcome.confidence
        contributing = list(outcome.contributing)
    else:
        judged = False
        unavailable_reason = outcome.reason.value
    coverage: dict[str, Any] = {
        "recorded": report.recorded,
        "answered_by": {check: impl for check, impl in report.answered_by},
        "unavailable": [
            {"check_id": check, "implementation": impl}
            for check, impl in report.unavailable
        ],
        "refusal": (
            None
            if report.refusal is None
            else {
                "reason": report.refusal[0],
                "check_id": report.refusal[1],
                "detail": report.refusal[2],
            }
        ),
        "outcome_kind": "judgment" if judged else "unavailable",
        "verdict": verdict,
        "confidence": confidence,
        "contributing": contributing,
        "unavailable_reason": unavailable_reason,
        "detail": outcome.detail,
    }
    return {
        "record_version": RECORD_VERSION,
        "snapshot_digest": assessment.snapshot_digest,
        "attempt_id": descriptor.attempt_id,
        "policy_id": descriptor.policy_id,
        "policy_digest": descriptor.policy_digest,
        "policy_version": authorization.policy_version,
        "action_class": descriptor.action_class,
        "artifact_sha256": descriptor.artifact_sha256,
        "target_canonical": descriptor.target_canonical,
        "requirements": [
            {"check_id": item.check_id, "permitted": list(item.permitted)}
            for item in authorization.requirements
        ],
        "coverage": coverage,
        "pinned_at": pinned_at,
    }


def is_versioned_record(record: object) -> bool:
    """Whether ``record`` is a record of the shape this module writes."""

    return isinstance(record, Mapping) and record.get("record_version") == RECORD_VERSION


def record_requirements(record: Mapping[str, Any]) -> tuple[BoundRequirement, ...]:
    """The pinned requirements, as the resolver's own type."""

    return tuple(
        BoundRequirement(
            check_id=str(item["check_id"]), permitted=tuple(str(p) for p in item["permitted"])
        )
        for item in record.get("requirements") or ()
    )


def restore_coverage(record: Mapping[str, Any]) -> CoverageReport:
    """The coverage report back out of a persisted record."""

    raw = record.get("coverage") or {}
    refusal = raw.get("refusal")
    return CoverageReport(
        answered_by=tuple(
            sorted((str(check), str(impl)) for check, impl in dict(raw.get("answered_by") or {}).items())
        ),
        unavailable=tuple(
            (str(item["check_id"]), str(item["implementation"]))
            for item in raw.get("unavailable") or ()
        ),
        refusal=(
            None
            if not refusal
            else (str(refusal["reason"]), str(refusal["check_id"]), str(refusal.get("detail", "")))
        ),
        recorded=bool(raw.get("recorded", False)),
    )
