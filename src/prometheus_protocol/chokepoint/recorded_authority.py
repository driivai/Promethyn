"""Production record-then-sign authority. The primitive signer is not a gate."""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable

from prometheus_protocol.chokepoint.approval import (
    APPROVAL_VERSION,
    DEFAULT_TTL_SECONDS,
    Approval,
    ApprovalAuthority,
    MigrationArtifact,
    MigrationTarget,
)
from prometheus_protocol.chokepoint.authorization_journal import (
    AuthorizationJournal,
    AuthorizationReceipt,
    AuthorizationUnavailable,
)
from prometheus_protocol.chokepoint.authorization_record import (
    FIELDS,
    AuthorizationContext,
    AuthorizationRecord,
    binding_preimage,
    finite_time,
    hex_bytes,
    target_bytes,
    text,
)
from prometheus_protocol.chokepoint.signer import (
    HMAC_SHA256,
    ApprovalSigner,
    KmsSigner,
    PublicKeyVerifier,
    SignerCapabilityAbsent,
    SignerMalformed,
    SignerUnavailable,
)
from typing import TYPE_CHECKING

from prometheus_protocol.core.models import Judgment, Unavailable, Verdict
from prometheus_protocol.policy.snapshot import ACTION_DATABASE_MIGRATE

if TYPE_CHECKING:  # pragma: no cover - import cycle: policy imports core.models
    from prometheus_protocol.policy.assessment import PolicyAssessment


class RecordedApprovalAuthority(ApprovalAuthority):
    def __init__(
        self,
        *,
        signer: ApprovalSigner,
        journal: AuthorizationJournal,
        context: AuthorizationContext,
        clock: Callable[[], float],
    ) -> None:
        super().__init__(signer=signer)
        self._journal = journal
        self._context = context.snapshot()
        self._clock = clock
        self._scheme, self._key_id = signer.scheme, signer.key_id
        self._check_signer()

    @property
    def journal(self) -> AuthorizationJournal:
        return self._journal

    def _check_signer(self) -> None:
        signer = self.signer
        identity = self._context.signer
        if signer.scheme != self._scheme or signer.key_id != self._key_id:
            raise AuthorizationUnavailable("signer identity changed")
        text(signer.key_id, maximum=128)
        if signer.scheme == HMAC_SHA256:
            if signer.external or identity["backend"] != "local-hmac":
                raise AuthorizationUnavailable("local signer identity mismatch")
            if identity["key_resource"] != signer.key_id:
                raise AuthorizationUnavailable("local signer key identity mismatch")
        else:
            public = getattr(signer, "public_key_der", None)
            if (
                not signer.external
                or not isinstance(public, bytes)
                or identity["backend"] == "local-hmac"
                or hashlib.sha256(public).hexdigest() != identity["public_key_sha256"]
            ):
                raise AuthorizationUnavailable(
                    "external signer public identity mismatch"
                )
            if (
                isinstance(signer, KmsSigner)
                and identity["caller_subject"] != signer.principal
            ):
                raise AuthorizationUnavailable("signer caller identity mismatch")

    def mint(self, **kwargs) -> Approval:
        if isinstance(self.signer, PublicKeyVerifier):
            raise SignerCapabilityAbsent("this authority can only verify")
        raise AuthorizationUnavailable(
            "production issuance requires authorize and a durable decision"
        )

    @staticmethod
    def _receipt(receipt: object, record: AuthorizationRecord) -> None:
        if not isinstance(receipt, AuthorizationReceipt):
            raise AuthorizationUnavailable("missing durable authorization receipt")
        if (
            type(receipt.seq) is not int
            or receipt.seq < 1
            or receipt.authorization_id != record.authorization_id
            or receipt.authorization_record_hash != record.record_hash
        ):
            raise AuthorizationUnavailable("unbound durable authorization receipt")
        hex_bytes(receipt.entry_hash, 32)
        hex_bytes(receipt.ledger_id, 32)

    def _result(
        self,
        record: AuthorizationRecord,
        *,
        state: str,
        reason: str,
        approval: Approval | None = None,
    ) -> None:
        payload = {
            "version": 1,
            "authorization_id": record.authorization_id,
            "authorization_record_hash": record.record_hash,
            "observed_at": finite_time(self._clock()).hex(),
            "state": state,
            "reason": reason,
            "provider_request_id": None,
            "approval": approval.to_dict() if approval is not None else None,
        }
        self._receipt(self._journal.record_sign_result(record, payload), record)

    def authorize(
        self,
        assessment: "PolicyAssessment",
        *,
        artifact: MigrationArtifact,
        target: MigrationTarget,
        now: float,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
    ) -> Approval | None:
        """PHASE-1.2b — the RECORDED authority, and the one production uses.

        ``build_migration_runtime`` builds this class, not the base
        ``ApprovalAuthority``, so this override is the migration path's real
        authorization surface. It took a raw ``Judgment`` and minted a signed
        single-use capability against a privileged database principal from it.

        The refusal is RECORDED rather than raised, unlike the other three
        surfaces. That is deliberate and is this class's whole contract: every
        authorization attempt produces an authorization record, and an attempt
        that arrived unbound is exactly the kind a reviewer needs to see. Raising
        here would leave no record of the attempt at all.
        """

        from prometheus_protocol.policy.assessment import PolicyAssessment

        # Statement form, not a ternary: the type gate refuses a union narrowed
        # in expression position, and it is right to. ``judgment`` below is read
        # for a verdict, and a narrowing that happens inside an expression is the
        # shape that has silently dropped a member here before.
        if isinstance(assessment, PolicyAssessment):
            judgment: Judgment | Unavailable | object = assessment.outcome
        else:
            judgment = assessment
        # Snapshot before I/O; mutable caller inputs never become the bytes
        # signed after the journal/anchor round trip.
        context = self._context.snapshot()
        value = dict.fromkeys(FIELDS)
        value.update(
            record_version=1,
            authorization_id=secrets.token_hex(16),
            request_id=secrets.token_hex(16),
            recorded_at=finite_time(self._clock()).hex(),
            requester=context.requester,
            gate_identity=context.gate_identity,
            policy_sha256=context.policy_sha256,
            decision="refused",
            reason="invalid_request",
            approval_version=APPROVAL_VERSION,
            binding_version=2,
            scheme=self._scheme,
            approval_key_id=self._key_id,
            signer=context.signer,
        )
        try:
            if not isinstance(artifact, MigrationArtifact):
                raise TypeError("invalid artifact")
            digest = artifact.sha256
            hex_bytes(digest, 32)
            value["artifact_sha256"] = digest
            if not isinstance(target, MigrationTarget):
                raise TypeError("invalid target")
            target_bytes(target.to_dict())
            value["target"] = target.to_dict()
            issued, ttl = finite_time(now), finite_time(ttl_seconds)
            expires = finite_time(issued + ttl)
            if ttl <= 0 or expires <= issued:
                raise ValueError("invalid expiry")
            value.update(
                nonce=secrets.token_hex(16),
                issued_at=issued.hex(),
                expires_at=expires.hex(),
                approval_version=APPROVAL_VERSION,
                binding_version=2,
                scheme=self._scheme,
                approval_key_id=self._key_id,
                signer=context.signer,
            )
            preimage = binding_preimage(value)
            value.update(
                approval_preimage=preimage.hex(),
                approval_digest=hashlib.sha256(preimage).hexdigest(),
            )
            if not isinstance(assessment, PolicyAssessment):
                # An unbound judgment reached the migration authority. Refused
                # and RECORDED under its own reason, so it is separable in the
                # journal from a verdict that failed on its merits.
                value["reason"] = "unbound_authorization"
            elif assessment.action_class != ACTION_DATABASE_MIGRATE:
                value["reason"] = "wrong_action_class"
            elif assessment.artifact_sha256 != digest:
                value["reason"] = "assessment_artifact_mismatch"
            elif assessment.target_canonical != target.canonical:
                value["reason"] = "assessment_target_mismatch"
            elif isinstance(judgment, Unavailable):
                value["reason"] = "verifier_unavailable"
            elif not isinstance(judgment, Judgment):
                value["reason"] = "invalid_request"
            elif judgment.authoritative is not True:
                value["reason"] = "non_authoritative"
            elif judgment.verdict != Verdict.PASS:
                value["reason"] = "verdict_fail"
            elif context.requester["identity_source"] == "unknown":
                value["reason"] = "requester_unavailable"
            else:
                value.update(decision="authorised", reason="authoritative_pass")
        except (TypeError, ValueError, OverflowError, UnicodeError):
            # Retain only independently validated artifact/target evidence.
            for key in (
                "nonce",
                "issued_at",
                "expires_at",
                "approval_digest",
                "approval_preimage",
            ):
                value[key] = None
        try:
            self._check_signer()
        except AuthorizationUnavailable:
            value.update(
                decision="refused", reason="security_configuration_unavailable"
            )
        try:
            record = AuthorizationRecord.create(value)
        except (TypeError, ValueError, OverflowError, UnicodeError):
            # A request can exceed the aggregate limit despite individually
            # valid fields (notably JSON-escaped target + its hex preimage).
            # Record a bounded refusal, never truncate into another identity.
            value.update(
                decision="refused",
                reason="invalid_request",
                target=None,
                nonce=None,
                issued_at=None,
                expires_at=None,
                approval_digest=None,
                approval_preimage=None,
            )
            record = AuthorizationRecord.create(value)
        receipt = self._journal.record_decision(record)
        self._receipt(receipt, record)
        if value["decision"] == "refused":
            return None

        # The one and only production Sign call is dominated by the append and
        # its bound receipt. No restart/retry entry point accepts this record.
        current = finite_time(self._clock())
        if current < issued or current >= expires:
            self._result(record, state="unavailable", reason="expired_before_sign")
            raise AuthorizationUnavailable("approval interval elapsed before signing")
        try:
            self._check_signer()
        except AuthorizationUnavailable:
            self._result(record, state="unavailable", reason="signer_identity_changed")
            raise
        try:
            signature = self.signer.sign(preimage)
            if not isinstance(signature, bytes) or not self.signer.verify(
                preimage, signature
            ):
                raise SignerMalformed("invalid signer response")
        except SignerUnavailable as exc:
            state = {
                "denied": "denied",
                "malformed": "malformed",
                "no-signing-capability": "unavailable",
            }.get(exc.kind, "outcome_unknown")
            self._result(record, state=state, reason="signer_" + state)
            # Do not let an adapter's raw exception text escape to the caller.
            raise type(exc)("signer unavailable; no approval issued") from None
        except Exception:  # noqa: BLE001 - unknown signing outcomes must withhold the approval
            self._result(
                record, state="outcome_unknown", reason="signer_outcome_unknown"
            )
            raise SignerUnavailable(
                "signing outcome unknown; no approval issued"
            ) from None
        approval = Approval.from_dict(
            {
                "version": APPROVAL_VERSION,
                "artifact_sha256": value["artifact_sha256"],
                "target": value["target"],
                "nonce": value["nonce"],
                "issued_at": issued,
                "expires_at": expires,
                "scheme": self._scheme,
                "key_id": self._key_id,
                "signature": signature.hex(),
            }
        )
        self._result(
            record, state="signed", reason="signature_verified", approval=approval
        )
        self._check_signer()
        current = finite_time(self._clock())
        if current < issued or current >= expires:
            raise AuthorizationUnavailable("approval interval elapsed before delivery")
        return approval
