"""Executed PROD-FIX-2 (F8) guard reverts: put each fix back the way it was, in
memory, run the tests that must go red, restore, and refuse any drift.

Same discipline and the same harness as the F11, PROM-FIX-B, substrate, PIH-4a,
TYPE-GATE and PROD-FIX-1 runners: a mutation that produces no call-phase
failure, or a run whose count differs from its pin in EITHER direction, is
itself a failure. Production files are never edited on disk.

F8 is one finding with one root cause — raw upstream text and unredacted
configuration reaching public strings — so the mutations come in two families,
and both must be load-bearing or the fix is a coincidence:

* **A2, the secret wrapper.** Each mutation puts a credential back as a raw
  value, or defeats one rendering path of the wrapper. The point of the family
  is that no single one of them is "the" fix: unwrapping ``Config``, or
  ``DbTarget``, or the provider, or the anchor client, or the signer, each
  reopens the leak on its own, which is why a per-field opt-out was never going
  to hold.
* **A1/A3/A5/A6, the bounded vocabulary.** Each mutation lets upstream bytes
  back into a diagnostic — by quoting an error body, by naming a redirect
  target, by reading ``JSONDecodeError.doc``, by leaving the exception chain
  intact, or by opening the reason/context allowlists.

The A4 mutation is listed with the second family because it is the same defect
on the SUCCESS path: writing the model's reply into ``Evidence.detail`` again.

WHAT THIS DOES AND DOES NOT PROVE. It proves the pinned mutations still make
their tests go red — that these guards are load-bearing today. It does NOT
prove the mutation set is complete, and the count says nothing about semantic
coverage. Nor is it externally anchored: the runner, its pins and its mutation
list are editable in one change by whoever edits the code under test.

Run with the repository's test environment:
    python scripts/prod_fix_2_revert_proofs.py
"""

from prometheus_protocol.chokepoint import runner, signer
from prometheus_protocol.core import config, diagnostics, secrets, transport
from prometheus_protocol.ledger import anchor_http
from prometheus_protocol.provider import remote
from prometheus_protocol.verifier import model_judge

import fix_b_revert_proofs as harness

SWEEP = "tests/conformance/test_secret_canary_sweep.py"
SINKS = "tests/conformance/test_secret_sink_regressions.py"

#: Observed first, then pinned — never predicted. Both a shortfall and an excess
#: are refused: a runner that quietly stops executing proofs would print a
#: smaller number and exit 0, and one that starts catching unrelated failures is
#: no longer measuring what it claims to.
EXPECTED_REVERTS = 15
EXPECTED_CALL_FAILURES = 24


def enforce_expected(caught: int, failures: int) -> None:
    if caught != EXPECTED_REVERTS or failures != EXPECTED_CALL_FAILURES:
        raise AssertionError(
            f"PROD-FIX-2 revert count drifted: {caught} reverts / {failures} "
            f"call-phase failures observed, {EXPECTED_REVERTS} / "
            f"{EXPECTED_CALL_FAILURES} pinned. A proof was added, removed or "
            "stopped executing; update the pin in the same change that changes "
            "the mutation list, never alone."
        )


def mutations():
    """(name, function, [(old, new)], test file, -k selection)."""

    return [
        # -- A2: the wrapper itself -------------------------------------------
        (
            # The whole of A2 in one line: if the VALUE renders, nothing else
            # matters, because every container eventually renders its contents.
            "secret-renders-its-value-again",
            secrets.Secret.__repr__,
            [('    return f"Secret({REDACTED})"', '    return f"{self._value}"')],
            SWEEP,
            "rendering_path or new_field_added_later or wrapped_credentials_are_still_usable",
        ),
        (
            # `asdict` deep-copies every non-dataclass field value, so
            # `__deepcopy__` decides what comes out the other side. The plausible
            # mistake is "a deep copy of a wrapper should be a copy of the DATA" —
            # which unwraps the credential into every asdict and every JSON built
            # from one.
            #
            # Note what is NOT pinned here: returning `Secret(self._value)`
            # instead of `self` does NOT leak, because the copy is still a
            # Secret. That variant was tried and produced no failure, so it is
            # not claimed as a proof. Returning self is an identity property;
            # returning the VALUE is the leak.
            "secret-deep-copies-to-its-raw-value",
            secrets.Secret.__deepcopy__,
            [("    return self", "    return self._value")],
            SINKS,
            "asdict_and_vars or dbtarget_asdict",
        ),
        (
            # The normaliser. A single "it is already a str, leave it" reopens
            # every caller that passes a raw value.
            "secret_or_none-passes-raw-values-through",
            secrets.secret_or_none,
            [("    return Secret(value)", "    return value")],
            SWEEP,
            "rendering_path or credential_is_still_reachable or wrapped_credentials",
        ),
        # -- A2: each storage site, because none of them is "the" fix ----------
        (
            "config-stores-the-credential-raw-again",
            config.Config.__post_init__,
            [(
                "    for name in SECRET_FIELDS:\n"
                "        object.__setattr__(self, name, secret_or_none(getattr(self, name)))",
                "    pass",
            )],
            SWEEP,
            "rendering_path or new_field_added_later",
        ),
        (
            # The measured case: repr=False was already there and asdict still
            # published the password.
            "dbtarget-stores-the-password-raw-again",
            runner.DbTarget.__post_init__,
            [(
                "    if not isinstance(self.password, Secret):\n"
                '        object.__setattr__(self, "password", Secret(self.password))',
                "    pass",
            )],
            SINKS,
            "dbtarget_asdict",
        ),
        (
            # A plain class: no field to annotate, no repr to set. Found by the
            # canary sweep, not by reading the class.
            "provider-stores-the-api-key-raw-again",
            remote.RemoteModelProvider.__init__,
            [(
                "    self.api_key = secret_or_none(api_key)",
                "    self.api_key = api_key",
            )],
            SWEEP,
            "plain_class_stores_a_credential or wrapped_credentials_are_still_usable",
        ),
        (
            "anchor-client-stores-the-token-raw-again",
            anchor_http.HttpAppendOnlyLog.__init__,
            [(
                "    self._token = secret_or_none(token)",
                "    self._token = token",
            )],
            SWEEP,
            "plain_class_stores_a_credential or wrapped_credentials_are_still_usable",
        ),
        (
            # The one with the most at stake: this key mints approvals.
            "signer-stores-the-signing-key-raw-again",
            signer.LocalHmacSigner.__init__,
            [(
                "    self._key = Secret(raw)",
                "    self._key = raw",
            )],
            SWEEP,
            "plain_class_stores_a_credential or wrapped_credentials_are_still_usable",
        ),
        # -- A1: raw upstream text back in a diagnostic ------------------------
        (
            # The review's headline sink: "endpoint returned HTTP 401: Bearer
            # <CANARY>". The body is already being drained; this keeps it.
            "provider-quotes-the-error-body-again",
            remote.RemoteModelProvider._http_failure,
            [
                # The body is drained exactly once, so the revert has to KEEP
                # those bytes rather than read again from an exhausted stream —
                # which is what the pre-fix code did.
                (
                    "    body_bytes = -1\n"
                    "    timed_out = False\n"
                    "    try:\n"
                    "        body_bytes = len(self._read_bounded(exc, deadline, limit=_ERROR_BODY_BYTES))",
                    "    body_bytes = -1\n"
                    "    timed_out = False\n"
                    "    quoted = b\"\"\n"
                    "    try:\n"
                    "        quoted = self._read_bounded(exc, deadline, limit=_ERROR_BODY_BYTES)\n"
                    "        body_bytes = len(quoted)",
                ),
                (
                    "    context: dict[str, object] = {\"status\": int(exc.code), **self._where()}\n"
                    "    if body_bytes >= 0:\n"
                    "        context[\"bytes_read\"] = body_bytes\n"
                    "    return ProviderHTTPError(exc.code, Diagnostic(http_reason(exc.code), context).message())",
                    "    return ProviderHTTPError(\n"
                    "        exc.code,\n"
                    "        f\"endpoint returned HTTP {exc.code}: \"\n"
                    "        + quoted.decode(\"utf-8\", \"replace\")[:500],\n"
                    "    )",
                ),
            ],
            SWEEP,
            "failing_provider_call or log_record_at_any_level",
        ),
        (
            # The reason allowlist. Open it and prose — which is where upstream
            # bytes get in — becomes a valid diagnostic again.
            "diagnostic-accepts-any-reason-string",
            diagnostics.Diagnostic.__post_init__,
            [("    if self.reason not in REASON_CODES:", "    if False:")],
            SINKS,
            "reason_code_set_is_closed",
        ),
        (
            # The context allowlist — the denylist trap in miniature. An
            # unlisted key is refused BY NOT BEING LISTED.
            "diagnostic-accepts-any-context-key",
            diagnostics.Diagnostic.__post_init__,
            [("        if expected is None:", "        if False:")],
            SINKS,
            "context_is_an_allowlist",
        ),
        (
            # The only two string-valued keys. Unconstrain `endpoint` and a host
            # that arrived in a response is printable again.
            "diagnostic-accepts-any-endpoint-string",
            diagnostics.Diagnostic.__post_init__,
            [(
                '        if key == "endpoint" and not _is_bare_origin(str(value)):',
                '        if key == "endpoint" and False:',
            )],
            SINKS,
            "string_context_keys_cannot_smuggle",
        ),
        # -- A3, A5, A6 ---------------------------------------------------------
        (
            # A3, and a correction to what the fix actually is. Clearing
            # __context__ inside `raise_bounded` is NOT the load-bearing part:
            # removing that line alone changes nothing, because Python only
            # populates __context__ when the raise happens while an exception is
            # being handled — and the call sites raise OUTSIDE the handler. That
            # variant was tried, produced no failure, and is therefore not
            # claimed as a proof.
            #
            # The load-bearing part is the CALL PATTERN. This mutation puts the
            # raise back inside the `except`, which is the shape the pre-fix code
            # had and the one every reviewer's instinct reaches for.
            "provider-raises-inside-the-except-block-again",
            remote.RemoteModelProvider._post,
            [(
                "    except urllib.error.HTTPError as exc:\n"
                "        translated = self._http_failure(exc, deadline)",
                "    except urllib.error.HTTPError as exc:\n"
                "        raise_bounded(self._http_failure(exc, deadline))",
            )],
            SWEEP,
            "failing_provider_call",
        ),
        (
            # A5: stripping path and query is not enough, because the ATTACKER
            # CHOOSES THE HOSTNAME.
            "redirect-names-the-target-again",
            transport.RefuseRedirects.redirect_request,
            [(
                "        redirect_diagnostic(code, endpoint=origin_only(req.full_url)).message()",
                "        f\"refusing redirect to {origin_only(newurl)}\"",
            )],
            SWEEP,
            "failing_provider_call or anchor_exchange",
        ),
        # -- A4: success is also a channel --------------------------------------
        (
            # A PASSING judgement wrote the model's reply verbatim into a
            # permanent, signed, replicated record.
            "judge-writes-the-raw-model-reply-again",
            model_judge.ModelJudgeVerifier.verify,
            [(
                "    return self._evidence(verdict, duration, detail=_judgement_detail(verdict, response))",
                "    return self._evidence(verdict, duration, detail=response)",
            )],
            SWEEP,
            "SUCCESSFUL_judge_call or persisted_ledger_row",
        ),
    ]


def main() -> int:
    harness.EXPECTED_REVERTS = EXPECTED_REVERTS
    harness.EXPECTED_CALL_FAILURES = EXPECTED_CALL_FAILURES
    harness.enforce_expected = enforce_expected
    harness.mutations = mutations
    return harness.main()


if __name__ == "__main__":
    raise SystemExit(main())
