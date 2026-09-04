"""What the runner zone holds at rest, and where it can spill (threat model §2).

Attacker 2 does not need to break the chokepoint if the chokepoint prints its
own secrets. Two dataclasses held them in plain fields, and a dataclass renders
every field in ``repr`` by default, so a log line, an f-string, or any traceback
frame carrying a target or a config published the database password and the
approval signing key verbatim. That converts "someone can read a log" into
"someone can mint approvals" — the same secret as threat model §1's A1-1, out a
different exit.

These also cover the credential's *lifetime*: a ``password_provider`` lets a
deployment hold no standing credential at all, fetching it at the moment of use.
No claim is made that the value is scrubbed from memory afterwards — Python
strings are immutable and may be copied — and a test asserting a wipe we cannot
perform would be exactly the void guard this project is named for.
"""

from __future__ import annotations

import json
import traceback

import pytest

from prometheus_protocol.chokepoint import (
    ApprovalAuthority,
    DbTarget,
    MigrationRunnerConfig,
)

PASSWORD = "prom-attacker2-db-password-9c4d17ba"
SIGNING_KEY = b"prom-attacker2-signing-key-000000"


def _target(**overrides) -> DbTarget:
    fields = dict(
        host="127.0.0.1", port=5432, dbname="appdb", user="migrator",
        password=PASSWORD, schema="public",
    )
    fields.update(overrides)
    return DbTarget(**fields)


# ---------------------------------------------------------------------------
# The credential does not render
# ---------------------------------------------------------------------------


def test_the_password_is_not_in_the_target_repr():
    assert PASSWORD not in repr(_target())


def test_the_password_is_not_in_the_target_str():
    assert PASSWORD not in str(_target())


def test_the_password_is_not_in_a_formatted_message():
    target = _target()
    assert PASSWORD not in f"connecting to {target}"
    assert PASSWORD not in f"connecting to {target!r}"
    assert PASSWORD not in "{}".format(target)


def test_the_password_is_not_in_a_traceback():
    """The realistic spill: an exception carrying the target, rendered into a log."""

    target = _target()
    try:
        raise RuntimeError(f"migration failed against {target!r}")
    except RuntimeError:
        rendered = traceback.format_exc()
    assert PASSWORD not in rendered


def test_the_signing_key_is_not_in_the_config_repr():
    config = MigrationRunnerConfig(
        target=_target(), signing_key=SIGNING_KEY, approval_store_path="/var/lib/prom/x.db",
    )
    rendered = repr(config)
    assert PASSWORD not in rendered, "the config repr leaks the database password"
    assert SIGNING_KEY.decode() not in rendered, "the config repr leaks the signing key"
    assert str(SIGNING_KEY) not in rendered


def test_the_target_still_renders_something_useful():
    """Redaction must not make operations blind: identity is what you want in a
    log, and it is exactly the credential-free part."""

    target = _target()
    rendered = str(target)
    assert "appdb" in rendered and "migrator" in rendered and "127.0.0.1" in rendered
    assert json.loads(rendered)["database"] == "appdb"


def test_the_identity_an_approval_binds_carries_no_credential():
    identity = _target().identity
    assert PASSWORD not in repr(identity)
    assert PASSWORD not in identity.canonical
    assert "password" not in identity.to_dict()


# ---------------------------------------------------------------------------
# The credential is still usable — redaction that broke it would be worse
# ---------------------------------------------------------------------------


def test_the_password_is_still_reachable_for_connecting():
    assert _target().resolve_password() == PASSWORD


# ---------------------------------------------------------------------------
# Lifetime: a deployment can hold no standing credential
# ---------------------------------------------------------------------------


def test_a_provider_is_consulted_instead_of_a_stored_credential():
    calls: list[int] = []

    def fetch() -> str:
        calls.append(1)
        return PASSWORD

    target = _target(password="", password_provider=fetch)

    assert calls == [], "the provider was called before the credential was needed"
    assert target.resolve_password() == PASSWORD
    assert calls == [1], "the credential should be fetched at the moment of use"
    assert target.resolve_password() == PASSWORD
    assert calls == [1, 1], "each use should fetch again rather than cache"


def test_a_provider_backed_target_stores_no_credential():
    target = _target(password="", password_provider=lambda: PASSWORD)
    assert target.password == ""
    assert PASSWORD not in repr(target)
    # An idle runner configured this way holds nothing worth stealing in the
    # object graph; the secret exists only for the length of a connect call.
    assert PASSWORD not in repr(
        MigrationRunnerConfig(
            target=target, signing_key=SIGNING_KEY, approval_store_path="/var/lib/prom/x.db",
        )
    )


def test_a_provider_does_not_change_the_bound_identity():
    """Rotating or re-sourcing a credential must not invalidate approvals, and
    must not silently change what an approval is bound to."""

    stored = _target()
    provided = _target(password="", password_provider=lambda: PASSWORD)
    assert stored.identity == provided.identity
    assert stored.identity.canonical == provided.identity.canonical


def test_a_failing_provider_surfaces_rather_than_connecting_with_nothing():
    def broken() -> str:
        raise RuntimeError("vault unreachable")

    target = _target(password="", password_provider=broken)
    with pytest.raises(RuntimeError):
        target.resolve_password()


# ---------------------------------------------------------------------------
# The authority does not render its key either
# ---------------------------------------------------------------------------


def test_the_approval_authority_does_not_expose_its_key_in_repr():
    authority = ApprovalAuthority(key=SIGNING_KEY)
    rendered = repr(authority)
    assert SIGNING_KEY.decode() not in rendered
    assert str(SIGNING_KEY) not in rendered
