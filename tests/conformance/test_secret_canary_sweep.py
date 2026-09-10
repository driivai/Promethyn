"""F8: a unique canary through every public output surface, found in none of them.

A per-sink fix list cannot prove absence. The independent review reproduced one
canary token reaching roughly twenty-five distinct sinks; fixing twenty-five
sinks proves twenty-five things and says nothing about the twenty-sixth. So this
module is the mechanism, and the fixes are what make it pass.

WHAT A "PUBLIC OUTPUT SURFACE" IS HERE — the list the review named, each asserted
below: ``str(exc)``, ``repr(exc)``, ``exc.args``, the ``__cause__`` and
``__context__`` chains AS TRAVERSED (not merely as ``traceback`` chooses to
render them), every public result object's ``repr``/``str``/``asdict``/JSON,
``Evidence.detail`` and ``Unavailable.detail``, ledger rows read back FROM DISK,
and captured log output at DEBUG and above.

HOW SURFACES ARE DISCOVERED, so a NEW sink is covered without editing a list:

* **credential-bearing dataclass fields** are found by walking every module
  under ``prometheus_protocol``, taking every dataclass, and matching field
  NAMES against a credential-shaped pattern. A field added next year called
  ``webhook_secret`` is discovered by that alone. The test then requires each to
  be a :class:`Secret`, so the redaction is a property of the type rather than a
  per-field opt-out somebody must remember.
* **credential-bearing ATTRIBUTES of plain classes** are found by parsing the
  source and matching ``self.<credential-shaped> = …`` assignments, requiring
  each to route through a wrapper. This axis exists because the dataclass axis
  alone MISSED THREE — ``LocalHmacSigner._key``, ``RemoteModelProvider.api_key``
  and ``HttpAppendOnlyLog._token`` — all with the ``DbTarget`` shape: a careful
  ``__repr__`` and a raw value that ``vars()`` prints. Reading the source rather
  than the objects means a class nobody here knows how to construct is covered.
* **CLI subcommands** are read off the real ``argparse`` parser, so a subcommand
  added later is swept without being registered here.
* **exception chains** are walked structurally rather than compared against a
  known set of exception types, and each exception's ATTRIBUTES are rendered as
  well as its ``repr`` — one level deeper than ``repr`` goes, because that is
  where ``HTTPError.hdrs`` (the whole header block, including an echoed
  ``Authorization``) actually lives.

WHAT STILL REQUIRES MANUAL REGISTRATION, stated rather than implied:

* **the exercises — the honest limit of this sweep.** Discovery finds SURFACES;
  it cannot invent a call that reaches a new subsystem. The exercises below are
  written by hand and drive the provider (failing five ways and succeeding), the
  judge (failing AND succeeding), the anchor (read AND write), ledger chain
  verification, attestation publish and verify, the signer, reconciliation and
  the database path, every CLI subcommand, and logging at every level. A
  genuinely new subsystem needs a new exercise, and until it has one it is
  untested rather than proven clean. This is why the per-sink regression tests
  in ``test_secret_sink_regressions.py`` exist beside this file.
* **the false-positive sanctions**. ``AuditPage.next_token`` is a pagination
  cursor and ``ModelSigner._public_key`` is a public key; neither is a
  credential. Both are sanctioned by name WITH the reason, and the sanction is
  checked to still correspond to a real field. The assignment axis needs no
  sanctions at all today, and its sanction table is empty rather than
  speculative.
"""

from __future__ import annotations

import dataclasses
import importlib
import io
import json
import logging
import pkgutil
import re
import sqlite3
import textwrap
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import prometheus_protocol
from prometheus_protocol.core.secrets import Secret, secret_or_none

#: One token, unique to this module, long and distinctive enough that a partial
#: echo or a truncated quote still matches. Not random: the run must be
#: reproducible, and a fixed value is greppable when a failure names it.
CANARY = "CANARY-7f3a9d2e5b1c8406-DO-NOT-LEAK"

#: A second canary for the places a bearer token is not the secret — a database
#: password, a signing key.
CANARY_PASSWORD = "CANARY-PW-4e8b1a67c209d3f5-DO-NOT-LEAK"

ALL_CANARIES = (CANARY, CANARY_PASSWORD)


def _leaks(*blobs: object) -> list[str]:
    """Which canaries appear in any of ``blobs``. Empty is the passing case.

    CASE-INSENSITIVE, and that is not a nicety. A credential echoed into a
    redirect ``Location`` comes back as a HOSTNAME, and hostnames are
    case-insensitive — the endpoint lowercases it. A case-sensitive matcher
    silently missed the entire redirect channel, which is one of the five the
    review named; it looked like a passing sweep. Anything that could match a
    fragment of the token must match it however it was cased.
    """

    haystack = "\n".join(
        f"{b!r}" if isinstance(b, bytes) else str(b) for b in blobs
    ).casefold()
    return [c for c in ALL_CANARIES if c.casefold() in haystack]


# ---------------------------------------------------------------------------
# 1. credential-bearing fields, DISCOVERED
# ---------------------------------------------------------------------------

#: A field name that looks like it holds a credential. Deliberately broad: a
#: false positive costs one sanction line with a reason, a false negative costs a
#: leak.
_CREDENTIAL_NAME = re.compile(
    r"(?:^|_)(api_key|key|token|password|secret|bearer|credential|passphrase)s?$",
    re.IGNORECASE,
)

#: Discovered fields that are NOT credentials, each with the reason. Checked
#: below to still exist, so a sanction cannot outlive the field it excuses.
_NOT_CREDENTIALS: dict[str, str] = {
    "prometheus_protocol.chokepoint.audit_source.AuditPage.next_token":
        "a pagination cursor returned by a KMS audit API, not a secret",
    "prometheus_protocol.chokepoint.audit_source_model.ModelSigner._public_key":
        "a PUBLIC key, and a callable at that; publishing it is its purpose",
}


def _all_dataclasses():
    for module in pkgutil.walk_packages(
        prometheus_protocol.__path__, "prometheus_protocol."
    ):
        try:
            imported = importlib.import_module(module.name)
        except Exception:  # noqa: BLE001 - an unimportable module is its own problem
            continue
        for name in dir(imported):
            obj = getattr(imported, name, None)
            if (
                isinstance(obj, type)
                and dataclasses.is_dataclass(obj)
                and obj.__module__ == module.name
            ):
                yield obj


def _discovered_credential_fields() -> dict[str, dataclasses.Field]:
    found = {}
    for klass in _all_dataclasses():
        for field in dataclasses.fields(klass):
            if _CREDENTIAL_NAME.search(field.name):
                found[f"{klass.__module__}.{klass.__name__}.{field.name}"] = field
    return found


def test_every_discovered_credential_field_is_a_secret():
    """The property that makes a NEW field safe by default.

    Discovery, not a hand-written list: a credential-shaped field added later is
    found by the name pattern and must be a ``Secret``. ``repr=False`` is not
    accepted as an alternative, because ``asdict`` and ``vars`` ignore it — which
    is exactly how ``DbTarget.password`` leaked while carrying it.
    """

    offenders = []
    for path, field in sorted(_discovered_credential_fields().items()):
        if path in _NOT_CREDENTIALS:
            continue
        annotation = str(field.type)
        if "Secret" not in annotation:
            offenders.append(f"{path}: {annotation}")

    assert offenders == [], (
        f"credential-shaped field(s) not held as Secret: {offenders}. Wrap the "
        "value (core/secrets.py) rather than adding repr=False — asdict and vars "
        "do not consult field.repr, and every other rendering path has to be "
        "remembered separately. If the field genuinely is not a credential, add "
        "it to _NOT_CREDENTIALS with the reason."
    )


def test_a_field_that_also_accepts_str_must_normalise_it():
    """The hole a widened annotation would otherwise open.

    Several credential fields accept ``str`` deliberately — a caller writing
    ``Config(api_key=os.environ[...])`` should not have to know about the
    wrapper. That convenience is only safe if the value is normalised on the way
    in, so ``Secret | str`` in an annotation is required to come with a
    ``__post_init__`` that wraps it. Without this check, widening an annotation
    from ``Secret`` to ``Secret | str`` would silently satisfy the test above
    while storing raw strings again.

    Checked from the SOURCE, so it holds for a class this file cannot construct.
    """

    import ast
    import inspect

    unnormalised = []
    for path, field in sorted(_discovered_credential_fields().items()):
        if path in _NOT_CREDENTIALS:
            continue
        annotation = str(field.type)
        if "str" not in annotation and "bytes" not in annotation:
            continue  # Secret-only: nothing to normalise.
        module_name, class_name, _ = path.rsplit(".", 2)
        klass = getattr(importlib.import_module(module_name), class_name)
        try:
            source = inspect.getsource(klass)
        except OSError:  # pragma: no cover - a class without source
            unnormalised.append(f"{path} (no source to check)")
            continue
        wraps = [
            node
            for node in ast.walk(ast.parse(textwrap.dedent(source)))
            if isinstance(node, ast.Call)
            and getattr(node.func, "id", getattr(node.func, "attr", ""))
            in ("Secret", "secret_or_none")
        ]
        mentions_field = field.name in source
        if not wraps or not mentions_field:
            unnormalised.append(f"{path}: {annotation}")

    assert unnormalised == [], (
        f"credential field(s) accepting a raw str/bytes with no normalisation: "
        f"{unnormalised}. A widened annotation without a __post_init__ that "
        "wraps the value stores the credential raw — which is the defect the "
        "Secret type exists to prevent, reintroduced through the type."
    )


def test_every_credential_field_on_config_is_actually_normalised():
    """The gap between "the annotation says Secret" and "the value IS one".

    ``Config`` normalises through a TUPLE — ``SECRET_FIELDS`` — so a credential
    field added to the class but not to the tuple would satisfy both source
    checks above (the annotation names ``Secret``; the class source contains
    wrapper calls, for the OTHER fields) and still store a raw string. That is
    the same shape as every finding in this sprint: a guard that matches the
    spelling rather than the property.

    So this constructs the real class with a raw string in each discovered
    credential field and asserts what is STORED.
    """

    from prometheus_protocol.core.config import SECRET_FIELDS, Config

    discovered = {
        path.rsplit(".", 1)[1]
        for path in _discovered_credential_fields()
        if path.startswith("prometheus_protocol.core.config.Config.")
        and path not in _NOT_CREDENTIALS
    }
    assert discovered, "discovery found no Config credential; this would be vacuous"
    missing = sorted(discovered - set(SECRET_FIELDS))
    assert missing == [], (
        f"credential field(s) on Config absent from SECRET_FIELDS: {missing}. "
        "The annotation alone does not normalise anything — add the field to "
        "the tuple, which is what __post_init__ actually reads."
    )

    for name in sorted(discovered):
        stored = getattr(Config(**{name: CANARY}), name)
        assert isinstance(stored, Secret), (
            f"Config({name}=<str>) stored a {type(stored).__name__}, not a Secret"
        )
        assert stored.reveal() == CANARY, f"{name} was not preserved"
        assert not _leaks(repr(Config(**{name: CANARY})))


def test_no_sanction_outlives_the_field_it_excuses():
    discovered = _discovered_credential_fields()
    stale = sorted(set(_NOT_CREDENTIALS) - set(discovered))
    assert stale == [], f"sanction for field(s) that no longer exist: {stale}"


def test_discovery_actually_finds_the_known_credential_fields():
    """A discovery sweep that discovered nothing would pass every test above."""

    discovered = set(_discovered_credential_fields())
    for expected in (
        "prometheus_protocol.core.config.Config.api_key",
        "prometheus_protocol.core.config.Config.judge_api_key",
        "prometheus_protocol.core.config.Config.ledger_anchor_token",
        "prometheus_protocol.core.config.Config.config_attestation_token",
        "prometheus_protocol.chokepoint.runner.DbTarget.password",
    ):
        assert expected in discovered, f"discovery missed {expected}"
    assert len(discovered) >= 7, sorted(discovered)


# ---------------------------------------------------------------------------
# 1b. credential-bearing ATTRIBUTES of plain classes, DISCOVERED
#
# The dataclass sweep above reads declared fields. A plain class declares
# nothing — it just assigns in ``__init__`` — so three credentials sat outside
# it: ``LocalHmacSigner._key``, ``RemoteModelProvider.api_key`` and
# ``HttpAppendOnlyLog._token``. All three had the DbTarget shape: a careful
# ``__repr__`` (or none at all) and a raw value that ``vars()`` prints.
#
# The static signal for a plain class is the ASSIGNMENT, so this reads the
# source. It is discovery in the same sense as the sweep above: nothing is
# listed, the pattern finds it.
# ---------------------------------------------------------------------------

#: Assignments that store a credential-shaped name without wrapping it.
_WRAPPERS = ("Secret", "secret_or_none")

#: Deliberately EMPTY. Every credential-shaped assignment in the package is
#: wrapped, so nothing needs excusing, and an empty allowlist is the strongest
#: state this can be in. A future non-credential (a public key, a cursor) goes
#: here with its reason, and the staleness test below removes it again when the
#: assignment it excuses is gone.
_ASSIGNMENT_SANCTIONS: dict[str, str] = {}


def _credential_assignments() -> dict[str, str]:
    """``self.<credential-shaped> = <expr>`` across the whole package.

    Returns the ones whose right-hand side does not route through a wrapper.
    Reading the source rather than the objects means a class nobody in this file
    knows how to construct is still covered.
    """

    import ast

    offenders: dict[str, str] = {}
    root = Path(prometheus_protocol.__path__[0])
    for path in sorted(root.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - a broken module is its own problem
            continue
        module = "prometheus_protocol." + str(
            path.relative_to(root).with_suffix("")
        ).replace("/", ".").removesuffix(".__init__")
        stack: list[str] = []

        class _Visit(ast.NodeVisitor):
            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                stack.append(node.name)
                self.generic_visit(node)
                stack.pop()

            def visit_Assign(self, node: ast.Assign) -> None:
                for goal in node.targets:
                    if (
                        isinstance(goal, ast.Attribute)
                        and isinstance(goal.value, ast.Name)
                        and goal.value.id == "self"
                        and _CREDENTIAL_NAME.search(goal.attr)
                    ):
                        source = ast.unparse(node.value)
                        # Must route through a wrapper AND must not unwrap on
                        # the way. `Secret(x).reveal()` names a wrapper and
                        # stores the plaintext; without the second clause it
                        # would pass, which is the shape of every bug this
                        # sprint is about — a check that matches the word
                        # rather than the property.
                        wrapped = any(w in source for w in _WRAPPERS)
                        if not wrapped or ".reveal()" in source:
                            klass = ".".join(stack) if stack else "<module>"
                            offenders[f"{module}.{klass}.{goal.attr}"] = source
                self.generic_visit(node)

        _Visit().visit(tree)
    return offenders


def test_no_plain_class_stores_a_credential_unwrapped():
    """The gap the dataclass sweep leaves, closed by the same discipline.

    ``self._key = key`` is the whole defect: no field to annotate, no ``repr``
    to set, and ``vars(obj)`` prints it. A wrapper on the assignment is the fix,
    and it is visible in the source, so it can be required from the source.
    """

    offenders = {
        path: source
        for path, source in _credential_assignments().items()
        if path not in _ASSIGNMENT_SANCTIONS
    }
    assert offenders == {}, (
        "credential-shaped attribute(s) assigned without a Secret wrapper: "
        f"{offenders}. Store `Secret(value)` or `secret_or_none(value)` and "
        "reveal() at the point of use. A careful __repr__ is not enough — "
        "vars() and json.dumps(vars()) do not consult it. If the value "
        "genuinely is not a credential (a public key, a cursor), add it to "
        "_ASSIGNMENT_SANCTIONS with the reason."
    )


def test_no_assignment_sanction_outlives_what_it_excuses():
    """The same rule the field sanctions live under.

    A sanction that no longer names a real assignment is a hole nobody is
    watching: the code moved, the excuse stayed, and the next credential to land
    on that path is waved through.
    """

    found = _credential_assignments()
    stale = sorted(set(_ASSIGNMENT_SANCTIONS) - set(found))
    assert stale == [], f"sanction for assignment(s) that no longer exist: {stale}"


def test_the_assignment_sweep_is_not_vacuous():
    """It must be able to SEE the assignments it is judging.

    Without this, a bug in the walker (a bad path-to-module mapping, an ast
    version difference) would make every assertion above pass by finding
    nothing at all.
    """

    import ast

    seen: list[str] = []
    root = Path(prometheus_protocol.__path__[0])
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(t, ast.Attribute)
                    and isinstance(t.value, ast.Name)
                    and t.value.id == "self"
                    and _CREDENTIAL_NAME.search(t.attr)
                    for t in node.targets
                )
            ):
                seen.append(f"{path.name}:{node.lineno}")
    assert len(seen) >= 3, (
        f"the assignment walker found only {seen}; it should see at least the "
        "signer key, the provider api_key and the anchor token"
    )


def test_the_wrapped_credentials_are_still_usable():
    """Wrapping must not break authentication — the failure mode that would
    turn a redaction into an outage is an f-string sending ``Secret(<redacted>)``
    as the bearer token."""

    from prometheus_protocol.chokepoint.signer import LocalHmacSigner
    from prometheus_protocol.ledger.anchor_http import HttpAppendOnlyLog
    from prometheus_protocol.provider.remote import RemoteModelProvider

    provider = RemoteModelProvider(
        api_base="https://api.example", model="m", api_key=CANARY
    )
    assert provider.api_key is not None
    assert provider.api_key.reveal() == CANARY
    for name, rendered in _renderings(provider).items():
        assert not _leaks(rendered), f"the provider leaked through {name}"

    log = HttpAppendOnlyLog("https://anchor.example", token=CANARY)
    assert log._token is not None and log._token.reveal() == CANARY  # noqa: SLF001
    for name, rendered in _renderings(log).items():
        assert not _leaks(rendered), f"the anchor client leaked through {name}"

    key = CANARY.encode().ljust(32, b"x")
    signer = LocalHmacSigner(key)
    assert signer.sign(b"m") == LocalHmacSigner(key).sign(b"m"), "signing broke"
    for name, rendered in _renderings(signer).items():
        assert not _leaks(rendered), f"the signer leaked through {name}"


# ---------------------------------------------------------------------------
# 2. every rendering path of a secret-bearing object
# ---------------------------------------------------------------------------


def _renderings(obj: object) -> dict[str, str]:
    """Every way this repository could turn ``obj`` into text."""

    out = {"repr": repr(obj), "str": str(obj), "fstring": f"{obj}"}
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out["asdict"] = repr(dataclasses.asdict(obj))
        out["asdict_json"] = json.dumps(dataclasses.asdict(obj), default=str)
    try:
        out["vars"] = repr(vars(obj))
    except TypeError:
        out["vars"] = ""
    out["format"] = format(obj)
    out["percent"] = "%s|%r" % (obj, obj)
    return out


def _config_with_canaries():
    from prometheus_protocol.core.config import Config

    return Config(
        api_key=CANARY,
        judge_api_key=CANARY,
        ledger_anchor_token=CANARY,
        config_attestation_token=CANARY,
    )


def _target_with_canary():
    from prometheus_protocol.chokepoint.runner import DbTarget

    return DbTarget("db.internal", 5432, "appdb", "migrator", CANARY_PASSWORD)


@pytest.mark.parametrize(
    "factory", [_config_with_canaries, _target_with_canary],
    ids=["Config", "DbTarget"],
)
def test_no_rendering_path_of_a_secret_bearing_object_leaks(factory):
    subject = factory()
    for name, rendered in _renderings(subject).items():
        assert not _leaks(rendered), (
            f"{type(subject).__name__} leaked through {name}: {rendered[:300]}"
        )


def test_the_credential_is_still_reachable_where_it_is_needed():
    """The positive control. A wrapper that lost the value would pass every
    leak assertion in this file and break production."""

    assert _config_with_canaries().api_key.reveal() == CANARY
    assert _target_with_canary().resolve_password() == CANARY_PASSWORD


def test_a_new_field_added_later_is_redacted_by_default():
    """The property A2 asks for, demonstrated on a dataclass this test defines.

    Nothing about ``Config`` is special: the redaction belongs to the VALUE, so a
    field nobody has written yet is covered the moment it holds a ``Secret``.
    """

    @dataclasses.dataclass
    class FutureConfig:
        webhook_secret: Secret | None = None
        endpoint: str = "https://x.example"

    subject = FutureConfig(webhook_secret=Secret(CANARY))
    for name, rendered in _renderings(subject).items():
        assert not _leaks(rendered), f"a new field leaked through {name}"
    assert subject.webhook_secret.reveal() == CANARY


# ---------------------------------------------------------------------------
# 3. the reflecting endpoint — the review's scenario
# ---------------------------------------------------------------------------


class _Reflector(BaseHTTPRequestHandler):
    """Echoes the bearer token back in whichever channel the mode selects.

    This is the review's endpoint, not a simplified stub: the token comes back in
    a 4xx body, a 5xx body, a 200 body, a response HEADER, and a redirect
    ``Location`` HOSTNAME.
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        return

    def _token(self) -> str:
        raw = self.headers.get("Authorization", "")
        return raw[len("Bearer "):] if raw.startswith("Bearer ") else raw

    def _respond(self):
        mode = getattr(self.server, "mode", "unauthorized")
        token = self._token()
        if mode == "redirect":
            # The attacker controls the HOSTNAME. Stripping path and query does
            # not help; that is the whole of A5.
            self.send_response(302)
            self.send_header("Location", f"https://{token.lower()}.example/next")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if mode == "error_header":
            # A 4xx whose BODY says nothing but whose HEADERS echo the token.
            # This is the review's "response headers object" sink, and it is the
            # one that makes exception CHAINING observable: urllib hangs the
            # whole header block off HTTPError.hdrs, so a chained HTTPError
            # carries the credential even though its own str() does not.
            body = json.dumps({"error": "unauthorized"}).encode()
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Echo-Authorization", token)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if mode == "header":
            body = json.dumps({"choices": [{"message": {"content": "PASS 0.9"}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Echo-Authorization", token)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if mode == "ok":
            # SUCCESS IS ALSO A CHANNEL (A4): a 200 whose content echoes the
            # token, so the judge's PASS carries it into Evidence.detail.
            body = json.dumps(
                {"choices": [{"message": {"content": f"PASS 0.95 {token}"}}]}
            ).encode()
            status = 200
        elif mode == "baddecode":
            # A decoder failure whose DOCUMENT contains the canary (A6).
            body = ('{"choices": "' + token + '"} trailing-garbage').encode()
            status = 200
        else:
            status = 401 if mode == "unauthorized" else 500
            body = json.dumps({"error": f"invalid credential: Bearer {token}"}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _respond


class _ReflectorServer(ThreadingHTTPServer):
    """Declares the attribute the handler reads.

    Setting ``mode`` on a bare ``ThreadingHTTPServer`` needs a ``type: ignore``,
    and this repository does not carry those: a suppression is a place where
    the checker was told to stop looking, which is the same shape as a guard
    that cannot fail. A three-line subclass makes the attribute real.
    """

    mode: str = "unauthorized"


class _Endpoint:
    def __init__(self, mode: str) -> None:
        self.server = _ReflectorServer(("127.0.0.1", 0), _Reflector)
        self.server.mode = mode
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        address = self.server.server_address
        host, port = str(address[0]), int(address[1])
        self.base = f"http://{host}:{port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@pytest.fixture
def reflector():
    made: list[_Endpoint] = []

    def make(mode: str) -> _Endpoint:
        item = _Endpoint(mode)
        made.append(item)
        return item

    yield make
    for item in made:
        item.close()


def _provider(base: str):
    from prometheus_protocol.provider.remote import RemoteModelProvider

    return RemoteModelProvider(
        api_base=base,
        model="m",
        api_key=CANARY,
        timeout_s=5.0,
        allow_insecure_loopback=True,
    )


def _exception_surfaces(exc: BaseException) -> dict[str, str]:
    """Every way an exception can be turned into text, chain included.

    The chain is walked STRUCTURALLY — ``__cause__`` then ``__context__``,
    ignoring ``__suppress_context__`` — because that is what a log formatter or
    an error-reporting SDK does, and ``from None`` does not sever the reference.
    ``traceback.format_exception`` is asserted separately because it honours the
    suppression flag and would therefore look clean either way.
    """

    surfaces = {
        "str": str(exc),
        "repr": repr(exc),
        "args": repr(exc.args),
        "format_exception": "".join(
            traceback.format_exception(type(exc), exc, exc.__traceback__)
        ),
    }
    walked: list[str] = []
    attributes: list[str] = []
    current: BaseException | None = exc
    guard = 0
    while current is not None and guard < 20:
        walked.append(f"{type(current).__name__}: {current!r} | {current.args!r}")
        # ONE LEVEL DEEPER THAN repr, because that is where the review found
        # two of the sinks and where repr does not go. `HTTPError.hdrs` reprs
        # as "<HTTPMessage object at 0x…>" and str()s as the whole header block
        # including an echoed Authorization; a psycopg error's connection object
        # is the same shape. A structured error reporter renders attributes, so
        # a sweep that stops at repr is measuring less than the real exposure.
        for name, value in getattr(current, "__dict__", {}).items():
            attributes.append(f"{type(current).__name__}.{name} = {value}")
        current = current.__cause__ or current.__context__
        guard += 1
    surfaces["chain_walk"] = "\n".join(walked)
    surfaces["chain_attributes"] = "\n".join(attributes)
    return surfaces


@pytest.mark.parametrize(
    "mode", ["unauthorized", "server_error", "baddecode", "redirect", "error_header"]
)
def test_a_failing_provider_call_leaks_the_canary_nowhere(reflector, mode, caplog):
    """The review's scenario: a reflecting endpoint, a real bearer token, and
    every exception surface asserted clean."""

    caplog.set_level(logging.DEBUG)
    endpoint = reflector(mode)
    provider = _provider(endpoint.base)

    with pytest.raises(Exception) as caught:
        provider.assess(prompt="hello")

    for name, rendered in _exception_surfaces(caught.value).items():
        assert not _leaks(rendered), f"{mode} leaked through exception {name}: {rendered[:400]}"
    assert not _leaks(caplog.text), f"{mode} leaked into logs"


def test_a_reflected_response_HEADER_leaks_the_canary_nowhere(reflector, caplog):
    """The header channel returns 200, so the call SUCCEEDS — there is no
    exception to inspect, and that is exactly why it is worth sweeping: a
    successful exchange whose headers echo the credential still passes through
    the transport's own logging and its response objects."""

    caplog.set_level(logging.DEBUG)
    provider = _provider(reflector("header").base)
    answer = provider.assess(prompt="hello")

    assert not _leaks(answer), "the reflected header reached the provider's answer"
    assert not _leaks(caplog.text), "the reflected header reached the logs"


def test_a_SUCCESSFUL_judge_call_leaks_the_canary_nowhere(reflector, caplog):
    """A4 — success is a channel too. The endpoint returns 200 with the token
    echoed in the content, the judge returns a PASS, and the token must not be
    anywhere in the Evidence."""

    from prometheus_protocol.core.models import Verdict
    from prometheus_protocol.verifier.model_judge import ModelJudgeVerifier

    caplog.set_level(logging.DEBUG)
    endpoint = reflector("ok")
    judge = ModelJudgeVerifier(_provider(endpoint.base))

    result = judge.verify(code="def add(a, b): return a + b", task=_task())

    # The positive control: this really is the success path. Narrowed with
    # isinstance rather than a getattr default — an Unavailable has no verdict
    # BY DESIGN and the type gate refuses the shortcut.
    from prometheus_protocol.core.models import Evidence

    assert isinstance(result, Evidence), result
    assert result.verdict == Verdict.PASS, result
    for name, rendered in _renderings(result).items():
        assert not _leaks(rendered), f"a PASS leaked through {name}: {rendered[:400]}"
    assert not _leaks(result.detail), f"Evidence.detail carried the canary: {result.detail}"
    assert not _leaks(caplog.text)
    # And the classification that replaced the text is still there.
    assert "verdict=PASS" in result.detail and "confidence=0.95" in result.detail


def test_a_failing_judge_call_leaks_the_canary_nowhere(reflector, caplog):
    from prometheus_protocol.core.models import Unavailable
    from prometheus_protocol.verifier.model_judge import ModelJudgeVerifier

    caplog.set_level(logging.DEBUG)
    judge = ModelJudgeVerifier(_provider(reflector("unauthorized").base))
    result = judge.verify(code="x", task=_task())

    assert isinstance(result, Unavailable)
    for name, rendered in _renderings(result).items():
        assert not _leaks(rendered), f"Unavailable leaked through {name}"
    assert not _leaks(result.detail, caplog.text)


def _task():
    from prometheus_protocol.core.models import Case, Task

    return Task(
        id="t1", entry_point="add", prompt="add two numbers", split="heldout",
        cases=(Case(args=(1, 2), expected=3),),
    )


@pytest.mark.parametrize("mode", ["unauthorized", "server_error", "redirect"])
def test_an_anchor_exchange_leaks_the_canary_nowhere(reflector, mode, caplog):
    from prometheus_protocol.ledger.anchor_http import HttpAppendOnlyLog

    caplog.set_level(logging.DEBUG)
    log = HttpAppendOnlyLog(
        reflector(mode).base, token=CANARY, allow_insecure_loopback=True, timeout_s=5
    )
    with pytest.raises(Exception) as caught:
        log.entries()
    for name, rendered in _exception_surfaces(caught.value).items():
        assert not _leaks(rendered), f"anchor {mode} leaked through {name}: {rendered[:400]}"
    assert not _leaks(caplog.text)


def test_a_persisted_ledger_row_never_carries_the_canary(reflector, tmp_path):
    """Read back FROM DISK, not from the object that wrote it."""

    from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
    from prometheus_protocol.verifier.model_judge import ModelJudgeVerifier

    judge = ModelJudgeVerifier(_provider(reflector("ok").base))
    evidence = judge.verify(code="def add(a, b): return a + b", task=_task())

    path = tmp_path / "audit.db"
    ledger = SqliteLedger(path)
    ledger.record_chained(
        event="judge_outcome",
        subject="canary-sweep",
        payload={"detail": evidence.detail, "verifier": evidence.verifier_id},
        created_at="1000.0",
    )
    del ledger

    raw = path.read_bytes()
    assert not _leaks(raw.decode("utf-8", "replace")), "the canary is in the ledger FILE"
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        for (table,) in rows:
            dumped = repr(connection.execute(f"SELECT * FROM {table}").fetchall())
            assert not _leaks(dumped), f"the canary is in ledger table {table}"


# ---------------------------------------------------------------------------
# 3b. the remaining credential-bearing exercises
#
# Everything above drives the paths the review reproduced. These drive the rest
# of the surfaces that hold a credential: the anchor WRITE (not just the read),
# chain verification, attestation publish and verify, the signer, and the
# reconciliation path that holds the database password.
# ---------------------------------------------------------------------------


def test_an_anchor_WRITE_leaks_the_canary_nowhere(reflector, caplog):
    """``entries()`` above is the read. A write is a different request with a
    different failure path, and it carries the same bearer token."""

    from prometheus_protocol.ledger.anchor_http import HttpAppendOnlyLog

    caplog.set_level(logging.DEBUG)
    log = HttpAppendOnlyLog(
        reflector("unauthorized").base,
        token=CANARY,
        allow_insecure_loopback=True,
        timeout_s=5,
    )
    with pytest.raises(Exception) as caught:
        log.append(b'{"tip": "abc"}')
    for name, rendered in _exception_surfaces(caught.value).items():
        assert not _leaks(rendered), f"anchor write leaked through {name}: {rendered[:400]}"
    assert not _leaks(caplog.text)


def test_ledger_chain_verification_leaks_the_canary_nowhere(reflector, tmp_path, caplog):
    """The anchor is consulted on EVERY verify, so a verify against an anchor
    that rejects the token is a diagnostic built while holding a credential.

    ``NOT_VERIFIABLE`` is the expected verdict — couldn't-verify is not
    verified-clean — and the reason it reports must not quote the endpoint.
    """

    from prometheus_protocol.ledger.anchor_http import HttpAppendOnlyLog
    from prometheus_protocol.ledger.anchor_targets import LogTipAnchor
    from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger

    caplog.set_level(logging.DEBUG)
    anchor = LogTipAnchor(
        HttpAppendOnlyLog(
            reflector("unauthorized").base,
            token=CANARY,
            allow_insecure_loopback=True,
            timeout_s=5,
        )
    )
    ledger = SqliteLedger(tmp_path / "chain.db", tip_anchor=anchor)
    try:
        ledger.record_chained(
            event="e", subject="s", payload={"k": "v"}, created_at="1000.0"
        )
    except Exception as exc:  # the anchor write fails first; that is a surface too
        for name, rendered in _exception_surfaces(exc).items():
            assert not _leaks(rendered), f"chained append leaked through {name}"

    try:
        verification = ledger.verify_chain()
    except Exception as exc:
        for name, rendered in _exception_surfaces(exc).items():
            assert not _leaks(rendered), f"verify_chain leaked through {name}"
    else:
        for name, rendered in _renderings(verification).items():
            assert not _leaks(rendered), f"ChainVerification leaked through {name}"

    assert not _leaks(caplog.text)
    assert not _leaks((tmp_path / "chain.db").read_bytes().decode("utf-8", "replace"))


def _attestation_config(base: str):
    from prometheus_protocol.core.config import Config

    return Config(
        config_attestation_target=base + "/attest",
        config_attestation_token=CANARY,
        allow_insecure_loopback=True,
    )


def test_attestation_publish_and_verify_leak_the_canary_nowhere(reflector, caplog):
    """Publish and read back, both against an endpoint that echoes the token.

    ``ConfigAttestor.attest`` interpolates the target's exception into its own
    failure detail, so a target that quoted upstream bytes would surface here
    even though the attestation module itself never touches the credential.
    """

    from prometheus_protocol.attestation.runtime import attestation_target_for

    caplog.set_level(logging.DEBUG)
    target = attestation_target_for(_attestation_config(reflector("unauthorized").base))
    assert target is not None, "no target built; this test would be vacuous"

    from prometheus_protocol.attestation.attest import AttestationRecord

    record = AttestationRecord(
        digest="a" * 64, created_at="1000", key_id="k", scheme="s", signature=b"sig"
    )
    with pytest.raises(Exception) as caught:
        target.publish(record)
    for name, rendered in _exception_surfaces(caught.value).items():
        assert not _leaks(rendered), f"attestation publish leaked through {name}"

    with pytest.raises(Exception) as caught_read:
        target.records()
    for name, rendered in _exception_surfaces(caught_read.value).items():
        assert not _leaks(rendered), f"attestation verify leaked through {name}"

    for name, rendered in _renderings(target).items():
        assert not _leaks(rendered), f"the attestation target itself leaked through {name}"
    assert not _leaks(caplog.text)


def test_the_attestor_failure_detail_leaks_the_canary_nowhere(reflector, caplog):
    """The whole ``ConfigAttestor`` cycle, not just the target underneath it."""

    from prometheus_protocol.attestation.attest import AttestationUnavailable
    from prometheus_protocol.attestation.runtime import (
        build_config_attestor,
        resolve_attestation_signer,
    )

    caplog.set_level(logging.DEBUG)
    config = _attestation_config(reflector("unauthorized").base)
    signer = resolve_attestation_signer(config, signing_key=CANARY.encode())
    attestor = build_config_attestor(config, signer=signer, storage_path=":memory:")
    assert attestor is not None

    try:
        record = attestor.attest()
    except AttestationUnavailable as exc:
        for name, rendered in _exception_surfaces(exc).items():
            assert not _leaks(rendered), f"attestor failure leaked through {name}"
    else:
        assert not _leaks(repr(record))
    assert not _leaks(caplog.text)


def test_the_signer_path_leaks_the_canary_nowhere(caplog):
    """A local signing key is a credential in a dataclass — the shape that put
    ``MigrationRunnerConfig.signing_key`` and ``_SignerRequest.signing_key`` in
    this sweep in the first place (discovery found both; neither was reported)."""

    from prometheus_protocol.attestation.runtime import (
        _SignerRequest,
        resolve_attestation_signer,
    )
    from prometheus_protocol.core.config import Config

    caplog.set_level(logging.DEBUG)
    key = CANARY.encode()
    request = _SignerRequest(signing_key=secret_or_none(key))
    for name, rendered in _renderings(request).items():
        assert not _leaks(rendered), f"_SignerRequest leaked through {name}"

    signer = resolve_attestation_signer(Config(), signing_key=key)
    for name, rendered in _renderings(signer).items():
        assert not _leaks(rendered), f"the resolved signer leaked through {name}"

    # A signature is derived from the key by design. Assert it is not the key.
    signature = signer.sign(b"message")
    assert not _leaks(signature, repr(signature))
    assert not _leaks(caplog.text)


def test_reconciliation_and_the_database_path_leak_the_canary_nowhere(tmp_path, caplog):
    """The reconciliation path holds the DATABASE password, not a bearer token.

    Pointed at a closed port so every database call fails — a failed connection
    is where the details get written, and it is the only place the password is
    resolved. ``psycopg`` composes its own error text, so what this asserts is
    what OUR public results carry, which is the surface an operator sees.
    """

    from prometheus_protocol.chokepoint.runner import (
        ApprovalAuthority,
        BrokeredMigrationRunner,
        ConsumedApprovals,
        DbTarget,
        MigrationRunnerConfig,
        postgres_executor,
        postgres_receipt_lookup,
    )
    from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger

    caplog.set_level(logging.DEBUG)
    target = DbTarget("127.0.0.1", 1, "appdb", "migrator", CANARY_PASSWORD)
    config = MigrationRunnerConfig(
        target=target,
        approval_store_path=tmp_path / "approvals.db",
        signing_key=CANARY.encode(),
    )
    for name, rendered in _renderings(config).items():
        assert not _leaks(rendered), f"MigrationRunnerConfig leaked through {name}"

    # The two functions that actually resolve the password.
    digest = "a" * 64
    result = postgres_executor("SELECT 1", target, digest, digest)
    for name, rendered in _renderings(result).items():
        assert not _leaks(rendered), f"ExecutorResult leaked through {name}: {rendered[:300]}"

    status = postgres_receipt_lookup(digest, digest, target)
    for name, rendered in _renderings(status).items():
        assert not _leaks(rendered), f"ReceiptStatus leaked through {name}: {rendered[:300]}"

    # And the runner-level reconciliation that reports them.
    ledger = SqliteLedger(tmp_path / "audit.db")
    consumed = ConsumedApprovals(tmp_path / "approvals.db")
    runner = BrokeredMigrationRunner(
        authority=ApprovalAuthority(key=CANARY.encode()),
        target=target,
        consumed=consumed,
        audit=ledger,
        clock=lambda: 1001.0,
    )
    for name, rendered in _renderings(runner).items():
        assert not _leaks(rendered), f"BrokeredMigrationRunner leaked through {name}"
    try:
        for outcome in runner.reconcile_unfinished():
            for name, rendered in _renderings(outcome).items():
                assert not _leaks(rendered), f"ReconciliationResult leaked via {name}"
    except Exception as exc:  # noqa: BLE001 - a crash is a surface too
        for name, rendered in _exception_surfaces(exc).items():
            assert not _leaks(rendered), f"reconcile_unfinished leaked through {name}"
    finally:
        consumed.close()

    assert not _leaks(caplog.text)
    for path in (tmp_path / "audit.db", tmp_path / "approvals.db"):
        if path.exists():
            assert not _leaks(path.read_bytes().decode("utf-8", "replace")), (
                f"the canary is in {path.name}"
            )


def test_residual_a_psycopg_error_object_still_carries_the_password():
    """A NAMED residual, pinned so it cannot change silently.

    ``psycopg`` is a third-party driver and this sprint does not modify it. Its
    ``OperationalError`` keeps the finished connection object on ``__dict__``,
    and that object's ``repr`` dumps the whole conninfo — password included.
    ``str(exc)`` is clean, and every diagnostic this codebase builds from a
    database failure is built from ``str``, which is why the sweep above passes.

    What this pins is the boundary: the OBJECT is not safe to render, only its
    text is. Anything that reaches for ``vars(exc)`` or ``exc.__dict__`` — a
    locals-capturing error reporter, a debugger, ``pytest --showlocals`` — sees
    the credential. If this test starts failing, psycopg has changed and the
    residual in ``docs/security-model.md`` should be revisited.
    """

    psycopg = pytest.importorskip("psycopg")

    try:
        psycopg.connect(
            host="127.0.0.1", port=1, dbname="d", user="u",
            password=CANARY_PASSWORD, connect_timeout=2,
        )
    except psycopg.Error as exc:
        assert not _leaks(str(exc)), "str(exc) now leaks; the diagnostics built from it are unsafe"
        assert not _leaks(repr(exc.args))
        assert _leaks(repr(vars(exc))), (
            "psycopg no longer exposes the password through the exception's "
            "__dict__ — good, but re-derive the residual in docs/security-model.md"
        )
    else:  # pragma: no cover - port 1 is not a database
        pytest.fail("the connection succeeded; re-derive this test")


# ---------------------------------------------------------------------------
# 4. the CLI, discovered from the parser
# ---------------------------------------------------------------------------


def _cli_subcommands() -> list[str]:
    """Every subcommand the real parser defines. Discovered, not listed."""

    import argparse

    from prometheus_protocol.cli.main import build_parser

    parser = build_parser()
    names: list[str] = []
    for action in parser._actions:  # noqa: SLF001 - argparse exposes no public API
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            names.extend(sorted(action.choices))
    return names


def test_the_cli_exposes_subcommands_to_sweep():
    """If discovery returned nothing, the CLI sweep below would be vacuous."""

    assert len(_cli_subcommands()) >= 3, _cli_subcommands()


def test_no_cli_subcommand_prints_the_canary(monkeypatch, capsys, tmp_path):
    """Every discovered subcommand, run with canaries in the environment.

    Most will fail — there is no provider, no database, no anchor — and that is
    the point: a failure path is where a diagnostic gets printed.
    """

    from prometheus_protocol.cli.main import main

    for name in ("PROM_API_KEY", "PROM_JUDGE_API_KEY", "PROM_LEDGER_ANCHOR_TOKEN",
                 "PROM_CONFIG_ATTESTATION_TOKEN"):
        monkeypatch.setenv(name, CANARY)
    monkeypatch.setenv("PROM_CHOKEPOINT_PG_PASSWORD", CANARY_PASSWORD)
    monkeypatch.chdir(tmp_path)

    leaked: list[str] = []
    for command in _cli_subcommands():
        capsys.readouterr()
        try:
            main([command])
        except BaseException:  # noqa: BLE001 - a crash is a surface too
            captured = capsys.readouterr()
            crash = traceback.format_exc()
            if _leaks(captured.out, captured.err, crash):
                leaked.append(command)
            continue
        captured = capsys.readouterr()
        if _leaks(captured.out, captured.err):
            leaked.append(command)

    assert leaked == [], f"CLI subcommand(s) printed a canary: {leaked}"


# ---------------------------------------------------------------------------
# 5. logging, at every level
# ---------------------------------------------------------------------------


def test_no_log_record_at_any_level_carries_the_canary(reflector, caplog):
    """Captured at DEBUG, which is the noisiest level this code emits."""

    from prometheus_protocol.verifier.model_judge import ModelJudgeVerifier

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.DEBUG)
    root = logging.getLogger("prometheus_protocol")
    root.addHandler(handler)
    previous = root.level
    root.setLevel(logging.DEBUG)
    try:
        with caplog.at_level(logging.DEBUG):
            judge = ModelJudgeVerifier(_provider(reflector("ok").base))
            judge.verify(code="def add(a, b): return a + b", task=_task())
            judge_bad = ModelJudgeVerifier(_provider(reflector("unauthorized").base))
            judge_bad.verify(code="x", task=_task())
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)

    assert not _leaks(stream.getvalue()), "a log record carried the canary"
    assert not _leaks(caplog.text)
    for record in caplog.records:
        assert not _leaks(record.getMessage(), repr(record.args))
