"""A credential that cannot render itself, by any path.

F8 was reported as roughly twenty-five distinct sinks. It is one root cause with
twenty-five symptoms: a credential is held as a plain ``str``, and every
rendering path in Python will happily print a ``str``.

WHY ``repr=False`` IS NOT THE FIX, measured rather than argued.
``DbTarget.password`` already carried ``field(repr=False)`` and already had a
``__str__`` that returns the target identity. Both worked. The credential still
came out::

    >>> t = DbTarget("db", 5432, "appdb", "migrator", CANARY)
    >>> CANARY in repr(t)                        # False  — repr=False worked
    >>> CANARY in str(t)                         # False  — __str__ worked
    >>> CANARY in json.dumps(asdict(t), default=str)   # True   <-- still leaks

``dataclasses.asdict`` does not consult ``field.repr``; it reads the field value
and deep-copies it. ``vars()`` reads ``__dict__`` directly. A logging call, an
f-string in a message nobody thought about, a serializer, a CLI JSON projection
— each is a separate path, and a per-field opt-out has to be remembered on every
one of them, for every field, forever. ``Config`` demonstrated the other half of
the same problem: it had no opt-out at all, and rendered four credentials through
``repr``, ``str``, f-strings, ``asdict`` and ``vars`` alike.

SO THE REDACTION LIVES IN THE VALUE, NOT IN THE CONTAINER. A :class:`Secret`
renders as ``Secret(<redacted>)`` under ``repr``, ``str``, ``format``, and — the
one that mattered — it survives ``asdict`` as itself rather than being copied
into a bare string, because :meth:`__deepcopy__` returns the same object. The
consequence is the property this sprint needs: **a NEW field added later is
redacted by default**, because it is redacted by being a ``Secret``, not by
someone remembering to write ``repr=False`` beside it.

It is also FAIL-CLOSED under JSON serialization. ``json.dumps`` raises
``TypeError`` on a ``Secret`` rather than emitting anything, so a new code path that tries to
serialize a structure containing one fails loudly at the point of the mistake
instead of quietly publishing the credential. Code that genuinely needs the
value calls :meth:`reveal`, which is greppable and rare. Today
``grep -rn '\\.reveal()' src/`` returns seven call sites, and every one is a
point of USE: two build an ``Authorization`` header, three hand a signing key to
HMAC or to the signer that holds it, one supplies the database password to
``psycopg.connect``, and one type-checks a configured key during validation.
There is no site that reveals a credential in order to describe it.

WHAT THIS DOES NOT DO, stated rather than discovered:

* It does not stop code that calls ``reveal()`` from putting the result
  somewhere public. ``reveal`` is the audited boundary; the whole point is that
  there are few call sites and they are named.
* It does not protect a credential that never becomes a ``Secret`` — a raw
  ``str`` field added later is a raw ``str``. That is why
  ``tests/conformance/test_secret_canary_sweep.py`` DISCOVERS credential-shaped
  fields from the dataclasses themselves and fails on any that is not a
  ``Secret``, rather than trusting this docstring.
* It does not scrub process memory. The value is a Python ``str`` on the heap
  and a core dump still contains it.
* It does not stop PICKLING. A ``Secret`` round-trips through ``pickle`` on
  purpose, so that a config or a target can be handed to a ``multiprocessing``
  worker — see :meth:`Secret.__reduce__`. A pickled config written to disk is
  therefore still a credential at rest.
"""

from __future__ import annotations

from typing import Any

#: What every rendering path shows instead of the credential.
REDACTED = "<redacted>"


class Secret:
    """A credential that renders as ``Secret(<redacted>)`` everywhere.

    ``__slots__`` keeps the value off any instance ``__dict__``, so ``vars()``
    on a ``Secret`` raises rather than returning the credential — one fewer
    reflection path to remember.
    """

    __slots__ = ("_value",)

    #: Declared so the checker can see it; ``__slots__`` still governs storage,
    #: because a bare annotation creates no class attribute.
    _value: str | bytes

    def __init__(self, value: str | bytes) -> None:
        if not isinstance(value, (str, bytes)):
            raise TypeError("a Secret holds str or bytes")
        self._value = value

    # -- rendering: every path answers the same -----------------------------

    def __repr__(self) -> str:
        return f"Secret({REDACTED})"

    def __str__(self) -> str:
        return f"Secret({REDACTED})"

    def __format__(self, spec: str) -> str:
        # An f-string with a format spec would otherwise fall through to
        # ``str.__format__`` on the underlying value for some spec strings.
        return f"Secret({REDACTED})"

    # -- ``asdict`` keeps the wrapper --------------------------------------

    def __deepcopy__(self, memo: dict) -> Secret:
        """Return SELF, not a copy.

        This is the load-bearing line. ``dataclasses.asdict`` deep-copies every
        non-dataclass field value; without this the wrapper would be copied and
        the copy would be... still a Secret, in fact. The reason it matters is
        different and worse: a deep copy of an immutable wrapper is pointless
        churn, and more importantly returning self guarantees that whatever
        ``asdict`` produces holds an object whose ``repr`` is redacted, with no
        dependence on ``copy`` module behaviour for ``__slots__`` classes.
        """

        return self

    def __copy__(self) -> Secret:
        return self

    def __reduce__(self) -> Any:
        """Picklable, DELIBERATELY, and this is a stated trade.

        Refusing to pickle would stop a ``Config`` or a ``DbTarget`` being
        handed to a ``multiprocessing`` worker, which this repository really
        does — ``test_independent_processes_cannot_both_spend_approval`` passes a
        target across a process boundary to prove two processes cannot both
        spend one approval. Breaking that to gain "no credential at rest" would
        trade a working safety proof for a partial one.

        THE RESIDUAL, therefore: ``pickle.dumps(config)`` round-trips the
        credential, so a pickled config written to a cache or a file IS a
        credential at rest, and a ``Secret`` does not prevent that. What it
        prevents is the accidental path — every RENDERING of the value. Pickling
        a config to disk is a deliberate act, and it is not one this repository
        performs.
        """

        return (Secret, (self._value,))

    # -- identity and truthiness, without leaking ---------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        # Constant-time: equality on credentials is compared often enough that a
        # timing side channel is worth closing at no cost.
        import hmac

        mine, theirs = self._value, other._value
        if isinstance(mine, str) and isinstance(theirs, str):
            return hmac.compare_digest(mine, theirs)
        if isinstance(mine, bytes) and isinstance(theirs, bytes):
            return hmac.compare_digest(mine, theirs)
        return False

    def __hash__(self) -> int:
        return hash((Secret, self._value))

    def __bool__(self) -> bool:
        """So ``if config.api_key:`` keeps working without revealing anything."""

        return bool(self._value)

    def __len__(self) -> int:
        """The LENGTH is not the credential, and a diagnostic may legitimately
        want to say "a 0-byte key was configured"."""

        return len(self._value)

    # -- the one audited exit ----------------------------------------------

    def reveal(self) -> Any:
        """The credential itself. Every call site is a deliberate one.

        Greppable on purpose: ``grep -rn '\\.reveal()' src/`` enumerates every
        place a credential leaves the wrapper, and that list is short.
        """

        return self._value


def secret_or_none(value: object) -> Secret | None:
    """Wrap a configured value, treating empty and ``None`` alike as absent.

    Configuration readers produce ``""`` for an unset environment variable as
    often as ``None``, and an empty credential is not a credential.
    """

    if value is None:
        return None
    if isinstance(value, Secret):
        return value
    if isinstance(value, (str, bytes)) and len(value) == 0:
        return None
    if not isinstance(value, (str, bytes)):
        raise TypeError("a Secret holds str or bytes")
    return Secret(value)


def reveal_or_none(value: Secret | str | bytes | None) -> Any:
    """The credential inside an optional ``Secret``, or ``None``.

    Accepts an already-plain value and returns it unchanged. That is not a
    loosening of the discipline — it is a consequence of it. The credential
    fields on :class:`~prometheus_protocol.core.config.Config` accept ``str``
    at construction and normalise in ``__post_init__``, so a *reader* holds a
    declared type of ``Secret | str | None`` even though what is stored is
    always a ``Secret``. Narrowing that at every call site would mean a cast
    per site, and a cast is a place where a wrong assumption is silent. Passing
    a raw value through here is the honest behaviour for a normaliser, and the
    invariant it relies on is asserted separately: the canary sweep requires
    every ``str``-accepting credential field to wrap in ``__post_init__``.
    """

    if value is None:
        return None
    if isinstance(value, Secret):
        return value.reveal()
    return value
