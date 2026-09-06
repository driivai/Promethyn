"""The out-of-band tip anchor — what makes a genesis rewrite detectable.

A hash chain proves internal consistency, and an adversary who can rewrite the
whole ledger file can recompute a consistent chain: every link checks out, and
the history is whatever they wanted it to be. ``docs/ledger-integrity.md`` has
always said so. The only thing that catches it is a copy of the tip held
somewhere the adversary does not control, compared against the live chain.

The primitive for that comparison (``ChainTip``, ``verify_rows(expected_tip=…)``)
already existed. What did not exist was anybody *storing* a tip — so the
capability was present, plausible, and never exercised, which is this project's
own definition of a void guard. This module persists it and the ledger consults
it automatically.

**The trust boundary is the whole point, so it is stated plainly.** The anchor
helps if and only if it lives somewhere the ledger-file adversary cannot write.
Three families of target exist (``docs/ledger-integrity.md``):

* :class:`FileTipAnchor` (here) — one mutable file, rewritten in place.
  **Non-protecting.** An anchor file sitting in the same directory as the
  ledger, on the same medium, owned by the same account, protects against
  nothing: an attacker who rewrites the chain simply rewrites the anchor to
  match. That case is not defended — it is a passing test — and pretending
  otherwise would be theatre. Development only.
* ``ObjectLockTipAnchor`` (``ledger/anchor_targets.py``) — one immutable record
  per anchored tip on a write-once medium: an object-locked bucket under
  retention, or a WORM volume. Even the credential that writes records cannot
  overwrite or delete one while retention holds.
* ``LogTipAnchor`` (``ledger/anchor_targets.py``) — one record per tip appended
  to a log the ledger host can only append to, run by a party the ledger-host
  adversary is not.

The two append-only families expose the **whole anchored history**, and the
verifier pins every record in it. That is what makes an immutable medium worth
having: a forged record appended by someone holding the write credential does
not mask the honest records before it. What remains, and is stated in the
threat model, is the adversary who holds authority over the *medium* — retention
lapsed or bypassed, or the log's own operator. See ``docs/threat-model.md`` §3.

Two behaviours make every target useful rather than decorative:

* **It is written on every append**, so it is never stale by more entries than
  the process has crashed through.
* **It refuses to move backwards.** A chain that has rewound — the live tip's
  seq is below the anchored one — is evidence, not something to quietly record.
  Silently re-anchoring a shortened chain would erase the only signal there was.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Protocol

from prometheus_protocol.ledger.audit_chain import ChainTip

ANCHOR_VERSION = 1


class AnchorUnavailable(RuntimeError):
    """The anchor could not be read or written.

    Deliberately NOT swallowed by the verifier: an anchor that was configured
    and cannot be read leaves verification unable to answer the question it was
    configured to answer, which is ``NOT_VERIFIABLE``, never ``VALID``. And not
    swallowed by the ledger's append either: an entry whose anchor write failed
    is one a later rewrite could hide, so the caller learns now, not during an
    incident.
    """


class AnchorRewind(AnchorUnavailable):
    """A write would move the anchored tip backwards.

    Raised rather than accepted. If the live chain is shorter than what was
    anchored, either entries were removed or the ledger was replaced — both are
    exactly what the anchor exists to reveal.
    """


class TipAnchor(Protocol):
    """Somewhere a chain tip can be kept out of the ledger adversary's reach."""

    #: Short label for logs and the CLI.
    name: str
    #: True when the target keeps every anchored tip as its own record, never
    #: overwrites or deletes one, and reads the whole history back. False for
    #: the single-file target, which is only as safe as its placement.
    append_only: bool

    def read(self) -> ChainTip | None:
        """The latest anchored tip, or ``None`` if nothing has been anchored yet.

        Raises :class:`AnchorUnavailable` when a tip exists but cannot be read —
        distinct from "no anchor", because the two must never be conflated.
        """

    def write(self, tip: ChainTip) -> None:
        """Record ``tip``. Raises :class:`AnchorRewind` if it moves backwards."""

    def history(self) -> list[ChainTip]:
        """Every anchored tip in the order written. The verifier pins them all."""


# -- the record, and the guard every target applies ------------------------


def encode_tip(tip: ChainTip) -> str:
    """The one canonical serialization of an anchor record."""

    payload = {"version": ANCHOR_VERSION, "seq": tip.seq, "entry_hash": tip.entry_hash}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def decode_tip(payload: object, *, where: str) -> ChainTip:
    """Validate a decoded record or raise :class:`AnchorUnavailable`.

    A malformed record must never degrade to "verify without one" — that would
    turn a tampered anchor into a clean bill of health.
    """

    if not isinstance(payload, dict):
        raise AnchorUnavailable(f"anchor at {where} is not an object")
    if payload.get("version") != ANCHOR_VERSION:
        raise AnchorUnavailable(
            f"anchor at {where} has unsupported version {payload.get('version')!r}"
        )
    seq, entry_hash = payload.get("seq"), payload.get("entry_hash")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise AnchorUnavailable(f"anchor at {where} has an invalid seq {seq!r}")
    if not isinstance(entry_hash, str) or len(entry_hash) != 64:
        raise AnchorUnavailable(f"anchor at {where} has an invalid entry_hash")
    try:
        bytes.fromhex(entry_hash)
    except ValueError as exc:
        raise AnchorUnavailable(f"anchor at {where} entry_hash is not hex") from exc
    return ChainTip(seq=seq, entry_hash=entry_hash)


def decode_record(body: bytes | str, *, where: str) -> ChainTip:
    """Decode one stored record (bytes or text) into a tip, or raise."""

    try:
        text = body.decode("utf-8") if isinstance(body, bytes) else body
        payload = json.loads(text)
    except (UnicodeDecodeError, ValueError) as exc:
        raise AnchorUnavailable(f"anchor at {where} is not valid JSON: {exc}") from exc
    return decode_tip(payload, where=where)


def check_monotonic(held: Iterable[ChainTip], tip: ChainTip, *, where: str) -> bool:
    """The guard every target applies before writing.

    Refuses a rewind (``tip.seq`` below the highest anchored seq) and a different
    hash at an already-anchored seq — both are the tampering the anchor exists
    to show, and recording over them would erase the evidence. Returns ``True``
    when ``tip`` is already anchored exactly (the write is idempotent), ``False``
    when it is new.
    """

    already = False
    latest = 0
    for current in held:
        latest = max(latest, current.seq)
        if current.seq == tip.seq:
            if current.entry_hash != tip.entry_hash:
                raise AnchorRewind(
                    f"refusing to re-anchor seq {tip.seq} with a different hash at "
                    f"{where}: the entry at that position was rewritten"
                )
            already = True
    if tip.seq < latest:
        raise AnchorRewind(
            f"refusing to anchor seq {tip.seq} over {latest} at {where}: the chain "
            "has shortened, which is the tampering this anchor exists to show"
        )
    return already


def anchor_history(anchor: TipAnchor) -> list[ChainTip]:
    """Every tip ``anchor`` holds — the whole history where the target keeps
    one, the single latest tip where it does not."""

    history = getattr(anchor, "history", None)
    if callable(history):
        return list(history())
    tip = anchor.read()
    return [tip] if tip is not None else []


# -- the single-file target: development only ------------------------------


@dataclass(frozen=True)
class FileTipAnchor:
    """A tip anchor kept as one small JSON file, rewritten in place.

    **Non-protecting.** It holds no history and refuses nothing: placing this
    file beside the ledger yields a value that looks like protection and is not,
    and placing it on a write-once medium does not help either, because it
    overwrites. It exists for development and for the passing test that records
    what an anchor on the adversary's own medium is worth. The runtime warns
    when it is the configured target.

    Writes are atomic (temp file plus rename) so a crash mid-write cannot leave a
    half-written anchor that reads as corrupt, and the file is created ``0600``.
    """

    name = "file"
    append_only = False

    path: Path

    def __init__(self, path: str | os.PathLike[str]) -> None:
        object.__setattr__(self, "path", Path(os.fspath(path)))

    def read(self) -> ChainTip | None:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise AnchorUnavailable(f"anchor at {self.path} could not be read: {exc}") from exc
        return decode_record(raw, where=str(self.path))

    def history(self) -> list[ChainTip]:
        tip = self.read()
        return [tip] if tip is not None else []

    def write(self, tip: ChainTip) -> None:
        if check_monotonic(self.history(), tip, where=str(self.path)):
            return  # already anchored exactly; nothing to rewrite
        body = encode_tip(tip)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Atomic: a crash mid-write leaves the previous anchor intact rather
            # than a truncated file that would read as corrupt and, worse, make a
            # healthy ledger look unverifiable.
            descriptor, temporary = tempfile.mkstemp(
                dir=str(self.path.parent), prefix=".anchor-", suffix=".tmp"
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    handle.write(body)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temporary, 0o600)
                os.replace(temporary, self.path)
            except BaseException:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
                raise
        except OSError as exc:
            raise AnchorUnavailable(f"anchor at {self.path} could not be written: {exc}") from exc
