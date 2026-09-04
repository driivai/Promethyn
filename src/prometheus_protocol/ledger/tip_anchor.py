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
That means a different trust domain — another host, an append-only or
write-once store, an object store with object-lock, a WORM volume, a printed or
signed digest. An anchor file sitting in the same directory as the ledger, on
the same medium, owned by the same account, protects against nothing: an
attacker who rewrites the chain simply rewrites the anchor to match. That case
is not defended, and pretending otherwise would be theater. See
``docs/threat-model.md`` §3.

Two behaviours make the anchor useful rather than decorative:

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
from typing import Protocol

from prometheus_protocol.ledger.audit_chain import ChainTip

ANCHOR_VERSION = 1


class AnchorUnavailable(RuntimeError):
    """The anchor could not be read or written.

    Deliberately NOT swallowed by the verifier: an anchor that was configured
    and cannot be read leaves verification unable to answer the question it was
    configured to answer, which is ``NOT_VERIFIABLE``, never ``VALID``.
    """


class AnchorRewind(AnchorUnavailable):
    """A write would move the anchored tip backwards.

    Raised rather than accepted. If the live chain is shorter than what was
    anchored, either entries were removed or the ledger was replaced — both are
    exactly what the anchor exists to reveal.
    """


class TipAnchor(Protocol):
    """Somewhere a chain tip can be kept out of the ledger adversary's reach."""

    def read(self) -> ChainTip | None:
        """The anchored tip, or ``None`` if nothing has been anchored yet.

        Raises :class:`AnchorUnavailable` when a tip exists but cannot be read —
        distinct from "no anchor", because the two must never be conflated.
        """

    def write(self, tip: ChainTip) -> None:
        """Record ``tip``. Raises :class:`AnchorRewind` if it moves backwards."""


@dataclass(frozen=True)
class FileTipAnchor:
    """A tip anchor kept as a small JSON file.

    Intended for a path on a *different medium* from the ledger — a read-only
    mount from another host, an append-only volume, a synced secret store. The
    class cannot check that, and does not pretend to: placing this file beside
    the ledger yields a value that looks like protection and is not.

    Writes are atomic (temp file plus rename) so a crash mid-write cannot leave a
    half-written anchor that reads as corrupt, and the file is created ``0600``.
    """

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
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise AnchorUnavailable(f"anchor at {self.path} is not valid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise AnchorUnavailable(f"anchor at {self.path} is not an object")
        if payload.get("version") != ANCHOR_VERSION:
            raise AnchorUnavailable(
                f"anchor at {self.path} has unsupported version {payload.get('version')!r}"
            )
        seq, entry_hash = payload.get("seq"), payload.get("entry_hash")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            raise AnchorUnavailable(f"anchor at {self.path} has an invalid seq {seq!r}")
        if not isinstance(entry_hash, str) or len(entry_hash) != 64:
            raise AnchorUnavailable(f"anchor at {self.path} has an invalid entry_hash")
        try:
            bytes.fromhex(entry_hash)
        except ValueError as exc:
            raise AnchorUnavailable(f"anchor at {self.path} entry_hash is not hex") from exc
        return ChainTip(seq=seq, entry_hash=entry_hash)

    def write(self, tip: ChainTip) -> None:
        current = self.read()  # raises AnchorUnavailable on a corrupt anchor
        if current is not None and tip.seq < current.seq:
            raise AnchorRewind(
                f"refusing to anchor seq {tip.seq} over {current.seq}: the chain "
                "has shortened, which is the tampering this anchor exists to show"
            )
        if current is not None and tip.seq == current.seq and tip.entry_hash != current.entry_hash:
            raise AnchorRewind(
                f"refusing to re-anchor seq {tip.seq} with a different hash: the "
                "entry at that position was rewritten"
            )
        payload = {
            "version": ANCHOR_VERSION,
            "seq": tip.seq,
            "entry_hash": tip.entry_hash,
        }
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
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
