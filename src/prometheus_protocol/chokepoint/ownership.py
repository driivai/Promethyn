"""Who owns an execution: host and lock identity in the ownership record.

The execution guard is an ``flock`` on the consumed-approval store's own
inode (``ConsumedApprovals.execution_guard``). It proves a previous owner is
dead only where two things hold at once: the lock is the same kernel's lock
(one host), and it is the *same lock object* the owner held. The independent
review's finding 2 showed the second half is not free: with a guard keyed to
the store's pathname, two aliases of one store gave two runners two locks,
and "I hold the guard" proved nothing about the owner. The guard is now keyed
to the store's identity, and every intent records which lock its owner held,
so that a recovering runner can check both halves before it reads "no
receipt" as "not committed":

* **same boot id and the same lock identity** — the recorded owner ran on
  this kernel and locked the inode this runner now holds exclusively; the
  owner is dead (or is this very process). Established.
* **same boot id, a different or missing lock identity** — the owner ran on
  this kernel but held some other lock, or an intent written before lock
  identities were recorded. Holding this lock says nothing about it. Not
  established (``lock_mismatch``).
* **same machine id and hostname, different boot id** — this machine
  rebooted since the intent; the owner process did not survive that.
  Established, whatever lock it held.
* **anything else** — the owner may be alive on another host. Not
  established (``foreign``).
* **no identity at all** — an intent written before identities were
  recorded. Nothing about it can be established (``legacy``).

Whatever is not established stays pending as ``owner_unverifiable`` until an
operator who has established it by other means reconciles with
``assume_owner_dead=True``, which the audit event records. This does not make
multi-host execution supported; it makes the unsupported cases fail closed
instead of producing false recovery evidence. The residuals — a cloned
machine id on two hosts with the same hostname, a kernel that reports no
boot id — are named in ``docs/chokepoint-threat-model.md``.
"""

from __future__ import annotations

import os
import re
import socket
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
MACHINE_ID_PATHS: tuple[str, ...] = ("/etc/machine-id", "/var/lib/dbus/machine-id")

OWNER_SAME_KERNEL = "same_kernel"
OWNER_REBOOTED = "rebooted"
OWNER_LEGACY = "legacy"
OWNER_FOREIGN = "foreign"
#: Same kernel, but the owner's guard was not this runner's lock object (or
#: the intent predates lock identities): a held lock proves nothing here.
OWNER_LOCK_MISMATCH = "lock_mismatch"

_IDENTITY_TOKEN = re.compile(r"^[0-9A-Za-z-]{8,64}$")
_OWNER_FIELDS = ("owner_host", "owner_boot_id", "owner_machine_id", "owner_pid")


@dataclass(frozen=True)
class OwnerIdentity:
    """This runner's identity as it is recorded in each execution intent."""

    host: str
    boot_id: str | None
    machine_id: str | None
    pid: int

    def as_payload(self) -> dict[str, object]:
        return {
            "owner_host": self.host,
            "owner_boot_id": self.boot_id,
            "owner_machine_id": self.machine_id,
            "owner_pid": self.pid,
        }


@dataclass(frozen=True)
class OwnerAssessment:
    """Whether this runner's exclusive lock proves the recorded owner is dead."""

    established: bool
    basis: str
    detail: str


def _read_identity_token(path: str) -> str | None:
    try:
        with open(path, encoding="ascii", errors="replace") as handle:
            value = handle.read(256).strip()
    except OSError:
        return None
    return value if _IDENTITY_TOKEN.match(value) else None


def local_identity(
    *,
    boot_id_path: str = BOOT_ID_PATH,
    machine_id_paths: Sequence[str] = MACHINE_ID_PATHS,
) -> OwnerIdentity:
    """Read this host's identity. A missing or malformed id is ``None``, never
    a placeholder: a ``None`` on either side of a comparison cannot establish
    anything, which is the fail-closed direction."""

    machine_id = None
    for candidate in machine_id_paths:
        machine_id = _read_identity_token(candidate)
        if machine_id is not None:
            break
    return OwnerIdentity(
        host=socket.gethostname(),
        boot_id=_read_identity_token(boot_id_path),
        machine_id=machine_id,
        pid=os.getpid(),
    )


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def assess_owner(
    payload: Mapping[str, object],
    local: OwnerIdentity,
    *,
    lock_id: str | None = None,
) -> OwnerAssessment:
    """Compare an intent's recorded owner with ``local`` (the runner that now
    holds the execution guard) and ``lock_id`` (the identity of the lock it
    holds: the store inode's ``dev:ino``)."""

    if not any(field in payload for field in _OWNER_FIELDS):
        return OwnerAssessment(
            established=False,
            basis=OWNER_LEGACY,
            detail=(
                "intent carries no owner identity, so nothing this runner holds "
                "says whether its owner is dead; it stays pending until an "
                "operator asserts otherwise"
            ),
        )
    host = _text(payload.get("owner_host"))
    boot_id = _text(payload.get("owner_boot_id"))
    machine_id = _text(payload.get("owner_machine_id"))
    recorded_lock = _text(payload.get("owner_lock_id"))
    if boot_id is not None and local.boot_id is not None and boot_id == local.boot_id:
        if recorded_lock is not None and lock_id is not None and recorded_lock == lock_id:
            return OwnerAssessment(
                established=True,
                basis=OWNER_SAME_KERNEL,
                detail=(
                    f"owner {host or '?'} ran on this kernel (boot {boot_id}) and "
                    f"held lock {recorded_lock}, the store inode this runner now "
                    "holds exclusively; the owner is gone"
                ),
            )
        return OwnerAssessment(
            established=False,
            basis=OWNER_LOCK_MISMATCH,
            detail=(
                f"owner {host or '?'} ran on this kernel (boot {boot_id}) but held "
                f"lock {recorded_lock or 'unrecorded'} while this runner holds "
                f"{lock_id or 'no lock identity'}: not provably the same object, "
                "so holding it says nothing about the owner; the intent stays "
                "pending"
            ),
        )
    if (
        machine_id is not None
        and local.machine_id is not None
        and machine_id == local.machine_id
        and host is not None
        and host == local.host
    ):
        # Same machine and hostname under another boot: the reboot ended the
        # owner's process whatever lock it held.
        return OwnerAssessment(
            established=True,
            basis=OWNER_REBOOTED,
            detail=(
                f"owner ran on this machine ({host}, machine {machine_id}) under "
                f"boot {boot_id or '?'}, not the current boot "
                f"{local.boot_id or '?'}; its process did not survive the reboot"
            ),
        )
    return OwnerAssessment(
        established=False,
        basis=OWNER_FOREIGN,
        detail=(
            f"owner {host or '?'} (boot {boot_id or '?'}, machine "
            f"{machine_id or '?'}) is not this kernel or this rebooted machine "
            f"({local.host}, boot {local.boot_id or '?'}, machine "
            f"{local.machine_id or '?'}); its liveness cannot be established "
            "from here, so its intent is not declared not-committed"
        ),
    )
