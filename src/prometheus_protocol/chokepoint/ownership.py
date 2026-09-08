"""Who owns an execution: host identity in the ownership record.

The execution guard (an ``flock`` beside the approval store) proves a previous
owner is dead only where that lock is the same kernel's lock: one host. Two
runners on two hosts that share a store or a ledger cannot be told apart by an
``flock`` at all — which is the F3 race in its multi-host form: a recovering
runner on host B finds host A's intent, finds no receipt yet (A has not
connected), and records "not committed" while A is about to commit.

So every execution intent records who took it — hostname, kernel boot id,
machine id, pid — and a recovering runner compares that record with itself
before it is allowed to say "no receipt, so not committed":

* **same boot id** — the recorded owner ran on this kernel, and this runner
  holds the exclusive lock that owner would have had to hold; the owner is
  dead (or is this very process). Established.
* **same machine id and hostname, different boot id** — this machine rebooted
  since the intent; the owner process did not survive that. Established.
* **anything else** — the owner may be alive on another host. Liveness cannot
  be established from here. The intent stays pending as ``owner_unverifiable``
  until an operator who has established it by other means reconciles with
  ``assume_owner_dead=True``, which the audit event records.
* **no identity at all** — an intent written before identities were recorded.
  It is reconciled under the same-host assumption those runners were deployed
  under, with a warning; the upgrade window is named in the threat model.

This does not make multi-host execution supported. It makes the unsupported
case fail closed instead of producing false recovery evidence. The residuals —
a cloned machine id on two hosts with the same hostname, a kernel that
reports no boot id — are named in ``docs/chokepoint-threat-model.md``.
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


def assess_owner(payload: Mapping[str, object], local: OwnerIdentity) -> OwnerAssessment:
    """Compare an intent's recorded owner with ``local`` (the runner that now
    holds the execution guard)."""

    if not any(field in payload for field in _OWNER_FIELDS):
        return OwnerAssessment(
            established=True,
            basis=OWNER_LEGACY,
            detail=(
                "intent predates ownership identity; reconciled under the "
                "same-host assumption its runner was deployed under"
            ),
        )
    host = _text(payload.get("owner_host"))
    boot_id = _text(payload.get("owner_boot_id"))
    machine_id = _text(payload.get("owner_machine_id"))
    if boot_id is not None and local.boot_id is not None and boot_id == local.boot_id:
        return OwnerAssessment(
            established=True,
            basis=OWNER_SAME_KERNEL,
            detail=(
                f"owner {host or '?'} ran on this kernel (boot {boot_id}); the "
                "exclusive execution guard this runner holds proves it is gone"
            ),
        )
    if (
        machine_id is not None
        and local.machine_id is not None
        and machine_id == local.machine_id
        and host is not None
        and host == local.host
    ):
        # Same machine and hostname. Either this kernel (then the exclusive
        # guard proves the owner gone) or an earlier boot (then the reboot did):
        # the owner is dead either way, so a missing boot id does not weaken it.
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
