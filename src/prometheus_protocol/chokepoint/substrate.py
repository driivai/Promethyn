"""Where the approval store lives: the filesystem the execution guard needs.

``ConsumedApprovals.execution_guard`` is an ``flock`` on the consumed-approval
store's own inode. That lock is mutual exclusion only where
the kernel granting it is the one kernel every runner talks to: a local
filesystem on one host. On a network filesystem the lock is one client's view,
emulated by a daemon, or not coordinated between hosts at all — and the F3
race (a recovering runner declaring a live owner's intent not committed) is
back, with nothing in the process to notice.

Until this module, that requirement was a sentence in a document. Here it is
something the runner checks before it builds:

* :func:`probe_substrate` names the filesystem behind a path where the
  platform exposes it (Linux, via ``/proc/self/mountinfo``) and classifies it
  as ``safe`` (a local filesystem whose ``flock`` is coherent for every
  process on the one kernel that mounts it), ``unsafe`` (a network, shared or
  multi-host filesystem) or ``unknown`` (a filesystem this module does not
  know, a layered filesystem whose substrate is not visible from inside it, or
  a platform where the probe cannot run at all).
* :func:`resolve_substrate_policy` combines the sources of the two settings
  that govern the answer — the runner config, the runtime ``Config`` and the
  environment — the way ``resolve_signer`` does for key custody.
* :func:`enforce_substrate` is the decision. ``unsafe`` is refused outright,
  with no opt-out. ``unknown`` is refused by default: couldn't-verify is not
  verified-safe. An operator who has verified the substrate by other means
  may set ``allow_unverified_substrate`` (``PROM_ALLOW_UNVERIFIED_SUBSTRATE``)
  and proceed under a warning logged at every construction, because the guard
  it re-enables is unproven there. ``require_verified_substrate``
  (``PROM_REQUIRE_VERIFIED_SUBSTRATE``, the OR of its sources) withdraws that
  opt-out for a production posture.

The probe reads the kernel's own mount table rather than calling ``statfs``
through ``ctypes``: it needs no per-architecture struct layout, it reports the
driver's *name* (so ``fuse.sshfs`` and ``fuse.glusterfs`` are distinguishable
from a local FUSE mount), and it can be fed a synthetic table in tests without
mounting anything. What it cannot see is named in ``docs/threat-model.md``
§2: the layers beneath an overlay, and whether a filesystem that looks local
is exported to other hosts from *this* one (those hosts see a network
filesystem and refuse on their side).
"""

from __future__ import annotations

import logging
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from prometheus_protocol.core.booleans import parse_env_bool, require_bool
from prometheus_protocol.core.errors import ConfigError

_LOG = logging.getLogger(__name__)

SUBSTRATE_SAFE = "safe"
SUBSTRATE_UNSAFE = "unsafe"
SUBSTRATE_UNKNOWN = "unknown"

#: Production posture: refuse the opt-out below. The OR of its sources.
VERIFIED_SUBSTRATE_REQUIRED_ENV = "PROM_REQUIRE_VERIFIED_SUBSTRATE"
#: The explicit, logged opt-out for an ``unknown`` (never an ``unsafe``) substrate.
UNVERIFIED_SUBSTRATE_ALLOWED_ENV = "PROM_ALLOW_UNVERIFIED_SUBSTRATE"

MOUNTINFO_PATH = "/proc/self/mountinfo"

#: Local filesystems: ``flock`` is coherent for every process on the kernel
#: that mounts them, which is the property the execution guard relies on.
SAFE_FILESYSTEMS = frozenset(
    {
        "ext2",
        "ext3",
        "ext4",
        "xfs",
        "btrfs",
        "f2fs",
        "zfs",
        "jfs",
        "reiserfs",
        "bcachefs",
        "tmpfs",
        "ramfs",
    }
)

#: Network, shared-storage and host-shared filesystems. An ``flock`` here is
#: at most one client's or one guest's view; runners on other hosts that mount
#: the same store are not excluded by it.
UNSAFE_FILESYSTEMS = frozenset(
    {
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "smbfs",
        "9p",
        "afs",
        "ceph",
        "coda",
        "gfs2",
        "ocfs2",
        "lustre",
        "ncpfs",
        "davfs",
        "virtiofs",
        "vboxsf",
        "prl_fs",
        "hostfs",
        "fuse.sshfs",
        "fuse.glusterfs",
        "fuse.s3fs",
        "fuse.gcsfuse",
        "fuse.davfs2",
        "fuse.ceph",
        "fuse.ceph-fuse",
        "fuse.rclone",
        "fuse.juicefs",
        "fuse.blobfuse",
        "fuse.blobfuse2",
        "fuse.goofys",
    }
)

_OVERLAY_FILESYSTEMS = frozenset({"overlay", "overlayfs"})
_OCTAL_ESCAPE = re.compile(r"\\([0-7]{3})")


@dataclass(frozen=True)
class MountEntry:
    """One line of the mount table: where it is mounted and what drives it."""

    mount_point: str
    fs_type: str


@dataclass(frozen=True)
class SubstrateReport:
    """What the probe established about the filesystem behind ``path``.

    ``verdict`` is one of ``safe``, ``unsafe`` or ``unknown``; ``fs_type`` and
    ``mount_point`` are ``None`` when the table could not be read at all.
    ``detail`` is the reason, in the words the refusal or warning will use.
    """

    path: str
    verdict: str
    fs_type: str | None
    mount_point: str | None
    detail: str


@dataclass(frozen=True)
class SubstratePolicy:
    """The resolved settings. ``require_verified`` withdraws ``allow_unverified``;
    both at once is refused as incoherent by :func:`resolve_substrate_policy`."""

    require_verified: bool = False
    allow_unverified: bool = False


def _flag(env: Mapping[str, str], name: str) -> bool:
    # The one strict parser: unset is the default, a misspelling is refused.
    return parse_env_bool(name, env.get(name), default=False)


def verified_substrate_required(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return _flag(env, VERIFIED_SUBSTRATE_REQUIRED_ENV)


def unverified_substrate_allowed(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return _flag(env, UNVERIFIED_SUBSTRATE_ALLOWED_ENV)


def _unescape(field: str) -> str:
    # The kernel escapes space, tab, newline and backslash in mount points as
    # three-digit octal (``\040`` for a space).
    return _OCTAL_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), field)


def parse_mountinfo(text: str) -> list[MountEntry]:
    """Parse ``/proc/self/mountinfo``: ``ID PARENT MAJ:MIN ROOT MOUNT_POINT
    OPTIONS [optional...] - FSTYPE SOURCE SUPER_OPTIONS``. Lines that do not
    have that shape are skipped, not guessed at."""

    entries: list[MountEntry] = []
    for line in text.splitlines():
        parts = line.split(" ")
        try:
            separator = parts.index("-")
        except ValueError:
            continue
        if separator < 5 or len(parts) < separator + 2:
            continue
        mount_point = _unescape(parts[4])
        fs_type = parts[separator + 1].strip()
        if not mount_point.startswith("/") or not fs_type:
            continue
        entries.append(MountEntry(mount_point=mount_point, fs_type=fs_type))
    return entries


def _covers(mount_point: str, path: str) -> bool:
    if mount_point == "/":
        return True
    trimmed = mount_point.rstrip("/")
    return path == trimmed or path.startswith(trimmed + "/")


def mount_for(path: str, entries: list[MountEntry]) -> MountEntry | None:
    """The most specific mount covering ``path``. Ties (a mount over a mount)
    go to the later line, which is the one the kernel shows at that point."""

    best: MountEntry | None = None
    for entry in entries:
        if not _covers(entry.mount_point, path):
            continue
        if best is None or len(entry.mount_point) >= len(best.mount_point):
            best = entry
    return best


def classify_filesystem(fs_type: str) -> tuple[str, str]:
    """``(verdict, detail)`` for one filesystem driver name."""

    name = fs_type.strip().lower()
    if name in SAFE_FILESYSTEMS:
        return (
            SUBSTRATE_SAFE,
            f"{name} is a local filesystem; an flock on it is coherent for every "
            "process on this kernel",
        )
    if name in UNSAFE_FILESYSTEMS:
        return (
            SUBSTRATE_UNSAFE,
            f"{name} is a network or host-shared filesystem; an flock on it does "
            "not exclude runners on other hosts that mount the same store",
        )
    if name in _OVERLAY_FILESYSTEMS:
        return (
            SUBSTRATE_UNKNOWN,
            f"{name} is a layered filesystem; the substrate beneath it is not "
            "visible from here, and a file present in a lower layer has a second "
            "inode after copy-up",
        )
    if name == "fuse" or name.startswith("fuse."):
        return (
            SUBSTRATE_UNKNOWN,
            f"{name} is a userspace filesystem whose locking depends on its daemon; "
            "it is also the usual way a network store is mounted",
        )
    return SUBSTRATE_UNKNOWN, f"{name} is not a filesystem this runner knows"


def classify_path(path: str, mountinfo: str) -> SubstrateReport:
    """Classify ``path`` against a mount table. Pure: nothing is read from the
    filesystem, so a synthetic table can stand in for an NFS mount in a test."""

    normalized = os.path.normpath(path)
    entry = mount_for(normalized, parse_mountinfo(mountinfo))
    if entry is None:
        return SubstrateReport(
            path=normalized,
            verdict=SUBSTRATE_UNKNOWN,
            fs_type=None,
            mount_point=None,
            detail="no mount table entry covers the path",
        )
    verdict, detail = classify_filesystem(entry.fs_type)
    return SubstrateReport(
        path=normalized,
        verdict=verdict,
        fs_type=entry.fs_type,
        mount_point=entry.mount_point,
        detail=detail,
    )


def _nearest_existing(path: Path) -> Path:
    candidate = path
    while not candidate.exists():
        parent = candidate.parent
        if parent == candidate:
            break
        candidate = parent
    return candidate


def probe_substrate(path: str | os.PathLike[str]) -> SubstrateReport:
    """Name and classify the filesystem behind ``path`` (or its nearest
    existing ancestor, since the store's directory may not exist yet).

    Anything that stops the probe — a platform without a mount table, an
    unreadable table — is reported as ``unknown`` with the reason. It is never
    reported as safe."""

    probed = os.path.realpath(_nearest_existing(Path(os.fspath(path)).expanduser()))
    if not sys.platform.startswith("linux"):
        return SubstrateReport(
            path=probed,
            verdict=SUBSTRATE_UNKNOWN,
            fs_type=None,
            mount_point=None,
            detail=f"no filesystem probe is implemented for {sys.platform}",
        )
    try:
        table = Path(MOUNTINFO_PATH).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return SubstrateReport(
            path=probed,
            verdict=SUBSTRATE_UNKNOWN,
            fs_type=None,
            mount_point=None,
            detail=f"{MOUNTINFO_PATH} could not be read ({type(exc).__name__})",
        )
    return classify_path(probed, table)


def resolve_substrate_policy(
    config: object | None = None,
    *,
    settings: object | None = None,
    env: Mapping[str, str] | None = None,
) -> SubstratePolicy:
    """The two settings, each the OR of its sources: the runner config
    (``MigrationRunnerConfig``), the runtime ``Config`` (``settings``) and the
    environment. Raising ``require_verified_substrate`` anywhere withdraws
    ``allow_unverified_substrate`` everywhere; the pair set together is refused
    as incoherent rather than resolved by a quiet precedence."""

    # A programmatic value is an actual bool or a refusal: "false" is a
    # non-empty string, and bool("false") would have enabled the opt-out.
    require = (
        require_bool(
            getattr(config, "require_verified_substrate", False),
            name="runner config require_verified_substrate",
        )
        or require_bool(
            getattr(settings, "require_verified_substrate", False),
            name="Config.require_verified_substrate",
        )
        or verified_substrate_required(env)
    )
    allow = (
        require_bool(
            getattr(config, "allow_unverified_substrate", False),
            name="runner config allow_unverified_substrate",
        )
        or require_bool(
            getattr(settings, "allow_unverified_substrate", False),
            name="Config.allow_unverified_substrate",
        )
        or unverified_substrate_allowed(env)
    )
    if require and allow:
        raise ConfigError(
            "require_verified_substrate=True cannot be honoured alongside "
            "allow_unverified_substrate=True: the opt-out for an unverified "
            "store substrate would never take effect under the requirement. "
            f"Withdraw one ({VERIFIED_SUBSTRATE_REQUIRED_ENV} / "
            f"{UNVERIFIED_SUBSTRATE_ALLOWED_ENV}, the runner config, or Config)."
        )
    return SubstratePolicy(require_verified=require, allow_unverified=allow)


def enforce_substrate(
    report: SubstrateReport,
    policy: SubstratePolicy,
    *,
    log: logging.Logger = _LOG,
) -> None:
    """Refuse or proceed. Raises :class:`ConfigError` for an ``unsafe``
    substrate (always) and for an ``unknown`` one unless the opt-out is set and
    not withdrawn; an accepted opt-out is logged as a warning every time."""

    where = f"{report.path} ({report.fs_type or 'filesystem undetermined'})"
    if report.verdict == SUBSTRATE_SAFE:
        return
    if report.verdict == SUBSTRATE_UNSAFE:
        raise ConfigError(
            f"consumed-approval store at {where} cannot host the execution "
            f"guard: {report.detail}. Cross-process execution ownership (the "
            "F3 guard) cannot be honoured there, so the runner refuses to build. "
            "Place the store and its lock file on a local filesystem of one "
            "trusted host; there is no opt-out for a known-unsafe substrate."
        )
    if policy.require_verified:
        raise ConfigError(
            "require_verified_substrate=True cannot be honoured: the filesystem "
            f"behind the consumed-approval store at {where} could not be "
            f"verified ({report.detail}). Move the store to a known local "
            "filesystem, or withdraw the requirement."
        )
    if not policy.allow_unverified:
        raise ConfigError(
            "the filesystem behind the consumed-approval store at "
            f"{where} could not be verified: {report.detail}. Couldn't-verify "
            "is not verified-safe, so the runner refuses to build by default. If "
            "you have established by other means that this filesystem is local "
            f"to one host, set {UNVERIFIED_SUBSTRATE_ALLOWED_ENV}=1 (or "
            "allow_unverified_substrate=True) to proceed under a logged warning; "
            "otherwise move the store to a known local filesystem."
        )
    log.warning(
        "consumed-approval store substrate at %s is UNVERIFIED (%s): proceeding "
        "on the explicit opt-out %s. Cross-process execution ownership is "
        "UNPROVEN on this filesystem; a runner on another host sharing it could "
        "recover a live owner's intent. Move the store to a local filesystem of "
        "one trusted host to withdraw this warning.",
        where,
        report.detail,
        UNVERIFIED_SUBSTRATE_ALLOWED_ENV,
    )
