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

* :func:`probe_opened_substrate` joins a held descriptor's ``fstat`` device to
  its Linux ``fdinfo`` mount ID and the corresponding ``mountinfo`` entry.
  :func:`probe_substrate` is the separate directory preflight, walking visible
  mount parentage rather than selecting a global longest pathname prefix.
  Both classify the identified driver
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
  and proceed under a warning logged at every accepted inspection, because the guard
  it re-enables is unproven there. ``require_verified_substrate``
  (``PROM_REQUIRE_VERIFIED_SUBSTRATE``, the OR of its sources) withdraws that
  opt-out for a production posture.

Missing, contradictory or ambiguous metadata is unverified, not a pathname or
device-only fallback. The issuance journal uses an ``O_PATH`` descriptor so
inspection does not disturb SQLite's process-owned POSIX locks. This trusts
the kernel, its proc metadata and a stable trusted mount namespace; it does
not bind Python SQLite's later pathname open atomically to our descriptor.
Driver recognition is not proof of physical storage durability, the layers
beneath an overlay, or the absence of exports to other hosts. See the named
residuals in ``docs/chokepoint-threat-model.md``.
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
_NAMESPACE_ROOT = re.compile(r"[a-z][a-z0-9_]*:\[[0-9]+\]")


@dataclass(frozen=True)
class MountEntry:
    """A mount identity, including the topology and superblock device."""

    mount_id: int
    parent_id: int
    device: tuple[int, int]
    root: str
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
    device: int | None = None
    inode: int | None = None
    mount_id: int | None = None


@dataclass(frozen=True)
class SubstratePolicy:
    """The resolved settings. ``require_verified`` withdraws ``allow_unverified``;
    both at once is refused as incoherent by :func:`resolve_substrate_policy`."""

    require_verified: bool = False
    allow_unverified: bool = False

    def __post_init__(self) -> None:
        require_bool(self.require_verified, name="SubstratePolicy.require_verified")
        require_bool(self.allow_unverified, name="SubstratePolicy.allow_unverified")
        if self.require_verified and self.allow_unverified:
            raise ConfigError("verified substrate requirement conflicts with opt-out")


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


def _valid_mount_root(root: str, fs_type: str) -> bool:
    # Field 4 is supplied by the filesystem's show_path implementation, not
    # necessarily pathname lookup. Linux nsfs_show_path emits e.g. net:[123].
    # Retain that entry; discarding it could expose the safe mount underneath.
    # This is syntax recognition only: nsfs remains an UNKNOWN substrate.
    if root.startswith("/"):
        return os.path.normpath(root) == root and "\x00" not in root
    return fs_type == "nsfs" and _NAMESPACE_ROOT.fullmatch(root) is not None


def parse_mountinfo(text: str) -> list[MountEntry]:
    """Retain mount identity and parentage; malformed/ambiguous tables refuse.

    Missing parents are possible outside a process root. They are retained,
    not invented; pathname resolution below requires one visible root.
    """

    entries: list[MountEntry] = []
    ids: set[int] = set()
    for line in text.splitlines():
        parts = line.split(" ")
        try:
            separator = parts.index("-")
            mount_id, parent_id = int(parts[0]), int(parts[1])
            major, minor = (int(n) for n in parts[2].split(":"))
        except (ValueError, IndexError) as exc:
            raise ValueError("malformed mount identity") from exc
        if (separator < 6 or len(parts) < separator + 4 or mount_id <= 0
                or parent_id < 0 or major < 0 or minor < 0 or mount_id in ids):
            raise ValueError("malformed or duplicate mount identity")
        root = _unescape(parts[3])
        mount_point = _unescape(parts[4])
        fs_type = parts[separator + 1].strip()
        if (not _valid_mount_root(root, fs_type)
                or not mount_point.startswith("/")
                or os.path.normpath(mount_point) != mount_point
                or "\x00" in mount_point or not fs_type):
            raise ValueError("malformed mount path or filesystem")
        ids.add(mount_id)
        entries.append(MountEntry(mount_id, parent_id, (major, minor), root,
                                  mount_point, fs_type))
    by_id = {entry.mount_id: entry for entry in entries}
    for entry in entries:
        seen: set[int] = set()
        node = entry
        while node.parent_id in by_id and node.parent_id != node.mount_id:
            if node.mount_id in seen:
                raise ValueError("mount parent cycle")
            seen.add(node.mount_id)
            parent = by_id[node.parent_id]
            if not _covers(parent.mount_point, node.mount_point):
                raise ValueError("mount outside parent")
            node = parent
        if node.parent_id == node.mount_id and node.mount_point != "/":
            raise ValueError("non-root self-parent mount")
    return entries


def _covers(mount_point: str, path: str) -> bool:
    if mount_point == "/":
        return True
    trimmed = mount_point.rstrip("/")
    return path == trimmed or path.startswith(trimmed + "/")


def mount_for(path: str, entries: list[MountEntry]) -> MountEntry | None:
    """Walk visible children from the root, following stacked mount parents.

    A stack at the current pathname hides *all* children of its lower mount.
    An earlier (shorter) child mount also hides lower-parent descendants. Two
    competing children at the same pathname are ambiguous, never list-ordered.
    This pure helper is for the directory preflight, not descriptor inspection.
    """
    ids = {entry.mount_id for entry in entries}
    roots = [e for e in entries if e.mount_point == "/"
             and (e.parent_id not in ids or e.parent_id == e.mount_id)]
    if len(roots) != 1:
        return None
    children: dict[int, list[MountEntry]] = {}
    for entry in entries:
        if entry.parent_id != entry.mount_id:
            children.setdefault(entry.parent_id, []).append(entry)
    current = roots[0]
    seen: set[int] = set()
    while current.mount_id not in seen:
        seen.add(current.mount_id)
        candidates = [e for e in children.get(current.mount_id, [])
                      if _covers(e.mount_point, path)]
        if not candidates:
            # A disconnected covering mount cannot safely be ignored.
            if any(e.parent_id not in ids and e.mount_id != roots[0].mount_id
                   and _covers(e.mount_point, path) for e in entries):
                return None
            return current
        nearest = min(len(e.mount_point) for e in candidates)
        next_mounts = [e for e in candidates if len(e.mount_point) == nearest]
        if len(next_mounts) != 1:
            return None
        current = next_mounts[0]
    return None


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
    try:
        entry = mount_for(normalized, parse_mountinfo(mountinfo))
    except ValueError:
        entry = None
    if entry is None:
        return SubstrateReport(
            path=normalized,
            verdict=SUBSTRATE_UNKNOWN,
            fs_type=None,
            mount_point=None,
            detail="mount topology is malformed, missing or ambiguous",
        )
    verdict, detail = classify_filesystem(entry.fs_type)
    return SubstrateReport(
        path=normalized,
        verdict=verdict,
        fs_type=entry.fs_type,
        mount_point=entry.mount_point,
        detail=detail,
        mount_id=entry.mount_id,
    )


def classify_opened(info: os.stat_result, fdinfo: str, mountinfo: str) -> SubstrateReport:
    """Join fstat's device to the opened descriptor's exact Linux mount ID.

    Device alone is not unique (bind mounts share it); a pathname is not used.
    An open descriptor can still reference a hidden mount. That is the actual
    object being classified, not the object now accessible at its old pathname.
    """
    entry = None
    try:
        values = [line.split(":", 1)[1].strip() for line in fdinfo.splitlines()
                  if line.startswith("mnt_id:")]
        if len(values) != 1 or not values[0].isascii() or not values[0].isdecimal():
            raise ValueError("missing or ambiguous descriptor mount ID")
        mount_id = int(values[0])
        matches = [e for e in parse_mountinfo(mountinfo) if e.mount_id == mount_id]
        if len(matches) != 1:
            raise ValueError("descriptor mount absent from this namespace")
        entry = matches[0]
        if entry.device != (os.major(info.st_dev), os.minor(info.st_dev)):
            raise ValueError("descriptor device and mount disagree")
    except ValueError:
        entry = None
    if entry is None:
        return SubstrateReport("opened object", SUBSTRATE_UNKNOWN, None, None,
                               "descriptor mount identity could not be established",
                               info.st_dev, info.st_ino)
    verdict, detail = classify_filesystem(entry.fs_type)
    return SubstrateReport("opened object", verdict, entry.fs_type, entry.mount_point,
                           detail, info.st_dev, info.st_ino, entry.mount_id)


def probe_opened_substrate(fd: int) -> SubstrateReport:
    """Inspect the held descriptor; no parent/pathname fallback on uncertainty."""
    info = os.fstat(fd)
    if sys.platform.startswith("linux"):
        try:
            return classify_opened(
                info,
                Path(f"/proc/self/fdinfo/{fd}").read_text(encoding="ascii"),
                Path(MOUNTINFO_PATH).read_text(encoding="utf-8"),
            )
        except (OSError, UnicodeError):
            pass
    return SubstrateReport("opened object", SUBSTRATE_UNKNOWN, None, None,
                           "descriptor mount metadata unavailable on this platform",
                           info.st_dev, info.st_ino)


def probe_file_substrate(path: Path) -> SubstrateReport:
    """Inspect an existing journal through Linux O_PATH, without SQLite I/O.

    Closing O_PATH does not drop SQLite's process-owned POSIX locks. Never use
    an extra ordinary file descriptor here: another journal thread may hold a
    transaction. Non-Linux/missing O_PATH is explicitly unverified.
    """
    if not sys.platform.startswith("linux") or not hasattr(os, "O_PATH"):
        return SubstrateReport(str(path), SUBSTRATE_UNKNOWN, None, None,
                               "Linux O_PATH inspection is unavailable")
    fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return probe_opened_substrate(fd)
    finally:
        os.close(fd)


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
    require = any((
        require_bool(
            getattr(config, "require_verified_substrate", False),
            name="runner config require_verified_substrate",
        ),
        require_bool(
            getattr(settings, "require_verified_substrate", False),
            name="Config.require_verified_substrate",
        ),
        verified_substrate_required(env),
    ))
    allow = any((
        require_bool(
            getattr(config, "allow_unverified_substrate", False),
            name="runner config allow_unverified_substrate",
        ),
        require_bool(
            getattr(settings, "allow_unverified_substrate", False),
            name="Config.allow_unverified_substrate",
        ),
        unverified_substrate_allowed(env),
    ))
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
