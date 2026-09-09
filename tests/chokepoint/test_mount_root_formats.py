"""Mount-root formats, recognized one shape at a time, from measured data.

Field 4 of a ``mountinfo`` row is whatever the kernel's path printer produced,
which is not always a pathname. Each shape here was observed on a real kernel
before it was recognized — ``scripts/mountinfo_diagnostic.py`` reports the
distribution on every Linux CI job, and the Linux integration suite produces
the ``//deleted`` shape from a real mount rather than a fixture.

What the CI matrix actually reported (identical on 3.10, 3.11 and 3.12: 26
rows, 26 read, none unread): 25 absolute roots across autofs, binfmt_misc,
bpf, cgroup2, configfs, debugfs, devpts, devtmpfs, efivarfs, ext4, fusectl,
hugetlbfs, mqueue, overlay, proc, pstore, securityfs, sysfs, tmpfs, tracefs
and vfat — and one ``nsfs`` kernel label, the shape that started this. So the
candidates a kernel-source reading would have suggested (overlay, btrfs
subvolume, autofs, cgroup2, tracefs, bind-mount subpath roots) needed no new
recognition at all: they are ordinary absolute pathnames and were already
read. Measuring first is what kept them out of the parser.

The discipline, from the nsfs work: recognize a shape exactly, scope it to
whatever emits it, leave mount-point validation strict, and keep
unrecognized-root → unread → refuse-if-relevant. Recognition decides whether a
row is *read*; it never decides whether the filesystem behind it is safe. The
driver is what is classified, and no driver is added to a safe list here.

Every negative control below must fail both before and after the change that
added its shape: a recognizer that accepts everything proves nothing.
"""

from __future__ import annotations

import pytest

from prometheus_protocol.chokepoint import substrate as s
from prometheus_protocol.core.errors import ConfigError

STRICT = s.SubstratePolicy(require_verified=True)
ROOT_ROW = "10 1 8:1 / / rw - ext4 /dev/root rw\n"


def row(root, fs_type="ext4", point="/srv/app"):
    return f"26 10 8:1 {root} {point} rw - {fs_type} /dev/root rw\n"


def read(root, fs_type="ext4", point="/srv/app"):
    """Was the row read as a mount identity?"""

    table = s.parse_mount_table(ROOT_ROW + row(root, fs_type, point))
    return [entry.root for entry in table.entries if entry.mount_id == 26]


# ---------------------------------------------------------------------------
# Recognized shapes, and what emits each
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("root,fs_type,emitted_by", [
    ("/", "ext4", "an ordinary whole-filesystem mount"),
    ("/srv/app", "ext4", "a bind mount of a subdirectory"),
    ("/@home", "btrfs", "a btrfs subvolume root (an ordinary absolute path)"),
    # Measured on the CI matrix as plain absolute roots, so they need no
    # recognition of their own — pinned here so that stays true.
    ("/", "overlay", "an overlay mount, observed with an absolute root"),
    ("/", "autofs", "autofs, observed with an absolute root"),
    ("/", "cgroup2", "cgroup2, observed with an absolute root"),
    ("/", "tracefs", "tracefs, observed with an absolute root"),
    ("net:[4026533001]", "nsfs", "nsfs_show_path, for a namespace file"),
    ("mnt:[4026531841]", "nsfs", "nsfs_show_path, for a mount namespace"),
    ("/srv/app/store.db//deleted", "ext4",
     "the generic dentry path printer, for an unlinked bind-mount source"),
    ("/deleted", "ext4", "an ordinary directory that happens to be named so"),
])
def test_a_recognized_root_is_read_and_classified_by_its_driver(root, fs_type, emitted_by):
    assert read(root, fs_type) == [root], emitted_by
    # Recognition reads the row; the driver still decides the verdict, and the
    # driver's own classification is untouched by the shape of its root.
    expected = "safe" if fs_type in ("ext4", "btrfs") else "unknown"
    assert s.classify_path("/srv/app/x", ROOT_ROW + row(root, fs_type)).verdict == expected


# ---------------------------------------------------------------------------
# The `//deleted` suffix: before and after, executed
# ---------------------------------------------------------------------------

DELETED = "/srv/app/store.db//deleted"


def test_the_deleted_suffix_was_unread_before_it_was_recognized(monkeypatch):
    """The before-state, executed rather than described.

    With the suffix branch disabled the row is unread — and because its mount
    point is the store's own directory, it is relevant and refuses. That is
    what a store whose bind-mount source had been unlinked actually met.
    """

    monkeypatch.setattr(s, "_DELETED_SUFFIX", "\x00not-a-suffix")
    assert read(DELETED) == []
    table = s.parse_mount_table(ROOT_ROW + row(DELETED))
    assert "not recognized" in table.unparsed[0].reason
    report = s.classify_path("/srv/app/store.db", ROOT_ROW + row(DELETED))
    assert report.verdict == "unknown"
    with pytest.raises(ConfigError, match="could not be verified"):
        s.enforce_substrate(report, STRICT)


def test_the_deleted_suffix_is_read_now_and_the_store_verifies():
    report = s.classify_path("/srv/app/store.db", ROOT_ROW + row(DELETED))
    assert (report.verdict, report.fs_type, report.mount_id) == ("safe", "ext4", 26)
    s.enforce_substrate(report, STRICT)


def test_the_suffix_is_not_scoped_to_a_driver_because_no_driver_emits_it():
    """Unlike an nsfs label, ``//deleted`` does not come from a filesystem's
    ``show_path``: the generic path printer appends it for any unlinked
    dentry. Scoping it to one driver would be a fiction, so the scope is the
    exact suffix on an otherwise valid absolute normalized path."""

    for fs_type in ("ext4", "xfs", "tmpfs", "overlay", "nfs4"):
        assert read(DELETED, fs_type) == [DELETED]
    # And the driver still decides: a network driver under a deleted root is
    # refused exactly as it would be under any other root.
    unsafe = s.classify_path("/srv/app/x", ROOT_ROW + row(DELETED, "nfs4"))
    assert unsafe.verdict == "unsafe"
    with pytest.raises(ConfigError, match="no opt-out"):
        s.enforce_substrate(unsafe, STRICT)


# ---------------------------------------------------------------------------
# Negative controls: these fail before AND after, for every shape
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("root,why", [
    ("//deleted", "the suffix alone is not a path that was deleted"),
    ("/srv//deleted/store.db", "the suffix is a suffix, not a path component"),
    ("/srv/store.db//deletedX", "an exact suffix, not a prefix of one"),
    ("/srv/store.db//DELETED", "not case-folded"),
    ("/srv/../store.db//deleted", "the path before the suffix stays normalized"),
    ("/srv//store.db//deleted", "and stays free of empty components"),
    ("srv/store.db//deleted", "and stays absolute"),
    ("/srv/store.db//deleted\x00", "no NUL anywhere in the field"),
    ("relative", "a bare relative path is not a root"),
    ("", "an empty root field is not a root"),
])
def test_a_near_miss_of_a_recognized_shape_is_not_read(root, why):
    assert read(root) == [], why


@pytest.mark.parametrize("root,fs_type", [
    ("net:[4026533001]", "ext4"),
    ("net:[4026533001]", "overlay"),
    ("mnt:[4026531841]", "tmpfs"),
])
def test_a_kernel_label_is_read_only_for_the_driver_that_emits_it(root, fs_type):
    """The nsfs scoping rule, restated for every shape that a single driver
    does emit: the label is that driver's, and no other driver's."""

    assert read(root, fs_type) == []
    assert read(root, "nsfs") == [root]


@pytest.mark.parametrize("point", ["srv/app", "/srv/../app", "/srv/app\x00x", ""])
def test_recognizing_a_root_never_loosens_mount_point_validation(point):
    """Mount points are how relevance is decided, so they stay strict for
    every root shape, recognized or not."""

    for root in ("/", DELETED, "net:[4026533001]"):
        fs_type = "nsfs" if root.startswith("net:") else "ext4"
        table = s.parse_mount_table(ROOT_ROW + row(root, fs_type, point))
        assert [entry.mount_id for entry in table.entries] == [10]
        assert table.unparsed[0].reason.startswith("mount point")


def test_an_unrecognized_shape_still_refuses_on_the_resolution_path():
    """The residual, as a test: recognition is empirical, so the next shape is
    unread — and unread on the path is a refusal, never a bypass."""

    future = row("futurefs~7!root", "futurefs", "/srv/app")
    assert read("futurefs~7!root", "futurefs") == []
    report = s.classify_path("/srv/app/store.db", ROOT_ROW + future)
    assert report.verdict == "unknown"
    with pytest.raises(ConfigError, match="could not be verified"):
        s.enforce_substrate(report, STRICT)
