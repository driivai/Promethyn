"""Relevance-scoped mount-table parsing: an unreadable row matters where it
could change the answer, and only there.

The regression that started this sprint: one unrelated ``nsfs`` mount — a
Docker service network namespace, whose mount root the kernel writes as a
label (``net:[4026533001]``) rather than a pathname — appeared in
``/proc/self/mountinfo`` on a stock CI runner and flipped the store's verdict
from safe to unknown, refusing startup. The refusal direction was right; the
coupling was not. A row on a subtree the target never touches cannot hide
anything from the target, so it may not degrade the target's resolution.

What is deliberately unchanged: a row that *could* affect the resolution still
refuses. These tests pin both halves — the false refusals that go away, and
the true ones that stay.
"""

from __future__ import annotations

import os
import re
from types import SimpleNamespace

import pytest

from prometheus_protocol.chokepoint import substrate as s
from prometheus_protocol.chokepoint.runner import ConsumedApprovals
from prometheus_protocol.core.errors import ConfigError

STORE = "/srv/app/store.db"
STRICT = s.SubstratePolicy(require_verified=True)

#: An ordinary local table: root and the store's own ext4 mount.
LOCAL = (
    "10 1 8:1 / / rw - ext4 /dev/root rw\n"
    "26 10 8:1 /srv /srv rw - ext4 /dev/root rw\n"
)

#: The observed shape, verbatim in form: kernel label root, parent outside the
#: visible table, on a subtree that has nothing to do with the store.
NSFS_ROW = "1264 25 0:52 net:[4026533001] /run/docker/netns/6d4a rw shared:9 - nsfs nsfs rw\n"


def opened(dev=(8, 1), ino=4242):
    return SimpleNamespace(st_dev=os.makedev(*dev), st_ino=ino)


def points(report):
    return [entry.mount_point for entry in report.set_aside]


# ---------------------------------------------------------------------------
# 1. The regression, and which mechanism actually carries it
# ---------------------------------------------------------------------------


def test_an_unrelated_namespace_mount_leaves_the_store_safe():
    """The reproduction: one nsfs row beside an ordinary ext4 table."""

    report = s.classify_path(STORE, LOCAL + NSFS_ROW)
    assert (report.verdict, report.fs_type, report.mount_id) == ("safe", "ext4", 26)
    s.enforce_substrate(report, STRICT)


def test_the_regression_is_carried_by_relevance_not_by_recognizing_nsfs(monkeypatch):
    """The load-bearing question: is the store safe because the row is
    irrelevant, or only because this parser happens to know ``nsfs``?

    Recognition is switched off — the label no longer matches, exactly as
    before nsfs was ever recognized — and the row becomes unreadable. The
    store is still safe, so relevance carries it. Recognition decides whether
    the row is *read*; relevance decides whether being unread can matter here.
    """

    monkeypatch.setattr(s, "_NAMESPACE_ROOT", re.compile(r"(?!x)x"))
    table = s.parse_mount_table(LOCAL + NSFS_ROW)
    assert [entry.mount_id for entry in table.entries] == [10, 26]
    assert len(table.unparsed) == 1
    assert table.unparsed[0].mount_point == "/run/docker/netns/6d4a"
    assert "not recognized" in table.unparsed[0].reason

    report = s.classify_path(STORE, LOCAL + NSFS_ROW)
    assert (report.verdict, report.mount_id) == ("safe", 26)
    assert points(report) == ["/run/docker/netns/6d4a"]
    s.enforce_substrate(report, STRICT)


def test_an_unrelated_unreadable_row_of_any_shape_leaves_the_store_safe():
    """Not an nsfs special case: any unreadable row off the path is set aside.

    A driver this parser has never heard of, emitting a root format it has
    never seen, on an unrelated subtree.
    """

    row = "1300 25 0:61 futurefs~root!7 /run/futurefs/one rw - futurefs none rw\n"
    report = s.classify_path(STORE, LOCAL + row)
    assert (report.verdict, report.mount_id) == ("safe", 26)
    assert points(report) == ["/run/futurefs/one"]


# ---------------------------------------------------------------------------
# 2. The relevance rule: what still refuses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target,point,why", [
    (STORE, "/", "the root is an ancestor of everything"),
    (STORE, "/srv", "an ancestor could overmount and hide the store's mount"),
    (STORE, "/srv/app", "the store's own directory: a member of that mount stack"),
    (STORE, "/srv/app/store.db", "the target pathname itself"),
    # probe_substrate resolves the store's directory, so a row below that
    # directory is a row the store's own creation could traverse.
    ("/srv/app", "/srv/app/inner", "a descendant could shadow a traversed component"),
])
def test_an_unreadable_row_on_the_resolution_path_refuses(target, point, why):
    row = f"1300 10 0:61 not-a-path {point} rw - futurefs none rw\n"
    report = s.classify_path(target, LOCAL + row)
    assert report.verdict == "unknown", why
    assert point in report.detail and not report.set_aside
    with pytest.raises(ConfigError, match="could not be verified"):
        s.enforce_substrate(report, STRICT)


@pytest.mark.parametrize("row", [
    "this is not a mountinfo line\n",
    "1300 10 0:61 / relative/point rw - futurefs none rw\n",
    "1300 10 0:61 / /srv/../etc rw - futurefs none rw\n",
    "1300 10 0:61 / /run/x\x00y rw - futurefs none rw\n",
    "not-a-number 10 0:61 / /run/x rw - futurefs none rw\n",
    "1300 10 not-a-device / /run/x rw - futurefs none rw\n",
    "\n",
])
def test_a_row_whose_location_is_unreadable_can_never_be_set_aside(row):
    """A row that does not say where it is cannot be shown to be elsewhere.

    This is the conservative half of the rule, and it is why the fix cannot be
    used to make an unreadable table quietly acceptable.
    """

    report = s.classify_path(STORE, LOCAL + row)
    assert (report.verdict, report.set_aside) == ("unknown", ())
    with pytest.raises(ConfigError):
        s.enforce_substrate(report, STRICT)


def test_a_same_path_stack_member_is_relevant_even_below_a_readable_row():
    """Two rows at one pathname are one stack; an unread member of the stack
    over the store's directory could be the mount that actually answers."""

    stack = "1300 26 0:61 kernel-label /srv/app rw - futurefs none rw\n"
    table = LOCAL + "27 26 8:1 /srv/app /srv/app rw - ext4 /dev/root rw\n"
    assert s.classify_path(STORE, table).verdict == "safe"
    report = s.classify_path(STORE, table + stack)
    assert report.verdict == "unknown" and "/srv/app" in report.detail


# ---------------------------------------------------------------------------
# 3. Recorded, never dropped
# ---------------------------------------------------------------------------


def test_every_row_is_either_read_or_recorded_as_unread(monkeypatch):
    """A dropped row is a mount that is not there to be reasoned about."""

    text = LOCAL + NSFS_ROW + "garbage\n" + "1301 10 0:62 / /mnt/x rw - ext4 d rw\n"
    table = s.parse_mount_table(text)
    assert len(table.entries) + len(table.unparsed) == len(text.splitlines()) == 5
    assert [entry.line_number for entry in table.unparsed] == [4]
    assert table.unparsed[0].raw == "garbage"
    # With recognition switched off the nsfs row joins the accounting rather
    # than disappearing from it: unread is a state a row is in, not an exit.
    monkeypatch.setattr(s, "_NAMESPACE_ROOT", re.compile(r"(?!x)x"))
    stricter = s.parse_mount_table(text)
    assert len(stricter.entries) + len(stricter.unparsed) == 5
    assert [entry.line_number for entry in stricter.unparsed] == [3, 4]
    assert stricter.unparsed[0].raw == NSFS_ROW.rstrip("\n")


def test_the_report_names_what_it_set_aside_and_why(monkeypatch):
    monkeypatch.setattr(s, "_NAMESPACE_ROOT", re.compile(r"(?!x)x"))
    report = s.classify_path(STORE, LOCAL + NSFS_ROW)
    summary = report.set_aside_summary()
    assert "1 unreadable mount table entry was recorded and set aside" in summary
    assert "line 3 at /run/docker/netns/6d4a" in summary
    assert "not recognized" in summary
    assert s.classify_path(STORE, LOCAL).set_aside_summary() == ""


def test_an_operator_who_is_refused_still_sees_what_was_set_aside(monkeypatch, caplog):
    """The refusal an operator reads names the ignored rows too, so "it was
    set aside" is never something they have to take on trust."""

    monkeypatch.setattr(s, "_NAMESPACE_ROOT", re.compile(r"(?!x)x"))
    unknown = s.classify_path(STORE, "10 1 8:1 / / rw - overlay o rw\n" + NSFS_ROW)
    assert unknown.verdict == "unknown" and points(unknown) == ["/run/docker/netns/6d4a"]
    with pytest.raises(ConfigError, match="Also recorded: 1 unreadable mount table"):
        s.enforce_substrate(unknown, STRICT)
    with caplog.at_level("WARNING"):
        s.enforce_substrate(unknown, s.SubstratePolicy(allow_unverified=True))
    assert "/run/docker/netns/6d4a" in caplog.text


@pytest.mark.parametrize("table,reason,point", [
    (LOCAL + "26 10 8:1 /srv /other rw - ext4 /dev/root rw\n", "duplicate mount id", "/srv"),
    ("10 1 8:1 / / rw - ext4 r rw\n20 21 0:1 / /a rw - ext4 d rw\n"
     "21 20 0:2 / /a/b rw - ext4 d rw\n", "mount outside parent", "/a"),
    ("10 1 8:1 / / rw - ext4 r rw\n20 20 0:1 / /a rw - ext4 d rw\n",
     "non-root self-parent mount", "/a"),
])
def test_a_topology_anomaly_demotes_its_own_row_and_keeps_its_location(table, reason, point):
    """An incoherent row is the same finding as an unreadable one: the row is
    not trustworthy. Demoting it (rather than failing the table) keeps the
    location, so relevance can still rule it out."""

    parsed = s.parse_mount_table(table)
    assert any(entry.reason == reason for entry in parsed.unparsed), parsed.unparsed
    assert point in [entry.mount_point for entry in parsed.unparsed]
    assert s.classify_path(point + "/store.db", table).verdict == "unknown"
    assert s.classify_path("/unrelated/store.db", table).verdict == "safe"


# ---------------------------------------------------------------------------
# 4. No regression in what the resolver already proved
# ---------------------------------------------------------------------------


HIDDEN = (
    "10 10 8:1 / / rw - ext4 /dev/vda1 rw\n"
    "20 10 8:2 / /srv rw - ext4 /dev/vdb1 rw\n"
    "21 20 0:31 / /srv/private rw - tmpfs tmpfs rw\n"
    "30 20 0:32 / /srv rw - nfs4 server:/shared rw\n"
)


def test_the_hidden_descendant_still_resolves_to_the_overmount():
    """Finding 1A: an earlier child mount hides the lower parent's descendants.
    Relevance scoping is applied to unread rows only; it does not touch this."""

    for table in (HIDDEN, HIDDEN + NSFS_ROW):
        report = s.classify_path("/srv/private/store.db", table)
        assert (report.verdict, report.mount_id, report.fs_type) == ("unsafe", 30, "nfs4")
        with pytest.raises(ConfigError, match="no opt-out"):
            s.enforce_substrate(report, STRICT)


def test_positive_control_a_table_with_no_unread_rows_is_unchanged():
    """Every field of the verdict, on a clean table, is what it always was."""

    clean = s.classify_path(STORE, LOCAL)
    assert (clean.verdict, clean.fs_type, clean.mount_point, clean.mount_id) == (
        "safe", "ext4", "/srv", 26)
    assert clean.set_aside == ()
    # And the same table read strictly, which is what it means for a row to be
    # unread: parse_mountinfo still refuses a table it cannot read entirely.
    assert [entry.mount_id for entry in s.parse_mountinfo(LOCAL)] == [10, 26]
    with pytest.raises(ValueError, match="unreadable mount table row"):
        s.parse_mountinfo(LOCAL + "garbage\n")


# ---------------------------------------------------------------------------
# 5. The opened-object join, where identity is a mount id
# ---------------------------------------------------------------------------


def test_the_descriptor_join_is_unaffected_by_an_irrelevant_unread_row(monkeypatch):
    monkeypatch.setattr(s, "_NAMESPACE_ROOT", re.compile(r"(?!x)x"))
    report = s.classify_opened(opened(), "mnt_id: 26", LOCAL + NSFS_ROW)
    assert (report.verdict, report.fs_type, report.mount_id) == ("safe", "ext4", 26)
    assert points(report) == ["/run/docker/netns/6d4a"]


@pytest.mark.parametrize("row,why", [
    ("26 10 0:61 kernel-label /elsewhere rw - futurefs none rw\n",
     "a row claiming the descriptor's own mount id could be it"),
    ("what 10 0:61 / /elsewhere rw - futurefs none rw\n",
     "a row whose mount id is unreadable might be it"),
])
def test_the_descriptor_join_refuses_a_row_that_could_be_its_mount(row, why):
    report = s.classify_opened(opened(), "mnt_id: 26", LOCAL + row)
    assert report.verdict == "unknown", why
    assert report.set_aside == ()
    with pytest.raises(ConfigError):
        s.enforce_substrate(report, STRICT)


def test_a_location_far_away_does_not_excuse_the_descriptor_s_own_mount_id():
    """Identity, not location, is the rule for the descriptor: the mount the
    kernel named is the object being classified wherever it is attached."""

    row = "26 10 0:61 kernel-label /run/docker/netns/6d4a rw - futurefs none rw\n"
    assert s.classify_path(STORE, LOCAL + row).verdict == "safe"
    assert s.classify_opened(opened(), "mnt_id: 26", LOCAL + row).verdict == "unknown"


# ---------------------------------------------------------------------------
# 6. End to end: the store the regression refused to build
# ---------------------------------------------------------------------------


def store_on(table, tmp_path, monkeypatch, *, target=None):
    """A real ConsumedApprovals whose probes read one synthetic mount table."""

    monkeypatch.setattr(s, "_NAMESPACE_ROOT", re.compile(r"(?!x)x"))
    path = tmp_path / "store.db"
    where = target or STORE
    return ConsumedApprovals(
        path,
        substrate_policy=STRICT,
        probe=lambda _p: s.classify_path(os.path.dirname(where), table),
        opened_probe=lambda _fd: s.classify_opened(opened(), "mnt_id: 26", table),
    )


def test_the_store_builds_and_locks_beside_an_unrelated_namespace_mount(tmp_path, monkeypatch):
    store = store_on(LOCAL + NSFS_ROW, tmp_path, monkeypatch)
    try:
        assert store.claim("relevance-positive-control", "now")
        with store.execution_guard() as held:
            assert held
    finally:
        store.close()


def test_the_store_still_refuses_when_the_unread_row_is_on_its_path(tmp_path, monkeypatch):
    ancestor = "1300 10 0:61 kernel-label /srv rw - futurefs none rw\n"
    with pytest.raises(ConfigError, match="could not be verified"):
        store_on(LOCAL + ancestor, tmp_path, monkeypatch)
