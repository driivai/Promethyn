"""Executed opened-substrate guard mutations; production files remain intact.

Reuse the established call-phase/error/skip accounting, with a separate mutation
list and exact pins. No pin may be updated without its executed evidence.
"""

from prometheus_protocol.chokepoint import substrate, runner, authorization_journal
import fix_b_revert_proofs as harness

UNIT = "tests/chokepoint/test_opened_substrate.py"
BUILD = "tests/chokepoint/test_substrate.py"
JOURNAL = "tests/chokepoint/test_authorization_record.py"
EXPECTED_REVERTS = 20
EXPECTED_CALL_FAILURES = 53


def enforce_expected(caught: int, failures: int) -> None:
    if caught != EXPECTED_REVERTS or failures != EXPECTED_CALL_FAILURES:
        raise AssertionError(
            f"substrate revert count drifted: {caught} / {failures} observed; "
            f"{EXPECTED_REVERTS} / {EXPECTED_CALL_FAILURES} pinned"
        )


def mutations():
    return [
        ("hidden-mount-longest-prefix", substrate.mount_for,
         [("    ids = {entry.mount_id for entry in entries}",
           "    return max((e for e in entries if _covers(e.mount_point, path)), key=lambda e: len(e.mount_point), default=None)\n    ids = {entry.mount_id for entry in entries}")],
         UNIT, "hidden_descendant_is_not_visible"),
        ("ambiguous-mount-first-wins", substrate.mount_for,
         [("if len(next_mounts) != 1:", "if False:")],
         UNIT, "unresolvable_topology"),
        ("descriptor-device-check-removed", substrate.classify_opened,
         [("if entry.device != (os.major(info.st_dev), os.minor(info.st_dev)):", "if False:")],
         UNIT, "descriptor_device_mismatch"),
        ("descriptor-mount-id-ignored", substrate.classify_opened,
         [("if e.mount_id == mount_id", "if e.fs_type == 'ext4'")],
         UNIT, "descriptor_identity_not_path_or_device_alone"),
        ("store-object-check-removed", runner.ConsumedApprovals._open_guard,
         [("enforce_substrate(self.substrate, self._substrate_policy)", "pass")],
         UNIT, "opened_store_refuses_despite_safe_parent"),
        ("builder-object-check-removed", runner.ConsumedApprovals._open_guard,
         [("enforce_substrate(self.substrate, self._substrate_policy)", "pass")],
         BUILD, "builder_refuses_an_unsafe_opened_store or builder_refuses_an_unknown_substrate or builder_honours_the_requirement"),
        ("held-lock-check-removed", runner.ConsumedApprovals.execution_guard.__wrapped__,
         [("enforce_substrate(self._opened_probe(fd), self._substrate_policy)", "pass")],
         UNIT, "held_lock_object_is_reinspected and False"),
        ("journal-queries-parent", authorization_journal.AuthorizationJournal._check_path,
         [("probe_file_substrate(self.path)", "probe_file_substrate(self.path.parent)")],
         JOURNAL, "private_storage_separately_mounted_file"),
        ("unknown-object-assumed-safe", substrate.classify_opened,
         [("SubstrateReport(\"opened object\", SUBSTRATE_UNKNOWN", "SubstrateReport(\"opened object\", SUBSTRATE_SAFE")],
         UNIT, "missing_or_ambiguous_descriptor_mount"),
        ("journal-substrate-check-removed", authorization_journal.AuthorizationJournal._check_path,
         [("enforce_substrate(report, self._substrate_policy)", "pass")],
         JOURNAL, "private_storage_separately_mounted_file"),
        ("journal-opened-identity-check-removed", authorization_journal.AuthorizationJournal._check_path,
         [("if report.device is not None and (report.device, report.inode) != self._identity:", "if False:")],
         UNIT, "journal_rechecks_before_operation and identity"),
        ("journal-opath-replaced-by-ordinary-fd", substrate.probe_file_substrate,
         [("os.O_PATH | os.O_NOFOLLOW", "os.O_RDONLY | os.O_NOFOLLOW")],
         UNIT, "journal_inspection_uses_o_path"),
        ("direct-policy-booleans-not-validated", substrate.SubstratePolicy.__post_init__,
         [('    require_bool(self.require_verified, name="SubstratePolicy.require_verified")',
           '    return\n    require_bool(self.require_verified, name="SubstratePolicy.require_verified")')],
         UNIT, "direct_policy_uses_strict_booleans"),
        ("unreadable-metadata-assumed-safe", substrate.probe_opened_substrate,
         [('SubstrateReport("opened object", SUBSTRATE_UNKNOWN', 'SubstrateReport("opened object", SUBSTRATE_SAFE')],
         UNIT, "real_descriptor_probe_reads_both_metadata_sources"),
        ("journal-operation-recheck-removed", authorization_journal.AuthorizationJournal._session.__wrapped__,
         [("self._check_path()", "pass")],
         UNIT, "journal_rechecks_before_operation"),
        ("policy-sources-short-circuited", substrate.resolve_substrate_policy,
         [('    allow = any((', '    allow = bool(getattr(config, "allow_unverified_substrate", False)) or any((')],
         UNIT, "requirement_does_not_hide_invalid_opt_out_source"),
        ("namespace-label-rejected-as-path", substrate._valid_mount_root,
         [('return fs_type == "nsfs" and _NAMESPACE_ROOT.fullmatch(root) is not None', 'return False')],
         UNIT, "namespace_root_label_preserves"),
        ("namespace-label-driver-unchecked", substrate._valid_mount_root,
         [('fs_type == "nsfs" and ', '')],
         UNIT, "namespace_metadata_does_not_weaken_validation"),
        ("namespace-label-shape-unchecked", substrate._valid_mount_root,
         [(' and _NAMESPACE_ROOT.fullmatch(root) is not None', '')],
         UNIT, "namespace_metadata_does_not_weaken_validation"),
        ("namespace-entry-discarded", substrate.parse_mountinfo,
         [('        ids.add(mount_id)', '        if fs_type == "nsfs":\n            continue\n        ids.add(mount_id)')],
         UNIT, "namespace_root_label_preserves"),
    ]


def main() -> int:
    saved = (harness.mutations, harness.enforce_expected,
             harness.EXPECTED_REVERTS, harness.EXPECTED_CALL_FAILURES)
    try:
        harness.mutations = mutations
        harness.enforce_expected = enforce_expected
        harness.EXPECTED_REVERTS = EXPECTED_REVERTS
        harness.EXPECTED_CALL_FAILURES = EXPECTED_CALL_FAILURES
        return harness.main()
    finally:
        (harness.mutations, harness.enforce_expected,
         harness.EXPECTED_REVERTS, harness.EXPECTED_CALL_FAILURES) = saved


if __name__ == "__main__":
    raise SystemExit(main())
