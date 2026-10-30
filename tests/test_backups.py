import copy
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from backups import export_backup, parse_backup, preview_restore, restore_backup
from cases import CaseDetails, CaseError, CaseStore
from labs import LabAssessment, reveal_feedback, submit_assessment
from test_cases import sample_report
from test_labs import lab_report


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = CaseStore(Path(self.directory.name) / "source.sqlite3")
        self.target = CaseStore(Path(self.directory.name) / "target.sqlite3")

    def seed(self):
        case = self.source.create_case(CaseDetails("Original"), sample_report(), actor="First analyst")
        self.source.update_case(case.summary.id, CaseDetails("Reviewed", status="Resolved"),
                                1, actor="Second analyst")
        return case.summary.id

    def test_round_trip_preserves_evidence_ids_timestamps_and_all_history(self):
        case_id = self.seed()
        data = export_backup(self.source)
        preview = preview_restore(self.target, data)
        self.assertEqual((preview.imported, preview.identical, preview.conflicts), (1, 0, ()))
        self.assertEqual(self.target.list_cases(), [])
        restored = restore_backup(self.target, data)
        self.assertEqual(restored.imported, 1)
        self.assertEqual(self.source.get_archive(case_id), self.target.get_archive(case_id))
        repeat = restore_backup(self.target, data)
        self.assertEqual((repeat.imported, repeat.identical, repeat.conflicts), (0, 1, ()))

    def test_conflicts_never_overwrite_even_when_backup_is_newer(self):
        case_id = self.seed()
        restore_backup(self.target, export_backup(self.source))
        self.source.update_case(case_id, CaseDetails("Newer backup"), 2)
        original_target = self.target.get_archive(case_id)
        result = restore_backup(self.target, export_backup(self.source))
        self.assertEqual(result.imported, 0)
        self.assertEqual(len(result.conflicts), 1)
        self.assertIn("not overwritten", result.conflicts[0].reason)
        self.assertEqual(self.target.get_archive(case_id), original_target)

    def test_mixed_merge_imports_new_skips_identical_and_reports_conflict(self):
        conflicting_id = self.seed()
        identical = self.source.create_case(CaseDetails("Identical"), sample_report())
        restore_backup(self.target, export_backup(self.source))
        self.target.update_case(conflicting_id, CaseDetails("Local edits"), 2)
        new_case = self.source.create_case(CaseDetails("Only in backup"), sample_report())
        result = restore_backup(self.target, export_backup(self.source))
        self.assertEqual((result.imported, result.identical, len(result.conflicts)), (1, 1, 1))
        self.assertEqual(self.target.get_case(conflicting_id).details.title, "Local edits")
        self.assertEqual(self.target.get_archive(identical.summary.id),
                         self.source.get_archive(identical.summary.id))
        self.assertEqual(self.target.get_archive(new_case.summary.id),
                         self.source.get_archive(new_case.summary.id))

    def test_preview_is_rechecked_when_target_changes_before_restore(self):
        case_id = self.seed()
        data = export_backup(self.source)
        self.assertEqual(preview_restore(self.target, data).imported, 1)
        restore_backup(self.target, data)
        self.target.update_case(case_id, CaseDetails("Edited after preview"), 2)
        result = restore_backup(self.target, data)
        self.assertEqual(len(result.conflicts), 1)
        self.assertEqual(self.target.get_case(case_id).details.title, "Edited after preview")

    def test_invalid_later_case_prevents_any_import(self):
        self.seed()
        self.source.create_case(CaseDetails("Second"), sample_report())
        payload = json.loads(export_backup(self.source))
        payload["cases"][-1]["case"]["snapshot"]["findings"][0]["packets"][0]["time"] = "bad"
        with self.assertRaises(CaseError):
            restore_backup(self.target, json.dumps(payload).encode())
        self.assertEqual(self.target.list_cases(), [])

    def test_invalid_history_summary_and_snapshots_rejected(self):
        self.seed()
        original = json.loads(export_backup(self.source))
        mutations = (
            lambda value: value["cases"][0]["history"].pop(),
            lambda value: value["cases"][0]["history"][1].update(revision=3),
            lambda value: value["cases"][0]["case"]["summary"].update(title="Mismatch"),
            lambda value: value["cases"][0]["case"]["snapshot"].update(privacy_notice="Redacted"),
            lambda value: value["cases"][0]["case"]["snapshot"].pop("capture"),
            lambda value: value["cases"][0]["case"]["summary"].update(revision=True),
            lambda value: value["cases"][0]["history"][0].update(actor=""),
        )
        for mutate in mutations:
            payload = copy.deepcopy(original)
            mutate(payload)
            with self.subTest(payload=payload["cases"][0]["case"]["summary"]["title"]):
                with self.assertRaises(CaseError):
                    restore_backup(self.target, json.dumps(payload).encode())
        self.assertEqual(self.target.list_cases(), [])

    def test_malformed_duplicate_keys_nonfinite_and_nonbackup_files_rejected(self):
        for data in (b"{}", b"not-json", b"\xff", b'{"a":1,"a":2}', b'{"a": NaN}',
                     json.dumps(sample_report()).encode()):
            with self.subTest(data=data[:30]), self.assertRaises(CaseError):
                parse_backup(data)
        self.seed()
        payload = json.loads(export_backup(self.source))
        payload["cases"].append(copy.deepcopy(payload["cases"][0]))
        with self.assertRaisesRegex(CaseError, "duplicate case IDs"):
            restore_backup(self.target, json.dumps(payload).encode())

    def test_size_version_and_case_count_limits(self):
        self.seed()
        data = export_backup(self.source)
        with patch("backups.MAX_BACKUP_BYTES", 10), self.assertRaisesRegex(CaseError, "20 MB"):
            parse_backup(data)
        with patch("backups.MAX_BACKUP_CASES", 0), self.assertRaises(CaseError):
            parse_backup(data)
        payload = json.loads(data)
        payload["version"] = 999
        with self.assertRaisesRegex(CaseError, "Unsupported backup"):
            parse_backup(json.dumps(payload).encode())

    def test_lab_snapshot_and_revealed_feedback_round_trip(self):
        scenario, report = lab_report("capture-d")
        report = reveal_feedback(submit_assessment(
            scenario, LabAssessment("Authorized activity", "Scheduled backup",
                                    "Volume and job record", "Verify job"), report))
        case = self.source.create_case(CaseDetails("Backup lab"), report)
        restore_backup(self.target, export_backup(self.source))
        self.assertEqual(self.target.get_archive(case.summary.id),
                         self.source.get_archive(case.summary.id))

    def test_database_failure_rolls_back_all_new_cases(self):
        self.seed()
        self.source.create_case(CaseDetails("Second"), sample_report())
        data = export_backup(self.source)
        with patch.object(self.target, "_record_revision", side_effect=CaseError("Disk unavailable")):
            with self.assertRaisesRegex(CaseError, "Disk unavailable"):
                restore_backup(self.target, data)
        self.assertEqual(self.target.list_cases(), [])

    def test_migrated_legacy_baseline_round_trip(self):
        case_id = self.seed()
        with closing(sqlite3.connect(self.source.path)) as connection:
            with connection:
                connection.execute("DROP TABLE case_history")
        restored = restore_backup(self.target, export_backup(self.source))
        self.assertEqual(restored.imported, 1)
        history = self.target.get_archive(case_id).history
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].revision, 2)
        self.assertEqual(history[0].event, "Legacy baseline")
