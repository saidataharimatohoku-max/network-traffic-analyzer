import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from analyzer import analyze, make_report, parse_csv
from cases import CaseDetails, CaseError, CaseStore, default_database_path


def sample_report():
    packets, warnings = parse_csv(
        Path(__file__).resolve().parents[1].joinpath("sample.csv").read_bytes())
    report = make_report(packets, analyze(packets), warnings,
                         {"window_seconds": 10, "scan_ports": 10, "volume_bytes": 1_000_000},
                         "Original capture notes")
    report["capture"] = {"name": "sample.csv", "csv_sha256": "demo"}
    return report


class CaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "private" / "cases.sqlite3"
        self.store = CaseStore(self.path)

    def test_save_reopen_and_edit_preserves_snapshot(self):
        report = sample_report()
        original = json.loads(json.dumps(report))
        created = self.store.create_case(CaseDetails("Demo", assessment="Initial"), report)
        report["findings"].clear()
        reopened = CaseStore(self.path).get_case(created.summary.id)
        self.assertEqual(reopened.snapshot, original)
        changed = CaseStore(self.path).update_case(
            reopened.summary.id,
            CaseDetails("Reviewed", "Resolved", "Authorized activity",
                        "Approved scan", "Scheduled scanner", "Document exception"),
            reopened.summary.revision,
        )
        after_restart = CaseStore(self.path).get_case(changed.summary.id)
        self.assertEqual(after_restart.details, changed.details)
        self.assertEqual(after_restart.summary.revision, 2)
        self.assertEqual(after_restart.snapshot, original)
        self.assertEqual(after_restart.summary.created_at, created.summary.created_at)

    def test_summary_and_parameterized_title(self):
        case = self.store.create_case(CaseDetails("'; DROP TABLE cases; --"), sample_report())
        summaries = self.store.list_cases()
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0].id, case.summary.id)
        self.assertEqual(summaries[0].title, "'; DROP TABLE cases; --")

    def test_concurrent_edits_do_not_overwrite(self):
        case = self.store.create_case(CaseDetails("Demo"), sample_report())
        self.store.update_case(case.summary.id, CaseDetails("First edit"), 1)
        with self.assertRaisesRegex(CaseError, "changed elsewhere"):
            self.store.update_case(case.summary.id, CaseDetails("Stale edit"), 1)
        self.assertEqual(self.store.get_case(case.summary.id).details.title, "First edit")

    def test_invalid_input_is_not_saved(self):
        for details in (CaseDetails(" "), CaseDetails("x" * 201),
                        CaseDetails("Demo", status="Unknown"),
                        CaseDetails("Demo", disposition="Unknown"),
                        CaseDetails("Demo", assessment="x" * 50_001)):
            with self.subTest(details=details.title[:10]), self.assertRaises(CaseError):
                self.store.create_case(details, sample_report())
        self.assertEqual(self.store.list_cases(), [])

    def test_missing_case_and_storage_error_are_explicit(self):
        with self.assertRaisesRegex(CaseError, "no longer exists"):
            self.store.get_case("not-present")
        blocker = Path(self.directory.name) / "not-a-directory"
        blocker.write_text("blocker")
        with self.assertRaisesRegex(CaseError, "Cannot access"):
            CaseStore(blocker / "cases.sqlite3").list_cases()

    def test_bad_snapshot_and_corrupt_saved_evidence(self):
        with self.assertRaisesRegex(CaseError, "unsupported"):
            self.store.create_case(CaseDetails("Demo"), {})
        case = self.store.create_case(CaseDetails("Demo"), sample_report())
        with closing(sqlite3.connect(self.path)) as connection:
            with connection:
                connection.execute("UPDATE cases SET snapshot = ? WHERE id = ?",
                                   ("not-json", case.summary.id))
        with self.assertRaisesRegex(CaseError, "unreadable evidence"):
            self.store.get_case(case.summary.id)

    def test_invalid_update_keeps_previous_details(self):
        case = self.store.create_case(CaseDetails("Demo"), sample_report())
        with self.assertRaises(CaseError):
            self.store.update_case(case.summary.id, replace(case.details, title=""), 1)
        self.assertEqual(self.store.get_case(case.summary.id).details.title, "Demo")

    def test_default_path_is_outside_project(self):
        with patch.dict("os.environ", {"LOCALAPPDATA": self.directory.name}):
            self.assertEqual(default_database_path(),
                             Path(self.directory.name) / "NetworkTrafficInvestigator"
                             / "cases.sqlite3")

    def test_revision_history_survives_restart_and_records_actor(self):
        created = self.store.create_case(CaseDetails("Demo"), sample_report(), actor="Analyst A")
        self.store.update_case(created.summary.id,
                               CaseDetails("Reviewed", status="Investigating", assessment="Checked"),
                               1, actor="Analyst B")
        archive = CaseStore(self.path).get_archive(created.summary.id)
        self.assertEqual([entry.revision for entry in archive.history], [1, 2])
        self.assertEqual([entry.actor for entry in archive.history], ["Analyst A", "Analyst B"])
        self.assertEqual(archive.history[0].details.title, "Demo")
        self.assertEqual(archive.history[1].details.assessment, "Checked")
        self.assertEqual(archive.history[-1].details, archive.case.details)
        self.assertEqual(archive.case.snapshot, created.snapshot)

    def test_history_failure_rolls_back_case_update(self):
        created = self.store.create_case(CaseDetails("Demo"), sample_report())
        with patch.object(self.store, "_record_revision", side_effect=CaseError("History unavailable")):
            with self.assertRaisesRegex(CaseError, "History unavailable"):
                self.store.update_case(created.summary.id, CaseDetails("Not committed"), 1)
        archive = self.store.get_archive(created.summary.id)
        self.assertEqual(archive.case.summary.revision, 1)
        self.assertEqual(archive.case.details.title, "Demo")
        self.assertEqual(len(archive.history), 1)

    def test_legacy_migration_keeps_current_revision_without_inventing_past(self):
        case = self.store.create_case(CaseDetails("Initial"), sample_report())
        self.store.update_case(case.summary.id, CaseDetails("Second"), 1)
        self.store.update_case(case.summary.id, CaseDetails("Third"), 2)
        with closing(sqlite3.connect(self.path)) as connection:
            with connection:
                connection.execute("DROP TABLE case_history")
        migrated = CaseStore(self.path).get_archive(case.summary.id)
        self.assertEqual(migrated.case.summary.revision, 3)
        self.assertEqual(len(migrated.history), 1)
        self.assertEqual(migrated.history[0].event, "Legacy baseline")
        self.assertEqual(migrated.history[0].actor, "Unknown (pre-history)")
        CaseStore(self.path).update_case(case.summary.id, CaseDetails("Fourth"), 3)
        self.assertEqual([entry.revision for entry in self.store.get_archive(case.summary.id).history],
                         [3, 4])
        self.assertEqual(migrated.case.snapshot, case.snapshot)

    def test_invalid_actor_and_conflict_do_not_add_history(self):
        created = self.store.create_case(CaseDetails("Demo"), sample_report())
        for actor in (" ", "x" * 101):
            with self.assertRaises(CaseError):
                self.store.update_case(created.summary.id, CaseDetails("Not saved"), 1, actor=actor)
        self.store.update_case(created.summary.id, CaseDetails("Reviewed"), 1)
        with self.assertRaises(CaseError):
            self.store.update_case(created.summary.id, CaseDetails("Stale"), 1)
        self.assertEqual(len(self.store.get_archive(created.summary.id).history), 2)

    def test_history_failure_does_not_leave_partially_created_case(self):
        with patch.object(self.store, "_record_revision", side_effect=CaseError("History unavailable")):
            with self.assertRaises(CaseError):
                self.store.create_case(CaseDetails("Not committed"), sample_report())
        self.assertEqual(self.store.list_cases(), [])
