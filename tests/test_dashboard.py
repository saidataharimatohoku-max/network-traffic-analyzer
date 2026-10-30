import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


@unittest.skipUnless(importlib.util.find_spec("streamlit"), "Install requirements for UI tests")
class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.database = Path(self.directory.name) / "cases.sqlite3"
        patcher = patch("cases.default_database_path", return_value=self.database)
        patcher.start()
        self.addCleanup(patcher.stop)

    def open_app(self):
        from streamlit.testing.v1 import AppTest

        return AppTest.from_file(
            str(Path(__file__).resolve().parents[1] / "app.py")).run(timeout=30)

    def test_demo_and_settings(self):
        app = self.open_app()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual([metric.value for metric in app.metric], ["15", "3,140", "12s", "1"])
        self.assertEqual(app.code[0].value, "frame.number in {1..10}")
        table = next(item.value for item in app.dataframe if "Capture frame" in item.value)
        self.assertEqual(table["Capture frame"].tolist(), list(range(1, 11)))
        next(item for item in app.number_input if item.label == "Bytes per source per window"
             ).set_value(1000).run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(app.metric[3].value, "2")
        next(item for item in app.text_area if item.label.startswith("Investigation notes")
             ).set_value("Validate against host logs").run()
        self.assertEqual(len(app.exception), 0)
        app.checkbox[0].uncheck().run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(len(app.metric), 0)

    def test_save_restart_reopen_and_edit_without_capture(self):
        from cases import CaseStore

        app = self.open_app()
        app.text_input[0].set_value("Lab scan investigation")
        next(item for item in app.text_area if item.label == "Root-cause hypothesis"
             ).set_value("Possibly an approved scanner")
        next(button for button in app.button if button.label == "Save new case locally"
             ).click().run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any("Case saved:" in item.value for item in app.success))
        store = CaseStore(self.database)
        saved = store.get_case(store.list_cases()[0].id)
        self.assertEqual(saved.details.root_cause, "Possibly an approved scanner")
        self.assertEqual(len(saved.snapshot["findings"][0]["packets"]), 10)

        restarted = self.open_app()
        restarted.radio[0].set_value("Saved cases").run()
        self.assertEqual(len(restarted.exception), 0)
        self.assertEqual(len(restarted.file_uploader), 0)
        self.assertEqual(restarted.text_input[0].value, "Lab scan investigation")
        self.assertEqual(restarted.code[0].value, "frame.number in {1..10}")
        next(item for item in restarted.selectbox if item.label == "Status").set_value("Resolved")
        next(item for item in restarted.selectbox if item.label == "Disposition"
             ).set_value("Authorized activity")
        next(item for item in restarted.text_area if item.label == "Analyst assessment / notes"
             ).set_value("Confirmed scheduled scan against lab inventory.")
        next(button for button in restarted.button if button.label == "Save case changes"
             ).click().run()
        self.assertEqual(len(restarted.exception), 0)
        updated = CaseStore(self.database).get_case(saved.summary.id)
        self.assertEqual(updated.details.status, "Resolved")
        self.assertEqual(updated.details.disposition, "Authorized activity")
        self.assertEqual(updated.snapshot, saved.snapshot)

    def test_empty_saved_cases_without_capture(self):
        app = self.open_app()
        app.radio[0].set_value("Saved cases").run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any("No saved cases yet" in item.value for item in app.info))

    def test_case_validation_error_is_visible(self):
        app = self.open_app()
        app.text_input[0].set_value(" ")
        next(button for button in app.button if button.label == "Save new case locally"
             ).click().run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any("Case title" in item.value for item in app.error))

    def test_all_evidence_saved_when_only_last_page_is_visible(self):
        from analyzer import Packet
        from cases import CaseStore

        packets = [Packet(i, i / 100, "192.0.2.1", "198.51.100.1",
                          "TCP", 10_000, "[ACK]", 443, i) for i in range(1, 251)]
        with patch("analyzer.parse_csv", return_value=(packets, [])):
            app = self.open_app()
            next(item for item in app.number_input if item.label.startswith("Evidence page")
                 ).set_value(3).run()
            table = next(item.value for item in app.dataframe if "Capture frame" in item.value)
            self.assertEqual(table["Capture frame"].tolist(), list(range(201, 251)))
            next(button for button in app.button if button.label == "Save new case locally"
                 ).click().run()
            self.assertEqual(len(app.exception), 0)
        store = CaseStore(self.database)
        case = store.get_case(store.list_cases()[0].id)
        evidence = case.snapshot["findings"][0]
        self.assertEqual(len(evidence["packets"]), 250)
        self.assertEqual(evidence["wireshark_filter"], "frame.number in {1..250}")
        self.assertEqual(sum(packet["length"] for packet in evidence["packets"]), 2_500_000)

    def test_conflicting_edit_is_visible_and_reload_works(self):
        from cases import CaseDetails, CaseStore
        from test_cases import sample_report

        store = CaseStore(self.database)
        saved = store.create_case(CaseDetails("Original title"), sample_report())
        app = self.open_app()
        app.radio[0].set_value("Saved cases").run()
        store.update_case(saved.summary.id, CaseDetails("Edited elsewhere"), 1)
        app.text_input[0].set_value("Stale browser edit")
        next(button for button in app.button if button.label == "Save case changes"
             ).click().run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any("changed elsewhere" in item.value for item in app.error))
        self.assertEqual(store.get_case(saved.summary.id).details.title, "Edited elsewhere")
        next(button for button in app.button if button.label.startswith("Reload case")
             ).click().run()
        self.assertEqual(app.text_input[0].value, "Edited elsewhere")

    def test_storage_failure_is_not_shown_as_success(self):
        from cases import CaseError

        app = self.open_app()
        with patch("cases.CaseStore.create_case", side_effect=CaseError("Database is read-only")):
            next(button for button in app.button if button.label == "Save new case locally"
                 ).click().run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any("read-only" in item.value for item in app.error))
        self.assertFalse(any("Case saved:" in item.value for item in app.success))

    def lab_app(self, scenario_id="capture-b"):
        app = self.open_app()
        app.radio[0].set_value("Guided lab").run()
        next(item for item in app.selectbox if item.label == "Practice capture"
             ).set_value(scenario_id).run()
        self.assertEqual(len(app.exception), 0)
        return app

    def submit_lab(self, app):
        next(item for item in app.selectbox if item.label == "Your disposition"
             ).set_value("Authorized activity")
        next(item for item in app.text_area if item.label == "Your hypothesis"
             ).set_value("An approved scanner is probing the target.")
        next(item for item in app.text_area if item.label.startswith("Your supporting")
             ).set_value("Frames 1-10 show distinct SYN destination ports; CHG-104 authorizes it.")
        next(item for item in app.text_area if item.label == "Your next investigation step"
             ).set_value("Verify source identity and change scope.")
        next(button for button in app.button if button.label == "Submit assessment").click().run()
        self.assertEqual(len(app.exception), 0)

    def test_lab_requires_assessment_before_reveal(self):
        app = self.lab_app()
        self.assertFalse(any(button.label == "Reveal reference explanation" for button in app.button))
        next(button for button in app.button if button.label == "Submit assessment").click().run()
        self.assertTrue(any("Record a hypothesis" in item.value for item in app.error))
        self.submit_lab(app)
        state = app.session_state["lab-attempt-capture-b-v1"]
        self.assertIsNone(state["report"]["guided_lab"]["feedback"])
        next(button for button in app.button if button.label == "Reveal reference explanation"
             ).click().run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(app.session_state["lab-attempt-capture-b-v1"]["report"]
                        ["guided_lab"]["feedback"]["disposition_matches"])

    def test_lab_attempt_can_be_saved_and_reopened_with_feedback(self):
        from cases import CaseStore

        app = self.lab_app()
        self.submit_lab(app)
        next(button for button in app.button if button.label == "Reveal reference explanation"
             ).click().run()
        next(button for button in app.button if button.label == "Save lab attempt as case"
             ).click().run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(next(button for button in app.button
                             if button.label == "Save lab attempt as case").disabled)
        store = CaseStore(self.database)
        case = store.get_case(store.list_cases()[0].id)
        self.assertEqual(case.details.disposition, "Authorized activity")
        self.assertIsNotNone(case.snapshot["guided_lab"]["feedback"])
        restarted = self.open_app()
        restarted.radio[0].set_value("Saved cases").run()
        self.assertEqual(len(restarted.exception), 0)
        self.assertTrue(any(heading.value == "Reference explanation" for heading in restarted.subheader))

    def test_lab_state_is_separate_and_reset_does_not_delete_cases(self):
        from cases import CaseStore

        app = self.lab_app()
        self.submit_lab(app)
        next(button for button in app.button if button.label == "Save lab attempt as case"
             ).click().run()
        next(button for button in app.button if button.label == "Reveal reference explanation"
             ).click().run()
        case = CaseStore(self.database).get_case(CaseStore(self.database).list_cases()[0].id)
        self.assertIsNone(case.snapshot["guided_lab"]["feedback"])
        next(item for item in app.selectbox if item.label == "Practice capture"
             ).set_value("capture-c").run()
        self.assertTrue(any(button.label == "Submit assessment" for button in app.button))
        next(item for item in app.selectbox if item.label == "Practice capture"
             ).set_value("capture-b").run()
        self.assertIsNotNone(app.session_state["lab-attempt-capture-b-v1"]["report"]
                             ["guided_lab"]["feedback"])
        next(button for button in app.button if button.label.startswith("Start a new attempt")
             ).click().run()
        self.assertEqual(len(app.exception), 0)
        self.assertIsNone(app.session_state["lab-attempt-capture-b-v1"]["report"])
        self.assertEqual(len(CaseStore(self.database).list_cases()), 1)

    def test_all_lab_captures_render_with_fixed_thresholds(self):
        app = self.lab_app("capture-a")
        self.assertEqual(app.metric[3].value, "0")
        for scenario_id, count in (("capture-b", "1"), ("capture-c", "1"), ("capture-d", "1")):
            next(item for item in app.selectbox if item.label == "Practice capture"
                 ).set_value(scenario_id).run()
            self.assertEqual(len(app.exception), 0)
            self.assertEqual(app.metric[3].value, count)
        self.assertFalse(any(item.label == "Bytes per source per window" for item in app.number_input))

    def test_history_shows_changes_and_analyst_attribution(self):
        from cases import CaseDetails, CaseStore
        from test_cases import sample_report

        store = CaseStore(self.database)
        case = store.create_case(CaseDetails("Initial"), sample_report(), actor="Analyst One")
        store.update_case(case.summary.id, CaseDetails("Reviewed", assessment="Confirmed"),
                           1, actor="Analyst Two")
        app = self.open_app()
        app.radio[0].set_value("Saved cases").run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any("Recorded by: Analyst One" in item.value for item in app.text))
        self.assertTrue(any("Recorded by: Analyst Two" in item.value for item in app.text))
        changes = [json.loads(item.value) for item in app.json]
        self.assertTrue(any(item.get("title") == {"before": "Initial", "after": "Reviewed"}
                            for item in changes if isinstance(item, dict)))

    def test_backup_preview_confirmation_and_repeat_merge(self):
        from backups import export_backup
        from cases import CaseDetails, CaseStore
        from test_cases import sample_report

        source = CaseStore(Path(self.directory.name) / "backup-source.sqlite3")
        source.create_case(CaseDetails("Imported case"), sample_report())
        data = export_backup(source)
        app = self.open_app()
        with patch("streamlit.file_uploader", return_value=io.BytesIO(data)):
            app.radio[0].set_value("Backups").run()
            self.assertEqual(len(app.exception), 0)
            self.assertTrue(any("New cases to import: 1" in item.value for item in app.text))
            merge = next(button for button in app.button if button.label == "Merge new cases from backup")
            self.assertTrue(merge.disabled)
            self.assertEqual(CaseStore(self.database).list_cases(), [])
            next(item for item in app.checkbox if item.label.startswith("I confirm")).check().run()
            next(button for button in app.button if button.label == "Merge new cases from backup"
                 ).click().run()
            self.assertEqual(len(app.exception), 0)
            self.assertTrue(any("imported 1" in item.value for item in app.success))
            self.assertEqual(len(CaseStore(self.database).list_cases()), 1)
            next(button for button in app.button if button.label == "Merge new cases from backup"
                 ).click().run()
            self.assertTrue(any("skipped 1 identical" in item.value for item in app.success))

    def test_backup_errors_and_conflicts_are_visible_without_overwriting(self):
        from backups import export_backup, restore_backup
        from cases import CaseDetails, CaseStore
        from test_cases import sample_report

        source = CaseStore(Path(self.directory.name) / "backup-source.sqlite3")
        case = source.create_case(CaseDetails("Backup version"), sample_report())
        data = export_backup(source)
        target = CaseStore(self.database)
        restore_backup(target, data)
        target.update_case(case.summary.id, CaseDetails("Keep local changes"), 1)
        app = self.open_app()
        with patch("streamlit.file_uploader", return_value=io.BytesIO(data)):
            app.radio[0].set_value("Backups").run()
            self.assertTrue(any("will NOT be overwritten" in item.value for item in app.warning))
            next(item for item in app.checkbox if item.label.startswith("I confirm")).check().run()
            next(button for button in app.button if button.label == "Merge new cases from backup"
                 ).click().run()
            self.assertEqual(len(app.exception), 0)
            self.assertEqual(target.get_case(case.summary.id).details.title, "Keep local changes")
        with patch("streamlit.file_uploader", return_value=io.BytesIO(b"not-json")):
            app.run()
            self.assertEqual(len(app.exception), 0)
            self.assertTrue(any("Cannot read backup JSON" in item.value for item in app.error))
            self.assertFalse(any(button.label == "Merge new cases from backup" for button in app.button))

    def test_anonymized_downloads_leave_analysis_and_stored_evidence_unchanged(self):
        from cases import CaseDetails, CaseStore
        from test_cases import sample_report

        store = CaseStore(self.database)
        case = store.create_case(
            CaseDetails("Private workstation", assessment="Internal analyst notes"),
            sample_report(), actor="Private analyst",
        )
        downloads = []

        def capture_download(label, data, *args, **kwargs):
            if label.startswith("Download saved case"):
                downloads.append((label, data, args[0]))
            return False

        app = self.open_app()
        app.radio[0].set_value("Saved cases").run()
        with patch("streamlit.download_button", side_effect=capture_download):
            next(item for item in app.checkbox if item.label == "Anonymize sharing exports"
                 ).check().run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(len(downloads), 2)
        for label, content, filename in downloads:
            self.assertNotIn("192.0.2.10", content)
            self.assertNotIn("Private analyst", content)
            self.assertNotIn(case.summary.id, filename)
        json_copy = json.loads(downloads[0][1])
        self.assertIn("privacy_notice", json_copy["snapshot"])
        self.assertIn("history", json_copy)
        self.assertEqual(store.get_case(case.summary.id), case)
        self.assertEqual(app.code[0].value, "frame.number in {1..10}")

    def test_anonymized_analysis_and_lab_downloads(self):
        downloads = []

        def capture_download(label, data, *args, **kwargs):
            if label.endswith("(JSON)"):
                downloads.append(json.loads(data))
            return False

        app = self.open_app()
        with patch("streamlit.download_button", side_effect=capture_download):
            next(item for item in app.checkbox if item.label == "Anonymize sharing exports"
                 ).check().run()
        self.assertEqual(len(app.exception), 0)
        self.assertIn("privacy_notice", downloads[-1])
        self.assertNotIn("192.0.2.10", json.dumps(downloads[-1]))
        app = self.lab_app()
        self.submit_lab(app)
        with patch("streamlit.download_button", side_effect=capture_download):
            next(item for item in app.checkbox if item.label == "Anonymize sharing exports"
                 ).check().run()
        self.assertEqual(len(app.exception), 0)
        self.assertIn("privacy_notice", downloads[-1])
        self.assertNotIn("192.0.2.10", json.dumps(downloads[-1]))
        state = app.session_state["lab-attempt-capture-b-v1"]["report"]
        self.assertEqual(state["findings"][0]["source"], "192.0.2.10")
