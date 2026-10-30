import hashlib
import json
import unittest

from analyzer import analyze, make_report, parse_csv
from labs import (LAB_CHOICES, LAB_SETTINGS, LabAssessment, LabError,
                  get_scenario, reveal_feedback, submit_assessment)


def lab_report(scenario_id="capture-b"):
    scenario = get_scenario(scenario_id)
    packets, warnings = parse_csv(scenario.csv_data)
    findings = analyze(packets)
    report = make_report(packets, findings, warnings, dict(LAB_SETTINGS), "Lab investigation")
    report["capture"] = {"name": scenario_id + ".csv",
                         "csv_sha256": hashlib.sha256(scenario.csv_data).hexdigest()}
    return scenario, report


class LabTests(unittest.TestCase):
    def test_all_scenarios_have_expected_rule_outputs(self):
        expected = {
            "capture-a": (6, [], "Authorized activity"),
            "capture-b": (12, ["Potential port scan"], "Authorized activity"),
            "capture-c": (12, ["Potential port scan"], "Suspicious"),
            "capture-d": (800, ["High traffic volume"], "Authorized activity"),
        }
        for scenario_id, (count, rules, disposition) in expected.items():
            with self.subTest(scenario=scenario_id):
                scenario, report = lab_report(scenario_id)
                self.assertEqual(report["packet_count"], count)
                self.assertEqual([item["rule"] for item in report["findings"]], rules)
                self.assertEqual(list(scenario.expected_rules), rules)
                self.assertEqual(scenario.expected_disposition, disposition)
                self.assertEqual(scenario.csv_data, get_scenario(scenario_id).csv_data)

    def test_backup_threshold_and_complete_evidence(self):
        _, report = lab_report("capture-d")
        self.assertEqual(report["captured_bytes"], 1_200_000)
        finding = report["findings"][0]
        self.assertEqual(len(finding["packets"]), 800)
        self.assertEqual(finding["wireshark_filter"], "frame.number in {1..800}")
        self.assertEqual(sum(packet["length"] for packet in finding["packets"]), 1_200_000)

    def test_reference_is_absent_until_explicit_reveal(self):
        scenario, report = lab_report()
        assessment = LabAssessment("Inconclusive", "A scan pattern", "Frames 1-10", "Check change log")
        submitted = submit_assessment(scenario, assessment, report)
        self.assertNotIn("guided_lab", report)
        self.assertIsNone(submitted["guided_lab"]["feedback"])
        self.assertNotIn(scenario.explanation, json.dumps(submitted))
        revealed = reveal_feedback(submitted)
        self.assertIsNone(submitted["guided_lab"]["feedback"])
        self.assertEqual(revealed["guided_lab"]["assessment"], submitted["guided_lab"]["assessment"])
        self.assertEqual(revealed["guided_lab"]["feedback"]["explanation"], scenario.explanation)
        self.assertFalse(revealed["guided_lab"]["feedback"]["disposition_matches"])

    def test_matches_reference_without_claiming_evidence_grade(self):
        scenario, report = lab_report("capture-c")
        submitted = submit_assessment(
            scenario, LabAssessment("Suspicious", "Unapproved scan", "Frames 1-10",
                                    "Correlate host logs"), report)
        feedback = reveal_feedback(submitted)["guided_lab"]["feedback"]
        self.assertTrue(feedback["disposition_matches"])
        self.assertIn("not an automated grade", feedback["notice"])

    def test_incomplete_assessments_and_unknown_labs_are_rejected(self):
        scenario, report = lab_report()
        for assessment in (
            LabAssessment("Unknown", "h", "e", "n"),
            LabAssessment("Inconclusive", " ", "e", "n"),
            LabAssessment("Inconclusive", "h", "", "n"),
            LabAssessment("Inconclusive", "h", "e", ""),
            LabAssessment("Inconclusive", "h" * 10_001, "e", "n"),
        ):
            with self.subTest(assessment=assessment.disposition), self.assertRaises(LabError):
                submit_assessment(scenario, assessment, report)
        with self.assertRaises(LabError):
            get_scenario("not-a-lab")
        with self.assertRaises(LabError):
            reveal_feedback(report)

    def test_attempts_do_not_share_mutable_evidence(self):
        scenario, report = lab_report()
        assessment = LabAssessment("Inconclusive", "h", "e", "n")
        submitted = submit_assessment(scenario, assessment, report)
        report["findings"].clear()
        self.assertEqual(len(submitted["findings"]), 1)
        self.assertEqual(len(LAB_CHOICES), 4)

    def test_no_finding_lab_still_preserves_packets_for_review(self):
        scenario, report = lab_report("capture-a")
        submitted = submit_assessment(
            scenario, LabAssessment("Authorized activity", "Normal browsing",
                                    "DNS and handshake", "Check destination inventory"), report)
        self.assertEqual(submitted["findings"], [])
        self.assertEqual(len(submitted["practice_packets"]), 6)
        self.assertEqual([packet["frame_number"] for packet in submitted["practice_packets"]],
                         list(range(1, 7)))
