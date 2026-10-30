import json
import unittest

from privacy import prepare_export
from test_cases import sample_report
from test_labs import lab_report
from labs import LabAssessment, reveal_feedback, submit_assessment


class PrivacyTests(unittest.TestCase):
    def test_unredacted_export_is_an_independent_exact_copy(self):
        original = sample_report()
        copy = prepare_export(original)
        self.assertEqual(copy, original)
        copy["findings"].clear()
        self.assertEqual(len(original["findings"]), 1)

    def test_report_addresses_consistent_and_original_unchanged(self):
        original = sample_report()
        redacted = prepare_export(original, True)
        text = json.dumps(redacted)
        for value in ("192.0.2.10", "198.51.100.20", "sample.csv", "Original capture notes"):
            self.assertNotIn(value, text)
        finding = redacted["findings"][0]
        self.assertEqual(finding["source"], finding["packets"][0]["source"])
        self.assertIsNone(finding["wireshark_filter"])
        self.assertEqual(finding["packets"][0]["frame_number"], 1)
        self.assertEqual(original["findings"][0]["source"], "192.0.2.10")
        self.assertIn("privacy_notice", redacted)

    def test_ipv4_prefixes_ipv6_variants_and_mac_formats(self):
        payload = {
            "source": "2001:db8::1", "destination": "192.0.2.1",
            "references": ["2001:0DB8:0000:0000:0000:0000:0000:0001",
                           "192.0.2.1", "192.0.2.10", "[2001:db8::1]:443",
                           "aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff"],
        }
        output = prepare_export(payload, True)
        refs = output["references"]
        self.assertEqual(refs[0], output["source"])
        self.assertEqual(refs[1], output["destination"])
        self.assertNotEqual(refs[1], refs[2])
        self.assertEqual(refs[3], f"[{output['source']}]:443")
        self.assertEqual(refs[4], refs[5])
        self.assertEqual(refs[5], refs[6])

    def test_host_labels_are_mapped_and_all_destination_sentinel_preserved(self):
        payload = {"source": "workstation.internal", "destination": "(all destinations)",
                   "references": ["WORKSTATION.INTERNAL connected", "workstation.internal2"]}
        output = prepare_export(payload, True)
        self.assertEqual(output["destination"], "(all destinations)")
        self.assertEqual(output["references"][0], output["source"] + " connected")
        self.assertEqual(output["references"][1], "workstation.internal2")

    def test_case_metadata_free_text_history_and_packet_details_redacted(self):
        report = sample_report()
        report["findings"][0]["packets"][0]["info"] = "DNS private.internal for Alice"
        payload = {
            "summary": {"id": "private-uuid", "title": "Alice's workstation", "created_at": "now"},
            "details": {"assessment": "Private notes", "root_cause": "Alice", "recommendation": "Bob"},
            "snapshot": report,
            "history": [{"case_id": "private-uuid", "actor": "Alice",
                         "details": {"title": "Private case", "assessment": "Private history"}}],
        }
        output = prepare_export(payload, True)
        text = json.dumps(output)
        for secret in ("private-uuid", "Alice", "Bob", "private.internal",
                       "Private notes", "Private history"):
            self.assertNotIn(secret, text)
        self.assertIn("privacy_notice", output)
        self.assertIn("privacy_notice", output["snapshot"])
        self.assertEqual(output["snapshot"]["packet_count"], report["packet_count"])

    def test_guided_lab_context_and_assessment_redacted_without_mutation(self):
        scenario, report = lab_report()
        submitted = reveal_feedback(submit_assessment(
            scenario, LabAssessment("Authorized activity", "Private Alice",
                                    "Private Bob", "Private workstation"), report))
        redacted = prepare_export(submitted, True)
        text = json.dumps(redacted)
        self.assertNotIn("Private Alice", text)
        self.assertNotIn("Private Bob", text)
        self.assertNotIn("192.0.2.10", text)
        self.assertEqual(redacted["guided_lab"]["assessment"]["disposition"], "Authorized activity")
        self.assertEqual(submitted["guided_lab"]["assessment"]["hypothesis"], "Private Alice")

    def test_ipv4_mapped_ipv6_uses_same_alias(self):
        output = prepare_export({"source": "192.0.2.1", "references": ["::ffff:192.0.2.1"]}, True)
        self.assertEqual(output["source"], output["references"][0])
