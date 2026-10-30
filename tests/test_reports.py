import unittest
from html.parser import HTMLParser

from labs import LabAssessment, reveal_feedback, submit_assessment
from reports import html_report
from test_labs import lab_report


class TableParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows = 0
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag == "tr":
            self.rows += 1


class ReportTests(unittest.TestCase):
    def test_html_includes_every_evidence_packet(self):
        _, report = lab_report("capture-d")
        html = html_report(report)
        parser = TableParser()
        parser.feed(html)
        self.assertEqual(parser.rows, 801)
        self.assertIn("frame.number in {1..800}", html)
        self.assertIn("Print / Save as PDF", html)
        self.assertNotIn("script", parser.tags)
        self.assertNotIn("iframe", parser.tags)

    def test_untrusted_strings_are_escaped_in_all_surfaces(self):
        _, report = lab_report("capture-b")
        payload = '</pre><script>alert("test")</script><img src=x onerror=alert(1)>'
        report["investigation_notes"] = payload
        report["capture"]["name"] = payload
        report["findings"][0]["packets"][0]["info"] = payload
        html = html_report(report, payload, {"assessment": payload})
        parser = TableParser()
        parser.feed(html)
        self.assertNotIn("script", parser.tags)
        self.assertNotIn("img", parser.tags)
        self.assertIn("&lt;script&gt;", html)

    def test_lab_answer_only_exported_after_reveal(self):
        scenario, report = lab_report()
        submitted = submit_assessment(
            scenario, LabAssessment("Inconclusive", "h", "e", "n"), report)
        hidden = html_report(submitted)
        self.assertIn("Reference explanation not revealed", hidden)
        self.assertNotIn(scenario.explanation, hidden)
        visible = html_report(reveal_feedback(submitted))
        self.assertIn("Reference explanation (revealed)", visible)
        self.assertIn(scenario.explanation, visible)

    def test_no_findings_and_missing_filter_are_explicit(self):
        _, report = lab_report("capture-a")
        self.assertIn("not a safety verdict", html_report(report))
        _, report = lab_report()
        report["findings"][0]["wireshark_filter"] = None
        self.assertIn("missing original frame numbers", html_report(report))

    def test_normal_lab_html_keeps_full_capture_without_findings(self):
        scenario, report = lab_report("capture-a")
        submitted = submit_assessment(
            scenario, LabAssessment("Authorized activity", "h", "e", "n"), report)
        html = html_report(submitted)
        parser = TableParser()
        parser.feed(html)
        self.assertEqual(parser.rows, 7)
        self.assertIn("Full synthetic practice capture", html)
