import json
import unittest
from pathlib import Path

from analyzer import Packet, TrafficError, analyze, make_report, parse_csv, wireshark_filter


def packet(time=0, port=80, length=60, info="[SYN]", source="a", destination="b"):
    return Packet(1, time, source, destination, "TCP", length, info, port)


class AnalyzerTests(unittest.TestCase):
    def test_demo(self):
        packets, warnings = parse_csv(
            Path(__file__).resolve().parents[1].joinpath("sample.csv").read_bytes())
        self.assertEqual(len(packets), 15)
        self.assertEqual(warnings, [])
        self.assertEqual([f.rule for f in analyze(packets)], ["Potential port scan"])

    def test_scan_boundary(self):
        self.assertEqual(len(analyze([packet(10, 81), packet(0, 80)], scan_ports=2)), 1)
        self.assertEqual(analyze([packet(0, 80), packet(10.01, 81)], scan_ports=2), [])

    def test_repeated_ports_and_separate_targets(self):
        self.assertEqual(analyze([packet(0), packet(1), packet(2, 81, destination="c")],
                                 scan_ports=2), [])

    def test_ack_not_scan_evidence(self):
        self.assertEqual(analyze([packet(0), packet(1, 81, info="[SYN, ACK]")],
                                 scan_ports=2), [])

    def test_scan_emits_one_per_pair(self):
        self.assertEqual(len(analyze([packet(i, 80 + i) for i in range(5)],
                                     scan_ports=2)), 1)

    def test_volume_boundary(self):
        findings = analyze([packet(0, length=500), packet(9, length=500),
                            packet(10, length=999)], volume_bytes=1000)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].end_seconds, 10)
        self.assertIn("1,000", findings[0].evidence)

    def test_volume_separates_sources(self):
        self.assertEqual(analyze([packet(length=600), packet(length=600, source="c")],
                                 volume_bytes=1000), [])

    def test_invalid_csv_values(self):
        for value in ("nan", "inf", "-1", "2026-01-01"):
            with self.subTest(value=value), self.assertRaises(TrafficError):
                parse_csv(f"Time,Source,Destination,Protocol,Length\n{value},a,b,TCP,60".encode())

    def test_bad_headers_and_rows(self):
        for text in ("", "Time,Time\n0,0", "Time,Source\n0,a",
                     "Time,Source,Destination,Protocol,Length\n0,a,b,TCP",
                     "Time,Source,Destination,Protocol,Length\n0,a,b,TCP,60,extra",
                     'Time,Source,Destination,Protocol,Length\n0,"a,b,TCP,60'):
            with self.subTest(text=text), self.assertRaises(TrafficError):
                parse_csv(text.encode())

    def test_optional_port_and_normalized_headers(self):
        packets, warnings = parse_csv(
            b"\xef\xbb\xbf Time , Source ,Destination,Protocol,Length,tcp.dstport,Info,No.\n"
            b"0,a,b,tcp,60,443,[SYN],12\n")
        self.assertEqual(packets[0].destination_port, 443)
        self.assertEqual(warnings, [])

    def test_unicode_arrow(self):
        packets, _ = parse_csv(
            "Time,Source,Destination,Protocol,Length,Info\n"
            "0,a,b,TCP,60,12345 \u2192 443 [SYN]\n".encode())
        self.assertEqual(packets[0].destination_port, 443)

    def test_invalid_ports_and_lengths(self):
        for length, port in (("-1", "80"), ("abc", "80"), ("60", "65536")):
            with self.subTest(length=length, port=port), self.assertRaises(TrafficError):
                parse_csv(("Time,Source,Destination,Protocol,Length,tcp.dstport\n"
                           f"0,a,b,TCP,{length},{port}").encode())

    def test_no_ports_warns(self):
        _, warnings = parse_csv(
            b"Time,Source,Destination,Protocol,Length\n0,a,b,UDP,60")
        self.assertEqual(len(warnings), 3)

    def test_report(self):
        report = make_report([packet()], [], ["test limitation"],
                             {"window_seconds": 10}, "Check host logs")
        self.assertEqual(json.loads(json.dumps(report))["investigation_notes"],
                         "Check host logs")
        self.assertEqual(report["captured_bytes"], 60)

    def test_invalid_thresholds(self):
        with self.assertRaises(TrafficError):
            analyze([], window=0)

    def test_original_frames_are_not_csv_records(self):
        packets, warnings = parse_csv(
            b"No.,Time,Source,Destination,Protocol,Length,Info\n"
            b"123,2,a,b,TCP,60,1000 -> 81 [SYN]\n"
            b"42,0,a,b,TCP,60,1000 -> 80 [SYN]\n")
        self.assertEqual(warnings, [])
        self.assertEqual([p.number for p in packets], [2, 1])
        finding = analyze(packets, scan_ports=2)[0]
        self.assertEqual([p.frame_number for p in finding.packets], [42, 123])
        self.assertEqual(finding.wireshark_filter, "frame.number in {42 123}")

    def test_scan_evidence_excludes_expired_ack_and_other_hosts(self):
        packets = [
            packet(0, 10), packet(20, 20), packet(21, 30),
            packet(21, 40, info="[ACK]"), packet(21, 50, destination="c"),
            packet(22, 60), packet(23, 70),
        ]
        finding = analyze(packets, scan_ports=3)[0]
        self.assertEqual([p.destination_port for p in finding.packets], [20, 30, 60])

    def test_volume_evidence_matches_exact_sum_and_bucket(self):
        packets = [packet(0, length=400), packet(9, length=600),
                   packet(9, length=900, source="c"), packet(10, length=999)]
        finding = analyze(packets, volume_bytes=1000)[0]
        self.assertEqual(len(finding.packets), 2)
        self.assertEqual(sum(p.length for p in finding.packets), 1000)

    def test_frame_filters_compress_ranges_and_preserve_gaps(self):
        packets = [Packet(i, 0, "a", "b", "TCP", 60, "[SYN]", 80, i)
                   for i in (12, 10, 11, 20, 25, 26)]
        self.assertEqual(wireshark_filter(packets), "frame.number in {10..12 20 25..26}")

    def test_missing_frames_never_use_record_numbers(self):
        packets, warnings = parse_csv(
            b"Time,Source,Destination,Protocol,Length,Info\n"
            b"0,a,b,TCP,60,1000 -> 80 [SYN]\n"
            b"1,a,b,TCP,60,1000 -> 81 [SYN]\n")
        self.assertIsNone(analyze(packets, scan_ports=2)[0].wireshark_filter)
        self.assertIn("original frame", warnings[0])
        self.assertIsNone(wireshark_filter([]))

    def test_frame_number_header_precedence_and_partial_ids(self):
        packets, warnings = parse_csv(
            b"No.,frame.number,Time,Source,Destination,Protocol,Length,Info\n"
            b"1,42,0,a,b,TCP,60,1000 -> 80 [SYN]\n"
            b"2,,1,a,b,TCP,60,1000 -> 81 [SYN]\n")
        self.assertEqual([p.frame_number for p in packets], [42, None])
        self.assertEqual(wireshark_filter(packets[:1]), "frame.number in {42}")
        self.assertIsNone(wireshark_filter(packets))
        self.assertEqual(len(warnings), 1)

    def test_invalid_and_duplicate_frame_numbers_rejected(self):
        for frames in (("0", "1"), ("-1", "2"), ("1.5", "2"), ("1", "1")):
            with self.subTest(frames=frames), self.assertRaises(TrafficError):
                parse_csv(("No.,Time,Source,Destination,Protocol,Length\n"
                           f"{frames[0]},0,a,b,TCP,60\n"
                           f"{frames[1]},1,a,b,TCP,60\n").encode())

    def test_report_includes_complete_evidence_and_filter(self):
        packets, warnings = parse_csv(
            Path(__file__).resolve().parents[1].joinpath("sample.csv").read_bytes())
        report = make_report(packets, analyze(packets), warnings, {}, "Investigate")
        restored = json.loads(json.dumps(report))
        self.assertEqual(restored["schema_version"], 2)
        self.assertEqual(len(restored["findings"][0]["packets"]), 10)
        self.assertEqual(restored["findings"][0]["wireshark_filter"],
                         "frame.number in {1..10}")


if __name__ == "__main__":
    unittest.main()
