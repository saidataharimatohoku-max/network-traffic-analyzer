"""Self-contained printable HTML exports with escaped, non-executable content."""

import json
from html import escape


def html_report(report: dict, title: str = "Network traffic investigation",
                case_details: dict | None = None, case_history: list[dict] | None = None) -> str:
    def text(value: object) -> str:
        return escape(str(value), quote=True)

    def section(heading: str, value: object) -> str:
        body = json.dumps(value, indent=2, ensure_ascii=True)
        return f"<h2>{text(heading)}</h2><pre>{text(body)}</pre>"

    def packet_table(packets: list[dict]) -> str:
        columns = ("number", "frame_number", "time", "source", "destination",
                   "protocol", "length", "destination_port", "info")
        labels = ("CSV record", "Capture frame", "Relative seconds", "Source", "Destination",
                  "Protocol", "Bytes", "Destination port", "Info")
        rows = [
            "<table><thead><tr>" + "".join(f"<th>{label}</th>" for label in labels)
            + "</tr></thead><tbody>"
        ]
        for packet in packets:
            rows.append("<tr>" + "".join(
                f"<td>{text(packet[column]) if packet[column] is not None else ''}</td>"
                for column in columns
            ) + "</tr>")
        rows.append("</tbody></table>")
        return "".join(rows)

    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>{text(title)}</title>",
        "<style>body{font:15px system-ui,sans-serif;max-width:1100px;margin:2rem auto;"
        "padding:0 1rem;color:#182333}h1,h2,h3{color:#173a57}pre{white-space:pre-wrap;"
        "overflow-wrap:anywhere;background:#f3f5f7;padding:1rem}table{border-collapse:collapse;"
        "width:100%;font-size:12px}th,td{border:1px solid #bbb;text-align:left;padding:5px;"
        "overflow-wrap:anywhere}thead{display:table-header-group}"
        "@media print{body{max-width:none;margin:0}pre{background:none}"
        "h2,h3{break-after:avoid}tr{break-inside:avoid}}</style></head><body>",
        f"<h1>{text(title)}</h1>",
        f"<p>{text(report['notice'])}</p>",
        "<p>Open this file in your browser and use Print / Save as PDF. "
        "Review sensitive information before sharing.</p>",
        section("Capture and detection settings", {
            "capture": report["capture"], "packet_count": report["packet_count"],
            "captured_bytes": report["captured_bytes"], "settings": report["settings"],
        }),
        f"<h2>Capture notes</h2><pre>{text(report['investigation_notes'])}</pre>",
    ]
    if case_details is not None:
        parts.append(section("Saved case details", case_details))
    if "privacy_notice" in report:
        parts.append(section("Sharing privacy notice", report["privacy_notice"]))
    if case_history is not None:
        parts.append(section("Case revision history", case_history))
    if "guided_lab" in report:
        lab = report["guided_lab"]
        parts.append(section("Guided lab: context and submitted assessment", {
            key: value for key, value in lab.items() if key != "feedback"
        }))
        if lab["feedback"] is None:
            parts.append("<p>Reference explanation not revealed for this attempt.</p>")
        else:
            parts.append(section("Reference explanation (revealed)", lab["feedback"]))
    parts.append(section("Limitations and filter guidance", {
        "limitations": report["limitations"], "filter_notice": report["filter_notice"],
    }))
    parts.append(f"<h2>Investigation leads: {len(report['findings'])}</h2>")
    if not report["findings"]:
        parts.append("<p>No configured thresholds reached. This is not a safety verdict.</p>")
    for finding in report["findings"]:
        parts.extend([
            f"<h3>{text(finding['rule'])}</h3>",
            f"<p>{text(finding['source'])} to {text(finding['destination'])}; "
            f"{text(finding['start_seconds'])} to {text(finding['end_seconds'])} seconds</p>",
            f"<p>{text(finding['evidence'])}</p>",
            f"<p>Next step: {text(finding['next_step'])}</p>",
            "<pre>" + text(finding["wireshark_filter"] if finding["wireshark_filter"] is not None
                           else ("Exact filters disabled in anonymized sharing exports."
                                 if "privacy_notice" in report else
                                 "Exact filter unavailable: missing original frame numbers."))
            + "</pre>",
            f"<p>All supporting packets: {len(finding['packets'])}</p>",
            packet_table(finding["packets"]),
        ])
    if "practice_packets" in report:
        parts.append("<h2>Full synthetic practice capture</h2>")
        parts.append(packet_table(report["practice_packets"]))
    parts.append("</body></html>")
    return "".join(parts)
