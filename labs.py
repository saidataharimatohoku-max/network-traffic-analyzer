"""Deterministic synthetic captures for analyst practice, not real traffic."""

import copy
import csv
import io
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from analyzer import parse_csv
from cases import DISPOSITIONS


LAB_VERSION = 1
LAB_CHOICES = {"capture-a": "Capture A", "capture-b": "Capture B",
               "capture-c": "Capture C", "capture-d": "Capture D"}
LAB_SETTINGS = {"window_seconds": 10, "scan_ports": 10, "volume_bytes": 1_000_000}


class LabError(ValueError):
    pass


@dataclass(frozen=True)
class LabScenario:
    id: str
    label: str
    brief: str
    context: tuple[str, ...]
    csv_data: bytes
    expected_rules: tuple[str, ...]
    expected_disposition: str
    explanation: str
    next_steps: tuple[str, ...]


@dataclass(frozen=True)
class LabAssessment:
    disposition: str
    hypothesis: str
    evidence: str
    next_step: str

    def validate(self) -> None:
        if self.disposition not in DISPOSITIONS:
            raise LabError("Choose a supported disposition.")
        if not all(value.strip() for value in (self.hypothesis, self.evidence, self.next_step)):
            raise LabError("Record a hypothesis, supporting evidence, and a next step "
                           "before submitting your assessment.")
        if any(len(value) > 10_000 for value in
               (self.hypothesis, self.evidence, self.next_step)):
            raise LabError("Each assessment field must be 10,000 characters or fewer.")


def _csv(rows: list[tuple[float, str, str, str, int, str]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"))
    for frame, row in enumerate(rows, 1):
        writer.writerow((frame, *row))
    return output.getvalue().encode("utf-8")


def get_scenario(scenario_id: str) -> LabScenario:
    if scenario_id not in LAB_CHOICES:
        raise LabError("Unknown lab capture. Select one of the available practice captures.")
    brief = "Review this synthetic capture and the supplied lab records. Explain what " \
            "the evidence supports, what remains uncertain, and what you would check next."
    if scenario_id == "capture-a":
        rows = [
            (0.0, "192.0.2.30", "203.0.113.53", "DNS", 80,
             "Standard query A example.test"),
            (0.1, "203.0.113.53", "192.0.2.30", "DNS", 100,
             "Standard query response A 198.51.100.40"),
            (0.2, "192.0.2.30", "198.51.100.40", "TCP", 60, "51000 -> 443 [SYN]"),
            (0.3, "198.51.100.40", "192.0.2.30", "TCP", 60, "443 -> 51000 [SYN, ACK]"),
            (0.4, "192.0.2.30", "198.51.100.40", "TCP", 60, "51000 -> 443 [ACK]"),
            (0.5, "198.51.100.40", "192.0.2.30", "TLSv1.3", 1200, "Application Data"),
        ]
        return LabScenario(
            scenario_id, LAB_CHOICES[scenario_id], brief,
            ("The lab user reports opening the approved training site example.test.",
             "The asset inventory maps 192.0.2.30 to that user's workstation.",
             "Only this short packet selection is available; no endpoint logs were supplied."),
            _csv(rows), (), "Authorized activity",
            "This is the normal-browsing reference. The DNS exchange, TCP handshake, "
            "and small TLS transfer are consistent with the supplied user record. Neither "
            "rule should trigger. This short export does not establish that the host is safe.",
            ("Verify the destination against the training-site inventory.",
             "If other symptoms exist, collect a longer capture and endpoint logs."),
        )
    if scenario_id in ("capture-b", "capture-c"):
        source = "192.0.2.10" if scenario_id == "capture-b" else "192.0.2.66"
        rows = [(i / 5, source, "198.51.100.20", "TCP", 60,
                 f"{50000 + i} -> {port} [SYN]")
                for i, port in enumerate((20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445))]
        approved = scenario_id == "capture-b"
        context = (
            ("Change CHG-104 authorizes 192.0.2.10 to scan 198.51.100.20 during this lab.",
             "The asset inventory identifies the source as the assessment workstation.")
            if approved else
            ("The change register has no approved scan for source 192.0.2.66.",
             "The inventory assigns 192.0.2.66 to a user workstation, not a scanner.")
        )
        return LabScenario(
            scenario_id, LAB_CHOICES[scenario_id], brief,
            (*context, "This export contains outbound attempts only; responses and host logs "
             "are not available."),
            _csv(rows), ("Potential port scan",),
            "Authorized activity" if approved else "Suspicious",
            ("The scan rule correctly identifies port-scanning behavior, but the supplied "
             "change record makes it authorized lab activity. This is a benign security "
             "alert, not proof of an attack. Verify scope and source identity before closing."
             if approved else
             "The scan pattern combined with the unapproved workstation source warrants "
             "investigation. The intended disposition is Suspicious, not confirmed compromise. "
             "Missing responses do not establish that every connection failed."),
            ("Correlate the capture window and source with change records and host logs.",
             "Confirm asset ownership and inspect responses before deciding on containment."),
        )
    rows = [(i / 200, "192.0.2.50", "198.51.100.80", "TCP", 1500,
             "52000 -> 443 [ACK]") for i in range(800)]
    return LabScenario(
        scenario_id, LAB_CHOICES[scenario_id], brief,
        ("The job scheduler records an approved backup from 192.0.2.50 to 198.51.100.80 "
         "during this capture.",
         "The destination inventory identifies 198.51.100.80 as the lab backup server.",
         "This is a synthetic excerpt of the transfer, not the full backup."),
        _csv(rows), ("High traffic volume",), "Authorized activity",
        "The source sends 1,200,000 captured bytes in the first 10-second bucket, exceeding "
        "the volume threshold. The job and inventory records support a legitimate backup. "
        "A volume threshold alone cannot distinguish backup traffic from exfiltration.",
        ("Verify the job ID, timing, and destination against backup logs.",
         "Compare the volume with normal backups before proposing a narrowly scoped exception."),
    )


def submit_assessment(scenario: LabScenario, assessment: LabAssessment, report: dict) -> dict:
    assessment.validate()
    result = copy.deepcopy(report)
    packets, _ = parse_csv(scenario.csv_data)
    result["practice_packets"] = [asdict(packet) for packet in packets]
    result["guided_lab"] = {
        "scenario_id": scenario.id,
        "scenario_version": LAB_VERSION,
        "label": scenario.label,
        "brief": scenario.brief,
        "context": list(scenario.context),
        "assessment": asdict(assessment),
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "feedback": None,
    }
    return result


def reveal_feedback(report: dict) -> dict:
    lab = report.get("guided_lab")
    if not isinstance(lab, dict) or lab.get("scenario_version") != LAB_VERSION:
        raise LabError("Submit an assessment for the current lab version before revealing feedback.")
    assessment = LabAssessment(**lab["assessment"])
    assessment.validate()
    scenario = get_scenario(lab["scenario_id"])
    result = copy.deepcopy(report)
    result["guided_lab"]["feedback"] = {
        "expected_rules": list(scenario.expected_rules),
        "expected_disposition": scenario.expected_disposition,
        "disposition_matches": assessment.disposition == scenario.expected_disposition,
        "explanation": scenario.explanation,
        "next_steps": list(scenario.next_steps),
        "notice": "Reference explanation for synthetic data, not an automated grade "
                  "of your evidence or proof about real traffic.",
    }
    return result
