"""Versioned JSON backups. Restore validates the entire file before merging."""

import json
import math
from dataclasses import asdict
from datetime import datetime, timezone
from uuid import UUID

from cases import (Case, CaseArchive, CaseDetails, CaseError, CaseRevision, CaseStore,
                   CaseSummary, MergeResult, validate_actor)


BACKUP_FORMAT = "network-traffic-investigator-backup"
MAX_BACKUP_BYTES = 20 * 1024 * 1024
MAX_BACKUP_CASES = 1000
DETAIL_FIELDS = {"title", "status", "disposition", "assessment", "root_cause", "recommendation"}
SUMMARY_FIELDS = {"id", "title", "status", "disposition", "created_at", "updated_at", "revision"}


def _object(value: object, label: str, keys: set[str] | None = None) -> dict:
    if not isinstance(value, dict) or (keys is not None and set(value) != keys):
        raise CaseError(f"Invalid backup: {label} has missing, extra, or invalid fields.")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise CaseError(f"Invalid backup: {label} must be text.")
    return value


def _integer(value: object, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise CaseError(f"Invalid backup: {label} must be an integer >= {minimum}.")
    return value


def _number(value: object, label: str) -> None:
    try:
        valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError as exc:
        raise CaseError(f"Invalid backup: {label} is outside the supported numeric range.") from exc
    if not valid:
        raise CaseError(f"Invalid backup: {label} must be finite and nonnegative.")


def _texts(value: object, label: str) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CaseError(f"Invalid backup: {label} must be a list of text values.")


def _time(value: object, label: str) -> datetime:
    value = _text(value, label)
    try:
        result = datetime.fromisoformat(value)
    except ValueError as exc:
        raise CaseError(f"Invalid backup: {label} is not an ISO timestamp.") from exc
    if result.utcoffset() is None:
        raise CaseError(f"Invalid backup: {label} must include a timezone.")
    return result


def _details(value: object) -> CaseDetails:
    details = _object(value, "case details", DETAIL_FIELDS)
    result = CaseDetails(**details)
    result.validate()
    if result.title != result.title.strip():
        raise CaseError("Invalid backup: case title must not have surrounding whitespace.")
    return result


def _packets(value: object) -> None:
    if not isinstance(value, list) or len(value) > 200_000:
        raise CaseError("Invalid backup: packet evidence must be a list of at most 200,000 packets.")
    for item in value:
        packet = _object(item, "packet")
        for field in ("source", "destination", "protocol", "info"):
            _text(packet.get(field), f"packet {field}")
        _integer(packet.get("number"), "CSV record", 1)
        _integer(packet.get("length"), "packet length")
        _number(packet.get("time"), "packet time")
        for field, minimum, maximum in (("frame_number", 1, 4_294_967_295),
                                        ("destination_port", 0, 65535)):
            if field not in packet:
                raise CaseError(f"Invalid backup: packet is missing {field}.")
            if packet[field] is not None:
                if _integer(packet[field], field, minimum) > maximum:
                    raise CaseError(f"Invalid backup: {field} exceeds {maximum}.")


def validate_report(value: object) -> None:
    report = _object(value, "evidence snapshot")
    if type(report.get("schema_version")) is not int or report["schema_version"] != 2:
        raise CaseError("Invalid backup: unsupported evidence format.")
    if "privacy_notice" in report:
        raise CaseError("Anonymized sharing reports cannot be restored as original evidence.")
    for field in ("project", "notice", "filter_notice", "investigation_notes"):
        _text(report.get(field), field)
    _integer(report.get("packet_count"), "packet count", 1)
    _integer(report.get("captured_bytes"), "captured bytes")
    _texts(report.get("limitations"), "limitations")
    capture = _object(report.get("capture"), "capture identity")
    _text(capture.get("name"), "capture name")
    _text(capture.get("csv_sha256"), "CSV fingerprint")
    settings = _object(report.get("settings"), "detection settings")
    for field, minimum in (("window_seconds", 1), ("scan_ports", 2), ("volume_bytes", 1)):
        _integer(settings.get(field), field, minimum)
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise CaseError("Invalid backup: findings must be a list.")
    for item in findings:
        finding = _object(item, "finding")
        for field in ("rule", "source", "destination", "evidence", "next_step"):
            _text(finding.get(field), f"finding {field}")
        _number(finding.get("start_seconds"), "finding start")
        _number(finding.get("end_seconds"), "finding end")
        if finding["end_seconds"] < finding["start_seconds"]:
            raise CaseError("Invalid backup: finding ends before it starts.")
        if "wireshark_filter" not in finding:
            raise CaseError("Invalid backup: missing Wireshark filter field.")
        if finding["wireshark_filter"] is not None:
            _text(finding["wireshark_filter"], "Wireshark filter")
        _packets(finding.get("packets"))
    if "practice_packets" in report:
        _packets(report["practice_packets"])
    if "guided_lab" in report:
        lab = _object(report["guided_lab"], "guided lab")
        for field in ("scenario_id", "label", "brief"):
            _text(lab.get(field), field)
        _integer(lab.get("scenario_version"), "lab version", 1)
        _time(lab.get("submitted_at"), "assessment time")
        _texts(lab.get("context"), "lab context")
        assessment = _object(lab.get("assessment"), "lab assessment")
        for field in ("disposition", "hypothesis", "evidence", "next_step"):
            _text(assessment.get(field), field)
        if "feedback" not in lab:
            raise CaseError("Invalid backup: missing lab feedback field.")
        if lab["feedback"] is not None:
            feedback = _object(lab["feedback"], "lab feedback")
            for field in ("expected_disposition", "explanation", "notice"):
                _text(feedback.get(field), field)
            for field in ("expected_rules", "next_steps"):
                _texts(feedback.get(field), field)
            if type(feedback.get("disposition_matches")) is not bool:
                raise CaseError("Invalid backup: disposition comparison must be boolean.")


def _archive(value: object) -> CaseArchive:
    entry = _object(value, "case archive", {"case", "history"})
    case = _object(entry["case"], "case", {"summary", "details", "snapshot"})
    summary_data = _object(case["summary"], "case summary", SUMMARY_FIELDS)
    case_id = _text(summary_data["id"], "case ID")
    try:
        valid_id = str(UUID(case_id)) == case_id
    except ValueError as exc:
        raise CaseError("Invalid backup: case ID must be a canonical UUID.") from exc
    if not valid_id:
        raise CaseError("Invalid backup: case ID must be a canonical UUID.")
    revision = _integer(summary_data["revision"], "case revision", 1)
    created = _time(summary_data["created_at"], "creation time")
    updated = _time(summary_data["updated_at"], "update time")
    if updated < created:
        raise CaseError("Invalid backup: case update predates creation.")
    details = _details(case["details"])
    for field in ("title", "status", "disposition"):
        if summary_data[field] != getattr(details, field):
            raise CaseError("Invalid backup: summary and investigation details disagree.")
    validate_report(case["snapshot"])
    history_data = entry["history"]
    if not isinstance(history_data, list) or not 1 <= len(history_data) <= 10_000:
        raise CaseError("Invalid backup: each case needs 1 to 10,000 history entries.")
    history = []
    previous_revision = None
    previous_time = created
    for item in history_data:
        item = _object(item, "history entry",
                       {"case_id", "revision", "recorded_at", "actor", "event", "details"})
        number = _integer(item["revision"], "history revision", 1)
        recorded = _time(item["recorded_at"], "history timestamp")
        validate_actor(item["actor"])
        if item["case_id"] != case_id or not previous_time <= recorded <= updated:
            raise CaseError("Invalid backup: history belongs to another case or has invalid timing.")
        if previous_revision is None:
            if item["event"] not in ("Created", "Legacy baseline"):
                raise CaseError("Invalid backup: history must start with creation or a legacy baseline.")
            if item["event"] == "Created" and (number != 1 or recorded != created):
                raise CaseError("Invalid backup: creation history must start at revision 1.")
        elif number != previous_revision + 1 or item["event"] != "Updated":
            raise CaseError("Invalid backup: history revisions must be contiguous and ordered.")
        history.append(CaseRevision(case_id, number, item["recorded_at"], item["actor"],
                                     item["event"], _details(item["details"])))
        previous_revision, previous_time = number, recorded
    if history[-1].revision != revision or history[-1].details != details or previous_time != updated:
        raise CaseError("Invalid backup: latest history does not match the saved case.")
    return CaseArchive(Case(CaseSummary(**summary_data), details, case["snapshot"]), tuple(history))


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CaseError(f"Invalid backup: duplicate JSON key {key!r}.")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise CaseError(f"Invalid backup: non-finite JSON value {value}.")


def parse_backup(data: bytes) -> list[CaseArchive]:
    if len(data) > MAX_BACKUP_BYTES:
        raise CaseError("Backup exceeds the 20 MB restore limit.")
    try:
        payload = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique_pairs,
                             parse_constant=_invalid_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise CaseError(f"Cannot read backup JSON: {exc}") from exc
    payload = _object(payload, "backup envelope", {"format", "version", "exported_at", "cases"})
    if payload["format"] != BACKUP_FORMAT or type(payload["version"]) is not int or payload["version"] != 1:
        raise CaseError("Unsupported backup format. Upload a full v4 JSON backup, not a sharing report.")
    _time(payload["exported_at"], "backup timestamp")
    if not isinstance(payload["cases"], list) or len(payload["cases"]) > MAX_BACKUP_CASES:
        raise CaseError("Backup must contain at most 1,000 cases.")
    archives = [_archive(item) for item in payload["cases"]]
    ids = [archive.case.summary.id for archive in archives]
    if len(ids) != len(set(ids)):
        raise CaseError("Invalid backup: duplicate case IDs.")
    return archives


def export_backup(store: CaseStore) -> bytes:
    payload = {"format": BACKUP_FORMAT, "version": 1,
               "exported_at": datetime.now(timezone.utc).isoformat(),
               "cases": [asdict(archive) for archive in store.list_archives()]}
    try:
        data = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CaseError(f"Cannot serialize backup: {exc}") from exc
    parse_backup(data)
    return data


def preview_restore(store: CaseStore, data: bytes) -> MergeResult:
    return store.merge_archives(parse_backup(data), dry_run=True)


def restore_backup(store: CaseStore, data: bytes) -> MergeResult:
    return store.merge_archives(parse_backup(data))
