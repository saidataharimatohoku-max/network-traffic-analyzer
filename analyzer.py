"""Local CSV parsing and explainable traffic heuristics. Standard library only."""

import csv
import io
import math
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass


class TrafficError(ValueError):
    pass


@dataclass(frozen=True)
class Packet:
    number: int
    time: float
    source: str
    destination: str
    protocol: str
    length: int
    info: str
    destination_port: int | None
    frame_number: int | None = None


@dataclass(frozen=True)
class Finding:
    rule: str
    source: str
    destination: str
    start_seconds: float
    end_seconds: float
    evidence: str
    next_step: str
    packets: tuple[Packet, ...] = ()
    wireshark_filter: str | None = None


def parse_csv(data: bytes) -> tuple[list[Packet], list[str]]:
    try:
        return _parse_csv(data)
    except csv.Error as exc:
        raise TrafficError(f"Invalid CSV: {exc}. Re-export the capture from Wireshark.") from exc


def _parse_csv(data: bytes) -> tuple[list[Packet], list[str]]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise TrafficError("Export the CSV as UTF-8 and try again.") from exc
    reader = csv.DictReader(io.StringIO(text), strict=True)
    if not reader.fieldnames:
        raise TrafficError("The CSV is empty or has no header.")
    fields = [field.strip().lower() for field in reader.fieldnames]
    if len(fields) != len(set(fields)):
        raise TrafficError("Duplicate column names are not supported.")
    required = {"time", "source", "destination", "protocol", "length"}
    missing = required - set(fields)
    if missing:
        raise TrafficError("Missing columns: " + ", ".join(sorted(missing)))
    reader.fieldnames = fields
    packets = []
    warnings = []
    port_column = next(
        (name for name in ("tcp.dstport", "destination port", "dst port") if name in fields),
        None,
    )
    frame_column = next(
        (name for name in ("frame.number", "no.") if name in fields), None,
    )
    seen_frames: set[int] = set()
    for line, row in enumerate(reader, start=2):
        if len(packets) >= 200_000:
            raise TrafficError("The maximum supported capture is 200,000 rows.")
        if None in row or any(value is None for value in row.values()):
            raise TrafficError(f"CSV record {line}: wrong number of columns.")
        try:
            time = float(row["time"])
            length = int(row["length"])
            if not math.isfinite(time) or time < 0 or length < 0:
                raise ValueError
            for key in ("source", "destination", "protocol"):
                if not row[key].strip():
                    raise ValueError
            info = row.get("info", "").strip()
            port_text = row.get(port_column, "").strip() if port_column else ""
            if not port_text:
                match = re.search(r"^\s*\d+\s*(?:→|->|>)\s*(\d+)\b", info)
                port_text = match.group(1) if match else ""
            port = int(port_text) if port_text else None
            if port is not None and not 0 <= port <= 65535:
                raise ValueError
            frame_text = row.get(frame_column, "").strip() if frame_column else ""
            frame_number = int(frame_text) if frame_text else None
            if frame_number is not None:
                if not 1 <= frame_number <= 4_294_967_295:
                    raise ValueError
        except (ValueError, TypeError) as exc:
            raise TrafficError(
                f"CSV record {line}: use numeric relative Time (seconds), "
                "nonnegative integer Length, nonempty addresses/protocol, "
                "a destination port between 0 and 65535, and a positive original "
                "frame number (No. or frame.number) when supplied."
            ) from exc
        if frame_number is not None:
            if frame_number in seen_frames:
                raise TrafficError(
                    f"CSV record {line}: duplicate original frame number {frame_number}."
                )
            seen_frames.add(frame_number)
        packets.append(Packet(line - 1, time, row["source"].strip(),
                              row["destination"].strip(), row["protocol"].strip().upper(),
                              length, info, port, frame_number))
    if not packets:
        raise TrafficError("The CSV contains no packets.")
    packets.sort(key=lambda packet: packet.time)
    if any(packet.frame_number is None for packet in packets):
        warnings.append(
            "Some original frame numbers are missing. Exact Wireshark filters are "
            "unavailable for affected findings. Export No. or frame.number; CSV "
            "record numbers are not capture frame numbers."
        )
    if not any(packet.destination_port is not None for packet in packets):
        warnings.append(
            "No destination ports found. Port-scan detection is unavailable. "
            "Include tcp.dstport or keep the default TCP Info column."
        )
    if not any("[SYN]" in packet.info.upper() for packet in packets):
        warnings.append(
            "No TCP [SYN] packets found in Info. Port-scan detection requires "
            "TCP SYN packets without ACK; other packets are not scan evidence."
        )
    return packets, warnings


def wireshark_filter(packets: list[Packet] | tuple[Packet, ...]) -> str | None:
    """Select only evidence frames, never substitute CSV row numbers."""
    if not packets or any(packet.frame_number is None for packet in packets):
        return None
    numbers = sorted({packet.frame_number for packet in packets
                      if packet.frame_number is not None})
    ranges = []
    start = end = numbers[0]
    for number in numbers[1:]:
        if number == end + 1:
            end = number
        else:
            ranges.append(str(start) if start == end else f"{start}..{end}")
            start = end = number
    ranges.append(str(start) if start == end else f"{start}..{end}")
    return "frame.number in {" + " ".join(ranges) + "}"


def analyze(
    packets: list[Packet],
    window: int = 10,
    scan_ports: int = 10,
    volume_bytes: int = 1_000_000,
) -> list[Finding]:
    if window < 1 or scan_ports < 2 or volume_bytes < 1:
        raise TrafficError("Use a positive window/byte threshold and at least two ports.")
    scans: dict[tuple[str, str], list[Packet]] = defaultdict(list)
    volumes: dict[tuple[str, int], list[Packet]] = defaultdict(list)
    for packet in sorted(packets, key=lambda item: item.time):
        volumes[(packet.source, int(packet.time // window))].append(packet)
        if (
            packet.protocol == "TCP"
            and packet.destination_port is not None
            and "[SYN]" in packet.info.upper()
        ):
            scans[(packet.source, packet.destination)].append(packet)
    findings = []
    for (source, destination), group in scans.items():
        left = 0
        counts: Counter[int] = Counter()
        for right, packet in enumerate(group):
            if packet.destination_port is not None:
                counts[packet.destination_port] += 1
            while packet.time - group[left].time > window:
                old_port = group[left].destination_port
                if old_port is not None:
                    counts[old_port] -= 1
                    if counts[old_port] == 0:
                        del counts[old_port]
                left += 1
            if len(counts) >= scan_ports:
                evidence_packets = tuple(group[left:right + 1])
                findings.append(Finding(
                    "Potential port scan", source, destination, group[left].time, packet.time,
                    f"{len(counts)} distinct destination ports in "
                    f"{packet.time - group[left].time:g}s; threshold "
                    f"{scan_ports} ports within {window}s. Ports: "
                    + ", ".join(map(str, sorted(counts))),
                    "Check whether this host is an authorized scanner. Inspect SYN/ACK "
                    "responses and host logs before escalating.",
                    evidence_packets, wireshark_filter(evidence_packets),
                ))
                break
    for (source, bucket), group in sorted(volumes.items()):
        total = sum(packet.length for packet in group)
        if total >= volume_bytes:
            findings.append(Finding(
                "High traffic volume", source, "(all destinations)",
                float(bucket * window), float((bucket + 1) * window),
                f"{total:,} captured bytes across {len(group):,} packets in the "
                f"fixed [{bucket * window}, {(bucket + 1) * window})s bucket; "
                f"threshold {volume_bytes:,} bytes.",
                "Compare with the host's normal workload and capture duration. "
                "Backups and large downloads can legitimately exceed this threshold.",
                tuple(group), wireshark_filter(group),
            ))
    return findings


def make_report(packets: list[Packet], findings: list[Finding],
                warnings: list[str], settings: dict[str, int], notes: str) -> dict:
    return {
        "schema_version": 2,
        "project": "Network Traffic Investigation Dashboard",
        "notice": "Heuristic investigation leads, not confirmed attacks. "
                  "No findings does not mean the capture is safe.",
        "packet_count": len(packets),
        "captured_bytes": sum(packet.length for packet in packets),
        "settings": settings,
        "limitations": warnings,
        "filter_notice": "Frame filters select exact exported evidence only in the "
                         "original capture. Do not use them on a different, merged, "
                         "or renumbered capture. CSV records are not frame numbers.",
        "findings": [asdict(finding) for finding in findings],
        "investigation_notes": notes,
    }
