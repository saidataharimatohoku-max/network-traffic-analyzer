"""Conservative sharing copies, never a transformation of stored evidence."""

import copy
import ipaddress
import re


PRIVACY_NOTICE = (
    "Pseudonymized sharing copy, not guaranteed irreversible anonymization. Address labels "
    "are replaced consistently within this export. Capture names/fingerprints, case IDs, "
    "analyst labels, absolute timestamps, and free-text analyst/packet/context fields are "
    "redacted. Exact Wireshark filters are disabled. Relative times, frame/record numbers, "
    "ports, counts, and traffic lengths remain and may allow correlation. No address "
    "mapping is included. Review all remaining content before sharing. Not a restore backup."
)
_MAC = re.compile(r"(?<![\w:.-])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![\w:.-])", re.I)
_CISCO_MAC = re.compile(r"(?<![\w.])(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}(?![\w.])", re.I)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6 = re.compile(
    r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*(?:%[a-z0-9_.-]+)?(?![\w:])",
    re.I,
)


def _address_key(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        mac = re.sub(r"[:.-]", "", value)
        if (_MAC.fullmatch(value) or _CISCO_MAC.fullmatch(value)) and len(mac) == 12:
            return "mac:" + mac.lower()
        return "label:" + value.casefold()
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return "ip:" + str(address.ipv4_mapped)
    return "ip:" + str(address).lower()


def prepare_export(payload: dict, anonymize: bool = False) -> dict:
    result = copy.deepcopy(payload)
    if not anonymize:
        return result
    aliases: dict[str, str] = {}
    labels: dict[str, str] = {}

    def alias(value: str) -> str:
        key = _address_key(value)
        if key not in aliases:
            aliases[key] = f"Host-{len(aliases) + 1:03}"
        return aliases[key]

    def collect(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in ("source", "destination") and isinstance(item, str):
                    if item and item != "(all destinations)":
                        replacement = alias(item)
                        if _address_key(item).startswith("label:"):
                            labels[item] = replacement
                collect(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                collect(item)

    collect(result)
    label_pattern = None
    if labels:
        label_pattern = re.compile(
            r"(?<![\w.])(?:" + "|".join(re.escape(label) for label in sorted(
                labels, key=len, reverse=True)) + r")(?![\w.])", re.I,
        )
    folded_labels = {key.casefold(): value for key, value in labels.items()}

    def scrub(text: str) -> str:
        def network_match(match: re.Match[str]) -> str:
            value = match.group()
            key = _address_key(value)
            return alias(value) if not key.startswith("label:") else value

        text = _MAC.sub(network_match, text)
        text = _CISCO_MAC.sub(network_match, text)
        text = _IPV6.sub(network_match, text)
        text = _IPV4.sub(network_match, text)
        if label_pattern is not None:
            text = label_pattern.sub(lambda match: folded_labels[match.group().casefold()], text)
        return text

    def walk(value: object) -> object:
        if isinstance(value, dict):
            output = {}
            for key, item in value.items():
                if key == "capture":
                    output[key] = {"name": "[Redacted capture name]",
                                   "csv_sha256": "[Removed fingerprint]"}
                elif key in ("source", "destination") and isinstance(item, str):
                    output[key] = item if item == "(all destinations)" else alias(item)
                elif key in ("id", "case_id"):
                    output[key] = "[Redacted case ID]"
                elif key == "actor":
                    output[key] = "[Redacted analyst label]"
                elif key.endswith("_at") and isinstance(item, str):
                    output[key] = "[Redacted absolute timestamp]"
                elif key in ("csv_sha256", "sha256", "fingerprint"):
                    output[key] = "[Removed fingerprint]"
                elif key == "title":
                    output[key] = "[Redacted title]"
                elif key in ("investigation_notes", "root_cause", "recommendation",
                             "hypothesis", "info", "brief", "explanation", "next_step"):
                    output[key] = "[Redacted free text]"
                elif key == "assessment" and isinstance(item, str):
                    output[key] = "[Redacted analyst text]"
                elif key == "evidence" and "rule" not in value:
                    output[key] = "[Redacted analyst evidence]"
                elif key in ("context", "next_steps") and isinstance(item, list):
                    output[key] = ["[Redacted context]" for _ in item]
                elif key == "wireshark_filter":
                    output[key] = None
                elif key == "filter_notice":
                    output[key] = "Exact Wireshark filters are disabled in anonymized sharing exports."
                else:
                    output[key] = walk(item)
            return output
        if isinstance(value, list):
            return [walk(item) for item in value]
        if isinstance(value, tuple):
            return tuple(walk(item) for item in value)
        if isinstance(value, str):
            return scrub(value)
        return value

    transformed = walk(result)
    if not isinstance(transformed, dict):
        raise TypeError("Sharing exports must be dictionaries.")
    transformed["privacy_notice"] = PRIVACY_NOTICE
    if isinstance(transformed.get("snapshot"), dict):
        transformed["snapshot"]["privacy_notice"] = PRIVACY_NOTICE
    return transformed
