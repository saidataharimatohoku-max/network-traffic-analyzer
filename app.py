import hashlib
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from analyzer import Packet, TrafficError, analyze, make_report, parse_csv
from backups import export_backup, preview_restore, restore_backup
from cases import DISPOSITIONS, STATUSES, CaseDetails, CaseError, CaseStore
from labs import (LAB_CHOICES, LAB_SETTINGS, LAB_VERSION, LabAssessment, LabError,
                  get_scenario, reveal_feedback, submit_assessment)
from reports import html_report
from privacy import prepare_export


def render_report_downloads(report: dict, key: str, filename: str, label: str, *,
                            case_payload: dict | None = None) -> None:
    anonymize = st.checkbox("Anonymize sharing exports", key=f"privacy-{key}")
    payload = prepare_export(case_payload if case_payload is not None else report, anonymize)
    if anonymize:
        st.warning("These are pseudonymized sharing copies, not guaranteed irreversible "
                   "anonymization. Review the JSON/HTML before sharing. Stored evidence "
                   "and full backups are not changed.")
        filename = "anonymized-case" if case_payload is not None else "anonymized-investigation"
    snapshot = payload["snapshot"] if case_payload is not None else payload
    title = payload["details"]["title"] if case_payload is not None else "Network traffic investigation"
    st.download_button(f"Download {label} (JSON)", json.dumps(payload, indent=2),
                       f"{filename}.json", "application/json", key=f"json-{key}")
    st.download_button(
        f"Download {label} (printable HTML)",
        html_report(snapshot, title, payload["details"] if case_payload is not None else None,
                    payload["history"] if case_payload is not None else None),
        f"{filename}.html", "text/html", key=f"html-{key}",
    )


def render_metrics(packets: list[Packet], finding_count: int) -> None:
    cols = st.columns(4)
    cols[0].metric("Packets", f"{len(packets):,}")
    cols[1].metric("Captured bytes", f"{sum(packet.length for packet in packets):,}")
    cols[2].metric("Observed duration", f"{packets[-1].time - packets[0].time:g}s")
    cols[3].metric("Investigation leads", finding_count)


def render_overview(packets: list[Packet], window: int) -> None:
    frame = pd.DataFrame(asdict(packet) for packet in packets)
    left, right = st.columns(2)
    protocols = Counter(packet.protocol for packet in packets)
    left.plotly_chart(px.pie(names=list(protocols), values=list(protocols.values()),
                             title="Protocol distribution"), width="stretch")
    sources = frame.groupby("source", as_index=False)["length"].sum().nlargest(10, "length")
    right.plotly_chart(px.bar(sources, x="source", y="length",
                              title="Top sources by captured bytes"), width="stretch")
    timeline = frame.assign(bucket=(frame["time"] // window) * window)
    totals = timeline.groupby("bucket", as_index=False)["length"].sum()
    st.plotly_chart(px.bar(totals, x="bucket", y="length",
                          title=f"Traffic over time ({window}s buckets)",
                          labels={"bucket": "Relative seconds", "length": "Captured bytes"}),
                    width="stretch")
    st.subheader("Top destinations")
    st.dataframe(frame.groupby("destination", as_index=False)["length"].sum()
                 .nlargest(10, "length"), hide_index=True)
    st.subheader("Packet preview (first 1,000 packets by time)")
    st.dataframe(frame.head(1000), hide_index=True)


def render_lab_record(lab: dict) -> None:
    st.subheader("Submitted lab assessment")
    st.json({key: value for key, value in lab.items() if key != "feedback"})
    feedback = lab["feedback"]
    if feedback is not None:
        st.subheader("Reference explanation")
        st.text(feedback["explanation"])
        st.text("Reference disposition: " + feedback["expected_disposition"])
        st.text("Expected rule findings: " + (", ".join(feedback["expected_rules"]) or "None"))
        st.info("Your disposition matches the reference." if feedback["disposition_matches"]
                else "Your disposition differs from the reference. Compare the evidence "
                     "and supplied context; a cautious alternative may still be defensible.")
        for step in feedback["next_steps"]:
            st.text("- " + step)
        st.caption(feedback["notice"])


def render_findings(findings: list[dict], key: str) -> None:
    st.caption("Filters select exact evidence frames in the original capture only. "
               "Do not apply them to a different, merged, or renumbered capture. "
               "CSV record numbers are not capture frame numbers.")
    if not findings:
        st.info("No configured thresholds were reached. This is not a safety verdict.")
    for index, finding in enumerate(findings, 1):
        with st.expander(f"{index}. {finding['rule']} | {finding['source']}", expanded=True):
            st.text(f"Target: {finding['destination']}")
            st.text(f"Time: {finding['start_seconds']:g} to "
                    f"{finding['end_seconds']:g} seconds")
            st.text(finding["evidence"])
            st.text("Next step: " + finding["next_step"])
            st.markdown("**Wireshark display filter**")
            if finding["wireshark_filter"] is not None:
                st.code(finding["wireshark_filter"], language="text")
            else:
                st.warning("Exact filter unavailable: original frame numbers are missing "
                           "from some evidence packets. Re-export with No. or frame.number.")
            evidence = finding["packets"]
            st.markdown(f"**Supporting packets: {len(evidence):,}**")
            if evidence:
                page_count = (len(evidence) + 99) // 100
                page = int(st.number_input(
                    "Evidence page (100 packets per page)", min_value=1,
                    max_value=page_count, value=1, key=f"{key}-page-{index}",
                ))
                preview = pd.DataFrame(evidence[(page - 1) * 100:page * 100]).rename(
                    columns={"number": "CSV record", "frame_number": "Capture frame",
                             "time": "Relative seconds", "destination_port": "Destination port"}
                )
                st.dataframe(preview, hide_index=True)
                st.caption("All supporting packets, not just this page, are included "
                           "in downloaded reports and saved cases.")


def case_form(details: CaseDetails, key: str) -> CaseDetails:
    title = st.text_input("Case title", value=details.title, max_chars=200, key=f"{key}-title")
    left, right = st.columns(2)
    status = left.selectbox("Status", STATUSES, index=STATUSES.index(details.status),
                            key=f"{key}-status")
    disposition = right.selectbox(
        "Disposition", DISPOSITIONS, index=DISPOSITIONS.index(details.disposition),
        key=f"{key}-disposition",
    )
    assessment = st.text_area("Analyst assessment / notes", value=details.assessment,
                              max_chars=50_000, key=f"{key}-assessment")
    root_cause = st.text_area("Root-cause hypothesis", value=details.root_cause,
                              max_chars=50_000, key=f"{key}-root")
    recommendation = st.text_area("Recommended action", value=details.recommendation,
                                  max_chars=50_000, key=f"{key}-action")
    return CaseDetails(title, status, disposition, assessment, root_cause, recommendation)


def render_saved_cases(store: CaseStore) -> None:
    st.header("Saved investigation cases")
    st.caption(f"Local database: {store.path}")
    st.caption("Evidence is a frozen snapshot; editing a case does not change its "
               "capture, detection thresholds, findings, or supporting packets.")
    if "case_notice" in st.session_state:
        st.success(st.session_state.pop("case_notice"))
    try:
        summaries = store.list_cases()
        if not summaries:
            st.info("No saved cases yet. Analyze a capture, then save a case in the report tab.")
            return
        labels = {case.id: f"{case.title} | {case.status} | {case.id[:8]}" for case in summaries}
        selected = st.selectbox("Open case", list(labels), format_func=labels.__getitem__,
                                key="selected-case")
        reload_case = st.button("Reload case from disk (discard unsaved edits)")
        cached = st.session_state.get("loaded-case")
        if cached is None or cached.summary.id != selected or reload_case:
            cached = store.get_case(selected)
            st.session_state["loaded-case"] = cached
            st.session_state["case-load-token"] = st.session_state.get("case-load-token", 0) + 1
        case = cached
        st.caption(f"Case ID: {case.summary.id} | Created (UTC): {case.summary.created_at} | "
                   f"Updated (UTC): {case.summary.updated_at} | Revision: {case.summary.revision}")
        editor_key = (f"edit-{case.summary.id}-{case.summary.revision}-"
                      f"{st.session_state['case-load-token']}")
        with st.form(editor_key):
            details = case_form(case.details, editor_key)
            actor = st.text_input("Recorded by (self-reported analyst label)",
                                  value="Local analyst", max_chars=100, key=f"{editor_key}-actor")
            submitted = st.form_submit_button("Save case changes")
        if submitted:
            updated = store.update_case(case.summary.id, details, case.summary.revision, actor=actor)
            st.session_state["loaded-case"] = updated
            st.session_state["case_notice"] = "Case changes saved locally."
            st.rerun()
        archive = store.get_archive(selected)
        if archive.case.summary.revision != case.summary.revision:
            st.warning("A newer saved revision exists. Reload before editing. Downloads and "
                       "history reflect the latest saved revision, not this stale form.")
        payload = asdict(archive.case)
        payload["history"] = [asdict(revision) for revision in archive.history]
        render_report_downloads(archive.case.snapshot, f"case-{selected}",
                                f"case-{selected}", "saved case", case_payload=payload)
        st.caption("Downloads contain the last saved case, not unsaved form edits.")
        st.subheader("Case revision history")
        st.caption("Analyst labels are self-reported, not authenticated identities. "
                   "Local history is not a tamper-proof audit log.")
        previous = None
        for revision in archive.history:
            current = asdict(revision.details)
            with st.expander(
                f"Revision {revision.revision} | {revision.event} | {revision.recorded_at}",
                expanded=revision.revision == archive.case.summary.revision,
            ):
                st.text("Recorded by: " + revision.actor)
                if revision.event == "Legacy baseline":
                    st.info("Only the latest pre-upgrade state is available. Earlier edits "
                            "and actor identities cannot be reconstructed.")
                changes = {field: {"before": previous[field] if previous is not None else None,
                                    "after": value}
                           for field, value in current.items()
                           if previous is None or value != previous[field]}
                if changes:
                    st.json(changes)
                else:
                    st.caption("No investigation field changes in this revision.")
            previous = current
        snapshot = case.snapshot
        st.subheader("Saved evidence")
        st.json({"capture": snapshot["capture"], "packet_count": snapshot["packet_count"],
                 "captured_bytes": snapshot["captured_bytes"], "settings": snapshot["settings"]})
        st.markdown("**Capture notes at case creation (read-only)**")
        st.text(snapshot["investigation_notes"] or "(No capture notes recorded.)")
        if "guided_lab" in snapshot:
            render_lab_record(snapshot["guided_lab"])
        if "practice_packets" in snapshot:
            with st.expander("Full synthetic practice capture"):
                st.dataframe(pd.DataFrame(snapshot["practice_packets"]), hide_index=True)
        for warning in snapshot["limitations"]:
            st.warning(warning)
        render_findings(snapshot["findings"], f"saved-{case.summary.id}")
    except CaseError as exc:
        st.error(str(exc))


def render_analysis(store: CaseStore, window: int, scan_ports: int, volume_bytes: int) -> None:
    uploaded = st.file_uploader("Upload a Wireshark CSV (UTF-8, up to 20 MB)", type=["csv"])
    demo = st.checkbox("Use synthetic demo capture", value=uploaded is None)
    if uploaded is not None:
        if uploaded.size > 20 * 1024 * 1024:
            st.error("This capture exceeds the 20 MB limit. Export a smaller packet selection.")
            return
        data = uploaded.getvalue()
        capture_name = uploaded.name
    elif demo:
        data = Path(__file__).with_name("sample.csv").read_bytes()
        capture_name = "sample.csv (synthetic)"
    else:
        st.caption("Upload a CSV or enable the demo to begin.")
        return
    try:
        packets, warnings = parse_csv(data)
        findings = analyze(packets, window, scan_ports, volume_bytes)
    except TrafficError as exc:
        st.error(str(exc))
        return
    for warning in warnings:
        st.warning(warning)

    digest = hashlib.sha256(data).hexdigest()
    settings = {"window_seconds": window, "scan_ports": scan_ports, "volume_bytes": volume_bytes}
    analysis_key = f"{digest}-{window}-{scan_ports}-{volume_bytes}"
    render_metrics(packets, len(findings))
    overview, alerts, report_tab = st.tabs(["Traffic overview", "Findings", "Investigation report"])
    with overview:
        render_overview(packets, window)
    with alerts:
        st.caption("Detection covers TCP SYN fan-out and configured traffic-volume thresholds "
                   "only. DNS analysis and payload inspection are not included.")
        render_findings([asdict(finding) for finding in findings], analysis_key)
    with report_tab:
        notes = st.text_area("Investigation notes: context, root cause hypothesis, "
                            "supporting evidence, and recommended action", height=180,
                            key=f"notes-{digest}")
        report = make_report(packets, findings, warnings, settings, notes)
        report["capture"] = {"name": capture_name, "csv_sha256": digest}
        render_report_downloads(report, analysis_key, "investigation-report", "investigation report")
        st.caption("Reports include addresses, packet metadata, and notes. Review sensitive "
                   "information before sharing. Notes are saved only by downloading or "
                   "explicitly saving a case.")
        st.subheader("Save an investigation case")
        st.caption(f"Stored locally at {store.path}. The evidence snapshot includes all "
                   "findings and supporting packet metadata, not the raw CSV or payloads.")
        with st.form(f"create-{analysis_key}"):
            details = case_form(CaseDetails(f"Investigation: {capture_name}"[:200]),
                                f"create-{analysis_key}")
            actor = st.text_input("Recorded by (self-reported analyst label)",
                                  value="Local analyst", max_chars=100,
                                  key=f"create-{analysis_key}-actor")
            submitted = st.form_submit_button("Save new case locally")
        if submitted:
            try:
                saved = store.create_case(details, report, actor=actor)
            except CaseError as exc:
                st.error(str(exc))
            else:
                st.success(f"Case saved: {saved.summary.id}. Open Saved cases to continue.")
        st.caption("Cases contain sensitive information and are not encrypted. Use a private "
                   "Windows account and disk encryption. Only saved changes survive restart.")


def render_guided_lab(store: CaseStore) -> None:
    st.header("Guided investigation lab")
    st.caption("Synthetic packet metadata and fictional records only. This is practice, "
               "not a scored certification exam. No traffic is captured or generated.")
    scenario_id = st.selectbox("Practice capture", list(LAB_CHOICES),
                               format_func=LAB_CHOICES.__getitem__, key="lab-choice")
    scenario = get_scenario(scenario_id)
    st.subheader("1. Review the supplied context")
    st.text(scenario.brief)
    for item in scenario.context:
        st.text("- " + item)
    st.download_button("Download practice CSV", scenario.csv_data, f"{scenario_id}.csv", "text/csv")
    st.caption("The CSV contains synthetic metadata, not a PCAP. Its frame numbers illustrate "
               "filters; no matching real capture is included.")
    packets, warnings = parse_csv(scenario.csv_data)
    findings = analyze(packets, LAB_SETTINGS["window_seconds"], LAB_SETTINGS["scan_ports"],
                       LAB_SETTINGS["volume_bytes"])
    render_metrics(packets, len(findings))
    with st.expander("2. Investigate traffic and packet evidence", expanded=True):
        overview, leads = st.tabs(["Lab traffic", "Lab findings"])
        with overview:
            render_overview(packets, LAB_SETTINGS["window_seconds"])
        with leads:
            for warning in warnings:
                st.warning(warning)
            render_findings([asdict(finding) for finding in findings], f"lab-{scenario_id}")

    state_key = f"lab-attempt-{scenario_id}-v{LAB_VERSION}"
    if state_key not in st.session_state:
        st.session_state[state_key] = {"generation": 0, "report": None, "saved_case_id": None}
    state = st.session_state[state_key]
    if st.button("Start a new attempt (clear this attempt)", key=f"reset-{state_key}"):
        st.session_state[state_key] = {
            "generation": state["generation"] + 1, "report": None, "saved_case_id": None,
        }
        st.rerun()
    st.caption("Submit before revealing the reference explanation. Submitted attempts stay "
               "in this browser session; save a case or download to keep them after restart. "
               "Unsubmitted drafts may be cleared when you switch workspaces or captures.")
    if state["report"] is None:
        st.subheader("3. Record your assessment")
        with st.form(f"assessment-{state_key}-{state['generation']}"):
            disposition = st.selectbox("Your disposition", DISPOSITIONS)
            hypothesis = st.text_area("Your hypothesis", max_chars=10_000)
            evidence = st.text_area("Your supporting evidence and uncertainties", max_chars=10_000)
            next_step = st.text_area("Your next investigation step", max_chars=10_000)
            submitted = st.form_submit_button("Submit assessment")
        if submitted:
            assessment = LabAssessment(disposition, hypothesis, evidence, next_step)
            report = make_report(packets, findings, warnings, dict(LAB_SETTINGS), hypothesis)
            report["capture"] = {
                "name": f"{scenario_id}.csv (synthetic)",
                "csv_sha256": hashlib.sha256(scenario.csv_data).hexdigest(),
            }
            try:
                state["report"] = submit_assessment(scenario, assessment, report)
            except LabError as exc:
                st.error(str(exc))
            else:
                st.rerun()
        return

    report = state["report"]
    render_lab_record(report["guided_lab"])
    if report["guided_lab"]["feedback"] is None:
        if st.button("Reveal reference explanation", key=f"reveal-{state_key}"):
            state["report"] = reveal_feedback(report)
            st.rerun()
    st.subheader("4. Export or save your investigation")
    render_report_downloads(report, f"lab-report-{state_key}",
                            f"{scenario_id}-investigation", "lab report")
    st.caption("Open the HTML in a browser and use Print / Save as PDF. Exports include "
               "reference feedback only if you have revealed it.")
    if st.button("Save lab attempt as case", disabled=state["saved_case_id"] is not None,
                 key=f"save-{state_key}"):
        assessment = report["guided_lab"]["assessment"]
        details = CaseDetails(
            f"Guided lab: {scenario.label}", "Investigating", assessment["disposition"],
            assessment["evidence"], assessment["hypothesis"], assessment["next_step"],
        )
        try:
            saved = store.create_case(details, report)
        except CaseError as exc:
            st.error(str(exc))
        else:
            state["saved_case_id"] = saved.summary.id
            st.rerun()
    if state["saved_case_id"] is not None:
        st.success("Lab attempt saved as case: " + state["saved_case_id"])
    st.caption("Saving freezes the current attempt, including feedback only if already "
               "revealed. Later reveals do not change the saved evidence. Saved cases "
               "are local and unencrypted.")


def render_backups(store: CaseStore) -> None:
    st.header("Case backups and non-overwriting restore")
    st.warning("Full backups are UNREDACTED and unencrypted: they contain original addresses, "
               "notes, analyst labels, evidence, and revision history. Store them securely. "
               "Use anonymized sharing exports instead when sharing a report.")
    st.caption(f"Local database: {store.path}")
    st.caption("Portable JSON backups support up to 20 MB, 1,000 cases, and 10,000 history "
               "entries per case. For larger databases, stop the app and copy the SQLite "
               "database as described in the setup guide.")
    try:
        st.download_button("Download full backup (JSON)", export_backup(store),
                           "network-traffic-cases-backup.json", "application/json")
    except CaseError as exc:
        st.error(str(exc))
    uploaded = st.file_uploader("Upload full backup to preview (JSON, up to 20 MB)",
                                type=["json"], key="restore-upload")
    if uploaded is None:
        return
    data = uploaded.getvalue()
    fingerprint = hashlib.sha256(data).hexdigest()
    try:
        preview = preview_restore(store, data)
        st.subheader("Restore preview")
        st.text(f"New cases to import: {preview.imported} | Identical cases to skip: "
                f"{preview.identical} | Conflicts to leave unchanged: {len(preview.conflicts)}")
        if preview.conflicts:
            st.warning("Conflicting cases will NOT be overwritten, even if the backup "
                       "has a higher revision.")
            st.dataframe([asdict(conflict) for conflict in preview.conflicts], hide_index=True)
        confirmed = st.checkbox(
            "I confirm importing only new cases and leaving all existing cases unchanged.",
            key=f"restore-confirm-{fingerprint}",
        )
        if st.button("Merge new cases from backup", disabled=not confirmed,
                     key=f"merge-{fingerprint}"):
            result = restore_backup(store, data)
            st.session_state.pop("loaded-case", None)
            st.success(f"Restore completed: imported {result.imported}, skipped "
                       f"{result.identical} identical, left {len(result.conflicts)} conflicts unchanged.")
            if result.conflicts:
                st.warning("Some cases were not imported because their IDs already exist "
                           "with different content. Your existing records were preserved.")
                st.dataframe([asdict(conflict) for conflict in result.conflicts], hide_index=True)
    except CaseError as exc:
        st.error(str(exc))


st.set_page_config(page_title="Network Traffic Investigator", page_icon="🔎", layout="wide")
st.title("Network Traffic Investigation Dashboard")
st.caption("Cybersecurity portfolio lab | Local Wireshark CSV analysis")
st.info("Findings are investigation leads, not confirmed attacks. "
        "Use only synthetic data or captures you are authorized to analyze.")
store = CaseStore()
with st.sidebar:
    mode = st.radio("Workspace", ["Analyze capture", "Saved cases", "Guided lab", "Backups"])
    if mode == "Analyze capture":
        st.header("Detection settings")
        window = int(st.number_input("Window (seconds)", 1, 3600, 10))
        scan_ports = int(st.number_input("Distinct ports for scan alert", 2, 1000, 10))
        volume_bytes = int(st.number_input("Bytes per source per window", 1, 1_000_000_000,
                                         1_000_000, step=100_000))
        st.caption("Scan: rolling window, one alert per source/target pair. "
                   "Volume: fixed buckets aligned to CSV Time zero.")
        st.download_button("Download sample CSV",
                           Path(__file__).with_name("sample.csv").read_bytes(),
                           "sample.csv", "text/csv")
    elif mode == "Guided lab":
        st.caption("Lab rules use fixed settings: 10 seconds, 10 distinct ports, "
                   "and 1,000,000 captured bytes. Analysis workspace settings do not "
                   "change the reference exercises.")
if mode == "Saved cases":
    render_saved_cases(store)
elif mode == "Guided lab":
    render_guided_lab(store)
elif mode == "Backups":
    render_backups(store)
else:
    render_analysis(store, window, scan_ports, volume_bytes)
