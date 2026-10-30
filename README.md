# Network Traffic Investigation Dashboard

A local cybersecurity portfolio project for authorized network analysis labs.
Upload a Wireshark CSV, explore charts, review explainable findings, and download
a JSON or printable HTML investigation report with your notes. Review supporting packets, copy exact
Wireshark frame filters, and save editable investigation cases in local SQLite.
Practice evidence-based decisions in the guided investigation lab.
Review case revision history, export pseudonymized sharing copies, and merge
portable backups without overwriting existing cases.
This is an educational triage tool, not an intrusion detection system or a malware verdict.

## Windows quick start

1. Install Python 3.11 or newer from https://www.python.org/downloads/ with
   the Python launcher enabled.
2. Extract the entire ZIP into a folder you control.
3. Double-click **Start Dashboard.bat**. First setup creates a project-local
   virtual environment and downloads dependencies from PyPI.
4. Open http://127.0.0.1:8501 if the browser does not open automatically.
5. Explore the synthetic demo, open **Guided lab**, or upload an authorized lab CSV.
6. Keep the terminal open while using the app. Press Ctrl+C to stop it.

The launcher checks dependencies on each start. Internet is required for initial
setup and dependency updates. Package versions are bounded, not locked.
The app binds to localhost and disables Streamlit usage statistics.
Captures are processed locally, not uploaded to a cloud service.
Do not deploy this educational app publicly without additional hardening.

Manual startup in PowerShell from the extracted folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1 --server.maxUploadSize 20 --browser.gatherUsageStats false
```

## Wireshark export

- Set the Time display format to **Seconds Since Beginning of Capture**.
- Select **File > Export Packet Dissections > As CSV**, including column headings.
- Required headers: `Time`, `Source`, `Destination`, `Protocol`, `Length`.
  Headers are case-insensitive and may contain surrounding spaces.
- Keep `Info` for TCP scan detection. Default TCP strings such as
  `50000 -> 443 [SYN]` and Unicode-arrow equivalents are supported.
- Optional destination port headers: `tcp.dstport`, `Destination Port`, `Dst Port`.
  Add a custom `tcp.dstport` column in Wireshark if necessary.
- Include `No.` or `frame.number` to preserve original capture frame numbers.
  Values must be positive, unique integers. Do not replace them with CSV row
  numbers or renumber the capture. If both columns exist, `frame.number` is used.
  Missing frame numbers do not prevent analysis, but disable exact filters for
  any finding with incomplete frame identifiers.
- Use UTF-8, comma-separated CSV. Time must be nonnegative relative seconds,
  not a date or time-of-day string. Length must be a nonnegative integer.
- Limits: 20 MB through the dashboard and 200,000 packet rows.

## Detection rules

**Potential port scan:** at least 10 distinct TCP destination ports from one source
to one destination within a rolling 10-second window. Only packets with `[SYN]`
in Info count, not `[SYN, ACK]`. Repeated ports do not increase the distinct count.
At most one finding is emitted per source/target pair. Distributed, horizontal,
UDP, and slow scans are outside this rule's scope.

**High traffic volume:** at least 1,000,000 captured bytes from one source in a
fixed 10-second bucket aligned to CSV Time zero. All protocols count. Traffic
near bucket boundaries may be split across buckets. This is an absolute
threshold, not baseline-relative anomaly detection.

Both rules have adjustable thresholds and display evidence and follow-up steps.
Missing scan evidence produces a warning. The synthetic demo uses reserved
documentation addresses and produces one scan finding at default settings.
Reduce the byte threshold to 1,000 to also exercise the volume rule.

Packet Length is the exported packet length, not application payload size.
Capture filters, packet loss, NAT, incomplete exports, and authorized scanning
can affect interpretation. No findings is not a safety guarantee.
DNS appears in protocol summaries, but DNS-specific detection and payload
inspection are not included in this version.

## Investigation reports

Add context in the report tab. Download JSON or explicitly save a case before
closing; nothing is automatically saved. Reports now include all supporting
packet metadata for each finding, exact frame filters where available, detection
settings, and limitations. The capture name and SHA-256 of the uploaded CSV help
identify the analyzed export; this is not a hash of its original PCAP.
Reports include addresses and notes: sanitize them before sharing.

**Printable reports:** analysis, saved cases, and guided lab attempts offer a
self-contained HTML download. Open it in a browser and use **Print > Save as PDF**.
These are printable text/table reports, not chart exports or direct PDF generation.
They contain full supporting packet tables, not just the visible evidence page.
No external assets or scripts are used. Uploaded text and notes are HTML-escaped.
Large captures may produce large HTML files and many printed pages.
Saved-case reports include the last saved investigation fields; unsaved edits
are not included.

### Packet evidence and Wireshark filters

Each finding displays the exact packet set used to trigger it:

- Scan evidence includes the SYN packets in the first triggering rolling window,
  including repeated attempts within that window. Expired packets, later packets,
  unrelated hosts, and SYN/ACK packets are excluded.
- Volume evidence includes all packets from that source in the triggering fixed
  bucket. Their captured lengths sum to the bytes cited by the finding.
- Evidence tables show 100 packets per page. Reports and case snapshots contain
  **all** supporting packets, not just the current page.
- `CSV record` identifies the record in the exported file. `Capture frame` is the
  original Wireshark frame number. They are deliberately kept separate.

Copy the code block's display filter into Wireshark while viewing the **same
original capture**. For example:

```text
frame.number in {42..45 123}
```

This selects frames 42 through 45 and frame 123, not intervening frames.
The synthetic demo's scan filter is `frame.number in {1..10}`.
These are display filters, not capture filters; no filters are executed by this
app. Exact selection avoids assuming that CSV address labels are IP addresses or
that the exported timestamps have full capture precision. Do not apply these
filters to another, merged, or renumbered capture. Without original frame
identifiers, the app warns instead of inventing an exact filter.

### Saved investigation cases

1. In **Investigation report**, add capture notes if desired.
2. Complete **Save an investigation case**: title, status, disposition, analyst
   assessment, root-cause hypothesis, and recommended action.
3. Click **Save new case locally**. This freezes the current evidence and settings.
4. Select **Saved cases** in the sidebar. No CSV upload is needed to reopen a case.
5. Edit the investigation fields, then click **Save case changes**.
6. Use **Download saved case (JSON)** for a portable copy of the last saved case,
   including the full evidence snapshot. Unsaved form edits are not included.

Statuses: New, Investigating, Resolved. Dispositions: Inconclusive, Authorized
activity, Suspicious. Capture notes at creation remain read-only in the snapshot;
continue the investigation in the editable analyst-assessment field.
Changing the current capture or thresholds does not change saved evidence.
Reanalysis creates a new case, rather than silently replacing an old snapshot.
Conflicting edits from another session are rejected; use **Reload case from disk**
to refresh (this discards unsaved edits).

On Windows, cases are stored outside the extracted project at:

```text
%LOCALAPPDATA%\NetworkTrafficInvestigator\cases.sqlite3
```

If LOCALAPPDATA is unavailable, the app uses `NetworkTrafficInvestigator` under
your home folder. The database path is displayed in the UI. Cases survive app
restarts and replacing the extracted project folder. The ZIP contains no database
or user data. Only supporting packet metadata, findings, settings, capture
identity, and notes are saved, not the raw CSV or packet payloads. Guided lab
cases additionally preserve the entire small synthetic practice capture.

**Privacy:** this is a single-user, unencrypted local database, not an authenticated
multi-user case platform. Use a private account and disk encryption. Sharing
reports are distinct from full restore backups (see below). There is no case
deletion button in this version; manage data retention accordingly.
Storage/validation errors are displayed, not treated as successful saves.

### Case revision history

Creation and each successful edit now record a UTC timestamp, revision number,
self-reported analyst label, and the complete investigation fields at that revision.
The history panel shows before/after values and previous versions read-only.
Creation/editing the case and recording its history occur in the same transaction:
a failed history write does not leave a partially saved case. Stale edits are
still rejected without adding a revision.

Use **Recorded by** when creating or editing a case. Guided lab saves default to
**Local analyst**. These labels are not authenticated identities, and local SQLite
history is not a tamper-proof or cryptographically signed audit log. Evidence
snapshots remain unchanged by case edits. JSON and printable HTML case exports
include revision history; unsaved form edits are excluded.

**Upgrading from v2/v3:** stop the old app and make a secure copy of the database
before first running v4. The history table is added automatically without changing
case IDs, current revisions, timestamps, or evidence. Existing cases receive one
**Legacy baseline** at their current revision, attributed to **Unknown (pre-history)**.
Earlier edits cannot be reconstructed and are not invented. Subsequent edits are
recorded normally. Do not keep an older app running against the upgraded database,
since older versions do not record history.

### Anonymized sharing exports

Check **Anonymize sharing exports** next to the download buttons in Analyze
capture, Saved cases, or a submitted Guided lab attempt. This affects JSON and
printable HTML downloads only; the on-screen investigation, stored cases, and
full backups retain the original evidence.

The sharing copy:

- Replaces source/destination labels, valid IP/MAC addresses, and matching address
  references with consistent `Host-001`-style aliases within the export.
- Removes capture filenames/fingerprints, case IDs, analyst labels, and absolute
  timestamps.
- Redacts free-text analyst notes, case titles, root-cause hypotheses, recommendations,
  packet Info details, and guided-lab narrative/context fields. Rule evidence
  counts and supported structured classifications remain.
- Removes exact Wireshark filters and includes a privacy notice. No alias mapping
  is embedded. Download filenames do not include original case IDs.

This is conservative **pseudonymization**, not a guarantee of irreversible
anonymization or a personal-data detection service. Relative packet times,
frame/record numbers, ports, counts, lengths, and other remaining structured data
can allow correlation. Review every field before sharing, especially unfamiliar
or manually added metadata. Sharing copies cannot restore original evidence.

### Full backups and non-overwriting restore

1. Select **Backups** in the sidebar.
2. Click **Download full backup (JSON)**. This is a consistent snapshot of all
   saved cases, immutable evidence, IDs, timestamps, and revision history.
3. Keep the backup securely: it is **unredacted and unencrypted**, regardless of
   sharing-export checkbox settings.
4. On the target app, upload the full backup JSON. Review the preview showing new
   cases, identical cases, and conflicts. A report/case sharing JSON or a SQLite
   file is not a portable backup input.
5. Confirm the merge, then click **Merge new cases from backup**.

The entire file is validated before importing any case. New IDs are imported
with their complete history. Identical cases are skipped. Existing IDs with any
different content/history are reported as conflicts and **never overwritten**,
even if the incoming case has a higher revision. Other new cases can still be
imported alongside reported conflicts. Conflicting histories are not merged.
The result reports imported, identical, and conflicting counts.
The database is rechecked at merge time, so a change after preview cannot cause
an overwrite. Reimporting the same backup is idempotent.

Imports are transactional: storage failures roll back all new cases from that
merge. Invalid files, duplicate IDs/JSON keys, unsupported versions, malformed
packet evidence, inconsistent history, and non-finite numeric values are rejected
with an error rather than a partial or success-shaped result.

Portable backup limits are **20 MB**, **1,000 cases**, and **10,000 history entries
per case**. Oversized exports/restores fail explicitly. For a larger database or
an offline disaster-recovery backup, stop the app and copy `cases.sqlite3` to
secure storage. Copying that file back manually replaces a database; the in-app
restore never does so. Do not copy/replace the SQLite file while the app is running.
Keep an original backup when a merge reports conflicts; there is no overwrite or
automatic conflict-resolution option in this version.

Suggested portfolio workflow: investigate a lead in Wireshark, correlate with host
logs, document what supports or contradicts your hypothesis, and recommend a
proportionate next step. Present this as a lab project, not production experience.

## Guided investigation lab

Choose **Guided lab** in the sidebar. Four neutral capture labels avoid revealing
the intended conclusion in the scenario name. The set covers ordinary browsing,
authorized assessment activity, unapproved scanning behavior, and a legitimate
large transfer. All addresses are reserved documentation addresses. All change
records, asset records, jobs, and user reports are fictional.

1. Choose a practice capture and read the supplied context.
2. Inspect the traffic overview, packet preview, and rule findings. Optionally
   download the synthetic CSV for further analysis.
3. Record a disposition, hypothesis, supporting evidence and uncertainties, and
   a next investigation step. All text fields are required.
4. Click **Submit assessment** to freeze your response for this attempt.
5. Only then can you click **Reveal reference explanation**.
6. Compare your reasoning with the reference. A disposition match is not a
   grade of your evidence; cautious alternatives can be reasonable.
7. Download the lab report as JSON or printable HTML, or click **Save lab attempt
   as case** to reopen it later through Saved cases.

The lab uses fixed default detection settings (10 seconds, 10 distinct ports,
1,000,000 captured bytes). Changing thresholds in Analyze capture does not alter
the exercises. The reference distinguishes a correct behavior alert from a
malicious-activity verdict: an approved scan or backup can legitimately trigger.
Unanswered connection attempts do not prove failed connections or compromise.

Submitted attempts include context, your assessment, the CSV identity, rule
settings, full synthetic packet metadata, and finding evidence. This preserves
evidence even for exercises with no alerts. Reference feedback is included in
exports and saved cases **only after explicit reveal**. Saving freezes the
current snapshot; revealing later does not modify an already saved case.
Each attempt can be saved once. Start a new attempt to save a separate review.
Existing v2 cases remain compatible and keep their original evidence.

Submitted attempts are independent per capture and retained only in the current
browser session unless saved or downloaded. Unsubmitted form drafts can be lost
when switching workspace/capture. **Start a new attempt** clears that capture's
current session attempt, including any unsaved response; it never deletes saved
cases. Stop and restart the app to clear session-only attempts.

This is a learning aid, not an exam security boundary: reference answers are in
the source code. Synthetic CSVs are metadata only, not PCAP files, and no actual
network traffic is generated. Their frame filters illustrate syntax but no
matching real capture is bundled. These few labeled examples verify expected
rule behavior; they do not establish real-world accuracy or false-positive rates.

## Tests

Engine, evidence/filter, history, privacy, backup/restore, case-persistence,
scenario, and HTML-report tests need only Python's standard
library. Dashboard tests are skipped if Streamlit is not installed:

```powershell
py -3 -m unittest discover -s tests -v
```

After installing dependencies, the same suite also exercises the dashboard,
including case creation, reopening in a fresh session, editing saved cases,
assessment/reveal gating, scenario isolation, saved lab attempts, sharing exports,
and restore preview/confirmation/conflict behavior:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```
