# Data sources, the review workflow and accounts

This page sets out, in plain language, how each data source in the paper (Objective 2
a–h) is handled. It can be adapted for Chapter 3.

## Data sources

| Source | Where the data comes from | What becomes a finding | How a finding is verified |
|---|---|---|---|
| SCA (configuration) | Wazuh alerts `wazuh-alerts-4.x-*` (read-only Indexer account) | A failed check | A later scan shows the check passed |
| Windows security events | Wazuh alerts, `data.win.system.eventID` in `config/monitored_events.json` | One of the events listed below appears; 4625 needs 5 or more in the lookback window | Someone marks it fixed, then a **later** assessment confirms the fix. For a linked SCA requirement, that check passes after the fix. Otherwise a newer SCA scan arrives with no repeat of the event. |
| File integrity (FIM) | Wazuh syscheck alerts under the paths in `config/fim_baseline.json` | A protected file or registry key is added, changed or deleted | After the fix is recorded, a later FIM record of the same path (the restore) |
| Vulnerabilities | `wazuh-states-vulnerabilities-*` | A CVE on an installed package; severity comes from CVSS | A later scan no longer lists it |
| Software inventory | `wazuh-states-inventory-packages-*` | A package that is not on `config/approved_software.json` (the rule is off while the list is empty) | A later inventory no longer shows it |
| Open ports | `wazuh-states-inventory-ports-*` | A listening port that is not on `config/approved_ports.json` (the rule is off while the list is empty) | A later inventory no longer shows it |
| BitLocker | PowerShell collector `collector/Send-BitLockerStatus.ps1` sending to `POST /api/collector/bitlocker` | The OS drive is not protected or not 100% encrypted (REQ-BL-02), or does not use XTS-AES 256 (REQ-BL-03) | A later collector report passes. A report older than 24 hours counts as **unknown**. |

These Windows events are monitored:

| Event ID | Meaning |
|---|---|
| 4719 | Audit policy changed |
| 1102 | Security log cleared |
| 4720 | New user account created |
| 4732 | User added to a security-enabled local group |
| 4625 | Failed sign-in |
| 5001 | Defender real-time protection turned off |

Safety rules:

- **Never "absence means fixed" when data is missing.** A source that cannot be read
  (missing index, Indexer error) is skipped and the dashboard shows a warning.
  State sources only treat a missing item as fixed for agents that are online.
- **Nothing sensitive is collected.** The BitLocker endpoint rejects any field that
  looks like a recovery key, password or key protector, and stores nothing from that
  report. The collector only sends seven status fields. FIM stores the path and change
  type, never file contents.
- **Sample mode** uses `samples/observations_sample.json`. It holds fictional events,
  file changes, CVE IDs from the year 2099, ports, packages and BitLocker reports, so
  every source can be shown on the floor plan without the lab.

### Field names still to confirm in the lab (Wazuh 4.14.8)

The event and FIM fields are the standard Wazuh 4.x alert fields. The state-index
fields come from the Wazuh source documentation (5.x). None of them has been seen in
this lab yet. If an index is missing in 4.14.8, the dashboard says so and that source
is skipped.

The Windows agent also needs these settings:

- The `Microsoft-Windows-Windows Defender/Operational` channel, so event 5001 is
  collected.
- A `<syscheck>` entry for `C:\LabData\ClientRecords` and the Run / RunOnce keys.

## Review workflow (Objective 2g)

| Status | Who sets it |
|---|---|
| open | sync (new failure or reopened) |
| in_review | reviewer or admin |
| fixed_pending | reviewer or admin, **with a note** describing the simulated fix |
| exception | **admin only**, with a justification; the finding stops being scored |
| cleared | sync only: it passed again before anyone marked it fixed |
| verified | sync only: a later assessment passed after it was marked fixed_pending |

Nobody can set `verified` or `cleared` by hand. Every change, including those made by
sync (shown as actor `system`), and every note goes to the `finding_events` history.
That history appears in the dashboard and in the report.

## Accounts and roles

- **admin**: accounts, asset fields, floor plans and positions, exceptions, and
  everything a reviewer can do.
- **reviewer**: reviews findings, records simulated fixes and notes, and generates
  the report and CSV export.

Login rules:

- Only password hashes are stored (scrypt), and passwords need at least 12
  characters.
- After 5 wrong passwords an account is locked for 15 minutes.
- Sessions last 8 hours. The session cookie is HttpOnly and SameSite=Strict, and also
  Secure when `SESSION_COOKIE_SECURE=1`.
- A disabled account loses access on its next request.

Create the first administrator on the server:

```bash
python -m webapp.auth create-user admin --role admin
```

## Report (Objective 2h)

`/report` is a printable page; use the browser's Print command to save it as PDF. It
contains:

- counts by band, status and source;
- every endpoint with its seat and highest band;
- open findings by priority, "Needs data" findings, and the verified, cleared and
  excepted findings, each with its full history.

`/api/reports/findings.csv` exports the same findings. Cells are escaped so a
spreadsheet cannot run them as formulas.
