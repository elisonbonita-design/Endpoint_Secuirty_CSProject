# Lab test run — 2026-10-28

First run against real Wazuh data. **Setup mode**: every laptop still had internet, so the isolation tests could not pass yet (see section 6).

| Item | Value |
|---|---|
| SEC01 | Ubuntu 26.04.1 LTS (not 24.04 as in Table 1), Wazuh 4.14.9 all-in-one, app on 127.0.0.1:5000 |
| SEC01 addresses | 10.20.0.20/24 (lab, no gateway) + 192.168.100.70/24 (router, DHCP) |
| WS01 | Windows 11 Pro 10.0.26100.1742, hostname DESKTOP-U842E9R, domain `results` (not `cxlab.internal`) |
| WS01 agent | Wazuh agent 4.14.9, ID 001, name WS01, reporting to 192.168.100.70 |
| DC01 | Not used in this run (Group Policy baseline not applied) |
| App accounts | Test accounts t-admin, t-reviewer and t-lockout, created only for this run |
| Test script | `tools/labtests/lab_tests.py`, run on SEC01 |

**Totals:** 20/20 app tests passed, 3 detection actions were raised, 1 of 3 findings was verified, and 3 network and isolation checks failed.

## 1. Unit and API tests

`python -m unittest discover -s tests` passed: **221 tests OK** on Windows (Python 3.13.17) and on SEC01 (Python 3.14.4).

## 2. Integration: the app reading live Wazuh data

| ID | Test | Result | Detail |
|---|---|---|---|
| I1 | App reads the indexer and lists WS01 | PASS | Agent 001, no warnings, 433 ms |
| I2 | SCA results are mapped to states | PASS | 482 CIS Windows 11 checks: 348 failed, 125 passed, 9 not applicable, 0 unknown. 27 baseline requirements: 14 compliant, 4 non-compliant, 9 no data |
| I3 | Open findings are scored and ranked | PASS | 4 SCA findings (REQ-PW-01, AU-01, AU-02 and SL-01) before the detection tests |
| I4 | CSV report is generated | PASS | 10 ms |
| I5 | Vulnerability and inventory data become findings | PASS, after a delay | 447 CVE findings on Windows 11 build 26100.1742. They appeared only once `wazuh-monitoring` listed WS01 as online, about 15 minutes after enrollment |

## 3. Detection: controlled actions on WS01

| ID | Action on WS01 | Expected finding | Result | Time to appear* | After reversal |
|---|---|---|---|---|---|
| D1 | Create local user `labtest-user1` | REQ-AC-03 (event 4720) | PASS | ≤ 5 s | Fix recorded, then **not verified**. See defect 1 |
| D2 | Change audit policy (Security System Extension), then restore | REQ-AU-03 (event 4719) | PASS | ≤ 11 s | Fix recorded, then **correctly still waiting**: REQ-AU-01 and REQ-AU-02 still fail on WS01 |
| D3 | Edit synthetic `C:\LabData\ClientRecords\client-3.txt` | REQ-FI-01 (FIM) | PASS | ≤ 11 s | **Verified** 70 s after the fix was recorded and the file restored |

\*Measured from the action to the first app read that showed the finding. Each time includes the polling interval, so it's an upper bound.

**Not run:** Defender real-time protection off (5001 needs the Defender channel and Tamper Protection off), 5 failed sign-ins (4625), an unapproved or old program, a blocked port, and BitLocker (the collector token was not set).

## 4. Workflow

| ID | Test | Result | Detail |
|---|---|---|---|
| W1 | Verified is never offered as a manual status | PASS | Reviewer options were `in_review` and `fixed_pending` |
| W2 | Setting verified by hand is refused | PASS | HTTP 400: "Only a later assessment can mark a finding cleared or verified." |
| W3 | Reviewer cannot approve an exception | PASS | HTTP 403 |
| W4 | A status change is recorded in history | PASS | |
| W5 | Fix recorded → later assessment → verified | PASS (FIM) | Finding 27: open → fixed_pending → verified |

## 5. Security

| ID | Test | Result | Detail |
|---|---|---|---|
| S1–S2 | Admin and reviewer sign in | PASS | |
| S3 | API without sign-in | PASS | HTTP 401 |
| S4 | Wrong password | PASS | HTTP 401 |
| S5 | Sign-in posted from another site | PASS | HTTP 403 |
| S6 | Lockout after 5 wrong passwords | PASS | The correct password is then refused (HTTP 429) |
| S7–S8 | Reviewer lists or creates accounts | PASS | HTTP 403 |
| S9 | Change without the dashboard header | PASS | HTTP 403 |
| S10 | Collector with a bad token | PASS | HTTP 503 (collector off). Retest once `COLLECTOR_TOKEN` is set |
| S11 | Invalid endpoint ID | PASS | HTTP 400 |
| N1 | Wazuh indexer (9200) from another laptop | PASS | Not reachable: it listens on 127.0.0.1 only |
| N2 | Compliance app (5000) from another laptop | PASS | Not reachable: it listens on 127.0.0.1 only. Lab mode needs 8443 with TLS |
| N3 | Wazuh API (55000) from another laptop | **FAIL** | Reachable from WS01. The paper expects this to fail |
| N4 | Agent enrollment without a password | **FAIL** | No enrollment password is set; WS01 enrolled without one ("No authentication password provided") |

## 6. Isolation

| ID | Test | Result |
|---|---|---|
| X1 | WS01 cannot reach the internet | **FAIL**: setup mode (WS01 reached 1.1.1.1:443) |
| X2 | No laptop has a default gateway | **FAIL**: SEC01 and WS01 both use 192.168.100.1 |

## 7. Performance (1 endpoint, 482 SCA checks, 454 findings)

| Operation | Time |
|---|---|
| Scan now (fleet read from Wazuh) | 430, 427, 422 ms (mean 426 ms) |
| Record a status change, including the score recompute | 1.1 s |
| CSV report | 10–17 ms |

## Follow-up run — 2026-10-29: approved software (REQ-SW-01) and the rescanning Scan now

| ID | Action | Result | Detail |
|---|---|---|---|
| D4 | Install 7-Zip 26.05 on WS01 (official release, SHA-256 matched GitHub's published hash), then Scan now | PASS | Finding #499 "Unapproved software installed: 7-Zip 26.05 (x64)" created. Scan now took 158 s: the agent took 64 s to restart, and no SCA summary arrived because the score didn't change, so the scan counted as done after the 90 s wait |
| D4r | Uninstall 7-Zip, then Scan now | PASS | Finding #499 open → cleared (state compliant) in 148 s |
| SW1 | Approve WS01's programs as the baseline (Software page, as t-admin) | Partly | Only 4 of 28 programs were in the inventory when the baseline was taken, so the 24 others (built-in Windows apps and WinRAR 7.23) opened as findings once the full inventory arrived |

| NP0 | Approve WS01's listening ports except SSH (Ports page, as t-admin) | PASS | 35 listening ports → 11 checks (6 fixed TCP ports, 5 programs on dynamic ports); 24 skipped (UDP or loopback-only). SSH caught right away as #501 "Unapproved listening port 22/tcp (sshd.exe)" |
| D5 | Turn on Remote Desktop on WS01 (firewall still on in all 3 profiles), then Scan now | PASS | #502 "Unapproved listening port 3389/tcp (svchost.exe)" created in 97 s. The first attempt timed out (183 s): turning RDP on dropped WS01's network for ~1 min, the restart request arrived while the agent was offline and was lost, and the button showed its 3-minute timeout note |

| D6 | Start a temporary test listener on WS01 (PowerShell, TCP 8080, firewall unchanged), then Scan now | PASS | #503 "Unapproved listening port 8080/tcp (powershell.exe)" created in 107 s |
| D6r | Stop the listener, then Scan now | PASS | #503 open → cleared (state compliant) in 97 s |

| SC1 | Install the add-on SCA policy `wazuh/sca/capstone_windows_extra.yml` on WS01. Each command was dry-run first; the file hash matched the repo; `<policies>` was added to the agent's `<sca>` block (backup: `ossec.conf.before-sca-custom`) | PASS | Both policies loaded and ran in 40 s. **REQ-PW-03** (password complexity, check 99004, the CIS 1.1.5 item Wazuh's CIS policy does not implement) is now tracked: **compliant** (`PasswordComplexity = 1`). REQ-PW-04, the Defender checks and Secure Boot are also compliant. **REQ-BL-01 is non-compliant**: system drive protection status 0. Requirements with no data: 9 → 2 |

Defects found and fixed in this run:

6. **A "future" monitoring snapshot hid WS01's real status.** SEC01 booted with its clock about 7½ hours fast, likely because a dual-boot Windows keeps the hardware clock in local time. Until NTP corrected it, the dashboard wrote one snapshot dated 16:45 UTC saying "disconnected". That snapshot stayed newest, so WS01 counted as offline, Scan now skipped it, and inventory findings were not read. **Fix:** snapshots dated more than 5 minutes ahead are ignored, and Scan now asks Wazuh to restart every agent and reports the ones it could not reach. **Still open:** SEC01's hardware clock. In lab mode (no NTP) it would stay wrong.

## Defects and gaps found

1. **An event finding with no linked check (REQ-AC-03) does not verify.** Verification waits for "a newer SCA scan", but restarting the agent did not move WS01's last SCA time past 11:33:45Z, apparently because no check results changed. Options: use the SCA scan summary time instead of check times, or define different evidence for event-only requirements.
2. **WS01 counted as "unknown" for about 15 minutes after enrollment,** until the dashboard filled `wazuh-monitoring`. During that time, vulnerability and inventory findings were skipped. This is by design, so missing data is never treated as clean.
3. **The Wazuh API is reachable from the lab network, and enrollment needs no password** (N3, N4). Fix: enable `<use_password>` in the manager's `<auth>` block, and restrict 55000 with ufw to SEC01 itself.
4. **WS01's clock is about 9 hours off** from SEC01. Alert times come from the manager, so detection still worked.
5. **`config/approved_ports.json` says the app does not collect listening ports,** but the code does read the port inventory (84 ports). Update the note.
