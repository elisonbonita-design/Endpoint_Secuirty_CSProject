# Lab scripts (isolated capstone lab only)

Both scripts are console menus for Windows PowerShell 5.1. Start them with the `.cmd`
file next to them: it asks for administrator rights and keeps the window open.

## DC01: `dc01\LabGpoMenu.cmd`

Creates the Group Policy baseline from the paper (Table 2) in the lab domain.

- **What it creates:**
  - the `LabWorkstations` OU, with WS01 moved into it
  - the GPOs `LAB-WS-SecurityBaseline`, `-Firewall`, `-Audit` and `-BitLocker`, all linked to that OU
- **Password and lockout rules** go in the **Default Domain Policy**, as in the paper's Table 2. Set them in the Group Policy editor; menu option 5 shows the steps and checks the values. A security template written into a new GPO by the first script version was ignored by Windows in lab testing, so the script no longer creates it.
- **Before you run it:** DC01 must already be a domain controller (AD DS, DNS, domain `cxlab.internal`), and WS01 must be joined to the domain.
- **Afterwards, on WS01:** run `gpupdate /force`, then check with `gpresult /r /scope computer`.
- **Still manual:** trusting the lab CA certificate (`lab-ca.crt` from SEC01) is done in the Group Policy editor; the menu prints where.

## WS01: `ws01\LabBaselineMenu.cmd`

The demo menu. It shows every baseline control as `[ ON ]`, `[OFF ]` or `[ ?? ]`. ON/OFF follow the same rules as the Wazuh checks.

| Key | What it does |
|---|---|
| number | Toggle that control (OFF should create a finding) |
| `A` | Apply the full baseline (everything ON) |
| `X` | Break everything for the demo (BitLocker is left alone) |
| `D` | Demo actions: test user (4720), group change (4732), failed sign-ins (4625), clear Security log (1102), protected-file and Run-key changes (FIM) |
| `U` | Setup: synthetic client records, BitLocker collector task, new Wazuh manager address after the network move, audit subcategories |
| `S` | Scan now: restarts the Wazuh agent, which runs SCA and inventory |

**Demo flow:**
1. Turn a control OFF, then press `S`.
2. The finding appears in the app.
3. In the app, record a simulated fix (Review and history → "Fixed, waiting for verification" with a note).
4. Turn the control back ON, then press `S`.
5. The finding becomes **Verified**.

If WS01 is in the domain, Group Policy also restores the baseline at its next refresh. That's the paper's drift-and-restore example.

**Notes:**
- Defender real-time protection can only be turned off after Tamper Protection is turned off in Windows Security.
- The menu never turns BitLocker *on*. Encryption is turned on through the BitLocker GPO, so the recovery key is stored in AD.
- Put `Send-BitLockerStatus.ps1` (from `collector\`) in the same folder before using setup option 2. The collector only accepts a lab address (`https://10.20.0.x`).
- Nothing in these scripts prints or stores passwords, recovery keys or file contents. The test user gets a random password that is never shown.
