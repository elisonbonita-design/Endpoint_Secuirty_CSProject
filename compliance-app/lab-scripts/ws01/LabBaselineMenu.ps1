<#
.SYNOPSIS
  WS01 demo menu: show and toggle the lab security baseline, and trigger the monitored test events.

.DESCRIPTION
  For the isolated capstone lab only (Windows 11 test laptop WS01). Run as Administrator,
  or start LabBaselineMenu.cmd, which asks for elevation.

  Each control maps to a requirement in config/requirements.json and to the Wazuh SCA check
  that verifies it, so turning a control OFF should produce a finding and turning it back ON
  should let the next assessment verify the fix ("S = scan now" restarts the agent, which runs SCA).

  When WS01 is joined to the lab domain, the LAB-WS-* GPOs from DC01 re-apply the baseline at
  the next Group Policy refresh (gpupdate /force), undoing demo changes. That is itself the
  drift-and-restore demo described in the paper.

  Nothing here reads or prints passwords, recovery keys or file contents.
#>
[CmdletBinding()]
param(
    [switch]$StatusOnly,                                   # print the status table once and exit (read-only)
    [string]$ServerUrl = 'https://10.20.0.20:8443',       # compliance app on SEC01 (lab network)
    [string]$DataFolder = 'C:\LabData\ClientRecords'      # protected folder watched by Wazuh FIM
)

$ErrorActionPreference = 'Stop'
$Host.UI.RawUI.WindowTitle = 'CX Lab - WS01 baseline demo'
$CollectorDir = 'C:\ProgramData\CapstoneCollector'
$TestUser = 'labtest'
$RunKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
$RunValue = 'LabDemoUpdater'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------- helpers: local security policy (secedit)

# %TEMP% can be an 8.3 short path (C:\Users\WS01~1\...) that Remove-Item cannot resolve. Use a fixed lab
# folder with a normal long path, and delete through .NET so clean-up can never stop the script.
$TempDir = Join-Path $env:ProgramData 'CapstoneLab\tmp'
New-Item -ItemType Directory -Force $TempDir -ErrorAction SilentlyContinue | Out-Null

function Remove-TempFile([string[]]$Paths) {
    foreach ($f in $Paths) { try { if ([IO.File]::Exists($f)) { [IO.File]::Delete($f) } } catch { } }
}

function Get-SecPolicySnapshot {
    $tmp = Join-Path $TempDir ("secpol-{0}.inf" -f [guid]::NewGuid())
    try {
        secedit /export /cfg $tmp /areas SECURITYPOLICY /quiet 2>$null | Out-Null
        $values = @{}
        if (-not [IO.File]::Exists($tmp)) { return $values }   # export failed (e.g. not elevated): those controls show ??
        foreach ($line in [IO.File]::ReadAllLines($tmp)) {
            if ($line -match '^\s*([A-Za-z]+)\s*=\s*(.+?)\s*$') { $values[$matches[1]] = $matches[2] }
        }
        return $values
    } finally { Remove-TempFile $tmp }
}

function Set-SecPolicy([hashtable]$Values) {
    $inf = Join-Path $TempDir ("secpol-set-{0}.inf" -f [guid]::NewGuid())
    $db = Join-Path $TempDir ("secpol-{0}.sdb" -f [guid]::NewGuid())
    $lines = @('[Unicode]', 'Unicode=yes', '[System Access]')
    foreach ($k in $Values.Keys) { $lines += "$k = $($Values[$k])" }
    $lines += @('[Version]', 'signature="$CHICAGO$"', 'Revision=1')
    try {
        Set-Content -Path $inf -Value $lines -Encoding Unicode
        secedit /configure /db $db /cfg $inf /areas SECURITYPOLICY /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "secedit failed (exit $LASTEXITCODE)" }
    } finally { Remove-TempFile @($inf, $db, ($db -replace '\.sdb$', '.jfm')) }
}

function Get-SecInt([hashtable]$Snap, [string]$Name) {
    if ($Snap.ContainsKey($Name)) { return [int]$Snap[$Name] } else { return $null }
}

# ---------------------------------------------------------------- helpers: registry, audit policy

function Get-RegDword([string]$Path, [string]$Name) {
    try { return [int](Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

function Set-RegDword([string]$Path, [string]$Name, [int]$Value) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

# Subcategory GUIDs avoid problems with localized subcategory names.
$AuditGuids = @{
    'Credential Validation'     = '{0CCE923F-69AE-11D9-BED3-505054503030}'
    'Process Creation'          = '{0CCE922B-69AE-11D9-BED3-505054503030}'
    'User Account Management'   = '{0CCE9235-69AE-11D9-BED3-505054503030}'
    'Security Group Management' = '{0CCE9237-69AE-11D9-BED3-505054503030}'
    'Logon'                     = '{0CCE9215-69AE-11D9-BED3-505054503030}'
    'Audit Policy Change'       = '{0CCE922F-69AE-11D9-BED3-505054503030}'
}

function Get-AuditSetting([string]$Name) {
    $raw = auditpol /get /subcategory:"$($AuditGuids[$Name])" /r 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $raw) { return $null }      # not elevated or not readable: unknown
    $csv = $raw | Where-Object { $_ } | ConvertFrom-Csv
    return ($csv | Select-Object -First 1).'Inclusion Setting'   # "Success", "Failure", "Success and Failure", "No Auditing"
}

function Set-AuditSetting([string]$Name, [bool]$Success, [bool]$Failure) {
    $s = if ($Success) { 'enable' } else { 'disable' }
    $f = if ($Failure) { 'enable' } else { 'disable' }
    auditpol /set /subcategory:"$($AuditGuids[$Name])" /success:$s /failure:$f | Out-Null
}

# ---------------------------------------------------------------- the controls

$FwPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
$DefenderPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
$SystemPolicy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$TermServer = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

# Same rule as the Wazuh CIS check: compliant when the policy value is absent (Windows default: on) or 1.
function Test-FirewallPolicyOn([string]$Key) {
    $v = Get-RegDword $Key 'EnableFirewall'
    return ($null -eq $v -or $v -eq 1)
}

# Each control: Name, Req (requirement id), Check (SCA id), Get { $true = compliant, $false = not, $null = unknown },
# On { make compliant }, Off { make non-compliant for the demo }.
$Controls = @(
    @{ Name = 'Minimum password length >= 14'; Req = 'REQ-PW-01'; Check = 'CIS 26003'
       Get = { param($s) $v = Get-SecInt $s 'MinimumPasswordLength'; if ($null -eq $v) { $null } else { $v -ge 14 } }
       On = { Set-SecPolicy @{ MinimumPasswordLength = 14 } }; Off = { Set-SecPolicy @{ MinimumPasswordLength = 0 } } }
    @{ Name = 'Password history >= 24'; Req = 'REQ-PW-02'; Check = 'CIS 26000'
       Get = { param($s) $v = Get-SecInt $s 'PasswordHistorySize'; if ($null -eq $v) { $null } else { $v -ge 24 } }
       On = { Set-SecPolicy @{ PasswordHistorySize = 24 } }; Off = { Set-SecPolicy @{ PasswordHistorySize = 0 } } }
    @{ Name = 'Password complexity enabled'; Req = 'REQ-PW-03'; Check = '99004'
       Get = { param($s) $v = Get-SecInt $s 'PasswordComplexity'; if ($null -eq $v) { $null } else { $v -eq 1 } }
       On = { Set-SecPolicy @{ PasswordComplexity = 1 } }; Off = { Set-SecPolicy @{ PasswordComplexity = 0 } } }
    @{ Name = 'Reversible password encryption off'; Req = 'REQ-PW-04'; Check = '99005'
       Get = { param($s) $v = Get-SecInt $s 'ClearTextPassword'; if ($null -eq $v) { $null } else { $v -eq 0 } }
       On = { Set-SecPolicy @{ ClearTextPassword = 0 } }; Off = { Set-SecPolicy @{ ClearTextPassword = 1 } } }
    @{ Name = 'Account lockout after 5 bad attempts'; Req = 'REQ-AC-01'; Check = 'CIS 26006'
       Get = { param($s) $v = Get-SecInt $s 'LockoutBadCount'; if ($null -eq $v) { $null } else { $v -ge 1 -and $v -le 5 } }
       On = { Set-SecPolicy @{ LockoutBadCount = 5; LockoutDuration = 15; ResetLockoutCount = 15 } }
       Off = { Set-SecPolicy @{ LockoutBadCount = 0 } } }
    @{ Name = 'Guest account disabled'; Req = 'REQ-AC-02'; Check = 'CIS 26009'
       Get = { param($s) $v = Get-SecInt $s 'EnableGuestAccount'; if ($null -eq $v) { $null } else { $v -eq 0 } }
       On = { Set-SecPolicy @{ EnableGuestAccount = 0 } }; Off = { Set-SecPolicy @{ EnableGuestAccount = 1 } } }
    @{ Name = 'Screen lock after 900 s idle'; Req = 'REQ-SL-01'; Check = 'CIS 26025'
       Get = { param($s) $v = Get-RegDword $SystemPolicy 'InactivityTimeoutSecs'; if ($null -eq $v) { $false } else { $v -ge 1 -and $v -le 900 } }
       On = { Set-RegDword $SystemPolicy 'InactivityTimeoutSecs' 900 }
       Off = { Remove-ItemProperty -Path $SystemPolicy -Name 'InactivityTimeoutSecs' -ErrorAction SilentlyContinue } }
    @{ Name = 'Firewall ON - Domain profile'; Req = 'REQ-FW-01'; Check = 'CIS 26116'
       Get = { param($s) Test-FirewallPolicyOn "$FwPolicy\DomainProfile" }
       On = { Set-RegDword "$FwPolicy\DomainProfile" 'EnableFirewall' 1 }; Off = { Set-RegDword "$FwPolicy\DomainProfile" 'EnableFirewall' 0 } }
    @{ Name = 'Firewall ON - Private profile'; Req = 'REQ-FW-02'; Check = 'CIS 26123'
       Get = { param($s) Test-FirewallPolicyOn "$FwPolicy\PrivateProfile" }
       On = { Set-RegDword "$FwPolicy\PrivateProfile" 'EnableFirewall' 1 }; Off = { Set-RegDword "$FwPolicy\PrivateProfile" 'EnableFirewall' 0 } }
    @{ Name = 'Firewall ON - Public profile'; Req = 'REQ-FW-03'; Check = 'CIS 26130'
       Get = { param($s) Test-FirewallPolicyOn "$FwPolicy\PublicProfile" }
       On = { Set-RegDword "$FwPolicy\PublicProfile" 'EnableFirewall' 1 }; Off = { Set-RegDword "$FwPolicy\PublicProfile" 'EnableFirewall' 0 } }
    @{ Name = 'Audit Credential Validation (S+F)'; Req = 'REQ-AU-01'; Check = 'CIS 26139'
       Get = { param($s) $v = Get-AuditSetting 'Credential Validation'; if (-not $v) { $null } else { $v -eq 'Success and Failure' } }
       On = { Set-AuditSetting 'Credential Validation' $true $true }; Off = { Set-AuditSetting 'Credential Validation' $false $false } }
    @{ Name = 'Audit Process Creation (Success)'; Req = 'REQ-AU-02'; Check = 'CIS 26144'
       Get = { param($s) $v = Get-AuditSetting 'Process Creation'; if (-not $v) { $null } else { $v -match '^Success' } }
       On = { Set-AuditSetting 'Process Creation' $true $false }; Off = { Set-AuditSetting 'Process Creation' $false $false } }
    @{ Name = 'Defender real-time protection on'; Req = 'REQ-AV-01'; Check = '99002 / event 5001'
       Get = { param($s) try { [bool](Get-MpComputerStatus).RealTimeProtectionEnabled } catch { $null } }
       On = { Set-RegDword $DefenderPolicy 'DisableRealtimeMonitoring' 0; Set-MpPreference -DisableRealtimeMonitoring $false }
       Off = { Set-MpPreference -DisableRealtimeMonitoring $true; Start-Sleep 2
               if ((Get-MpComputerStatus).RealTimeProtectionEnabled) {
                   Write-Warning 'Tamper Protection blocked the change. Turn Tamper Protection off in Windows Security first (lab only).' } } }
    @{ Name = 'BitLocker protection on (C:)'; Req = 'REQ-BL-01/02'; Check = '99001 / collector'
       Get = { param($s) try { (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -eq 'On' } catch { $null } }
       On = { $v = Get-BitLockerVolume -MountPoint $env:SystemDrive
              if ($v.VolumeStatus -eq 'FullyDecrypted') {
                  Write-Warning 'C: is not encrypted. Turn BitLocker on through the LAB-WS-BitLocker GPO (recovery key goes to AD), not from this menu.'
              } else { Resume-BitLocker -MountPoint $env:SystemDrive | Out-Null } }
       Off = { Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 0 | Out-Null } }
    @{ Name = 'Remote Desktop off (port 3389 closed)'; Req = 'REQ-NP-01'; Check = 'inventory ports'
       Get = { param($s) (Get-RegDword $TermServer 'fDenyTSConnections') -eq 1 }
       On = { Set-RegDword $TermServer 'fDenyTSConnections' 1
              Disable-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -ErrorAction SilentlyContinue }
       Off = { Set-RegDword $TermServer 'fDenyTSConnections' 0
               Enable-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -ErrorAction SilentlyContinue } }
)

function Get-ControlStates {
    $snap = Get-SecPolicySnapshot
    foreach ($c in $Controls) {
        try { $state = & $c.Get $snap } catch { $state = $null }
        [pscustomobject]@{ Control = $c; State = $state }
    }
}

function Show-Status {
    $states = @(Get-ControlStates)
    $cs = Get-CimInstance Win32_ComputerSystem
    Clear-Host
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host '  CX LAB  |  WS01 baseline demo  |  isolated lab, synthetic data only' -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    if ($cs.PartOfDomain) {
        Write-Host "  Domain: $($cs.Domain). Group Policy re-applies the baseline at the next refresh (gpupdate /force)." -ForegroundColor DarkYellow
    } else {
        Write-Host '  Not domain joined: changes stay until you change them back here.' -ForegroundColor DarkGray
    }
    $agent = Get-Service WazuhSvc -ErrorAction SilentlyContinue
    Write-Host ("  Wazuh agent: {0}" -f $(if ($agent) { $agent.Status } else { 'not installed' })) -ForegroundColor DarkGray
    Write-Host ''
    Write-Host ('  {0,-3} {1,-40} {2,-8} {3,-12} {4}' -f '#', 'Control', 'State', 'Requirement', 'Checked by')
    Write-Host ('  {0,-3} {1,-40} {2,-8} {3,-12} {4}' -f '--', ('-' * 38), '-----', '-----------', '----------')
    $i = 0
    foreach ($s in $states) {
        $i++
        $label, $color = switch ($s.State) { $true { '[ ON ]', 'Green' } $false { '[OFF ]', 'Red' } default { '[ ?? ]', 'Yellow' } }
        Write-Host ('  {0,-3} {1,-40} ' -f $i, $s.Control.Name) -NoNewline
        Write-Host ('{0,-8} ' -f $label) -ForegroundColor $color -NoNewline
        Write-Host ('{0,-12} {1}' -f $s.Control.Req, $s.Control.Check) -ForegroundColor DarkGray
    }
    Write-Host ''
    return $states
}

function Invoke-Control([int]$Index, [bool]$TurnOn) {
    $c = $Controls[$Index]
    $verb = if ($TurnOn) { 'ON (compliant)' } else { 'OFF (non-compliant, demo)' }
    Write-Host "  -> $($c.Name): $verb" -ForegroundColor Cyan
    try {
        if ($TurnOn) { & $c.On } else { & $c.Off }
        Write-Host '     done' -ForegroundColor Green
    } catch {
        Write-Host "     failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-ScanNow {
    Write-Host '  Restarting the Wazuh agent: SCA and inventory run at agent start (results reach the app in ~1-2 min).' -ForegroundColor Cyan
    Restart-Service WazuhSvc
    Write-Host '  done' -ForegroundColor Green
}

# ---------------------------------------------------------------- demo actions (events and FIM)

function New-RandomPassword {
    $chars = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'.ToCharArray()
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[] 20
    $rng.GetBytes($bytes)
    (-join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })) + '!7a'
}

function Show-DemoMenu {
    while ($true) {
        Clear-Host
        Write-Host '  DEMO ACTIONS  (each one should create a finding in the app)' -ForegroundColor Cyan
        Write-Host ''
        Write-Host '   1  Create test user "labtest"                 -> event 4720  (REQ-AC-03)'
        Write-Host '   2  Add "labtest" to Administrators            -> event 4732  (REQ-AC-04)'
        Write-Host '   3  6 failed sign-ins                          -> event 4625  (REQ-AC-05)'
        Write-Host '   4  Clear the Security event log (asks first)  -> event 1102  (REQ-AU-04)'
        Write-Host '   5  Change a synthetic client record           -> FIM modified (REQ-FI-01)'
        Write-Host '   6  Add a new synthetic client record          -> FIM added    (REQ-FI-01)'
        Write-Host '   7  Delete the added client record             -> FIM deleted  (REQ-FI-01)'
        Write-Host '   8  Add a startup Run registry value           -> FIM registry (REQ-FI-02)'
        Write-Host '   9  Remove the startup Run registry value      -> FIM registry (REQ-FI-02)'
        Write-Host '  10  Remove "labtest" (clean-up)'
        Write-Host ''
        Write-Host '   B  Back' -ForegroundColor DarkGray
        $choice = (Read-Host '  Choose').Trim().ToUpper()
        try {
            switch ($choice) {
                '1' {
                    if (Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue) { Write-Host '  labtest already exists.' }
                    else {
                        $pw = ConvertTo-SecureString (New-RandomPassword) -AsPlainText -Force   # never shown
                        New-LocalUser -Name $TestUser -Password $pw -Description 'Capstone lab test account' | Out-Null
                        Write-Host '  created labtest (random password, not shown)' -ForegroundColor Green
                    } }
                '2' { Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $TestUser; Write-Host '  added to Administrators' -ForegroundColor Green }
                '3' {
                    1..6 | ForEach-Object {
                        net use \\127.0.0.1\IPC$ /user:$TestUser 'wrong-password-demo' 2>$null | Out-Null
                        net use \\127.0.0.1\IPC$ /delete 2>$null | Out-Null
                    }
                    Write-Host '  6 failed sign-ins generated' -ForegroundColor Green }
                '4' {
                    if ((Read-Host '  Really clear the Security log? This deletes local audit history (lab only). Type YES') -eq 'YES') {
                        wevtutil cl Security; Write-Host '  Security log cleared' -ForegroundColor Green } }
                '5' {
                    New-Item -ItemType Directory -Force $DataFolder | Out-Null
                    $f = Join-Path $DataFolder 'client_0001.csv'
                    Add-Content -Path $f -Value ("{0},Synthetic Client {0}" -f (Get-Random -Minimum 100 -Maximum 999))
                    Write-Host "  modified $f" -ForegroundColor Green }
                '6' { $f = Join-Path $DataFolder 'client_demo.csv'; Set-Content -Path $f -Value "id,name`n900,Synthetic Demo Client"
                      Write-Host "  added $f" -ForegroundColor Green }
                '7' { Remove-Item (Join-Path $DataFolder 'client_demo.csv') -ErrorAction SilentlyContinue; Write-Host '  deleted client_demo.csv' -ForegroundColor Green }
                '8' { New-ItemProperty -Path $RunKey -Name $RunValue -Value 'C:\LabData\demo-updater.exe' -PropertyType String -Force | Out-Null
                      Write-Host "  added $RunValue to $RunKey" -ForegroundColor Green }
                '9' { Remove-ItemProperty -Path $RunKey -Name $RunValue -ErrorAction SilentlyContinue; Write-Host "  removed $RunValue" -ForegroundColor Green }
                '10' {
                    Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $TestUser -ErrorAction SilentlyContinue
                    Remove-LocalUser -Name $TestUser -ErrorAction SilentlyContinue
                    Write-Host '  labtest removed' -ForegroundColor Green }
                'B' { return }
                default { Write-Host '  unknown choice' -ForegroundColor Yellow }
            }
        } catch { Write-Host "  failed: $($_.Exception.Message)" -ForegroundColor Red }
        Read-Host '  Press Enter' | Out-Null
    }
}

# ---------------------------------------------------------------- setup actions

function Show-SetupMenu {
    while ($true) {
        Clear-Host
        Write-Host '  SETUP' -ForegroundColor Cyan
        Write-Host ''
        Write-Host "   1  Create the protected folder with 5 synthetic client records ($DataFolder)"
        Write-Host '   2  Install the BitLocker status collector (scheduled task, every 15 min, as SYSTEM)'
        Write-Host '   3  Send BitLocker status now'
        Write-Host '   4  Point the Wazuh agent at a new manager address (after the lab network move)'
        Write-Host '   5  Enable the audit subcategories the event tests need'
        Write-Host ''
        Write-Host '   B  Back' -ForegroundColor DarkGray
        $choice = (Read-Host '  Choose').Trim().ToUpper()
        try {
            switch ($choice) {
                '1' {
                    New-Item -ItemType Directory -Force $DataFolder | Out-Null
                    1..5 | ForEach-Object { Set-Content -Path (Join-Path $DataFolder ("client_{0:d4}.csv" -f $_)) -Value "id,name`n$_,Synthetic Client $_" }
                    Write-Host '  created 5 synthetic records. Restart the agent (S) so FIM takes a baseline.' -ForegroundColor Green }
                '2' {
                    $src = Join-Path $PSScriptRoot 'Send-BitLockerStatus.ps1'
                    if (-not (Test-Path $src)) { throw "Put Send-BitLockerStatus.ps1 next to this script first ($PSScriptRoot)." }
                    New-Item -ItemType Directory -Force $CollectorDir | Out-Null
                    Copy-Item $src $CollectorDir -Force
                    $url = Read-Host "  App URL [$ServerUrl]"; if (-not $url) { $url = $ServerUrl }
                    $secure = Read-Host '  Collector token (COLLECTOR_TOKEN on SEC01, input hidden)' -AsSecureString
                    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
                    $tokenFile = Join-Path $CollectorDir 'token.txt'
                    Set-Content -Path $tokenFile -Value $plain -NoNewline -Encoding ascii
                    $plain = $null
                    icacls $tokenFile /inheritance:r /grant 'Administrators:F' 'SYSTEM:F' | Out-Null
                    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ("-NoProfile -ExecutionPolicy Bypass -File `"{0}\Send-BitLockerStatus.ps1`" -ServerUrl {1}" -f $CollectorDir, $url)
                    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15)
                    Register-ScheduledTask -TaskName 'Capstone BitLocker Collector' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
                    Write-Host '  collector installed (token file readable by Administrators and SYSTEM only)' -ForegroundColor Green }
                '3' {
                    $task = Get-ScheduledTask -TaskName 'Capstone BitLocker Collector' -ErrorAction SilentlyContinue
                    if (-not $task) { throw 'Install the collector first (option 2).' }
                    Start-ScheduledTask -TaskName 'Capstone BitLocker Collector'; Start-Sleep 5
                    $info = Get-ScheduledTaskInfo -TaskName 'Capstone BitLocker Collector'
                    Write-Host ("  last run {0}, result {1} (0 = OK)" -f $info.LastRunTime, $info.LastTaskResult) -ForegroundColor Green }
                '4' {
                    $conf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
                    $ip = Read-Host '  New Wazuh manager address (lab: 10.20.0.20)'
                    if ($ip -notmatch '^10\.20\.0\.\d{1,3}$|^192\.168\.\d{1,3}\.\d{1,3}$') { throw 'Use the lab address 10.20.0.x (or the VMware NAT address during setup).' }
                    $text = Get-Content $conf -Raw
                    $text = [regex]::Replace($text, '<address>[^<]*</address>', "<address>$ip</address>")
                    Set-Content -Path $conf -Value $text -Encoding UTF8
                    Restart-Service WazuhSvc
                    Write-Host "  agent now reports to $ip" -ForegroundColor Green }
                '5' {
                    foreach ($n in 'User Account Management', 'Security Group Management', 'Logon', 'Audit Policy Change') { Set-AuditSetting $n $true $true }
                    Write-Host '  audit enabled for account, group, logon and audit-policy changes' -ForegroundColor Green }
                'B' { return }
                default { Write-Host '  unknown choice' -ForegroundColor Yellow }
            }
        } catch { Write-Host "  failed: $($_.Exception.Message)" -ForegroundColor Red }
        Read-Host '  Press Enter' | Out-Null
    }
}

# ---------------------------------------------------------------- main loop

if (-not (Test-Admin)) {
    Write-Host 'Run this as Administrator (or start LabBaselineMenu.cmd).' -ForegroundColor Red
    if (-not $StatusOnly) { exit 1 }
}

if ($StatusOnly) { Show-Status | Out-Null; return }

while ($true) {
    $states = Show-Status
    Write-Host '  Number = toggle that control        A = apply full baseline (all ON)   X = break all (demo, all OFF)'
    Write-Host '  D = demo actions (events, FIM)      U = setup                          S = scan now (restart agent)'
    Write-Host '  R = refresh                         Q = quit'
    $choice = (Read-Host '  Choose').Trim().ToUpper()
    if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $Controls.Count) {
        $idx = [int]$choice - 1
        Invoke-Control $idx (-not ($states[$idx].State -eq $true))
        Write-Host '  Tip: S = scan now, so the app sees the change.' -ForegroundColor DarkGray
        Read-Host '  Press Enter' | Out-Null
        continue
    }
    switch ($choice) {
        'A' { for ($i = 0; $i -lt $Controls.Count; $i++) { if ($states[$i].State -ne $true) { Invoke-Control $i $true } }
              Read-Host '  Press Enter' | Out-Null }
        'X' { if ((Read-Host '  Turn EVERY control off for the demo? Type YES') -eq 'YES') {
                  for ($i = 0; $i -lt $Controls.Count; $i++) {
                      if ($Controls[$i].Req -like 'REQ-BL*') { continue }   # BitLocker stays as is unless toggled on purpose
                      if ($states[$i].State -ne $false) { Invoke-Control $i $false } } }
              Read-Host '  Press Enter' | Out-Null }
        'D' { Show-DemoMenu }
        'U' { Show-SetupMenu }
        'S' { Invoke-ScanNow; Read-Host '  Press Enter' | Out-Null }
        'R' { }
        'Q' { return }
        default { }
    }
}
