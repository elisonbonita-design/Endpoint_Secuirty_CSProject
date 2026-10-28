<#
.SYNOPSIS
  DC01 menu: create, link, inspect or remove the lab Group Policy baseline (paper, Table 2).

.DESCRIPTION
  For the isolated capstone lab domain only (default cxlab.internal). Run on DC01 as a
  Domain Admin in Windows PowerShell 5.1 (GroupPolicy and ActiveDirectory modules).

  Account rules (paper, Table 2: Default Domain Policy): min length 14, history 24, complexity on,
  reversible off, lockout 5 / 15 min. Set them in the Default Domain Policy with the Group Policy
  editor (option 5 shows the steps). In lab testing (2026-10-26) a security template written by
  this script into a new GPO was ignored by Windows (gpresult showed the Default Domain Policy as the
  winning GPO and Get-GPOReport did not list the settings), while the editor change worked at once.

  GPOs, all linked to OU=LabWorkstations (WS01 is moved there):
    LAB-WS-SecurityBaseline Screen lock 900 s, NTLMv2 only, Defender real-time on
                           (Guest account: disabled by default; check it in the WS01 menu)
    LAB-WS-Firewall        all profiles on, inbound blocked by default, logging on
    LAB-WS-Audit           credential validation, logon, account/group management, process creation,
                           audit policy change (advanced audit policy)
    LAB-WS-BitLocker       XTS-AES 256 for the OS drive, TPM, recovery password kept in AD DS

  The advanced audit policy (not registry-based) is written to the GPO's SYSVOL folder, the same
  audit.csv the Group Policy editor writes, and the GPO version is raised so clients apply it
  (confirmed working on WS01).
#>
[CmdletBinding()]
param([string]$OuName = 'LabWorkstations', [string]$Computer = 'WS01')

$ErrorActionPreference = 'Stop'
$Host.UI.RawUI.WindowTitle = 'CX Lab - DC01 Group Policy baseline'
$LabDomain = 'cxlab.internal'

# ------------------------------------------------------------------------------ DC01 not a domain controller yet

function Show-PrepMenu {
    while ($true) {
        $role = (Get-CimInstance Win32_ComputerSystem).DomainRole        # 4/5 = domain controller
        $adds = (Get-WindowsFeature AD-Domain-Services).Installed
        $gpmc = (Get-WindowsFeature GPMC).Installed
        if ($role -ge 4 -and $gpmc) { return }
        Clear-Host
        Write-Host ('=' * 70) -ForegroundColor DarkCyan
        Write-Host '  CX LAB  |  DC01 is not a domain controller yet' -ForegroundColor Cyan
        Write-Host ('=' * 70) -ForegroundColor DarkCyan
        Write-Host ("  AD DS role installed: {0}   GPMC tools: {1}   Domain controller: {2}" -f $adds, $gpmc, ($role -ge 4))
        $dhcp = @(Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected | Where-Object { $_.Dhcp -eq 'Enabled' -and $_.InterfaceAlias -notlike 'Loopback*' })
        if ($dhcp) {
            Write-Host ''
            Write-Host "  Warning: $($dhcp.InterfaceAlias -join ', ') gets its IP from DHCP. A domain controller should have a" -ForegroundColor Yellow
            Write-Host '  fixed IP (paper: 10.20.0.10/24, DNS 127.0.0.1) before promotion. During the NAT setup phase it still' -ForegroundColor Yellow
            Write-Host '  works; after the lab network move, set the static IP and run: ipconfig /registerdns' -ForegroundColor Yellow
        }
        Write-Host ''
        Write-Host '   1  Install the AD DS role, DNS and the Group Policy / AD management tools (no reboot)'
        Write-Host "   2  Promote DC01 to a new forest '$LabDomain' (asks for the recovery-mode password, REBOOTS)"
        Write-Host '   Q  Quit'
        $choice = (Read-Host '  Choose').Trim().ToUpper()
        try {
            switch ($choice) {
                '1' {
                    Install-WindowsFeature AD-Domain-Services, DNS, GPMC, RSAT-AD-PowerShell -IncludeManagementTools | Format-Table -AutoSize
                    Write-Host '  done. Next: option 2.' -ForegroundColor Green }
                '2' {
                    if (-not (Get-WindowsFeature AD-Domain-Services).Installed) { throw 'Run option 1 first.' }
                    Write-Host '  The Directory Services Restore Mode password is for recovery only; keep it in your lab notes.' -ForegroundColor DarkGray
                    $dsrm = Read-Host '  DSRM password (input hidden)' -AsSecureString
                    Import-Module ADDSDeployment
                    Install-ADDSForest -DomainName $LabDomain -DomainNetbiosName 'CXLAB' -InstallDns `
                        -SafeModeAdministratorPassword $dsrm -Force -NoRebootOnCompletion:$false
                    return }
                'Q' { exit 0 }
            }
        } catch { Write-Host "  failed: $($_.Exception.Message)" -ForegroundColor Red }
        Read-Host '  Press Enter' | Out-Null
    }
}

Show-PrepMenu
Import-Module GroupPolicy, ActiveDirectory

$Domain = Get-ADDomain
$DnsRoot = $Domain.DNSRoot
$OuDn = "OU=$OuName,$($Domain.DistinguishedName)"
$Gpos = 'LAB-WS-SecurityBaseline', 'LAB-WS-Firewall', 'LAB-WS-Audit', 'LAB-WS-BitLocker'

# Client-side extension pairs ([CSE GUID][tool GUID]) that clients need to process the files below.
$CseAudit = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'

function Get-OrNewGpo([string]$Name, [string]$Comment) {
    $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if (-not $gpo) { $gpo = New-GPO -Name $Name -Comment $Comment; Write-Host "  created $Name" -ForegroundColor Green }
    else { Write-Host "  updating $Name" -ForegroundColor DarkGray }
    $linked = @((Get-GPInheritance -Target $OuDn).GpoLinks | ForEach-Object { $_.DisplayName })
    if ($linked -notcontains $Name) {
        New-GPLink -Guid $gpo.Id -Target $OuDn -LinkEnabled Yes | Out-Null
        Write-Host "  linked $Name to $OuDn" -ForegroundColor Green
    }
    return $gpo
}

function Get-GpoSysvol($Gpo) { "\\$DnsRoot\SYSVOL\$DnsRoot\Policies\{$($Gpo.Id)}" }

# Register client-side extensions and raise the computer version (AD + GPT.INI) after editing SYSVOL files.
function Update-GpoMachineVersion($Gpo, [string[]]$Cses) {
    $dn = "CN={$($Gpo.Id)},CN=Policies,CN=System,$($Domain.DistinguishedName)"
    $obj = Get-ADObject $dn -Properties gPCMachineExtensionNames, versionNumber
    $existing = @()
    if ($obj.gPCMachineExtensionNames) { $existing = @([regex]::Matches($obj.gPCMachineExtensionNames, '\[[^\]]+\]') | ForEach-Object { $_.Value }) }
    $all = @($existing + $Cses) | Sort-Object -Unique
    $version = [int]$obj.versionNumber + 1          # low 16 bits = computer version
    Set-ADObject $dn -Replace @{ gPCMachineExtensionNames = ($all -join ''); versionNumber = $version }
    $ini = Join-Path (Get-GpoSysvol $Gpo) 'GPT.INI'
    $lines = if (Test-Path $ini) { Get-Content $ini } else { @('[General]') }
    if ($lines -match '^Version=') { $lines = $lines -replace '^Version=\d+', "Version=$version" } else { $lines += "Version=$version" }
    Set-Content -Path $ini -Value $lines -Encoding ASCII
}

function Set-GpoAdvancedAudit($Gpo, [object[]]$Rows) {
    $dir = Join-Path (Get-GpoSysvol $Gpo) 'Machine\Microsoft\Windows NT\Audit'
    New-Item -ItemType Directory -Force $dir | Out-Null
    $csv = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
    foreach ($r in $Rows) {
        $text = switch ($r[2]) { 1 { 'Success' } 2 { 'Failure' } 3 { 'Success and Failure' } }
        $csv += ",System,$($r[0]),$($r[1]),$text,,$($r[2])"
    }
    Set-Content -Path (Join-Path $dir 'audit.csv') -Value $csv -Encoding UTF8
    Update-GpoMachineVersion $Gpo @($CseAudit)
}

function Set-Reg($Gpo, [string]$Key, [string]$Name, $Value, [string]$Type = 'DWord') {
    Set-GPRegistryValue -Guid $Gpo.Id -Key $Key -ValueName $Name -Type $Type -Value $Value | Out-Null
}

# ------------------------------------------------------------------------------ actions

function New-LabOu {
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$OuName'" -SearchBase $Domain.DistinguishedName -SearchScope OneLevel)) {
        New-ADOrganizationalUnit -Name $OuName -Path $Domain.DistinguishedName -ProtectedFromAccidentalDeletion $true
        Write-Host "  created $OuDn" -ForegroundColor Green
    }
    $pc = Get-ADComputer -Filter "Name -eq '$Computer'" -ErrorAction SilentlyContinue
    if ($pc -and $pc.DistinguishedName -notlike "*$OuDn") { Move-ADObject $pc.DistinguishedName -TargetPath $OuDn; Write-Host "  moved $Computer into $OuName" -ForegroundColor Green }
    elseif (-not $pc) { Write-Host "  $Computer is not joined to the domain yet; join it, then run this again." -ForegroundColor Yellow }
}

function Set-LabBaseline {
    New-LabOu

    $g = Get-OrNewGpo 'LAB-WS-SecurityBaseline' 'Capstone lab: general security options'
    Set-Reg $g 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs' 900
    Set-Reg $g 'HKLM\System\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5            # NTLMv2 only
    Set-Reg $g 'HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring' 0
    Set-Reg $g 'HKLM\System\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1     # use advanced audit policy

    $g = Get-OrNewGpo 'LAB-WS-Firewall' 'Capstone lab: Windows Defender Firewall on for all profiles'
    foreach ($p in 'DomainProfile', 'PrivateProfile', 'PublicProfile') {
        $k = "HKLM\Software\Policies\Microsoft\WindowsFirewall\$p"
        Set-Reg $g $k 'EnableFirewall' 1
        Set-Reg $g $k 'DefaultInboundAction' 1
        Set-Reg $g $k 'DefaultOutboundAction' 0
        Set-Reg $g "$k\Logging" 'LogDroppedPackets' 1
        Set-Reg $g "$k\Logging" 'LogSuccessfulConnections' 1
        Set-Reg $g "$k\Logging" 'LogFileSize' 16384
    }

    $g = Get-OrNewGpo 'LAB-WS-Audit' 'Capstone lab: advanced audit policy for the monitored events'
    Set-GpoAdvancedAudit $g @(
        @('Audit Credential Validation', '{0cce923f-69ae-11d9-bed3-505054503030}', 3),
        @('Audit Logon', '{0cce9215-69ae-11d9-bed3-505054503030}', 3),
        @('Audit User Account Management', '{0cce9235-69ae-11d9-bed3-505054503030}', 3),
        @('Audit Security Group Management', '{0cce9237-69ae-11d9-bed3-505054503030}', 1),
        @('Audit Process Creation', '{0cce922b-69ae-11d9-bed3-505054503030}', 1),
        @('Audit Audit Policy Change', '{0cce922f-69ae-11d9-bed3-505054503030}', 1))

    $g = Get-OrNewGpo 'LAB-WS-BitLocker' 'Capstone lab: BitLocker for the OS drive, recovery password kept in AD DS'
    $fve = 'HKLM\Software\Policies\Microsoft\FVE'
    Set-Reg $g $fve 'EncryptionMethodWithXtsOs' 7            # XTS-AES 256
    Set-Reg $g $fve 'UseAdvancedStartup' 1                   # require additional authentication at startup...
    Set-Reg $g $fve 'EnableBDEWithNoTPM' 0                   # ...and do not allow BitLocker without a TPM
    Set-Reg $g $fve 'UseTPM' 1
    Set-Reg $g $fve 'OSRecovery' 1                           # choose how OS drives can be recovered
    Set-Reg $g $fve 'OSManageDRA' 0
    Set-Reg $g $fve 'OSRecoveryPassword' 2                   # require 48-digit recovery password
    Set-Reg $g $fve 'OSRecoveryKey' 0                        # do not allow 256-bit recovery key
    Set-Reg $g $fve 'OSHideRecoveryPage' 1
    Set-Reg $g $fve 'OSActiveDirectoryBackup' 1
    Set-Reg $g $fve 'OSActiveDirectoryInfoToStore' 1
    Set-Reg $g $fve 'OSRequireActiveDirectoryBackup' 1      # encrypt only after the key is in AD DS

    Write-Host ''
    Write-Host "  Done. On $Computer run:  gpupdate /force   then check with:  gpresult /r /scope computer" -ForegroundColor Cyan
    Write-Host '  Still manual (paper LAB-WS-Deploy): trust the lab CA certificate in a GPO (Group Policy editor >' -ForegroundColor DarkGray
    Write-Host '  Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies >' -ForegroundColor DarkGray
    Write-Host '  Trusted Root Certification Authorities > Import lab-ca.crt). The collector task is installed by' -ForegroundColor DarkGray
    Write-Host '  the WS01 menu (U > 2).' -ForegroundColor DarkGray
}

function Show-LabStatus {
    Write-Host ''
    Write-Host ('  {0,-26} {1,-8} {2,-10} {3}' -f 'GPO', 'Linked', 'Computer v', 'Modified')
    $links = (Get-GPInheritance -Target $OuDn -ErrorAction SilentlyContinue).GpoLinks
    foreach ($n in $Gpos) {
        $g = Get-GPO -Name $n -ErrorAction SilentlyContinue
        if (-not $g) { Write-Host ('  {0,-26} {1}' -f $n, 'missing') -ForegroundColor Red; continue }
        $linked = [bool]($links | Where-Object { $_.DisplayName -eq $n -and $_.Enabled })
        Write-Host ('  {0,-26} {1,-8} {2,-10} {3}' -f $n, $linked, $g.Computer.DSVersion, $g.ModificationTime) -ForegroundColor $(if ($linked) { 'Green' } else { 'Yellow' })
    }
    $pc = Get-ADComputer -Filter "Name -eq '$Computer'" -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Host ("  {0}: {1}" -f $Computer, $(if ($pc) { $pc.DistinguishedName } else { 'not in the domain yet' }))
}

function Show-AccountPolicy {
    # Read the Default Domain Policy as the Group Policy tools see it (same view WS01 gets).
    [xml]$report = Get-GPOReport -Name 'Default Domain Policy' -ReportType Xml
    $want = [ordered]@{ MinimumPasswordLength = 14; PasswordHistorySize = 24; LockoutBadCount = 5 }
    Write-Host ''
    Write-Host '  Default Domain Policy, Account Policies (paper, Table 2):'
    $accounts = @($report.GetElementsByTagName('q1:Account')) + @($report.GetElementsByTagName('Account'))
    foreach ($name in $want.Keys) {
        $node = $accounts | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        $value = if ($node) { [int]$node.SettingNumber } else { $null }
        $ok = $null -ne $value -and $value -ge $want[$name]
        Write-Host ('    {0,-24} {1,-6} (want {2})' -f $name, $(if ($null -eq $value) { 'not set' } else { $value }), $want[$name]) `
            -ForegroundColor $(if ($ok) { 'Green' } else { 'Yellow' })
    }
    Write-Host ''
    Write-Host '  To change them: gpmc.msc > cxlab.internal > Default Domain Policy > Edit > Computer Configuration >' -ForegroundColor DarkGray
    Write-Host '  Policies > Windows Settings > Security Settings > Account Policies. Password Policy: minimum length 14,' -ForegroundColor DarkGray
    Write-Host '  history 24, complexity Enabled, reversible encryption Disabled. Account Lockout Policy: threshold 5' -ForegroundColor DarkGray
    Write-Host '  (accept the suggested 15-minute values). Then on WS01: gpupdate /force' -ForegroundColor DarkGray
}

function Remove-LabBaseline {
    if ((Read-Host '  Remove all LAB-WS-* GPOs? Type YES') -ne 'YES') { return }
    foreach ($n in $Gpos + 'LAB-WS-AccountPolicy') {   # LAB-WS-AccountPolicy: left over from the first script version
        if (Get-GPO -Name $n -ErrorAction SilentlyContinue) { Remove-GPO -Name $n; Write-Host "  removed $n" -ForegroundColor Green }
    }
}

while ($true) {
    Clear-Host
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
    Write-Host "  CX LAB  |  DC01 Group Policy baseline  |  domain $DnsRoot" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
    Write-Host '   1  Create / update all LAB-WS-* GPOs and link them (also creates the OU, moves WS01)'
    Write-Host '   2  Show GPO status'
    Write-Host '   3  Create the OU and move WS01 only'
    Write-Host '   4  Remove all LAB-WS-* GPOs'
    Write-Host '   5  Check the password/lockout rules in the Default Domain Policy (and how to set them)'
    Write-Host '   Q  Quit'
    $choice = (Read-Host '  Choose').Trim().ToUpper()
    try {
        switch ($choice) {
            '1' { Set-LabBaseline }
            '2' { Show-LabStatus }
            '3' { New-LabOu }
            '4' { Remove-LabBaseline }
            '5' { Show-AccountPolicy }
            'Q' { return }
        }
    } catch { Write-Host "  failed: $($_.Exception.Message)" -ForegroundColor Red }
    Read-Host '  Press Enter' | Out-Null
}
