<#
.SYNOPSIS
  Sends selected BitLocker status fields of this PC to the compliance app (lab only).

.DESCRIPTION
  Runs on the Windows 11 test laptop (WS01) as a scheduled task (GPO LAB-WS-Deploy),
  as SYSTEM, every 15 minutes. It reads Get-BitLockerVolume and sends ONLY:
    mount_point, volume_type, volume_status, protection_status,
    encryption_percentage, encryption_method, lock_status
  It never reads or sends recovery passwords, recovery keys or key protectors
  (the KeyProtector property is not selected, and the server rejects any such field).

  The shared token is read from a file only Administrators and SYSTEM can read.
  The server address must be inside the isolated lab network (10.20.0.0/24) and use
  HTTPS with the lab certificate trusted through Group Policy.

.EXAMPLE
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File Send-BitLockerStatus.ps1 `
      -ServerUrl https://10.20.0.20:8443 -TokenFile C:\ProgramData\CapstoneCollector\token.txt
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ServerUrl,
    [string]$TokenFile = 'C:\ProgramData\CapstoneCollector\token.txt',
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# Only the isolated lab network is allowed.
$uri = [Uri]$ServerUrl
$labAddress = [System.Net.IPAddress]::None
if ($uri.Scheme -ne 'https' -or -not [System.Net.IPAddress]::TryParse($uri.Host, [ref]$labAddress) -or
    -not $uri.Host.StartsWith('10.20.0.')) {
    throw "ServerUrl must be https://10.20.0.x:<port> (isolated lab network)."
}

$volumes = foreach ($v in Get-BitLockerVolume) {
    [ordered]@{
        mount_point           = [string]$v.MountPoint
        volume_type           = [string]$v.VolumeType
        volume_status         = [string]$v.VolumeStatus
        protection_status     = [string]$v.ProtectionStatus
        encryption_percentage = [double]$v.EncryptionPercentage
        encryption_method     = [string]$v.EncryptionMethod
        lock_status           = [string]$v.LockStatus
    }
}

$body = [ordered]@{
    hostname     = $env:COMPUTERNAME
    collected_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    volumes      = @($volumes)
} | ConvertTo-Json -Depth 4

if ($DryRun) {
    Write-Output $body
    return
}

$token = (Get-Content -LiteralPath $TokenFile -Raw).Trim()
if ($token.Length -lt 32) { throw "The token in $TokenFile is too short." }

$response = Invoke-RestMethod -Method Post -Uri "$($ServerUrl.TrimEnd('/'))/api/collector/bitlocker" `
    -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body $body -TimeoutSec 20
Write-Output "Stored $($response.stored) volume(s) for $($response.hostname)."
