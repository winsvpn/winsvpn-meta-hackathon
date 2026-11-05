[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Apk,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedApkSha256,
    [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
    [string]$Adb = (Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'),
    [string]$RegressionScript = '',
    [string]$WirelessMonitorScript = '',
    [ValidatePattern('^$|^[0-9A-Fa-f]{64}$')][string]$ExpectedPublicEgressSha256 = '',
    [ValidateRange(2, 30)][int]$PollSeconds = 3
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Windows PowerShell 5.1 does not initialize PSScriptRoot early enough for a
# parameter-default expression when the script is launched through `-File` by
# Task Scheduler. Resolve sibling tools only after parameter binding.
if ([string]::IsNullOrWhiteSpace($RegressionScript)) {
    $RegressionScript = Join-Path $PSScriptRoot 'android_fresh_release_regression.ps1'
}
if ([string]::IsNullOrWhiteSpace($WirelessMonitorScript)) {
    $WirelessMonitorScript = Join-Path $PSScriptRoot 'android_wireless_live_monitor.sh'
}

foreach ($requiredFile in @($Apk, $Adb, $RegressionScript, $WirelessMonitorScript)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Required Android live-test file is missing: $requiredFile"
    }
}
$actualApkSha256 = (Get-FileHash -LiteralPath $Apk -Algorithm SHA256).Hash
if ($actualApkSha256 -cne $ExpectedApkSha256.ToUpperInvariant()) {
    throw "Staged Android APK hash mismatch: expected=$($ExpectedApkSha256.ToUpperInvariant()) actual=$actualApkSha256"
}

Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class WinsAndroidWaiterExecutionState {
    [DllImport("kernel32.dll")]
    public static extern uint SetThreadExecutionState(uint flags);
}
'@

function Get-AuthorizedAndroidSerials {
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $lines = & $Adb devices 2>$null
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    @(
        $lines | Select-Object -Skip 1 | ForEach-Object {
            if ($_ -match '^([^\s]+)\s+device(?:\s|$)') { $Matches[1] }
        }
    )
}

function Wait-ForSingleStableAuthorizedAndroid {
    while ($true) {
        $serials = @(Get-AuthorizedAndroidSerials)
        if ($serials.Count -eq 1) {
            $serial = $serials[0]
            & $Adb -s $serial shell echo winsvpn-ready 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Start-Sleep -Seconds 2
                $confirmed = @(Get-AuthorizedAndroidSerials)
                if ($confirmed.Count -eq 1 -and $confirmed[0] -ceq $serial) {
                    return $serial
                }
            }
        }
        $waitMessage = if ($serials.Count -eq 0) {
            'Waiting for one authorized USB or paired wireless Android device.'
        } else {
            'Multiple authorized Android devices are visible; refusing to select one.'
        }
        Write-Status -State 'waiting' -Message $waitMessage
        Start-Sleep -Seconds $PollSeconds
    }
}

function Write-Status {
    param(
        [Parameter(Mandatory = $true)][string]$State,
        [string]$Serial = '',
        [string]$Message = ''
    )
    [ordered]@{
        schemaVersion = 1
        timestampUtc = [DateTimeOffset]::UtcNow.ToString('o')
        state = $State
        apkSha256 = $actualApkSha256
        serial = $Serial
        message = $Message
    } | ConvertTo-Json | Set-Content -LiteralPath $statusFile -Encoding utf8
}

New-Item -ItemType Directory -Force -Path $EvidenceDirectory | Out-Null
$statusFile = Join-Path $EvidenceDirectory 'status.json'
$logFile = Join-Path $EvidenceDirectory 'android-exact-live.log'
[void][WinsAndroidWaiterExecutionState]::SetThreadExecutionState([uint32]2147483651)
$serial = ''

try {
    Write-Status -State 'waiting'
    $serial = Wait-ForSingleStableAuthorizedAndroid
    & $Adb -s $serial shell svc power stayon true | Out-Null
    & $Adb -s $serial shell settings put global stay_on_while_plugged_in 7 | Out-Null
    & $Adb -s $serial shell input keyevent 224 | Out-Null
    Write-Status -State 'testing' -Serial $serial

    $arguments = @{
        Apk = $Apk
        Adb = $Adb
        Serial = $serial
        LiveDoubleVpn = $true
        WirelessMonitorScript = $WirelessMonitorScript
        AcknowledgeThirdPartySecuritySheet = $true
    }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedPublicEgressSha256)) {
        $arguments.ExpectedPublicEgressSha256 = $ExpectedPublicEgressSha256
    }
    & $RegressionScript @arguments *>&1 | Tee-Object -FilePath $logFile
    Write-Status -State 'passed' -Serial $serial -Message 'Exact APK fresh-install and live Double VPN regression passed.'
} catch {
    ($_ | Out-String) | Tee-Object -FilePath $logFile -Append | Out-Null
    Write-Status -State 'failed' -Serial $serial -Message $_.Exception.Message
    throw
} finally {
    [void][WinsAndroidWaiterExecutionState]::SetThreadExecutionState([uint32]2147483648)
}
