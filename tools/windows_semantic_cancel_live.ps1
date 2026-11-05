[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputRoot,
    [ValidateRange(20, 90)][int]$ObserveSeconds = 45
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$invokeTool = Join-Path $PSScriptRoot 'windows_invoke_vpn_power.ps1'
$captureTool = Join-Path $PSScriptRoot 'windows_capture_vpn_window.ps1'
$output = [IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$samples = [Collections.Generic.List[object]]::new()

function Get-NativeState {
    $awg = Get-Service -Name 'AmneziaWGTunnel$winsvpn' `
        -ErrorAction SilentlyContinue
    $split = Get-Service -Name 'WinsVPNSplitTunnel' `
        -ErrorAction SilentlyContinue
    $adapter = Get-NetAdapter -Name 'winsvpn' -ErrorAction SilentlyContinue
    $xrayCount = @(Get-Process xray -ErrorAction SilentlyContinue).Count
    $active = ($null -ne $awg -and $awg.Status -eq 'Running') -or
        ($null -ne $split -and $split.Status -eq 'Running') -or
        ($null -ne $adapter -and $adapter.Status -eq 'Up') -or
        $xrayCount -gt 0
    return [ordered]@{
        active = $active
        tunnel_service_running = (
            $null -ne $awg -and $awg.Status -eq 'Running'
        )
        split_service_running = (
            $null -ne $split -and $split.Status -eq 'Running'
        )
        adapter_up = $null -ne $adapter -and $adapter.Status -eq 'Up'
        xray_process_count = $xrayCount
    }
}

function Add-Sample([string]$Phase, [double]$ElapsedSeconds) {
    $samples.Add([ordered]@{
        at_utc = [DateTime]::UtcNow.ToString('o')
        elapsed_seconds = [Math]::Round($ElapsedSeconds, 3)
        phase = $Phase
        state = Get-NativeState
    })
}

$failurePath = Join-Path $env:APPDATA 'wins_vpn\last_tunnel_failure.json'
$failureBefore = if (Test-Path -LiteralPath $failurePath) {
    (Get-Item -LiteralPath $failurePath).LastWriteTimeUtc.ToString('o')
} else {
    ''
}
$initial = Get-NativeState
if ($initial.active) {
    throw 'Semantic cancellation smoke requires a clean initial tunnel state.'
}

$connectResult = & $invokeTool -Action Toggle -SettleSeconds 0 `
    -ResultPath (Join-Path $output 'connect-invoke.txt')
$connectAt = [DateTime]::UtcNow
Start-Sleep -Milliseconds 350
& $captureTool -OutputPath (Join-Path $output 'cancel-control-visible.png') |
    Out-Null
$cancelResult = & $invokeTool -Action Cancel -SettleSeconds 0 `
    -ResultPath (Join-Path $output 'cancel-invoke.txt')
$cancelAt = [DateTime]::UtcNow
Start-Sleep -Milliseconds 350
& $captureTool -OutputPath (Join-Path $output 'after-cancel.png') |
    Out-Null

$clock = [Diagnostics.Stopwatch]::StartNew()
while ($clock.Elapsed.TotalSeconds -lt $ObserveSeconds) {
    Add-Sample -Phase 'after_semantic_cancel' `
        -ElapsedSeconds $clock.Elapsed.TotalSeconds
    Start-Sleep -Milliseconds 250
}
$clock.Stop()
Add-Sample -Phase 'final' -ElapsedSeconds $clock.Elapsed.TotalSeconds

$failureAfter = if (Test-Path -LiteralPath $failurePath) {
    (Get-Item -LiteralPath $failurePath).LastWriteTimeUtc.ToString('o')
} else {
    ''
}
$lateActive = @(
    $samples | Where-Object {
        $_.elapsed_seconds -ge 8 -and $_.state.active
    }
)
$finalState = $samples[$samples.Count - 1].state
$passed = $connectResult -match 'PASS label=Connect VPN role=43 default_action=' -and
    $cancelResult -match 'PASS label=Cancel VPN connection role=43 default_action=' -and
    $lateActive.Count -eq 0 -and
    -not $finalState.active -and
    $failureAfter -eq $failureBefore
$result = [ordered]@{
    schema = 'winsvpn-windows-semantic-cancel-live-v1'
    tested_at_utc = [DateTime]::UtcNow.ToString('o')
    connect_invocation = [string]$connectResult
    cancel_invocation = [string]$cancelResult
    connect_invoked_at_utc = $connectAt.ToUniversalTime().ToString('o')
    cancel_invoked_at_utc = $cancelAt.ToUniversalTime().ToString('o')
    last_tunnel_failure_before_utc = $failureBefore
    last_tunnel_failure_after_utc = $failureAfter
    late_activity_after_eight_seconds = $lateActive.Count
    final_state = $finalState
    samples = $samples
    pass = $passed
    publication_authorized = $false
}
$resultPath = Join-Path $output 'windows-semantic-cancel-live.json'
[IO.File]::WriteAllText(
    $resultPath,
    (ConvertTo-Json $result -Depth 7) + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false)
)
if (-not $passed) {
    throw "Semantic cancellation live gate failed. See $resultPath"
}
Write-Output "WINDOWS_SEMANTIC_CANCEL_LIVE=PASS evidence=$resultPath"
