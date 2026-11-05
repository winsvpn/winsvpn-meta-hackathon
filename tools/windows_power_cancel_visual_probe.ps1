[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$inputTool = Join-Path $PSScriptRoot 'windows_interactive_input.ps1'
$captureTool = Join-Path $PSScriptRoot 'windows_capture_vpn_window.ps1'
$output = [IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$samples = [Collections.Generic.List[object]]::new()

function Get-NativeState {
    $service = Get-Service -Name 'AmneziaWGTunnel$winsvpn' `
        -ErrorAction SilentlyContinue
    $split = Get-Service -Name 'WinsVPNSplitTunnel' `
        -ErrorAction SilentlyContinue
    $adapter = Get-NetAdapter -Name 'winsvpn' -ErrorAction SilentlyContinue
    return [ordered]@{
        tunnel_service_running = (
            $null -ne $service -and $service.Status -eq 'Running'
        )
        split_service_running = (
            $null -ne $split -and $split.Status -eq 'Running'
        )
        adapter_up = $null -ne $adapter -and $adapter.Status -eq 'Up'
        xray_process_count = @(Get-Process xray -ErrorAction SilentlyContinue).Count
    }
}

function Add-Sample([string]$Phase) {
    $samples.Add([ordered]@{
        at = [DateTime]::UtcNow.ToString('o')
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

Add-Sample 'initial'
& $inputTool -Action Click -XFraction 0.5 -YFraction 0.792 `
    -SettleSeconds 0 | Out-Null
$connectClicked = [DateTime]::UtcNow
$deadline = $connectClicked.AddSeconds(90)
do {
    Start-Sleep -Milliseconds 500
    Add-Sample 'wait_active'
    $state = Get-NativeState
} while (-not $state.tunnel_service_running -and (Get-Date) -lt $deadline)
if (-not $state.tunnel_service_running) {
    throw 'Exact center power invocation did not produce an active tunnel.'
}

& $captureTool -OutputPath (Join-Path $output 'before-cancel.png') |
    Out-Null
Start-Sleep -Seconds 7
& $inputTool -Action Click -XFraction 0.5 -YFraction 0.792 `
    -SettleSeconds 0 | Out-Null
$cancelClicked = [DateTime]::UtcNow
Start-Sleep -Milliseconds 750
& $captureTool -OutputPath (Join-Path $output 'after-cancel-750ms.png') |
    Out-Null

$observeDeadline = (Get-Date).AddSeconds(25)
do {
    Add-Sample 'after_cancel'
    Start-Sleep -Milliseconds 500
} while ((Get-Date) -lt $observeDeadline)

$failureAfter = if (Test-Path -LiteralPath $failurePath) {
    (Get-Item -LiteralPath $failurePath).LastWriteTimeUtc.ToString('o')
} else {
    ''
}
$result = [ordered]@{
    schema = 'winsvpn-windows-power-cancel-visual-probe-v1'
    connect_clicked_at = $connectClicked.ToUniversalTime().ToString('o')
    cancel_clicked_at = $cancelClicked.ToUniversalTime().ToString('o')
    last_tunnel_failure_before_utc = $failureBefore
    last_tunnel_failure_after_utc = $failureAfter
    samples = $samples
}
[IO.File]::WriteAllText(
    (Join-Path $output 'result.json'),
    (ConvertTo-Json $result -Depth 7) + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false)
)
