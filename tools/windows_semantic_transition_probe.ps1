[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputRoot,
    [string]$InvokeTool = (Join-Path $PSScriptRoot 'windows_invoke_vpn_power.ps1'),
    [string]$WatchdogScript = (Join-Path $PSScriptRoot 'windows_test_failsafe_watchdog.ps1'),
    [Parameter(Mandatory)][string]$WatchdogRoot,
    [bool]$DoubleVpnRequested = $false,
    [ValidateRange(90, 600)][int]$WatchdogDeadlineSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$samples = [Collections.Generic.List[object]]::new()

function Get-State {
    $manager = Get-Service -Name 'WinsVpnTunnelManager' `
        -ErrorAction SilentlyContinue
    $service = Get-Service -Name 'AmneziaWGTunnel$winsvpn' `
        -ErrorAction SilentlyContinue
    $split = Get-Service -Name 'WinsVPNSplitTunnel' `
        -ErrorAction SilentlyContinue
    $adapter = Get-NetAdapter -Name 'winsvpn' -IncludeHidden `
        -ErrorAction SilentlyContinue
    $xray = @(Get-Process xray -ErrorAction SilentlyContinue).Count
    $routes = @(Get-NetRoute -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -eq 'winsvpn' })
    $active = ($null -ne $service -and $service.Status -eq 'Running') -or
        ($null -ne $split -and $split.Status -eq 'Running') -or
        ($null -ne $adapter -and $adapter.Status -eq 'Up') -or
        $xray -gt 0 -or $routes.Count -gt 0
    [ordered]@{
        active = $active
        manager_running = (
            $null -ne $manager -and $manager.Status -eq 'Running'
        )
        tunnel_service_running = (
            $null -ne $service -and $service.Status -eq 'Running'
        )
        split_service_running = (
            $null -ne $split -and $split.Status -eq 'Running'
        )
        adapter_up = $null -ne $adapter -and $adapter.Status -eq 'Up'
        xray_process_count = $xray
        tunnel_route_count = $routes.Count
    }
}

$failurePath = Join-Path $env:APPDATA 'wins_vpn\last_tunnel_failure.json'
$failureBefore = if (Test-Path $failurePath) {
    (Get-Item $failurePath).LastWriteTimeUtc.ToString('o')
} else { '' }
$initial = Get-State
if ($initial.active) { throw 'Transition probe requires clean native state.' }
if (-not $initial.manager_running) {
    throw 'Transition probe requires the tunnel manager to be running.'
}

$nonce = [Guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Force -Path $WatchdogRoot | Out-Null
& icacls.exe $WatchdogRoot /inheritance:r `
    /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to make the watchdog directory owner-only.'
}
$armPath = Join-Path $WatchdogRoot 'arm.json'
$disarmPath = Join-Path $WatchdogRoot 'normal-teardown.json'
$watchdogOutput = Join-Path $WatchdogRoot 'watchdog-evidence.json'
[IO.File]::WriteAllText(
    $armPath,
    (ConvertTo-Json ([ordered]@{
        schema = 'winsvpn-windows-test-failsafe-arm-v1'
        armed = $true
        nonce = $nonce
        armed_at_utc = [DateTime]::UtcNow.ToString('o')
    })) + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false)
)
$watchdogTask = "WinsVPN Test Failsafe $nonce"
$watchdogArguments = @(
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', ('"' + $WatchdogScript + '"'),
    '-Root', ('"' + $WatchdogRoot + '"'),
    '-ArmPath', ('"' + $armPath + '"'),
    '-DisarmPath', ('"' + $disarmPath + '"'),
    '-OutputPath', ('"' + $watchdogOutput + '"'),
    '-Nonce', $nonce,
    '-DeadlineSeconds', [string]$WatchdogDeadlineSeconds
) -join ' '
$watchdogAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument $watchdogArguments
$watchdogPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
    -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $watchdogTask -Action $watchdogAction `
    -Principal $watchdogPrincipal -Force | Out-Null
Start-ScheduledTask -TaskName $watchdogTask
$watchdogStartDeadline = [DateTime]::UtcNow.AddSeconds(10)
do {
    Start-Sleep -Milliseconds 200
    $watchdogState = [string](Get-ScheduledTask -TaskName $watchdogTask).State
} while ($watchdogState -ne 'Running' -and
    [DateTime]::UtcNow -lt $watchdogStartDeadline)
if ($watchdogState -ne 'Running') {
    throw 'The independent fail-safe watchdog did not arm before connect.'
}

$connect = & $InvokeTool -Action Toggle -SettleSeconds 0 `
    -ResultPath (Join-Path $OutputRoot 'connect-invoke.txt')
$clock = [Diagnostics.Stopwatch]::StartNew()
$transition = $null
while ($clock.Elapsed.TotalSeconds -lt 20) {
    $state = Get-State
    $sample = [ordered]@{
        at_utc = [DateTime]::UtcNow.ToString('o')
        elapsed_seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 3)
        state = $state
    }
    [void]$samples.Add($sample)
    if ($state.active) {
        $transition = $sample
        break
    }
    Start-Sleep -Milliseconds 100
}
$clock.Stop()

$cancelAttempts = [Collections.Generic.List[object]]::new()
$cleanupClock = [Diagnostics.Stopwatch]::StartNew()
$final = Get-State
${cleanSince} = $null
while ($cleanupClock.Elapsed.TotalSeconds -lt 75) {
    if ($final.active) {
        ${cleanSince} = $null
        foreach ($cleanupAction in @('Cancel', 'Disconnect')) {
            try {
                $resultPath = Join-Path $OutputRoot (
                    "cleanup-$cleanupAction-$($cancelAttempts.Count).txt"
                )
                $invocation = & $InvokeTool -Action $cleanupAction `
                    -SettleSeconds 0 -ResultPath $resultPath
                [void]$cancelAttempts.Add([ordered]@{
                    at_utc = [DateTime]::UtcNow.ToString('o')
                    action = $cleanupAction
                    result = [string]$invocation
                    succeeded = $true
                })
            } catch {
                [void]$cancelAttempts.Add([ordered]@{
                    at_utc = [DateTime]::UtcNow.ToString('o')
                    action = $cleanupAction
                    result = $_.Exception.Message
                    succeeded = $false
                })
            }
            Start-Sleep -Milliseconds 300
            $final = Get-State
            if (-not $final.active) { break }
        }
    } elseif ($null -eq ${cleanSince}) {
        ${cleanSince} = [DateTime]::UtcNow
    } elseif (([DateTime]::UtcNow - ${cleanSince}).TotalSeconds -ge 8) {
        break
    }
    Start-Sleep -Milliseconds 250
    $final = Get-State
}
$cleanupClock.Stop()
$failureAfter = if (Test-Path $failurePath) {
    (Get-Item $failurePath).LastWriteTimeUtc.ToString('o')
} else { '' }

$normalTeardownProven = -not $final.active -and
    $null -ne ${cleanSince} -and
    ([DateTime]::UtcNow - ${cleanSince}).TotalSeconds -ge 8
if ($normalTeardownProven) {
    [IO.File]::WriteAllText(
        $disarmPath,
        (ConvertTo-Json ([ordered]@{
            schema = 'winsvpn-windows-test-failsafe-disarm-v1'
            nonce = $nonce
            normal_teardown_proven = $true
            proven_at_utc = [DateTime]::UtcNow.ToString('o')
            clean_state = [ordered]@{
                manager_running = (
                    (Get-Service WinsVpnTunnelManager -ErrorAction SilentlyContinue).Status `
                        -eq 'Running'
                )
                tunnel_service_running = [bool]$final.tunnel_service_running
                split_service_running = [bool]$final.split_service_running
                adapter_up = [bool]$final.adapter_up
                xray_process_count = [int]$final.xray_process_count
                tunnel_route_count = @(
                    Get-NetRoute -ErrorAction SilentlyContinue |
                        Where-Object { $_.InterfaceAlias -eq 'winsvpn' }
                ).Count
            }
        }) -Depth 6) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
}
$watchdogWaitDeadline = [DateTime]::UtcNow.AddSeconds(
    $WatchdogDeadlineSeconds + 60
)
do {
    Start-Sleep -Milliseconds 250
    $watchdogTaskState = [string](
        Get-ScheduledTask -TaskName $watchdogTask -ErrorAction SilentlyContinue
    ).State
} while ($watchdogTaskState -ne 'Ready' -and
    [DateTime]::UtcNow -lt $watchdogWaitDeadline)
$watchdogEvidence = if (Test-Path -LiteralPath $watchdogOutput) {
    Get-Content -LiteralPath $watchdogOutput -Raw | ConvertFrom-Json
} else { $null }
Unregister-ScheduledTask -TaskName $watchdogTask -Confirm:$false `
    -ErrorAction Stop
$final = Get-State
$cleanupInvocationSucceeded = @(
    $cancelAttempts | Where-Object {
        $_.succeeded -and $_.action -in @('Cancel', 'Disconnect')
    }
).Count -gt 0
$pass = $connect -match 'PASS label=Connect VPN role=43' -and
    $null -ne $transition -and
    $cleanupInvocationSucceeded -and
    $normalTeardownProven -and
    -not $final.active -and
    $null -ne $watchdogEvidence -and
    $watchdogEvidence.pass -eq $true -and
    $watchdogEvidence.normal_teardown_proven -eq $true -and
    $watchdogEvidence.fail_safe_triggered -eq $false
$document = [ordered]@{
    schema = 'winsvpn-windows-semantic-transition-v1'
    tested_at_utc = [DateTime]::UtcNow.ToString('o')
    double_vpn_requested = $DoubleVpnRequested
    connect_invocation = [string]$connect
    transition = $transition
    cleanup_invocations = $cancelAttempts
    normal_teardown_proven = $normalTeardownProven
    cleanup_seconds = [Math]::Round($cleanupClock.Elapsed.TotalSeconds, 3)
    watchdog_task_removed_after_run = $true
    watchdog_evidence_sha256 = if (Test-Path $watchdogOutput) {
        (Get-FileHash $watchdogOutput -Algorithm SHA256).Hash
    } else { '' }
    fail_safe_triggered = if ($null -ne $watchdogEvidence) {
        [bool]$watchdogEvidence.fail_safe_triggered
    } else { $null }
    final_state = $final
    failure_before_utc = $failureBefore
    failure_after_utc = $failureAfter
    samples = $samples
    pass = $pass
    publication_authorized = $false
}
$output = Join-Path $OutputRoot 'windows-semantic-transition.json'
[IO.File]::WriteAllText(
    $output,
    (ConvertTo-Json $document -Depth 8) + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false)
)
if (-not $pass) {
    throw "Semantic transition probe failed. See $output"
}
Write-Output "WINDOWS_SEMANTIC_TRANSITION=PASS evidence=$output"
