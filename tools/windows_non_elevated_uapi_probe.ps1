[CmdletBinding()]
param(
    [ValidateRange(5, 90)][int]$DurationSeconds = 45,
    [ValidateRange(50, 1000)][int]$PollMilliseconds = 150,
    [string]$Output = '.artifacts\windows-non-elevated-uapi-probe.json',
    [ValidateRange(1, [int]::MaxValue)][int]$WindowProcessId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$outputPath = if ([IO.Path]::IsPathRooted($Output)) {
    [IO.Path]::GetFullPath($Output)
} else {
    [IO.Path]::GetFullPath((Join-Path $repo $Output))
}
if (Test-Path -LiteralPath $outputPath) {
    throw 'Refusing to overwrite an existing UAPI probe result.'
}

function Read-SanitizedAwgUapi {
    $result = [ordered]@{
        connected = $false
        terminated = $false
        errno_zero = $false
        handshake_unix = [uint64]0
        rx_bytes = [uint64]0
        tx_bytes = [uint64]0
        failure_type = ''
    }
    $pipe = $null
    try {
        $pipe = [IO.Pipes.NamedPipeClientStream]::new(
            '.',
            'ProtectedPrefix\Administrators\AmneziaWG\winsvpn',
            [IO.Pipes.PipeDirection]::InOut,
            [IO.Pipes.PipeOptions]::Asynchronous
        )
        $pipe.Connect(100)
        $result.connected = $true
        $request = [Text.Encoding]::ASCII.GetBytes("get=1`n`n")
        $pipe.Write($request, 0, $request.Length)
        $pipe.Flush()
        $buffer = [byte[]]::new(4096)
        $memory = [IO.MemoryStream]::new()
        try {
            $deadline = [DateTime]::UtcNow.AddMilliseconds(750)
            do {
                $read = $pipe.Read($buffer, 0, $buffer.Length)
                if ($read -gt 0) {
                    $memory.Write($buffer, 0, $read)
                    $text = [Text.Encoding]::ASCII.GetString($memory.ToArray())
                    if ($text.EndsWith("`n`n")) { break }
                }
            } while ($read -gt 0 -and [DateTime]::UtcNow -lt $deadline)
            $raw = [Text.Encoding]::ASCII.GetString($memory.ToArray())
        } finally {
            $memory.Dispose()
        }
        $result.terminated = $raw.EndsWith("`n`n")
        foreach ($line in ($raw -split "`n")) {
            if ($line -notmatch '^([^=]+)=([0-9]+)$') { continue }
            $key = $Matches[1]
            $value = [uint64]0
            if (-not [uint64]::TryParse($Matches[2], [ref]$value)) { continue }
            switch ($key) {
                'errno' { $result.errno_zero = $value -eq 0 }
                'last_handshake_time_sec' { $result.handshake_unix = $value }
                'rx_bytes' { $result.rx_bytes = $value }
                'tx_bytes' { $result.tx_bytes = $value }
            }
        }
    } catch {
        $failure = $_.Exception
        while ($failure.InnerException) { $failure = $failure.InnerException }
        $result.failure_type = $failure.GetType().FullName
    } finally {
        if ($pipe) { $pipe.Dispose() }
    }
    [pscustomobject]$result
}

$toggleResult = Join-Path ([IO.Path]::GetDirectoryName($outputPath)) (
    [IO.Path]::GetFileNameWithoutExtension($outputPath) + '-toggle.txt'
)
Remove-Item -LiteralPath $toggleResult -Force -ErrorAction SilentlyContinue
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (
    Join-Path $repo 'tools\windows_invoke_vpn_power.ps1'
) -Action Toggle -SettleSeconds 0 -ResultPath $toggleResult `
    -WindowProcessId $WindowProcessId | Out-Null

$started = [DateTime]::UtcNow
$deadline = $started.AddSeconds($DurationSeconds)
$serviceSamples = 0
$pipeAttempts = 0
$pipeConnections = 0
$adapterSamples = 0
$ipv4AddressSamples = 0
$defaultRouteSamples = 0
$onLinkDefaultRouteSamples = 0
$gatewayDefaultRouteSamples = 0
$maximumReceivedBytes = [uint64]0
$maximumSentBytes = [uint64]0
$directServiceSamples = 0
$xrayServiceSamples = 0
$maximumDirectReceivedBytes = [uint64]0
$maximumDirectSentBytes = [uint64]0
$maximumXrayReceivedBytes = [uint64]0
$maximumXraySentBytes = [uint64]0
$firstServiceUtc = ''
$lastServiceUtc = ''
$best = $null
$failureTypes = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal
)
while ([DateTime]::UtcNow -lt $deadline) {
    $service = Get-Service -Name 'AmneziaWGTunnel$winsvpn' `
        -ErrorAction SilentlyContinue
    if ($service) {
        $now = [DateTime]::UtcNow.ToString('o')
        $serviceSamples++
        if ([string]::IsNullOrEmpty($firstServiceUtc)) { $firstServiceUtc = $now }
        $lastServiceUtc = $now
        if ($service.Status -eq [ServiceProcess.ServiceControllerStatus]::Running) {
            $xrayPresent = @(Get-Process xray -ErrorAction SilentlyContinue).Count -gt 0
            if ($xrayPresent) { $xrayServiceSamples++ } else { $directServiceSamples++ }
            $adapters = @(Get-NetAdapter -Name winsvpn `
                -ErrorAction SilentlyContinue)
            if ($adapters.Count -eq 1) {
                $adapterSamples++
                $adapter = $adapters[0]
                $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex `
                    -AddressFamily IPv4 -ErrorAction SilentlyContinue)
                if ($addresses.Count -gt 0) { $ipv4AddressSamples++ }
                $defaults = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex `
                    -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
                    -ErrorAction SilentlyContinue)
                if ($defaults.Count -gt 0) {
                    $defaultRouteSamples++
                    if (@($defaults | Where-Object NextHop -eq '0.0.0.0').Count -gt 0) {
                        $onLinkDefaultRouteSamples++
                    }
                    if (@($defaults | Where-Object NextHop -ne '0.0.0.0').Count -gt 0) {
                        $gatewayDefaultRouteSamples++
                    }
                }
                $statistics = Get-NetAdapterStatistics `
                    -Name $adapter.Name -ErrorAction SilentlyContinue
                if ($statistics) {
                    $maximumReceivedBytes = [Math]::Max(
                        $maximumReceivedBytes, [uint64]$statistics.ReceivedBytes
                    )
                    $maximumSentBytes = [Math]::Max(
                        $maximumSentBytes, [uint64]$statistics.SentBytes
                    )
                    if ($xrayPresent) {
                        $maximumXrayReceivedBytes = [Math]::Max(
                            $maximumXrayReceivedBytes,
                            [uint64]$statistics.ReceivedBytes
                        )
                        $maximumXraySentBytes = [Math]::Max(
                            $maximumXraySentBytes,
                            [uint64]$statistics.SentBytes
                        )
                    } else {
                        $maximumDirectReceivedBytes = [Math]::Max(
                            $maximumDirectReceivedBytes,
                            [uint64]$statistics.ReceivedBytes
                        )
                        $maximumDirectSentBytes = [Math]::Max(
                            $maximumDirectSentBytes,
                            [uint64]$statistics.SentBytes
                        )
                    }
                }
            }
            $pipeAttempts++
            $sample = Read-SanitizedAwgUapi
            if ($sample.connected) {
                $pipeConnections++
                if ($null -eq $best -or
                    $sample.handshake_unix -gt $best.handshake_unix -or
                    $sample.rx_bytes -gt $best.rx_bytes -or
                    $sample.tx_bytes -gt $best.tx_bytes) {
                    $best = $sample
                }
            } elseif (-not [string]::IsNullOrEmpty($sample.failure_type)) {
                [void]$failureTypes.Add($sample.failure_type)
            }
        }
    }
    Start-Sleep -Milliseconds $PollMilliseconds
}

$cleanupAttempted = $false
$cleanupInvoked = $false
$preCleanupService = Get-Service -Name 'AmneziaWGTunnel$winsvpn' `
    -ErrorAction SilentlyContinue
$preCleanupXrayCount = @(Get-Process xray -ErrorAction SilentlyContinue).Count
if ($preCleanupService -or $preCleanupXrayCount -gt 0) {
    $cleanupAttempted = $true
    foreach ($action in @('Cancel', 'Disconnect')) {
        try {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (
                Join-Path $repo 'tools\windows_invoke_vpn_power.ps1'
            ) -Action $action -SettleSeconds 0 -WindowProcessId `
                $WindowProcessId | Out-Null
            $cleanupInvoked = $true
            break
        } catch {}
    }
    $cleanupDeadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 250
        $remainingService = Get-Service -Name 'AmneziaWGTunnel$winsvpn' `
            -ErrorAction SilentlyContinue
        $remainingXray = @(Get-Process xray -ErrorAction SilentlyContinue).Count
    } while (($remainingService -or $remainingXray -gt 0) -and
             [DateTime]::UtcNow -lt $cleanupDeadline)
}
$xrayCount = @(Get-Process xray -ErrorAction SilentlyContinue).Count
$tunnelService = Get-Service -Name 'AmneziaWGTunnel$winsvpn' `
    -ErrorAction SilentlyContinue
$bestHandshake = [uint64]0
$bestRx = [uint64]0
$bestTx = [uint64]0
if ($best) {
    $bestHandshake = [uint64]$best.handshake_unix
    $bestRx = [uint64]$best.rx_bytes
    $bestTx = [uint64]$best.tx_bytes
}
$result = [ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-non-elevated-uapi-probe-v1'
    captured_at_utc = [DateTime]::UtcNow.ToString('o')
    secret_material_redacted = $true
    publication_authorized = $false
    service_samples = $serviceSamples
    first_service_utc = $firstServiceUtc
    last_service_utc = $lastServiceUtc
    pipe_attempts = $pipeAttempts
    pipe_connections = $pipeConnections
    pipe_failure_types = @($failureTypes | Sort-Object)
    adapter_samples = $adapterSamples
    ipv4_address_samples = $ipv4AddressSamples
    default_route_samples = $defaultRouteSamples
    on_link_default_route_samples = $onLinkDefaultRouteSamples
    gateway_default_route_samples = $gatewayDefaultRouteSamples
    maximum_adapter_received_bytes = $maximumReceivedBytes
    maximum_adapter_sent_bytes = $maximumSentBytes
    direct_service_samples = $directServiceSamples
    xray_service_samples = $xrayServiceSamples
    maximum_direct_adapter_received_bytes = $maximumDirectReceivedBytes
    maximum_direct_adapter_sent_bytes = $maximumDirectSentBytes
    maximum_xray_adapter_received_bytes = $maximumXrayReceivedBytes
    maximum_xray_adapter_sent_bytes = $maximumXraySentBytes
    handshake_unix = $bestHandshake
    rx_bytes = $bestRx
    tx_bytes = $bestTx
    cleanup_attempted = $cleanupAttempted
    cleanup_invoked = $cleanupInvoked
    tunnel_service_remaining = $null -ne $tunnelService
    xray_process_count_after = $xrayCount
    teardown_clean = $null -eq $tunnelService -and $xrayCount -eq 0
}
[IO.File]::WriteAllText(
    $outputPath,
    ($result | ConvertTo-Json -Depth 6) + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false)
)
Write-Output "WINDOWS_NON_ELEVATED_UAPI_PROBE=$outputPath"
