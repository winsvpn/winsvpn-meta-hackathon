[CmdletBinding()]
param(
    [string]$OutputPath = 'C:\ProgramData\WinsVPN\awg-handshake-probe.json',
    [ValidateRange(0, 240)][int]$WaitForTunnelSeconds = 180,
    [ValidateRange(0, 30)][int]$HandshakeSettleSeconds = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$isAdministrator = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdministrator) {
    throw 'The AWG handshake probe requires elevation.'
}

$awg = 'C:\Program Files\AmneziaWG\awg.exe'
if (-not (Test-Path -LiteralPath $awg -PathType Leaf)) {
    throw 'The installed AWG diagnostic executable is missing.'
}

$deadline = [DateTime]::UtcNow.AddSeconds($WaitForTunnelSeconds)
do {
    $tunnelService = Get-Service -Name 'AmneziaWGTunnel$winsvpn' `
        -ErrorAction SilentlyContinue
    if ($tunnelService -and $tunnelService.Status -eq 'Running') { break }
    Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt $deadline)
if (-not $tunnelService -or $tunnelService.Status -ne 'Running') {
    throw 'The AWG tunnel did not become observable during the bounded probe.'
}
if ($HandshakeSettleSeconds -gt 0) {
    Start-Sleep -Seconds $HandshakeSettleSeconds
}

$handshakeRaw = @(& $awg show winsvpn latest-handshakes 2>&1)
$handshakeExit = $LASTEXITCODE
$transferRaw = @(& $awg show winsvpn transfer 2>&1)
$transferExit = $LASTEXITCODE

$latestEpoch = 0L
if ($handshakeExit -eq 0 -and $handshakeRaw.Count -gt 0) {
    $parts = ([string]$handshakeRaw[0]) -split '\s+'
    if ($parts.Count -ge 2) {
        [void][long]::TryParse($parts[-1], [ref]$latestEpoch)
    }
}
$receivedBytes = 0L
$sentBytes = 0L
if ($transferExit -eq 0 -and $transferRaw.Count -gt 0) {
    $parts = ([string]$transferRaw[0]) -split '\s+'
    if ($parts.Count -ge 3) {
        [void][long]::TryParse($parts[-2], [ref]$receivedBytes)
        [void][long]::TryParse($parts[-1], [ref]$sentBytes)
    }
}

$parent = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Force -Path $parent | Out-Null
[ordered]@{
    schema_version = 1
    platform = 'windows'
    tested_at_utc = [DateTime]::UtcNow.ToString('o')
    secret_material_redacted = $true
    query_passed = $handshakeExit -eq 0 -and $transferExit -eq 0
    latest_handshake_present = $latestEpoch -gt 0
    latest_handshake_age_seconds = if ($latestEpoch -gt 0) {
        [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $latestEpoch
    } else { $null }
    received_bytes = $receivedBytes
    sent_bytes = $sentBytes
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutputPath -Encoding UTF8

if ($handshakeExit -ne 0 -or $transferExit -ne 0) {
    throw 'The elevated AWG runtime query failed.'
}
