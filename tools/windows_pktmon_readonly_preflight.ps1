[CmdletBinding()]
param([Parameter(Mandatory)][string]$Output)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows_transport_diagnostic_helpers.ps1')

if (-not (Test-WinsAdministrator)) {
    throw 'The read-only PktMon preflight requires elevation.'
}
$outputPath = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $outputPath) {
    throw 'The read-only PktMon preflight output already exists.'
}

function Get-SafeShape {
    param([AllowEmptyString()][string]$Value)
    $lines = @($Value -split '\r?\n' | ForEach-Object { $_.Trim() } |
        Where-Object { $_ })
    if ($Value -match
        '(?i)(?:\b\d{1,3}(?:\.\d{1,3}){3}\b|' +
        '\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b|' +
        '\b(?:port|ip|address)\s*[:=]\s*\d)') {
        return @('[redacted_nonempty_filter_or_endpoint_state]')
    }
    @($lines | ForEach-Object {
        $_ -replace '(?i)[A-Z]:\\[^\s]+', '[path]' `
           -replace '\b\d+\b', '#'
    })
}

$status = Invoke-WinsPktMon @('status')
$filters = Invoke-WinsPktMon @('filter', 'list')
$logman = Join-Path $env:SystemRoot 'System32\logman.exe'
$logmanProcess = [Diagnostics.ProcessStartInfo]::new()
$logmanProcess.FileName = $logman
$logmanProcess.Arguments = 'query PktMon -ets'
$logmanProcess.UseShellExecute = $false
$logmanProcess.CreateNoWindow = $true
$logmanProcess.RedirectStandardOutput = $true
$logmanProcess.RedirectStandardError = $true
$query = [Diagnostics.Process]::new()
$query.StartInfo = $logmanProcess
[void]$query.Start()
$query.StandardOutput.ReadToEnd() | Out-Null
$query.StandardError.ReadToEnd() | Out-Null
$query.WaitForExit()

$result = [ordered]@{
    contract = 'winsvpn-windows-pktmon-readonly-preflight-v1'
    mutation_performed = $false
    logman_pktmon_session_present = $query.ExitCode -eq 0
    pktmon_status_exit_code = $status.exit_code
    pktmon_status_safe_shape = Get-SafeShape $status.stdout
    pktmon_filter_exit_code = $filters.exit_code
    pktmon_filter_safe_shape = Get-SafeShape $filters.stdout
}
[IO.File]::WriteAllText(
    $outputPath,
    ($result | ConvertTo-Json -Depth 6) + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false)
)
