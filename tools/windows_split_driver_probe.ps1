[CmdletBinding()]
param(
    [string]$DriverPath = 'C:\Program Files\WinsVPN\mullvad-split-tunnel.sys',
    [string]$OutputPath = 'C:\ProgramData\WinsVPN\split-driver-probe.json',
    [ValidatePattern('^[A-Za-z][A-Za-z0-9_-]{2,63}$')]
    [string]$ServiceName = 'WinsVPNSplitTunnelProbe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$isAdministrator = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdministrator) { throw 'Split-driver probe requires elevation.' }
if (-not (Test-Path -LiteralPath $DriverPath -PathType Leaf)) {
    throw "Split driver not found: $DriverPath"
}

& sc.exe stop $ServiceName 2>&1 | Out-Null
& sc.exe delete $ServiceName 2>&1 | Out-Null
Start-Sleep -Seconds 1

$createOutput = (& sc.exe create $ServiceName type= kernel start= demand `
    error= normal binPath= $DriverPath 2>&1 | Out-String).Trim()
$createExit = $LASTEXITCODE
$startOutput = ''
$startExit = -1
$configuration = $null
try {
    if ($createExit -eq 0) {
        $startOutput = (& sc.exe start $ServiceName 2>&1 | Out-String).Trim()
        $startExit = $LASTEXITCODE
        $configuration = Get-CimInstance Win32_SystemDriver `
            -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue |
            Select-Object Name, State, Status, StartMode, PathName, ExitCode,
                ServiceSpecificExitCode
    }

    $evidence = [ordered]@{
        schema_version = 1
        tested_at_utc = [DateTime]::UtcNow.ToString('o')
        secret_material_redacted = $true
        driver_sha256 = (Get-FileHash -LiteralPath $DriverPath -Algorithm SHA256).Hash.ToLowerInvariant()
        create_exit_code = $createExit
        start_exit_code = $startExit
        create_output = $createOutput
        start_output = $startOutput
        configuration = $configuration
    }
    [IO.Directory]::CreateDirectory((Split-Path -Parent $OutputPath)) | Out-Null
    [IO.File]::WriteAllText(
        $OutputPath,
        ($evidence | ConvertTo-Json -Depth 6),
        [Text.UTF8Encoding]::new($false)
    )
} finally {
    & sc.exe stop $ServiceName 2>&1 | Out-Null
    & sc.exe delete $ServiceName 2>&1 | Out-Null
}

if ($createExit -ne 0 -or $startExit -ne 0) { exit 1 }
