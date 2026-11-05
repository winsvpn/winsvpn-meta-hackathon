[CmdletBinding()]
param(
    [string]$Installer = 'build\windows-installer\WinsVPN-Setup.exe',
    [string]$OutputRoot = '.artifacts\windows-startup-smoke',
    [int]$WarmupSeconds = 15,
    [switch]$AllowUnsignedLocalCandidate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$InstallerPath = if ([IO.Path]::IsPathRooted($Installer)) {
    (Resolve-Path -LiteralPath $Installer).Path
} else {
    (Resolve-Path -LiteralPath (Join-Path $RepoRoot $Installer)).Path
}
$OutputPath = if ([IO.Path]::IsPathRooted($OutputRoot)) {
    $OutputRoot
} else {
    Join-Path $RepoRoot $OutputRoot
}
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

$versionText = Get-Content -LiteralPath (Join-Path $RepoRoot 'pubspec.yaml') -Raw
if ($versionText -notmatch '(?m)^version:\s*([^+\s]+)\+(\d+)\s*$') {
    throw 'pubspec.yaml must contain version: <semver>+<build>.'
}
$ExpectedVersion = $Matches[1]
$ExpectedBuild = $Matches[2]
$BuiltRunnerRoot = Join-Path $RepoRoot 'build\windows\x64\runner\Release'
$BuiltAppPath = Join-Path $BuiltRunnerRoot 'wins_vpn.exe'
$BuiltTunnelServicePath = Join-Path $BuiltRunnerRoot 'wins_vpn_tunnel_service.exe'
$BuiltAwgEnginePath = Join-Path $BuiltRunnerRoot 'winsvpn_awg_engine.exe'
$StagedRuntimeRoot = Join-Path $RepoRoot 'build\windows-installer\payload-stage'
$StagedAwgToolPath = Join-Path $StagedRuntimeRoot 'awg.exe'
$StagedWintunPath = Join-Path $StagedRuntimeRoot 'wintun.dll'
foreach ($requiredPayload in @(
        $BuiltAppPath, $BuiltTunnelServicePath, $BuiltAwgEnginePath,
        $StagedAwgToolPath, $StagedWintunPath)) {
    if (-not (Test-Path -LiteralPath $requiredPayload -PathType Leaf)) {
        throw "Exact Windows build payload is missing: $requiredPayload"
    }
}
$InstallerHash = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash.ToLowerInvariant()
$InstallerSignature = Get-AuthenticodeSignature -LiteralPath $InstallerPath
if ($InstallerSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -and -not $AllowUnsignedLocalCandidate) {
    throw "Installer Authenticode status is $($InstallerSignature.Status). Public-candidate startup smoke requires a valid signature."
}

$isAdministrator = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdministrator) {
    throw 'Windows clean-install startup smoke requires an elevated administrator session.'
}

function Get-WinsVpnUninstallEntry {
    return Get-ItemProperty `
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', `
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', `
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' `
        -ErrorAction SilentlyContinue |
        Where-Object {
            $displayName = $_.PSObject.Properties['DisplayName']
            $displayName -and [string]$displayName.Value -match "^Win.?s VPN(?:\s|$)"
        } |
        Select-Object -First 1
}

function Get-EntryPropertyString {
    param(
        [Parameter(Mandatory)][object]$Entry,
        [Parameter(Mandatory)][string]$Name
    )
    $property = $Entry.PSObject.Properties[$Name]
    if (-not $property -or $null -eq $property.Value) {
        return ''
    }
    return [string]$property.Value
}

function Get-UninstallerPath {
    param([Parameter(Mandatory)][object]$Entry)
    $quietCommand = Get-EntryPropertyString -Entry $Entry -Name 'QuietUninstallString'
    $command = if (-not [string]::IsNullOrWhiteSpace($quietCommand)) {
        $quietCommand
    } else {
        Get-EntryPropertyString -Entry $Entry -Name 'UninstallString'
    }
    if ([string]::IsNullOrWhiteSpace($command)) {
        throw "Registered Win's VPN entry does not provide an uninstall command."
    }
    if ($command -match '^"([^"]+)"') {
        return $Matches[1]
    }
    return ($command -split '\s+', 2)[0]
}

function Test-UnauthorizedPipeClientRejection {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new(
        '.',
        'WinsVPN.TunnelManager.v1',
        [IO.Pipes.PipeDirection]::InOut,
        [IO.Pipes.PipeOptions]::None,
        [Security.Principal.TokenImpersonationLevel]::Identification
    )
    try {
        $pipe.Connect(5000)
        $pipe.ReadMode = [IO.Pipes.PipeTransmissionMode]::Message
        # Keep this fixture byte-for-byte aligned with RequestHeader in
        # windows_tunnel_service_protocol.h. Protocol v4 keeps the 24-byte
        # header (generation after carrier_pid) and adds start/stop success
        # verbs. This smoke runs elevated, so kStatus would succeed as the
        # release-canary role; send kStart to prove mutation still requires
        # the installed app identity.
        $request = [byte[]]::new(24)
        [Buffer]::BlockCopy([BitConverter]::GetBytes([uint32]0x31505657), 0, $request, 0, 4)
        [Buffer]::BlockCopy([BitConverter]::GetBytes([uint16]4), 0, $request, 4, 2)
        [Buffer]::BlockCopy([BitConverter]::GetBytes([uint16]1), 0, $request, 6, 2)
        [Buffer]::BlockCopy([BitConverter]::GetBytes([uint32]0), 0, $request, 8, 4)
        [Buffer]::BlockCopy([BitConverter]::GetBytes([uint32]0), 0, $request, 12, 4)
        [Buffer]::BlockCopy([BitConverter]::GetBytes([uint64]0), 0, $request, 16, 8)
        $pipe.Write($request, 0, $request.Length)
        $pipe.Flush()

        $response = [byte[]]::new(12 + 8192)
        $responseSize = 0
        do {
            if ($responseSize -ge $response.Length) {
                throw 'Tunnel manager authenticated-protocol response exceeded its hard limit.'
            }
            $read = $pipe.Read(
                $response,
                $responseSize,
                $response.Length - $responseSize
            )
            if ($read -le 0) {
                throw 'Tunnel manager closed the pipe before completing its authenticated-protocol response.'
            }
            $responseSize += $read
        } until ($pipe.IsMessageComplete)
        if ($responseSize -lt 12) {
            throw 'Tunnel manager returned an incomplete authenticated-protocol response.'
        }
        $magic = [BitConverter]::ToUInt32($response, 0)
        $version = [BitConverter]::ToUInt16($response, 4)
        $status = [BitConverter]::ToUInt16($response, 6)
        $payloadSize = [BitConverter]::ToUInt32($response, 8)
        if ($magic -ne 0x31505657 -or $version -ne 4 -or $status -ne 1 -or
            $payloadSize -gt 8192 -or $responseSize -ne 12 + $payloadSize) {
            throw 'Tunnel manager did not return the expected authenticated-protocol rejection.'
        }
        $message = if ($payloadSize -gt 0) {
            [Text.Encoding]::UTF8.GetString($response, 12, [int]$payloadSize)
        } else {
            ''
        }
        if ($message -cne 'Tunnel request failed client identity verification.') {
            throw "Tunnel manager returned an unexpected rejection message: $message"
        }
        return $true
    } finally {
        $pipe.Dispose()
    }
}

Get-Process -Name wins_vpn -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
$existing = Get-WinsVpnUninstallEntry
if ($existing) {
    $uninstaller = Get-UninstallerPath -Entry $existing
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
        throw "Registered Win's VPN uninstaller is missing: $uninstaller"
    }
    $uninstall = Start-Process -FilePath $uninstaller -ArgumentList @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART',
        '/RESTARTEXITCODE=3010', '/SP-'
    ) -Wait -PassThru
    if ($uninstall.ExitCode -ne 0) {
        throw "Existing Win's VPN uninstall failed with exit code $($uninstall.ExitCode)."
    }
}
if (Get-WinsVpnUninstallEntry) {
    throw "Existing Win's VPN registration remains after uninstall."
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$installLog = Join-Path $OutputPath "install-$stamp.log"
$eventStart = Get-Date
$install = Start-Process -FilePath $InstallerPath -ArgumentList @(
    '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART',
    '/RESTARTEXITCODE=3010', '/SP-', "/LOG=$installLog"
) -Wait -PassThru
if ($install.ExitCode -eq 3010) {
    throw "Win's VPN installed successfully but requires a reboot before startup validation. Exit code 3010. See $installLog"
}
if ($install.ExitCode -ne 0) {
    throw "Win's VPN installer failed with exit code $($install.ExitCode). See $installLog"
}
$installLogText = Get-Content -LiteralPath $installLog -Raw
if ($installLogText -match '(?mi)CurStepChanged raised an exception|Runtime error \(at') {
    throw "Win's VPN installer reported a suppressed internal failure despite exit code 0. See $installLog"
}

$installed = Get-WinsVpnUninstallEntry
if (-not $installed -or (Get-EntryPropertyString -Entry $installed -Name 'DisplayVersion') -cne $ExpectedVersion) {
    throw "Installed registry version does not match $ExpectedVersion."
}
$installLocation = Get-EntryPropertyString -Entry $installed -Name 'InstallLocation'
if ([string]::IsNullOrWhiteSpace($installLocation)) {
    $installLocation = Join-Path $env:ProgramFiles 'WinsVPN'
}
$appPath = Join-Path $installLocation 'wins_vpn.exe'
if (-not (Test-Path -LiteralPath $appPath -PathType Leaf)) {
    throw "Installed executable is missing: $appPath"
}
$tunnelServicePath = Join-Path $installLocation 'wins_vpn_tunnel_service.exe'
if (-not (Test-Path -LiteralPath $tunnelServicePath -PathType Leaf)) {
    throw "Installed tunnel-manager executable is missing: $tunnelServicePath"
}
$awgEnginePath = Join-Path $installLocation 'winsvpn_awg_engine.exe'
$awgToolPath = Join-Path $installLocation 'awg.exe'
$wintunPath = Join-Path $installLocation 'wintun.dll'
foreach ($requiredRuntime in @($awgEnginePath, $awgToolPath, $wintunPath)) {
    if (-not (Test-Path -LiteralPath $requiredRuntime -PathType Leaf)) {
        throw "Installed pinned AWG runtime is missing: $requiredRuntime"
    }
}
$installedAppHash = (Get-FileHash -LiteralPath $appPath -Algorithm SHA256).Hash.ToLowerInvariant()
$installedTunnelServiceHash = (Get-FileHash -LiteralPath $tunnelServicePath -Algorithm SHA256).Hash.ToLowerInvariant()
$installedAwgEngineHash = (Get-FileHash -LiteralPath $awgEnginePath -Algorithm SHA256).Hash.ToLowerInvariant()
$installedAwgToolHash = (Get-FileHash -LiteralPath $awgToolPath -Algorithm SHA256).Hash.ToLowerInvariant()
$installedWintunHash = (Get-FileHash -LiteralPath $wintunPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($installedAppHash -cne (Get-FileHash -LiteralPath $BuiltAppPath -Algorithm SHA256).Hash.ToLowerInvariant()) {
    throw 'Installed GUI executable does not match the exact current Windows build payload.'
}
if ($installedTunnelServiceHash -cne (Get-FileHash -LiteralPath $BuiltTunnelServicePath -Algorithm SHA256).Hash.ToLowerInvariant()) {
    throw 'Installed tunnel-manager executable does not match the exact current Windows build payload.'
}
if ($installedAwgEngineHash -cne (Get-FileHash -LiteralPath $BuiltAwgEnginePath -Algorithm SHA256).Hash.ToLowerInvariant() -or
    $installedAwgToolHash -cne (Get-FileHash -LiteralPath $StagedAwgToolPath -Algorithm SHA256).Hash.ToLowerInvariant() -or
    $installedWintunHash -cne (Get-FileHash -LiteralPath $StagedWintunPath -Algorithm SHA256).Hash.ToLowerInvariant()) {
    throw 'Installed AWG engine runtime does not match the exact reviewed build payload.'
}
$awgEngineGuard = Start-Process -FilePath $awgEnginePath -Wait -PassThru `
    -WindowStyle Hidden
if ($awgEngineGuard.ExitCode -ne 2 -or
    (Get-Process winsvpn_awg_engine -ErrorAction SilentlyContinue)) {
    throw 'The installed AWG engine did not reject a non-LocalSystem launch.'
}

$service = Get-CimInstance Win32_Service -Filter "Name='WinsVpnTunnelManager'"
if (-not $service) {
    throw 'Protected tunnel-manager service is missing after installation.'
}
if ($service.State -cne 'Running' -or $service.StartMode -cne 'Auto' -or
    $service.StartName -cne 'LocalSystem') {
    throw "Protected tunnel-manager service is missing or misconfigured: state=$($service.State) start=$($service.StartMode) account=$($service.StartName)"
}
if ([string]$service.PathName -notmatch '^"(?<binary>[^"]+)"\s+--service$' -or
    -not [StringComparer]::OrdinalIgnoreCase.Equals(
        [IO.Path]::GetFullPath($Matches.binary),
        [IO.Path]::GetFullPath($tunnelServicePath)
    )) {
    throw "Protected tunnel-manager ImagePath is not pinned to the installed service binary: $($service.PathName)"
}
$serviceRegistry = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\WinsVpnTunnelManager'
$delayedAutoStart = $serviceRegistry.PSObject.Properties['DelayedAutoStart']
if ([int]$serviceRegistry.Start -ne 2 -or [int]$serviceRegistry.ErrorControl -ne 2 -or
    ($delayedAutoStart -and [int]$delayedAutoStart.Value -ne 0) -or
    [int]$serviceRegistry.ServiceSidType -ne 1 -or
    $null -eq $serviceRegistry.FailureActions -or $serviceRegistry.FailureActions.Length -eq 0) {
    throw 'Protected tunnel-manager service hardening registry contract is incomplete.'
}
$protocolSelfTest = Start-Process -FilePath $tunnelServicePath -ArgumentList '--protocol-self-test' -Wait -PassThru -WindowStyle Hidden
if ($protocolSelfTest.ExitCode -ne 0) {
    throw "Tunnel-manager protocol/config validation self-test failed with exit code $($protocolSelfTest.ExitCode)."
}
$unauthorizedPipeClientRejected = Test-UnauthorizedPipeClientRejection

$app = Start-Process -FilePath $appPath -PassThru
Start-Sleep -Seconds $WarmupSeconds
$running = Get-Process -Id $app.Id -ErrorAction SilentlyContinue
if (-not $running) {
    throw "Win's VPN exited during the startup smoke."
}
$applicationErrors = @(Get-WinEvent -FilterHashtable @{
    LogName = 'Application'
    StartTime = $eventStart
    Id = 1000
} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'wins_vpn\.exe' })
if ($applicationErrors.Count -gt 0) {
    throw 'Windows recorded an Application Error event for wins_vpn.exe.'
}

$evidencePath = Join-Path $OutputPath "startup-evidence-$stamp.json"
[ordered]@{
    schema_version = 1
    platform = 'windows'
    app_version = $ExpectedVersion
    build_number = $ExpectedBuild
    artifact_sha256 = $InstallerHash
    artifact_signature_status = $InstallerSignature.Status.ToString()
    unsigned_local_candidate_override = [bool]$AllowUnsignedLocalCandidate
    clean_uninstall_passed = $true
    clean_install_passed = $true
    installed_executable_sha256 = $installedAppHash
    installed_tunnel_service_sha256 = $installedTunnelServiceHash
    installed_awg_engine_sha256 = $installedAwgEngineHash
    installed_awg_tool_sha256 = $installedAwgToolHash
    installed_wintun_sha256 = $installedWintunHash
    exact_built_payload_match = $true
    awg_engine_non_system_launch_rejected = $true
    tunnel_service_running = $true
    tunnel_service_local_system = $true
    tunnel_service_auto_start = $true
    tunnel_service_delayed_auto_start = $false
    tunnel_service_sid_unrestricted = $true
    tunnel_service_failure_actions_configured = $true
    tunnel_service_protocol_self_test_passed = $true
    unauthorized_pipe_client_rejected = [bool]$unauthorizedPipeClientRejected
    foreground_process_alive = $true
    foreground_process_started_from_elevated_test_session = $true
    application_error_event_scan_passed = $true
    tunnel_tested = $false
    tested_at_utc = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $evidencePath -Encoding UTF8

Write-Host '[WINDOWS-STARTUP] PASS'
Write-Host "[WINDOWS-STARTUP] Installer SHA-256: $InstallerHash"
Write-Host "[WINDOWS-STARTUP] Authenticode: $($InstallerSignature.Status)"
Write-Host "[WINDOWS-STARTUP] Evidence: $evidencePath"
if ($InstallerSignature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
    Write-Warning 'This is local startup evidence only. The unsigned installer remains ineligible for publication.'
}
