[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RollbackInstaller,
    [Parameter(Mandatory)][string]$RollbackManifest,
    [Parameter(Mandatory)][string]$CurrentInstaller,
    [Parameter(Mandatory)][string]$CurrentManifest,
    [Parameter(Mandatory)][string]$OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Read-CandidateManifest {
    param(
        [Parameter(Mandatory)][string]$Installer,
        [Parameter(Mandatory)][string]$Manifest
    )
    $installerPath = (Resolve-Path -LiteralPath $Installer).Path
    $manifestPath = (Resolve-Path -LiteralPath $Manifest).Path
    $document = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $installerHash = Get-Sha256 -Path $installerPath
    if ($installerHash -cne ([string]$document.installer.sha256).ToLowerInvariant()) {
        throw "Installer does not match its payload manifest: $installerPath"
    }
    $installedPayload = [System.Collections.Generic.List[object]]::new()
    $installedPaths = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $releasePrefix = 'build/windows/x64/runner/Release/'
    $dependencyPrefix = 'build/windows-installer/payload-stage/'
    foreach ($entry in @($document.payload)) {
        $sourcePath = ([string]$entry.path).Replace('\', '/')
        $relative = $null
        if ($sourcePath.StartsWith($releasePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            $relative = $sourcePath.Substring($releasePrefix.Length)
        } elseif ($sourcePath.StartsWith($dependencyPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            $leaf = [IO.Path]::GetFileName($sourcePath)
            # These two prerequisites are embedded for temporary execution and
            # are deliberately not installed under Program Files\WinsVPN.
            if ($leaf -in @('VC_redist.x64.exe', 'amneziawg-amd64.msi')) {
                continue
            }
            $relative = $leaf
        } else {
            throw "Manifest contains an unexpected Windows payload path: $sourcePath"
        }
        $parts = @(($relative + '').Replace('\', '/') -split '/')
        $sha256 = ([string]$entry.sha256).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($relative) -or
            [IO.Path]::IsPathRooted($relative) -or
            $parts -contains '' -or $parts -contains '.' -or $parts -contains '..' -or
            $sha256 -notmatch '^[0-9a-f]{64}$' -or
            -not $installedPaths.Add($relative)) {
            throw "Manifest contains an unsafe or duplicate installed payload path: $sourcePath"
        }
        $installedPayload.Add([pscustomobject]@{
            RelativePath = $relative.Replace('\', '/')
            Sha256 = $sha256
        })
    }
    $gui = @($installedPayload | Where-Object {
            [IO.Path]::GetFileName([string]$_.RelativePath) -ieq 'wins_vpn.exe'
        })
    $service = @($installedPayload | Where-Object {
            [IO.Path]::GetFileName([string]$_.RelativePath) -ieq 'wins_vpn_tunnel_service.exe'
        })
    if ($gui.Count -ne 1 -or $service.Count -ne 1) {
        throw "Manifest must identify exactly one GUI and tunnel service payload: $manifestPath"
    }
    $awg = @($installedPayload | Where-Object {
            [IO.Path]::GetFileName([string]$_.RelativePath) -ieq 'winsvpn_awg_engine.exe'
        })
    return [pscustomobject]@{
        Installer = $installerPath
        Manifest = $manifestPath
        InstallerSha256 = $installerHash
        InstalledPayload = @($installedPayload)
        GuiSha256 = ([string]$gui[0].Sha256).ToLowerInvariant()
        ServiceSha256 = ([string]$service[0].Sha256).ToLowerInvariant()
        AwgEngineSha256 = if ($awg.Count -eq 1) {
            ([string]$awg[0].Sha256).ToLowerInvariant()
        } else {
            $null
        }
    }
}

function Get-WinsVpnUninstallEntry {
    return Get-ItemProperty `
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', `
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', `
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' `
        -ErrorAction SilentlyContinue |
        Where-Object {
            $_.PSObject.Properties['DisplayName'] -and
            [string]$_.DisplayName -match "^Win.?s VPN(?:\s|$)"
        } |
        Select-Object -First 1
}

function Get-EntryString {
    param([Parameter(Mandatory)][object]$Entry, [Parameter(Mandatory)][string]$Name)
    $property = $Entry.PSObject.Properties[$Name]
    if (-not $property -or $null -eq $property.Value) {
        return ''
    }
    return [string]$property.Value
}

function Uninstall-WinsVpn {
    Get-Process -Name wins_vpn -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    $entry = Get-WinsVpnUninstallEntry
    if (-not $entry) {
        return $false
    }
    $command = Get-EntryString -Entry $entry -Name 'QuietUninstallString'
    if ([string]::IsNullOrWhiteSpace($command)) {
        $command = Get-EntryString -Entry $entry -Name 'UninstallString'
    }
    if ($command -match '^"([^"]+)"') {
        $uninstaller = $Matches[1]
    } else {
        $uninstaller = ($command -split '\s+', 2)[0]
    }
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
        throw "Registered Win's VPN uninstaller is missing: $uninstaller"
    }
    $process = Start-Process -FilePath $uninstaller -ArgumentList @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART',
        '/RESTARTEXITCODE=3010', '/SP-'
    ) -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Win's VPN uninstall returned $($process.ExitCode)."
    }
    if (Get-WinsVpnUninstallEntry) {
        throw "Win's VPN registration remains after uninstall."
    }
    return $true
}

function Install-WinsVpn {
    param([Parameter(Mandatory)][pscustomobject]$Candidate)
    $process = Start-Process -FilePath $Candidate.Installer -ArgumentList @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART',
        '/RESTARTEXITCODE=3010', '/SP-'
    ) -Wait -PassThru
    if ($process.ExitCode -eq 3010) {
        throw "Win's VPN installer requires a reboot before rollback validation: $($Candidate.Installer)"
    }
    if ($process.ExitCode -ne 0) {
        throw "Win's VPN installer returned $($process.ExitCode): $($Candidate.Installer)"
    }
}

function Assert-InstalledCandidate {
    param(
        [Parameter(Mandatory)][pscustomobject]$Candidate,
        [Parameter(Mandatory)][string]$Stage
    )
    $root = Join-Path $env:ProgramFiles 'WinsVPN'
    $rootFull = [IO.Path]::GetFullPath($root)
    $rootPrefix = $rootFull.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    foreach ($payload in @($Candidate.InstalledPayload)) {
        $installedPath = [IO.Path]::GetFullPath((Join-Path $rootFull ([string]$payload.RelativePath)))
        if (-not $installedPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $installedPath -PathType Leaf) -or
            (Get-Sha256 -Path $installedPath) -cne [string]$payload.Sha256) {
            throw "$Stage installed payload does not match its manifest: $($payload.RelativePath)"
        }
    }
    $gui = Join-Path $root 'wins_vpn.exe'
    $serviceBinary = Join-Path $root 'wins_vpn_tunnel_service.exe'
    if (-not (Get-WinsVpnUninstallEntry) -or
        -not (Test-Path -LiteralPath $gui -PathType Leaf) -or
        -not (Test-Path -LiteralPath $serviceBinary -PathType Leaf)) {
        throw "$Stage candidate registration or payload is missing."
    }
    $guiHash = Get-Sha256 -Path $gui
    $serviceHash = Get-Sha256 -Path $serviceBinary
    if ($guiHash -cne $Candidate.GuiSha256 -or
        $serviceHash -cne $Candidate.ServiceSha256) {
        throw "$Stage candidate payload does not match its manifest."
    }
    $awgHash = $null
    if ($Candidate.AwgEngineSha256) {
        $awg = Join-Path $root 'winsvpn_awg_engine.exe'
        if (-not (Test-Path -LiteralPath $awg -PathType Leaf)) {
            throw "$Stage candidate AWG engine is missing."
        }
        $awgHash = Get-Sha256 -Path $awg
        if ($awgHash -cne $Candidate.AwgEngineSha256) {
            throw "$Stage candidate AWG engine does not match its manifest."
        }
    }
    $service = Get-CimInstance Win32_Service -Filter "Name='WinsVpnTunnelManager'"
    if (-not $service -or $service.State -cne 'Running' -or
        $service.StartMode -cne 'Auto' -or $service.StartName -cne 'LocalSystem') {
        throw "$Stage tunnel-manager service is missing or misconfigured."
    }
    return [ordered]@{
        installer_sha256 = $Candidate.InstallerSha256
        installed_gui_sha256 = $guiHash
        installed_service_sha256 = $serviceHash
        installed_awg_engine_sha256 = $awgHash
        installed_payload_file_count = @($Candidate.InstalledPayload).Count
        service_running = $true
        service_auto_start = $true
        service_local_system = $true
    }
}

$administrator = ([Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $administrator) {
    throw 'Rollback/reinstall smoke requires an elevated administrator session.'
}

$rollback = Read-CandidateManifest -Installer $RollbackInstaller -Manifest $RollbackManifest
$current = Read-CandidateManifest -Installer $CurrentInstaller -Manifest $CurrentManifest
$outputPath = [IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$evidencePath = Join-Path $outputPath "rollback-reinstall-$stamp.json"
$started = [DateTime]::UtcNow
$initial = $null
$rollbackInstalled = $null
$currentRestored = $null
$testError = $null
$recoveryNeeded = $false

try {
    $initial = Assert-InstalledCandidate -Candidate $current -Stage 'Initial current'
    [void](Uninstall-WinsVpn)
    Install-WinsVpn -Candidate $rollback
    $rollbackInstalled = Assert-InstalledCandidate -Candidate $rollback -Stage 'Rollback'
    [void](Uninstall-WinsVpn)
    Install-WinsVpn -Candidate $current
    $currentRestored = Assert-InstalledCandidate -Candidate $current -Stage 'Restored current'
} catch {
    $testError = $_.Exception.Message
} finally {
    try {
        $currentPresent = $false
        try {
            [void](Assert-InstalledCandidate -Candidate $current -Stage 'Recovery check')
            $currentPresent = $true
        } catch {
            $currentPresent = $false
        }
        if (-not $currentPresent) {
            $recoveryNeeded = $true
            [void](Uninstall-WinsVpn)
            Install-WinsVpn -Candidate $current
        }
        $currentRestored = Assert-InstalledCandidate -Candidate $current -Stage 'Final current'
    } catch {
        $recoveryFailure = $_.Exception.Message
        if ($testError) {
            $testError = "$testError Final recovery also failed: $recoveryFailure"
        } else {
            $testError = "Final recovery failed: $recoveryFailure"
        }
    }
}

Get-Process -Name wins_vpn -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
$tunnelAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq 'winsvpn' -and $_.Status -eq 'Up' })
$tunnelRoutes = @(Get-NetRoute -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceAlias -eq 'winsvpn' })
$awgEngines = @(Get-Process winsvpn_awg_engine -ErrorAction SilentlyContinue)
$xrayProcesses = @(Get-Process xray -ErrorAction SilentlyContinue)
$adapterAbsentOrDown = $tunnelAdapters.Count -eq 0
$routesAbsent = $tunnelRoutes.Count -eq 0
$awgEngineAbsent = $awgEngines.Count -eq 0
$xrayAbsent = $xrayProcesses.Count -eq 0
if (-not $adapterAbsentOrDown -or -not $routesAbsent -or
    -not $awgEngineAbsent -or -not $xrayAbsent) {
    $residueFailure = 'Final rollback/reinstall state contains native VPN residue.'
    if ($testError) {
        $testError = "$testError $residueFailure"
    } else {
        $testError = $residueFailure
    }
}
$result = if ($testError) { 'fail' } else { 'pass' }

[ordered]@{
    schema = 'winsvpn.windows.rollback-reinstall-smoke.v2'
    machine = $env:COMPUTERNAME
    started_at_utc = $started.ToString('o')
    completed_at_utc = [DateTime]::UtcNow.ToString('o')
    initial_current = $initial
    rollback_installed = $rollbackInstalled
    current_restored = $currentRestored
    recovery_needed = $recoveryNeeded
    safe_disconnected_state = [ordered]@{
        tunnel_adapter_absent_or_down = $adapterAbsentOrDown
        tunnel_routes_absent = $routesAbsent
        awg_engine_absent = $awgEngineAbsent
        xray_absent = $xrayAbsent
    }
    error = $testError
    result = $result
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $evidencePath -Encoding UTF8

Write-Host "[WINDOWS-ROLLBACK] Result: $result"
Write-Host "[WINDOWS-ROLLBACK] Evidence: $evidencePath"
if ($testError) {
    throw $testError
}
