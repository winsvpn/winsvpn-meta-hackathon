[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Installer,
    [Parameter(Mandatory)][string]$CredentialStore,
    [Parameter(Mandatory)][string]$ObserverScript,
    [Parameter(Mandatory)][string]$StartupOutputRoot,
    [Parameter(Mandatory)][string]$TransportOutput,
    [ValidateRange(30, 180)][int]$ObserveSeconds = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$isAdministrator = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdministrator) {
    throw 'The combined Windows install/transport diagnostic requires elevation.'
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$installerPath = (Resolve-Path -LiteralPath $Installer).Path
$credentialPath = (Resolve-Path -LiteralPath $CredentialStore).Path
$observerPath = (Resolve-Path -LiteralPath $ObserverScript).Path
$builtGui = Join-Path $repo 'build\windows\x64\runner\Release\wins_vpn.exe'
if (-not (Test-Path -LiteralPath $builtGui -PathType Leaf)) {
    throw 'The exact built Windows GUI is missing.'
}
$guiHash = (Get-FileHash -LiteralPath $builtGui -Algorithm SHA256).Hash
$runnerOutput = "$TransportOutput.runner.json"
if (Test-Path -LiteralPath $runnerOutput) {
    throw 'The combined diagnostic runner output already exists.'
}

try {
    & (Join-Path $PSScriptRoot 'windows_install_startup_smoke.ps1') `
        -Installer $installerPath `
        -OutputRoot $StartupOutputRoot `
        -WarmupSeconds 10 `
        -AllowUnsignedLocalCandidate

    & (Join-Path $PSScriptRoot 'windows_transport_live_probe.ps1') `
        -ExpectedGuiSha256 $guiHash `
        -CredentialStore $credentialPath `
        -ObserverScript $observerPath `
        -Output $TransportOutput `
        -ObserveSeconds $ObserveSeconds

    $runner = [ordered]@{
        contract = 'winsvpn-windows-install-transport-runner-v1'
        tested_at_utc = [DateTime]::UtcNow.ToString('o')
        status = 'passed'
        error_type = $null
        error_message = $null
    }
} catch {
    $message = [string]$_.Exception.Message
    foreach ($prefix in @($repo, $env:USERPROFILE)) {
        if (-not [string]::IsNullOrWhiteSpace($prefix)) {
            $message = [regex]::Replace(
                $message, [regex]::Escape($prefix), '<local-path>',
                [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    }
    $runner = [ordered]@{
        contract = 'winsvpn-windows-install-transport-runner-v1'
        tested_at_utc = [DateTime]::UtcNow.ToString('o')
        status = 'failed'
        error_type = $_.Exception.GetType().FullName
        error_message = $message
    }
} finally {
    [IO.File]::WriteAllText(
        $runnerOutput,
        (($runner | ConvertTo-Json -Depth 4) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false)
    )
}

if ($runner.status -cne 'passed') {
    throw $runner.error_message
}

Write-Output 'WINDOWS_INSTALL_TRANSPORT_DIAGNOSTIC=PASS'
