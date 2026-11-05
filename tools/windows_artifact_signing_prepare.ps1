[CmdletBinding()]
param(
    [switch]$InstallPrerequisites,
    [switch]$RegisterProvider,
    [string]$Endpoint,
    [string]$AccountName,
    [string]$CertificateProfileName,
    [string]$MetadataPath = '',
    [string]$StatusPath = '',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Get-WindowsProgramFilesRoots {
    @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)}
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
}

function Get-AzureCliCandidates {
    foreach ($root in (Get-WindowsProgramFilesRoots)) {
        Join-Path $root 'Microsoft SDKs\Azure\CLI2\wbin\az.cmd'
    }
}

function Get-ArtifactSigningDlibCandidates {
    foreach ($root in (Get-WindowsProgramFilesRoots)) {
        Join-Path $root 'Microsoft\ArtifactSigningClientTools\bin\x64\Azure.CodeSigning.Dlib.dll'
    }
}

function Find-FirstFile {
    param([Parameter(Mandatory=$true)][string[]]$Candidates)
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return $null
}

function Test-PathIsInsideRoot {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Root
    )
    $fullPath = [IO.Path]::GetFullPath($Path)
    $rootFull = [IO.Path]::GetFullPath($Root)
    foreach ($separator in @([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar, '\', '/')) {
        $prefix = $rootFull.TrimEnd('\', '/') + [string]$separator
        if ($fullPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Assert-SafeSigningToken {
    param(
        [Parameter(Mandatory=$true)][string]$Value,
        [Parameter(Mandatory=$true)][string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "$Label is empty." }
    if ($Value -match '[\x00-\x1f\x7f"`|*?<>]') {
        throw "$Label contains a forbidden path or argument character."
    }
}

function Get-ArtifactSigningStateRoot {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw 'LOCALAPPDATA is required to store Artifact Signing metadata and status outside Git.'
    }
    return [IO.Path]::GetFullPath((Join-Path (Join-Path $env:LOCALAPPDATA 'WinsVPN') 'Signing'))
}

function Find-PrepareSignTool {
    foreach ($root in (Get-WindowsProgramFilesRoots)) {
        $kitRoot = Join-Path $root 'Windows Kits\10\bin'
        if (-not (Test-Path -LiteralPath $kitRoot)) { continue }
        $candidate = Get-ChildItem -LiteralPath $kitRoot -Directory -ErrorAction SilentlyContinue |
            Sort-Object { try { [version]$_.Name } catch { [version]'0.0' } } -Descending |
            ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Select-Object -First 1
        if ($candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return $null
}

function Assert-ArtifactEndpoint {
    param([Parameter(Mandatory=$true)][string]$Value)
    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -ne 'https' -or
        $uri.Host -notmatch '^[a-z0-9-]+\.codesigning\.azure\.net$' -or
        -not [string]::IsNullOrEmpty($uri.UserInfo) -or
        -not [string]::IsNullOrEmpty($uri.Query) -or
        -not [string]::IsNullOrEmpty($uri.Fragment) -or
        ($uri.AbsolutePath -ne '/' -and $uri.AbsolutePath -ne '')) {
        throw 'Endpoint must be the regional HTTPS *.codesigning.azure.net URI shown by the Artifact Signing account.'
    }
}

function Assert-ArtifactSigningName {
    param(
        [Parameter(Mandatory=$true)][string]$Value,
        [Parameter(Mandatory=$true)][string]$Label
    )
    if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,99}$') {
        throw "Account and certificate-profile names must be nonempty, at most 100 characters, and contain no control characters."
    }
}

function Assert-SigningStatePath {
    param(
        [Parameter(Mandatory=$true)][string]$Value,
        [Parameter(Mandatory=$true)][string]$ExactFileName
    )
    Assert-SafeSigningToken -Value $Value -Label $ExactFileName
    $fullPath = [IO.Path]::GetFullPath($Value)
    if (-not [string]::Equals([IO.Path]::GetFileName($fullPath), $ExactFileName, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Artifact Signing output identity must be exactly $ExactFileName."
    }
    $stateRoot = Get-ArtifactSigningStateRoot
    if (-not (Test-PathIsInsideRoot -Path $fullPath -Root $stateRoot)) {
        throw 'Artifact Signing metadata and status must stay under LOCALAPPDATA\WinsVPN\Signing.'
    }
    if (Test-PathIsInsideRoot -Path $fullPath -Root $RepoRoot) {
        throw 'Artifact Signing metadata must stay outside the Git repository.'
    }
    return $fullPath
}

function Assert-ExternalMetadataPath {
    param([Parameter(Mandatory=$true)][string]$Value)
    return Assert-SigningStatePath -Value $Value -ExactFileName 'artifact-signing-metadata.json'
}

function Install-OfficialPrerequisites {
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) { throw 'winget.exe is required for prerequisite installation.' }
    $packages = @(
        'Microsoft.AzureCLI',
        'Microsoft.Azure.ArtifactSigningClientTools',
        'Microsoft.DotNet.Runtime.8'
    )
    foreach ($package in $packages) {
        & $winget.Source install --id $package --exact --source winget `
            --accept-package-agreements --accept-source-agreements --silent --disable-interactivity
        if ($LASTEXITCODE -ne 0) { throw "Failed to install official package $package." }
    }
}

function Write-ArtifactMetadata {
    param(
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [Parameter(Mandatory=$true)][string]$EndpointValue,
        [Parameter(Mandatory=$true)][string]$AccountValue,
        [Parameter(Mandatory=$true)][string]$ProfileValue
    )
    Assert-ArtifactEndpoint -Value $EndpointValue
    Assert-ArtifactSigningName -Value $AccountValue -Label 'account'
    Assert-ArtifactSigningName -Value $ProfileValue -Label 'certificate-profile'
    $resolved = Assert-SigningStatePath -Value $OutputPath -ExactFileName 'artifact-signing-metadata.json'
    $parent = Split-Path -Parent $resolved
    [void][IO.Directory]::CreateDirectory($parent)
    $metadata = [ordered]@{
        Endpoint = $EndpointValue
        CodeSigningAccountName = $AccountValue
        CertificateProfileName = $ProfileValue
    }
    $json = $metadata | ConvertTo-Json
    [IO.File]::WriteAllText($resolved, $json + "`n", [Text.UTF8Encoding]::new($false))
    $roundTrip = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    if (($roundTrip.Endpoint + '') -cne $EndpointValue -or
        ($roundTrip.CodeSigningAccountName + '') -cne $AccountValue -or
        ($roundTrip.CertificateProfileName + '') -cne $ProfileValue) {
        throw 'Artifact Signing metadata round-trip identity mismatch.'
    }
    return $resolved
}

function Write-ArtifactStatus {
    param(
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [Parameter(Mandatory=$true)][System.Collections.IDictionary]$Status
    )
    $resolved = Assert-SigningStatePath -Value $OutputPath -ExactFileName 'artifact-signing-status.json'
    $parent = Split-Path -Parent $resolved
    [void][IO.Directory]::CreateDirectory($parent)
    $json = $Status | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText($resolved, $json + "`n", [Text.UTF8Encoding]::new($false))
    $roundTrip = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    if (($roundTrip.contract + '') -cne 'winsvpn-artifact-signing-status-v1' -or
        [bool]$roundTrip.production_signing_ready -ne $false -or
        ($roundTrip.owner_authenticode_leaf_sha256 + '') -cne 'OWNER-BLOCKED: ABSENT') {
        throw 'Artifact Signing status round-trip identity mismatch.'
    }
    return $resolved
}

if ($SelfTest) {
    Assert-ArtifactEndpoint -Value 'https://eus.codesigning.azure.net'
    foreach ($hostile in @(
        'https://example.com',
        'https://evil:pw@eus.codesigning.azure.net',
        'https://eus.codesigning.azure.net/steal',
        'https://eus.codesigning.azure.net?x=1',
        'http://eus.codesigning.azure.net'
    )) {
        $rejected = $false
        try { Assert-ArtifactEndpoint -Value $hostile } catch { $rejected = $true }
        if (-not $rejected) { throw "Self-test accepted a non-Artifact-Signing endpoint: $hostile" }
    }
    $savedLocalAppData = $env:LOCALAPPDATA
    $jail = Join-Path ([IO.Path]::GetTempPath()) ("winsvpn-artifact-selftest-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $jail -Force | Out-Null
    try {
        $env:LOCALAPPDATA = $jail
        $stateRoot = Join-Path (Join-Path $jail 'WinsVPN') 'Signing'
        $okMetadata = Join-Path $stateRoot 'artifact-signing-metadata.json'
        $okStatus = Join-Path $stateRoot 'artifact-signing-status.json'
        [void](Assert-SigningStatePath -Value $okMetadata -ExactFileName 'artifact-signing-metadata.json')
        [void](Assert-SigningStatePath -Value $okStatus -ExactFileName 'artifact-signing-status.json')
        foreach ($hostilePath in @(
            (Join-Path $RepoRoot 'artifact-signing-metadata.json'),
            (Join-Path $RepoRoot 'metadata.json'),
            (Join-Path $jail 'artifact-signing-metadata.json'),
            '/tmp/artifact-signing-metadata.json',
            (Join-Path $stateRoot 'evil.json'),
            (Join-Path (Join-Path $jail 'WinsVPN') 'artifact-signing-metadata.json')
        )) {
            $rejected = $false
            try { [void](Assert-SigningStatePath -Value $hostilePath -ExactFileName 'artifact-signing-metadata.json') } catch { $rejected = $true }
            if (-not $rejected) { throw "Self-test accepted a hostile metadata path: $hostilePath" }
        }
        $rejected = $false
        try { [void](Assert-ExternalMetadataPath -Value (Join-Path $RepoRoot 'artifact-signing-metadata.json')) } catch { $rejected = $true }
        if (-not $rejected) { throw 'Self-test accepted repository-local signing metadata.' }
        foreach ($hostileName in @('acc ount', 'acc;count', 'acc`count', '"account"', "account`nname", 'ab')) {
            $rejected = $false
            try { Assert-ArtifactSigningName -Value $hostileName -Label 'account' } catch { $rejected = $true }
            if (-not $rejected) { throw "Self-test accepted a hostile account name: $hostileName" }
        }
        $written = Write-ArtifactMetadata -OutputPath $okMetadata `
            -EndpointValue 'https://eus.codesigning.azure.net' -AccountValue 'winsvpnacct' -ProfileValue 'winsvpnprofile'
        if ($written -ne [IO.Path]::GetFullPath($okMetadata)) {
            throw 'Self-test metadata output identity mismatch.'
        }
    } finally {
        $env:LOCALAPPDATA = $savedLocalAppData
        Remove-Item -LiteralPath $jail -Recurse -Force -ErrorAction SilentlyContinue
    }
    $statusText = Get-Content -LiteralPath $PSCommandPath -Raw
    foreach ($required in @(
        'winsvpn-artifact-signing-status-v1',
        'azure_subscription_required',
        'Microsoft.CodeSigning',
        'identity_validation_requires_portal',
        'OWNER-BLOCKED: ABSENT',
        'production_signing_ready = $false',
        'UserInfo',
        'LOCALAPPDATA\WinsVPN\Signing',
        'artifact-signing-status.json'
    )) {
        if (-not $statusText.Contains($required)) { throw "Self-test contract missing: $required" }
    }
    Write-Host 'WINDOWS ARTIFACT SIGNING PREPARATION SELF-TEST: PASS' -ForegroundColor Green
    exit 0
}

if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    throw 'LOCALAPPDATA is required to store Artifact Signing metadata and status outside Git.'
}
if ([string]::IsNullOrWhiteSpace($MetadataPath)) {
    $MetadataPath = Join-Path $env:LOCALAPPDATA 'WinsVPN\Signing\artifact-signing-metadata.json'
}
if ([string]::IsNullOrWhiteSpace($StatusPath)) {
    $StatusPath = Join-Path $env:LOCALAPPDATA 'WinsVPN\Signing\artifact-signing-status.json'
}

if ($InstallPrerequisites) { Install-OfficialPrerequisites }

$az = Find-FirstFile -Candidates @(Get-AzureCliCandidates)
$dlib = Find-FirstFile -Candidates @(Get-ArtifactSigningDlibCandidates)
$signToolPath = Find-PrepareSignTool
if (-not $az) { throw 'Azure CLI is missing. Run this script with -InstallPrerequisites.' }
if (-not $dlib) { throw 'Artifact Signing Client Tools are missing. Run this script with -InstallPrerequisites.' }
if (-not $signToolPath) { throw 'A compatible x64 Windows SDK SignTool is missing.' }

$extensionJson = & $az extension show --name artifact-signing --only-show-errors -o json 2>$null
$extensionPresent = $LASTEXITCODE -eq 0
if (-not $extensionPresent -and $InstallPrerequisites) {
    & $az extension add --name artifact-signing --yes --only-show-errors | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'The Azure Artifact Signing CLI extension could not be installed.' }
    $extensionJson = & $az extension show --name artifact-signing --only-show-errors -o json
    $extensionPresent = $LASTEXITCODE -eq 0
}
if (-not $extensionPresent) {
    throw 'The Azure Artifact Signing CLI extension is missing. Run this script with -InstallPrerequisites.'
}
$extension = $extensionJson | ConvertFrom-Json

$savedErrorPreference = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
try {
    & $az account show --only-show-errors --query id -o tsv *> $null
    $authenticated = $LASTEXITCODE -eq 0
} finally {
    $ErrorActionPreference = $savedErrorPreference
}
$subscriptionCount = 0
$providerState = 'Unavailable'
if ($authenticated) {
    $subscriptionsJson = & $az account list --all --only-show-errors -o json
    if ($LASTEXITCODE -ne 0) { throw 'Azure subscription enumeration failed.' }
    $subscriptions = @($subscriptionsJson | ConvertFrom-Json)
    $subscriptionCount = @($subscriptions | Where-Object { $_.state -eq 'Enabled' }).Count
    $providerState = (& $az provider show --namespace Microsoft.CodeSigning `
        --query registrationState -o tsv --only-show-errors 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($providerState)) {
        $providerState = 'Unknown'
    }
}
if ($RegisterProvider) {
    if (-not $authenticated) { throw 'Azure sign-in is required before provider registration. Run az login in your own interactive terminal.' }
    & $az provider register --namespace Microsoft.CodeSigning
    if ($LASTEXITCODE -ne 0) { throw 'Microsoft.CodeSigning provider registration failed.' }
    & $az provider wait --namespace Microsoft.CodeSigning --registered --interval 5 --timeout 300
    if ($LASTEXITCODE -ne 0) { throw 'Microsoft.CodeSigning provider registration did not reach Registered state.' }
    $providerState = 'Registered'
}

$provided = @(@($Endpoint, $AccountName, $CertificateProfileName) |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($provided.Count -notin @(0, 3)) {
    throw 'Endpoint, AccountName, and CertificateProfileName must be supplied together.'
}
$writtenMetadata = $null
$resolvedMetadataPath = Assert-SigningStatePath -Value $MetadataPath -ExactFileName 'artifact-signing-metadata.json'
$resolvedStatusPath = Assert-SigningStatePath -Value $StatusPath -ExactFileName 'artifact-signing-status.json'
if ([string]::Equals($resolvedMetadataPath, $resolvedStatusPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Artifact Signing metadata and status must be distinct files.'
}
if ($provided.Count -eq 3) {
    $writtenMetadata = Write-ArtifactMetadata -OutputPath $resolvedMetadataPath `
        -EndpointValue $Endpoint -AccountValue $AccountName -ProfileValue $CertificateProfileName
}

$blockers = [System.Collections.Generic.List[string]]::new()
if (-not $authenticated -or $subscriptionCount -lt 1) { $blockers.Add('azure_subscription_required') }
if ($authenticated -and $providerState -ne 'Registered') { $blockers.Add('microsoft_codesigning_provider_not_registered') }
if (-not $writtenMetadata) { $blockers.Add('public_trust_profile_metadata_not_configured') }
$blockers.Add('identity_validation_requires_portal')
$blockers.Add('owner_authenticode_certificate_blocked')
$status = [ordered]@{
    schema_version = 1
    contract = 'winsvpn-artifact-signing-status-v1'
    captured_at_utc = [DateTime]::UtcNow.ToString('o')
    prerequisites = [ordered]@{
        azure_cli = $true
        artifact_signing_extension = $true
        artifact_signing_extension_version = [string]$extension.version
        artifact_signing_client_tools = $true
        signtool = $true
    }
    azure = [ordered]@{
        authenticated_subscription = [bool]$authenticated
        enabled_subscription_count = [int]$subscriptionCount
        microsoft_codesigning_provider = $providerState
    }
    metadata_configured = [bool]$writtenMetadata
    identity_validation_automatable = $false
    owner_authenticode_leaf_sha256 = 'OWNER-BLOCKED: ABSENT'
    production_signing_ready = $false
    blockers = @($blockers)
    secrets_recorded = $false
    publication_authorized = $false
}
$writtenStatus = Write-ArtifactStatus -OutputPath $resolvedStatusPath -Status $status

Write-Host "Azure CLI: $az"
Write-Host "Artifact Signing dlib: $dlib"
Write-Host "SignTool: $signToolPath"
Write-Host "Azure authenticated: $authenticated"
Write-Host "Enabled Azure subscriptions: $subscriptionCount"
Write-Host "Microsoft.CodeSigning provider: $providerState"
Write-Host "Redacted status: $writtenStatus"
if ($writtenMetadata) {
    Write-Host "Metadata written outside Git: $writtenMetadata"
    Write-Host "Set WINS_WINDOWS_ARTIFACT_SIGNING_METADATA to that path after Microsoft completes Public Trust identity validation."
} else {
    Write-Host 'No billed Artifact Signing account or certificate profile was created.'
    Write-Host 'Identity validation must be completed by the legal organization representative in the Azure portal.'
}
