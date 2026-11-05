#Requires -Version 5.1
<#
build_winn3_msi_arm64.ps1 — produce a Windows ARM64 MSI carrying the Winn
Protocol v3 engine payload, using the WiX Toolset installed as a dotnet global
tool. ARM64 sibling of build_winn3_msi.ps1.

WHY A SEPARATE ARM64 PACKAGE

  Windows on ARM emulates x64 USER-MODE code, but the Winn v3 relay drives
  Wintun, a kernel-mode driver, and drivers are never emulated. So an ARM64
  Windows host needs the ARM64 native half of winsvpn_winn3_engine.exe and
  winn-datapath.exe plus the ARM64 build of wintun.dll. This package is built
  with `wix build -arch arm64`, so its Package Template is Arm64 and Windows
  Installer refuses to install it on any non-ARM64 edition, and it carries a
  distinct UpgradeCode so it can never be mistaken for an upgrade of the x64
  package.

WHAT IT GATES ON

  The SAME v3 carrier-completeness decision as the x64 MSI: winn-datapath.exe
  must CONTAIN 'winsvpn.local/winnprotocol/winn3' by raw-byte content — not
  merely exist — and winsvpn_winn3_engine.exe must be present under that exact
  name. Both halves must be PE32+ AArch64 (COFF machine 0xAA64), as must the
  ARM64 Wintun DLL; a host that silently packaged an x64 half would produce an
  ARM64 MSI that installs perfectly and refuses every session because the Wintun
  driver request fails.

  The machine type is read from each binary's COFF header, never trusted from a
  filename — a cross-compile can put the wrong machine type behind the right
  name and nothing downstream would notice until a user's session refused.

EXAMPLE

    powershell -ExecutionPolicy Bypass -File build_winn3_msi_arm64.ps1 `
      -ReleaseDir C:\stage\arm64 -AppVersion 1.0.15.30
#>
[CmdletBinding()]
param(
    [Alias('ReleaseDir')]
    [string]$EngineDir        = (Join-Path $PSScriptRoot '..\..\build\windows\winn3\arm64'),
    [string]$DependenciesDir  = (Join-Path $PSScriptRoot 'dependencies'),
    [string]$LicensesDir      = (Join-Path $PSScriptRoot 'licenses'),
    [string]$OutDir           = (Join-Path $PSScriptRoot '..\..\build\windows-installer'),
    [string]$StageDir         = '',
    [string]$AppVersion       = '0.0.0.0',
    [switch]$RequireCodeSigning
)

$ErrorActionPreference = 'Stop'
$Marker = 'winsvpn.local/winnprotocol/winn3'
# COFF machine type for the ARM64 (AArch64) architecture family.
$Arm64Machine = 0xAA64
$WintunExpectedSha256 = 'f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80'

function Write-Step { param([string]$m) Write-Host "[build_winn3_msi_arm64] $m" }

# BEGIN-WINDOWS-PRODUCER-AUTHENTICODE-POLICY
# Byte-identical in build_zip_installer.ps1, build_store_msix.ps1,
# build_winn3_msi.ps1 and build_winn3_msi_arm64.ps1. It applies the same
# Authenticode policy as installer/windows/build_installer.ps1
# (Find-SignTool -RequireApprovedMicrosoftSignature, Get-CodeSigningSelector,
# Assert-CodeSigningCertificate, Assert-MicrosoftTrustedRootProgramChain,
# New-ProductSignArgumentList, Assert-ProductSignature). A producer signs only
# when WINS_WINDOWS_ARTIFACT_SIGNING_METADATA or WINS_WINDOWS_SIGN_CERT_SHA1 is
# set; otherwise it builds an unsigned rehearsal and records it as unsigned.
$WinsProducerArtifactSigningTimestampUrl = 'http://timestamp.acs.microsoft.com'
$WinsProducerDefaultTimestampUrl = 'http://timestamp.digicert.com'
$WinsProducerApprovedTimestampUrls = @(
    'http://timestamp.acs.microsoft.com',
    'http://timestamp.digicert.com',
    'https://timestamp.digicert.com'
)
$WinsProducerPinnedMicrosoftRoots = @(
    '3B1EFD3A66EA28B16697394703A72CA340A05BD5', # Microsoft Root CA 2010
    '8F43288AD272F3103B6FB1428485EA3014C0BCFE'  # Microsoft Root CA 2011
)

function Assert-WinsProducerApprovedTimestampUrl {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -match '[\x00-\x1f\x7f"`|*?<>]') {
        throw 'The signing timestamp URL is empty or contains a forbidden path or argument character.'
    }
    if ($Value -cnotin $WinsProducerApprovedTimestampUrls) {
        throw 'The signing timestamp URL must be an exact approved Microsoft/DigiCert RFC 3161 endpoint.'
    }
}

function Get-WinsProducerSdkArchitectures {
    param([Parameter(Mandatory = $true)][ValidateSet('x64', 'arm64')][string]$Architecture)
    $arches = @($Architecture)
    if ($arches -notcontains 'x64') { $arches += 'x64' }
    return $arches
}

function Assert-WinsProducerMicrosoftReleaseTool {
    # The tool must sit under a fixed admin-writable root AND carry a valid
    # Microsoft Authenticode signature; neither condition alone is enough.
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$AllowedRoots
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Release signing tool does not exist: $Path"
    }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $separator = [IO.Path]::DirectorySeparatorChar
    $withinApprovedRoot = @($AllowedRoots | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_) -and
        $resolved.StartsWith(($_.TrimEnd('\', '/') + $separator), [StringComparison]::OrdinalIgnoreCase)
    }).Count -gt 0
    if (-not $withinApprovedRoot) {
        throw "Release signing tool is outside every approved root: $resolved"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $resolved
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
        throw "Release signing tool lacks the required valid Microsoft signature: $resolved"
    }
    return $resolved
}

function Find-WinsProducerSignTool {
    # Only the fixed Windows Kits root is searched; PATH and any tool-path
    # override variable are never trusted for the signing call.
    param([Parameter(Mandatory = $true)][ValidateSet('x64', 'arm64')][string]$Architecture)
    $roots = @()
    if (${env:ProgramFiles(x86)}) {
        $roots += (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin')
    }
    foreach ($kitRoot in $roots) {
        if (-not (Test-Path -LiteralPath $kitRoot -PathType Container)) { continue }
        $versionDirs = @(Get-ChildItem -LiteralPath $kitRoot -Directory -ErrorAction SilentlyContinue |
            Sort-Object { try { [version]$_.Name } catch { [version]'0.0' } } -Descending)
        foreach ($arch in (Get-WinsProducerSdkArchitectures -Architecture $Architecture)) {
            foreach ($versionDir in $versionDirs) {
                $candidate = Join-Path $versionDir.FullName (Join-Path $arch 'signtool.exe')
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    return (Assert-WinsProducerMicrosoftReleaseTool -Path $candidate -AllowedRoots $roots)
                }
            }
        }
    }
    return $null
}

function Find-WinsProducerArtifactSigningDlib {
    # Per-user locations and any DLIB-path override variable are user-writable and
    # never trusted; only the fixed Program Files roots are searched.
    param([Parameter(Mandatory = $true)][ValidateSet('x64', 'arm64')][string]$Architecture)
    $roots = @()
    foreach ($arch in (Get-WinsProducerSdkArchitectures -Architecture $Architecture)) {
        if (${env:ProgramFiles(x86)}) {
            $roots += (Join-Path ${env:ProgramFiles(x86)} "Microsoft\ArtifactSigningClientTools\bin\$arch")
        }
        if ($env:ProgramFiles) {
            $roots += (Join-Path $env:ProgramFiles "Microsoft\ArtifactSigningClientTools\bin\$arch")
        }
    }
    foreach ($root in $roots) {
        $candidate = Join-Path $root 'Azure.CodeSigning.Dlib.dll'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Assert-WinsProducerMicrosoftReleaseTool -Path $candidate -AllowedRoots $roots)
        }
    }
    return $null
}

function Resolve-WinsProducerArtifactSigningMetadataPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RepoRoot
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "WINS_WINDOWS_ARTIFACT_SIGNING_METADATA does not exist: $Path"
    }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $repoPrefix = ([IO.Path]::GetFullPath($RepoRoot)).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if ($resolved.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Artifact Signing metadata must be stored outside the repository tree.'
    }
    if ((Get-Item -LiteralPath $resolved).Length -gt 16384) {
        throw 'Artifact Signing metadata is unexpectedly large.'
    }
    try {
        $metadata = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    } catch {
        throw "Artifact Signing metadata is not valid JSON: $($_.Exception.Message)"
    }
    if ($null -eq $metadata -or $metadata -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'Artifact Signing metadata must be a JSON object.'
    }
    $allowedFields = @('Endpoint', 'CodeSigningAccountName', 'CertificateProfileName', 'CorrelationId', 'ExcludeCredentials')
    foreach ($field in @($metadata.PSObject.Properties.Name)) {
        if ($field -cnotin $allowedFields) {
            throw "Artifact Signing metadata field '$field' is forbidden. Authentication tokens and secrets must come from Azure identity providers, not metadata JSON."
        }
    }
    $values = @{}
    foreach ($field in @('Endpoint', 'CodeSigningAccountName', 'CertificateProfileName')) {
        $property = $metadata.PSObject.Properties[$field]
        $value = if ($null -eq $property) { '' } else { [string]$property.Value }
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw "Artifact Signing metadata requires $field."
        }
        $values[$field] = $value
    }
    $endpoint = $null
    if (-not [Uri]::TryCreate($values['Endpoint'], [UriKind]::Absolute, [ref]$endpoint) -or
        $endpoint.Scheme -ne 'https' -or
        $endpoint.Host -notmatch '^[a-z0-9-]+\.codesigning\.azure\.net$' -or
        -not [string]::IsNullOrEmpty($endpoint.Query) -or
        -not [string]::IsNullOrEmpty($endpoint.Fragment)) {
        throw 'Artifact Signing Endpoint must be a regional HTTPS *.codesigning.azure.net URI with no query or fragment.'
    }
    return $resolved
}

function Assert-WinsProducerCodeSigningCertificate {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$SignerPattern,
        [Parameter(Mandatory = $true)][string]$SourceLabel
    )
    if (-not $Certificate.HasPrivateKey) {
        throw "$SourceLabel does not contain an accessible private key."
    }
    $now = [DateTime]::UtcNow
    if ($now -lt $Certificate.NotBefore.ToUniversalTime() -or $now -gt $Certificate.NotAfter.ToUniversalTime()) {
        throw "$SourceLabel is not currently valid."
    }
    if ($Certificate.Subject -eq $Certificate.Issuer) {
        throw "A self-signed certificate is forbidden for production distribution: $SourceLabel"
    }
    if ($Certificate.Subject -notmatch $SignerPattern) {
        throw "$SourceLabel subject does not match WINS_WINDOWS_SIGNER_SUBJECT_REGEX."
    }
    $eku = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
    $hasCodeSigningEku = $false
    if ($eku -and $eku.EnhancedKeyUsages) {
        $hasCodeSigningEku = @($eku.EnhancedKeyUsages | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.3' }).Count -eq 1
    }
    if (-not $hasCodeSigningEku) {
        throw "$SourceLabel is not an Authenticode Code Signing certificate. TLS/server certificates are forbidden."
    }
}

function Assert-WinsProducerTrustedRootChain {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreNotTimeValid
        [void]$chain.Build($Certificate)
        if ($chain.ChainElements.Count -lt 2) { throw "The signer lacks a public CA chain: $Path" }
        $rootThumbprint = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Thumbprint
        $trusted = $false
        $installedRoot = $false
        foreach ($location in @(
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        )) {
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('AuthRoot', $location)
            try {
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                if (@($store.Certificates | Where-Object { $_.Thumbprint -eq $rootThumbprint }).Count -gt 0) { $trusted = $true }
            } finally { $store.Close() }
            $rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', $location)
            try {
                $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                if (@($rootStore.Certificates | Where-Object { $_.Thumbprint -eq $rootThumbprint }).Count -gt 0) { $installedRoot = $true }
            } finally { $rootStore.Close() }
        }
        if (-not $trusted -and -not ($installedRoot -and $rootThumbprint -in $WinsProducerPinnedMicrosoftRoots)) {
            throw "The signer does not terminate in AuthRoot or an explicitly pinned Microsoft system root: $Path"
        }
    } finally { $chain.Dispose() }
}

# Committed publisher identity, the same CN and O that
# tools/windows_cross_store_artifact_gate.py enforces at upload
# (AUTHENTICODE_LEAF_CN/AUTHENTICODE_LEAF_O). The environment subject regex
# and thumbprint still apply; this is an extra pin, not a replacement.
$WindowsAuthenticodePublisherName = "WIN'S VPN INC."
function Assert-WinsAuthenticodePublisherIdentity {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $flags = [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseNewLines -bor
        [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::DoNotUseQuotes
    $rdns = @($Certificate.SubjectName.Decode($flags) -split "`r?`n" | Where-Object { $_ -ne '' })
    $cn = @($rdns | Where-Object { $_.StartsWith('CN=', [StringComparison]::Ordinal) } | ForEach-Object { $_.Substring(3) })
    $org = @($rdns | Where-Object { $_.StartsWith('O=', [StringComparison]::Ordinal) } | ForEach-Object { $_.Substring(2) })
    # A control character inside an attribute value (for example a CN holding
    # a line break and a fake O=) would forge an extra decoded line. -cne is a
    # culture-aware compare that ignores zero-width, soft-hyphen and BOM
    # characters, so the names are compared ordinally.
    if ($Certificate.Subject -match '[\x00-\x1f\x7f]' -or
        $cn.Count -ne 1 -or -not [string]::Equals($cn[0], $WindowsAuthenticodePublisherName, [StringComparison]::Ordinal) -or
        $org.Count -ne 1 -or -not [string]::Equals($org[0], $WindowsAuthenticodePublisherName, [StringComparison]::Ordinal)) {
        throw "Authenticode signer of $Path is not the reviewed $WindowsAuthenticodePublisherName publisher: $($Certificate.Subject)"
    }
}

function Get-WinsProducerCertificateStoreSelector {
    # Certificate-store selection by thumbprint never puts a secret on the
    # SignTool command line.
    param([Parameter(Mandatory = $true)][string]$SignerPattern)
    $thumbprint = (($env:WINS_WINDOWS_SIGN_CERT_SHA1 + '') -replace '\s', '').ToUpperInvariant()
    if ($thumbprint -notmatch '^[A-F0-9]{40}$') {
        throw 'WINS_WINDOWS_SIGN_CERT_SHA1 must be a 40-character certificate thumbprint.'
    }
    $storeScope = if ($env:WINS_WINDOWS_SIGN_CERT_STORE) { [string]$env:WINS_WINDOWS_SIGN_CERT_STORE } else { 'CurrentUser' }
    if ($storeScope -cnotin @('CurrentUser', 'LocalMachine')) {
        throw 'WINS_WINDOWS_SIGN_CERT_STORE must be CurrentUser or LocalMachine.'
    }
    $location = [System.Security.Cryptography.X509Certificates.StoreLocation]::$storeScope
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', $location)
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $found = @($store.Certificates | Where-Object { $_.Thumbprint -eq $thumbprint })
        if ($found.Count -ne 1) {
            throw "WINS_WINDOWS_SIGN_CERT_SHA1 must resolve to exactly one certificate in $storeScope\My."
        }
        Assert-WinsProducerCodeSigningCertificate -Certificate $found[0] `
            -SignerPattern $SignerPattern -SourceLabel 'WINS_WINDOWS_SIGN_CERT_SHA1'
        Assert-WinsProducerTrustedRootChain -Certificate $found[0] -Path 'WINS_WINDOWS_SIGN_CERT_SHA1'
    } finally {
        $store.Close()
    }
    $selector = @('/s', 'My', '/sha1', $thumbprint)
    if ($storeScope -ceq 'LocalMachine') { $selector = @('/sm') + $selector }
    return $selector
}

function New-WinsProducerSignArgumentList {
    param(
        [Parameter(Mandatory = $true)][string]$Timestamp,
        [Parameter(Mandatory = $true)][string[]]$SignerArguments,
        [Parameter(Mandatory = $true)][string]$Target
    )
    Assert-WinsProducerApprovedTimestampUrl -Value $Timestamp
    $list = @('sign', '/v', '/fd', 'SHA256', '/tr', $Timestamp, '/td', 'SHA256', '/d', "Win's VPN") +
        @($SignerArguments) + @($Target)
    foreach ($argument in $list) {
        if ([string]::IsNullOrWhiteSpace([string]$argument)) { throw 'Empty SignTool argument is forbidden.' }
        if ([string]$argument -match '[\x00-\x1f\x7f]') { throw 'SignTool argument contains a control character.' }
    }
    foreach ($forbidden in @('/as', '/f', '/p', '/ac', '/a')) {
        if ($list -contains $forbidden) {
            throw "SignTool argument $forbidden is forbidden for release signing."
        }
    }
    if ([string]$list[$list.Count - 1] -cne $Target) {
        throw 'SignTool target must be the final argument.'
    }
    return $list
}

function Get-WinsProducerCertificateSha256 {
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (-join ($sha.ComputeHash($Certificate.RawData) | ForEach-Object { $_.ToString('x2') }))
    } finally { $sha.Dispose() }
}

function Get-WinsProducerAuthenticodeLeafPin {
    # Optional pin shared with build_installer.ps1:
    # tools/toolchain-pins.json tools.windows_authenticode.leaf_sha256. Absent
    # means the subject regex, EKU, chain, timestamp and signtool checks apply
    # without a leaf pin; present means every signature must use that leaf.
    param([Parameter(Mandatory = $true)][string]$RepoRoot)
    $pinPath = Join-Path (Join-Path $RepoRoot 'tools') 'toolchain-pins.json'
    if (-not (Test-Path -LiteralPath $pinPath -PathType Leaf)) { return '' }
    try { $pins = Get-Content -LiteralPath $pinPath -Raw | ConvertFrom-Json }
    catch { throw "tools/toolchain-pins.json is not valid JSON: $($_.Exception.Message)" }
    $node = $pins
    foreach ($key in @('tools', 'windows_authenticode', 'leaf_sha256')) {
        if ($null -eq $node -or $node -isnot [System.Management.Automation.PSCustomObject]) { return '' }
        $property = $node.PSObject.Properties[$key]
        if ($null -eq $property) { return '' }
        $node = $property.Value
    }
    $value = [string]$node
    if ([string]::IsNullOrEmpty($value)) { return '' }
    if ($value -cnotmatch '^[0-9a-f]{64}$') {
        throw 'tools.windows_authenticode.leaf_sha256 in tools/toolchain-pins.json must be 64 lowercase hex characters.'
    }
    return $value
}

function Assert-WinsProducerSignature {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$SignerPattern,
        [Parameter(Mandatory = $true)][string]$SignTool,
        [AllowEmptyString()][string]$ExpectedLeafSha256 = ''
    )
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $subject = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '' }
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $subject -notmatch $SignerPattern) {
        throw "Product signature verification failed for $Path. Status=$($signature.Status); signer=$subject"
    }
    if ($signature.SignerCertificate.Subject -eq $signature.SignerCertificate.Issuer) {
        throw "A self-signed certificate is forbidden for production distribution: $Path"
    }
    Assert-WinsProducerTrustedRootChain -Certificate $signature.SignerCertificate -Path $Path
    Assert-WinsAuthenticodePublisherIdentity -Certificate $signature.SignerCertificate -Path $Path
    $leafSha256 = Get-WinsProducerCertificateSha256 -Certificate $signature.SignerCertificate
    if (-not [string]::IsNullOrEmpty($ExpectedLeafSha256) -and $leafSha256 -cne $ExpectedLeafSha256) {
        throw "Authenticode leaf certificate of $Path does not match tools.windows_authenticode.leaf_sha256 (expected $ExpectedLeafSha256, actual $leafSha256)."
    }
    if (-not $signature.TimeStamperCertificate) {
        throw "The Authenticode signature on $Path is missing a trusted timestamp."
    }
    $verifyOutput = & $SignTool verify /pa /all /v /tw $Path 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or
        $verifyOutput -notmatch 'Successfully verified' -or
        $verifyOutput -notmatch '(Timestamp Verified by:|The signature is timestamped|Signing time:)') {
        throw "SignTool policy/timestamp verification failed for $Path. $verifyOutput"
    }
    return [ordered]@{
        signer_subject = [string]$subject
        signer_leaf_sha256 = $leafSha256
        timestamp_verified = $true
    }
}

function Invoke-WinsProducerSigning {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Signing
    )
    $signArgs = New-WinsProducerSignArgumentList -Timestamp ([string]$Signing.TimestampUrl) `
        -SignerArguments @($Signing.SignerArguments) -Target $Path
    & ([string]$Signing.SignTool) @signArgs | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Authenticode signing failed for $Path."
    }
    return (Assert-WinsProducerSignature -Path $Path -SignerPattern ([string]$Signing.SignerPattern) `
        -SignTool ([string]$Signing.SignTool) -ExpectedLeafSha256 ([string]$Signing.LeafSha256Pin))
}

function Resolve-WinsProducerSigningConfiguration {
    # Returns $null for an unsigned rehearsal (no signing identity configured)
    # or the resolved SignTool, signer arguments, timestamp URL and signer regex.
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][ValidateSet('x64', 'arm64')][string]$Architecture,
        [switch]$RequireSigning
    )
    if (-not [string]::IsNullOrWhiteSpace(($env:WINS_WINDOWS_SIGN_PFX + '')) -or
        -not [string]::IsNullOrWhiteSpace(($env:WINS_WINDOWS_SIGN_PFX_PASSWORD + ''))) {
        throw 'PFX command-line signing (WINS_WINDOWS_SIGN_PFX/WINS_WINDOWS_SIGN_PFX_PASSWORD) is disabled for a signed release. Configure WINS_WINDOWS_ARTIFACT_SIGNING_METADATA or WINS_WINDOWS_SIGN_CERT_SHA1 instead.'
    }
    $timestampUrl = $WinsProducerDefaultTimestampUrl
    if (-not [string]::IsNullOrWhiteSpace(($env:WINS_WINDOWS_TIMESTAMP_URL + ''))) {
        $timestampUrl = ($env:WINS_WINDOWS_TIMESTAMP_URL + '').Trim()
    }
    Assert-WinsProducerApprovedTimestampUrl -Value $timestampUrl
    $artifactMetadata = ($env:WINS_WINDOWS_ARTIFACT_SIGNING_METADATA + '').Trim()
    $thumbprintConfigured = -not [string]::IsNullOrWhiteSpace(($env:WINS_WINDOWS_SIGN_CERT_SHA1 + ''))
    if (-not $artifactMetadata -and -not $thumbprintConfigured) {
        if ($RequireSigning) {
            throw 'Windows release signing is required. Configure WINS_WINDOWS_ARTIFACT_SIGNING_METADATA or WINS_WINDOWS_SIGN_CERT_SHA1.'
        }
        return $null
    }
    if ($artifactMetadata -and $thumbprintConfigured) {
        throw 'Configure Artifact Signing metadata or a certificate-store identity, not both.'
    }
    $signerPattern = ($env:WINS_WINDOWS_SIGNER_SUBJECT_REGEX + '')
    if ([string]::IsNullOrWhiteSpace($signerPattern)) {
        throw 'WINS_WINDOWS_SIGNER_SUBJECT_REGEX is required for a signed release.'
    }
    if ($artifactMetadata) {
        $metadataPath = Resolve-WinsProducerArtifactSigningMetadataPath -Path $artifactMetadata -RepoRoot $RepoRoot
        $dlib = Find-WinsProducerArtifactSigningDlib -Architecture $Architecture
        if (-not $dlib) {
            throw 'Microsoft Artifact Signing Client Tools were not found under an approved Program Files root. Install Microsoft.Azure.ArtifactSigningClientTools.'
        }
        $signerArguments = @('/dlib', $dlib, '/dmdf', $metadataPath)
        $timestampUrl = $WinsProducerArtifactSigningTimestampUrl
        $mode = 'artifact-signing'
    } else {
        $signerArguments = @(Get-WinsProducerCertificateStoreSelector -SignerPattern $signerPattern)
        $mode = 'certificate-store'
    }
    Assert-WinsProducerApprovedTimestampUrl -Value $timestampUrl
    if (@($signerArguments).Count -eq 0) {
        throw 'Windows release signing resolved no signer arguments.'
    }
    $leafPin = Get-WinsProducerAuthenticodeLeafPin -RepoRoot $RepoRoot
    $signTool = Find-WinsProducerSignTool -Architecture $Architecture
    if (-not $signTool) {
        throw 'SignTool was not found under an approved Windows SDK root. Install the Windows SDK.'
    }
    return [pscustomobject]@{
        Mode = $mode
        SignTool = [string]$signTool
        SignerArguments = @($signerArguments)
        TimestampUrl = $timestampUrl
        SignerPattern = $signerPattern
        LeafSha256Pin = $leafPin
    }
}
# END-WINDOWS-PRODUCER-AUTHENTICODE-POLICY

function Get-Sha256 { param([string]$Path) (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }

# Test-PeMachine reads the COFF header rather than trusting a filename. For the
# ARM64 package every payload PE must be machine 0xAA64 (AArch64).
function Test-PeMachine {
    param([string]$Path, [int]$Expected = 0xAA64)
    $fs = [System.IO.File]::OpenRead($Path)
    try {
        $br = New-Object System.IO.BinaryReader($fs)
        if ($br.ReadUInt16() -ne 0x5A4D) { return $false }   # MZ
        $fs.Position = 0x3C
        $peOffset = $br.ReadUInt32()
        $fs.Position = $peOffset
        if ($br.ReadUInt32() -ne 0x00004550) { return $false } # PE\0\0
        return ($br.ReadUInt16() -eq $Expected)
    } finally { $fs.Dispose() }
}

function Test-FileContainsMarker {
    param([string]$Path, [string]$MarkerValue)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $text  = [System.Text.Encoding]::ASCII.GetString($bytes)
    return $text.IndexOf($MarkerValue, [StringComparison]::Ordinal) -ge 0
}

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
    throw "The WiX Toolset is not on PATH. Install it with: dotnet tool install --global wix"
}
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$Signing = Resolve-WinsProducerSigningConfiguration -RepoRoot $RepoRoot -Architecture 'arm64' `
    -RequireSigning:$RequireCodeSigning
if ($null -eq $Signing) {
    Write-Warning 'No Windows signing identity is configured; this is an unsigned rehearsal MSI and its receipt records authenticode_status unsigned.'
}
$signedPayloads = [System.Collections.Generic.List[object]]::new()

if ([string]::IsNullOrWhiteSpace($StageDir)) {
    $StageDir = Join-Path ([System.IO.Path]::GetTempPath()) ("winn3msi-arm64-" + [Guid]::NewGuid().ToString('N'))
}
$payload = Join-Path $StageDir 'payload'
if (Test-Path -LiteralPath $payload) {
    throw "Refusing an existing ARM64 payload stage that could contain stale files: $payload"
}
New-Item -ItemType Directory -Force -Path $payload | Out-Null
New-Item -ItemType Directory -Force -Path $OutDir  | Out-Null

# ---- stage (ARM64 wintun comes from dependencies/wintun-arm64.dll) ----------
$sources = @(
    @{ Name = 'winn-datapath.exe';        From = (Join-Path $EngineDir       'winn-datapath.exe') },
    @{ Name = 'winsvpn_winn3_engine.exe'; From = (Join-Path $EngineDir       'winsvpn_winn3_engine.exe') },
    @{ Name = 'wintun.dll';               From = (Join-Path $DependenciesDir 'wintun-arm64.dll') }
)
foreach ($s in $sources) {
    if (-not (Test-Path -LiteralPath $s.From -PathType Leaf)) {
        throw "Missing required payload file: $($s.From)"
    }
    if ($s.Name -ceq 'wintun.dll') {
        $actual = Get-Sha256 $s.From
        if ($actual -cne $WintunExpectedSha256) {
            throw "Pinned wintun-arm64.dll SHA-256 $actual does not match reviewed ARM64 pin $WintunExpectedSha256."
        }
    }
    Copy-Item -LiteralPath $s.From -Destination (Join-Path $payload $s.Name) -Force
    Write-Step "staged $($s.Name)"
}

$blockedSymbols = @('.pdb', '.ilk', '.iobj', '.ipdb')
$symbolFiles = @(Get-ChildItem -LiteralPath $payload -Recurse -File -Force |
    Where-Object { $blockedSymbols -contains $_.Extension.ToLowerInvariant() })
if ($symbolFiles.Count -gt 0) {
    throw ("Winn v3 ARM64 MSI payload contains debug symbol files: " + ($symbolFiles.Name -join ', '))
}

# ---- Authenticode: first-party engines (pinned wintun.dll keeps its bytes) ----
if ($null -ne $Signing) {
    foreach ($engine in @('winn-datapath.exe', 'winsvpn_winn3_engine.exe')) {
        $enginePath = Join-Path $payload $engine
        $evidence = Invoke-WinsProducerSigning -Path $enginePath -Signing $Signing
        $signedPayloads.Add([ordered]@{
            name = $engine
            sha256 = (Get-Sha256 $enginePath)
            signer_subject = [string]$evidence.signer_subject
            signer_leaf_sha256 = [string]$evidence.signer_leaf_sha256
        })
        Write-Step "signed and verified $engine"
    }
}

# ---- the v3 carrier-completeness gate (all payload PEs must be AArch64) ----
$problems = @()
$datapath = Join-Path $payload 'winn-datapath.exe'
$relay    = Join-Path $payload 'winsvpn_winn3_engine.exe'
if (-not (Test-FileContainsMarker -Path $datapath -MarkerValue $Marker)) {
    $problems += "winn-datapath.exe contains no '$Marker' reference, so it does not carry Winn Protocol v3."
}
foreach ($nonCarrier in @($relay, (Join-Path $payload 'wintun.dll'))) {
    if (Test-FileContainsMarker -Path $nonCarrier -MarkerValue $Marker) {
        $problems += "$([IO.Path]::GetFileName($nonCarrier)) unexpectedly contains '$Marker'; only winn-datapath.exe is the Winn v3 carrier."
    }
}
foreach ($p in @($datapath, $relay, (Join-Path $payload 'wintun.dll'))) {
    if (-not (Test-PeMachine -Path $p -Expected $Arm64Machine)) {
        $problems += "$([IO.Path]::GetFileName($p)) is not PE32+ AArch64 (COFF machine 0xAA64)."
    }
}
if ($problems.Count -gt 0) {
    throw "Winn Protocol v3 carrier is not shippable for ARM64:`n - " + ($problems -join "`n - ")
}
Write-Step 'v3 carrier-completeness gate: PASS (AArch64)'

# ---- payload manifest ----------------------------------------------------
$entries = @()
foreach ($f in (Get-ChildItem -LiteralPath $payload -File | Sort-Object Name)) {
    $entries += [ordered]@{ name = $f.Name; bytes = $f.Length; sha256 = (Get-Sha256 $f.FullName) }
}
$manifest = [ordered]@{
    product      = "Win's VPN Winn Protocol v3 Engines"
    version      = $AppVersion
    built_utc    = (Get-Date).ToUniversalTime().ToString('o')
    architecture = 'arm64'
    files        = $entries
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Encoding ASCII (Join-Path $payload 'payload-manifest.json')
Write-Step "payload-manifest.json written for $($entries.Count) files"

# ---- build (arm64 arch) ---------------------------------------------------
$wxs = Join-Path $PSScriptRoot 'wix\winsvpn_winn3_payload_arm64.wxs'
$msi = Join-Path $OutDir "WinsVPN-Winn3-Engines-$AppVersion-arm64.msi"
Write-Step "wix build (arm64) -> $msi"
& wix build -arch arm64 `
    -d "AppVersion=$AppVersion" `
    -d "PayloadDir=$payload" `
    -d "LicensesDir=$((Resolve-Path $LicensesDir).Path)" `
    -o $msi $wxs
if ($LASTEXITCODE -ne 0) { throw "wix build failed with exit code $LASTEXITCODE" }
if (-not (Test-Path -LiteralPath $msi)) { throw "wix build reported success but produced no file at $msi" }

$msiSignature = $null
if ($null -ne $Signing) {
    $msiSignature = Invoke-WinsProducerSigning -Path $msi -Signing $Signing
    Write-Step "signed and verified $([IO.Path]::GetFileName($msi))"
}
$msiSigned = $null -ne $msiSignature
$msiAuthenticodeStatus = if ($msiSigned) { 'signed' } else { 'unsigned' }
$msiSigningMode = if ($msiSigned) { [string]$Signing.Mode } else { 'none' }
$msiSignerSubject = if ($msiSigned) { [string]$msiSignature.signer_subject } else { '' }
$msiSignerLeaf = if ($msiSigned) { [string]$msiSignature.signer_leaf_sha256 } else { '' }
$msiHash = Get-Sha256 $msi
Set-Content -Encoding ASCII "$msi.sha256" "$msiHash  $([IO.Path]::GetFileName($msi))"
$receipt = [ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-wix-winn3-engine-receipt-v1'
    architecture = 'arm64'
    complete_windows_product = $false
    missing_complete_product_payloads = @(
        'wins_vpn.exe',
        'wins_vpn_tunnel_service.exe',
        'winsvpn_awg_engine.exe',
        'awg.exe',
        'xray.exe',
        'amneziawg-arm64.exe',
        'VC_redist.arm64.exe',
        'amneziawg-arm64.msi'
    )
    store_upload_authorized = $false
    authenticode_verified = $msiSigned
    authenticode_status = $msiAuthenticodeStatus
    timestamp_verified = $msiSigned
    signing_mode = $msiSigningMode
    signer_subject = $msiSignerSubject
    signer_leaf_sha256 = $msiSignerLeaf
    signed_payloads = @($signedPayloads)
    winn_v3_primary = $true
    winn_v1_awg_then_xray = $false
    debug_symbols_excluded = $true
    private_symbol_custody_established = $false
    payload = @($entries)
    msi = [ordered]@{
        path = [IO.Path]::GetFileName($msi)
        sha256 = $msiHash
        bytes = [long](Get-Item -LiteralPath $msi).Length
    }
}
$receiptPath = "$msi.receipt.json"
if (Test-Path -LiteralPath $receiptPath) { Remove-Item -LiteralPath $receiptPath -Force }
$receiptTemp = "$receiptPath.tmp"
($receipt | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $receiptTemp -Encoding UTF8
[IO.File]::Move($receiptTemp, $receiptPath)
Write-Step "MSI: $msi"
Write-Step "bytes: $((Get-Item $msi).Length)"
Write-Step "sha256: $msiHash"
if ($msiSigned) {
    Write-Step 'WINN3 ARM64 MSI BUILD: SIGNED engine fragment (engines and MSI verified); not a complete Windows product'
} else {
    Write-Step 'WINN3 ARM64 MSI BUILD: UNSIGNED REHEARSAL engine fragment; not a complete Windows product'
}
