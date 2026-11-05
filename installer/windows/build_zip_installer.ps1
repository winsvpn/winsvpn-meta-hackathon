#Requires -Version 5.1
<#
build_zip_installer.ps1 - assemble the no-Inno distribution route.

The ZIP distribution route is disabled until an authenticated bootstrap can
verify the archive before invoking its PowerShell installer. -SkipZip remains
available for isolated payload staging and tests.

This is the build side of the "plain zip + PowerShell installer" route that
exists so the Windows product can be packaged WITHOUT Inno Setup on the build
host. It needs nothing but what Windows 10/11 and this repository already
provide: the in-box System.IO.Compression ZipArchive writer for a
deterministic zip, Get-FileHash for the manifest, and the Go/Git-Bash
builders for the two v3 engines (which live on the same host the existing
build_installer.ps1 already requires). Compress-Archive is not used: it is
non-deterministic, glob-expanding, and follows reparse points.

WHAT IT PRODUCES, and the parity it keeps with build_installer.ps1/winsvpn.iss:

  1. A payload stage identical in shape to what build_installer.ps1 stages for
     ISCC: the Flutter Release runner, the tunnel service, the third-party
     dependencies, and the licence texts.
  2. payload-manifest.json binding EVERY staged file to its exact SHA-256 and
     byte count. install_winsvpn_zip.ps1 verifies every entry against this
     manifest before it changes anything. This is the zip-route equivalent of
     Inno's GetSHA256OfFile / the existing WinsVPN-Setup.exe.payload-manifest.json.
  3. The v3 carrier-completeness gate, byte-for-byte the same decision as
     Write-Winn3CarrierCompleteness in build_installer.ps1: winn-datapath.exe
     must CONTAIN 'winsvpn.local/winnprotocol/winn3' by raw-byte content (not
     by existence) and winsvpn_winn3_engine.exe must be staged under its exact
     resolved name. Missing or non-carrying halves make the build FATAL, the
     same way the Inno build is fatal.
  4. A deterministic ZipArchive (no 7-Zip, no Compress-Archive, no
     third-party compressor) whose members are ordinal-sorted, canonical,
     regular files with a fixed DOS timestamp. Contents are re-hashed
     against the manifest after creation (round-trip), then the extracted
     payload is re-audited for x64/arm64 identity, the first-party
     engine-then-product signing state, Winn v3 primary plus Winn v1 AWG then
     Xray fallback, and forbidden bytes. A .sha256 of the zip is written
     for out-of-band publication. Partial zip/receipt outputs are deleted
     if any later gate fails.
  5. Authenticode: when WINS_WINDOWS_ARTIFACT_SIGNING_METADATA or
     WINS_WINDOWS_SIGN_CERT_SHA1 is set, the first-party engines and then
     the product binaries are signed and verified with the same policy as
     build_installer.ps1 (approved-root Microsoft-signed SignTool, signer
     subject regex, Microsoft root chain, approved RFC 3161 timestamp,
     signtool verify /pa). Pinned third-party dependencies keep their exact
     reviewed bytes. Without credentials the ZIP is an unsigned rehearsal and
     its receipt says so; -RequireCodeSigning refuses that case.

The privileged steps of install_winsvpn_zip.ps1 (VC runtime, AmneziaWG
MSI, tunnel-manager service) are NOT executed by this script and never should
be - those modify the target machine and are the owner's call, exactly as
running the Inno Setup wizard is.

EXAMPLE (after the v3 engine lane has produced the two engines, or with
-EngineDir pointing at a dir containing winn-datapath.exe and
winsvpn_winn3_engine.exe):

    powershell -ExecutionPolicy Bypass -File build_zip_installer.ps1 `
      -ReleaseDir C:\WinsVPNBuild\...\Release `
      -DependenciesDir C:\WinsVPNBuild\...\payload-stage `
      -EngineDir C:\Users\owner\winsvpn-engines `
      -AppVersion 1.0.17.34
#>
[CmdletBinding()]
param(
    [string]$ReleaseDir = (Join-Path $PSScriptRoot '..\..\build\windows\x64\runner\Release'),
    [string]$DependenciesDir = (Join-Path $PSScriptRoot 'dependencies'),
    [string]$LicensesDir = (Join-Path $PSScriptRoot 'licenses'),
    [string]$EngineDir = (Join-Path $PSScriptRoot '..\..\build\windows\winn3\x64'),
    [string]$OutDir = (Join-Path $PSScriptRoot '..\..\build\windows-installer'),
    [string]$AppVersion = '0.0.0',
    [string]$ThirdPartiesDoc = (Join-Path (Join-Path $PSScriptRoot '..\..') 'docs\THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md'),
    [ValidateSet('x64', 'arm64')]
    [string]$TargetArchitecture = 'x64',
    [switch]$RequireCodeSigning,
    [switch]$SkipZip
)

$ErrorActionPreference = 'Stop'
if (-not $SkipZip) {
    throw 'The ZIP installer has no authenticated bootstrap. Use the signed Inno installer for distribution; -SkipZip remains available for isolated payload staging.'
}
$Marker = 'winsvpn.local/winnprotocol/winn3'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$ZipX86PeMachine = [uint16]0x014c
$ZipX64PeMachine = [uint16]0x8664
$ZipArm64PeMachine = [uint16]0xAA64
$ZipX64DependencyPins = [ordered]@{
    'VC_redist.x64.exe' = [ordered]@{ sha256 = 'cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b'; dest = 'temp'; source = 'VC_redist.x64.exe' }
    'amneziawg-amd64.msi' = [ordered]@{ sha256 = 'a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b'; dest = 'temp'; source = 'amneziawg-amd64.msi' }
    'amneziawg.exe' = [ordered]@{ sha256 = '12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41'; dest = 'app'; source = 'amneziawg.exe' }
    'awg.exe' = [ordered]@{ sha256 = '272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12'; dest = 'app'; source = 'awg.exe' }
    'wintun.dll' = [ordered]@{ sha256 = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'; dest = 'app'; source = 'wintun.dll' }
    'xray.exe' = [ordered]@{ sha256 = 'fffbe5dd92fe13cfc6ab72dead66ddd92c09b2bb27a85592e8e6f4ec27ee1224'; dest = 'app'; source = 'xray.exe' }
}
$ZipArm64DependencyPins = [ordered]@{
    'VC_redist.arm64.exe' = [ordered]@{ sha256 = '5139e1440c3a20b92153a4db561c069a0175aaf76c276c3e5b6f56099edcf4b0'; dest = 'temp'; source = 'VC_redist.arm64.exe' }
    'amneziawg-arm64.msi' = [ordered]@{ sha256 = '3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa'; dest = 'temp'; source = 'amneziawg-arm64.msi' }
    'awg.exe' = [ordered]@{ sha256 = '3106950ce9f0b93eb4c3f7975cbf44af41623ffeed630f19909730cd16d36e43'; dest = 'app'; source = 'awg-arm64.exe' }
    'wintun.dll' = [ordered]@{ sha256 = 'f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80'; dest = 'app'; source = 'wintun-arm64.dll' }
    'xray.exe' = [ordered]@{ sha256 = 'c6edaa0e535b81d8c4c4a25378e6717b4406a8a0d72b751f4d0a1f171817e7af'; dest = 'app'; source = 'xray-arm64.exe' }
}
$ZipX64DependencyContract = [ordered]@{
    amneziawg_client_version = '3.1.0'
    amneziawg_msi_sha256 = 'a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b'
    amneziawg_msi_runtime_amneziawg_sha256 = 'ba446f6e1a4093e43a65d6ff45f4b8c7b6485dc419327eedaa1a218549740e3a'
    amneziawg_maintenance_helper_sha256 = '12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41'
    amneziawg_source_commit = 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968'
    amneziawg_engine_version = 'v3.1.20260828'
    amneziawg_engine_commit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'
    awg_exe_sha256 = '272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12'
    wintun_version = '0.14.1'
    wintun_dll_sha256 = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
    xray_version = 'v26.9.30'
    xray_source_commit = 'b26a91de4f3294e26a0ad0a970b81a386a41f789'
    xray_exe_sha256 = 'fffbe5dd92fe13cfc6ab72dead66ddd92c09b2bb27a85592e8e6f4ec27ee1224'
    xray_go_version = '1.27.1'
    vc_redist_version = '14.44.35211.0'
    vc_redist_sha256 = 'cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b'
}
$ZipArm64DependencyContract = [ordered]@{
    amneziawg_client_version = '3.1.0'
    amneziawg_msi_sha256 = '3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa'
    amneziawg_msi_runtime_amneziawg_sha256 = '25fa81103152699bf416f394059b40d447001c3d0dea5ef889a9426f315e4c0a'
    amneziawg_source_commit = 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968'
    amneziawg_engine_version = 'v3.1.20260828'
    amneziawg_engine_commit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'
    awg_exe_sha256 = '3106950ce9f0b93eb4c3f7975cbf44af41623ffeed630f19909730cd16d36e43'
    wintun_version = '0.14.1'
    wintun_dll_sha256 = 'f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80'
    xray_version = 'v26.9.30'
    xray_source_commit = 'b26a91de4f3294e26a0ad0a970b81a386a41f789'
    xray_exe_sha256 = 'c6edaa0e535b81d8c4c4a25378e6717b4406a8a0d72b751f4d0a1f171817e7af'
    xray_go_version = '1.27.1'
    vc_redist_version = '14.44.35211.0'
    vc_redist_sha256 = '5139e1440c3a20b92153a4db561c069a0175aaf76c276c3e5b6f56099edcf4b0'
}
# Default to the reviewed x64 pin set so source-contract tests can locate the
# assignment. Initialize-ZipArchitectureContract rebinds these for arm64.
$ZipDependencyPins = $ZipX64DependencyPins
$ZipDependencyContract = $ZipX64DependencyContract
$ZipPeMachine = $ZipX64PeMachine
$ZipArchitecture = 'x64'
$ZipAwgGoTarget = 'windows-amd64'
$ZipHelperSourceName = 'amneziawg.exe'
$AmneziaWgHelperProvenance = 'amneziawg.exe.provenance.json'
$script:ZipVcRedistLeaf = 'VC_redist.x64.exe'
$ZipLicenseFiles = @(
    'Wintun-Prebuilt-Binaries-License.txt',
    'Xray-core-MPL-2.0.txt',
    'amneziawg-MIT.txt',
    'amneziawg-tools-GPL-2.0.txt'
)
$ZipFirstPartyEnginePaths = @(
    'winn-datapath.exe',
    'winsvpn_winn3_engine.exe',
    'winsvpn_awg_engine.exe',
    'dependencies/xray.exe'
)
$ZipFirstPartyProductPaths = @(
    'wins_vpn.exe',
    'wins_vpn_tunnel_service.exe'
)
$script:ZipPartialOutputPaths = New-Object 'System.Collections.Generic.List[string]'
$script:ZipSigning = $null
$script:ZipSignatureEvidence = [System.Collections.Generic.List[object]]::new()
$ForbiddenZipPayloadLeafNames = @(
    'mullvad-split-tunnel.sys',
    'mullvad-split-tunnel.cat',
    'mullvad-split-tunnel.inf',
    'mullvad-split-tunnel-MPL-2.0.txt'
)
$ForbiddenZipPayloadLeafPrefixes = @('mullvad-split-tunnel')
$ForbiddenZipPayloadExtensions = @('.sys', '.cat', '.inf')
$ForbiddenZipPayloadPaths = @('licenses/README.txt')
$ForbiddenZipPayloadSha256 = @(
    '10cf25bbcfe51fd663a1fec88a98e9b858f3a579589bb2ec496b66e4fdd1b201',
    'c599926a0327d7ae06b534f4cd039db30392e1897bb9d03e4fec3631744a4e6d',
    '3dd5905e5fb98d61a942a33e8c9a5ba07c3a2de1e4f319e1fec3e54df6591608',
    '6af8b3bfe5aa095d5276187558c7c7d3a3e0c174b34406cd6c4b3f8e6ffa6534',
    'c3d27636739ebaa7dde369d113347de83e3e2173b8a512bb8863d11b148de7ce',
    '0bfdb044e40535dabbeb3620b655c1563714b3a6f3231d3492c972c6e8dea6f1',
    'faeba3cc7a3fb890ec25497b192d860683915e46061bf6588268fd2ddcdc6342',
    '56ab6a25ca2f4dcd0303567815a64f6d09835e2cceb3958020185772c4871c1e'
)
$ForbiddenZipPayloadFingerprints = @(
    @{
        sha256 = '10cf25bbcfe51fd663a1fec88a98e9b858f3a579589bb2ec496b66e4fdd1b201'
        length = 98400
        offset = 102
        marker = '756e20696e20444f53206d6f64652e0d0d0a2400000000000000504500006486'
    }
    @{
        sha256 = 'c599926a0327d7ae06b534f4cd039db30392e1897bb9d03e4fec3631744a4e6d'
        length = 12350
        offset = 64
        marker = '07d2300c060a2b0601040182370c01010410d41414c82cf2934592eb09d9eb5e'
    }
    @{
        sha256 = '3dd5905e5fb98d61a942a33e8c9a5ba07c3a2de1e4f319e1fec3e54df6591608'
        length = 1796
        offset = 690
        marker = '0a254d616e7566616374757265724e616d65253d5374616e646172642c4e5461'
    }
    @{
        sha256 = '6af8b3bfe5aa095d5276187558c7c7d3a3e0c174b34406cd6c4b3f8e6ffa6534'
        length = 101984
        offset = 102
        marker = '756e20696e20444f53206d6f64652e0d0d0a24000000000000005045000064aa'
    }
    @{
        sha256 = 'c3d27636739ebaa7dde369d113347de83e3e2173b8a512bb8863d11b148de7ce'
        length = 12158
        offset = 64
        marker = '0716300c060a2b0601040182370c010104107031a5612275734e8f257e09ec3d'
    }
    @{
        sha256 = '0bfdb044e40535dabbeb3620b655c1563714b3a6f3231d3492c972c6e8dea6f1'
        length = 1796
        offset = 690
        marker = '0a254d616e7566616374757265724e616d65253d5374616e646172642c4e5441'
    }
)

function Write-Step { param([string]$Message) Write-Host "[build_zip_installer] $Message" }

function Initialize-ZipArchitectureContract {
    param([Parameter(Mandatory = $true)][ValidateSet('x64', 'arm64')][string]$Architecture)
    $script:ZipArchitecture = $Architecture
    if ($Architecture -ceq 'arm64') {
        $script:ZipPeMachine = $ZipArm64PeMachine
        $script:ZipDependencyPins = $ZipArm64DependencyPins
        $script:ZipDependencyContract = $ZipArm64DependencyContract
        $script:ZipAwgGoTarget = 'windows-arm64'
        $script:ZipHelperSourceName = 'amneziawg-arm64.exe'
        $script:AmneziaWgHelperProvenance = 'amneziawg-arm64.exe.provenance.json'
        $script:ZipVcRedistLeaf = 'VC_redist.arm64.exe'
    } else {
        $script:ZipPeMachine = $ZipX64PeMachine
        $script:ZipDependencyPins = $ZipX64DependencyPins
        $script:ZipDependencyContract = $ZipX64DependencyContract
        $script:ZipAwgGoTarget = 'windows-amd64'
        $script:ZipHelperSourceName = 'amneziawg.exe'
        $script:AmneziaWgHelperProvenance = 'amneziawg.exe.provenance.json'
        $script:ZipVcRedistLeaf = 'VC_redist.x64.exe'
    }
}

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

function Assert-ZipWindowsHostMatchesTarget {
    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    )) {
        return
    }
    $osArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $normalizedHost = switch -Regex ($osArch) {
        '^(?i:X64|Amd64)$' { 'x64' }
        '^(?i:Arm64)$' { 'arm64' }
        default { throw "Unsupported Windows host architecture '$osArch'." }
    }
    if ($normalizedHost -cne $script:ZipArchitecture) {
        throw ("A Windows $($script:ZipArchitecture) ZIP cannot be produced on a $normalizedHost host. " +
            'Flutter build windows has no target-platform override. Mixing host output with a different dependency architecture is refused.')
    }
}

function Assert-SafeZipPathArgument {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "$Name is empty." }
    if ($Path -cne $Path.Trim()) { throw "$Name has surrounding whitespace." }
    foreach ($character in $Path.ToCharArray()) {
        if ([int]$character -lt 32 -or [int]$character -eq 127) {
            throw "$Name contains a control character."
        }
    }
    if ($Path.IndexOfAny([char[]]'`"*|?<>') -ge 0) {
        throw "$Name contains a forbidden path or argument character."
    }
}

function Reset-ZipPartialOutputs {
    $script:ZipPartialOutputPaths = New-Object 'System.Collections.Generic.List[string]'
}

function Register-ZipPartialOutput {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if ($null -eq $script:ZipPartialOutputPaths) { Reset-ZipPartialOutputs }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not $script:ZipPartialOutputPaths.Contains($full)) {
        [void]$script:ZipPartialOutputPaths.Add($full)
    }
}

function Remove-ZipPartialOutputs {
    if ($null -eq $script:ZipPartialOutputPaths) { return }
    foreach ($path in @($script:ZipPartialOutputPaths)) {
        if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
    $script:ZipPartialOutputPaths.Clear()
}

function Assert-RegularContainer {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    $root = Get-ValidatedContainerRoot -Root $Path -Purpose $Purpose
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw "$Purpose root is missing: $root"
    }
    $item = Get-Item -LiteralPath $root -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Purpose root is a reparse point: $root"
    }
}

function Assert-RegularLeafFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "$Purpose path is empty." }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "Missing required ${Purpose}: $full"
    }
    $item = Get-Item -LiteralPath $full -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Purpose is a reparse point: $full"
    }
    $parent = [IO.Path]::GetDirectoryName($full)
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        Assert-NoReparsePointChain -Root $parent -FullPath $full -Purpose $Purpose
    }
}

function Assert-Dir {
    param([string]$Path, [string]$What)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Missing required ${What}: '${Path}'"
    }
    Assert-RegularContainer -Path $Path -Purpose $What
}

function Test-FileContainsMarker {
    # Raw-byte marker scan. Codepage 28591 is a 1:1 byte->char mapping, the
    # PowerShell equivalent of `strings | grep`; measuring the ARTIFACT, not the
    # source that produced it.
    param([string]$Path, [string]$MarkerValue)
    try {
        $text = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($Path))
        return $text.IndexOf($MarkerValue, [StringComparison]::Ordinal) -ge 0
    } catch {
        Write-Warning "Could not scan $Path for '$MarkerValue': $($_.Exception.Message)"
        return $false
    }
}

function Sha256-Of {
    param([string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-PeCoffMachine {
    param([string]$Path)
    $fs = [IO.File]::OpenRead($Path)
    try {
        if ($fs.Length -lt 64) { return [uint16]0 }
        $br = New-Object IO.BinaryReader($fs)
        if ($br.ReadUInt16() -ne 0x5A4D) { return [uint16]0 }
        $fs.Position = 0x3C
        $peOffset = $br.ReadUInt32()
        if ($peOffset -gt ($fs.Length - 26)) { return [uint16]0 }
        $fs.Position = $peOffset
        if ($br.ReadUInt32() -ne 0x00004550) { return [uint16]0 }
        $machine = $br.ReadUInt16()
        $sectionCount = $br.ReadUInt16()
        $fs.Position = $peOffset + 20
        $optionalHeaderSize = $br.ReadUInt16()
        if ($sectionCount -eq 0 -or $optionalHeaderSize -lt 2 -or
            ($peOffset + 24 + $optionalHeaderSize) -gt $fs.Length) { return [uint16]0 }
        $fs.Position = $peOffset + 24
        $optionalMagic = $br.ReadUInt16()
        $pe32Plus = [uint16]0x020b
        $pe32 = [uint16]0x010b
        if (($machine -eq $ZipX64PeMachine -and $optionalMagic -ne $pe32Plus) -or
            ($machine -eq $ZipArm64PeMachine -and $optionalMagic -ne $pe32Plus) -or
            ($machine -eq $ZipX86PeMachine -and $optionalMagic -ne $pe32)) { return [uint16]0 }
        return $machine
    } finally { $fs.Dispose() }
}

function Get-PeCertificateTableSize {
    param([Parameter(Mandatory = $true)][string]$Path)
    $fs = [IO.File]::OpenRead($Path)
    try {
        if ($fs.Length -lt 64) { return [uint32]0 }
        $br = New-Object IO.BinaryReader($fs)
        if ($br.ReadUInt16() -ne 0x5A4D) { return [uint32]0 }
        $fs.Position = 0x3C
        $peOffset = $br.ReadUInt32()
        if ($peOffset -gt ($fs.Length - 26)) { return [uint32]0 }
        $fs.Position = $peOffset
        if ($br.ReadUInt32() -ne 0x00004550) { return [uint32]0 }
        [void]$br.ReadUInt16()
        [void]$br.ReadUInt16()
        $fs.Position = $peOffset + 20
        $optionalHeaderSize = $br.ReadUInt16()
        if ($optionalHeaderSize -lt 2 -or
            ($peOffset + 24 + $optionalHeaderSize) -gt $fs.Length) { return [uint32]0 }
        $fs.Position = $peOffset + 24
        $optionalMagic = $br.ReadUInt16()
        $pe32Plus = [uint16]0x020b
        $pe32 = [uint16]0x010b
        $directoryOffset = 0
        if ($optionalMagic -eq $pe32Plus) { $directoryOffset = 112 }
        elseif ($optionalMagic -eq $pe32) { $directoryOffset = 96 }
        else { return [uint32]0 }
        if ($optionalHeaderSize -lt ($directoryOffset + 40)) { return [uint32]0 }
        $fs.Position = $peOffset + 24 + $directoryOffset - 4
        $numberOfRvaAndSizes = $br.ReadUInt32()
        if ($numberOfRvaAndSizes -lt 5) { return [uint32]0 }
        $fs.Position = $peOffset + 24 + $directoryOffset + 32
        [void]$br.ReadUInt32()
        return $br.ReadUInt32()
    } finally { $fs.Dispose() }
}

function ConvertTo-CanonicalPayloadPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -cne $Path.Trim()) {
        throw 'Payload paths must be non-empty and have no surrounding whitespace.'
    }
    if ($Path -cne $Path.Normalize([Text.NormalizationForm]::FormC)) {
        throw "Payload path is not Unicode NFC-normalized: $Path"
    }
    if ($Path.Contains('\') -or $Path -match '^[A-Za-z]:' -or
        $Path.StartsWith('/') -or $Path.Contains(':')) {
        throw "Payload path must be relative and use forward slashes only: $Path"
    }
    $segments = @($Path -split '/')
    if ($segments.Count -eq 0) { throw "Payload path has no segments: $Path" }
    foreach ($segment in $segments) {
        if ([string]::IsNullOrWhiteSpace($segment) -or $segment -in @('.', '..')) {
            throw "Payload path contains an empty or dot segment: $Path"
        }
        if ($segment.EndsWith(' ') -or $segment.EndsWith('.') -or
            $segment.IndexOfAny([char[]]'<>"|?*:') -ge 0) {
            throw "Payload path contains a Windows-ambiguous segment: $Path"
        }
        foreach ($character in $segment.ToCharArray()) {
            if ([int]$character -lt 32) { throw "Payload path contains a control character: $Path" }
        }
        if ($segment -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') {
            throw "Payload path uses a reserved Windows device name: $Path"
        }
    }
    return ($segments -join '/')
}

function Assert-CanonicalReservedPayloadPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $canonical = ConvertTo-CanonicalPayloadPath -Path $Path
    $firstSegment = @($canonical -split '/')[0]
    foreach ($reserved in @('dependencies', 'licenses')) {
        if ($firstSegment.Equals($reserved, [StringComparison]::OrdinalIgnoreCase) -and
            -not $firstSegment.Equals($reserved, [StringComparison]::Ordinal)) {
            throw "Reserved payload prefix '$reserved' must use canonical lowercase spelling: $canonical"
        }
    }
    return $canonical
}

function Assert-ZipPayloadAllowed {
    param([Parameter(Mandatory = $true)][string]$Path)
    $canonical = Assert-CanonicalReservedPayloadPath -Path $Path
    $lastSlash = $canonical.LastIndexOf('/')
    $leaf = if ($lastSlash -ge 0) { $canonical.Substring($lastSlash + 1) } else { $canonical }
    foreach ($forbiddenPrefix in $ForbiddenZipPayloadLeafPrefixes) {
        if ($leaf.StartsWith($forbiddenPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Windows ZIP payload forbids the withdrawn kernel split-tunnel artifact: $canonical"
        }
    }
    foreach ($forbiddenLeaf in $ForbiddenZipPayloadLeafNames) {
        if ($leaf.Equals($forbiddenLeaf, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Windows ZIP payload forbids the withdrawn kernel split-tunnel artifact: $canonical"
        }
    }
    $extension = [IO.Path]::GetExtension($leaf).ToLowerInvariant()
    if ($extension -in $ForbiddenZipPayloadExtensions) {
        throw "Windows ZIP payload forbids kernel driver package files: $canonical"
    }
    foreach ($forbiddenPath in $ForbiddenZipPayloadPaths) {
        if ($canonical.Equals($forbiddenPath, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Windows ZIP payload forbids the obsolete kernel split-tunnel notice: $canonical"
        }
    }
    return $canonical
}

function Assert-ZipPayloadHashAllowed {
    param(
        [Parameter(Mandatory = $true)][string]$Sha256,
        [Parameter(Mandatory = $true)][string]$Path
    )
    foreach ($forbiddenHash in $ForbiddenZipPayloadSha256) {
        if ($Sha256.Equals($forbiddenHash, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Windows ZIP payload forbids withdrawn kernel split-tunnel bytes, including when renamed: $Path"
        }
    }
}

function Assert-ZipPayloadBytesAllowed {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Path
    )
    if ($null -eq $Bytes) { $Bytes = [byte[]]::new(0) }
    if (-not ('WinsZipForbiddenPayloadScan' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Security.Cryptography;
using System.Text;
public static class WinsZipForbiddenPayloadScan {
    public static string Sha256Hex(byte[] data) {
        using (var sha = SHA256.Create()) {
            return Hex(sha.ComputeHash(data ?? Array.Empty<byte>()));
        }
    }
    public static bool Contains(byte[] haystack, string markerHex, int markerOffset, int payloadLength, string sha256Hex) {
        if (haystack == null || payloadLength <= 0 || haystack.Length < payloadLength) return false;
        byte[] marker = HexToBytes(markerHex);
        if (marker.Length == 0 || haystack.Length < marker.Length) return false;
        int start = 0;
        while (true) {
            int idx = IndexOf(haystack, marker, start);
            if (idx < 0) return false;
            int payloadStart = idx - markerOffset;
            if (payloadStart >= 0 && payloadStart <= haystack.Length - payloadLength) {
                using (var sha = SHA256.Create()) {
                    if (Hex(sha.ComputeHash(haystack, payloadStart, payloadLength)).Equals(sha256Hex, StringComparison.OrdinalIgnoreCase)) {
                        return true;
                    }
                }
            }
            start = idx + 1;
        }
    }
    static int IndexOf(byte[] haystack, byte[] needle, int start) {
        if (start < 0) start = 0;
        int last = haystack.Length - needle.Length;
        for (int i = start; i <= last; i++) {
            int j = 0;
            for (; j < needle.Length; j++) {
                if (haystack[i + j] != needle[j]) break;
            }
            if (j == needle.Length) return i;
        }
        return -1;
    }
    static byte[] HexToBytes(string hex) {
        if (string.IsNullOrEmpty(hex) || (hex.Length & 1) != 0) throw new ArgumentException("hex");
        byte[] data = new byte[hex.Length / 2];
        for (int i = 0; i < data.Length; i++) data[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return data;
    }
    static string Hex(byte[] hash) {
        var sb = new StringBuilder(hash.Length * 2);
        for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
        return sb.ToString();
    }
}
'@
    }
    $sha256 = [WinsZipForbiddenPayloadScan]::Sha256Hex($Bytes)
    Assert-ZipPayloadHashAllowed -Sha256 $sha256 -Path $Path
    foreach ($fingerprint in $ForbiddenZipPayloadFingerprints) {
        if ([WinsZipForbiddenPayloadScan]::Contains(
                $Bytes,
                [string]$fingerprint.marker,
                [int]$fingerprint.offset,
                [int]$fingerprint.length,
                [string]$fingerprint.sha256
            )) {
            throw "Windows ZIP payload forbids withdrawn kernel split-tunnel bytes, including when renamed: $Path"
        }
    }
}

function Get-ValidatedContainerRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    if ([string]::IsNullOrWhiteSpace($Root)) { throw "$Purpose root is empty." }
    $rootFull = [IO.Path]::GetFullPath($Root)
    $pathRoot = [IO.Path]::GetPathRoot($rootFull)
    $rootTrimmed = $rootFull.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $pathRootTrimmed = $pathRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    if ([string]::IsNullOrEmpty($rootTrimmed) -or
        [string]::Equals($rootTrimmed, $pathRootTrimmed, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing a filesystem-root container for ${Purpose}: $rootFull"
    }
    return $rootTrimmed
}

function Get-ContainedPayloadPath {
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$RelativePath)
    $canonical = ConvertTo-CanonicalPayloadPath -Path $RelativePath
    $rootFull = Get-ValidatedContainerRoot -Root $Root -Purpose 'payload'
    $nativeRelative = $canonical.Replace('/', [IO.Path]::DirectorySeparatorChar)
    $full = [IO.Path]::GetFullPath((Join-Path $rootFull $nativeRelative))
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Payload path escapes its root: $RelativePath"
    }
    Assert-NoReparsePointChain -Root $rootFull -FullPath $full -Purpose 'Payload path'
    return $full
}

function Assert-NoReparsePointChain {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$FullPath,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    $rootFull = Get-ValidatedContainerRoot -Root $Root -Purpose $Purpose
    if (Test-Path -LiteralPath $rootFull) {
        $rootItem = Get-Item -LiteralPath $rootFull -Force
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Purpose root is a reparse point: $rootFull"
        }
    }
    $targetFull = [IO.Path]::GetFullPath($FullPath)
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    if (-not $targetFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Purpose is outside its approved root."
    }
    $current = $rootFull
    foreach ($part in @($targetFull.Substring($prefix.Length) -split '[\\/]')) {
        if ([string]::IsNullOrEmpty($part)) { continue }
        $current = Join-Path $current $part
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Purpose crosses a reparse point: $current"
            }
        }
    }
}

function Get-ContainedFileItems {
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$Purpose)
    $rootFull = Get-ValidatedContainerRoot -Root $Root -Purpose $Purpose
    if (-not (Test-Path -LiteralPath $rootFull -PathType Container)) { throw "$Purpose root is missing: $rootFull" }
    $rootItem = Get-Item -LiteralPath $rootFull -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Purpose root is a reparse point: $rootFull"
    }
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($rootFull)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            $full = [IO.Path]::GetFullPath($item.FullName)
            if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "$Purpose item escaped its root: $full"
            }
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Purpose contains a reparse point: $full"
            }
            if ($item.PSIsContainer) { $pending.Push($full) } else { $item }
        }
    }
}

function Copy-ContainedDirectoryFiles {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$DestinationRoot,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    $sourceRootFull = Get-ValidatedContainerRoot -Root $SourceRoot -Purpose "$Purpose source"
    $destinationRootFull = Get-ValidatedContainerRoot -Root $DestinationRoot -Purpose "$Purpose destination"
    $sourcePrefix = $sourceRootFull + [IO.Path]::DirectorySeparatorChar
    $sourceFiles = @(Get-ContainedFileItems -Root $sourceRootFull -Purpose "$Purpose source")
    foreach ($file in $sourceFiles) {
        $sourceFull = [IO.Path]::GetFullPath($file.FullName)
        Assert-NoReparsePointChain -Root $sourceRootFull -FullPath $sourceFull -Purpose "$Purpose source"
        $relative = $sourceFull.Substring($sourcePrefix.Length).Replace('\', '/')
        $canonical = Assert-ZipPayloadAllowed -Path $relative
        Assert-ZipPayloadBytesAllowed -Bytes ([IO.File]::ReadAllBytes($sourceFull)) -Path $canonical
        $destination = Get-ContainedPayloadPath -Root $destinationRootFull -RelativePath $canonical
        $parent = Split-Path -Parent $destination
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        Copy-Item -LiteralPath $sourceFull -Destination $destination -Force
    }
}

function Copy-ExactContainedFile {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$RelativeSource,
        [Parameter(Mandatory = $true)][string]$DestinationRoot,
        [Parameter(Mandatory = $true)][string]$RelativeDestination,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    $source = Get-ContainedPayloadPath -Root $SourceRoot -RelativePath $RelativeSource
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Missing required ${Purpose}: $source"
    }
    Assert-ZipPayloadBytesAllowed -Bytes ([IO.File]::ReadAllBytes($source)) -Path $RelativeDestination
    $destination = Get-ContainedPayloadPath -Root $DestinationRoot -RelativePath $RelativeDestination
    $parent = Split-Path -Parent $destination
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Copy-Item -LiteralPath $source -Destination $destination -Force
}

function Copy-ZipEnginePayloads {
    param(
        [Parameter(Mandatory = $true)][string]$EngineRoot,
        [Parameter(Mandatory = $true)][string]$StageRoot
    )
    Assert-RegularContainer -Path $EngineRoot -Purpose 'EngineDir'
    foreach ($engineName in @('winn-datapath.exe', 'winsvpn_winn3_engine.exe')) {
        $candidate = Get-ContainedPayloadPath -Root $StageRoot -RelativePath $engineName
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { continue }
        $engineSource = Get-ContainedPayloadPath -Root $EngineRoot -RelativePath $engineName
        if (-not (Test-Path -LiteralPath $engineSource -PathType Leaf)) {
            Write-Warning "EngineDir lacks $engineName; v3 completeness gate will report it."
            continue
        }
        Copy-ExactContainedFile -SourceRoot $EngineRoot -RelativeSource $engineName `
            -DestinationRoot $StageRoot -RelativeDestination $engineName -Purpose "EngineDir $engineName"
        Write-Step "Fused $engineName into stage from EngineDir (sha256 $((Sha256-Of -Path $candidate)))"
    }
}

function Copy-ZipPinnedDependencies {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$StageRoot
    )
    Assert-RegularContainer -Path $SourceRoot -Purpose 'DependenciesDir'
    New-Item -ItemType Directory -Path (Join-Path $StageRoot 'dependencies') -Force | Out-Null
    foreach ($name in $ZipDependencyPins.Keys) {
        $sourceName = [string]$ZipDependencyPins[$name].source
        if ([string]::IsNullOrWhiteSpace($sourceName)) { $sourceName = $name }
        Copy-ExactContainedFile -SourceRoot $SourceRoot -RelativeSource $sourceName `
            -DestinationRoot $StageRoot -RelativeDestination "dependencies/$name" `
            -Purpose "pinned dependency $sourceName"
    }
}

function Get-ZipFirstPartyEnginePaths {
    $paths = New-Object 'System.Collections.Generic.List[string]'
    foreach ($relative in $ZipFirstPartyEnginePaths) { [void]$paths.Add($relative) }
    if ($script:ZipArchitecture -cne 'arm64') {
        [void]$paths.Add('dependencies/amneziawg.exe')
    }
    return @($paths)
}

function Assert-ZipUnsignedEngineProductOrdering {
    param([Parameter(Mandatory = $true)][string]$StageRoot)
    $signedEngines = New-Object 'System.Collections.Generic.List[string]'
    $unsignedEngines = New-Object 'System.Collections.Generic.List[string]'
    $signedProducts = New-Object 'System.Collections.Generic.List[string]'
    $unsignedProducts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($relative in @(Get-ZipFirstPartyEnginePaths)) {
        $full = Get-ContainedPayloadPath -Root $StageRoot -RelativePath $relative
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { continue }
        if ((Get-PeCertificateTableSize -Path $full) -gt 0) {
            [void]$signedEngines.Add($relative)
        } else {
            [void]$unsignedEngines.Add($relative)
        }
    }
    foreach ($relative in $ZipFirstPartyProductPaths) {
        $full = Get-ContainedPayloadPath -Root $StageRoot -RelativePath $relative
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { continue }
        if ((Get-PeCertificateTableSize -Path $full) -gt 0) {
            [void]$signedProducts.Add($relative)
        } else {
            [void]$unsignedProducts.Add($relative)
        }
    }
    if ($signedEngines.Count -gt 0 -and $unsignedProducts.Count -gt 0) {
        throw ("Signed first-party engines with unsigned product payloads are refused. This producer signs engines then product in one pass; a partial set was signed elsewhere. Signed engines: " + ($signedEngines -join ', '))
    }
    if ($signedProducts.Count -gt 0 -and $unsignedEngines.Count -gt 0) {
        throw ("Signed product payloads with unsigned first-party engines are refused. An unsigned ZIP keeps first-party engines and product unsigned together. Signed product: " + ($signedProducts -join ', '))
    }
    if ($signedEngines.Count -gt 0 -or $signedProducts.Count -gt 0) {
        throw 'First-party ZIP engines and product already carry Authenticode signatures, but no signing identity is configured to verify them. Configure WINS_WINDOWS_ARTIFACT_SIGNING_METADATA or WINS_WINDOWS_SIGN_CERT_SHA1 so this producer performs and verifies engine then product signing, or stage unsigned inputs.'
    }
}

function Get-ZipSignedPayloadPlan {
    # Engines first, then every other first-party PE (product). Pinned
    # third-party dependencies under dependencies/ keep their exact reviewed
    # bytes and are never re-signed; Assert-StagedDependencyPins binds them.
    param([Parameter(Mandatory = $true)][string]$StageRoot)
    $engines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($relative in $ZipFirstPartyEnginePaths) {
        if ($relative.StartsWith('dependencies/', [StringComparison]::Ordinal)) { continue }
        $full = Get-ContainedPayloadPath -Root $StageRoot -RelativePath $relative
        if (Test-Path -LiteralPath $full -PathType Leaf) { [void]$engines.Add($relative) }
    }
    $products = New-Object 'System.Collections.Generic.List[string]'
    foreach ($relative in @(Get-RelativePaths -Root $StageRoot)) {
        if ($relative.StartsWith('dependencies/', [StringComparison]::Ordinal) -or
            $relative.StartsWith('licenses/', [StringComparison]::Ordinal)) { continue }
        if ([IO.Path]::GetExtension($relative).ToLowerInvariant() -notin @('.exe', '.dll')) { continue }
        if ($engines.Contains($relative)) { continue }
        [void]$products.Add($relative)
    }
    foreach ($required in $ZipFirstPartyProductPaths) {
        if (-not $products.Contains($required)) {
            throw "Signed ZIP plan is missing first-party product $required."
        }
    }
    return @($engines) + @($products)
}

function Invoke-ZipFirstPartySigning {
    param([Parameter(Mandatory = $true)][string]$StageRoot)
    if ($null -eq $script:ZipSigning) {
        throw 'Invoke-ZipFirstPartySigning requires a resolved signing identity.'
    }
    $script:ZipSignatureEvidence = [System.Collections.Generic.List[object]]::new()
    foreach ($relative in @(Get-ZipSignedPayloadPlan -StageRoot $StageRoot)) {
        $full = Get-ContainedPayloadPath -Root $StageRoot -RelativePath $relative
        $evidence = Invoke-WinsProducerSigning -Path $full -Signing $script:ZipSigning
        [void]$script:ZipSignatureEvidence.Add([ordered]@{
            path = $relative
            sha256 = (Sha256-Of -Path $full)
            signer_subject = [string]$evidence.signer_subject
            signer_leaf_sha256 = [string]$evidence.signer_leaf_sha256
        })
        Write-Step "Signed and verified $relative"
    }
}

function Assert-ZipSignedEngineProductPayloads {
    param([Parameter(Mandatory = $true)][string]$StageRoot)
    if ($null -eq $script:ZipSigning) {
        throw 'Assert-ZipSignedEngineProductPayloads requires a resolved signing identity.'
    }
    $plan = @(Get-ZipSignedPayloadPlan -StageRoot $StageRoot)
    $unsigned = @($plan | Where-Object {
        (Get-PeCertificateTableSize -Path (Get-ContainedPayloadPath -Root $StageRoot -RelativePath $_)) -eq 0
    })
    if ($unsigned.Count -gt 0) {
        throw ("Signed ZIP left first-party payloads without an Authenticode signature: " + ($unsigned -join ', '))
    }
    foreach ($relative in $plan) {
        $full = Get-ContainedPayloadPath -Root $StageRoot -RelativePath $relative
        [void](Assert-WinsProducerSignature -Path $full `
            -SignerPattern ([string]$script:ZipSigning.SignerPattern) `
            -SignTool ([string]$script:ZipSigning.SignTool) `
            -ExpectedLeafSha256 ([string]$script:ZipSigning.LeafSha256Pin))
    }
}

function Assert-ZipEngineProductSigningState {
    param([Parameter(Mandatory = $true)][string]$StageRoot)
    if ($null -eq $script:ZipSigning) {
        Assert-ZipUnsignedEngineProductOrdering -StageRoot $StageRoot
    } else {
        Assert-ZipSignedEngineProductPayloads -StageRoot $StageRoot
    }
}

function Assert-StagedDependencyPins {
    param([Parameter(Mandatory = $true)][string]$StageRoot)
    foreach ($name in $ZipDependencyPins.Keys) {
        $stagedPath = Get-ContainedPayloadPath -Root $StageRoot -RelativePath ("dependencies/$name")
        if (-not (Test-Path -LiteralPath $stagedPath -PathType Leaf)) {
            throw "Staged dependency $name is missing after copy: $stagedPath"
        }
        $actual = Sha256-Of -Path $stagedPath
        $expected = [string]$ZipDependencyPins[$name].sha256
        if ($actual -cne $expected) {
            throw "Staged dependency $name has SHA-256 $actual after copy; expected $expected. Refusing to package bytes that changed after the pre-copy pin check."
        }
    }
}

function New-DeterministicZipArchive {
    param(
        [Parameter(Mandatory = $true)][string]$StageRoot,
        [Parameter(Mandatory = $true)][string]$ZipPath
    )
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $entries = @(Get-RelativePaths -Root $StageRoot)
    $parent = Split-Path -Parent $ZipPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $stream = [IO.File]::Open($ZipPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $archive = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            $timestamp = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
            foreach ($relative in $entries) {
                $full = Get-ContainedPayloadPath -Root $StageRoot -RelativePath $relative
                $entry = $archive.CreateEntry($relative, [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $timestamp
                $entry.ExternalAttributes = 0
                $bytes = [IO.File]::ReadAllBytes($full)
                Assert-ZipPayloadBytesAllowed -Bytes $bytes -Path $relative
                $entryStream = $entry.Open()
                try { $entryStream.Write($bytes, 0, $bytes.Length) }
                finally { $entryStream.Dispose() }
            }
        } finally {
            $archive.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Assert-ZipArchiveInventory {
    param([Parameter(Mandatory = $true)][string]$ZipPath)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $names = New-Object 'System.Collections.Generic.List[string]'
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $archive.Entries) {
            $rawName = [string]$entry.FullName
            $isDirectory = [string]::IsNullOrEmpty([string]$entry.Name) -or
                $rawName.EndsWith('/') -or $rawName.EndsWith('\')
            if ($isDirectory) {
                throw "ZIP directory entries are forbidden: $rawName"
            }
            $canonical = Assert-ZipPayloadAllowed -Path $rawName.Replace('\', '/')
            if ($rawName -cne $canonical) {
                throw "ZIP member is not a canonical forward-slash path: $rawName"
            }
            if (-not $seen.Add($canonical)) { throw "ZIP contains a duplicate path: $canonical" }
            $unixFileType = ([int64]$entry.ExternalAttributes -shr 16) -band 0xF000
            if ($unixFileType -eq 0xA000) { throw "ZIP symlink entries are forbidden: $canonical" }
            if ($unixFileType -ne 0 -and $unixFileType -ne 0x8000) {
                throw "ZIP member has a forbidden Unix file type: $canonical"
            }
            [void]$names.Add($canonical)
        }
        $ordered = New-Object string[] $names.Count
        $names.CopyTo($ordered)
        [Array]::Sort($ordered, [StringComparer]::Ordinal)
        for ($index = 0; $index -lt $names.Count; $index++) {
            if ($names[$index] -cne $ordered[$index]) {
                throw ("ZIP inventory is not ordinal-sorted; '{0}' precedes '{1}'." -f $names[$index], $ordered[$index])
            }
        }
    } finally {
        $archive.Dispose()
    }
}

function Invoke-ZipExtractedPayloadReaudit {
    param([Parameter(Mandatory = $true)][string]$StageRoot)
    Test-Winn3CarrierCompleteness -StageRoot $StageRoot
    Assert-StagedPeMachines -StageRoot $StageRoot
    Assert-ZipEngineProductSigningState -StageRoot $StageRoot
    Assert-StagedDependencyPins -StageRoot $StageRoot
    $blocked = @('.pdb', '.ilk', '.iobj', '.ipdb')
    $symbols = @(Get-ContainedFileItems -Root $StageRoot -Purpose 'ZIP re-audit' |
        Where-Object { $blocked -contains $_.Extension.ToLowerInvariant() })
    if ($symbols.Count -gt 0) {
        throw ("Zip re-audit found debug symbol files: " + ($symbols.Name -join ', '))
    }
}

function Assert-ZipReceiptMatchesArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$ReceiptPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    if (-not (Test-Path -LiteralPath $ReceiptPath -PathType Leaf)) {
        throw "ZIP receipt is missing: $ReceiptPath"
    }
    $receipt = Get-Content -LiteralPath $ReceiptPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $signed = $null -ne $script:ZipSigning
    $expectedStatus = if ($signed) { 'signed' } else { 'unsigned' }
    if ([int]$receipt.schema_version -ne 1 -or
        [string]$receipt.contract -cne 'winsvpn-windows-zip-artifact-receipt-v1' -or
        [string]$receipt.architecture -cne $script:ZipArchitecture -or
        [string]$receipt.route -cne 'zip-plus-powershell' -or
        [bool]$receipt.store_upload_authorized -ne $false -or
        [string]$receipt.authenticode_status -cne $expectedStatus -or
        [bool]$receipt.authenticode_verified -ne $signed -or
        [bool]$receipt.timestamp_verified -ne $signed -or
        @($receipt.signed_payloads).Count -ne $script:ZipSignatureEvidence.Count -or
        ($signed -and $script:ZipSignatureEvidence.Count -eq 0) -or
        [bool]$receipt.winn_v3_primary -ne $true -or
        [bool]$receipt.winn_v1_awg_then_xray -ne $true) {
        throw "ZIP receipt does not match the $expectedStatus v3-primary AWG-then-Xray contract."
    }
    $actualSha = Sha256-Of -Path $ZipPath
    if ($actualSha -cne $ExpectedSha256 -or [string]$receipt.zip.sha256 -cne $ExpectedSha256) {
        throw 'ZIP receipt sha256 does not match the produced archive.'
    }
}

# BEGIN-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT
function Assert-WindowsAwgSchema2OwnerPublicationContract {
    param(
        [Parameter(Mandatory = $true)][string]$ProvenancePath,
        [Parameter(Mandatory = $true)][string]$HelperPath,
        [Parameter(Mandatory = $true)][string]$ExpectedUnsignedSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedTarget
    )
    if (-not (Test-Path -LiteralPath $ProvenancePath -PathType Leaf)) {
        throw 'The rebuilt AmneziaWG maintenance-helper provenance is missing.'
    }
    if (-not (Test-Path -LiteralPath $HelperPath -PathType Leaf)) {
        throw 'The rebuilt AmneziaWG maintenance helper is missing.'
    }
    if ($ExpectedUnsignedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'The reviewed unsigned AmneziaWG helper digest is not lowercase SHA-256.'
    }
    $raw = Get-Content -LiteralPath $ProvenancePath -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw 'The rebuilt AmneziaWG provenance is empty.'
    }
    # Every field the contract reads must appear once: PowerShell's JSON
    # parser keeps the last duplicate silently, so a repeated key could hide
    # a second value behind the reviewed one.
    foreach ($name in @(
            'schema_version', 'source_repository', 'source_version', 'source_commit',
            'source_go_mod_sha256', 'source_go_sum_sha256', 'source_build_bat_sha256',
            'patched_build_bat_sha256', 'build_patch_sha256', 'windows_library_repository',
            'windows_library_version', 'windows_library_commit', 'engine_module',
            'engine_version', 'engine_commit', 'go_version', 'go_archive', 'go_archive_sha256',
            'go_toolchain_policy', 'go_module_policy', 'go_checksum_database', 'target',
            'unsigned_artifact_sha256', 'expected_unsigned_artifact_sha256',
            'reproducibility_builds', 'reproducibility_status', 'module_build_info'
        )) {
        if ([regex]::Matches($raw, '"' + [regex]::Escape($name) + '"\s*:').Count -gt 1) {
            throw "Windows AWG helper provenance repeats JSON key $name."
        }
    }
    try { $evidence = $raw | ConvertFrom-Json }
    catch { throw "The rebuilt AmneziaWG provenance is invalid JSON: $($_.Exception.Message)" }
    if ($null -eq $evidence) {
        throw 'The rebuilt AmneziaWG provenance is not a JSON object.'
    }

    function Get-RequiredJsonProperty {
        param($Object, [string]$Name)
        $property = $Object.PSObject.Properties[$Name]
        if ($null -eq $property) {
            throw "Windows AWG schema-2 provenance is missing required field '$Name'."
        }
        return $property.Value
    }
    function Assert-JsonIntegerEquals {
        param($Value, [long]$Expected, [string]$Name)
        if ($null -eq $Value -or $Value -is [bool] -or $Value -is [string] -or
            $Value -is [double] -or $Value -is [float] -or $Value -is [decimal] -or
            ($Value -isnot [int] -and $Value -isnot [long])) {
            $actualType = if ($null -eq $Value) { 'null' } else { $Value.GetType().FullName }
            throw "Windows AWG field $Name must be JSON integer $Expected, not $actualType."
        }
        if ([int64]$Value -ne $Expected) {
            throw "Windows AWG field $Name must equal JSON integer $Expected."
        }
    }
    function Assert-JsonStringEquals {
        param($Value, [string]$Expected, [string]$Name)
        if ($Value -isnot [string]) {
            $actualType = if ($null -eq $Value) { 'null' } else { $Value.GetType().FullName }
            throw "Windows AWG field $Name must be a JSON string, not $actualType."
        }
        if ($Value -cne $Expected) {
            throw "Windows AWG field $Name is not the reviewed value."
        }
    }
    function Assert-JsonHexString {
        param($Value, [int]$Length, [string]$Name)
        if ($Value -isnot [string] -or $Value -cnotmatch ("^[0-9a-f]{$Length}$")) {
            throw "Windows AWG field $Name must be a lowercase $Length-hex JSON string."
        }
    }

    Assert-JsonIntegerEquals -Value (Get-RequiredJsonProperty $evidence 'schema_version') -Expected 2 -Name 'schema_version'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'source_repository') -Expected 'https://github.com/amnezia-vpn/amneziawg-windows-client.git' -Name 'source_repository'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'source_version') -Expected '3.1.0' -Name 'source_version'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'source_commit') -Expected 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968' -Name 'source_commit'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'source_go_mod_sha256') -Expected 'ad578b6a2107ae4c1bab214c8057e89608ac516d6e381675c3d9441ccc4da70a' -Name 'source_go_mod_sha256'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'source_go_sum_sha256') -Expected '268286d6183ec93c39e5295e73e660d9920481c66ecff8331ab64fa082230723' -Name 'source_go_sum_sha256'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'source_build_bat_sha256') -Expected 'c501fd947d08a4bfdb29f65a9f06ced004779be7a90a125f703c1c5a5130350b' -Name 'source_build_bat_sha256'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'patched_build_bat_sha256') -Expected '79bd946166bc6e87d4ff1602889557590703fc8a64737fbfe7f0b64ebda431d7' -Name 'patched_build_bat_sha256'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'build_patch_sha256') -Expected 'a5ad25797aadc29f0e7aa0bf91e6197ce57c48cb845194a18ae7c2dbbebadcbd' -Name 'build_patch_sha256'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'windows_library_repository') -Expected 'https://github.com/amnezia-vpn/amneziawg-windows.git' -Name 'windows_library_repository'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'windows_library_version') -Expected 'v3.1.20260814' -Name 'windows_library_version'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'windows_library_commit') -Expected 'e90531d15802cb976773f3b63443bc281f738ca3' -Name 'windows_library_commit'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'engine_module') -Expected 'github.com/amnezia-vpn/amneziawg-go/v3' -Name 'engine_module'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'engine_version') -Expected 'v3.1.20260828' -Name 'engine_version'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'engine_commit') -Expected 'b5928efb6ca19f0153958460c3d141f04abc5c2e' -Name 'engine_commit'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'go_version') -Expected '1.27.1' -Name 'go_version'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'go_archive') -Expected 'go1.27.1.windows-amd64.zip' -Name 'go_archive'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'go_archive_sha256') -Expected 'a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d' -Name 'go_archive_sha256'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'go_toolchain_policy') -Expected 'verified_archive_only' -Name 'go_toolchain_policy'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'go_module_policy') -Expected 'readonly' -Name 'go_module_policy'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'go_checksum_database') -Expected 'sum.golang.org' -Name 'go_checksum_database'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'target') -Expected $ExpectedTarget -Name 'target'
    Assert-JsonHexString -Value (Get-RequiredJsonProperty $evidence 'unsigned_artifact_sha256') -Length 64 -Name 'unsigned_artifact_sha256'
    Assert-JsonHexString -Value (Get-RequiredJsonProperty $evidence 'expected_unsigned_artifact_sha256') -Length 64 -Name 'expected_unsigned_artifact_sha256'
    if ($ExpectedTarget -ceq 'windows-arm64') {
        Assert-JsonIntegerEquals -Value (Get-RequiredJsonProperty $evidence 'reproducibility_builds') -Expected 2 -Name 'reproducibility_builds'
        Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'reproducibility_status') -Expected 'two_clean_builds_byte_identical' -Name 'reproducibility_status'
    }
    $unsignedDigest = [string](Get-RequiredJsonProperty $evidence 'unsigned_artifact_sha256')
    $expectedDigest = [string](Get-RequiredJsonProperty $evidence 'expected_unsigned_artifact_sha256')
    $actualHelper = (Get-FileHash -LiteralPath $HelperPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($unsignedDigest -cne $expectedDigest -or $unsignedDigest -cne $ExpectedUnsignedSha256 -or $actualHelper -cne $ExpectedUnsignedSha256) {
        throw 'Windows AWG schema-2 provenance unsigned digest does not agree with the helper bytes and reviewed pin.'
    }
    $moduleBuildInfo = Get-RequiredJsonProperty $evidence 'module_build_info'
    if ($moduleBuildInfo -is [string]) {
        throw 'Windows AWG field module_build_info must be a JSON array of strings, not a string.'
    }
    $moduleLines = @($moduleBuildInfo)
    if ($moduleLines.Count -lt 1) {
        throw 'Windows AWG field module_build_info must be a non-empty JSON array of strings.'
    }
    foreach ($line in $moduleLines) {
        if ($line -isnot [string]) {
            throw 'Windows AWG field module_build_info must contain only JSON strings.'
        }
    }
    $moduleText = [string]::Join("`n", $moduleLines)
    if ($moduleText -notmatch '(?m)^\s*dep\s+github\.com/amnezia-vpn/amneziawg-go/v3\s+v3\.1\.20260828\s+' -or
        $moduleText -notmatch '(?m)^\s*dep\s+github\.com/amnezia-vpn/amneziawg-windows/v3\s+v3\.1\.20260814\s+') {
        throw 'The rebuilt AmneziaWG maintenance-helper provenance lacks the exact AWG 3.1 module identities.'
    }
}
# END-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT

function Assert-ZipDependencyInputs {
    if (-not $ZipDependencyPins.Contains('amneziawg.exe')) {
        throw ("Missing pin: the $script:ZipArchitecture ZIP requires its app-owned amneziawg.exe maintenance helper. " +
            "Measure the reproducibly built ARM64 helper with Get-FileHash -Algorithm SHA256 " +
            "and record its digest in the producer and both ZIP dependency tables before packaging.")
    }
    foreach ($name in $ZipDependencyPins.Keys) {
        $sourceName = [string]$ZipDependencyPins[$name].source
        if ([string]::IsNullOrWhiteSpace($sourceName)) { $sourceName = $name }
        $path = Get-ContainedPayloadPath -Root $DependenciesDir -RelativePath $sourceName
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required pinned dependency is missing: $path"
        }
        $actual = Sha256-Of -Path $path
        $expected = [string]$ZipDependencyPins[$name].sha256
        if ($actual -cne $expected) {
            throw "Pinned dependency $sourceName has SHA-256 $actual; expected $expected. Refusing to package stale or mixed Windows dependencies. Refresh it through the reviewed producer."
        }
    }
    # The ARM64 pin table carries no product maintenance helper yet (the AWG
    # helper producer has no reviewed ARM64 ProductHelperSha256), so a table
    # without amneziawg.exe is refused above; helper provenance binds to that pin.
    if ($ZipDependencyPins.Contains('amneziawg.exe')) {
        Assert-WindowsAwgSchema2OwnerPublicationContract `
            -ProvenancePath (Join-Path $DependenciesDir $AmneziaWgHelperProvenance) `
            -HelperPath (Join-Path $DependenciesDir $script:ZipHelperSourceName) `
            -ExpectedUnsignedSha256 ([string]$ZipDependencyPins['amneziawg.exe'].sha256) `
            -ExpectedTarget $script:ZipAwgGoTarget
    }
}

function Assert-StagedPeMachines {
    param([Parameter(Mandatory = $true)][string]$StageRoot)
    foreach ($relative in @(Get-RelativePaths -Root $StageRoot)) {
        if ([IO.Path]::GetExtension($relative).ToLowerInvariant() -notin @('.exe', '.dll', '.sys')) { continue }
        $full = Get-ContainedPayloadPath -Root $StageRoot -RelativePath $relative
        $leaf = [IO.Path]::GetFileName($relative)
        $expected = if ($leaf -ceq $script:ZipVcRedistLeaf) { $ZipX86PeMachine } else { $script:ZipPeMachine }
        $actual = Get-PeCoffMachine -Path $full
        if ($actual -ne $expected) {
            throw ("Payload {0} has PE/COFF machine 0x{1:x4}; expected 0x{2:x4}. The {3} zip route refuses invalid or mixed-architecture executable, DLL, and PE payloads." -f $relative, $actual, $expected, $script:ZipArchitecture)
        }
    }
}

function Remove-StagedDebugSymbolFiles {
    param([Parameter(Mandatory = $true)][string]$StageRoot)
    $blocked = @('.pdb', '.ilk', '.iobj', '.ipdb')
    $found = @(Get-ContainedFileItems -Root $StageRoot -Purpose 'ZIP stage' |
        Where-Object { $blocked -contains $_.Extension.ToLowerInvariant() })
    foreach ($file in $found) {
        Write-Warning "Removing $($file.Name); debug symbol files are excluded from the zip route."
        Remove-Item -LiteralPath $file.FullName -Force
    }
    $leftover = @(Get-ContainedFileItems -Root $StageRoot -Purpose 'ZIP stage' |
        Where-Object { $blocked -contains $_.Extension.ToLowerInvariant() })
    if ($leftover.Count -gt 0) {
        throw ("Zip stage still contains debug symbol files: " + ($leftover.FullName -join ', '))
    }
}

function Test-Winn3CarrierCompleteness {
    # Same decision as build_installer.ps1's Write-Winn3CarrierCompleteness.
    param([string]$StageRoot)
    $datapath = Join-Path $StageRoot 'winn-datapath.exe'
    $relay = Join-Path $StageRoot 'winsvpn_winn3_engine.exe'
    $problems = @()
    if (-not (Test-Path -LiteralPath $datapath -PathType Leaf)) {
        $problems += 'winn-datapath.exe was not staged'
    }
    if (-not (Test-Path -LiteralPath $relay -PathType Leaf)) {
        $problems += 'winsvpn_winn3_engine.exe was not staged'
    }
    if (Test-Path -LiteralPath $datapath -PathType Leaf) {
        if (-not (Test-FileContainsMarker -Path $datapath -MarkerValue $Marker)) {
            $problems += "winn-datapath.exe was staged but contains no '$Marker' reference, so it does not carry Winn Protocol v3."
        } elseif ((Get-PeCoffMachine -Path $datapath) -ne $script:ZipPeMachine) {
            $problems += "winn-datapath.exe is not PE32+ $($script:ZipArchitecture) (COFF 0x$('{0:x4}' -f $script:ZipPeMachine)); refusing mixed-architecture ZIP payloads."
        }
    }
    if (Test-Path -LiteralPath $relay -PathType Leaf) {
        if ((Get-PeCoffMachine -Path $relay) -ne $script:ZipPeMachine) {
            $problems += "winsvpn_winn3_engine.exe is not PE32+ $($script:ZipArchitecture) (COFF 0x$('{0:x4}' -f $script:ZipPeMachine)); refusing mixed-architecture ZIP payloads."
        }
    }
    $awgEngine = Join-Path $StageRoot 'winsvpn_awg_engine.exe'
    $xray = Join-Path $StageRoot 'dependencies/xray.exe'
    $awgTool = Join-Path $StageRoot 'dependencies/awg.exe'
    if (-not (Test-Path -LiteralPath $awgEngine -PathType Leaf)) {
        $problems += 'winsvpn_awg_engine.exe was not staged; Winn v1 AWG fallback is required'
    }
    if (-not (Test-Path -LiteralPath $awgTool -PathType Leaf)) {
        $problems += 'dependencies/awg.exe was not staged; Winn v1 AWG fallback is required'
    }
    if (-not (Test-Path -LiteralPath $xray -PathType Leaf)) {
        $problems += 'dependencies/xray.exe was not staged; Winn v1 Xray fallback is required'
    }
    $service = Join-Path $StageRoot 'wins_vpn_tunnel_service.exe'
    if (-not (Test-Path -LiteralPath $service -PathType Leaf)) {
        $problems += 'wins_vpn_tunnel_service.exe was not staged; the ZIP product payload is incomplete'
    }
    if ($problems.Count -eq 0) {
        Write-Step 'Winn Protocol v3 carrier: COMPLETE (winn-datapath.exe carrying winn/3 + winsvpn_winn3_engine.exe both staged). Winn v1 AWG then Xray fallback payloads are present.'
        return
    }
    $detail = ($problems | ForEach-Object { "  - $_" }) -join "`n"
    throw "Winn Protocol v3 carrier is not shippable:`n$detail`n`nRefusing to produce a v1-only zip. Every Windows ZIP candidate must contain the complete Winn Protocol v3 carrier before packaging, plus the Winn v1 AWG then Xray fallback payloads."
}

function Get-RelativePaths {
    param([string]$Root)
    $rootFull = Get-ValidatedContainerRoot -Root $Root -Purpose 'staged payload'
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    $paths = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @(Get-ContainedFileItems -Root $Root -Purpose 'Staged payload')) {
        $full = [IO.Path]::GetFullPath($item.FullName)
        if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Staged file escaped the stage root: $full"
        }
        Assert-NoReparsePointChain -Root $rootFull -FullPath $full -Purpose 'Staged payload source'
        $relative = $full.Substring($prefix.Length).Replace('\', '/')
        [void]$paths.Add((Assert-ZipPayloadAllowed -Path $relative))
    }
    $array = $paths.ToArray()
    if ($array.Length -gt 1) {
        [Array]::Sort($array, [StringComparer]::Ordinal)
    }
    return $array
}

function Write-PayloadManifest {
    # Every staged file, bound to bytes + sha256 + a deploy hint the installer
    # reads. deploy: app (install into {app}), app-license (install under
    # {app}\licenses), temp (prerequisite used from the stage, NOT installed),
    # tooling (the zip's own installer scripts, never copied to {app}).
    param([string]$StageRoot)
    $knownDeps = @{}
    foreach ($name in $ZipDependencyPins.Keys) {
        $knownDeps["dependencies/$name"] = [string]$ZipDependencyPins[$name].dest
    }
    $files = @()
    foreach ($rel in (Get-RelativePaths -Root $StageRoot)) {
        $relFwd = ConvertTo-CanonicalPayloadPath -Path $rel
        $full = Get-ContainedPayloadPath -Root $StageRoot -RelativePath $relFwd
        $sha256 = Sha256-Of -Path $full
        Assert-ZipPayloadBytesAllowed -Bytes ([IO.File]::ReadAllBytes($full)) -Path $relFwd
        $dest = 'app'
        $lastSlash = $relFwd.LastIndexOf('/')
        $base = if ($lastSlash -ge 0) { $relFwd.Substring($lastSlash + 1) } else { $relFwd }
        $dir = if ($lastSlash -ge 0) { $relFwd.Substring(0, $lastSlash) } else { '' }
        if ($relFwd.StartsWith('dependencies/', [StringComparison]::Ordinal)) {
            if (-not $knownDeps.ContainsKey($relFwd)) {
                throw "Unapproved dependency payload in ZIP stage: $relFwd"
            }
            $dest = $knownDeps[$relFwd]
        } elseif ($dir -ceq 'licenses') {
            $dest = 'app-license'
        } elseif ($base -in @('install_winsvpn_zip.ps1', 'remove_winsvpn_zip.ps1')) {
            $dest = 'tooling'
        }
        $files += [ordered]@{
            path = $relFwd
            bytes = (Get-Item -LiteralPath $full).Length
            sha256 = $sha256
            dest = $dest
        }
    }
    $manifest = [ordered]@{
        schema_version = 2
        route = 'zip-plus-powershell'
        app = 'Win''s VPN'
        app_version = $AppVersion
        architecture = $script:ZipArchitecture
        built_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        file_count = $files.Count
        dependency_contract = $ZipDependencyContract
        files = @($files)
    }
    $manifestPath = Join-Path $StageRoot 'payload-manifest.json'
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    Write-Step ("Payload manifest written: {0} entries -> {1}" -f $files.Count, $manifestPath)
    return $manifest
}

function Expand-SafeZipArchive {
    param([Parameter(Mandatory = $true)][string]$ZipPath, [Parameter(Mandatory = $true)][string]$DestinationRoot)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $plans = @()
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $archive.Entries) {
            $rawName = [string]$entry.FullName
            $isDirectory = [string]::IsNullOrEmpty([string]$entry.Name) -or
                $rawName.EndsWith('/') -or $rawName.EndsWith('\')
            if ($isDirectory) { $rawName = $rawName.TrimEnd([char[]]@('/', '\')) }
            if ([string]::IsNullOrEmpty($rawName)) { continue }
            # Windows PowerShell 5.1 Compress-Archive writes nested member
            # names with backslashes. Normalize archive separators first, then
            # apply the same rooted, dot-segment, duplicate, and containment
            # gates. Manifest paths themselves remain forward-slash-only.
            $canonical = Assert-ZipPayloadAllowed -Path $rawName.Replace('\', '/')
            if (-not $seen.Add($canonical)) { throw "ZIP contains a duplicate path: $canonical" }
            $unixFileType = ([int64]$entry.ExternalAttributes -shr 16) -band 0xF000
            if ($unixFileType -eq 0xA000) { throw "ZIP symlink entries are forbidden: $canonical" }
            $destination = Get-ContainedPayloadPath -Root $DestinationRoot -RelativePath $canonical
            $plans += [pscustomobject]@{ entry = $entry; path = $destination; is_directory = $isDirectory; canonical = $canonical; bytes = $null }
        }
        foreach ($plan in $plans) {
            if ($plan.is_directory) { continue }
            $buffer = New-Object IO.MemoryStream
            $entryStream = $plan.entry.Open()
            try { $entryStream.CopyTo($buffer) }
            finally { $entryStream.Dispose() }
            $plan.bytes = $buffer.ToArray()
            Assert-ZipPayloadBytesAllowed -Bytes $plan.bytes -Path $plan.canonical
        }
        foreach ($plan in $plans) {
            if ($plan.is_directory) {
                New-Item -ItemType Directory -Path $plan.path -Force | Out-Null
                continue
            }
            $parent = Split-Path -Parent $plan.path
            if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            $output = [IO.File]::Open($plan.path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $output.Write($plan.bytes, 0, $plan.bytes.Length) }
            finally { $output.Dispose() }
        }
    } finally {
        $archive.Dispose()
    }
}

function Test-ZipRoundTrip {
    # Expand the zip we just wrote into a fresh dir and re-hash every manifest
    # entry. A zip whose contents no longer match its own manifest is not a
    # deliverable. Reads the manifest back OUT of the zip to avoid trusting the
    # staged one. When -ReauditPayloadIdentity is set, the extracted tree is
    # the post-build identity re-audit surface.
    param(
        [string]$ZipPath,
        [switch]$ReauditPayloadIdentity
    )
    $verifyRoot = Join-Path (Split-Path $ZipPath) ("_verify-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $verifyRoot -Force | Out-Null
    try {
        Expand-SafeZipArchive -ZipPath $ZipPath -DestinationRoot $verifyRoot
        $manifestPath = Join-Path $verifyRoot 'payload-manifest.json'
        if (-not (Test-Path -LiteralPath $manifestPath)) { throw 'Round-trip: payload-manifest.json missing from produced zip.' }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $bad = @()
        if ([int]$manifest.schema_version -ne 2 -or [string]$manifest.route -cne 'zip-plus-powershell' -or
            [string]$manifest.architecture -cne $script:ZipArchitecture -or [int]$manifest.file_count -ne @($manifest.files).Count) {
            $bad += 'manifest header does not satisfy the ZIP schema v2 contract'
        }
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($file in @($manifest.files)) {
            try {
                $canonical = ConvertTo-CanonicalPayloadPath -Path ([string]$file.path)
                if (-not $seen.Add($canonical)) { throw "duplicate payload path $canonical" }
                $full = Get-ContainedPayloadPath -Root $verifyRoot -RelativePath $canonical
            } catch {
                $bad += $_.Exception.Message
                continue
            }
            if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
                $bad += "$($file.path) MISSING"
                continue
            }
            $size = (Get-Item -LiteralPath $full).Length
            $sha = (Sha256-Of -Path $full)
            if ($size -ne $file.bytes) { $bad += "$($file.path) size $size != $($file.bytes)" }
            if ($sha -ne $file.sha256) { $bad += "$($file.path) sha256 mismatch" }
        }
        $physical = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($file in @(Get-ContainedFileItems -Root $verifyRoot -Purpose 'Round-trip payload')) {
            $relative = $file.FullName.Substring([IO.Path]::GetFullPath($verifyRoot).TrimEnd('\', '/').Length + 1).Replace('\', '/')
            if ($relative -ceq 'payload-manifest.json') { continue }
            try { $relative = ConvertTo-CanonicalPayloadPath -Path $relative }
            catch { $bad += $_.Exception.Message; continue }
            [void]$physical.Add($relative)
            if (-not $seen.Contains($relative)) { $bad += "$relative is present in the zip but unlisted by the manifest" }
        }
        foreach ($relative in $seen) {
            if (-not $physical.Contains($relative)) { $bad += "$relative is listed by the manifest but absent from the zip" }
        }
        if ($bad.Count -gt 0) {
            throw ("Round-trip verification FAILED for $ZipPath`n" + (($bad | Select-Object -First 10) -join "`n"))
        }
        Write-Step ("Round-trip verified: {0} entries re-hashed from the zip match the manifest." -f $manifest.files.Count)
        Assert-ZipArchiveInventory -ZipPath $ZipPath
        if ($ReauditPayloadIdentity) {
            Write-Step 'Post-build re-audit of extracted ZIP payload identity...'
            Invoke-ZipExtractedPayloadReaudit -StageRoot $verifyRoot
        }
    } finally {
        if (Test-Path -LiteralPath $verifyRoot) { Remove-Item -LiteralPath $verifyRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# ---------------------------------------------------------------------------
Write-Step "Repository root: $RepoRoot"
if ($AppVersion -cnotmatch '^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$') {
    throw "AppVersion is not safe for manifest or output naming: $AppVersion"
}
Assert-SafeZipPathArgument -Path $ReleaseDir -Name 'ReleaseDir'
Assert-SafeZipPathArgument -Path $DependenciesDir -Name 'DependenciesDir'
Assert-SafeZipPathArgument -Path $LicensesDir -Name 'LicensesDir'
Assert-SafeZipPathArgument -Path $OutDir -Name 'OutDir'
Assert-SafeZipPathArgument -Path $ThirdPartiesDoc -Name 'ThirdPartiesDoc'
if (-not [string]::IsNullOrWhiteSpace($EngineDir)) {
    Assert-SafeZipPathArgument -Path $EngineDir -Name 'EngineDir'
}
Initialize-ZipArchitectureContract -Architecture $TargetArchitecture
$script:ZipSigning = Resolve-WinsProducerSigningConfiguration -RepoRoot $RepoRoot `
    -Architecture $TargetArchitecture -RequireSigning:$RequireCodeSigning
if ($null -eq $script:ZipSigning) {
    Write-Warning 'No Windows signing identity is configured; this is an unsigned rehearsal ZIP and its receipt records authenticode_status unsigned.'
} else {
    Write-Step "Authenticode signing identity resolved ($($script:ZipSigning.Mode)); first-party engines then product will be signed and verified."
}
Assert-ZipWindowsHostMatchesTarget
if ($TargetArchitecture -ceq 'arm64') {
    $defaultX64Release = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\build\windows\x64\runner\Release'))
    if ([IO.Path]::GetFullPath($ReleaseDir) -eq $defaultX64Release) {
        $ReleaseDir = Join-Path $PSScriptRoot '..\..\build\windows\arm64\runner\Release'
        Assert-SafeZipPathArgument -Path $ReleaseDir -Name 'ReleaseDir'
    }
    $defaultX64Engine = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\build\windows\winn3\x64'))
    if ([IO.Path]::GetFullPath($EngineDir) -eq $defaultX64Engine) {
        $EngineDir = Join-Path $PSScriptRoot '..\..\build\windows\winn3\arm64'
        Assert-SafeZipPathArgument -Path $EngineDir -Name 'EngineDir'
    }
}
Assert-Dir -Path $ReleaseDir -What 'ReleaseDir'
Assert-Dir -Path $DependenciesDir -What 'DependenciesDir'
Assert-Dir -Path $LicensesDir -What 'LicensesDir'
if ($EngineDir) { Assert-Dir -Path $EngineDir -What 'EngineDir' }
Assert-RegularLeafFile -Path $ThirdPartiesDoc -Purpose 'third-party notices'
Write-Step "Validating exact $script:ZipArchitecture dependency hashes and AWG 3.1 provenance before staging..."
Assert-ZipDependencyInputs

$OutDir = [IO.Path]::GetFullPath($OutDir)
[void](Get-ValidatedContainerRoot -Root $OutDir -Purpose 'OutDir')
if (Test-Path -LiteralPath $OutDir) {
    Assert-RegularContainer -Path $OutDir -Purpose 'OutDir'
}
$stamp = Get-Date -Format 'yyyyMMddTHHmmss'
$routeDir = Get-ContainedPayloadPath -Root $OutDir -RelativePath 'zip-route'
$stage = Get-ContainedPayloadPath -Root $routeDir -RelativePath "stage-$stamp"
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

Write-Step "Copying Flutter Release runner from $ReleaseDir"
Copy-ContainedDirectoryFiles -SourceRoot $ReleaseDir -DestinationRoot $stage -Purpose 'Flutter Release runner'
$gui = Get-ContainedPayloadPath -Root $stage -RelativePath 'wins_vpn.exe'
if (-not (Test-Path -LiteralPath $gui -PathType Leaf)) {
    throw "ReleaseDir did not contain wins_vpn.exe: $ReleaseDir"
}
if ((Get-PeCoffMachine -Path $gui) -ne $script:ZipPeMachine) {
    throw "wins_vpn.exe is not PE32+ $($script:ZipArchitecture) (COFF 0x$($script:ZipPeMachine.ToString('x4'))); refusing to mix Flutter GUI architecture with ZIP dependencies."
}

if (-not [string]::IsNullOrWhiteSpace($EngineDir)) {
    Copy-ZipEnginePayloads -EngineRoot $EngineDir -StageRoot $stage
}

Write-Step "Copying dependencies from $DependenciesDir"
Copy-ZipPinnedDependencies -SourceRoot $DependenciesDir -StageRoot $stage
Write-Step 'Re-verifying staged dependency bytes against reviewed pins after copy...'
Assert-StagedDependencyPins -StageRoot $stage
if ($ZipDependencyPins.Contains('amneziawg.exe')) {
    Assert-WindowsAwgSchema2OwnerPublicationContract `
        -ProvenancePath (Join-Path $DependenciesDir $AmneziaWgHelperProvenance) `
        -HelperPath (Get-ContainedPayloadPath -Root $stage -RelativePath 'dependencies/amneziawg.exe') `
        -ExpectedUnsignedSha256 ([string]$ZipDependencyPins['amneziawg.exe'].sha256) `
        -ExpectedTarget $script:ZipAwgGoTarget
}

Write-Step "Copying licences from $LicensesDir"
New-Item -ItemType Directory -Path (Join-Path $stage 'licenses') -Force | Out-Null
foreach ($licenseName in $ZipLicenseFiles) {
    Copy-ExactContainedFile -SourceRoot $LicensesDir -RelativeSource $licenseName `
        -DestinationRoot $stage -RelativeDestination "licenses/$licenseName" `
        -Purpose "ZIP license $licenseName"
}
$noticesBytes = [IO.File]::ReadAllBytes(([IO.Path]::GetFullPath($ThirdPartiesDoc)))
Assert-ZipPayloadBytesAllowed -Bytes $noticesBytes -Path 'licenses/THIRD_PARTY_NOTICES.md'
$noticesDestination = Get-ContainedPayloadPath -Root $stage -RelativePath 'licenses/THIRD_PARTY_NOTICES.md'
Copy-Item -LiteralPath $ThirdPartiesDoc -Destination $noticesDestination -Force

foreach ($tool in @('install_winsvpn_zip.ps1', 'remove_winsvpn_zip.ps1')) {
    Copy-ExactContainedFile -SourceRoot $PSScriptRoot -RelativeSource $tool `
        -DestinationRoot $stage -RelativeDestination $tool -Purpose $tool
}

Write-Step 'Excluding debug symbol files from the zip stage...'
Remove-StagedDebugSymbolFiles -StageRoot $stage

Write-Step 'Running the v3 carrier-completeness gate on the stage...'
Test-Winn3CarrierCompleteness -StageRoot $stage

Write-Step "Checking every executable, DLL, and PE payload for the reviewed $($script:ZipArchitecture) architecture..."
Assert-StagedPeMachines -StageRoot $stage

if ($null -ne $script:ZipSigning) {
    Write-Step 'Signing first-party engines, then product payloads...'
    Invoke-ZipFirstPartySigning -StageRoot $stage
}
Write-Step 'Checking first-party engine then product signing state...'
Assert-ZipEngineProductSigningState -StageRoot $stage

Write-Step 'Writing payload manifest...'
$manifest = Write-PayloadManifest -StageRoot $stage

if ($SkipZip) {
    Write-Step "SkipZip requested; staged payload left at $stage"
    exit 0
}

$zipSuffix = if ($script:ZipArchitecture -ceq 'arm64') { '-arm64' } else { '' }
$zipName = "WinsVPN-Win-$AppVersion-zip-install$zipSuffix.zip"
$zipPath = Get-ContainedPayloadPath -Root $OutDir -RelativePath $zipName
$receiptPath = "$zipPath.receipt.json"
$zipShaPath = "$zipPath.sha256"
$receiptTemp = "$receiptPath.tmp"
Reset-ZipPartialOutputs
foreach ($output in @($zipPath, $receiptPath, $zipShaPath, $receiptTemp)) {
    if (Test-Path -LiteralPath $output) { Remove-Item -LiteralPath $output -Force }
    Register-ZipPartialOutput -Path $output
}
try {
    Write-Step "Writing deterministic ZipArchive inventory -> $zipPath"
    New-DeterministicZipArchive -StageRoot $stage -ZipPath $zipPath
    Test-ZipRoundTrip -ZipPath $zipPath -ReauditPayloadIdentity

    $zipSha = Sha256-Of -Path $zipPath
    Set-Content -LiteralPath $zipShaPath -Value "$zipSha  $zipName" -Encoding ASCII
    $manifestDigest = Sha256-Of -Path (Join-Path $stage 'payload-manifest.json')
    $zipSigned = $null -ne $script:ZipSigning
    $zipAuthenticodeStatus = if ($zipSigned) { 'signed' } else { 'unsigned' }
    $zipSigningMode = if ($zipSigned) { [string]$script:ZipSigning.Mode } else { 'none' }
    $receipt = [ordered]@{
        schema_version = 1
        contract = 'winsvpn-windows-zip-artifact-receipt-v1'
        created_utc = [DateTime]::UtcNow.ToString('o')
        architecture = $script:ZipArchitecture
        route = 'zip-plus-powershell'
        store_upload_authorized = $false
        authenticode_status = $zipAuthenticodeStatus
        authenticode_verified = $zipSigned
        timestamp_verified = $zipSigned
        signing_mode = $zipSigningMode
        signed_payloads = @($script:ZipSignatureEvidence)
        pinned_dependencies_resigned = $false
        authenticode_store_route = 'inno-win32'
        winn_v3_primary = $true
        winn_v1_awg_then_xray = $true
        debug_symbols_excluded = $true
        private_symbol_custody_established = $false
        zip = [ordered]@{
            path = $zipName
            sha256 = $zipSha
            bytes = [long](Get-Item -LiteralPath $zipPath).Length
        }
        payload_manifest_sha256 = $manifestDigest
        file_count = $manifest.file_count
        producer = [ordered]@{
            path = 'installer/windows/build_zip_installer.ps1'
            sha256 = (Sha256-Of -Path $PSCommandPath)
        }
    }
    $receiptJson = $receipt | ConvertTo-Json -Depth 6
    Set-Content -LiteralPath $receiptTemp -Value $receiptJson -Encoding UTF8
    if (Test-Path -LiteralPath $receiptPath -PathType Leaf) {
        throw "ZIP receipt already exists after zip replacement: $receiptPath"
    }
    [IO.File]::Move($receiptTemp, $receiptPath)
    Assert-ZipReceiptMatchesArtifact -ZipPath $zipPath -ReceiptPath $receiptPath -ExpectedSha256 $zipSha
    $script:ZipPartialOutputPaths.Clear()
} catch {
    Remove-ZipPartialOutputs
    throw
}
$summary = [ordered]@{
    zip_path = $zipPath
    zip_sha256 = $zipSha
    manifest_sha256 = $manifestDigest
    receipt_path = $receiptPath
    staged_payload_dir = $stage
    file_count = $manifest.file_count
    authenticode_status = $zipAuthenticodeStatus
}
$summary | ConvertTo-Json | Write-Host
if ($zipSigned) {
    Write-Step ("ZIP BUILD: SIGNED first-party engines and product verified ($zipSigningMode). Keep $zipShaPath with the zip so distributors can verify it out-of-band.")
} else {
    Write-Step ("ZIP BUILD: UNSIGNED REHEARSAL; first-party payloads carry no Authenticode signature, so a release tunnel service refuses its client. Keep $zipShaPath with the zip so distributors can verify it out-of-band.")
}
