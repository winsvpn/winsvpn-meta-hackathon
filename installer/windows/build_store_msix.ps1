[CmdletBinding()]
param(
    [switch]$SkipFlutterBuild,
    [switch]$DevelopmentIdentity,
    [switch]$SelfTest,
    [string]$IdentityName = $env:WINS_MSIX_IDENTITY_NAME,
    [string]$Publisher = $env:WINS_MSIX_PUBLISHER,
    [string]$PublisherDisplayName = $env:WINS_MSIX_PUBLISHER_DISPLAY_NAME,
    [string]$OutputDirectory = "",
    [string]$ReleaseDirectory = "",
    [ValidateSet('x64', 'arm64')]
    [string]$TargetArchitecture = 'x64',
    [switch]$RequireCodeSigning,
    [switch]$BoundarySelfTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ScriptPath = $MyInvocation.MyCommand.Path
$InstallerDirectory = Split-Path -Parent $ScriptPath
$Root = (Resolve-Path (Join-Path $InstallerDirectory '..\..')).Path
$Template = Join-Path $InstallerDirectory 'store\AppxManifest.xml.template'
$CertificationNotes = Join-Path $InstallerDirectory 'store\certification-notes.md'
$DependencyDirectory = Join-Path $InstallerDirectory 'dependencies'
$Pubspec = Join-Path $Root 'pubspec.yaml'
$ObfuscationTool = Join-Path $Root 'tools\release_obfuscation_contract.py'
$ProductionMsixBlockedReason = @'
Production MSIX needs the Partner Center package identity: pass -IdentityName, -Publisher and -PublisherDisplayName (or set WINS_MSIX_IDENTITY_NAME, WINS_MSIX_PUBLISHER and WINS_MSIX_PUBLISHER_DISPLAY_NAME) to the values Partner Center shows for the app. The Microsoft Store Win32-installer path (the signed Inno EXE from build_installer.ps1) does not need them; MSIX packaging of the Windows service and offline-installer architecture does. -DevelopmentIdentity builds a local experiment package instead.
'@.Trim()
function Read-MsixPubspecReleaseIdentity {
    # Same mapping as build_installer.ps1: pubspec.yaml major.minor.patch+build
    # becomes the four-part Windows version major.minor.patch.build.
    param([Parameter(Mandatory=$true)][string]$Path)
    $text = Get-Content -LiteralPath $Path -Raw
    $match = [regex]::Match($text, '(?m)^version:\s*(\d+)\.(\d+)\.(\d+)\+(\d+)\s*$')
    if (-not $match.Success) {
        throw 'pubspec.yaml must contain version: major.minor.patch+build.'
    }
    $parts = @(1..4 | ForEach-Object { [long]$match.Groups[$_].Value })
    if (@($parts | Where-Object { $_ -lt 0 -or $_ -gt 65535 }).Count -ne 0) {
        throw 'Every MSIX version component must fit in the range 0-65535.'
    }
    return [pscustomobject]@{
        SourceVersion = "$($parts[0]).$($parts[1]).$($parts[2])+$($parts[3])"
        PackageVersion = "$($parts[0]).$($parts[1]).$($parts[2]).$($parts[3])"
    }
}
function Get-Winn3DescriptorPubkeyDefines {
    $defines = @()
    foreach ($slot in @('G1','G2','G3')) {
        $var = "WINS_WINN3_DESCRIPTOR_PUBKEY_$slot"
        $fileVar = "${var}_FILE"
        $filePath = [Environment]::GetEnvironmentVariable($fileVar)
        $envValue = [Environment]::GetEnvironmentVariable($var)
        $raw = $null; $value = $null
        if ($filePath -and $filePath.Trim()) {
            $filePath = $filePath.Trim()
            if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) { throw "Winn3 pubkey file missing: $fileVar=$filePath" }
            $raw = (Get-Content -LiteralPath $filePath -Raw -ErrorAction Stop).Trim() -replace '\r','' -replace '\n',''
            $raw = $raw.Trim()
            if ($raw.StartsWith('--dart-define=') -or $raw.StartsWith('WINS_WINN3_DESCRIPTOR_PUBKEY_') -or $raw.StartsWith('WINN3_DESCRIPTOR_PUBKEY_')) { throw "Refusing $fileVar that looks like a dart-define or hub key: $($raw.Substring(0,[Math]::Min(60,$raw.Length)))" }
            $value = $raw
        } elseif ($envValue -and $envValue.Trim()) {
            $raw = $envValue
            if ($raw.StartsWith('--dart-define=')) { throw "Refusing $var that already contains --dart-define" }
            if ($raw.StartsWith('WINN3_DESCRIPTOR_PUBKEY_')) { throw "Refusing $var that looks like hub key name: $($raw.Substring(0,[Math]::Min(60,$raw.Length)))" }
            $value = $raw.Trim()
        } else { continue }
        if (-not $value) { continue }
        try { $d=[Convert]::FromBase64String($value); if($d.Length -ne 32){throw "bad"} } catch { throw "Winn3 pubkey $var not valid base64 of 32 bytes: $($value.Substring(0,[Math]::Min(20,$value.Length)))..." }
        $defines += "--dart-define=$var=$value"
    }
    return $defines
}
function Write-Winn3DescriptorPubkeyStatus { param([string[]]$Defines) $c=if($Defines){$Defines.Count}else{0}; if($c -gt 0){ Write-Host "Winn3 descriptor verification ring: PRESENT ($c slot(s))" } else { throw "Standalone v3 Windows Store release requires WINS_WINN3_DESCRIPTOR_PUBKEY_G1, G2, or G3" } }

# Official AmneziaWG Windows client 3.1.0 / AWG Go v3.1.20260828 identities.
# These pins are immutable expected values. A mismatch fails closed and never rewrites the pin from the bytes on disk.
# This packager does not download, fabricate, or refresh the dependency cache.
$AmneziaWgVersion = '3.1.0'
$AmneziaWgSourceCommit = 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968'
$AmneziaWgWindowsLibraryVersion = 'v3.1.20260814'
$AmneziaWgWindowsLibraryCommit = 'e90531d15802cb976773f3b63443bc281f738ca3'
$AmneziaWgEngineVersion = 'v3.1.20260828'
$AmneziaWgEngineCommit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'
$AmneziaWgHelperGoVersion = '1.27.1'
$AmneziaWgHelperGoArchiveSha256 = 'a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d'
$rejectedLegacyMsiSha256 =
    'a0fa81022a6e0204b67c92f0046aaebac923bf6ffc786f503c5acff483807b4a'
$rejectedLegacyAwgExeSha256 =
    'cd17f8641bb78ea6476c7341fb7339731ecd8f682e46ab1b43618cea75185552'
$rejectedLegacyProductHelperSha256 =
    'c1a9500254948ac4a1562d8ddf0808b45441ed36bf6746499b67efee6eef1ae9'
$Pinned = @{
    'amneziawg-amd64.msi' = 'a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b'
    'amneziawg.exe' = '12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41'
    'awg.exe' = '272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12'
    'wintun.dll' = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
    'xray.exe' = 'fffbe5dd92fe13cfc6ab72dead66ddd92c09b2bb27a85592e8e6f4ec27ee1224'
}
$RejectedLegacy = @{
    'amneziawg-amd64.msi' = $rejectedLegacyMsiSha256
    'awg.exe' = $rejectedLegacyAwgExeSha256
    'amneziawg.exe' = $rejectedLegacyProductHelperSha256
}
# Official ARM64 identities. Recorded so this packager cannot treat an unreviewed
# amneziawg-arm64.msi as a pin: the digest below is the file that was committed before
# the official 3.1.0 MSI replaced it, and it stays a reject value. ARM64 MSIX packaging
# stays disabled.
$OfficialArm64Pins = @{
    'amneziawg-arm64.msi' = '3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa'
    'amneziawg_msi_runtime_amneziawg_sha256' = '25fa81103152699bf416f394059b40d447001c3d0dea5ef889a9426f315e4c0a'
    'awg-arm64.exe' = '3106950ce9f0b93eb4c3f7975cbf44af41623ffeed630f19909730cd16d36e43'
    'wintun-arm64.dll' = 'f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80'
    'xray-arm64.exe' = 'c6edaa0e535b81d8c4c4a25378e6717b4406a8a0d72b751f4d0a1f171817e7af'
    'VC_redist.arm64.exe' = '5139e1440c3a20b92153a4db561c069a0175aaf76c276c3e5b6f56099edcf4b0'
}
$UnreviewedArm64MsiSha256 = '1699f9e6b313d8b90ec812f1ed0ec70b7d8d2e129010d179029d6990d9955fca'
$MsixX64PeMachine = [uint16]0x8664
$MsixX86PeMachine = [uint16]0x014c
$MsixArm64PeMachine = [uint16]0xAA64
$Winn3Marker = 'winsvpn.local/winnprotocol/winn3'
$MsixFirstPartyEngineLeaves = @('winn-datapath.exe', 'winsvpn_winn3_engine.exe', 'winsvpn_awg_engine.exe')
$MsixPinnedDependencyLeaves = @('awg.exe', 'wintun.dll', 'xray.exe', 'amneziawg.exe')
$PubspecReleaseIdentity = Read-MsixPubspecReleaseIdentity -Path $Pubspec
$CanonicalSourceVersion = [string]$PubspecReleaseIdentity.SourceVersion
$CanonicalPackageVersion = [string]$PubspecReleaseIdentity.PackageVersion
$CanonicalMsixArchitecture = 'x64'
$CanonicalMsixFilename = "WinsVPN-Store-$CanonicalPackageVersion-x64.msix"
$DevelopmentIdentityName = 'WinsVPN.Development'
$DevelopmentPublisher = 'CN=WinsVPNDevelopment'
$DevelopmentPublisherDisplayName = "Win's VPN Development"
$PartnerCenterX64Filename = 'WinsVPN-PartnerCenter.exe'
$PartnerCenterArm64Filename = 'WinsVPN-PartnerCenter-arm64.exe'
$WebsiteX64Filename = 'WinsVPN-Setup.exe'
$WebsiteArm64Filename = 'WinsVPN-Setup-arm64.exe'
$Arm64MsixFilename = "WinsVPN-Store-$CanonicalPackageVersion-arm64.msix"
$RequiredMsixCapabilityNames = @(
    'internetClient',
    'privateNetworkClientServer',
    'runFullTrust',
    'allowElevation'
)
$ForbiddenMsixCapabilityNames = @(
    'broadFileSystemAccess',
    'packageManagement',
    'documentsLibrary',
    'enterpriseAuthentication',
    'sharedUserCertificates',
    'removableStorage'
)
$ForbiddenMsixIdentityLeaves = @(
    $PartnerCenterX64Filename,
    $PartnerCenterArm64Filename,
    $WebsiteX64Filename,
    $WebsiteArm64Filename,
    $Arm64MsixFilename,
    'AppxSignature.p7x'
)
$ForbiddenMsixSignerTimestampArguments = @(
    'sign', '/tr', '/td', '/tw', '/as', '/ac', '/fd', '/sha1'
)
$script:MsixPublishedByThisRun = $false
$script:MsixReceiptPublishedByThisRun = $false
$script:MsixStagedPackage = ''
$script:MsixCanonicalPackage = ''
$script:MsixPayloadManifest = ''
$script:MsixStage = ''
$script:MsixExtractedMsi = ''
$script:MsixVerifyDirectory = ''
$script:StoreArchitecture = $CanonicalMsixArchitecture
$script:MsixSigning = $null
$script:MsixSignatureEvidence = [System.Collections.Generic.List[object]]::new()

function Assert-MsixSafeToken {
    param(
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory=$true)][string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "$Label is empty." }
    if ($Value -match '[\x00-\x1f\x7f"`|*?<>]') {
        throw "$Label contains a forbidden path or argument character."
    }
    if ($Value.Contains('--%')) {
        throw "$Label contains a PowerShell stop-parsing token."
    }
}

function Assert-MsixMsiexecPath {
    param(
        [Parameter(Mandatory=$true)][string]$Value,
        [Parameter(Mandatory=$true)][string]$Label
    )
    Assert-MsixSafeToken -Value $Value -Label $Label
    if ($Value.IndexOfAny([char[]]@('"', '=', ';', '&')) -ge 0) {
        throw "$Label contains a character that would inject msiexec arguments."
    }
}

function Assert-MsixArgumentList {
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$Purpose
    )
    foreach ($argument in @($Arguments)) {
        if ([string]::IsNullOrWhiteSpace($argument)) {
            throw "$Purpose argument list contains an empty token."
        }
        if ($argument -match '[\x00-\x1f\x7f]') {
            throw "$Purpose argument contains a control character."
        }
        foreach ($forbidden in $ForbiddenMsixSignerTimestampArguments) {
            if ($argument.Equals($forbidden, [StringComparison]::OrdinalIgnoreCase)) {
                throw "MSIX producer refuses signer/timestamp argument $forbidden. x64 and arm64 Partner Center candidates are signed then timestamped by tools/windows_inno_sign.ps1."
            }
        }
    }
}

function Assert-MsixSignerTimestampOrder {
    param([Parameter(Mandatory=$true)][AllowEmptyCollection()][string[]]$Arguments)
    $sign = -1
    $timestamp = -1
    $digest = -1
    $verify = -1
    $timestampVerify = -1
    for ($index = 0; $index -lt $Arguments.Count; $index++) {
        $token = [string]$Arguments[$index]
        if ($token.Equals('sign', [StringComparison]::OrdinalIgnoreCase) -and $sign -lt 0) { $sign = $index }
        elseif ($token.Equals('/tr', [StringComparison]::OrdinalIgnoreCase) -and $timestamp -lt 0) { $timestamp = $index }
        elseif ($token.Equals('/td', [StringComparison]::OrdinalIgnoreCase) -and $digest -lt 0) { $digest = $index }
        elseif ($token.Equals('verify', [StringComparison]::OrdinalIgnoreCase) -and $verify -lt 0) { $verify = $index }
        elseif ($token.Equals('/tw', [StringComparison]::OrdinalIgnoreCase) -and $timestampVerify -lt 0) { $timestampVerify = $index }
        elseif ($token.Equals('/as', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'partially signed artifact is not shippable'
        }
    }
    if ($timestamp -ge 0 -and ($sign -lt 0 -or $timestamp -lt $sign)) {
        throw 'timestamp must not precede signer'
    }
    if ($digest -ge 0 -and ($timestamp -lt 0 -or $digest -lt $timestamp)) {
        throw 'timestamp digest must follow the timestamp URL'
    }
    if ($verify -ge 0 -and ($sign -lt 0 -or $verify -lt $sign -or $timestamp -lt 0 -or $verify -lt $timestamp)) {
        throw 'SignTool verify must follow signer then timestamp'
    }
    if ($timestampVerify -ge 0 -and ($verify -lt 0 -or $timestampVerify -lt $verify)) {
        throw 'timestamp verification /tw must follow SignTool verify'
    }
}

function Test-MsixPathIsInsideRoot {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Root
    )
    $fullPath = [IO.Path]::GetFullPath($Path)
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    if ($fullPath.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    foreach ($separator in @([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar, [char]'\', [char]'/')) {
        $prefix = $rootFull + [string]$separator
        if ($fullPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Get-ValidatedMsixContainerRoot {
    param(
        [Parameter(Mandatory=$true)][string]$Root,
        [Parameter(Mandatory=$true)][string]$Purpose
    )
    if ([string]::IsNullOrWhiteSpace($Root)) { throw "$Purpose root is empty." }
    $rootFull = [IO.Path]::GetFullPath($Root)
    $pathRoot = [IO.Path]::GetPathRoot($rootFull)
    $rootTrimmed = $rootFull.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $pathRootTrimmed = ([string]$pathRoot).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    if ([string]::IsNullOrEmpty($rootTrimmed) -or
        [string]::Equals($rootTrimmed, $pathRootTrimmed, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing a filesystem-root container for ${Purpose}: $rootFull"
    }
    return $rootTrimmed
}

function Assert-NoReparsePointChain {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Label
    )
    $full = [IO.Path]::GetFullPath($Path)
    $cursor = $full
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            $linkType = [string]$item.LinkType
            $isReparse = (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
                ($linkType -in @('SymbolicLink', 'Junction'))
            if ($isReparse) {
                throw "$Label path crosses a reparse point: $cursor"
            }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Assert-MsixNotPartnerCenterLeaf {
    param(
        [Parameter(Mandatory=$true)][string]$Leaf,
        [Parameter(Mandatory=$true)][string]$Label
    )
    foreach ($forbidden in $ForbiddenMsixIdentityLeaves) {
        if ($Leaf.Equals($forbidden, [StringComparison]::OrdinalIgnoreCase)) {
            throw "$Label collides with a signed website or Partner Center payload identity: $forbidden"
        }
    }
}

function Assert-MsixNotPartnerCenterPath {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Label
    )
    $full = [IO.Path]::GetFullPath($Path)
    Assert-MsixNotPartnerCenterLeaf -Leaf ([IO.Path]::GetFileName($full)) -Label $Label
    foreach ($forbidden in $ForbiddenMsixIdentityLeaves) {
        if ($full.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "$Label collides with a signed website or Partner Center payload identity: $forbidden"
        }
    }
    $installerRoot = [IO.Path]::GetFullPath((Join-Path $Root 'build\windows-installer'))
    if (Test-MsixPathIsInsideRoot -Path $full -Root $installerRoot) {
        throw "$Label must not write into the Inno website/Partner Center output directory."
    }
}

function Assert-MsixRepoBoundPath {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Label
    )
    Assert-MsixSafeToken -Value $Path -Label $Label
    $full = Get-ValidatedMsixContainerRoot -Root ([IO.Path]::GetFullPath($Path)) -Purpose $Label
    Assert-MsixNotPartnerCenterPath -Path $full -Label $Label
    if (-not (Test-MsixPathIsInsideRoot -Path $full -Root $Root)) {
        throw "$Label must stay inside the repository tree."
    }
    Assert-NoReparsePointChain -Path $full -Label $Label
    return $full
}

function Assert-MsixIdentityContract {
    param(
        [Parameter(Mandatory=$true)][string]$IdentityName,
        [Parameter(Mandatory=$true)][string]$Publisher,
        [Parameter(Mandatory=$true)][string]$PublisherDisplayName,
        [Parameter(Mandatory=$true)][string]$Architecture,
        [Parameter(Mandatory=$true)][string]$PackageVersion,
        [switch]$Production
    )
    Assert-MsixSafeToken -Value $IdentityName -Label 'MSIX identity name'
    Assert-MsixSafeToken -Value $Publisher -Label 'MSIX publisher'
    Assert-MsixSafeToken -Value $PublisherDisplayName -Label 'MSIX publisher display name'
    if ($IdentityName -notmatch '^[A-Za-z0-9.-]{3,50}$') {
        throw 'MSIX identity name contains unsupported characters or length.'
    }
    if ($Publisher -notmatch '^CN=') { throw 'MSIX publisher must start with CN=.' }
    if ($Architecture -cne $CanonicalMsixArchitecture) {
        throw 'MSIX architecture must be exactly x64. ARM64 MSIX packaging is disabled; use the native ARM64 Inno Partner Center candidate.'
    }
    if ($PackageVersion -cne $CanonicalPackageVersion) {
        throw "MSIX identity version $PackageVersion is not the pubspec.yaml release mapping $CanonicalSourceVersion / $CanonicalPackageVersion."
    }
    if ($Production) {
        if ($IdentityName -ceq $DevelopmentIdentityName -or $Publisher -ceq $DevelopmentPublisher -or
            $PublisherDisplayName -ceq $DevelopmentPublisherDisplayName) {
            throw 'Production MSIX identity must be the Partner Center identity, not the WinsVPN.Development experiment identity.'
        }
        return
    }
    if ($IdentityName -ceq 'WinsVPN' -or $Publisher -match "WIN'S VPN INC") {
        throw 'Development MSIX identity must not use the production Store name or WIN''S VPN INC. publisher.'
    }
    if ($IdentityName -cne $DevelopmentIdentityName -or
        $Publisher -cne $DevelopmentPublisher -or
        $PublisherDisplayName -cne $DevelopmentPublisherDisplayName) {
        throw 'Development MSIX identity must be the exact WinsVPN.Development / CN=WinsVPNDevelopment contract.'
    }
}

function New-MsixMsiexecExtractArgumentList {
    param(
        [Parameter(Mandatory=$true)][string]$MsiPath,
        [Parameter(Mandatory=$true)][string]$Destination
    )
    Assert-MsixMsiexecPath -Value $MsiPath -Label 'AmneziaWG MSI path'
    Assert-MsixMsiexecPath -Value $Destination -Label 'msiexec TARGETDIR'
    $arguments = @('/a', $MsiPath, '/qn', ('TARGETDIR=' + $Destination), '/norestart')
    Assert-MsixArgumentList -Arguments $arguments -Purpose 'msiexec'
    return $arguments
}

function New-MsixMakeAppxPackArgumentList {
    param(
        [Parameter(Mandatory=$true)][string]$StageDirectory,
        [Parameter(Mandatory=$true)][string]$PackagePath
    )
    Assert-MsixSafeToken -Value $StageDirectory -Label 'makeappx pack directory'
    Assert-MsixSafeToken -Value $PackagePath -Label 'makeappx pack output'
    Assert-MsixNotPartnerCenterPath -Path $PackagePath -Label 'makeappx pack output'
    $arguments = @('pack', '/d', $StageDirectory, '/p', $PackagePath)
    Assert-MsixArgumentList -Arguments $arguments -Purpose 'makeappx pack'
    return $arguments
}

function New-MsixMakeAppxUnpackArgumentList {
    param(
        [Parameter(Mandatory=$true)][string]$PackagePath,
        [Parameter(Mandatory=$true)][string]$Destination
    )
    Assert-MsixSafeToken -Value $PackagePath -Label 'makeappx unpack input'
    Assert-MsixSafeToken -Value $Destination -Label 'makeappx unpack directory'
    $arguments = @('unpack', '/p', $PackagePath, '/d', $Destination, '/nv')
    Assert-MsixArgumentList -Arguments $arguments -Purpose 'makeappx unpack'
    return $arguments
}

function Invoke-Native {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments
    )
    Assert-MsixSafeToken -Value $FilePath -Label 'native executable'
    $leaf = [IO.Path]::GetFileName($FilePath)
    if ($leaf.Equals('signtool.exe', [StringComparison]::OrdinalIgnoreCase) -or
        $leaf.Equals('signtool', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'MSIX producer refuses SignTool through Invoke-Native. Signing runs only through Invoke-WinsProducerSigning with the approved-root Microsoft-signed SignTool, signer regex, chain and timestamp checks.'
    }
    if ($null -eq $Arguments) { $Arguments = @() }
    Assert-MsixArgumentList -Arguments $Arguments -Purpose $leaf
    if ($leaf.Equals('makeappx.exe', [StringComparison]::OrdinalIgnoreCase) -or
        $leaf.Equals('makeappx', [StringComparison]::OrdinalIgnoreCase)) {
        if ($Arguments.Count -lt 1 -or ($Arguments[0] -cne 'pack' -and $Arguments[0] -cne 'unpack')) {
            throw 'makeappx is limited to pack and unpack; sign is refused for MSIX.'
        }
    }
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE."
    }
}

function Find-WindowsSdkTool {
    param([Parameter(Mandatory=$true)][string]$Name)
    Assert-MsixSafeToken -Value $Name -Label 'Windows SDK tool name'
    if ($Name -notmatch '^[A-Za-z0-9]+\.exe$') {
        throw 'Windows SDK tool name is not an exact executable leaf.'
    }
    $kitRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if ([string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)}) -or -not (Test-Path -LiteralPath $kitRoot -PathType Container)) {
        throw "$Name was not found in the Windows SDK."
    }
    Assert-NoReparsePointChain -Path $kitRoot -Label 'Windows SDK kit root'
    $preferred = @($script:StoreArchitecture)
    if ($preferred -notcontains 'x64') { $preferred += 'x64' }
    $versionDirs = @(Get-ChildItem -LiteralPath $kitRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object { try { [version]$_.Name } catch { [version]'0.0' } } -Descending)
    foreach ($versionDir in $versionDirs) {
        foreach ($arch in $preferred) {
            if ($arch -notmatch '^(x64|arm64|x86)$') { continue }
            $tool = Join-Path $versionDir.FullName (Join-Path $arch $Name)
            if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { continue }
            Assert-NoReparsePointChain -Path $tool -Label "$Name SDK tool"
            $resolved = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $tool).Path)
            if (-not (Test-MsixPathIsInsideRoot -Path $resolved -Root $kitRoot)) {
                throw "$Name resolved outside the Windows SDK kit root."
            }
            if (-not [IO.Path]::GetFileName($resolved).Equals($Name, [StringComparison]::OrdinalIgnoreCase)) {
                throw "$Name resolved to an unexpected leaf."
            }
            return $resolved
        }
    }
    throw "$Name was not found in the Windows SDK."
}

function Write-AtomicNewUtf8File {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Contents
    )
    Assert-MsixSafeToken -Value $Path -Label 'atomic UTF-8 path'
    $directory = [IO.Path]::GetDirectoryName($Path)
    if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw "Atomic UTF-8 parent directory is missing: $directory"
    }
    $temporary = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temporary, $Contents, [Text.UTF8Encoding]::new($false))
        if (Test-Path -LiteralPath $Path) {
            throw "Refusing to overwrite an existing MSIX receipt: $Path"
        }
        [IO.File]::Move($temporary, $Path)
    } catch {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Quarantine-StaleMsixOutputs {
    param(
        [Parameter(Mandatory=$true)][string]$PackagePath,
        [Parameter(Mandatory=$true)][string]$ReceiptPath
    )
    $parent = [IO.Path]::GetDirectoryName($PackagePath)
    $quarantine = Join-Path $parent ('.msix-quarantine-' + [guid]::NewGuid().ToString('N'))
    foreach ($path in @($PackagePath, $ReceiptPath, $script:MsixStagedPackage)) {
        if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) { continue }
        if (-not (Test-Path -LiteralPath $quarantine -PathType Container)) {
            New-Item -ItemType Directory -Force -Path $quarantine | Out-Null
        }
        Move-Item -LiteralPath $path -Destination (Join-Path $quarantine ([IO.Path]::GetFileName($path)))
    }
    foreach ($path in @($PackagePath, $ReceiptPath)) {
        if (Test-Path -LiteralPath $path) {
            throw "Stale canonical MSIX output survived quarantine: $path"
        }
    }
}

function Remove-MsixPartialOutputs {
    $paths = @(
        $script:MsixStagedPackage,
        $script:MsixVerifyDirectory,
        $script:MsixExtractedMsi,
        $script:MsixStage
    )
    if (-not $script:MsixReceiptPublishedByThisRun) { $paths += $script:MsixPayloadManifest }
    if (-not $script:MsixPublishedByThisRun) { $paths += $script:MsixCanonicalPackage }
    foreach ($path in $paths) {
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $path) {
            throw "Partial MSIX output could not be removed: $path"
        }
    }
}

function Assert-MsixPackedManifestText {
    param(
        [Parameter(Mandatory=$true)][string]$Text,
        [Parameter(Mandatory=$true)][string]$IdentityName,
        [Parameter(Mandatory=$true)][string]$Publisher,
        [Parameter(Mandatory=$true)][string]$PackageVersion,
        [Parameter(Mandatory=$true)][string]$Architecture,
        [Parameter(Mandatory=$true)][string]$PublisherDisplayName
    )
    if ($Text -match '@[A-Z_]+@') { throw 'Unresolved MSIX manifest token remains.' }
    $xml = [xml]$Text
    $id = $xml.Package.Identity
    if ($id.Name -cne $IdentityName -or
        $id.Publisher -cne $Publisher -or
        $id.Version -cne $PackageVersion -or
        $id.ProcessorArchitecture -cne $Architecture) {
        throw 'Packed MSIX identity does not match the requested Partner Center identity.'
    }
    if ($id.ProcessorArchitecture -cne $CanonicalMsixArchitecture -or $Architecture -cne $CanonicalMsixArchitecture) {
        throw 'Packed MSIX architecture is not the exact x64 identity; ARM64 MSIX is disabled.'
    }
    if ($id.Version -cne $CanonicalPackageVersion) {
        throw "Packed MSIX version is not the pubspec.yaml package version $CanonicalPackageVersion."
    }
    $display = [string]$xml.Package.Properties.PublisherDisplayName
    if ($display -cne $PublisherDisplayName) {
        throw 'Packed MSIX publisher display name does not match the exact identity contract.'
    }
    $executable = [string]$xml.Package.Applications.Application.Executable
    if ($executable -cne 'wins_vpn.exe') {
        throw 'Packed MSIX application executable is not wins_vpn.exe.'
    }
    $capabilityMatches = [regex]::Matches($Text, 'Capability Name="([^"]+)"')
    $actualCapabilities = @($capabilityMatches | ForEach-Object { $_.Groups[1].Value })
    if (($actualCapabilities -join ',') -cne ($RequiredMsixCapabilityNames -join ',')) {
        throw 'Packed MSIX capability set is not the exact reviewed contract.'
    }
    foreach ($forbidden in $ForbiddenMsixCapabilityNames) {
        if ($Text.Contains($forbidden)) {
            throw "Packed MSIX includes a forbidden capability: $forbidden"
        }
    }
}

function Assert-MsixStageForbidsForeignIdentities {
    param(
        [Parameter(Mandatory=$true)][string]$StageRoot,
        [switch]$PackedSignatureAllowed
    )
    $rootFull = [IO.Path]::GetFullPath($StageRoot).TrimEnd('\', '/')
    $files = @(Get-ChildItem -LiteralPath $StageRoot -Recurse -File -Force -ErrorAction SilentlyContinue)
    foreach ($file in $files) {
        # Only an unpacked signed package may carry its own root AppxSignature.p7x.
        if ($PackedSignatureAllowed -and $file.Name -ceq 'AppxSignature.p7x' -and
            [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($file.FullName)).TrimEnd('\', '/') -eq $rootFull) {
            continue
        }
        Assert-MsixNotPartnerCenterLeaf -Leaf $file.Name -Label "Staged MSIX payload $($file.Name)"
        if ($file.Extension.Equals('.msix', [StringComparison]::OrdinalIgnoreCase) -and
            -not $file.Name.Equals($CanonicalMsixFilename, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Staged MSIX payload uses a non-canonical package leaf: $($file.Name)"
        }
    }
}

function Assert-MsixPackageUnsigned {
    param(
        [Parameter(Mandatory=$true)][string]$PackagePath,
        [Parameter(Mandatory=$true)][string]$VerifyRoot
    )
    $signature = Join-Path $VerifyRoot 'AppxSignature.p7x'
    if (Test-Path -LiteralPath $signature) {
        throw 'Packed MSIX contains AppxSignature.p7x but no signing identity is configured; an unsigned build must carry no package signature.'
    }
    $command = Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue
    if ($command) {
        $authenticode = Get-AuthenticodeSignature -LiteralPath $PackagePath
        if ([string]$authenticode.Status -cne 'NotSigned') {
            throw "Packed MSIX Authenticode status is $($authenticode.Status); an unsigned build must be NotSigned."
        }
        if ($authenticode.SignerCertificate -or $authenticode.TimeStamperCertificate) {
            throw 'Packed MSIX has a signer or timestamp certificate but no signing identity is configured.'
        }
    }
}

function Assert-MsixPackageSigned {
    param(
        [Parameter(Mandatory=$true)][string]$PackagePath,
        [Parameter(Mandatory=$true)][string]$VerifyRoot
    )
    if ($null -eq $script:MsixSigning) {
        throw 'Assert-MsixPackageSigned requires a resolved signing identity.'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $VerifyRoot 'AppxSignature.p7x') -PathType Leaf)) {
        throw 'Signed MSIX is missing AppxSignature.p7x.'
    }
    return (Assert-WinsProducerSignature -Path $PackagePath `
        -SignerPattern ([string]$script:MsixSigning.SignerPattern) `
        -SignTool ([string]$script:MsixSigning.SignTool) `
        -ExpectedLeafSha256 ([string]$script:MsixSigning.LeafSha256Pin))
}

function Assert-MsixPackageSignatureState {
    # Unsigned rehearsal: no package or payload signature at all. Signed:
    # package signature plus every first-party PE, verified with the same
    # policy as build_installer.ps1. Pinned dependency leaves keep their
    # reviewed bytes and are bound by SHA-256 elsewhere.
    param(
        [Parameter(Mandatory=$true)][string]$PackagePath,
        [Parameter(Mandatory=$true)][string]$VerifyRoot
    )
    if ($null -eq $script:MsixSigning) {
        Assert-MsixPackageUnsigned -PackagePath $PackagePath -VerifyRoot $VerifyRoot
        return
    }
    [void](Assert-MsixPackageSigned -PackagePath $PackagePath -VerifyRoot $VerifyRoot)
    foreach ($path in @(Get-MsixSigningPlan -StageRoot $VerifyRoot)) {
        [void](Assert-WinsProducerSignature -Path $path `
            -SignerPattern ([string]$script:MsixSigning.SignerPattern) `
            -SignTool ([string]$script:MsixSigning.SignTool) `
            -ExpectedLeafSha256 ([string]$script:MsixSigning.LeafSha256Pin))
    }
}

function Get-MsixSigningPlan {
    # Engines first, then every other first-party PE. Pinned dependency
    # leaves at the stage root are copied over the stage after signing and
    # keep their exact reviewed bytes, so they are never in the plan.
    param([Parameter(Mandatory=$true)][string]$StageRoot)
    $stageFull = [IO.Path]::GetFullPath($StageRoot).TrimEnd('\', '/')
    $engines = @()
    foreach ($name in $MsixFirstPartyEngineLeaves) {
        $path = Join-Path $stageFull $name
        if (Test-Path -LiteralPath $path -PathType Leaf) { $engines += [IO.Path]::GetFullPath($path) }
    }
    $products = @()
    foreach ($file in @(Get-ChildItem -LiteralPath $stageFull -Recurse -File -Force)) {
        if ($file.Extension.ToLowerInvariant() -notin @('.exe', '.dll')) { continue }
        $full = [IO.Path]::GetFullPath($file.FullName)
        if ($engines -contains $full) { continue }
        $atRoot = [IO.Path]::GetDirectoryName($full).TrimEnd('\', '/') -eq $stageFull
        if ($atRoot -and $MsixPinnedDependencyLeaves -contains $file.Name) { continue }
        $products += $full
    }
    $products = @($products | Sort-Object -CaseSensitive)
    if (@($products | Where-Object { [IO.Path]::GetFileName($_) -ceq 'wins_vpn.exe' }).Count -ne 1) {
        throw 'MSIX signing plan is missing the first-party product wins_vpn.exe.'
    }
    return @($engines) + @($products)
}

function Invoke-MsixFirstPartySigning {
    param([Parameter(Mandatory=$true)][string]$StageRoot)
    if ($null -eq $script:MsixSigning) {
        throw 'Invoke-MsixFirstPartySigning requires a resolved signing identity.'
    }
    $stageFull = [IO.Path]::GetFullPath($StageRoot).TrimEnd('\', '/')
    $script:MsixSignatureEvidence = [System.Collections.Generic.List[object]]::new()
    foreach ($path in @(Get-MsixSigningPlan -StageRoot $stageFull)) {
        $evidence = Invoke-WinsProducerSigning -Path $path -Signing $script:MsixSigning
        [void]$script:MsixSignatureEvidence.Add([ordered]@{
            path = $path.Substring($stageFull.Length + 1).Replace('\', '/')
            signer_subject = [string]$evidence.signer_subject
            signer_leaf_sha256 = [string]$evidence.signer_leaf_sha256
        })
    }
}

function Get-FileSha256 {
    param([Parameter(Mandatory=$true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-NotRejectedSha256 {
    param(
        [Parameter(Mandatory=$true)][string]$Actual,
        [Parameter(Mandatory=$true)][string]$Rejected,
        [Parameter(Mandatory=$true)][string]$Label
    )
    if ($Actual -ceq $Rejected) {
        throw "$Label matches the rejected legacy 2.0.1 identity $Rejected. Official AWG 3.1.0 is required."
    }
}

function Assert-PinnedFile {
    param([Parameter(Mandatory=$true)][string]$Name)
    $path = Join-Path $DependencyDirectory $Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Pinned Windows dependency is missing: $Name"
    }
    $actual = Get-FileSha256 -Path $path
    if ($RejectedLegacy.ContainsKey($Name)) {
        Assert-NotRejectedSha256 -Actual $actual -Rejected $RejectedLegacy[$Name] `
            -Label "Cached Windows dependency $Name"
    }
    if ($actual -cne $Pinned[$Name]) {
        throw "Pinned Windows dependency SHA-256 mismatch: $Name. Expected=$($Pinned[$Name]) Actual=$actual. Refusing to package stale or mixed Windows dependencies."
    }
    return $path
}

function Assert-AmneziaWgHelperProvenance {
    # Binds the committed helper provenance to the pins of its only producer,
    # tools/build_windows_amneziawg_client.ps1 (product helper 902c9f28...,
    # Go 1.27.1 archive a3911b5e...), never to the file's own hash.
    $provenancePath = Join-Path $DependencyDirectory 'amneziawg.exe.provenance.json'
    if (-not (Test-Path -LiteralPath $provenancePath -PathType Leaf)) {
        throw 'The rebuilt AmneziaWG maintenance-helper provenance is missing.'
    }
    try { $evidence = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json }
    catch { throw "The rebuilt AmneziaWG provenance is invalid JSON: $($_.Exception.Message)" }
    if ($null -eq $evidence -or $evidence -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'The rebuilt AmneziaWG provenance is not a JSON object.'
    }
    $schemaProperty = $evidence.PSObject.Properties['schema_version']
    $schema = if ($null -eq $schemaProperty) { $null } else { $schemaProperty.Value }
    if ($null -eq $schema -or $schema -is [bool] -or $schema -is [string] -or
        ($schema -isnot [int] -and $schema -isnot [long]) -or [int64]$schema -ne 2) {
        throw "AmneziaWG helper provenance schema_version is $schema; tools/build_windows_amneziawg_client.ps1 writes schema 2. Rebuild the helper with that producer on a Windows host."
    }
    $expected = [ordered]@{
        source_version = $AmneziaWgVersion
        source_commit = $AmneziaWgSourceCommit
        windows_library_version = $AmneziaWgWindowsLibraryVersion
        windows_library_commit = $AmneziaWgWindowsLibraryCommit
        engine_version = $AmneziaWgEngineVersion
        engine_commit = $AmneziaWgEngineCommit
        go_version = $AmneziaWgHelperGoVersion
        go_archive_sha256 = $AmneziaWgHelperGoArchiveSha256
        target = 'windows-amd64'
        unsigned_artifact_sha256 = $Pinned['amneziawg.exe']
    }
    foreach ($name in $expected.Keys) {
        $property = $evidence.PSObject.Properties[$name]
        if ($null -eq $property -or $property.Value -isnot [string] -or
            [string]$property.Value -cne [string]$expected[$name]) {
            throw "AmneziaWG helper provenance field $name does not match the reviewed producer pin $($expected[$name]) from tools/build_windows_amneziawg_client.ps1. Rebuild the helper with that producer on a Windows host."
        }
    }
}

function Assert-OfficialAwg31Dependencies {
    foreach ($name in @(
        'amneziawg-amd64.msi',
        'awg.exe',
        'amneziawg.exe',
        'wintun.dll',
        'xray.exe'
    )) {
        Assert-PinnedFile $name | Out-Null
    }
    Assert-AmneziaWgHelperProvenance
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

function Get-MsixPeCoffMachine {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    try {
        if ($stream.Length -lt 64) { return [uint16]0 }
        $reader = New-Object IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { return [uint16]0 }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -gt ($stream.Length - 26)) { return [uint16]0 }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { return [uint16]0 }
        $machine = $reader.ReadUInt16()
        $sectionCount = $reader.ReadUInt16()
        $stream.Position = $peOffset + 20
        $optionalHeaderSize = $reader.ReadUInt16()
        if ($sectionCount -eq 0 -or $optionalHeaderSize -lt 2 -or
            ($peOffset + 24 + $optionalHeaderSize) -gt $stream.Length) { return [uint16]0 }
        $stream.Position = $peOffset + 24
        $optionalMagic = $reader.ReadUInt16()
        $pe32Plus = [uint16]0x020b
        $pe32 = [uint16]0x010b
        if (($machine -eq $MsixX64PeMachine -and $optionalMagic -ne $pe32Plus) -or
            ($machine -eq [uint16]0xAA64 -and $optionalMagic -ne $pe32Plus) -or
            ($machine -eq $MsixX86PeMachine -and $optionalMagic -ne $pe32)) { return [uint16]0 }
        return $machine
    } finally { $stream.Dispose() }
}

function Test-MsixFileContainsMarker {
    param([string]$Path, [string]$Needle)
    $text = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($Path))
    return $text.IndexOf($Needle, [StringComparison]::Ordinal) -ge 0
}

function Remove-MsixDebugSymbolFiles {
    param([Parameter(Mandatory = $true)][string]$StageRoot)
    $blocked = @('.pdb', '.ilk', '.iobj', '.ipdb', '.map', '.sym', '.dbg', '.debug')
    $found = @(Get-ChildItem -LiteralPath $StageRoot -Recurse -File -Force |
        Where-Object { $blocked -contains $_.Extension.ToLowerInvariant() })
    foreach ($file in $found) {
        Remove-Item -LiteralPath $file.FullName -Force
    }
    $leftover = @(Get-ChildItem -LiteralPath $StageRoot -Recurse -File -Force |
        Where-Object { $blocked -contains $_.Extension.ToLowerInvariant() })
    if ($leftover.Count -gt 0) {
        throw ("MSIX stage still contains debug symbol files: " + ($leftover.FullName -join ', '))
    }
}

function Assert-MsixStageCompleteness {
    param(
        [Parameter(Mandatory = $true)][string]$StageRoot,
        [switch]$PackedSignatureAllowed
    )
    $problems = @()
    foreach ($name in @(
        'wins_vpn.exe',
        'winn-datapath.exe',
        'winsvpn_winn3_engine.exe',
        'winsvpn_awg_engine.exe',
        'awg.exe',
        'wintun.dll',
        'xray.exe',
        'amneziawg.exe'
    )) {
        $path = Join-Path $StageRoot $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            $problems += "$name was not staged; Winn v3 primary plus Winn v1 AWG then Xray fallback is required"
        }
    }
    $datapath = Join-Path $StageRoot 'winn-datapath.exe'
    if ((Test-Path -LiteralPath $datapath -PathType Leaf) -and
        -not (Test-MsixFileContainsMarker -Path $datapath -Needle $Winn3Marker)) {
        $problems += "winn-datapath.exe was staged but contains no '$Winn3Marker' reference, so it does not carry Winn Protocol v3."
    }
    $blocked = @('.pdb', '.ilk', '.iobj', '.ipdb', '.map', '.sym', '.dbg', '.debug')
    $symbols = @(Get-ChildItem -LiteralPath $StageRoot -Recurse -File -Force |
        Where-Object { $blocked -contains $_.Extension.ToLowerInvariant() })
    if ($symbols.Count -gt 0) {
        $problems += ("debug symbol files must not ship in MSIX: " + ($symbols.Name -join ', '))
    }
    foreach ($file in @(Get-ChildItem -LiteralPath $StageRoot -Recurse -File -Force |
        Where-Object { $_.Extension.ToLowerInvariant() -in @('.exe', '.dll', '.sys') })) {
        Assert-MsixNotPartnerCenterLeaf -Leaf $file.Name -Label "MSIX payload $($file.Name)"
        $actual = Get-MsixPeCoffMachine -Path $file.FullName
        if ($actual -eq $MsixArm64PeMachine) {
            $problems += "$($file.Name) is ARM64 PE/COFF; MSIX packaging cannot relabel ARM64 Partner Center payloads as MSIX"
        } elseif ($actual -ne $MsixX64PeMachine) {
            $problems += ("$($file.Name) has PE/COFF machine 0x{0:x4}; MSIX packaging is x64-only (0x8664)" -f $actual)
        }
    }
    Assert-MsixStageForbidsForeignIdentities -StageRoot $StageRoot -PackedSignatureAllowed:$PackedSignatureAllowed
    if ($problems.Count -gt 0) {
        throw ("MSIX payload is not a complete Winn v3 + v1 artifact:`n - " + ($problems -join "`n - "))
    }
}

function Assert-MsixPostBuildReAudit {
    param(
        [Parameter(Mandatory=$true)][string]$VerifyRoot,
        [Parameter(Mandatory=$true)][string]$PackagePath,
        [Parameter(Mandatory=$true)][string]$ReceiptPath,
        [Parameter(Mandatory=$true)][string]$IdentityName,
        [Parameter(Mandatory=$true)][string]$Publisher,
        [Parameter(Mandatory=$true)][string]$PublisherDisplayName,
        [Parameter(Mandatory=$true)][string]$PackageVersion,
        [Parameter(Mandatory=$true)][string]$Architecture
    )
    if (-not [IO.Path]::GetFileName($PackagePath).Equals($CanonicalMsixFilename, [StringComparison]::Ordinal)) {
        throw "Canonical MSIX filename is not $CanonicalMsixFilename."
    }
    $packedText = Get-Content -LiteralPath (Join-Path $VerifyRoot 'AppxManifest.xml') -Raw
    Assert-MsixPackedManifestText -Text $packedText `
        -IdentityName $IdentityName `
        -Publisher $Publisher `
        -PackageVersion $PackageVersion `
        -Architecture $Architecture `
        -PublisherDisplayName $PublisherDisplayName
    Assert-MsixStageCompleteness -StageRoot $VerifyRoot -PackedSignatureAllowed:($null -ne $script:MsixSigning)
    Assert-MsixPackageSignatureState -PackagePath $PackagePath -VerifyRoot $VerifyRoot
    foreach ($name in @('awg.exe', 'wintun.dll', 'xray.exe', 'amneziawg.exe')) {
        $path = Join-Path $VerifyRoot $name
        $actual = Get-FileSha256 -Path $path
        if ($actual -cne $Pinned[$name]) {
            throw "Post-build MSIX payload SHA-256 mismatch: $name. Expected=$($Pinned[$name]) Actual=$actual."
        }
    }
    $receipt = Get-Content -LiteralPath $ReceiptPath -Raw | ConvertFrom-Json
    $packageHash = Get-FileSha256 -Path $PackagePath
    if ([string]$receipt.artifact.sha256 -cne $packageHash) {
        throw 'Post-build MSIX receipt hash does not match the packed artifact.'
    }
    if ([string]$receipt.package_identity.name -cne $IdentityName -or
        [string]$receipt.package_identity.publisher -cne $Publisher -or
        [string]$receipt.package_identity.version -cne $CanonicalPackageVersion -or
        [string]$receipt.package_identity.architecture -cne $CanonicalMsixArchitecture) {
        throw 'Post-build MSIX receipt identity does not match the packed identity.'
    }
    $signed = $null -ne $script:MsixSigning
    $expectedStatus = if ($signed) { 'signed' } else { 'unsigned' }
    if ([string]$receipt.authenticode_status -cne $expectedStatus -or
        [bool]$receipt.authenticode_verified -ne $signed -or
        [bool]$receipt.timestamp_verified -ne $signed -or
        [bool]$receipt.artifact.signed -ne $signed -or
        @($receipt.signed_payloads).Count -ne $script:MsixSignatureEvidence.Count -or
        ($signed -and $script:MsixSignatureEvidence.Count -eq 0)) {
        throw "Post-build MSIX receipt does not record the $expectedStatus package truthfully."
    }
    if ([string]$receipt.signed_partner_center_payloads.x64 -cne $PartnerCenterX64Filename -or
        [string]$receipt.signed_partner_center_payloads.arm64 -cne $PartnerCenterArm64Filename) {
        throw 'Post-build MSIX receipt lost the exact x64/arm64 Partner Center signed payload binding.'
    }
    $expectedCapabilities = @($receipt.restricted_capabilities)
    if ($expectedCapabilities -notcontains 'runFullTrust' -or $expectedCapabilities -notcontains 'allowElevation') {
        throw 'Post-build MSIX receipt lost restricted capability binding.'
    }
}

function Get-ReleaseIdentity {
    return (Read-MsixPubspecReleaseIdentity -Path $Pubspec)
}

function Convert-ToXmlAttribute {
    param([Parameter(Mandatory=$true)][string]$Value)
    return [Security.SecurityElement]::Escape($Value)
}

function New-StoreAssets {
    param([Parameter(Mandatory=$true)][string]$Destination)
    try { Add-Type -AssemblyName System.Drawing.Common -ErrorAction Stop }
    catch { Add-Type -AssemblyName System.Drawing -ErrorAction Stop }

    $sourcePath = Join-Path $Root 'assets\icon\app_icon.png'
    $source = [Drawing.Image]::FromFile($sourcePath)
    try {
        $specs = @(
            @{ Name='StoreLogo.png'; Width=50; Height=50 },
            @{ Name='Square44x44Logo.png'; Width=44; Height=44 },
            @{ Name='Square150x150Logo.png'; Width=150; Height=150 },
            @{ Name='Square310x310Logo.png'; Width=310; Height=310 },
            @{ Name='Wide310x150Logo.png'; Width=310; Height=150 },
            @{ Name='SplashScreen.png'; Width=620; Height=300 }
        )
        New-Item -ItemType Directory -Force -Path $Destination | Out-Null
        foreach ($spec in $specs) {
            $bitmap = New-Object Drawing.Bitmap($spec.Width, $spec.Height)
            try {
                $graphics = [Drawing.Graphics]::FromImage($bitmap)
                try {
                    $graphics.Clear([Drawing.Color]::FromArgb(255, 7, 26, 42))
                    $graphics.CompositingQuality = [Drawing.Drawing2D.CompositingQuality]::HighQuality
                    $graphics.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                    $graphics.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::HighQuality
                    $scale = [Math]::Min($spec.Width / $source.Width, $spec.Height / $source.Height)
                    $width = [int][Math]::Round($source.Width * $scale)
                    $height = [int][Math]::Round($source.Height * $scale)
                    $x = [int](($spec.Width - $width) / 2)
                    $y = [int](($spec.Height - $height) / 2)
                    $graphics.DrawImage($source, $x, $y, $width, $height)
                } finally { $graphics.Dispose() }
                $bitmap.Save((Join-Path $Destination $spec.Name), [Drawing.Imaging.ImageFormat]::Png)
            } finally { $bitmap.Dispose() }
        }
    } finally { $source.Dispose() }
}

function Invoke-MsixProducerBoundarySelfTest {
    $script:StoreArchitecture = $CanonicalMsixArchitecture
    Assert-MsixIdentityContract -IdentityName $DevelopmentIdentityName `
        -Publisher $DevelopmentPublisher `
        -PublisherDisplayName $DevelopmentPublisherDisplayName `
        -Architecture $CanonicalMsixArchitecture `
        -PackageVersion $CanonicalPackageVersion
    foreach ($hostile in @(
        @{ Name = 'WinsVPN'; Publisher = $DevelopmentPublisher; Display = $DevelopmentPublisherDisplayName; Needle = 'production Store name' },
        @{ Name = $DevelopmentIdentityName; Publisher = "CN=WIN'S VPN INC."; Display = $DevelopmentPublisherDisplayName; Needle = "WIN'S VPN INC" },
        @{ Name = 'WinsVPN.Store'; Publisher = $DevelopmentPublisher; Display = $DevelopmentPublisherDisplayName; Needle = 'exact WinsVPN.Development' },
        @{ Name = $DevelopmentIdentityName; Publisher = 'CN=WinsVPNDevelopment; calc.exe'; Display = $DevelopmentPublisherDisplayName; Needle = 'exact WinsVPN.Development' },
        @{ Name = $DevelopmentIdentityName; Publisher = $DevelopmentPublisher; Display = $DevelopmentPublisherDisplayName; Architecture = 'arm64'; Needle = 'exactly x64' },
        @{ Name = $DevelopmentIdentityName; Publisher = $DevelopmentPublisher; Display = $DevelopmentPublisherDisplayName; Version = '0.0.0.1'; Needle = 'is not the pubspec.yaml release mapping' }
    )) {
        $arch = if ($hostile.ContainsKey('Architecture')) { [string]$hostile.Architecture } else { $CanonicalMsixArchitecture }
        $version = if ($hostile.ContainsKey('Version')) { [string]$hostile.Version } else { $CanonicalPackageVersion }
        $rejected = $true
        try {
            Assert-MsixIdentityContract -IdentityName ([string]$hostile.Name) `
                -Publisher ([string]$hostile.Publisher) `
                -PublisherDisplayName ([string]$hostile.Display) `
                -Architecture $arch `
                -PackageVersion $version
            $rejected = $false
        } catch {
            $rejected = $true
            if ($_.Exception.Message.IndexOf([string]$hostile.Needle, [StringComparison]::Ordinal) -lt 0) {
                throw "Identity self-test threw the wrong message for $($hostile.Name): $($_.Exception.Message)"
            }
        }
        if (-not $rejected) { throw "Identity self-test accepted hostile identity $($hostile.Name)." }
    }

    foreach ($token in @("`"`"evil", "a|b", "a<b>", "--% skip", ("a" + [char]7 + "b"))) {
        $rejected = $true
        try {
            Assert-MsixSafeToken -Value $token -Label 'hostile token'
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) { throw "Safe-token self-test accepted $token" }
    }

    $quotePath = 'C:\stage\evil".msi'
    $rejected = $true
    try {
        [void](New-MsixMsiexecExtractArgumentList -MsiPath $quotePath -Destination 'C:\stage\out')
        $rejected = $false
    } catch { $rejected = $true }
    if (-not $rejected) { throw 'msiexec argv self-test accepted a quote-injected MSI path.' }

    $ampPath = 'C:\stage\out&calc.exe'
    $rejected = $true
    try {
        [void](New-MsixMsiexecExtractArgumentList -MsiPath 'C:\stage\ok.msi' -Destination $ampPath)
        $rejected = $false
    } catch { $rejected = $true }
    if (-not $rejected) { throw 'msiexec argv self-test accepted a TARGETDIR injection.' }

    $okMsi = Join-Path $Root 'installer\windows\dependencies\amneziawg-amd64.msi'
    $okDest = Join-Path $Root 'build\windows-store\amneziawg-layout'
    $msiArgs = New-MsixMsiexecExtractArgumentList -MsiPath $okMsi -Destination $okDest
    if ($msiArgs[0] -cne '/a' -or $msiArgs[1] -cne $okMsi -or $msiArgs[3] -cne ('TARGETDIR=' + $okDest)) {
        throw 'msiexec argv self-test lost the exact array binding.'
    }
    if (@($msiArgs | Where-Object { $_.Contains('"') }).Count -ne 0) {
        throw 'msiexec argv self-test wrapped paths in injectable quotes.'
    }

    $partnerPackage = Join-Path $Root "build\windows-store\$PartnerCenterX64Filename"
    $rejected = $true
    try {
        [void](New-MsixMakeAppxPackArgumentList -StageDirectory (Join-Path $Root 'build\windows-store\stage') -PackagePath $partnerPackage)
        $rejected = $false
    } catch { $rejected = $true }
    if (-not $rejected) { throw 'makeappx pack self-test accepted a Partner Center EXE identity.' }

    $arm64Package = Join-Path $Root "build\windows-store\$Arm64MsixFilename"
    $rejected = $true
    try {
        [void](New-MsixMakeAppxPackArgumentList -StageDirectory (Join-Path $Root 'build\windows-store\stage') -PackagePath $arm64Package)
        $rejected = $false
    } catch { $rejected = $true }
    if (-not $rejected) { throw 'makeappx pack self-test accepted an ARM64 MSIX identity.' }

    $canonicalPackage = Join-Path $Root "build\windows-store\$CanonicalMsixFilename"
    $packArgs = New-MsixMakeAppxPackArgumentList -StageDirectory (Join-Path $Root 'build\windows-store\stage') -PackagePath $canonicalPackage
    if ($packArgs[0] -cne 'pack' -or $packArgs -contains '/o' -or $packArgs -contains 'sign') {
        throw 'makeappx pack argv is not the exact unsigned pack contract.'
    }

    foreach ($argv in @(
        @('sign', '/fd', 'SHA256', '/tr', 'http://timestamp.digicert.com', '/td', 'SHA256', 'payload.exe'),
        @('/tr', 'http://timestamp.digicert.com', 'sign', 'payload.exe'),
        @('pack', '/d', 'stage', '/p', 'out.msix', '/as')
    )) {
        $rejected = $true
        try {
            Assert-MsixArgumentList -Arguments $argv -Purpose 'hostile-sign'
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) { throw 'Signer/timestamp argv self-test accepted a signing token in the MSIX producer.' }
    }

    $inverted = @('/tr', 'http://timestamp.digicert.com', 'sign', '/fd', 'SHA256', $WebsiteX64Filename)
    $rejected = $true
    try {
        Assert-MsixSignerTimestampOrder -Arguments $inverted
        $rejected = $false
    } catch {
        $rejected = $true
        if ($_.Exception.Message.IndexOf('timestamp must not precede signer', [StringComparison]::Ordinal) -lt 0) {
            throw "Inverted signer/timestamp self-test threw the wrong message: $($_.Exception.Message)"
        }
    }
    if (-not $rejected) { throw 'Inverted signer/timestamp order was accepted.' }

    $append = @('sign', '/as', $PartnerCenterX64Filename)
    $rejected = $true
    try {
        Assert-MsixSignerTimestampOrder -Arguments $append
        $rejected = $false
    } catch {
        $rejected = $true
        if ($_.Exception.Message.IndexOf('partially signed artifact is not shippable', [StringComparison]::Ordinal) -lt 0) {
            throw "Partial-sign self-test threw the wrong message: $($_.Exception.Message)"
        }
    }
    if (-not $rejected) { throw 'Append-signature /as was accepted.' }

    Assert-MsixSignerTimestampOrder -Arguments @(
        'sign', '/v', '/fd', 'SHA256', '/tr', 'http://timestamp.digicert.com', '/td', 'SHA256', $PartnerCenterX64Filename
    )

    $rejected = $true
    try {
        Invoke-Native 'signtool.exe' @('sign', '/fd', 'SHA256', $CanonicalMsixFilename)
        $rejected = $false
    } catch { $rejected = $true }
    if (-not $rejected) { throw 'Invoke-Native accepted SignTool.' }

    $rejected = $true
    try {
        Assert-MsixIdentityContract -IdentityName $DevelopmentIdentityName `
            -Publisher $DevelopmentPublisher `
            -PublisherDisplayName $DevelopmentPublisherDisplayName `
            -Architecture $CanonicalMsixArchitecture `
            -PackageVersion $CanonicalPackageVersion -Production
        $rejected = $false
    } catch { $rejected = $true }
    if (-not $rejected) { throw 'Production identity self-test accepted the development identity.' }
    Assert-MsixIdentityContract -IdentityName 'WinsVPN.Product' `
        -Publisher 'CN=00000000-0000-0000-0000-000000000000' `
        -PublisherDisplayName "Win's VPN" `
        -Architecture $CanonicalMsixArchitecture `
        -PackageVersion $CanonicalPackageVersion -Production

    $goodXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10" xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10" xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="$DevelopmentIdentityName" Publisher="$DevelopmentPublisher" Version="$CanonicalPackageVersion" ProcessorArchitecture="$CanonicalMsixArchitecture" />
  <Properties><PublisherDisplayName>$DevelopmentPublisherDisplayName</PublisherDisplayName></Properties>
  <Applications><Application Id="WinsVPN" Executable="wins_vpn.exe" /></Applications>
  <Capabilities>
    <Capability Name="internetClient" />
    <Capability Name="privateNetworkClientServer" />
    <rescap:Capability Name="runFullTrust" />
    <rescap:Capability Name="allowElevation" />
  </Capabilities>
</Package>
"@
    Assert-MsixPackedManifestText -Text $goodXml `
        -IdentityName $DevelopmentIdentityName `
        -Publisher $DevelopmentPublisher `
        -PackageVersion $CanonicalPackageVersion `
        -Architecture $CanonicalMsixArchitecture `
        -PublisherDisplayName $DevelopmentPublisherDisplayName

    $badArch = $goodXml.Replace('ProcessorArchitecture="x64"', 'ProcessorArchitecture="arm64"')
    $rejected = $true
    try {
        Assert-MsixPackedManifestText -Text $badArch `
            -IdentityName $DevelopmentIdentityName `
            -Publisher $DevelopmentPublisher `
            -PackageVersion $CanonicalPackageVersion `
            -Architecture 'arm64' `
            -PublisherDisplayName $DevelopmentPublisherDisplayName
        $rejected = $false
    } catch { $rejected = $true }
    if (-not $rejected) { throw 'Packed-manifest self-test accepted an ARM64 MSIX identity.' }

    $extraCap = $goodXml.Replace('<rescap:Capability Name="allowElevation" />', '<rescap:Capability Name="allowElevation" /><rescap:Capability Name="broadFileSystemAccess" />')
    $rejected = $true
    try {
        Assert-MsixPackedManifestText -Text $extraCap `
            -IdentityName $DevelopmentIdentityName `
            -Publisher $DevelopmentPublisher `
            -PackageVersion $CanonicalPackageVersion `
            -Architecture $CanonicalMsixArchitecture `
            -PublisherDisplayName $DevelopmentPublisherDisplayName
        $rejected = $false
    } catch { $rejected = $true }
    if (-not $rejected) { throw 'Packed-manifest self-test accepted a forbidden capability.' }

    $boundaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('winsvpn-msix-boundary-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $boundaryRoot | Out-Null
    try {
        $outside = Join-Path $boundaryRoot $PartnerCenterX64Filename
        [IO.File]::WriteAllBytes($outside, [byte[]](0x4D, 0x5A) + [byte[]]::new(64))
        $rejected = $true
        try {
            Assert-MsixNotPartnerCenterPath -Path $outside -Label 'boundary payload'
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) { throw 'Foreign-identity self-test accepted a Partner Center EXE leaf.' }

        $partialPackage = Join-Path $boundaryRoot 'partial.msix'
        $partialReceipt = Join-Path $boundaryRoot 'partial.msix.payload-manifest.json'
        [IO.File]::WriteAllText($partialPackage, 'partial-msix')
        [IO.File]::WriteAllText($partialReceipt, '{}')
        $script:MsixPublishedByThisRun = $false
        $script:MsixReceiptPublishedByThisRun = $false
        $script:MsixCanonicalPackage = $partialPackage
        $script:MsixPayloadManifest = $partialReceipt
        $script:MsixStagedPackage = ''
        $script:MsixVerifyDirectory = ''
        $script:MsixExtractedMsi = ''
        $script:MsixStage = ''
        Remove-MsixPartialOutputs
        if ((Test-Path -LiteralPath $partialPackage) -or (Test-Path -LiteralPath $partialReceipt)) {
            throw 'Partial MSIX outputs survived failure cleanup.'
        }

        $keptPackage = Join-Path $boundaryRoot $CanonicalMsixFilename
        $keptReceipt = Join-Path $boundaryRoot ($CanonicalMsixFilename + '.payload-manifest.json')
        [IO.File]::WriteAllText($keptPackage, 'canonical-msix')
        [IO.File]::WriteAllText($keptReceipt, '{}')
        $script:MsixPublishedByThisRun = $true
        $script:MsixReceiptPublishedByThisRun = $true
        $script:MsixCanonicalPackage = $keptPackage
        $script:MsixPayloadManifest = $keptReceipt
        Remove-MsixPartialOutputs
        if (-not (Test-Path -LiteralPath $keptPackage) -or -not (Test-Path -LiteralPath $keptReceipt)) {
            throw 'Successful MSIX outputs were deleted by partial-output cleanup.'
        }

        $x64Pe = [byte[]]::new(128)
        $x64Pe[0] = 0x4D; $x64Pe[1] = 0x5A
        [BitConverter]::GetBytes([int32]0x40).CopyTo($x64Pe, 0x3C)
        [BitConverter]::GetBytes([uint32]0x00004550).CopyTo($x64Pe, 0x40)
        [BitConverter]::GetBytes([uint16]0x8664).CopyTo($x64Pe, 0x44)
        [BitConverter]::GetBytes([uint16]1).CopyTo($x64Pe, 0x46)
        [BitConverter]::GetBytes([uint16]2).CopyTo($x64Pe, 0x54)
        [BitConverter]::GetBytes([uint16]0x020B).CopyTo($x64Pe, 0x58)
        $x64Path = Join-Path $boundaryRoot 'wins_vpn.exe'
        [IO.File]::WriteAllBytes($x64Path, $x64Pe)
        if ((Get-MsixPeCoffMachine -Path $x64Path) -ne $MsixX64PeMachine) {
            throw 'PE self-test failed to recognize an x64 image.'
        }
        $armPe = [byte[]]::new($x64Pe.Length)
        [Array]::Copy($x64Pe, $armPe, $x64Pe.Length)
        [BitConverter]::GetBytes([uint16]0xAA64).CopyTo($armPe, 0x44)
        $armPath = Join-Path $boundaryRoot 'winsvpn_winn3_engine.exe'
        [IO.File]::WriteAllBytes($armPath, $armPe)
        if ((Get-MsixPeCoffMachine -Path $armPath) -ne $MsixArm64PeMachine) {
            throw 'PE self-test failed to recognize an ARM64 image.'
        }
    } finally {
        $script:MsixPublishedByThisRun = $false
        $script:MsixReceiptPublishedByThisRun = $false
        $script:MsixCanonicalPackage = ''
        $script:MsixPayloadManifest = ''
        if (Test-Path -LiteralPath $boundaryRoot) {
            Remove-Item -LiteralPath $boundaryRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $savedTs = $env:WINS_WINDOWS_TIMESTAMP_URL
    $savedPfx = $env:WINS_WINDOWS_SIGN_PFX
    try {
        $env:WINS_WINDOWS_TIMESTAMP_URL = 'https://evil.example/ts /f C:\pwn.pfx'
        $rejected = $true
        try {
            [void](Resolve-WinsProducerSigningConfiguration -RepoRoot $Root -Architecture $CanonicalMsixArchitecture)
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) { throw 'Authenticode precondition self-test accepted a hostile timestamp URL.' }
        $env:WINS_WINDOWS_TIMESTAMP_URL = $savedTs
        $env:WINS_WINDOWS_SIGN_PFX = 'C:\evil.pfx'
        $rejected = $true
        try {
            [void](Resolve-WinsProducerSigningConfiguration -RepoRoot $Root -Architecture $CanonicalMsixArchitecture)
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) { throw 'Authenticode precondition self-test accepted PFX command-line signing.' }
    } finally {
        $env:WINS_WINDOWS_TIMESTAMP_URL = $savedTs
        $env:WINS_WINDOWS_SIGN_PFX = $savedPfx
    }
}

function Invoke-SelfTest {
    $templateText = Get-Content -LiteralPath $Template -Raw
    $notesText = Get-Content -LiteralPath $CertificationNotes -Raw
    foreach ($token in '@IDENTITY_NAME@','@PUBLISHER@','@PACKAGE_VERSION@','@PUBLISHER_DISPLAY_NAME@','@PROCESSOR_ARCHITECTURE@') {
        if (-not $templateText.Contains($token)) { throw "MSIX template token missing: $token" }
    }
    foreach ($required in 'runFullTrust','allowElevation','packagedClassicApp','Microsoft.VCLibs.140.00.UWPDesktop') {
        if (-not $templateText.Contains($required)) { throw "MSIX contract missing: $required" }
    }
    foreach ($required in 'AmneziaWGTunnel$winsvpn','versioned HTTPS','silent','port 80','port 443','9110','PayPal','separate x64','native ARM64') {
        if (-not $notesText.Contains($required)) { throw "Certification disclosure missing: $required" }
    }
    if (-not $ProductionMsixBlockedReason.Contains('Windows service and offline-installer architecture') -or
        -not $ProductionMsixBlockedReason.Contains('Microsoft Store Win32-installer path')) {
        throw 'Production MSIX blocker no longer explains the required Store route.'
    }
    if ($templateText -match '66\.179\.|212\.227\.|:8000|:5000') {
        throw 'MSIX template contains a forbidden origin literal.'
    }
    if ($Pinned['amneziawg-amd64.msi'] -ceq $rejectedLegacyMsiSha256 -or
        $Pinned['awg.exe'] -ceq $rejectedLegacyAwgExeSha256 -or
        $Pinned['amneziawg.exe'] -ceq $rejectedLegacyProductHelperSha256) {
        throw 'Store packager still accepts a rejected AmneziaWG 2.0.1 MSI/helper identity as a pin.'
    }
    if ($AmneziaWgVersion -cne '3.1.0' -or
        $AmneziaWgEngineVersion -cne 'v3.1.20260828' -or
        $AmneziaWgEngineCommit -cne 'b5928efb6ca19f0153958460c3d141f04abc5c2e' -or
        $AmneziaWgSourceCommit -cne 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968' -or
        $AmneziaWgWindowsLibraryVersion -cne 'v3.1.20260814' -or
        $AmneziaWgWindowsLibraryCommit -cne 'e90531d15802cb976773f3b63443bc281f738ca3' -or
        $Pinned['amneziawg-amd64.msi'] -cne 'a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b' -or
        $Pinned['awg.exe'] -cne '272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12' -or
        $Pinned['amneziawg.exe'] -cne '12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41') {
        throw 'Store packager is not aligned with official Windows client 3.1.0 / AWG Go v3.1.20260828.'
    }
    if ($OfficialArm64Pins['amneziawg-arm64.msi'] -cne '3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa' -or
        $OfficialArm64Pins['awg-arm64.exe'] -cne '3106950ce9f0b93eb4c3f7975cbf44af41623ffeed630f19909730cd16d36e43' -or
        $OfficialArm64Pins['wintun-arm64.dll'] -cne 'f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80' -or
        $OfficialArm64Pins['xray-arm64.exe'] -cne 'c6edaa0e535b81d8c4c4a25378e6717b4406a8a0d72b751f4d0a1f171817e7af' -or
        $OfficialArm64Pins['VC_redist.arm64.exe'] -cne '5139e1440c3a20b92153a4db561c069a0175aaf76c276c3e5b6f56099edcf4b0' -or
        $OfficialArm64Pins['amneziawg_msi_runtime_amneziawg_sha256'] -cne '25fa81103152699bf416f394059b40d447001c3d0dea5ef889a9426f315e4c0a') {
        throw 'Store packager lost the official ARM64 AWG 3.1.0 pin literals.'
    }
    if ($OfficialArm64Pins['amneziawg-arm64.msi'] -ceq $UnreviewedArm64MsiSha256) {
        throw 'Store packager treated the unreviewed ARM64 MSI hash as the official pin.'
    }
    if ($Pinned.ContainsKey('amneziawg-arm64.msi')) {
        throw 'ARM64 MSIX remains disabled; do not add amneziawg-arm64.msi to the x64 MSIX pin table.'
    }
    if (-not $templateText.Contains('Winn Protocol v3') -or
        -not $templateText.Contains('Winn v1 AmneziaWG then Xray fallback')) {
        throw 'MSIX template no longer describes Winn v3 primary plus Winn v1 AWG then Xray fallback.'
    }
    if ($templateText.Contains('feature-complete app requires a Windows kernel driver')) {
        throw 'MSIX template still uses the withdrawn kernel-driver identity rationale.'
    }
    if (-not $templateText.Contains('Wintun kernel-mode driver')) {
        throw 'MSIX template no longer discloses the Wintun kernel-mode driver.'
    }
    $identity = Get-ReleaseIdentity
    if ($identity.SourceVersion -cne $CanonicalSourceVersion -or $identity.PackageVersion -cne $CanonicalPackageVersion -or
        $CanonicalMsixFilename -cne "WinsVPN-Store-$($identity.PackageVersion)-x64.msix") {
        throw 'MSIX identity is not the pubspec.yaml release mapping.'
    }
    Invoke-MsixProducerBoundarySelfTest
    Assert-OfficialAwg31Dependencies
    Write-Host 'WINDOWS STORE MSIX SELF-TEST: PASS'
}

if ($BoundarySelfTest) {
    if ($SelfTest) { throw 'BoundarySelfTest cannot be combined with -SelfTest.' }
    Invoke-MsixProducerBoundarySelfTest
    Write-Host 'WINDOWS STORE MSIX BOUNDARY SELF-TEST: PASS'
    exit 0
}
if ($SelfTest) {
    Invoke-SelfTest
    exit 0
}

$script:MsixSigning = Resolve-WinsProducerSigningConfiguration -RepoRoot $Root `
    -Architecture $TargetArchitecture -RequireSigning:$RequireCodeSigning
Assert-OfficialAwg31Dependencies

$script:StoreArchitecture = $TargetArchitecture
$osArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$normalizedHost = switch -Regex ($osArch) {
    '^(?i:X64|Amd64)$' { 'x64' }
    '^(?i:Arm64)$' { 'arm64' }
    default { throw "Unsupported Windows host architecture '$osArch'." }
}
if ($TargetArchitecture -cne $normalizedHost) {
    throw "A Windows $TargetArchitecture Store package cannot be produced on a $normalizedHost host. Flutter build windows has no target-platform override."
}
if ($TargetArchitecture -ceq 'arm64') {
    throw 'ARM64 MSIX packaging is disabled: this MSIX producer reviews only the x64 dependency pins (the amneziawg-arm64.exe product-helper pin in tools/build_windows_amneziawg_client.ps1 serves the ARM64 Inno candidate). Use the native ARM64 Inno candidate; do not package x64 dependencies or relabel an x64 MSIX.'
}
if ($script:StoreArchitecture -cne $CanonicalMsixArchitecture) {
    throw 'MSIX architecture must be exactly x64. ARM64 MSIX packaging is disabled; use the native ARM64 Inno Partner Center candidate.'
}

$identity = Get-ReleaseIdentity
if ($DevelopmentIdentity) {
    if (-not $IdentityName) { $IdentityName = 'WinsVPN.Development' }
    if (-not $Publisher) { $Publisher = 'CN=WinsVPNDevelopment' }
    if (-not $PublisherDisplayName) { $PublisherDisplayName = "Win's VPN Development" }
    if ($IdentityName -ceq 'WinsVPN' -or $Publisher -match "WIN'S VPN INC") {
        throw 'Development MSIX identity must not use the production Store name or WIN''S VPN INC. publisher.'
    }
} elseif ([string]::IsNullOrWhiteSpace($IdentityName) -or
    [string]::IsNullOrWhiteSpace($Publisher) -or
    [string]::IsNullOrWhiteSpace($PublisherDisplayName)) {
    throw $ProductionMsixBlockedReason
}
if ($null -ne $script:MsixSigning -and $DevelopmentIdentity) {
    throw 'A signed MSIX needs the Partner Center identity: the WinsVPN.Development publisher CN=WinsVPNDevelopment cannot match a release certificate subject. Drop -DevelopmentIdentity or the signing identity.'
}
if ($null -eq $script:MsixSigning) {
    Write-Warning 'No Windows signing identity is configured; this MSIX is unsigned (Partner Center signs Store uploads; sideloading needs a signed package). Its receipt records authenticode_status unsigned.'
}
if ($IdentityName -notmatch '^[A-Za-z0-9.-]{3,50}$') {
    throw 'MSIX identity name contains unsupported characters or length.'
}
if ($Publisher -notmatch '^CN=') { throw 'MSIX publisher must start with CN=.' }
Assert-MsixIdentityContract -IdentityName $IdentityName `
    -Publisher $Publisher `
    -PublisherDisplayName $PublisherDisplayName `
    -Architecture $script:StoreArchitecture `
    -PackageVersion $identity.PackageVersion `
    -Production:(-not $DevelopmentIdentity)

if (-not $OutputDirectory) { $OutputDirectory = Join-Path $Root 'build\windows-store' }
if (-not $ReleaseDirectory) { $ReleaseDirectory = Join-Path $Root "build\windows\$($script:StoreArchitecture)\runner\Release" }
$OutputDirectory = Assert-MsixRepoBoundPath -Path $OutputDirectory -Label 'MSIX output directory'
$ReleaseDirectory = Assert-MsixRepoBoundPath -Path $ReleaseDirectory -Label 'MSIX release directory'
$SymbolsDirectory = Assert-MsixRepoBoundPath -Path (
    Join-Path $Root ".artifacts\private-release-symbols\windows\$($script:StoreArchitecture)\$($identity.SourceVersion)"
) -Label 'MSIX symbols directory'
$AotManifest = Join-Path $SymbolsDirectory 'aot-manifest.json'
$MsixManifest = Join-Path $SymbolsDirectory 'msix-manifest.json'
$script:MsixStage = Join-Path $OutputDirectory 'stage'
$script:MsixExtractedMsi = Join-Path $OutputDirectory 'amneziawg-layout'
$script:MsixCanonicalPackage = Join-Path $OutputDirectory $CanonicalMsixFilename
$script:MsixPayloadManifest = "$($script:MsixCanonicalPackage).payload-manifest.json"
$script:MsixVerifyDirectory = Join-Path $OutputDirectory 'verify-unpacked'
$script:MsixStagedPackage = Join-Path $OutputDirectory ('msix-partial-' + [guid]::NewGuid().ToString('N') + '.msix')
$Stage = $script:MsixStage
$ExtractedMsi = $script:MsixExtractedMsi
$Package = $script:MsixCanonicalPackage
$PayloadManifest = $script:MsixPayloadManifest
if (-not $Package.Equals((Join-Path $OutputDirectory $CanonicalMsixFilename), [StringComparison]::Ordinal)) {
    throw "Canonical MSIX filename is not $CanonicalMsixFilename."
}

Quarantine-StaleMsixOutputs -PackagePath $Package -ReceiptPath $PayloadManifest
New-Item -ItemType Directory -Force -Path $OutputDirectory,$SymbolsDirectory | Out-Null

try {
    if (-not $SkipFlutterBuild) {
        Push-Location $Root
        try {
            Invoke-Native flutter pub get
            $winn3PubkeyDefines = Get-Winn3DescriptorPubkeyDefines
            Write-Winn3DescriptorPubkeyStatus -Defines $winn3PubkeyDefines
            $winn3IdentityTool = Join-Path $Root 'tools/winn3_descriptor_ring_identity.py'
            Assert-MsixSafeToken -Value $winn3IdentityTool -Label 'winn3 identity tool'
            $winn3RingSha256 = (& python $winn3IdentityTool @winn3PubkeyDefines).Trim()
            if ($LASTEXITCODE -ne 0) { throw 'Winn3 descriptor ring identity calculation failed.' }
            $expectedWinn3RingSha256 = [string]$env:WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256
            if ($expectedWinn3RingSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
                $expectedWinn3RingSha256.ToLowerInvariant() -cne $winn3RingSha256) {
                throw "Reviewed Winn3 descriptor ring identity mismatch. Computed=$winn3RingSha256"
            }
            $winn3PubkeyDefines += "--dart-define=WINS_WINN3_DESCRIPTOR_RING_SHA256=$winn3RingSha256"
            Assert-MsixSafeToken -Value $SymbolsDirectory -Label 'split-debug-info directory'
            $flutterArgs = @('build','windows','--release','--obfuscate',"--split-debug-info=$SymbolsDirectory",'--extra-gen-snapshot-options=--strip','--dart-define=WINS_WINN3_ENABLED_PLATFORMS=windows') + $winn3PubkeyDefines
            Assert-MsixArgumentList -Arguments $flutterArgs -Purpose 'flutter'
            Invoke-Native flutter @flutterArgs
            Invoke-Native python (Join-Path $Root 'tools/verify_winn3_ring_artifact.py') `
                $winn3RingSha256 (Join-Path $ReleaseDirectory 'data\app.so')
        } finally { Pop-Location }
        $appSo = Join-Path $ReleaseDirectory 'data\app.so'
        Invoke-Native python $ObfuscationTool record --platform windows --symbols-dir $SymbolsDirectory --manifest $AotManifest --artifact $appSo
    } else {
        $appSo = Join-Path $ReleaseDirectory 'data\app.so'
        Invoke-Native python $ObfuscationTool verify --platform windows --symbols-dir $SymbolsDirectory --manifest $AotManifest --artifact $appSo
    }

    foreach ($directory in $Stage,$ExtractedMsi,$script:MsixVerifyDirectory) {
        if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force }
    }
    New-Item -ItemType Directory -Force -Path $Stage,$ExtractedMsi | Out-Null
    Get-ChildItem -LiteralPath $ReleaseDirectory -Force | ForEach-Object {
        Assert-NoReparsePointChain -Path $_.FullName -Label "Release payload $($_.Name)"
        Assert-MsixNotPartnerCenterLeaf -Leaf $_.Name -Label "Release payload $($_.Name)"
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Stage $_.Name) -Recurse -Force
    }
    if ($null -ne $script:MsixSigning) {
        # Engines first, then product; the pinned dependencies copied below
        # keep their exact reviewed bytes.
        Invoke-MsixFirstPartySigning -StageRoot $Stage
    }

    $amneziaMsi = Assert-PinnedFile 'amneziawg-amd64.msi'
    $amneziaHelper = Assert-PinnedFile 'amneziawg.exe'
    $cachedAwg = Assert-PinnedFile 'awg.exe'
    $cachedWintun = Assert-PinnedFile 'wintun.dll'
    $xray = Assert-PinnedFile 'xray.exe'
    $msiArgs = New-MsixMsiexecExtractArgumentList -MsiPath $amneziaMsi -Destination $ExtractedMsi
    Invoke-Native msiexec.exe @msiArgs
    $amneziaPayload = Join-Path $ExtractedMsi 'AmneziaWG'
    foreach ($name in 'awg.exe','wintun.dll') {
        $path = Join-Path $amneziaPayload $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "AmneziaWG MSI did not contain $name." }
        $actual = Get-FileSha256 -Path $path
        if ($RejectedLegacy.ContainsKey($name)) {
            Assert-NotRejectedSha256 -Actual $actual -Rejected $RejectedLegacy[$name] `
                -Label "Extracted AmneziaWG MSI $name"
        }
        if ($actual -cne $Pinned[$name]) {
            throw "AmneziaWG MSI $name SHA-256 mismatch. Expected=$($Pinned[$name]) Actual=$actual. Refusing to package stale or mixed Windows dependencies."
        }
        Copy-Item -LiteralPath $path -Destination (Join-Path $Stage $name) -Force
    }
    $extractedAwg = Get-FileSha256 -Path (Join-Path $Stage 'awg.exe')
    $extractedWintun = Get-FileSha256 -Path (Join-Path $Stage 'wintun.dll')
    if ($extractedAwg -cne (Get-FileSha256 -Path $cachedAwg) -or
        $extractedWintun -cne (Get-FileSha256 -Path $cachedWintun)) {
        throw 'Extracted AmneziaWG MSI payloads do not match the pinned cached awg.exe/wintun.dll. Refusing to package stale or mixed Windows dependencies.'
    }
    Copy-Item -LiteralPath $amneziaHelper `
        -Destination (Join-Path $Stage 'amneziawg.exe') -Force
    Copy-Item -LiteralPath $xray -Destination (Join-Path $Stage 'xray.exe') -Force

    Remove-MsixDebugSymbolFiles -StageRoot $Stage
    Assert-MsixStageCompleteness -StageRoot $Stage

    $manifestText = Get-Content -LiteralPath $Template -Raw
    $manifestText = $manifestText.Replace('@IDENTITY_NAME@', (Convert-ToXmlAttribute $IdentityName))
    $manifestText = $manifestText.Replace('@PUBLISHER@', (Convert-ToXmlAttribute $Publisher))
    $manifestText = $manifestText.Replace('@PUBLISHER_DISPLAY_NAME@', (Convert-ToXmlAttribute $PublisherDisplayName))
    $manifestText = $manifestText.Replace('@PACKAGE_VERSION@', $identity.PackageVersion)
    $manifestText = $manifestText.Replace('@PROCESSOR_ARCHITECTURE@', $script:StoreArchitecture)
    if ($manifestText -match '@[A-Z_]+@') { throw 'Unresolved MSIX manifest token remains.' }
    Assert-MsixPackedManifestText -Text $manifestText `
        -IdentityName $IdentityName `
        -Publisher $Publisher `
        -PackageVersion $identity.PackageVersion `
        -Architecture $script:StoreArchitecture `
        -PublisherDisplayName $PublisherDisplayName
    $manifestPath = Join-Path $Stage 'AppxManifest.xml'
    [IO.File]::WriteAllText($manifestPath, $manifestText, [Text.UTF8Encoding]::new($false))
    New-StoreAssets -Destination (Join-Path $Stage 'Assets')

    $makeAppx = Find-WindowsSdkTool 'makeappx.exe'
    $packArgs = New-MsixMakeAppxPackArgumentList -StageDirectory $Stage -PackagePath $script:MsixStagedPackage
    Invoke-Native $makeAppx @packArgs
    if (-not (Test-Path -LiteralPath $script:MsixStagedPackage -PathType Leaf)) {
        throw 'makeappx pack did not produce a staged MSIX package.'
    }
    if ($null -ne $script:MsixSigning) {
        [void](Invoke-WinsProducerSigning -Path $script:MsixStagedPackage -Signing $script:MsixSigning)
    }

    if (Test-Path -LiteralPath $script:MsixVerifyDirectory) {
        Remove-Item -LiteralPath $script:MsixVerifyDirectory -Recurse -Force
    }
    $unpackArgs = New-MsixMakeAppxUnpackArgumentList -PackagePath $script:MsixStagedPackage -Destination $script:MsixVerifyDirectory
    Invoke-Native $makeAppx @unpackArgs
    $packedManifestText = Get-Content -LiteralPath (Join-Path $script:MsixVerifyDirectory 'AppxManifest.xml') -Raw
    Assert-MsixPackedManifestText -Text $packedManifestText `
        -IdentityName $IdentityName `
        -Publisher $Publisher `
        -PackageVersion $identity.PackageVersion `
        -Architecture $script:StoreArchitecture `
        -PublisherDisplayName $PublisherDisplayName
    $packedManifest = [xml]$packedManifestText
    if ($packedManifest.Package.Identity.Name -cne $IdentityName -or
        $packedManifest.Package.Identity.Publisher -cne $Publisher -or
        $packedManifest.Package.Identity.Version -cne $identity.PackageVersion -or
        $packedManifest.Package.Identity.ProcessorArchitecture -cne $script:StoreArchitecture) {
        throw 'Packed MSIX identity does not match the requested Partner Center identity.'
    }
    Assert-MsixStageCompleteness -StageRoot $script:MsixVerifyDirectory -PackedSignatureAllowed:($null -ne $script:MsixSigning)
    Assert-MsixPackageSignatureState -PackagePath $script:MsixStagedPackage -VerifyRoot $script:MsixVerifyDirectory

    if (Test-Path -LiteralPath $Package) {
        throw "Canonical MSIX path already exists after quarantine: $Package"
    }
    [IO.File]::Move($script:MsixStagedPackage, $Package)
    $script:MsixStagedPackage = ''

    # The MSIX must not be mislabeled as a website or Partner Center EXE target.
    Invoke-Native python $ObfuscationTool record --platform windows --symbols-dir $SymbolsDirectory --manifest $MsixManifest --artifact $Package
    Invoke-Native python $ObfuscationTool verify --platform windows --symbols-dir $SymbolsDirectory --manifest $MsixManifest --artifact $Package

    $payloadFiles = Get-ChildItem -LiteralPath $Stage -Recurse -File | Sort-Object FullName | ForEach-Object {
        [ordered]@{
            path = $_.FullName.Substring($Stage.Length + 1).Replace('\\','/')
            bytes = $_.Length
            sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $msixSigned = $null -ne $script:MsixSigning
    $msixPackageSignature = $null
    if ($msixSigned) {
        $msixPackageSignature = Assert-MsixPackageSigned -PackagePath $Package -VerifyRoot $script:MsixVerifyDirectory
    }
    $msixChannel = if ($DevelopmentIdentity) { 'development_identity_experiment' } else { 'production' }
    $msixAuthenticodeStatus = if ($msixSigned) { 'signed' } else { 'unsigned' }
    $msixSigningMode = if ($msixSigned) { [string]$script:MsixSigning.Mode } else { 'none' }
    $msixSignerSubject = if ($msixSigned) { [string]$msixPackageSignature.signer_subject } else { '' }
    $msixSignerLeaf = if ($msixSigned) { [string]$msixPackageSignature.signer_leaf_sha256 } else { '' }
    $msixSignerOrder = if ($msixSigned) { 'sign-then-rfc3161-timestamp-then-verify' } else { 'unsigned' }
    $msixSigningAuthority = if ($msixSigned) { "Authenticode ($msixSigningMode): $msixSignerSubject" } elseif ($DevelopmentIdentity) { 'unsigned development identity' } else { 'unsigned; Partner Center signs Store uploads' }
    $metadata = [ordered]@{
        schema_version = 1
        contract = 'winsvpn-windows-msix-artifact-receipt-v1'
        channel = $msixChannel
        authenticode_verified = $msixSigned
        authenticode_status = $msixAuthenticodeStatus
        timestamp_verified = $msixSigned
        signing_mode = $msixSigningMode
        signer_subject = $msixSignerSubject
        signer_leaf_sha256 = $msixSignerLeaf
        signed_payloads = @($script:MsixSignatureEvidence)
        pinned_dependencies_resigned = $false
        authenticode_store_route = 'inno-win32'
        winn_v3_primary = $true
        winn_v1_awg_then_xray = $true
        debug_symbols_excluded = $true
        private_symbol_custody_established = $false
        canonical_release = $identity.SourceVersion
        signer_timestamp_order = $msixSignerOrder
        signed_partner_center_payloads = [ordered]@{
            x64 = $PartnerCenterX64Filename
            arm64 = $PartnerCenterArm64Filename
            producer = 'installer/windows/build_installer.ps1'
            signer = 'tools/windows_inno_sign.ps1'
        }
        private_symbols = [ordered]@{
            path = $SymbolsDirectory.Substring($Root.Length + 1).Replace('\\','/')
            uploaded = $false
        }
        artifact = [ordered]@{
            path = [IO.Path]::GetFileName($Package)
            bytes = (Get-Item -LiteralPath $Package).Length
            sha256 = (Get-FileHash -LiteralPath $Package -Algorithm SHA256).Hash.ToLowerInvariant()
            signed = $msixSigned
            signing_authority = $msixSigningAuthority
        }
        source_version = $identity.SourceVersion
        package_identity = [ordered]@{
            name = $IdentityName
            publisher = $Publisher
            publisher_display_name = $PublisherDisplayName
            version = $identity.PackageVersion
            architecture = $script:StoreArchitecture
        }
        restricted_capabilities = @('runFullTrust','allowElevation')
        native_components = @('winn-datapath.exe','winsvpn_winn3_engine.exe','winsvpn_awg_engine.exe','amneziawg.exe','awg.exe','wintun.dll','xray.exe')
        template_sha256 = (Get-FileHash -LiteralPath $Template -Algorithm SHA256).Hash.ToLowerInvariant()
        builder_sha256 = (Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
        obfuscation_manifest = $MsixManifest.Substring($Root.Length + 1).Replace('\\','/')
        payload = @($payloadFiles)
    }
    Write-AtomicNewUtf8File -Path $PayloadManifest -Contents ($metadata | ConvertTo-Json -Depth 8)
    Assert-MsixPostBuildReAudit -VerifyRoot $script:MsixVerifyDirectory `
        -PackagePath $Package `
        -ReceiptPath $PayloadManifest `
        -IdentityName $IdentityName `
        -Publisher $Publisher `
        -PublisherDisplayName $PublisherDisplayName `
        -PackageVersion $identity.PackageVersion `
        -Architecture $script:StoreArchitecture
    $script:MsixReceiptPublishedByThisRun = $true
    $script:MsixPublishedByThisRun = $true

    Write-Host "WINDOWS STORE MSIX CANDIDATE: BUILT $msixChannel $msixAuthenticodeStatus"
    Write-Host "Package: $Package"
    Write-Host "SHA-256: $($metadata.artifact.sha256)"
    Write-Host "Signing: $msixSigningAuthority"
} catch {
    Remove-MsixPartialOutputs
    throw
}
