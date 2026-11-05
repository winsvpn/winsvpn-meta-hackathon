[CmdletBinding()]
param(
    [string]$Output,
    [string]$ProvenanceOutput,
    [string]$UpstreamMsiOutput,
    [string]$AwgToolOutput,
    [string]$WintunOutput,
    [switch]$KeepWorkingDirectory,
    [switch]$SkipUpstreamPayloadDownload,
    [ValidateSet('amd64', 'arm64')]
    [string]$TargetArchitecture = 'amd64'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ([string]::IsNullOrWhiteSpace($Output)) {
    $helperName = if ($TargetArchitecture -ceq 'arm64') {
        'amneziawg-arm64.exe'
    } else {
        'amneziawg.exe'
    }
    $Output = Join-Path $repo "installer\windows\dependencies\$helperName"
}
$outputFull = [IO.Path]::GetFullPath($Output)
if ([string]::IsNullOrWhiteSpace($ProvenanceOutput)) {
    $ProvenanceOutput = "$outputFull.provenance.json"
}
$provenanceFull = [IO.Path]::GetFullPath($ProvenanceOutput)
$payloadDirectory = Split-Path -Parent $outputFull
if ([string]::IsNullOrWhiteSpace($UpstreamMsiOutput)) {
    $UpstreamMsiOutput = Join-Path $payloadDirectory "amneziawg-$TargetArchitecture.msi"
}
if ([string]::IsNullOrWhiteSpace($AwgToolOutput)) {
    $AwgToolOutput = Join-Path $payloadDirectory $(
        if ($TargetArchitecture -ceq 'arm64') { 'awg-arm64.exe' } else { 'awg.exe' }
    )
}
if ([string]::IsNullOrWhiteSpace($WintunOutput)) {
    $WintunOutput = Join-Path $payloadDirectory $(
        if ($TargetArchitecture -ceq 'arm64') { 'wintun-arm64.dll' } else { 'wintun.dll' }
    )
}
$upstreamMsiFull = [IO.Path]::GetFullPath($UpstreamMsiOutput)
$awgToolFull = [IO.Path]::GetFullPath($AwgToolOutput)
$wintunFull = [IO.Path]::GetFullPath($WintunOutput)
$payloadPaths = @(
    $outputFull,
    $upstreamMsiFull,
    $awgToolFull,
    $wintunFull,
    $provenanceFull
)
$distinctPayloadPaths = @($payloadPaths | Sort-Object -Unique)
if ($distinctPayloadPaths.Count -ne $payloadPaths.Count) {
    throw 'The rebuilt product maintenance helper path must not collide with the official MSI, awg.exe, or wintun.dll path.'
}
$rejectedCacheRoot = Join-Path $repo `
    '.artifacts\rejected-dependency-cache\windows-awg'

$sourceRepository = 'https://github.com/amnezia-vpn/amneziawg-windows-client.git'
# Official Windows GUI client release. This is not the Go engine tag
# v3.1.20260828 and must not be copied onto amneziawg-go producers.
$sourceVersion = '3.1.0'
$sourceCommit = 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968'
$sourceGoModSha256 =
    'ad578b6a2107ae4c1bab214c8057e89608ac516d6e381675c3d9441ccc4da70a'
$sourceGoSumSha256 =
    '268286d6183ec93c39e5295e73e660d9920481c66ecff8331ab64fa082230723'
# The official client 3.1.0 tag and library tag v3.1.20260814 both require
# amneziawg-go v3.1.20260814, and no wrapper tag consumes the frozen engine tag
# yet. The build raises exactly the engine requirement to $engineVersion in the
# clone after the pristine go.mod/go.sum are verified. The two engine versions
# share a byte-identical go.mod, so only the module zip hash differs. Both
# hashes are the sum.golang.org values.
$upstreamEngineVersion = 'v3.1.20260814'
$upstreamEngineModuleH1 =
    'h1:l2AhBD+sFycU8Im81n/bZORMxW7fWtlZJEuJ4Hh0+z0='
$engineModuleH1 =
    'h1:D8d8gGvwXcTxUIsE4z6F6vjy4/VZddu95vMNtOygh1c='
$engineModuleGoModH1 =
    'h1:YoPc6qcOZqD7TXZ1xpedD8Sx3aSKsxN05ZqEFmXDNHk='
$buildGoModSha256 =
    'bdc3d347ffebb8fea5eab4e8baf3e1c99d7488f119b1aafc38922973d643afa2'
$buildGoSumSha256 =
    '84243a4e2616cf698afee71c8a8f2193f6012987428a956dba8249cd143b5e36'
$sourceBuildBatSha256 =
    'c501fd947d08a4bfdb29f65a9f06ced004779be7a90a125f703c1c5a5130350b'
$patchedBuildBatSha256 =
    '79bd946166bc6e87d4ff1602889557590703fc8a64737fbfe7f0b64ebda431d7'
$expectedBuildPatchSha256 =
    'a5ad25797aadc29f0e7aa0bf91e6197ce57c48cb845194a18ae7c2dbbebadcbd'
$windowsLibraryRepository = 'https://github.com/amnezia-vpn/amneziawg-windows.git'
$windowsLibraryVersion = 'v3.1.20260814'
$windowsLibraryCommit = 'e90531d15802cb976773f3b63443bc281f738ca3'
$engineModule = 'github.com/amnezia-vpn/amneziawg-go/v3'
$engineVersion = 'v3.1.20260828'
$engineCommit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'
$engineSourceArchiveSha256 =
    '10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4'
$goVersion = '1.27.1'
$goArchive = "go$goVersion.windows-amd64.zip"
$goArchiveSha256 =
    'a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d'
$oldGoPin =
    'go1.24.4.windows-amd64.zip b751a1136cb9d8a2e7ebb22c538c4f02c09b98138c7c8bfb78a54a4566c013b1'
$newGoPin = "$goArchive $goArchiveSha256"
# Official AmneziaWG 3.1.0 Windows architecture-specific MSI and payloads.
# These pins are immutable expected identities. A mismatch fails closed and
# never rewrites the pin from the bytes on disk. The MSI's amneziawg.exe is
# the upstream GUI helper; it is verified, then discarded. The product
# maintenance helper rebuilt below is a different artifact.
$upstreamMsiVersion = '3.1.0'
$upstreamReleaseId = 374470280
$upstreamAssetId = @{
    amd64 = 523857174
    arm64 = 523857871
}[$TargetArchitecture]
$upstreamMsiName = "amneziawg-$TargetArchitecture-$upstreamMsiVersion.msi"
$upstreamReleaseApiUrl =
    "https://api.github.com/repos/amnezia-vpn/amneziawg-windows-client/releases/tags/$upstreamMsiVersion"
$upstreamReleaseListApiUrl =
    'https://api.github.com/repos/amnezia-vpn/amneziawg-windows-client/releases?per_page=100'
$upstreamMsiUrl =
    "https://github.com/amnezia-vpn/amneziawg-windows-client/releases/download/$upstreamMsiVersion/$upstreamMsiName"
$architecturePins = @{
    amd64 = @{
        MsiSha256 = 'a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b'
        MsiBytes = 3641344
        AwgSha256 = '272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12'
        AwgBytes = 157624
        MsiHelperSha256 = 'ba446f6e1a4093e43a65d6ff45f4b8c7b6485dc419327eedaa1a218549740e3a'
        MsiHelperBytes = 9214392
        WintunSha256 = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
        WintunBytes = 427552
        ProductHelperSha256 = '12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41'
        ProductHelperBytes = 9153024
        PeMachine = [uint16]0x8664
    }
    arm64 = @{
        MsiSha256 = '3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa'
        MsiBytes = 3330048
        AwgSha256 = '3106950ce9f0b93eb4c3f7975cbf44af41623ffeed630f19909730cd16d36e43'
        AwgBytes = 131512
        MsiHelperSha256 = '25fa81103152699bf416f394059b40d447001c3d0dea5ef889a9426f315e4c0a'
        MsiHelperBytes = 8596408
        WintunSha256 = 'f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80'
        WintunBytes = 222488
        ProductHelperSha256 = '0e88c6d049d0905b5aa1e53c63ffa24f2760701be4b28eee5975b381393ef73f'
        ProductHelperBytes = 8483840
        PeMachine = [uint16]0xAA64
    }
}[$TargetArchitecture]
$upstreamMsiSha256 = $architecturePins.MsiSha256
$upstreamMsiBytes = $architecturePins.MsiBytes
$upstreamAwgExeSha256 = $architecturePins.AwgSha256
$upstreamAwgExeBytes = $architecturePins.AwgBytes
$upstreamMsiHelperSha256 = $architecturePins.MsiHelperSha256
$upstreamMsiHelperBytes = $architecturePins.MsiHelperBytes
$upstreamWintunDllSha256 = $architecturePins.WintunSha256
$upstreamWintunDllBytes = $architecturePins.WintunBytes
$expectedProductHelperSha256 = $architecturePins.ProductHelperSha256
$expectedProductHelperBytes = $architecturePins.ProductHelperBytes
$expectedPeMachine = $architecturePins.PeMachine
$rejectedLegacyMsiSha256 =
    'a0fa81022a6e0204b67c92f0046aaebac923bf6ffc786f503c5acff483807b4a'
$rejectedLegacyAwgExeSha256 =
    'cd17f8641bb78ea6476c7341fb7339731ecd8f682e46ab1b43618cea75185552'
$rejectedLegacyProductHelperSha256 =
    'c1a9500254948ac4a1562d8ddf0808b45441ed36bf6746499b67efee6eef1ae9'
$privacyTechnologiesSignerThumbprint =
    '141D90A1BA8F61863FBEDDF7DD1D66C1D1E0B128'
$wireGuardSignerThumbprint =
    'DF98E075A012ED8C86FBCF14854B8F9555CB3D45'
if ($sourceVersion -ceq $engineVersion -or
    $sourceVersion -ceq $windowsLibraryVersion) {
    throw 'The official Windows client release tag is not the Go engine tag.'
}
if ($windowsLibraryVersion -ceq $engineVersion) {
    throw 'The Windows library tag and the Go engine tag are independent pins and must not be conflated.'
}
if ($sourceCommit -ceq $engineCommit -or
    $sourceCommit -ceq $windowsLibraryCommit) {
    throw 'The Windows client commit must remain distinct from the Go engine and Windows library commits.'
}
if ($upstreamMsiSha256 -ceq $engineSourceArchiveSha256) {
    throw 'The Windows client MSI digest must not be labeled as the Go engine archive hash.'
}

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Assert-Sha256 {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][string]$Label
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is missing: $Path"
    }
    $actual = Get-Sha256 -Path $Path
    if ($actual -cne $Expected) {
        throw "$Label SHA-256 mismatch. Expected=$Expected Actual=$actual"
    }
}

function Set-EngineRequirementOverride {
    param(
        [Parameter(Mandatory)][string]$GoModPath,
        [Parameter(Mandatory)][string]$GoSumPath
    )
    $utf8 = [Text.UTF8Encoding]::new($false)
    $edits = @(
        @{
            Path = $GoModPath
            Old = "`t$engineModule $upstreamEngineVersion`n"
            New = "`t$engineModule $engineVersion`n"
        },
        @{
            Path = $GoSumPath
            Old = "$engineModule $upstreamEngineVersion $upstreamEngineModuleH1`n"
            New = "$engineModule $engineVersion $engineModuleH1`n"
        },
        @{
            Path = $GoSumPath
            Old = "$engineModule $upstreamEngineVersion/go.mod $engineModuleGoModH1`n"
            New = "$engineModule $engineVersion/go.mod $engineModuleGoModH1`n"
        }
    )
    foreach ($edit in $edits) {
        $text = [IO.File]::ReadAllText($edit.Path)
        $first = $text.IndexOf($edit.Old, [StringComparison]::Ordinal)
        if ($first -lt 0 -or
            $text.IndexOf(
                $edit.Old,
                $first + $edit.Old.Length,
                [StringComparison]::Ordinal
            ) -ge 0) {
            throw "The pristine engine requirement was not found exactly once in $($edit.Path)."
        }
        [IO.File]::WriteAllText(
            $edit.Path,
            $text.Replace($edit.Old, $edit.New),
            $utf8
        )
    }
}

function Assert-FileSize {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][long]$Expected,
        [Parameter(Mandatory)][string]$Label
    )
    $actual = (Get-Item -LiteralPath $Path -Force).Length
    if ($actual -ne $Expected) {
        throw "$Label size mismatch. Expected=$Expected Actual=$actual"
    }
}

function Assert-RegularPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label,
        [switch]$Directory
    )
    $pathType = if ($Directory) { 'Container' } else { 'Leaf' }
    if (-not (Test-Path -LiteralPath $Path -PathType $pathType)) {
        throw "$Label is missing or has the wrong path type: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must not be a reparse point: $Path"
    }
}

function Assert-NoReparseAncestors {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )
    $currentPath = [IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrWhiteSpace($currentPath)) {
        $current = Get-Item -LiteralPath $currentPath -Force
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label must not have a reparse-point ancestor: $currentPath"
        }
        $parentPath = [IO.Path]::GetDirectoryName($currentPath)
        if ([string]::IsNullOrWhiteSpace($parentPath) -or
            $parentPath -ceq $currentPath) {
            break
        }
        $currentPath = $parentPath
    }
}

function Assert-TargetPe {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Label = 'AmneziaWG payload'
    )
    Assert-RegularPath -Path $Path -Label $Label
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 512 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
        throw "$Label is not a valid DOS/PE executable."
    }
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    if ($peOffset -lt 0x40 -or ($peOffset + 6) -ge $bytes.Length -or
        $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or
        $bytes[$peOffset + 2] -ne 0 -or $bytes[$peOffset + 3] -ne 0) {
        throw "$Label has an invalid PE header."
    }
    $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
    if ($machine -ne $expectedPeMachine) {
        throw ("$Label is not Windows $TargetArchitecture. " +
            ('PE machine=0x{0:x4}' -f $machine))
    }
}

function Assert-NoReparseTree {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Label
    )
    Assert-RegularPath -Path $Root -Label $Label -Directory
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push((Get-Item -LiteralPath $Root -Force).FullName)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($entryPath in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $entry = Get-Item -LiteralPath $entryPath -Force
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Label must not contain a reparse point: $($entry.FullName)"
            }
            if ($entry.PSIsContainer) {
                $pending.Push($entry.FullName)
            }
        }
    }
}

function Assert-AuthenticodeSigner {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$SubjectPattern,
        [string]$ExpectedThumbprint = '',
        [Parameter(Mandatory)][string]$Label
    )
    Assert-RegularPath -Path $Path -Label $Label
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne
        [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch $SubjectPattern -or
        (-not [string]::IsNullOrWhiteSpace($ExpectedThumbprint) -and
            (($signature.SignerCertificate.Thumbprint -replace '\s', '').ToUpperInvariant() -cne
                $ExpectedThumbprint.ToUpperInvariant()))) {
        throw "$Label has an invalid or unexpected Authenticode signer. Status=$($signature.Status) Subject=$($signature.SignerCertificate.Subject)"
    }
    return ($signature.SignerCertificate.Thumbprint -replace '\s', '').ToUpperInvariant()
}

function Assert-NotRejectedSha256 {
    param(
        [Parameter(Mandatory)][string]$Actual,
        [Parameter(Mandatory)][string]$Rejected,
        [Parameter(Mandatory)][string]$Label
    )
    if ($Actual -ceq $Rejected) {
        throw "$Label matches the rejected legacy 2.0.1 identity $Rejected. Official AWG 3.1.0 is required."
    }
}

function Invoke-PinnedHttpsDownload {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$OutFile,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Curl
    )
    $lastError = $null
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        & $Curl --fail --location --silent --show-error --tlsv1.2 `
            --proto '=https' --proto-redir '=https' `
            --connect-timeout 30 --max-time 300 --output $OutFile $Uri
        if ($LASTEXITCODE -eq 0 -and
            (Test-Path -LiteralPath $OutFile -PathType Leaf)) {
            return
        }
        $lastError = "$Label download attempt $attempt failed."
    }
    if ([string]::IsNullOrWhiteSpace($lastError)) {
        $lastError = "$Label download failed."
    }
    throw $lastError
}

function Get-VerifiedOfficialReleaseAsset {
    param(
        [Parameter(Mandatory)][string]$WorkingRoot,
        [Parameter(Mandatory)][string]$Curl
    )
    $releasePath = Join-Path $WorkingRoot 'official-release.json'
    $releaseListPath = Join-Path $WorkingRoot 'official-releases.json'
    Invoke-PinnedHttpsDownload -Uri $upstreamReleaseApiUrl `
        -OutFile $releasePath -Label 'Official AmneziaWG release metadata' `
        -Curl $Curl
    Invoke-PinnedHttpsDownload -Uri $upstreamReleaseListApiUrl `
        -OutFile $releaseListPath `
        -Label 'Official AmneziaWG stable-release list' -Curl $Curl
    try {
        $release = Get-Content -Raw -LiteralPath $releasePath | ConvertFrom-Json
        $releaseList = Get-Content -Raw -LiteralPath $releaseListPath |
            ConvertFrom-Json
        $releaseList = @($releaseList)
    } catch {
        throw 'Official AmneziaWG release metadata was not valid JSON.'
    }
    $stableReleases = @($releaseList | Where-Object {
        -not [bool]$_.draft -and -not [bool]$_.prerelease -and
        [string]$_.tag_name -match '^\d+\.\d+\.\d+$'
    })
    if ($stableReleases.Count -eq 0) {
        throw 'The official Windows client has no discoverable stable release.'
    }
    $latestStable = $stableReleases |
        Sort-Object { [version]([string]$_.tag_name) } -Descending |
        Select-Object -First 1
    if ([string]$latestStable.tag_name -cne $upstreamMsiVersion) {
        throw "A newer official stable AmneziaWG Windows release exists: $($latestStable.tag_name). Review and freeze its exact inputs before building."
    }
    if ([long]$release.id -ne $upstreamReleaseId -or
        [string]$release.tag_name -cne $upstreamMsiVersion -or
        [bool]$release.draft -or [bool]$release.prerelease) {
        throw 'The official AmneziaWG 3.1.0 release identity changed.'
    }
    $assets = @($release.assets | Where-Object {
        [string]$_.name -ceq $upstreamMsiName
    })
    if ($assets.Count -ne 1) {
        throw "The official release must contain exactly one $upstreamMsiName asset."
    }
    $asset = $assets[0]
    if ([long]$asset.id -ne $upstreamAssetId -or
        [long]$asset.size -ne $upstreamMsiBytes -or
        [string]$asset.digest -cne "sha256:$upstreamMsiSha256" -or
        [string]$asset.browser_download_url -cne $upstreamMsiUrl) {
        throw "The official AmneziaWG 3.1.0 $TargetArchitecture release asset identity changed."
    }
    return [ordered]@{
        release_id = [long]$release.id
        asset_id = [long]$asset.id
        asset_name = [string]$asset.name
        asset_size = [long]$asset.size
        asset_digest = [string]$asset.digest
        release_metadata_verified = $true
    }
}

function Resolve-OfficialMsiCandidate {
    param(
        [Parameter(Mandatory)][string]$CachePath,
        [Parameter(Mandatory)][string]$WorkingRoot,
        [Parameter(Mandatory)][string]$Curl,
        [switch]$AllowDownload
    )
    if (Test-Path -LiteralPath $CachePath) {
        Assert-RegularPath -Path $CachePath `
            -Label 'Cached official AmneziaWG MSI'
        $existing = Get-Sha256 -Path $CachePath
        if ($existing -ceq $upstreamMsiSha256) {
            Assert-FileSize -Path $CachePath -Expected $upstreamMsiBytes `
                -Label 'Cached official AmneziaWG MSI'
            return $CachePath
        }
        if (-not $AllowDownload) {
            if ($existing -ceq $rejectedLegacyMsiSha256) {
                throw "Cached official AmneziaWG MSI is the rejected 2.0.1 asset $existing. Downloading is disabled."
            }
            throw "Cached official AmneziaWG MSI SHA-256 mismatch. Expected=$upstreamMsiSha256 Actual=$existing"
        }
    } elseif (-not $AllowDownload) {
        throw "Cached official AmneziaWG MSI is missing: $CachePath"
    }

    $candidate = Join-Path $WorkingRoot $upstreamMsiName
    Invoke-PinnedHttpsDownload -Uri $upstreamMsiUrl -OutFile $candidate `
        -Label 'Official AmneziaWG 3.1.0 amd64 MSI' -Curl $Curl
    Assert-RegularPath -Path $candidate `
        -Label 'Downloaded official AmneziaWG 3.1.0 amd64 MSI'
    Assert-FileSize -Path $candidate -Expected $upstreamMsiBytes `
        -Label 'Downloaded official AmneziaWG 3.1.0 amd64 MSI'
    Assert-Sha256 -Path $candidate -Expected $upstreamMsiSha256 `
        -Label 'Downloaded official AmneziaWG 3.1.0 amd64 MSI'
    Assert-NotRejectedSha256 -Actual (Get-Sha256 -Path $candidate) `
        -Rejected $rejectedLegacyMsiSha256 `
        -Label 'Downloaded official AmneziaWG 3.1.0 amd64 MSI'
    return $candidate
}

function Flush-DurableFile {
    param([Parameter(Mandatory)][string]$Path)
    Assert-RegularPath -Path $Path -Label 'Durable transaction file'
    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::Read
    )
    try {
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
}

function Write-Utf8Durably {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Content
    )
    $parent = Split-Path -Parent $Path
    Assert-RegularPath -Path $parent -Label 'Durable file parent' -Directory
    $temporary = Join-Path $parent (
        ".$([IO.Path]::GetFileName($Path)).$([guid]::NewGuid().ToString('N')).tmp"
    )
    try {
        $normalized = $Content.Replace("`r`n", "`n").Replace("`r", "`n")
        [IO.File]::WriteAllText(
            $temporary,
            $normalized,
            [Text.UTF8Encoding]::new($false)
        )
        Flush-DurableFile -Path $temporary
        Move-Item -LiteralPath $temporary -Destination $Path
        Flush-DurableFile -Path $Path
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Assert-SamePublicationDirectory {
    param([Parameter(Mandatory)][string[]]$Paths)
    $parents = @($Paths | ForEach-Object {
        [IO.Path]::GetFullPath((Split-Path -Parent $_)).TrimEnd('\')
    } | Sort-Object -Unique)
    if ($parents.Count -ne 1) {
        throw 'All AWG generation files must publish in one directory.'
    }
    Assert-RegularPath -Path $parents[0] `
        -Label 'AWG publication directory' -Directory
    Assert-NoReparseAncestors -Path $parents[0] `
        -Label 'AWG publication directory'
    return $parents[0]
}

function Move-AwgTransactionPath {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][ref]$RenameCounter,
        [int]$FailAfterRename = -1
    )
    Assert-RegularPath -Path $Source -Label 'AWG transaction rename source'
    Move-Item -LiteralPath $Source -Destination $Destination
    $RenameCounter.Value++
    if ($FailAfterRename -eq $RenameCounter.Value) {
        throw "Injected AWG transaction failure after rename $($RenameCounter.Value)."
    }
}

function Read-ValidatedAwgTransactionJournal {
    param(
        [Parameter(Mandatory)][string]$JournalPath,
        [Parameter(Mandatory)][string[]]$AllowedDestinations,
        [Parameter(Mandatory)][string]$AllowedTransactionParent
    )
    Assert-RegularPath -Path $JournalPath -Label 'AWG transaction journal'
    try {
        $journal = Get-Content -Raw -LiteralPath $JournalPath | ConvertFrom-Json
    } catch {
        throw 'The AWG transaction journal is not valid JSON.'
    }
    if ([string]$journal.schema -cne 'winsvpn.windows-awg-publication.v2' -or
        [string]$journal.transaction_id -notmatch '^[0-9a-f]{32}$' -or
        @($journal.entries).Count -ne 5) {
        throw 'The AWG transaction journal has an invalid identity or entry count.'
    }
    $transactionRoot = [IO.Path]::GetFullPath([string]$journal.transaction_root)
    $transactionParent = [IO.Path]::GetFullPath(
        (Split-Path -Parent $transactionRoot))
    if ($transactionParent -cne
            [IO.Path]::GetFullPath($AllowedTransactionParent) -or
        [IO.Path]::GetFileName($transactionRoot) -cne
            "transaction-$([string]$journal.transaction_id)") {
        throw 'The AWG transaction journal root is not authorized.'
    }
    $expected = @($AllowedDestinations | ForEach-Object {
        [IO.Path]::GetFullPath($_)
    } | Sort-Object)
    $actual = @($journal.entries | ForEach-Object {
        [IO.Path]::GetFullPath([string]$_.destination)
    } | Sort-Object)
    if (($expected -join "`n") -cne ($actual -join "`n")) {
        throw 'The AWG transaction journal destination set is not authorized.'
    }
    foreach ($entry in @($journal.entries)) {
        if ([string]$entry.expected_sha256 -notmatch '^[0-9a-f]{64}$' -or
            [long]$entry.expected_bytes -lt 1 -or
            [string]$entry.previous_sha256 -notmatch '^(|[0-9a-f]{64})$') {
            throw 'The AWG transaction journal contains invalid file identity data.'
        }
        $destinationParent = [IO.Path]::GetFullPath(
            (Split-Path -Parent ([string]$entry.destination)))
        $backupParent = [IO.Path]::GetFullPath(
            (Split-Path -Parent ([string]$entry.backup)))
        $stagedParent = [IO.Path]::GetFullPath(
            (Split-Path -Parent ([string]$entry.staged)))
        if ($backupParent -cne $transactionRoot -or
            $stagedParent -cne $transactionRoot -or
            $destinationParent -cne [IO.Path]::GetFullPath(
                (Split-Path -Parent $AllowedDestinations[0]))) {
            throw 'The AWG transaction journal contains a path outside its generation roots.'
        }
    }
    return $journal
}

function Restore-AwgTransaction {
    param(
        [Parameter(Mandatory)][string]$JournalPath,
        [Parameter(Mandatory)][string[]]$AllowedDestinations,
        [Parameter(Mandatory)][string]$AllowedTransactionParent,
        [int]$FailAfterRename = -1
    )
    if (-not (Test-Path -LiteralPath $JournalPath)) {
        return
    }
    $journal = Read-ValidatedAwgTransactionJournal `
        -JournalPath $JournalPath -AllowedDestinations $AllowedDestinations `
        -AllowedTransactionParent $AllowedTransactionParent
    $entries = @($journal.entries)
    [array]::Reverse($entries)
    $renameCounter = 0
    foreach ($entry in $entries) {
        $destination = [string]$entry.destination
        $backup = [string]$entry.backup
        $hadPrevious = [bool]$entry.had_previous
        if (Test-Path -LiteralPath $backup) {
            Assert-RegularPath -Path $backup -Label 'AWG rollback backup'
            if (Test-Path -LiteralPath $destination) {
                Assert-RegularPath -Path $destination `
                    -Label 'AWG rollback destination'
                $failed = Join-Path ([string]$journal.transaction_root) (
                    ([IO.Path]::GetFileName($destination)) + '.failed'
                )
                if (Test-Path -LiteralPath $failed) {
                    Assert-RegularPath -Path $failed `
                        -Label 'AWG rollback failed-generation file'
                    Remove-Item -LiteralPath $failed -Force
                }
                Move-AwgTransactionPath -Source $destination `
                    -Destination $failed -RenameCounter ([ref]$renameCounter) `
                    -FailAfterRename $FailAfterRename
            }
            Move-AwgTransactionPath -Source $backup `
                -Destination $destination -RenameCounter ([ref]$renameCounter) `
                -FailAfterRename $FailAfterRename
        } elseif (Test-Path -LiteralPath $destination) {
            Assert-RegularPath -Path $destination `
                -Label 'AWG rollback destination'
            $destinationSha256 = Get-Sha256 -Path $destination
            if ($hadPrevious) {
                if ($destinationSha256 -cne [string]$entry.previous_sha256) {
                    throw 'AWG rollback lost its previous generation backup.'
                }
            } elseif ($destinationSha256 -ceq [string]$entry.expected_sha256) {
                Remove-Item -LiteralPath $destination -Force
            } else {
                throw 'AWG rollback found an unknown file at a formerly empty destination.'
            }
        } elseif ($hadPrevious) {
            throw 'AWG rollback cannot restore a missing previous generation.'
        }
    }
    foreach ($entry in @($journal.entries)) {
        if ([bool]$entry.had_previous) {
            Assert-Sha256 -Path ([string]$entry.destination) `
                -Expected ([string]$entry.previous_sha256) `
                -Label 'Restored AWG previous generation file'
            Assert-FileSize -Path ([string]$entry.destination) `
                -Expected ([long]$entry.previous_bytes) `
                -Label 'Restored AWG previous generation file'
        } elseif (Test-Path -LiteralPath ([string]$entry.destination)) {
            throw 'AWG rollback left a file that did not exist in the previous generation.'
        }
    }
    Remove-Item -LiteralPath $JournalPath -Force
    Remove-Item -LiteralPath ([string]$journal.transaction_root) `
        -Recurse -Force -ErrorAction SilentlyContinue
}

function Publish-AwgGenerationTransaction {
    param(
        [Parameter(Mandatory)][object[]]$Entries,
        [Parameter(Mandatory)][string]$JournalPath,
        [Parameter(Mandatory)][string]$TransactionRoot,
        [Parameter(Mandatory)][string]$TransactionId,
        [int]$FailAfterRename = -1,
        [switch]$SimulateCrash
    )
    $allowedDestinations = @($Entries | ForEach-Object { [string]$_.Destination })
    $publicationDirectory = Assert-SamePublicationDirectory `
        -Paths $allowedDestinations
    if (Test-Path -LiteralPath $JournalPath) {
        Restore-AwgTransaction -JournalPath $JournalPath `
            -AllowedDestinations $allowedDestinations `
            -AllowedTransactionParent (Split-Path -Parent $TransactionRoot)
    }
    [void][IO.Directory]::CreateDirectory($TransactionRoot)
    Assert-RegularPath -Path $TransactionRoot `
        -Label 'AWG transaction directory' -Directory
    Assert-NoReparseAncestors -Path $TransactionRoot `
        -Label 'AWG transaction directory'
    if ([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($TransactionRoot)) -cne
        [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($publicationDirectory))) {
        throw 'The AWG transaction and publication directories must share one volume.'
    }
    $journalEntries = @()
    for ($index = 0; $index -lt $Entries.Count; $index++) {
        $entry = $Entries[$index]
        Assert-RegularPath -Path ([string]$entry.Source) `
            -Label "$($entry.Label) transaction source"
        Assert-Sha256 -Path ([string]$entry.Source) `
            -Expected ([string]$entry.Sha256) -Label $entry.Label
        Assert-FileSize -Path ([string]$entry.Source) `
            -Expected ([long]$entry.Bytes) -Label $entry.Label
        $destination = [IO.Path]::GetFullPath([string]$entry.Destination)
        $hadPrevious = Test-Path -LiteralPath $destination
        $previousSha256 = ''
        $previousBytes = 0
        if ($hadPrevious) {
            Assert-RegularPath -Path $destination `
                -Label "$($entry.Label) previous generation"
            $previousSha256 = Get-Sha256 -Path $destination
            $previousBytes = (Get-Item -LiteralPath $destination -Force).Length
        }
        $staged = Join-Path $TransactionRoot ("$index.staged")
        $backup = Join-Path $TransactionRoot ("$index.backup")
        Copy-Item -LiteralPath ([string]$entry.Source) -Destination $staged
        Assert-Sha256 -Path $staged -Expected ([string]$entry.Sha256) `
            -Label "$($entry.Label) staged generation"
        Assert-FileSize -Path $staged -Expected ([long]$entry.Bytes) `
            -Label "$($entry.Label) staged generation"
        Flush-DurableFile -Path $staged
        $journalEntries += [ordered]@{
            label = [string]$entry.Label
            destination = $destination
            staged = $staged
            backup = $backup
            expected_sha256 = [string]$entry.Sha256
            expected_bytes = [long]$entry.Bytes
            had_previous = [bool]$hadPrevious
            previous_sha256 = $previousSha256
            previous_bytes = [long]$previousBytes
        }
    }
    $journal = [ordered]@{
        schema = 'winsvpn.windows-awg-publication.v2'
        transaction_id = $TransactionId
        transaction_root = $TransactionRoot
        provenance_is_commit_marker = $true
        entries = $journalEntries
    }
    Write-Utf8Durably -Path $JournalPath -Content (
        ($journal | ConvertTo-Json -Depth 5) + [Environment]::NewLine)
    $renameCounter = 0
    try {
        foreach ($entry in $journalEntries) {
            if ([bool]$entry.had_previous) {
                Move-AwgTransactionPath `
                    -Source ([string]$entry.destination) `
                    -Destination ([string]$entry.backup) `
                    -RenameCounter ([ref]$renameCounter) `
                    -FailAfterRename $FailAfterRename
            }
            Move-AwgTransactionPath -Source ([string]$entry.staged) `
                -Destination ([string]$entry.destination) `
                -RenameCounter ([ref]$renameCounter) `
                -FailAfterRename $FailAfterRename
            Assert-Sha256 -Path ([string]$entry.destination) `
                -Expected ([string]$entry.expected_sha256) `
                -Label "$($entry.label) committed generation"
            Assert-FileSize -Path ([string]$entry.destination) `
                -Expected ([long]$entry.expected_bytes) `
                -Label "$($entry.label) committed generation"
        }
        Remove-Item -LiteralPath $JournalPath -Force
        Remove-Item -LiteralPath $TransactionRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
    } catch {
        $publicationError = $_
        if ($SimulateCrash) {
            throw $publicationError
        }
        Restore-AwgTransaction -JournalPath $JournalPath `
            -AllowedDestinations $allowedDestinations `
            -AllowedTransactionParent (Split-Path -Parent $TransactionRoot)
        throw $publicationError
    }
}

function Get-OfficialAwg31PayloadCandidates {
    param(
        [Parameter(Mandatory)][string]$MsiPath,
        [Parameter(Mandatory)][string]$AwgPath,
        [Parameter(Mandatory)][string]$WintunPath,
        [Parameter(Mandatory)][string]$WorkingRoot,
        [Parameter(Mandatory)][string]$ExtractRoot,
        [Parameter(Mandatory)][string]$BackupRoot,
        [Parameter(Mandatory)][string]$Curl,
        [Parameter(Mandatory)][string]$Msiexec,
        [switch]$AllowDownload
    )
    $releaseEvidence = Get-VerifiedOfficialReleaseAsset `
        -WorkingRoot $WorkingRoot -Curl $Curl
    $msiCandidate = Resolve-OfficialMsiCandidate -CachePath $MsiPath `
        -WorkingRoot $WorkingRoot -Curl $Curl -AllowDownload:$AllowDownload
    $msiSigner = Assert-AuthenticodeSigner -Path $msiCandidate `
        -SubjectPattern 'O=Privacy Technologies OU' `
        -ExpectedThumbprint $privacyTechnologiesSignerThumbprint `
        -Label 'Official AmneziaWG 3.1.0 amd64 MSI'

    if (Test-Path -LiteralPath $ExtractRoot) {
        Remove-Item -LiteralPath $ExtractRoot -Recurse -Force
    }
    [void][IO.Directory]::CreateDirectory($ExtractRoot)
    Assert-RegularPath -Path $ExtractRoot `
        -Label 'Official MSI extraction directory' -Directory
    $extractLog = Join-Path $ExtractRoot 'msiexec.log'
    $msiArgs = '/a "{0}" /qn TARGETDIR="{1}" /norestart /l*v "{2}"' -f `
        $msiCandidate, $ExtractRoot, $extractLog
    $extract = Start-Process -FilePath $Msiexec -ArgumentList $msiArgs `
        -Wait -PassThru -WindowStyle Hidden
    if ($extract.ExitCode -ne 0) {
        throw "Official AmneziaWG 3.1.0 MSI administrative extract failed: $($extract.ExitCode)"
    }
    Assert-NoReparseTree -Root $ExtractRoot `
        -Label 'Official MSI extraction tree'

    $extracted = @{}
    foreach ($name in @('amneziawg.exe', 'awg.exe', 'wintun.dll')) {
        $matches = @(Get-ChildItem -LiteralPath $ExtractRoot -Recurse `
            -File -Filter $name)
        if ($matches.Count -ne 1) {
            throw "Official AmneziaWG 3.1.0 MSI must contain exactly one $name."
        }
        $extracted[$name] = $matches[0].FullName
        Assert-RegularPath -Path $extracted[$name] `
            -Label "Official MSI $name payload"
    }

    $payloads = @(
        @{ Name = 'amneziawg.exe'; Hash = $upstreamMsiHelperSha256; Bytes = $upstreamMsiHelperBytes; Signer = 'O=Privacy Technologies OU'; Thumbprint = $privacyTechnologiesSignerThumbprint },
        @{ Name = 'awg.exe'; Hash = $upstreamAwgExeSha256; Bytes = $upstreamAwgExeBytes; Signer = 'O=Privacy Technologies OU'; Thumbprint = $privacyTechnologiesSignerThumbprint },
        @{ Name = 'wintun.dll'; Hash = $upstreamWintunDllSha256; Bytes = $upstreamWintunDllBytes; Signer = 'O=WireGuard LLC'; Thumbprint = $wireGuardSignerThumbprint }
    )
    $payloadSigners = @{}
    foreach ($payload in $payloads) {
        $payloadPath = $extracted[$payload.Name]
        Assert-Sha256 -Path $payloadPath -Expected $payload.Hash `
            -Label "Official MSI $($payload.Name)"
        Assert-FileSize -Path $payloadPath -Expected $payload.Bytes `
            -Label "Official MSI $($payload.Name)"
        Assert-TargetPe -Path $payloadPath `
            -Label "Official MSI $($payload.Name)"
        $payloadSigners[$payload.Name] = Assert-AuthenticodeSigner `
            -Path $payloadPath -SubjectPattern $payload.Signer `
            -ExpectedThumbprint $payload.Thumbprint `
            -Label "Official MSI $($payload.Name)"
    }
    Assert-NotRejectedSha256 `
        -Actual (Get-Sha256 -Path $extracted['awg.exe']) `
        -Rejected $rejectedLegacyAwgExeSha256 `
        -Label 'Official AmneziaWG 3.1.0 MSI awg.exe'

    if ((Get-Sha256 -Path $extracted['amneziawg.exe']) -ceq
        (Get-Sha256 -Path $extracted['awg.exe'])) {
        throw 'Upstream MSI helper and awg.exe must remain distinct identities.'
    }
    # The official MSI GUI helper is verified above and deliberately not
    # published to the product maintenance-helper path.
    return [ordered]@{
        release = $releaseEvidence
        msi_signer_thumbprint = $msiSigner
        msi_helper_signer_thumbprint = $payloadSigners['amneziawg.exe']
        awg_signer_thumbprint = $payloadSigners['awg.exe']
        wintun_signer_thumbprint = $payloadSigners['wintun.dll']
        msi_candidate = $msiCandidate
        awg_candidate = $extracted['awg.exe']
        wintun_candidate = $extracted['wintun.dll']
    }
}

if ($env:OS -cne 'Windows_NT' -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -notin @(
        [Runtime.InteropServices.Architecture]::X64,
        [Runtime.InteropServices.Architecture]::Arm64
    )) {
    throw 'This builder requires a Windows x64 or ARM64 host.'
}

$git = (Get-Command git.exe -ErrorAction Stop).Source
$gitSignature = Get-AuthenticodeSignature -LiteralPath $git
if ($gitSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw "The selected Git executable is not Authenticode-valid: $git"
}
$gitRoot = Split-Path -Parent (Split-Path -Parent $git)
$system32 = Join-Path $env:SystemRoot 'System32'
$cmd = Join-Path $system32 'cmd.exe'
$curl = Join-Path $system32 'curl.exe'
$msiexec = Join-Path $system32 'msiexec.exe'
$systemToolPaths = @(
    $cmd,
    $curl,
    $msiexec,
    (Join-Path $system32 'tar.exe'),
    (Join-Path $system32 'certutil.exe')
)
foreach ($systemToolPath in $systemToolPaths) {
    if (-not (Test-Path -LiteralPath $systemToolPath -PathType Leaf)) {
        throw "Required Windows system tool is missing: $systemToolPath"
    }
    [void](Assert-AuthenticodeSigner -Path $systemToolPath `
        -SubjectPattern 'O=Microsoft Corporation' `
        -Label 'Required Windows system tool')
}

$workingRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "winsvpn-amneziawg-client-$([guid]::NewGuid().ToString('N'))"
)
$sourceRoot = Join-Path $workingRoot 'source'
$builtExe = Join-Path $sourceRoot "$TargetArchitecture\amneziawg.exe"
$goBuildCache = Join-Path $workingRoot 'go-build-cache'
$goModuleCache = Join-Path $workingRoot 'go-module-cache'
$goTemporary = Join-Path $workingRoot 'go-temporary'
$previousEnvironment = @{}
$refreshLock = $null
$controlledEnvironment = [ordered]@{
    GoGenerate = ''
    GOTOOLCHAIN = 'local'
    GOENV = 'off'
    GOWORK = 'off'
    GO111MODULE = 'on'
    GOFLAGS = '-mod=readonly -buildvcs=false'
    GOSUMDB = 'sum.golang.org'
    GOPROXY = 'https://proxy.golang.org,direct'
    GONOSUMDB = ''
    GOPRIVATE = ''
    GONOPROXY = ''
    GOINSECURE = ''
    GOCACHE = $goBuildCache
    GOMODCACHE = $goModuleCache
    GOTMPDIR = $goTemporary
    GOOS = 'windows'
    GOARCH = $TargetArchitecture
    GOAMD64 = 'v1'
    GO386 = 'sse2'
    GOARM64 = 'v8.0'
    GOEXPERIMENT = ''
    CGO_ENABLED = '1'
    CGO_CFLAGS = ''
    CGO_CPPFLAGS = ''
    CGO_CXXFLAGS = ''
    CGO_LDFLAGS = ''
    CC = ''
    CXX = ''
    SigningProvider = ''
    TimestampServer = ''
    PATH = "$system32;$env:SystemRoot;$gitRoot\cmd"
}

try {
    [void][IO.Directory]::CreateDirectory($rejectedCacheRoot)
    Assert-RegularPath -Path $rejectedCacheRoot `
        -Label 'Rejected AWG cache backup directory' -Directory
    $refreshLockPath = Join-Path $rejectedCacheRoot 'producer.lock'
    try {
        $refreshLock = [IO.File]::Open(
            $refreshLockPath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
    } catch {
        throw 'Another Windows AWG dependency producer is already running.'
    }
    foreach ($controlledDirectory in @(
        $workingRoot,
        $goBuildCache,
        $goModuleCache,
        $goTemporary
    )) {
        [void][IO.Directory]::CreateDirectory($controlledDirectory)
    }
    $publicationDirectory = Assert-SamePublicationDirectory -Paths $payloadPaths
    $transactionJournalPath = Join-Path $publicationDirectory `
        '.winsvpn-awg31-publication.json'
    Restore-AwgTransaction -JournalPath $transactionJournalPath `
        -AllowedDestinations $payloadPaths `
        -AllowedTransactionParent $rejectedCacheRoot
    $upstreamEvidence = Get-OfficialAwg31PayloadCandidates `
        -MsiPath $upstreamMsiFull `
        -AwgPath $awgToolFull `
        -WintunPath $wintunFull `
        -WorkingRoot $workingRoot `
        -ExtractRoot (Join-Path $workingRoot 'official-msi') `
        -BackupRoot $rejectedCacheRoot `
        -Curl $curl `
        -Msiexec $msiexec `
        -AllowDownload:(-not $SkipUpstreamPayloadDownload)
    & $git -c core.autocrlf=false clone --depth 1 --branch $sourceVersion `
        --single-branch $sourceRepository $sourceRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to clone the pinned AmneziaWG Windows client source.'
    }
    & $git -C $sourceRoot config core.autocrlf false
    $head = (& $git -C $sourceRoot rev-parse HEAD).Trim()
    if ($head -cne $sourceCommit) {
        throw "AmneziaWG tag $sourceVersion resolved to unexpected commit $head."
    }
    $tagCommit = (& $git -C $sourceRoot rev-list -n 1 $sourceVersion).Trim()
    if ($tagCommit -cne $sourceCommit) {
        throw "AmneziaWG tag $sourceVersion is not bound to $sourceCommit."
    }
    Assert-Sha256 -Path (Join-Path $sourceRoot 'go.mod') `
        -Expected $sourceGoModSha256 -Label 'Pinned AmneziaWG go.mod'
    Assert-Sha256 -Path (Join-Path $sourceRoot 'go.sum') `
        -Expected $sourceGoSumSha256 -Label 'Pinned AmneziaWG go.sum'
    Set-EngineRequirementOverride `
        -GoModPath (Join-Path $sourceRoot 'go.mod') `
        -GoSumPath (Join-Path $sourceRoot 'go.sum')
    Assert-Sha256 -Path (Join-Path $sourceRoot 'go.mod') `
        -Expected $buildGoModSha256 -Label 'Engine-overridden AmneziaWG go.mod'
    Assert-Sha256 -Path (Join-Path $sourceRoot 'go.sum') `
        -Expected $buildGoSumSha256 -Label 'Engine-overridden AmneziaWG go.sum'

    $buildScript = Join-Path $sourceRoot 'build.bat'
    Assert-Sha256 -Path $buildScript -Expected $sourceBuildBatSha256 `
        -Label 'Pinned AmneziaWG build.bat'
    $buildText = [IO.File]::ReadAllText($buildScript)
    $firstGoPin = $buildText.IndexOf(
        $oldGoPin,
        [StringComparison]::Ordinal
    )
    if ($firstGoPin -lt 0 -or
        $buildText.IndexOf(
            $oldGoPin,
            $firstGoPin + $oldGoPin.Length,
            [StringComparison]::Ordinal
        ) -ge 0) {
        throw 'The reviewed upstream Go archive pin was not found exactly once.'
    }
    [IO.File]::WriteAllText(
        $buildScript,
        $buildText.Replace($oldGoPin, $newGoPin),
        [Text.UTF8Encoding]::new($false)
    )
    Assert-Sha256 -Path $buildScript -Expected $patchedBuildBatSha256 `
        -Label 'Reviewed Go 1.27 AmneziaWG build.bat'
    $trackedChanges = @(& $git -C $sourceRoot diff --name-only)
    if (($trackedChanges -join "`n") -cne "build.bat`ngo.mod`ngo.sum") {
        throw "Unexpected tracked source changes: $($trackedChanges -join ', ')"
    }
    $buildPatchPath = Join-Path $workingRoot 'go-1.27-build.patch'
    & $git -C $sourceRoot diff --binary --output=$buildPatchPath -- build.bat
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to materialize the reviewed Go 1.27 build patch.'
    }
    $buildPatchSha256 = Get-Sha256 -Path $buildPatchPath
    if ($buildPatchSha256 -cne $expectedBuildPatchSha256) {
        throw "The reviewed Go 1.27 build patch changed. Expected=$expectedBuildPatchSha256 Actual=$buildPatchSha256"
    }

    foreach ($entry in $controlledEnvironment.GetEnumerator()) {
        $existing = Get-Item -LiteralPath "Env:$($entry.Key)" `
            -ErrorAction SilentlyContinue
        $previousEnvironment[$entry.Key] =
            if ($null -eq $existing) { $null } else { [string]$existing.Value }
        Set-Item -LiteralPath "Env:$($entry.Key)" -Value $entry.Value
    }

    Push-Location $sourceRoot
    try {
        & $cmd /d /c build.bat
        if ($LASTEXITCODE -ne 0) {
            throw "The pinned AmneziaWG upstream build failed: $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }

    Assert-Sha256 -Path (Join-Path $sourceRoot 'go.mod') `
        -Expected $buildGoModSha256 -Label 'Post-build AmneziaWG go.mod'
    Assert-Sha256 -Path (Join-Path $sourceRoot 'go.sum') `
        -Expected $buildGoSumSha256 -Label 'Post-build AmneziaWG go.sum'
    Assert-Sha256 -Path $buildScript -Expected $patchedBuildBatSha256 `
        -Label 'Post-build Go 1.27 AmneziaWG build.bat'
    if (@(& $git -C $sourceRoot diff --name-only) -join "`n" -cne "build.bat`ngo.mod`ngo.sum") {
        throw 'The build modified reviewed tracked source beyond build.bat and the engine requirement override.'
    }

    $go = Join-Path $sourceRoot '.deps\go\bin\go.exe'
    $reportedGoVersion = (& $go version).Trim()
    if ($reportedGoVersion -cne "go version go$goVersion windows/amd64") {
        throw "The extracted Go toolchain is not the required ${goVersion}: $reportedGoVersion"
    }
    if (-not (Test-Path -LiteralPath $builtExe -PathType Leaf)) {
        throw "The upstream build did not produce $TargetArchitecture\amneziawg.exe."
    }
    Assert-TargetPe -Path $builtExe -Label 'Rebuilt product maintenance helper'
    $reproducibilityBuilds = 1
    $reproducibilityStatus = 'matched_owner_reviewed_digest'
    if ($TargetArchitecture -ceq 'arm64') {
        $firstBuild = Join-Path $workingRoot 'amneziawg-arm64.first.exe'
        Copy-Item -LiteralPath $builtExe -Destination $firstBuild
        $firstBuildSha256 = Get-Sha256 -Path $firstBuild
        $firstBuildBytes = (Get-Item -LiteralPath $firstBuild).Length
        Remove-Item -LiteralPath $builtExe -Force
        Remove-Item -LiteralPath $goBuildCache -Recurse -Force
        [void][IO.Directory]::CreateDirectory($goBuildCache)
        Push-Location $sourceRoot
        try {
            & $go build -tags load_wgnt_from_rsrc `
                '-ldflags=-H windowsgui -s -w' -trimpath -buildvcs=false `
                -o $builtExe
            if ($LASTEXITCODE -ne 0) {
                throw 'The independent ARM64 maintenance-helper rebuild failed.'
            }
        } finally {
            Pop-Location
        }
        Assert-TargetPe -Path $builtExe `
            -Label 'Independently rebuilt ARM64 product maintenance helper'
        $secondBuildSha256 = Get-Sha256 -Path $builtExe
        $secondBuildBytes = (Get-Item -LiteralPath $builtExe).Length
        if ($secondBuildSha256 -cne $firstBuildSha256 -or
            $secondBuildBytes -ne $firstBuildBytes) {
            throw ("Independent ARM64 maintenance-helper builds were not byte-identical. " +
                "First=$firstBuildSha256/$firstBuildBytes Second=$secondBuildSha256/$secondBuildBytes")
        }
        if ($null -ne $architecturePins.ProductHelperSha256 -and
            ($secondBuildSha256 -cne $architecturePins.ProductHelperSha256 -or
                $secondBuildBytes -ne $architecturePins.ProductHelperBytes)) {
            throw ("The reproducible ARM64 product maintenance helper changed. " +
                "Expected=$($architecturePins.ProductHelperSha256)/$($architecturePins.ProductHelperBytes) " +
                "Actual=$secondBuildSha256/$secondBuildBytes")
        }
        $expectedProductHelperSha256 = $secondBuildSha256
        $expectedProductHelperBytes = $secondBuildBytes
        $reproducibilityBuilds = 2
        $reproducibilityStatus = 'two_clean_builds_byte_identical'
    }
    $moduleInfo = (& $go version -m $builtExe 2>&1 | Out-String).TrimEnd()
    if ($moduleInfo -notmatch
            "(?m)^.+:\s+go$([regex]::Escape($goVersion))\s*$" -or
        $moduleInfo -notmatch
            '(?m)^\s*path\s+github\.com/amnezia-vpn/amneziawg-windows-client\s*$' -or
        $moduleInfo -notmatch
            '(?m)^\s*dep\s+github\.com/amnezia-vpn/amneziawg-go/v3\s+v3\.1\.20260828\s+' -or
        $moduleInfo -notmatch
            '(?m)^\s*dep\s+github\.com/amnezia-vpn/amneziawg-windows/v3\s+v3\.1\.20260814\s+') {
        throw 'The rebuilt helper does not contain the required Go/source build metadata.'
    }
    $normalizedModuleInfo = @($moduleInfo -split "`r?`n")
    $normalizedModuleInfo[0] = "amneziawg.exe: go$goVersion"
    $signature = Get-AuthenticodeSignature -LiteralPath $builtExe
    if ($signature.Status -ne
        [System.Management.Automation.SignatureStatus]::NotSigned) {
        throw "The isolated pre-signing output has unexpected signature status: $($signature.Status)"
    }
    $unsignedSha256 = Get-Sha256 -Path $builtExe
    Assert-FileSize -Path $builtExe -Expected $expectedProductHelperBytes `
        -Label 'Rebuilt product maintenance helper'
    if ($unsignedSha256 -cne $expectedProductHelperSha256) {
        throw "The reproducible product maintenance helper changed. Expected=$expectedProductHelperSha256 Actual=$unsignedSha256"
    }
    if ($unsignedSha256 -ceq $upstreamMsiHelperSha256) {
        throw 'The rebuilt product maintenance helper must not match the official MSI amneziawg.exe.'
    }
    Assert-NotRejectedSha256 -Actual $unsignedSha256 `
        -Rejected $rejectedLegacyProductHelperSha256 `
        -Label 'Rebuilt product maintenance helper'
    $transactionId = [guid]::NewGuid().ToString('N')
    $provenance = [ordered]@{
        schema_version = 2
        publication_transaction_id = $transactionId
        publication_contract = 'winsvpn.windows-awg-publication.v2'
        provenance_is_commit_marker = $true
        generated_at_utc = [DateTime]::UtcNow.ToString('o')
        source_repository = $sourceRepository
        source_version = $sourceVersion
        source_commit = $sourceCommit
        source_go_mod_sha256 = $sourceGoModSha256
        source_go_sum_sha256 = $sourceGoSumSha256
        source_build_bat_sha256 = $sourceBuildBatSha256
        patched_build_bat_sha256 = $patchedBuildBatSha256
        windows_library_repository = $windowsLibraryRepository
        windows_library_version = $windowsLibraryVersion
        windows_library_commit = $windowsLibraryCommit
        engine_module = $engineModule
        engine_version = $engineVersion
        engine_commit = $engineCommit
        go_version = $goVersion
        go_archive = $goArchive
        go_archive_sha256 = $goArchiveSha256
        go_toolchain_policy = 'verified_archive_only'
        go_module_policy = 'readonly'
        go_checksum_database = 'sum.golang.org'
        build_patch_sha256 = $buildPatchSha256
        target = "windows-$TargetArchitecture"
        unsigned_artifact_sha256 = $unsignedSha256
        expected_unsigned_artifact_sha256 = $expectedProductHelperSha256
        unsigned_artifact_size = $expectedProductHelperBytes
        reproducibility_builds = $reproducibilityBuilds
        reproducibility_status = $reproducibilityStatus
        authenticode_status = 'pending_release_signing'
        release_signing_required = $true
        helper_kind = 'canonical_unsigned_product_maintenance_helper'
        signing_boundary = 'release_staged_copy_only'
        upstream_msi_helper_kind = 'official_upstream_signed_gui_helper_not_published'
        upstream_release_id = $upstreamReleaseId
        upstream_asset_id = $upstreamAssetId
        upstream_asset_name = $upstreamMsiName
        upstream_asset_size = $upstreamMsiBytes
        upstream_asset_sha256 = $upstreamMsiSha256
        upstream_release_metadata_verified = `
            [bool]$upstreamEvidence.release.release_metadata_verified
        upstream_msi_url = $upstreamMsiUrl
        upstream_msi_version = $upstreamMsiVersion
        upstream_msi_sha256 = $upstreamMsiSha256
        upstream_msi_size = $upstreamMsiBytes
        upstream_awg_exe_sha256 = $upstreamAwgExeSha256
        upstream_awg_exe_size = $upstreamAwgExeBytes
        upstream_msi_helper_sha256 = $upstreamMsiHelperSha256
        upstream_msi_helper_size = $upstreamMsiHelperBytes
        upstream_wintun_dll_sha256 = $upstreamWintunDllSha256
        upstream_wintun_dll_size = $upstreamWintunDllBytes
        expected_privacy_technologies_signer_thumbprint = `
            $privacyTechnologiesSignerThumbprint
        expected_wireguard_signer_thumbprint = $wireGuardSignerThumbprint
        upstream_msi_signer_thumbprint = `
            $upstreamEvidence.msi_signer_thumbprint
        upstream_msi_helper_signer_thumbprint = `
            $upstreamEvidence.msi_helper_signer_thumbprint
        upstream_awg_signer_thumbprint = $upstreamEvidence.awg_signer_thumbprint
        upstream_wintun_signer_thumbprint = `
            $upstreamEvidence.wintun_signer_thumbprint
        rejected_legacy_msi_sha256 = $rejectedLegacyMsiSha256
        rejected_legacy_awg_exe_sha256 = $rejectedLegacyAwgExeSha256
        rejected_legacy_product_helper_sha256 = `
            $rejectedLegacyProductHelperSha256
        artifact_roles = @(
            [ordered]@{
                name = $upstreamMsiName
                role = 'official_windows_client_distribution_container'
                sha256 = $upstreamMsiSha256
                size = $upstreamMsiBytes
                release_id = $upstreamReleaseId
                asset_id = $upstreamAssetId
                signing_boundary = 'official_upstream_authenticode'
                expected_signer_thumbprint = `
                    $privacyTechnologiesSignerThumbprint
                observed_signer_thumbprint = `
                    $upstreamEvidence.msi_signer_thumbprint
            },
            [ordered]@{
                name = 'awg.exe'
                role = 'official_awg_userspace_configuration_tool'
                sha256 = $upstreamAwgExeSha256
                size = $upstreamAwgExeBytes
                signing_boundary = 'official_upstream_authenticode'
                expected_signer_thumbprint = `
                    $privacyTechnologiesSignerThumbprint
                observed_signer_thumbprint = `
                    $upstreamEvidence.awg_signer_thumbprint
            },
            [ordered]@{
                name = 'wintun.dll'
                role = 'official_wireguard_tunnel_adapter_library'
                sha256 = $upstreamWintunDllSha256
                size = $upstreamWintunDllBytes
                signing_boundary = 'official_upstream_authenticode'
                expected_signer_thumbprint = $wireGuardSignerThumbprint
                observed_signer_thumbprint = `
                    $upstreamEvidence.wintun_signer_thumbprint
            },
            [ordered]@{
                name = 'amneziawg.exe'
                role = 'winsvpn_rebuilt_unsigned_product_maintenance_helper'
                sha256 = $expectedProductHelperSha256
                size = $expectedProductHelperBytes
                signing_boundary = 'unsigned_canonical_input_release_copy_only'
                expected_signer_thumbprint = $null
                observed_signer_thumbprint = $null
            },
            [ordered]@{
                name = 'official-msi-amneziawg.exe'
                role = 'verified_upstream_gui_helper_not_published'
                sha256 = $upstreamMsiHelperSha256
                size = $upstreamMsiHelperBytes
                signing_boundary = 'official_upstream_authenticode'
                expected_signer_thumbprint = `
                    $privacyTechnologiesSignerThumbprint
                observed_signer_thumbprint = `
                    $upstreamEvidence.msi_helper_signer_thumbprint
            },
            [ordered]@{
                name = 'amneziawg.exe.provenance.json'
                role = 'generation_commit_marker_and_provenance'
                signing_boundary = 'unsigned_repository_evidence'
                expected_signer_thumbprint = $null
                observed_signer_thumbprint = $null
            }
        )
        module_build_info = $normalizedModuleInfo
    }
    $provenanceCandidate = Join-Path $workingRoot 'amneziawg.exe.provenance.json'
    [IO.File]::WriteAllText(
        $provenanceCandidate,
        ($provenance | ConvertTo-Json -Depth 6) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
    $provenanceSha256 = Get-Sha256 -Path $provenanceCandidate
    $provenanceBytes = (Get-Item -LiteralPath $provenanceCandidate -Force).Length
    $transactionRoot = Join-Path $rejectedCacheRoot `
        ("transaction-$transactionId")
    $transactionEntries = @(
        [ordered]@{ Source = $upstreamEvidence.msi_candidate; Destination = $upstreamMsiFull; Sha256 = $upstreamMsiSha256; Bytes = $upstreamMsiBytes; Label = 'Official AmneziaWG 3.1.0 MSI' },
        [ordered]@{ Source = $upstreamEvidence.awg_candidate; Destination = $awgToolFull; Sha256 = $upstreamAwgExeSha256; Bytes = $upstreamAwgExeBytes; Label = 'Official AWG 3.1 awg.exe' },
        [ordered]@{ Source = $upstreamEvidence.wintun_candidate; Destination = $wintunFull; Sha256 = $upstreamWintunDllSha256; Bytes = $upstreamWintunDllBytes; Label = 'Official AWG 3.1 wintun.dll' },
        [ordered]@{ Source = $builtExe; Destination = $outputFull; Sha256 = $expectedProductHelperSha256; Bytes = $expectedProductHelperBytes; Label = 'Rebuilt product maintenance helper' },
        [ordered]@{ Source = $provenanceCandidate; Destination = $provenanceFull; Sha256 = $provenanceSha256; Bytes = $provenanceBytes; Label = 'AWG 3.1 generation provenance commit marker' }
    )
    Publish-AwgGenerationTransaction -Entries $transactionEntries `
        -JournalPath $transactionJournalPath `
        -TransactionRoot $transactionRoot -TransactionId $transactionId
    Write-Host "WINDOWS AMNEZIAWG CLIENT BUILD: PASS ($unsignedSha256)" `
        -ForegroundColor Green
    Write-Host "Output: $outputFull"
    Write-Host "Provenance: $provenanceFull"
} finally {
    if ($null -ne $refreshLock) {
        $refreshLock.Dispose()
    }
    foreach ($entry in $previousEnvironment.GetEnumerator()) {
        if ($null -eq $entry.Value) {
            Remove-Item -LiteralPath "Env:$($entry.Key)" `
                -ErrorAction SilentlyContinue
        } else {
            Set-Item -LiteralPath "Env:$($entry.Key)" -Value $entry.Value
        }
    }
    if ($KeepWorkingDirectory) {
        Write-Host "Preserved working directory: $workingRoot"
    } else {
        Remove-Item -LiteralPath $workingRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
}
