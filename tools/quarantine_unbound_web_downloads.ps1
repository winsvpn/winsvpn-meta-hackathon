[CmdletBinding()]
param(
    [string]$Workspace = (Split-Path -Parent $PSScriptRoot),
    [string]$QuarantineRelativePath = '.artifacts/web-downloads-quarantine-20260721'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-FullPath([string]$Path) {
    return [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
}

function Test-PathWithin([string]$Path, [string]$Root) {
    $fullPath = Get-FullPath $Path
    $fullRoot = Get-FullPath $Root
    return $fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith(
            $fullRoot + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase
        )
}

$workspaceRoot = Get-FullPath $Workspace
$webRoot = Get-FullPath (Join-Path $workspaceRoot 'web')
$downloadsRoot = Get-FullPath (Join-Path $webRoot 'downloads')
$releaseManifestPath = Get-FullPath (Join-Path $webRoot 'releases/downloads.json')
$quarantineRoot = Get-FullPath (Join-Path $workspaceRoot $QuarantineRelativePath)
$payloadRoot = Get-FullPath (Join-Path $quarantineRoot 'files')

if (-not (Test-PathWithin $downloadsRoot $workspaceRoot)) {
    throw "Downloads root escapes the workspace: $downloadsRoot"
}
if (-not (Test-PathWithin $quarantineRoot $workspaceRoot)) {
    throw "Quarantine root escapes the workspace: $quarantineRoot"
}
if (Test-PathWithin $quarantineRoot $webRoot) {
    throw "Quarantine must remain private and outside web/: $quarantineRoot"
}
if (-not (Test-Path -LiteralPath $releaseManifestPath -PathType Leaf)) {
    throw "Authoritative release manifest is missing: $releaseManifestPath"
}
if (-not (Test-Path -LiteralPath $downloadsRoot -PathType Container)) {
    throw "Public downloads directory is missing: $downloadsRoot"
}
if (Test-Path -LiteralPath $quarantineRoot) {
    $existingQuarantineFiles = @(
        Get-ChildItem -LiteralPath $quarantineRoot -File -Recurse -Force
    )
    if ($existingQuarantineFiles.Count -ne 0) {
        throw "Refusing to reuse a non-empty quarantine directory: $quarantineRoot"
    }
}

$releaseManifestRaw = Get-Content -LiteralPath $releaseManifestPath -Raw
$releaseManifest = $releaseManifestRaw | ConvertFrom-Json
if ($releaseManifest.schema -ne 'winsvpn-download-manifest-v2') {
    throw "Unexpected release manifest schema: $($releaseManifest.schema)"
}

$bound = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase
)
foreach ($entry in @($releaseManifest.artifacts)) {
    $filename = [string]$entry.artifact.filename
    if (-not [string]::IsNullOrWhiteSpace($filename)) {
        $normalized = $filename.Replace('/', [IO.Path]::DirectorySeparatorChar)
        if ([IO.Path]::IsPathRooted($normalized) -or $normalized.Contains('..')) {
            throw "Unsafe bound filename in release manifest: $filename"
        }
        [void]$bound.Add($normalized)
        [void]$bound.Add([IO.Path]::GetFileName($normalized))
    }

    $url = [string]$entry.delivery.url
    if (-not [string]::IsNullOrWhiteSpace($url)) {
        $uri = [Uri]$url
        if ($uri.AbsolutePath -match '/downloads/(.+)$') {
            $urlFilename = [Uri]::UnescapeDataString($Matches[1]).Replace(
                '/',
                [IO.Path]::DirectorySeparatorChar
            )
            if ([IO.Path]::IsPathRooted($urlFilename) -or $urlFilename.Contains('..')) {
                throw "Unsafe bound delivery URL in release manifest: $url"
            }
            [void]$bound.Add($urlFilename)
            [void]$bound.Add([IO.Path]::GetFileName($urlFilename))
        }
    }
}

$allFiles = @(Get-ChildItem -LiteralPath $downloadsRoot -File -Recurse | Sort-Object FullName)
$records = [Collections.Generic.List[object]]::new()
foreach ($file in $allFiles) {
    $relative = [IO.Path]::GetRelativePath($downloadsRoot, $file.FullName)
    if ([IO.Path]::IsPathRooted($relative) -or $relative.StartsWith('..')) {
        throw "A downloads file escaped the public downloads root: $($file.FullName)"
    }
    if ($bound.Contains($relative) -or $bound.Contains($file.Name)) {
        continue
    }
    $destination = Get-FullPath (Join-Path $payloadRoot $relative)
    if (-not (Test-PathWithin $destination $payloadRoot)) {
        throw "Computed quarantine destination escapes payload root: $destination"
    }
    $records.Add([ordered]@{
        relative_path = $relative.Replace([IO.Path]::DirectorySeparatorChar, '/')
        source = $file.FullName
        destination = $destination
        bytes = [int64]$file.Length
        sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    })
}

foreach ($record in $records) {
    $name = [IO.Path]::GetFileName([string]$record.relative_path)
    if ($bound.Contains([string]$record.relative_path) -or $bound.Contains($name)) {
        throw "Fail-closed refusal: a manifest-bound artifact entered the move plan: $($record.relative_path)"
    }
}

$totalBytes = [int64]0
foreach ($record in $records) {
    $totalBytes += [int64]$record.bytes
}

New-Item -ItemType Directory -Path $payloadRoot -Force | Out-Null
$releaseManifestSha256 = (
    Get-FileHash -LiteralPath $releaseManifestPath -Algorithm SHA256
).Hash.ToLowerInvariant()
$plan = [ordered]@{
    schema = 'winsvpn-web-downloads-quarantine-v1'
    status = 'planned'
    created_at_utc = [DateTime]::UtcNow.ToString('o')
    workspace = $workspaceRoot
    authoritative_release_manifest = $releaseManifestPath
    authoritative_release_manifest_sha256 = $releaseManifestSha256
    bound_relative_paths = @($bound | Sort-Object)
    move_count = $records.Count
    total_bytes = $totalBytes
    records = @($records)
}
$planPath = Join-Path $quarantineRoot 'quarantine-plan.json'
$plan | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $planPath -Encoding utf8

foreach ($record in $records) {
    $destinationDirectory = Split-Path -Parent ([string]$record.destination)
    New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    if (Test-Path -LiteralPath ([string]$record.destination)) {
        throw "Refusing to overwrite quarantine destination: $($record.destination)"
    }
    Move-Item -LiteralPath ([string]$record.source) -Destination ([string]$record.destination)
}

foreach ($record in $records) {
    if (Test-Path -LiteralPath ([string]$record.source)) {
        throw "Source still exists after move: $($record.source)"
    }
    if (-not (Test-Path -LiteralPath ([string]$record.destination) -PathType Leaf)) {
        throw "Quarantine destination is missing after move: $($record.destination)"
    }
    $moved = Get-Item -LiteralPath ([string]$record.destination)
    $movedHash = (
        Get-FileHash -LiteralPath $moved.FullName -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ([int64]$moved.Length -ne [int64]$record.bytes -or $movedHash -ne $record.sha256) {
        throw "Post-move verification failed: $($record.relative_path)"
    }
}

$remainingUnbound = @()
foreach ($file in @(Get-ChildItem -LiteralPath $downloadsRoot -File -Recurse)) {
    $relative = [IO.Path]::GetRelativePath($downloadsRoot, $file.FullName)
    if (-not ($bound.Contains($relative) -or $bound.Contains($file.Name))) {
        $remainingUnbound += $relative
    }
}
if ($remainingUnbound.Count -ne 0) {
    throw "Unbound public downloads remain: $($remainingUnbound -join ', ')"
}

$recordJson = @($records) | ConvertTo-Json -Depth 6 -Compress
$recordDigest = [Security.Cryptography.SHA256]::HashData(
    [Text.Encoding]::UTF8.GetBytes($recordJson)
)
$recordDigestHex = [Convert]::ToHexString($recordDigest).ToLowerInvariant()
$manifest = [ordered]@{
    schema = 'winsvpn-web-downloads-quarantine-v1'
    status = 'verified'
    verified_at_utc = [DateTime]::UtcNow.ToString('o')
    workspace = $workspaceRoot
    public_downloads_root = $downloadsRoot
    quarantine_root = $quarantineRoot
    authoritative_release_manifest = $releaseManifestPath
    authoritative_release_manifest_sha256 = $releaseManifestSha256
    bound_relative_paths = @($bound | Sort-Object)
    moved_count = $records.Count
    total_bytes = $totalBytes
    records_sha256 = $recordDigestHex
    records = @($records)
}
$manifestPath = Join-Path $quarantineRoot 'quarantine-manifest.json'
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8

$summary = [ordered]@{
    ok = $true
    manifest = $manifestPath
    manifest_sha256 = (
        Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    moved_count = $records.Count
    total_bytes = $manifest.total_bytes
    records_sha256 = $recordDigestHex
    bound_count = $bound.Count
    remaining_public_files = @(
        Get-ChildItem -LiteralPath $downloadsRoot -File -Recurse
    ).Count
}
$summary | ConvertTo-Json -Depth 4
