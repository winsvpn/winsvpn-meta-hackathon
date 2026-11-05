[CmdletBinding()]
param(
    [string]$OutputDirectory = '.artifacts\cross-machine-sync',
    [string]$ArchiveName = 'wins-vpn-current-source.tar.gz',
    [string]$ReviewedUntrackedManifest,
    [string]$ReviewedApprovedPathManifest
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $root

$allowedRoots = @(
    '.github', 'android', 'app_store', 'apple', 'assets', 'docs', 'installer', 'ios', 'legal',
    'lib', 'linux', 'macos', 'netlify', 'server', 'test', 'tools', 'web',
    'windows'
)
$allowedRootFiles = @(
    '.metadata', 'AGENTS.md', 'analysis_options.yaml', 'pubspec.lock',
    'pubspec.yaml', 'README_FINAL_DEPLOYMENT.md'
)
$forbiddenNames = @(
    'key.properties', 'local.properties', '.env', 'secrets.json',
    'google-services.json'
)
$forbiddenExtensions = @(
    '.jks', '.keystore', '.p8', '.p12', '.pfx', '.pem', '.key',
    '.mobileprovision', '.provisionprofile'
)

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $stream = [IO.File]::Open(
        $LiteralPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = $algorithm.ComputeHash($stream)
        } finally {
            $algorithm.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
    return ([BitConverter]::ToString($digest)).Replace('-', '').ToUpperInvariant()
}

function Test-IsInsideProjectTree {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $rootPrefix = $root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    return $LiteralPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-ExternalManifest {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $fullPath = [IO.Path]::GetFullPath($LiteralPath)
    if (Test-IsInsideProjectTree -LiteralPath $fullPath) {
        throw "The $Description manifest must be stored outside the project tree."
    }
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "$Description manifest not found: $fullPath"
    }
    $item = Get-Item -LiteralPath $fullPath -Force
    if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
        throw "The $Description manifest must not be a symbolic link or reparse point."
    }
    return $fullPath
}

function Assert-SafeSourcePath {
    param(
        [Parameter(Mandatory = $true)][string]$Relative,
        [Parameter(Mandatory = $true)][Collections.Generic.HashSet[string]]$KnownPaths,
        [Parameter(Mandatory = $true)][hashtable]$TrackedModes,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if ($Relative -cne $Relative.Replace('\', '/') -or
        [IO.Path]::IsPathRooted($Relative) -or
        $Relative.StartsWith('/') -or $Relative.EndsWith('/') -or
        $Relative -match '^[A-Za-z]:' -or $Relative.Contains('//')) {
        throw "$Description path is not an exact repo-relative path: $Relative"
    }
    $parts = @($Relative -split '/')
    if ($parts.Count -eq 0 -or $parts -contains '' -or
        $parts -contains '.' -or $parts -contains '..' -or
        -not $KnownPaths.Contains($Relative)) {
        throw "$Description path is unsafe, missing, ignored, or not spelled exactly as Git reports it: $Relative"
    }

    $top = $parts[0]
    $leaf = $parts[-1]
    $extension = [IO.Path]::GetExtension($Relative).ToLowerInvariant()
    if (-not (($allowedRoots -contains $top) -or ($allowedRootFiles -contains $Relative))) {
        throw "$Description path is outside the approved source roots: $Relative"
    }
    if (($forbiddenNames -contains $leaf) -or ($forbiddenExtensions -contains $extension)) {
        throw "$Description path is a forbidden credential or private signing artifact: $Relative"
    }

    # Validate each component before looking through it. Checking only the leaf
    # would let a tracked directory be replaced with a junction or symlink and
    # make both the review hash and tar read bytes outside the repository.
    $current = $root
    $item = $null
    for ($index = 0; $index -lt $parts.Count; $index++) {
        $current = Join-Path $current $parts[$index]
        if (-not (Test-Path -LiteralPath $current)) {
            throw "$Description path component is missing: $Relative"
        }
        $item = Get-Item -LiteralPath $current -Force
        if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
            throw "$Description path contains a symbolic link or reparse point: $Relative"
        }
        if ($index -lt ($parts.Count - 1) -and -not $item.PSIsContainer) {
            throw "$Description path contains a non-directory ancestor: $Relative"
        }
    }
    $unixStat = $null
    if ($null -ne $item -and $null -ne $item.PSObject.Properties['UnixStat']) {
        $unixStat = $item.UnixStat
    }
    if ($null -eq $item -or $item.PSIsContainer -or
        -not (Test-Path -LiteralPath $current -PathType Leaf) -or
        ($null -ne $unixStat -and [string]$unixStat.ItemType -cne 'File')) {
        throw "$Description path is not a regular file: $Relative"
    }
    if ($TrackedModes.ContainsKey($Relative) -and
        [string]$TrackedModes[$Relative] -notin @('100644', '100755')) {
        throw "$Description tracked path is not a regular Git file: $Relative"
    }
}

function Read-HashReviewedManifest {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][Collections.Generic.HashSet[string]]$KnownPaths,
        [Parameter(Mandatory = $true)][hashtable]$TrackedModes,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $reviewed = [ordered]@{}
    foreach ($line in Get-Content -LiteralPath $LiteralPath) {
        $trimmed = ([string]$line).Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }
        if ($trimmed -notmatch '^(?<sha>[0-9A-Fa-f]{64})\s{2}(?<path>\S.*)$') {
            throw "Each $Description manifest line must be: <sha256><two spaces><repo-relative-path>."
        }
        $expectedHash = $Matches.sha.ToLowerInvariant()
        $relative = [string]$Matches.path
        if ($relative -cne $relative.Trim()) {
            throw "$Description manifest paths must not have leading or trailing whitespace."
        }
        Assert-SafeSourcePath -Relative $relative -KnownPaths $KnownPaths `
            -TrackedModes $TrackedModes -Description $Description
        if ($reviewed.Contains($relative)) {
            throw "$Description manifest contains a duplicate path: $relative"
        }
        $actualHash = (Get-FileSha256 -LiteralPath (Join-Path $root $relative)).ToLowerInvariant()
        if ($actualHash -cne $expectedHash) {
            throw "$Description file changed after review: $relative"
        }
        $reviewed[$relative] = $actualHash
    }
    if ($reviewed.Count -eq 0) {
        throw "The $Description manifest did not approve any files."
    }
    return $reviewed
}

if (-not [string]::IsNullOrWhiteSpace($ReviewedUntrackedManifest) -and
    -not [string]::IsNullOrWhiteSpace($ReviewedApprovedPathManifest)) {
    throw 'Use either -ReviewedUntrackedManifest or -ReviewedApprovedPathManifest, not both.'
}

$trackedPaths = @(
    & git ls-files --cached
    if ($LASTEXITCODE -ne 0) { throw 'git tracked-source inventory failed.' }
)
$trackedModes = @{}
foreach ($line in @(& git ls-files --stage)) {
    if ($line -match '^(?<mode>\d{6})\s+[0-9a-f]+\s+\d+\t(?<path>.+)$') {
        $trackedModes[$Matches.path.Replace('\', '/')] = $Matches.mode
    }
}
if ($LASTEXITCODE -ne 0) { throw 'git tracked-mode inventory failed.' }
$knownTracked = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($entry in $trackedPaths) {
    [void]$knownTracked.Add(([string]$entry).Replace('\', '/'))
}
$knownUntracked = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($entry in @(& git ls-files --others --exclude-standard)) {
    [void]$knownUntracked.Add(([string]$entry).Replace('\', '/'))
}
if ($LASTEXITCODE -ne 0) { throw 'git untracked-source inventory failed.' }
$knownSourcePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($entry in $knownTracked) { [void]$knownSourcePaths.Add($entry) }
foreach ($entry in $knownUntracked) { [void]$knownSourcePaths.Add($entry) }

$reviewedUntracked = [ordered]@{}
if (-not [string]::IsNullOrWhiteSpace($ReviewedUntrackedManifest)) {
    $manifestPath = Assert-ExternalManifest -LiteralPath $ReviewedUntrackedManifest `
        -Description 'reviewed-untracked'
    $reviewedUntracked = Read-HashReviewedManifest -LiteralPath $manifestPath `
        -KnownPaths $knownUntracked -TrackedModes $trackedModes -Description 'Reviewed untracked'
}

$reviewedApproved = [ordered]@{}
if (-not [string]::IsNullOrWhiteSpace($ReviewedApprovedPathManifest)) {
    $manifestPath = Assert-ExternalManifest -LiteralPath $ReviewedApprovedPathManifest `
        -Description 'reviewed-approved-path'
    $reviewedApproved = Read-HashReviewedManifest -LiteralPath $manifestPath `
        -KnownPaths $knownSourcePaths -TrackedModes $trackedModes -Description 'Reviewed approved path'
}

$candidatePaths = if ($reviewedApproved.Count -gt 0) {
    @($reviewedApproved.Keys)
} else {
    @($trackedPaths) + @($reviewedUntracked.Keys)
}
$paths = @($candidatePaths | ForEach-Object {
    ($_ + '').Replace('\', '/')
} | Where-Object {
    if ([string]::IsNullOrWhiteSpace($_)) { return $false }
    $top = ($_ -split '/', 2)[0]
    $leaf = Split-Path -Leaf $_
    $extension = [IO.Path]::GetExtension($_).ToLowerInvariant()
    $allowed = ($allowedRoots -contains $top) -or ($allowedRootFiles -contains $_)
    $safeName = ($forbiddenNames -notcontains $leaf) -and
        ($forbiddenExtensions -notcontains $extension)
    return $allowed -and $safeName -and
        (Test-Path -LiteralPath (Join-Path $root $_) -PathType Leaf)
} | Sort-Object -Unique)
foreach ($relative in $paths) {
    Assert-SafeSourcePath -Relative $relative -KnownPaths $knownSourcePaths `
        -TrackedModes $trackedModes -Description 'Selected source'
}

if ($reviewedApproved.Count -eq 0 -and $paths.Count -lt 100) {
    throw "Refusing an unexpectedly small source archive: $($paths.Count) files."
}

$resolvedOutput = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory
} else {
    Join-Path $root $OutputDirectory
}
[IO.Directory]::CreateDirectory($resolvedOutput) | Out-Null
$listPath = Join-Path $resolvedOutput 'source-files.txt'
$executableListPath = Join-Path $resolvedOutput 'source-executables.txt'
$archiveListPath = Join-Path $resolvedOutput 'source-archive-files.txt'
$archivePath = Join-Path $resolvedOutput $ArchiveName
$embeddedExecutableListRelative = '.artifacts/cross-machine-sync-stage/source-executables.txt'
$embeddedExecutableListPath = Join-Path $root $embeddedExecutableListRelative
$embeddedExecutableListDirectory = Split-Path -Parent $embeddedExecutableListPath
$archiveOwnedByInvocation = $false
try {
    # Enter cleanup protection before creating the in-tree manifest. This also
    # removes residue from an interrupted earlier invocation.
    if (Test-Path -LiteralPath $embeddedExecutableListPath -PathType Leaf) {
        Remove-Item -LiteralPath $embeddedExecutableListPath -Force
    }
    [IO.File]::WriteAllLines($listPath, $paths, [Text.UTF8Encoding]::new($false))

    $executablePaths = @($paths | Where-Object {
        $extension = [IO.Path]::GetExtension($_).ToLowerInvariant()
        $hasPortableShebang = $false
        if ($extension -in @('.py', '.rb', '.pl', '.bash', '.zsh')) {
            $firstLine = Get-Content -LiteralPath (Join-Path $root $_) -TotalCount 1
            $hasPortableShebang = [string]$firstLine -like '#!*'
        }
        ([string]$trackedModes[$_] -eq '100755') -or
            $extension -in @('.sh', '.command') -or
            $hasPortableShebang
    })
    [IO.File]::WriteAllText(
        $executableListPath,
        (($executablePaths -join "`n") + "`n"),
        [Text.UTF8Encoding]::new($false)
    )
    [IO.Directory]::CreateDirectory($embeddedExecutableListDirectory) | Out-Null
    [IO.File]::WriteAllText(
        $embeddedExecutableListPath,
        (($executablePaths -join "`n") + "`n"),
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllLines(
        $archiveListPath,
        @($paths) + $embeddedExecutableListRelative,
        [Text.UTF8Encoding]::new($false)
    )

    # Recheck every explicitly approved file, including dirty tracked and
    # untracked files in curated mode, immediately before tar reads it.
    $approvedForRecheck = if ($reviewedApproved.Count -gt 0) {
        $reviewedApproved
    } else {
        $reviewedUntracked
    }
    foreach ($entry in $approvedForRecheck.GetEnumerator()) {
        Assert-SafeSourcePath -Relative $entry.Key -KnownPaths $knownSourcePaths `
            -TrackedModes $trackedModes -Description 'Approved source'
        $actualHash = (Get-FileSha256 -LiteralPath (Join-Path $root $entry.Key)).ToLowerInvariant()
        if ($actualHash -cne [string]$entry.Value) {
            throw "Reviewed approved file changed before archive creation: $($entry.Key)"
        }
    }

    if (Test-Path -LiteralPath $archivePath -PathType Leaf) {
        Remove-Item -LiteralPath $archivePath -Force
    }
    # From this point onward any archive at this path belongs to this
    # invocation. Never leave a partial tar or a privacy-rejected archive that
    # a later handoff could mistake for a successful result.
    $archiveOwnedByInvocation = $true
    & tar.exe -czf $archivePath --format ustar -T $archiveListPath
    if ($LASTEXITCODE -ne 0) { throw 'Cross-machine source archive creation failed.' }

    $privacyValidator = Join-Path $root 'tools/validate_release_artifact_privacy.py'
    & python.exe $privacyValidator --static
    if ($LASTEXITCODE -ne 0) { throw 'Source privacy validation failed.' }

    $result = [ordered]@{
        schema = 3
        selection_mode = if ($reviewedApproved.Count -gt 0) { 'reviewed-approved-paths' } else { 'tracked-plus-reviewed-untracked' }
        file_count = $paths.Count
        reviewed_untracked_file_count = $reviewedUntracked.Count
        reviewed_approved_file_count = $reviewedApproved.Count
        executable_file_count = $executablePaths.Count
        executable_manifest = $embeddedExecutableListRelative
        archive = $archivePath
        sha256 = Get-FileSha256 -LiteralPath $archivePath
    }
    $json = $result | ConvertTo-Json -Compress
    $archiveOwnedByInvocation = $false
    $json
} finally {
    if ($archiveOwnedByInvocation -and [IO.File]::Exists($archivePath)) {
        [IO.File]::Delete($archivePath)
    }
    if ([IO.File]::Exists($embeddedExecutableListPath)) {
        [IO.File]::Delete($embeddedExecutableListPath)
    }
    if ([IO.Directory]::Exists($embeddedExecutableListDirectory) -and
        [IO.Directory]::GetFileSystemEntries($embeddedExecutableListDirectory).Count -eq 0) {
        [IO.Directory]::Delete($embeddedExecutableListDirectory, $false)
    }
}
