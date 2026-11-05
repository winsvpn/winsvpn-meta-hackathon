param(
    [string]$RepoRoot = "$env:USERPROFILE\Downloads\wins_vpn",
    [string]$StateDir = "$env:LOCALAPPDATA\WinsVPN\RemoteBuildState",
    [string]$FlutterRoot = '',
    [string]$PowerShellExecutable = $env:WINS_WINDOWS_POWERSHELL_EXECUTABLE,
    [string]$ExpectedFlutterRevision = $null,
    [Parameter(Mandatory = $true)][string]$ReleaseInputIndex,
    [string]$RunId = '',
    [switch]$AllowUnsignedEngineering,
    [switch]$SkipReadinessValidation,
    [switch]$SelfTestStatusPublication,
    [switch]$StandaloneWinn3Release,
    [ValidateSet('x64', 'arm64')]
    [string]$TargetArchitecture = 'x64'
)

$ErrorActionPreference = 'Stop'
if (-not $SelfTestStatusPublication) {
    $osArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $normalizedHost = switch -Regex ($osArch) {
        '^(?i:X64|Amd64)$' { 'x64' }
        '^(?i:Arm64)$' { 'arm64' }
        default { throw "Unsupported Windows host architecture '$osArch'." }
    }
    if ($TargetArchitecture -cne $normalizedHost) {
        throw "A Windows $TargetArchitecture remote candidate cannot be produced on a $normalizedHost host."
    }
}

function Resolve-CanonicalRunId {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return [Guid]::NewGuid().ToString('D')
    }
    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParseExact($Value, 'D', [ref]$parsed) -or
        $parsed -eq [Guid]::Empty -or $Value -cne $parsed.ToString('D')) {
        throw 'RunId must be one canonical lowercase nonzero UUID.'
    }
    return $parsed.ToString('D')
}

function Get-RepoRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $absolute = [IO.Path]::GetFullPath($Path)
    $prefix = $rootPath + [IO.Path]::DirectorySeparatorChar
    if (-not $absolute.StartsWith(
            $prefix, [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Path is outside the repository: $absolute"
    }
    return $absolute.Substring($prefix.Length).Replace('\', '/')
}

function Write-RemoteBuildStatusAtomic {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Status
    )

    foreach ($required in @(
        'schema_version', 'contract', 'run_id', 'state', 'done', 'ok',
        'build_mode', 'signing', 'publishability'
    )) {
        if (-not $Status.Contains($required)) {
            throw "Remote build status is missing $required."
        }
    }
    if ([int]$Status.schema_version -ne 2 -or
        [string]$Status.contract -cne
            'winsvpn-windows-remote-build-status-v2') {
        throw 'Remote build status must use the v2 contract.'
    }
    $canonicalRunId = Resolve-CanonicalRunId -Value ([string]$Status.run_id)
    if ([string]$Status.run_id -cne $canonicalRunId) {
        throw 'Remote build status has a noncanonical run_id.'
    }
    if ([string]$Status.build_mode -cnotin @(
            'production_signed', 'unsigned_engineering'
        )) {
        throw 'Remote build status has an invalid build_mode.'
    }
    $newState = [string]$Status.state
    if (($newState -ceq 'running' -and
            ([bool]$Status.done -or [bool]$Status.ok)) -or
        ($newState -ceq 'succeeded' -and
            (-not [bool]$Status.done -or -not [bool]$Status.ok)) -or
        ($newState -ceq 'failed' -and
            (-not [bool]$Status.done -or [bool]$Status.ok)) -or
        $newState -cnotin @('running', 'succeeded', 'failed')) {
        throw 'Remote build status state/done/ok fields are inconsistent.'
    }
    if ($Status.signing -isnot [System.Collections.IDictionary] -or
        $Status.publishability -isnot [System.Collections.IDictionary]) {
        throw 'Remote build status signing and publishability must be objects.'
    }
    foreach ($requiredSigningField in @(
        'required', 'production_signed', 'payload_manifest_verified'
    )) {
        if (-not $Status.signing.Contains($requiredSigningField)) {
            throw "Remote build status signing is missing $requiredSigningField."
        }
    }
    foreach ($requiredPublishabilityField in @(
        'classification', 'store_submission_eligible',
        'publication_authorized', 'reason'
    )) {
        if (-not $Status.publishability.Contains(
                $requiredPublishabilityField
            )) {
            throw "Remote build status publishability is missing $requiredPublishabilityField."
        }
    }
    $expectedSigning = [string]$Status.build_mode -ceq 'production_signed'
    if ([bool]$Status.signing.required -ne $expectedSigning -or
        [bool]$Status.publishability.store_submission_eligible -or
        [bool]$Status.publishability.publication_authorized) {
        throw 'Remote build status mode/signing/publishability fields disagree.'
    }
    if ($newState -ceq 'succeeded') {
        if (-not [bool]$Status.signing.payload_manifest_verified -or
            [bool]$Status.signing.production_signed -ne $expectedSigning -or
            $Status.copyback_manifest -isnot
                [System.Collections.IDictionary] -or
            [string]$Status.copyback_manifest.path -notmatch '\S' -or
            [long]$Status.copyback_manifest.size -le 0 -or
            [string]$Status.copyback_manifest.sha256 -cnotmatch
                '^[0-9a-f]{64}$') {
            throw 'Successful remote build status lacks verified signing or copyback evidence.'
        }
    } elseif ([bool]$Status.signing.payload_manifest_verified -or
        $null -ne $Status.signing.production_signed -or
        $null -ne $Status.copyback_manifest) {
        throw 'Non-success remote build status contains success-only evidence.'
    }

    $resolvedPath = [IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $resolvedPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "Remote build status parent does not exist: $parent"
    }
    if (Test-Path -LiteralPath $resolvedPath -PathType Container) {
        throw "Remote build status target is a directory: $resolvedPath"
    }
    if (Test-Path -LiteralPath $resolvedPath -PathType Leaf) {
        try {
            $existingStatus = Get-Content -LiteralPath $resolvedPath -Raw `
                -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        } catch {
            throw "Existing remote build status is invalid: $($_.Exception.Message)"
        }
        if ([int]$existingStatus.schema_version -ne 2 -or
            [string]$existingStatus.contract -cne
                'winsvpn-windows-remote-build-status-v2' -or
            [string]$existingStatus.run_id -cne [string]$Status.run_id -or
            [string]$existingStatus.build_mode -cne
                [string]$Status.build_mode) {
            throw 'Existing remote build status does not belong to this run and mode.'
        }
        if ([string]$existingStatus.state -cne 'running' -or
            [bool]$existingStatus.done -or [bool]$existingStatus.ok) {
            throw 'Remote build status is terminal and immutable.'
        }
        if ($newState -cnotin @('succeeded', 'failed')) {
            throw 'Remote build status may only advance from running to terminal.'
        }
    } elseif ($newState -cne 'running') {
        throw 'The first remote build status must be running.'
    }
    $temporary = Join-Path $parent (
        '.' + [IO.Path]::GetFileName($resolvedPath) + '.publish.' + $PID +
        '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    )
    $backup = Join-Path $parent (
        '.' + [IO.Path]::GetFileName($resolvedPath) + '.backup.' + $PID +
        '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    )
    try {
        $json = ConvertTo-Json -InputObject $Status -Depth 8 -Compress
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + "`n")
        $stream = [IO.File]::Open(
            $temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }

        if (Test-Path -LiteralPath $resolvedPath -PathType Leaf) {
            # File.Replace is the same-volume atomic overwrite boundary. The
            # path is run-owned, so replacement can only advance this run.
            [IO.File]::Replace($temporary, $resolvedPath, $backup, $true)
        } elseif (Test-Path -LiteralPath $resolvedPath) {
            throw "Remote build status target is not a regular file: $resolvedPath"
        } else {
            [IO.File]::Move($temporary, $resolvedPath)
        }

        $published = Get-Content -LiteralPath $resolvedPath -Raw -Encoding UTF8 |
            ConvertFrom-Json
        if ([int]$published.schema_version -ne [int]$Status.schema_version -or
            [string]$published.contract -cne [string]$Status.contract -or
            [string]$published.run_id -cne [string]$Status.run_id -or
            [string]$published.state -cne [string]$Status.state -or
            [bool]$published.done -ne [bool]$Status.done -or
            [string]$published.build_mode -cne [string]$Status.build_mode) {
            throw 'Published remote build status did not round-trip exactly.'
        }
    } finally {
        Remove-Item -LiteralPath $temporary, $backup -Force `
            -ErrorAction SilentlyContinue
    }
}

function Write-AtomicNewUtf8File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Value
    )

    $resolvedPath = [IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $resolvedPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "Atomic publication parent does not exist: $parent"
    }
    if (Test-Path -LiteralPath $resolvedPath) {
        throw "Refusing to overwrite immutable publication: $resolvedPath"
    }
    $temporary = Join-Path $parent (
        '.' + [IO.Path]::GetFileName($resolvedPath) + '.publish.' + $PID +
        '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    )
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
        $stream = [IO.File]::Open(
            $temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        [IO.File]::Move($temporary, $resolvedPath)
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Initialize-RunStateDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$CanonicalRunId
    )

    $absoluteRoot = [IO.Path]::GetFullPath($Root)
    [void][IO.Directory]::CreateDirectory($absoluteRoot)
    if (-not (Test-Path -LiteralPath $absoluteRoot -PathType Container) -or
        ((Get-Item -LiteralPath $absoluteRoot -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint)) {
        throw 'StateDir must be a regular directory, not a reparse point.'
    }
    $runDirectory = Join-Path $absoluteRoot $CanonicalRunId
    if (Test-Path -LiteralPath $runDirectory) {
        throw "RunId state already exists; refusing reuse or overwrite: $runDirectory"
    }
    New-Item -ItemType Directory -Path $runDirectory -ErrorAction Stop |
        Out-Null
    return $runDirectory
}

function Test-PowerShellExecutableLaunch {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return $null
        }
        $absolute = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
        $probe = (& $absolute -NoLogo -NoProfile -NonInteractive -Command `
            '[Console]::Out.Write("WINSVPN_POWERSHELL_OK|" + $PSVersionTable.PSVersion.ToString())' `
            2>&1 | Out-String).Trim()
        $probeExitCode = $LASTEXITCODE
        if ($probeExitCode -ne 0 -or
            $probe -cnotmatch '^WINSVPN_POWERSHELL_OK\|([0-9]+(?:\.[0-9]+){1,3})$') {
            return $null
        }
        return [pscustomobject]@{
            Path = $absolute
            Version = [string]$Matches[1]
        }
    } catch {
        return $null
    }
}

function Resolve-LaunchTestedPowerShellExecutable {
    param([string]$Requested)

    $candidates = [Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        if ([IO.Path]::IsPathRooted($Requested)) {
            $candidates.Add($Requested)
        } else {
            foreach ($command in @(Get-Command $Requested -All `
                    -ErrorAction SilentlyContinue)) {
                if (-not [string]::IsNullOrWhiteSpace($command.Source)) {
                    $candidates.Add($command.Source)
                }
            }
        }
        if ($candidates.Count -eq 0) {
            throw "Requested PowerShell executable was not found: $Requested"
        }
    } else {
        foreach ($name in @('pwsh.exe', 'powershell.exe')) {
            foreach ($command in @(Get-Command $name -All `
                    -ErrorAction SilentlyContinue)) {
                if (-not [string]::IsNullOrWhiteSpace($command.Source)) {
                    $candidates.Add($command.Source)
                }
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
            $candidates.Add((Join-Path $env:SystemRoot `
                'System32\WindowsPowerShell\v1.0\powershell.exe'))
        }
    }

    $seen = @{}
    foreach ($candidate in $candidates) {
        $key = ([string]$candidate).ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $launch = Test-PowerShellExecutableLaunch -Path $candidate
        if ($null -ne $launch) {
            return $launch
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        throw "Requested PowerShell executable failed its launch test: $Requested"
    }
    throw 'No launch-tested PowerShell executable is available.'
}

function Set-SafePowerShellProcessEnvironment {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$Version
    )

    $selectedDirectory = Split-Path -Parent $Executable
    $safeSegments = [Collections.Generic.List[string]]::new()
    $safeSegments.Add($selectedDirectory)
    foreach ($segment in (($env:PATH + '') -split ';')) {
        $trimmed = $segment.Trim().Trim('"')
        if ([string]::IsNullOrWhiteSpace($trimmed) -or
            $trimmed.TrimEnd('\') -ieq $selectedDirectory.TrimEnd('\')) {
            continue
        }
        # Store App Execution Aliases can be visible to command discovery but
        # reject CreateProcess in SSH/service sessions. Never let Flutter pick
        # that unlaunchable pwsh.exe ahead of the executable tested above.
        if ($trimmed.TrimEnd('\') -imatch
            '\\Microsoft\\WindowsApps$') {
            $alias = Join-Path $trimmed 'pwsh.exe'
            $discoveredAliases = @(
                Get-Command pwsh.exe -All -ErrorAction SilentlyContinue |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_.Source) -and
                        (Split-Path -Parent $_.Source).TrimEnd('\') -ieq
                            $trimmed.TrimEnd('\')
                    }
            )
            if ((Test-Path -LiteralPath $alias) -or
                $discoveredAliases.Count -ne 0) {
                $aliasLaunch = Test-PowerShellExecutableLaunch -Path $alias
                if ($null -eq $aliasLaunch) { continue }
            }
        }
        $safeSegments.Add($trimmed)
    }
    $env:PATH = ($safeSegments -join ';')
    $env:WINS_WINDOWS_POWERSHELL_EXECUTABLE = $Executable
    $confirmation = Test-PowerShellExecutableLaunch -Path $Executable
    if ($null -eq $confirmation -or
        [string]$confirmation.Version -cne $Version) {
        throw 'The selected PowerShell executable stopped passing its launch test.'
    }
}

function Assert-PayloadManifestSigningMode {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Installer,
        [Parameter(Mandatory = $true)][bool]$ExpectProductionSigned,
        [Parameter(Mandatory = $true)][bool]$ExpectStandaloneWinn3
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Windows payload manifest is missing: $Path"
    }
    try {
        $manifest = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Windows payload manifest is invalid JSON: $($_.Exception.Message)"
    }
    $installerItem = Get-Item -LiteralPath $Installer
    $installerHash = (Get-FileHash -LiteralPath $Installer -Algorithm SHA256).
        Hash.ToLowerInvariant()
    if ([int]$manifest.schema_version -ne 3 -or
        [string]$manifest.installer.name -cne $installerItem.Name -or
        [long]$manifest.installer.size -ne [long]$installerItem.Length -or
        [string]$manifest.installer.sha256 -cne $installerHash) {
        throw 'Windows payload manifest does not bind the exact installer.'
    }
    if ([bool]$manifest.standalone_winn3 -ne $ExpectStandaloneWinn3 -or
        [bool]$manifest.standalone_payload_verified -ne $ExpectStandaloneWinn3) {
        throw 'Windows payload manifest standalone-v3 flags do not match the requested release mode.'
    }
    foreach ($field in @(
        'production_signed', 'every_loose_pe_verified',
        'inno_setup_and_uninstaller_signed'
    )) {
        if ([bool]$manifest.signing.$field -ne $ExpectProductionSigned) {
            throw "Windows payload manifest signing.$field does not match build mode."
        }
    }
    $expectXraySigned = $ExpectProductionSigned -and -not $ExpectStandaloneWinn3
    if ([bool]$manifest.signing.staged_xray_product_signed -ne $expectXraySigned) {
        throw 'Windows payload manifest staged Xray signing does not match Winn v3 primary plus Winn v1 AWG/Xray fallback.'
    }
    if ([bool]$manifest.signing.self_signed_certificate_forbidden -ne $true) {
        throw 'Windows payload manifest does not forbid self-signed certificates.'
    }
    return $manifest
}

function Assert-FormalBuildReceiptMode {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Installer,
        [Parameter(Mandatory = $true)][bool]$ExpectProductionSigned,
        [Parameter(Mandatory = $true)]
        [ValidateSet('x64', 'arm64')][string]$Architecture
    )

    try {
        $receipt = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Formal Windows build receipt is invalid: $($_.Exception.Message)"
    }
    $expectedTarget = "windows-$Architecture-inno-" + $(
        if ($ExpectProductionSigned) { 'signed' } else { 'unsigned' }
    )
    $installerItem = Get-Item -LiteralPath $Installer
    $installerHash = (Get-FileHash -LiteralPath $Installer -Algorithm SHA256).
        Hash.ToLowerInvariant()
    if ([int]$receipt.schema_version -ne 1 -or
        [string]$receipt.contract -cne 'winsvpn-build-receipt-v1' -or
        [string]$receipt.platform -cne 'windows' -or
        [string]$receipt.toolchain.target -cne $expectedTarget -or
        [string]$receipt.artifact.name -cne $installerItem.Name -or
        [long]$receipt.artifact.size_bytes -ne [long]$installerItem.Length -or
        [string]$receipt.artifact.sha256 -cne $installerHash -or
        [bool]$receipt.publication_authorized -ne $false) {
        throw 'Formal Windows build receipt does not match the requested build mode and artifact.'
    }
    return $receipt
}

function Resolve-PreservedArtifactSet {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$Installer,
        [Parameter(Mandatory = $true)][string]$PayloadManifest,
        [Parameter(Mandatory = $true)][bool]$ExpectProductionSigned
    )

    $installerItem = Get-Item -LiteralPath $Installer
    $installerHash = (Get-FileHash -LiteralPath $Installer -Algorithm SHA256).
        Hash.ToLowerInvariant()
    $manifestHash = (Get-FileHash -LiteralPath $PayloadManifest `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $preservationRoot = Join-Path $Repository '.artifacts\rollback\windows'
    if (-not (Test-Path -LiteralPath $preservationRoot -PathType Container)) {
        throw 'Windows preserved artifact root is missing.'
    }
    $matches = @(
        Get-ChildItem -LiteralPath $preservationRoot -Directory -Force |
            Where-Object {
                $_.Name.EndsWith(
                    '-' + $installerHash,
                    [StringComparison]::Ordinal
                )
            }
    )
    if ($matches.Count -ne 1) {
        throw 'The exact installer must have one preserved hash namespace.'
    }
    $directory = $matches[0]
    if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'The preserved Windows artifact namespace cannot be a reparse point.'
    }
    $preservedInstaller = Join-Path $directory.FullName $installerItem.Name
    $preservedManifest = Join-Path $directory.FullName (
        [IO.Path]::GetFileName($PayloadManifest)
    )
    $receipt = Join-Path $directory.FullName 'PRESERVED_ARTIFACT.json'
    foreach ($required in @($preservedInstaller, $preservedManifest, $receipt)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Preserved Windows artifact set is incomplete: $required"
        }
    }
    if ((Get-FileHash -LiteralPath $preservedInstaller -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne $installerHash -or
        (Get-FileHash -LiteralPath $preservedManifest -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne $manifestHash) {
        throw 'Preserved Windows artifact bytes differ from canonical outputs.'
    }
    try {
        $receiptDocument = Get-Content -LiteralPath $receipt -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Preserved Windows artifact receipt is invalid: $($_.Exception.Message)"
    }
    if ([int]$receiptDocument.schema_version -ne 1 -or
        [string]$receiptDocument.contract -cne
            'winsvpn-preserved-windows-artifact-v1' -or
        [bool]$receiptDocument.production_signed -ne $ExpectProductionSigned -or
        [bool]$receiptDocument.publication_authorized -ne $false -or
        [string]$receiptDocument.artifact.path -cne $installerItem.Name -or
        [long]$receiptDocument.artifact.size -ne [long]$installerItem.Length -or
        [string]$receiptDocument.artifact.sha256 -cne $installerHash -or
        [string]$receiptDocument.payload_manifest.path -cne
            [IO.Path]::GetFileName($PayloadManifest) -or
        [string]$receiptDocument.payload_manifest.sha256 -cne $manifestHash) {
        throw 'Preserved Windows artifact receipt does not bind the exact build mode and bytes.'
    }
    return [pscustomobject]@{
        Directory = $directory.FullName
        Namespace = $directory.Name
        Installer = $preservedInstaller
        PayloadManifest = $preservedManifest
        PreservationReceipt = $receipt
        InstallerSha256 = $installerHash
        PayloadManifestSha256 = $manifestHash
    }
}

function Publish-ImmutableCopybackBundle {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$CanonicalRunId,
        [Parameter(Mandatory = $true)][string]$BuildMode,
        [Parameter(Mandatory = $true)][bool]$ProductionSigned,
        [Parameter(Mandatory = $true)][pscustomobject]$Preserved,
        [Parameter(Mandatory = $true)][string]$BuildReceiptDirectory,
        [Parameter(Mandatory = $true)][string]$InputIndex
    )

    $copybackParent = Join-Path $Repository `
        '.artifacts\remote-windows-copyback'
    [void][IO.Directory]::CreateDirectory($copybackParent)
    $bundle = Join-Path $copybackParent $CanonicalRunId
    if (Test-Path -LiteralPath $bundle) {
        throw "RunId already owns a copyback bundle: $bundle"
    }
    New-Item -ItemType Directory -Path $bundle -ErrorAction Stop | Out-Null

    $entries = [Collections.Generic.List[object]]::new()
    function Add-CopybackFile {
        param(
            [Parameter(Mandatory = $true)][string]$Source,
            [Parameter(Mandatory = $true)][string]$RelativeDestination,
            [Parameter(Mandatory = $true)][string]$Role
        )
        if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
            throw "Copyback source is missing: $Source"
        }
        $destination = Join-Path $bundle (
            $RelativeDestination.Replace('/', [IO.Path]::DirectorySeparatorChar)
        )
        $destinationParent = Split-Path -Parent $destination
        [void][IO.Directory]::CreateDirectory($destinationParent)
        [IO.File]::Copy($Source, $destination, $false)
        $sourceHash = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).
            Hash.ToLowerInvariant()
        $destinationHash = (Get-FileHash -LiteralPath $destination `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        $destinationSize = [long](Get-Item -LiteralPath $destination).Length
        if ($destinationHash -cne $sourceHash -or
            $destinationSize -ne [long](Get-Item -LiteralPath $Source).Length) {
            throw "Copyback verification failed: $RelativeDestination"
        }
        $entries.Add([ordered]@{
            path = $RelativeDestination.Replace('\', '/')
            role = $Role
            size = $destinationSize
            sha256 = $destinationHash
        })
    }

    $preservedPrefix = 'preserved/' + $Preserved.Namespace
    Add-CopybackFile -Source $Preserved.Installer `
        -RelativeDestination ($preservedPrefix + '/' +
            [IO.Path]::GetFileName($Preserved.Installer)) `
        -Role 'preserved_installer'
    Add-CopybackFile -Source $Preserved.PayloadManifest `
        -RelativeDestination ($preservedPrefix + '/' +
            [IO.Path]::GetFileName($Preserved.PayloadManifest)) `
        -Role 'preserved_payload_manifest'
    Add-CopybackFile -Source $Preserved.PreservationReceipt `
        -RelativeDestination ($preservedPrefix + '/PRESERVED_ARTIFACT.json') `
        -Role 'preservation_receipt'

    $receiptNames = @(
        'WINDOWS_BUILD_BEGIN.json',
        'WINDOWS_BUILD_BEGIN.json.sha256',
        'WINDOWS_BUILD_RECEIPT.json',
        'WINDOWS_BUILD_RECEIPT.json.sha256'
    )
    $receiptItems = @(Get-ChildItem -LiteralPath $BuildReceiptDirectory -Force)
    $receiptFiles = @($receiptItems | Where-Object { -not $_.PSIsContainer })
    if ($receiptItems.Count -ne $receiptNames.Count -or
        $receiptFiles.Count -ne $receiptNames.Count -or
        @($receiptFiles | Where-Object {
            $_.Attributes -band [IO.FileAttributes]::ReparsePoint
        }).Count -ne 0) {
        throw 'Formal Windows build receipt directory must contain exactly four files including SHA-256 anchors.'
    }
    foreach ($name in $receiptNames) {
        Add-CopybackFile -Source (Join-Path $BuildReceiptDirectory $name) `
            -RelativeDestination ('build-receipts/' + $name) `
            -Role 'formal_build_receipt'
    }

    $inputIndexPath = [IO.Path]::GetFullPath($InputIndex)
    $controlDirectory = Split-Path -Parent $inputIndexPath
    $controlItems = @(Get-ChildItem -LiteralPath $controlDirectory -Force)
    $controlFiles = @($controlItems | Where-Object { -not $_.PSIsContainer })
    if ($controlItems.Count -ne 8 -or $controlFiles.Count -ne 8 -or
        @($controlFiles | Where-Object {
            $_.Attributes -band [IO.FileAttributes]::ReparsePoint
        }).Count -ne 0) {
        throw 'Release input control directory must remain an exact eight-file set.'
    }
    foreach ($controlFile in @($controlFiles | Sort-Object Name)) {
        Add-CopybackFile -Source $controlFile.FullName `
            -RelativeDestination ('release-input-control/' + $controlFile.Name) `
            -Role 'release_input_control'
    }

    $sortedEntries = @($entries | Sort-Object { $_.path })
    $copybackManifest = [ordered]@{
        schema_version = 1
        contract = 'winsvpn-windows-remote-copyback-v1'
        run_id = $CanonicalRunId
        created_utc = [DateTime]::UtcNow.ToString('o')
        build_mode = $BuildMode
        production_signed = $ProductionSigned
        publication_authorized = $false
        preserved_namespace = $Preserved.Namespace
        installer_sha256 = $Preserved.InstallerSha256
        payload_manifest_sha256 = $Preserved.PayloadManifestSha256
        release_input_index = 'release-input-control/RELEASE_INPUT_INDEX.json'
        files = $sortedEntries
    }
    $manifestPath = Join-Path $bundle 'COPYBACK_MANIFEST.json'
    $manifestJson = ConvertTo-Json -InputObject $copybackManifest -Depth 7
    Write-AtomicNewUtf8File -Path $manifestPath -Value ($manifestJson + "`n")

    $published = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 |
        ConvertFrom-Json -ErrorAction Stop
    if ([string]$published.contract -cne
            'winsvpn-windows-remote-copyback-v1' -or
        [string]$published.run_id -cne $CanonicalRunId -or
        [bool]$published.production_signed -ne $ProductionSigned -or
        @($published.files).Count -ne $sortedEntries.Count) {
        throw 'Published copyback manifest did not round-trip exactly.'
    }
    foreach ($entry in @($published.files)) {
        $path = Join-Path $bundle (
            ([string]$entry.path).Replace(
                '/', [IO.Path]::DirectorySeparatorChar
            )
        )
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
            [long](Get-Item -LiteralPath $path).Length -ne [long]$entry.size -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).
                Hash.ToLowerInvariant() -cne [string]$entry.sha256) {
            throw "Published copyback entry failed verification: $($entry.path)"
        }
    }
    $unboundFiles = @(
        Get-ChildItem -LiteralPath $bundle -File -Recurse -Force |
            Where-Object { $_.FullName -cne $manifestPath }
    )
    if ($unboundFiles.Count -ne $sortedEntries.Count) {
        throw 'Copyback bundle contains an unbound file.'
    }
    return [pscustomobject]@{
        Directory = $bundle
        Manifest = $manifestPath
        ManifestSha256 = (Get-FileHash -LiteralPath $manifestPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        ManifestSize = [long](Get-Item -LiteralPath $manifestPath).Length
    }
}

function New-StatusSigningRecord {
    param(
        [Parameter(Mandatory = $true)][bool]$Required,
        [AllowNull()][Nullable[bool]]$ProductionSigned,
        [Parameter(Mandatory = $true)][bool]$PayloadManifestVerified
    )
    return [ordered]@{
        required = $Required
        production_signed = $ProductionSigned
        payload_manifest_verified = $PayloadManifestVerified
    }
}

function New-StatusPublishabilityRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Classification,
        [Parameter(Mandatory = $true)][bool]$StoreSubmissionEligible,
        [Parameter(Mandatory = $true)][string]$Reason
    )
    return [ordered]@{
        classification = $Classification
        store_submission_eligible = $StoreSubmissionEligible
        publication_authorized = $false
        reason = $Reason
    }
}

function Invoke-StatusPublicationSelfTest {
    $testRoot = Join-Path ([IO.Path]::GetTempPath()) (
        'winsvpn-remote-build-status-selftest-' + [Guid]::NewGuid().ToString('N')
    )
    [void][IO.Directory]::CreateDirectory($testRoot)
    try {
        $currentRunId = [Guid]::NewGuid().ToString('D')
        $runDirectory = Initialize-RunStateDirectory -Root $testRoot `
            -CanonicalRunId $currentRunId
        $testPath = Join-Path $runDirectory 'remote-build-status.json'
        $running = [ordered]@{
            schema_version = 2
            contract = 'winsvpn-windows-remote-build-status-v2'
            run_id = $currentRunId
            state = 'running'
            done = $false
            ok = $false
            build_mode = 'production_signed'
            signing = New-StatusSigningRecord -Required $true `
                -ProductionSigned $null -PayloadManifestVerified $false
            publishability = New-StatusPublishabilityRecord `
                -Classification 'pending_signed_verification' `
                -StoreSubmissionEligible $false `
                -Reason 'Build has not completed.'
        }
        Write-RemoteBuildStatusAtomic -Path $testPath -Status $running
        $terminal = [ordered]@{}
        foreach ($key in $running.Keys) {
            $terminal[$key] = $running[$key]
        }
        $terminal.state = 'failed'
        $terminal.done = $true
        Write-RemoteBuildStatusAtomic -Path $testPath -Status $terminal
        $observed = Get-Content -LiteralPath $testPath -Raw | ConvertFrom-Json
        if (-not [bool]$observed.done -or
            [string]$observed.state -cne 'failed' -or
            [string]$observed.run_id -cne $currentRunId) {
            throw 'Run-owned atomic status advancement failed.'
        }
        $terminalOverwriteAccepted = $false
        try {
            Write-RemoteBuildStatusAtomic -Path $testPath -Status $terminal
            $terminalOverwriteAccepted = $true
        } catch {
            $terminalOverwriteAccepted = $false
        }
        if ($terminalOverwriteAccepted) {
            throw 'Terminal remote build status was mutable.'
        }
        $reuseAccepted = $false
        try {
            [void](Initialize-RunStateDirectory -Root $testRoot `
                -CanonicalRunId $currentRunId)
            $reuseAccepted = $true
        } catch {
            $reuseAccepted = $false
        }
        if ($reuseAccepted) {
            throw 'RunId state reuse was accepted.'
        }
        if (@(Get-ChildItem -LiteralPath $runDirectory -Filter '*.tmp' -Force).
                Count -ne 0) {
            throw 'Atomic status publication left a temporary file behind.'
        }
    } finally {
        Remove-Item -LiteralPath $testRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
    Write-Host 'WINDOWS REMOTE BUILD STATUS SELF-TEST: PASS'
}

if ($SelfTestStatusPublication) {
    Invoke-StatusPublicationSelfTest
    exit 0
}

$RunId = Resolve-CanonicalRunId -Value $RunId
if ([string]::IsNullOrWhiteSpace($StateDir)) {
    throw 'StateDir is required for run-bound remote build status.'
}
$buildMode = if ($AllowUnsignedEngineering) {
    'unsigned_engineering'
} else {
    'production_signed'
}
$signingRequired = -not [bool]$AllowUnsignedEngineering
$preflightRepository = [IO.Path]::GetFullPath($RepoRoot)
$preflightBuildReceiptDirectory = Join-Path $preflightRepository (
    '.artifacts\remote-windows-build-receipts\' + $RunId
)
$preflightCopybackDirectory = Join-Path $preflightRepository (
    '.artifacts\remote-windows-copyback\' + $RunId
)
foreach ($runOwnedPath in @(
    $preflightBuildReceiptDirectory, $preflightCopybackDirectory
)) {
    if (Test-Path -LiteralPath $runOwnedPath) {
        throw "RunId already owns build evidence; refusing collision before status publication: $runOwnedPath"
    }
}
$runStateDirectory = Initialize-RunStateDirectory -Root $StateDir `
    -CanonicalRunId $RunId
$statusPath = Join-Path $runStateDirectory 'remote-build-status.json'
$startedUtc = [DateTime]::UtcNow.ToString('o')
$runningStatus = [ordered]@{
    schema_version = 2
    contract = 'winsvpn-windows-remote-build-status-v2'
    run_id = $RunId
    state = 'running'
    done = $false
    ok = $false
    build_mode = $buildMode
    started_utc = $startedUtc
    pid = $PID
    signing = New-StatusSigningRecord -Required $signingRequired `
        -ProductionSigned $null -PayloadManifestVerified $false
    publishability = New-StatusPublishabilityRecord `
        -Classification $(if ($signingRequired) {
            'pending_signed_verification'
        } else {
            'unsigned_engineering_nonpublishable'
        }) -StoreSubmissionEligible $false `
        -Reason $(if ($signingRequired) {
            'Signed build has not completed verification.'
        } else {
            'Unsigned engineering artifacts must never be published.'
        })
    copyback_manifest = $null
}
Write-RemoteBuildStatusAtomic -Path $statusPath -Status $runningStatus
Write-Output "WINDOWS_REMOTE_BUILD_RUN_ID=$RunId"
Write-Output "WINDOWS_REMOTE_BUILD_STATUS=$statusPath"

$resolvedPowerShell = $null
try {
    # Establish and launch-test PowerShell before Flutter is placed on PATH or
    # invoked. This prevents an inaccessible WindowsApps pwsh alias from
    # producing Flutter's misleading engine-version failure.
    $resolvedPowerShell = Resolve-LaunchTestedPowerShellExecutable `
        -Requested $PowerShellExecutable
    Set-SafePowerShellProcessEnvironment `
        -Executable $resolvedPowerShell.Path `
        -Version $resolvedPowerShell.Version

    if (-not [string]::IsNullOrWhiteSpace($FlutterRoot)) {
        $flutterBin = Join-Path $FlutterRoot 'bin'
        $flutterCommand = Join-Path $flutterBin 'flutter.bat'
        if (-not (Test-Path -LiteralPath $flutterCommand -PathType Leaf)) {
            throw "Flutter SDK was not found at $FlutterRoot."
        }
        $env:PATH = "$flutterBin;$env:PATH"
    }
    if ([string]::IsNullOrWhiteSpace($ExpectedFlutterRevision)) {
        # SINGLE SOURCE OF TRUTH for the reviewed revision: read
        # tools/toolchain-pins.json at run time instead of a literal. A
        # literal that agrees today still desynchronises this build from
        # every other build on the next pin bump.
        $pinFile = Join-Path $RepoRoot 'tools\toolchain-pins.json'
        if (-not (Test-Path -LiteralPath $pinFile -PathType Leaf)) {
            throw "Unable to resolve the reviewed Flutter revision: $pinFile is missing."
        }
        $pin = Get-Content -Raw -LiteralPath $pinFile | ConvertFrom-Json -ErrorAction Stop
        $ExpectedFlutterRevision = [string]$pin.tools.flutter.revision
    }
    if ($ExpectedFlutterRevision -notmatch '^[0-9a-f]{40}$') {
        throw 'ExpectedFlutterRevision must be a full lowercase Git revision.'
    }
    $flutterExecutable = (Get-Command flutter.bat -ErrorAction Stop).Source
    $resolvedFlutterRoot = Split-Path -Parent (Split-Path -Parent $flutterExecutable)
    $actualFlutterRevision = (& git.exe -C $resolvedFlutterRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $actualFlutterRevision -ne $ExpectedFlutterRevision) {
        throw "Flutter revision mismatch; expected $ExpectedFlutterRevision and found $actualFlutterRevision."
    }
    $RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
    Set-Location $RepoRoot
    $buildReceiptParent = Join-Path $RepoRoot `
        '.artifacts\remote-windows-build-receipts'
    [void][IO.Directory]::CreateDirectory($buildReceiptParent)
    $buildReceiptDirectory = Join-Path $buildReceiptParent $RunId
    if (Test-Path -LiteralPath $buildReceiptDirectory) {
        throw "RunId already owns a Windows build receipt directory: $buildReceiptDirectory"
    }
    if (-not $SkipReadinessValidation) {
        & python.exe tools\validate_desktop_tunnel_readiness.py
        if ($LASTEXITCODE -ne 0) {
            throw "Readiness validator exited $LASTEXITCODE."
        }
    }

    $installerModeArgument = if ($AllowUnsignedEngineering) {
        '-AllowUnsigned'
    } else {
        '-RequireCodeSigning'
    }
    $standaloneArgument = @()
    if ($StandaloneWinn3Release) {
        $standaloneArgument = @('-StandaloneWinn3Release')
    }
    & $resolvedPowerShell.Path -NoProfile -NonInteractive `
        -ExecutionPolicy Bypass -File installer\windows\build_installer.ps1 `
        $installerModeArgument -SkipRuntimeDownload @standaloneArgument `
        -TargetArchitecture $TargetArchitecture `
        -ReleaseInputIndex $ReleaseInputIndex `
        -BuildReceiptDirectory $buildReceiptDirectory
    if ($LASTEXITCODE -ne 0) {
        throw "Installer build exited $LASTEXITCODE."
    }

    # Treat the child producer's checks as necessary but not sufficient. The
    # remote wrapper owns the end-to-end success boundary, so independently
    # re-verify the exact Windows source scope after the installer process has
    # returned and before reading or reporting any candidate artifact.
    & python.exe tools\release_dependency_freeze.py verify-index `
        --repo $RepoRoot --index $ReleaseInputIndex --platform windows
    if ($LASTEXITCODE -ne 0) {
        throw "Post-installer Windows release input verification exited $LASTEXITCODE."
    }

    $installerName = if ($TargetArchitecture -ceq 'arm64') {
        'WinsVPN-Setup-arm64.exe'
    } else {
        'WinsVPN-Setup.exe'
    }
    $installer = Join-Path $RepoRoot "build\windows-installer\$installerName"
    $flutterArch = @{ 'x64' = 'x64'; 'arm64' = 'arm64' }[$TargetArchitecture]
    $gui = Join-Path $RepoRoot "build\windows\$flutterArch\runner\Release\wins_vpn.exe"
    $service = Join-Path $RepoRoot "build\windows\$flutterArch\runner\Release\wins_vpn_tunnel_service.exe"
    $payloadManifest = "$installer.payload-manifest.json"
    $buildBeginReceipt = Join-Path $buildReceiptDirectory `
        'WINDOWS_BUILD_BEGIN.json'
    $buildReceipt = Join-Path $buildReceiptDirectory 'WINDOWS_BUILD_RECEIPT.json'
    foreach ($requiredOutput in @(
        $installer, $gui, $service, $payloadManifest,
        $buildBeginReceipt, $buildReceipt
    )) {
        if (-not (Test-Path -LiteralPath $requiredOutput -PathType Leaf)) {
            throw "Remote Windows producer did not create required output: $requiredOutput"
        }
    }
    if ($StandaloneWinn3Release) {
        & python.exe tools\verify_windows_standalone_v3_artifact.py $installer
        if ($LASTEXITCODE -ne 0) {
            throw "Remote Windows standalone-v3 payload verification exited $LASTEXITCODE."
        }
    }
    & python.exe tools\release_dependency_freeze.py verify-receipt `
        --repo $RepoRoot --index $ReleaseInputIndex --platform windows `
        --receipt $buildReceipt --artifact $installer
    if ($LASTEXITCODE -ne 0) {
        throw "Remote Windows build receipt verification exited $LASTEXITCODE."
    }
    $buildReceiptDocument = Assert-FormalBuildReceiptMode `
        -Path $buildReceipt -Installer $installer `
        -ExpectProductionSigned $signingRequired `
        -Architecture $TargetArchitecture

    $payloadDocument = Assert-PayloadManifestSigningMode `
        -Path $payloadManifest -Installer $installer `
        -ExpectProductionSigned $signingRequired `
        -ExpectStandaloneWinn3 ([bool]$StandaloneWinn3Release)
    $preserved = Resolve-PreservedArtifactSet -Repository $RepoRoot `
        -Installer $installer -PayloadManifest $payloadManifest `
        -ExpectProductionSigned $signingRequired
    $copyback = Publish-ImmutableCopybackBundle -Repository $RepoRoot `
        -CanonicalRunId $RunId -BuildMode $buildMode `
        -ProductionSigned $signingRequired -Preserved $preserved `
        -BuildReceiptDirectory $buildReceiptDirectory `
        -InputIndex $ReleaseInputIndex

    # Sealing the copyback bundle is the last fallible artifact operation.
    # Re-verify source scope and the formal receipt once more so status can
    # never report success for evidence copied after source drift.
    & python.exe tools\release_dependency_freeze.py verify-index `
        --repo $RepoRoot --index $ReleaseInputIndex --platform windows
    if ($LASTEXITCODE -ne 0) {
        throw "Post-copyback Windows release input verification exited $LASTEXITCODE."
    }
    & python.exe tools\release_dependency_freeze.py verify-receipt `
        --repo $RepoRoot --index $ReleaseInputIndex --platform windows `
        --receipt $buildReceipt --artifact $installer
    if ($LASTEXITCODE -ne 0) {
        throw "Post-copyback Windows build receipt verification exited $LASTEXITCODE."
    }

    $buildReceiptRelative = Get-RepoRelativePath -Root $RepoRoot `
        -Path $buildReceipt
    $copybackManifestRelative = Get-RepoRelativePath -Root $RepoRoot `
        -Path $copyback.Manifest
    $result = [ordered]@{
        schema_version = 2
        contract = 'winsvpn-windows-remote-build-status-v2'
        run_id = $RunId
        state = 'succeeded'
        done = $true
        ok = $true
        build_mode = $buildMode
        started_utc = $startedUtc
        finished_utc = [DateTime]::UtcNow.ToString('o')
        powershell = [ordered]@{
            executable = $resolvedPowerShell.Path
            version = $resolvedPowerShell.Version
            launch_tested = $true
        }
        signing = New-StatusSigningRecord -Required $signingRequired `
            -ProductionSigned ([bool]$payloadDocument.signing.production_signed) `
            -PayloadManifestVerified $true
        publishability = New-StatusPublishabilityRecord `
            -Classification $(if ($signingRequired) {
                'production_signed_candidate'
            } else {
                'unsigned_engineering_nonpublishable'
            }) -StoreSubmissionEligible $false `
            -Reason $(if ($signingRequired) {
                'Separate release approval and evidence are required before store submission.'
            } else {
                'Unsigned engineering artifacts must never be published.'
            })
        installer_sha256 = $preserved.InstallerSha256
        gui_sha256 = (Get-FileHash -LiteralPath $gui -Algorithm SHA256).
            Hash.ToLowerInvariant()
        service_sha256 = (Get-FileHash -LiteralPath $service -Algorithm SHA256).
            Hash.ToLowerInvariant()
        payload_manifest_sha256 = $preserved.PayloadManifestSha256
        build_receipt_path = $buildReceiptRelative
        build_receipt_sha256 = (Get-FileHash -LiteralPath $buildReceipt `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        copyback_manifest = [ordered]@{
            path = $copybackManifestRelative
            size = $copyback.ManifestSize
            sha256 = $copyback.ManifestSha256
        }
    }
    Write-RemoteBuildStatusAtomic -Path $statusPath -Status $result
} catch {
    $buildFailure = $_
    $failureSigning = New-StatusSigningRecord -Required $signingRequired `
        -ProductionSigned $null -PayloadManifestVerified $false
    $result = [ordered]@{
        schema_version = 2
        contract = 'winsvpn-windows-remote-build-status-v2'
        run_id = $RunId
        state = 'failed'
        done = $true
        ok = $false
        build_mode = $buildMode
        started_utc = $startedUtc
        finished_utc = [DateTime]::UtcNow.ToString('o')
        signing = $failureSigning
        publishability = New-StatusPublishabilityRecord `
            -Classification 'failed_nonpublishable' `
            -StoreSubmissionEligible $false `
            -Reason 'Failed builds are never publishable.'
        copyback_manifest = $null
        error = (($buildFailure.Exception.Message + '') -replace '[\r\n]+', ' ')
    }
    if ($null -ne $resolvedPowerShell) {
        $result.powershell = [ordered]@{
            executable = $resolvedPowerShell.Path
            version = $resolvedPowerShell.Version
            launch_tested = $true
        }
    }
    try {
        Write-RemoteBuildStatusAtomic -Path $statusPath -Status $result
    } catch {
        throw "Remote build failed: $($buildFailure.Exception.Message) Atomic failure-status publication also failed: $($_.Exception.Message)"
    }
    throw $buildFailure
}

# This script is commonly dot-invoked by an outer build wrapper so that the
# wrapper can run post-build dependency verification in the same process. A
# successful native build may leave $LASTEXITCODE nonzero after a later
# PowerShell cmdlet, even though the sealed status above is ok=true. Normalize
# the native exit-code channel only on the proven-success path; failures throw
# before reaching this point.
$global:LASTEXITCODE = 0
