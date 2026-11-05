Set-StrictMode -Version 3.0

$script:WinsAndroidCustodyContract = 'winsvpn-android-toolchain-custody-v1'
$script:WinsAndroidSha256Pattern = '^[0-9a-f]{64}$'
$script:WinsAndroidOfficialKeys = @(
    'schema_version',
    'contract',
    'issuance_id',
    'created_utc',
    'helper',
    'helper_sha256',
    'provisioner',
    'manifest',
    'manifest_sha256',
    'windows_helper',
    'windows_helper_sha256',
    'platforms'
)
$script:WinsAndroidSubsetKeys = @('schema_version', 'contract', 'platforms')
$script:WinsAndroidIssuancePattern = '^[0-9a-f]{32}$'
$script:WinsAndroidUtcPattern = '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
$script:WinsAndroidReviewedIssuanceUtc = [datetime]::ParseExact(
    '2026-08-19T00:00:00Z',
    'yyyy-MM-ddTHH:mm:ssZ',
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
)
$script:WinsAndroidWindowsTransactionHeld = $false

$script:WinsAndroidCustodyHelperPath = [string]$MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($script:WinsAndroidCustodyHelperPath)) {
    throw 'Android Windows helper identity is unbound'
}
Assert-NoReparsePath -Path $script:WinsAndroidCustodyHelperPath -Description 'Android Windows helper'
$script:WinsAndroidCustodyHelperStream = [IO.FileStream]::new(
    $script:WinsAndroidCustodyHelperPath,
    [IO.FileMode]::Open,
    [IO.FileAccess]::Read,
    [IO.FileShare]::Read
)
$script:WinsAndroidCustodyHelperIdentity = Get-WinsFileIdentityFromStream -Stream $script:WinsAndroidCustodyHelperStream
if ($script:WinsAndroidCustodyHelperIdentity.NumberOfLinks -ne 1) {
    $script:WinsAndroidCustodyHelperStream.Dispose()
    throw "Android Windows helper must be a single-link file: $($script:WinsAndroidCustodyHelperPath)"
}

function Get-WinsAndroidCustodyStreamIdentity {
    param([Parameter(Mandatory)][IO.FileStream]$Stream)

    return Get-WinsFileIdentityFromStream -Stream $Stream
}

function Test-WinsAndroidCustodyIdentityEqual {
    param(
        [Parameter(Mandatory)]$First,
        [Parameter(Mandatory)]$Second
    )

    return $First.VolumeSerialNumber -eq $Second.VolumeSerialNumber -and
        $First.FileIndexHigh -eq $Second.FileIndexHigh -and
        $First.FileIndexLow -eq $Second.FileIndexLow -and
        $First.NumberOfLinks -eq $Second.NumberOfLinks -and
        $First.FileSize -eq $Second.FileSize -and
        $First.LastWriteFileTime -eq $Second.LastWriteFileTime
}

function Get-WinsAndroidExactInteger {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Label
    )

    if ($null -eq $Value) {
        throw "$Label has the wrong type"
    }
    $typeName = $Value.GetType().FullName
    if ($typeName -eq 'System.Boolean') {
        throw "$Label must be an integer, not bool-as-int"
    }
    if ($typeName -ne 'System.Int32' -and $typeName -ne 'System.Int64') {
        throw "$Label has the wrong type"
    }
    return [int]$Value
}

function Get-WinsAndroidHeldFileDigest {
    param(
        [Parameter(Mandatory)][IO.FileStream]$Stream,
        [Parameter(Mandatory)]$ExpectedIdentity,
        [Parameter(Mandatory)][string]$Description
    )

    $before = Get-WinsAndroidCustodyStreamIdentity -Stream $Stream
    if (-not (Test-WinsAndroidCustodyIdentityEqual -First $ExpectedIdentity -Second $before)) {
        throw "$Description changed before it was hashed"
    }
    if ($before.NumberOfLinks -ne 1) {
        throw "$Description must be a single-link file"
    }
    $null = $Stream.Seek(0, [IO.SeekOrigin]::Begin)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
    $after = Get-WinsAndroidCustodyStreamIdentity -Stream $Stream
    if (-not (Test-WinsAndroidCustodyIdentityEqual -First $before -Second $after)) {
        throw "$Description changed while it was hashed"
    }
    return $digest
}

function Get-WinsAndroidCustodyFileRecord {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    Assert-NoReparsePath -Path $Path -Description $Description
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.LinkType -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Description must be one regular non-reparse file: $Path"
    }
    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $before = Get-WinsAndroidCustodyStreamIdentity -Stream $stream
        $digest = Get-WinsAndroidHeldFileDigest `
            -Stream $stream -ExpectedIdentity $before -Description $Description
        return [pscustomobject]@{
            Digest = $digest
            Size = [uint64]$before.FileSize
        }
    } finally {
        $stream.Dispose()
    }
}

function Get-WinsAndroidCustodyFileSha256 {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    return [string](Get-WinsAndroidCustodyFileRecord -Path $Path -Description $Description).Digest
}

function Get-WinsAndroidLiveHelperSha256 {
    if ($null -eq $script:WinsAndroidCustodyHelperStream) {
        throw 'Android Windows helper stream is unbound'
    }
    return Get-WinsAndroidHeldFileDigest `
        -Stream $script:WinsAndroidCustodyHelperStream `
        -ExpectedIdentity $script:WinsAndroidCustodyHelperIdentity `
        -Description 'Android Windows helper'
}

function Test-WinsAndroidWindowsOs {
    try {
        return [bool]$IsWindows
    } catch {
        return [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    }
}

function Assert-WinsAndroidWindowsManifestAndTreeTransaction {
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$Root
    )

    # ANDROID_WINDOWS_CUSTODY_TREE_TRANSACTION
    if (-not (Test-WinsAndroidWindowsOs)) {
        return
    }
    $script:WinsAndroidWindowsTransactionHeld = $false
    try {
        Add-Type -AssemblyName System.Transactions -ErrorAction Stop
        $scope = [Transactions.TransactionScope]::new(
            [Transactions.TransactionScopeOption]::Required,
            [TimeSpan]::FromMinutes(5)
        )
        try {
            Assert-SingleLinkFile -Path $ManifestPath -Description 'Android toolchain custody manifest'
            Assert-NoReparsePath -Path $Root -Description 'Android toolchain tree'
            $script:WinsAndroidWindowsTransactionHeld = $true
            $scope.Complete()
        } finally {
            $scope.Dispose()
        }
    } catch {
        throw 'owner/environment blocker: Windows must hold the Android toolchain manifest and tree transaction or remain owner-blocked'
    }
    if (-not $script:WinsAndroidWindowsTransactionHeld) {
        throw 'owner/environment blocker: Windows must hold the Android toolchain manifest and tree transaction or remain owner-blocked'
    }
}

function Get-WinsAndroidToolchainTreeSha256 {
    param(
        [Parameter(Mandatory)][string]$Root,
        [string]$Description = 'Android toolchain'
    )

    Assert-NoReparsePath -Path $Root -Description "$Description root"
    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or $rootItem.LinkType -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Description root must be one regular non-reparse directory: $Root"
    }
    $rootPath = $rootItem.FullName.TrimEnd('\', '/')
    $entries = @(Get-ChildItem -LiteralPath $rootPath -Force -Recurse -ErrorAction Stop)
    $relativeNames = [Collections.Generic.List[string]]::new()
    $entryByRelativeName = @{}
    foreach ($entry in $entries) {
        $relative = $entry.FullName.Substring($rootPath.Length).TrimStart('\', '/').Replace('\', '/')
        if ([string]::IsNullOrWhiteSpace($relative) -or $relative.IndexOf([char]0) -ge 0 -or
            $relative.IndexOf("`n") -ge 0 -or $relative.IndexOf("`r") -ge 0 -or
            $relative.IndexOf("`t") -ge 0) {
            throw "$Description contains an unsupported path name: $($entry.FullName)"
        }
        if ($entryByRelativeName.ContainsKey($relative)) {
            throw "$Description contains a duplicate normalized path: $relative"
        }
        $relativeNames.Add($relative)
        $entryByRelativeName[$relative] = $entry
    }
    $relativeArray = $relativeNames.ToArray()
    [Array]::Sort($relativeArray, [StringComparer]::Ordinal)
    $records = [Collections.Generic.List[string]]::new()
    foreach ($relative in $relativeArray) {
        $entry = $entryByRelativeName[$relative]
        if ($entry.LinkType -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "$Description tree must not contain reparse points: $($entry.FullName)"
        }
        if ($entry.PSIsContainer) {
            $records.Add("D`t$relative")
            continue
        }
        $fileRecord = Get-WinsAndroidCustodyFileRecord `
            -Path $entry.FullName -Description "$Description file"
        $records.Add("F`t$relative`t$($fileRecord.Size)`t$($fileRecord.Digest)")
    }
    $payload = [Text.Encoding]::UTF8.GetBytes(($records -join "`n") + "`n")
    $treeSha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($treeSha.ComputeHash($payload))).Replace('-', '').ToLowerInvariant()
    } finally {
        $treeSha.Dispose()
    }
}

function ConvertFrom-WinsAndroidCustodyManifest {
    param([Parameter(Mandatory)][string]$ManifestPath)

    Assert-SingleLinkFile -Path $ManifestPath -Description 'Android toolchain custody manifest'
    Assert-NoReparsePath -Path $ManifestPath -Description 'Android toolchain custody manifest'
    $item = Get-Item -LiteralPath $ManifestPath -Force -ErrorAction Stop
    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $before = Get-WinsAndroidCustodyStreamIdentity -Stream $stream
        if ($before.NumberOfLinks -ne 1) {
            throw "Android toolchain custody manifest must be a single-link file: $ManifestPath"
        }
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false), $false, 1024, $true)
        $text = $reader.ReadToEnd()
        $after = Get-WinsAndroidCustodyStreamIdentity -Stream $stream
        if (-not (Test-WinsAndroidCustodyIdentityEqual -First $before -Second $after)) {
            throw "Android toolchain custody manifest changed while it was read: $ManifestPath"
        }
    } finally {
        $stream.Dispose()
    }
    $manifest = $text | ConvertFrom-Json -ErrorAction Stop
    $schema = Get-WinsAndroidExactInteger -Value $manifest.schema_version -Label 'schema_version'
    if ($schema -ne 1 -or $manifest.contract -cne $script:WinsAndroidCustodyContract) {
        throw 'Android toolchain custody manifest schema or contract is unsupported.'
    }
    $names = @($manifest.PSObject.Properties.Name)
    $hasOfficial = $false
    foreach ($key in $script:WinsAndroidOfficialKeys) {
        if ($key -notin $script:WinsAndroidSubsetKeys -and $names -contains $key) {
            $hasOfficial = $true
            break
        }
    }
    if ($hasOfficial) {
        foreach ($key in $script:WinsAndroidOfficialKeys) {
            if ($names -notcontains $key) {
                throw "Android toolchain custody contract field is absent: $key"
            }
        }
        foreach ($name in $names) {
            if ($script:WinsAndroidOfficialKeys -notcontains $name) {
                throw "unexpected extra field rejected: contract.$name"
            }
        }
        $issuance = [string]$manifest.issuance_id
        if ($issuance -cnotmatch $script:WinsAndroidIssuancePattern) {
            throw 'issuance_id must be a 32-hex issuance identity'
        }
        if ($text -notmatch '"created_utc"\s*:\s*"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"') {
            throw 'created_utc must be exact ISO UTC'
        }
        $createdValue = $manifest.created_utc
        if ($createdValue -is [datetime]) {
            $createdUtc = ([datetime]$createdValue).ToUniversalTime()
        } else {
            $created = [string]$createdValue
            if ($created -cnotmatch $script:WinsAndroidUtcPattern) {
                throw 'created_utc must be exact ISO UTC'
            }
            $createdUtc = [datetime]::ParseExact(
                $created,
                'yyyy-MM-ddTHH:mm:ssZ',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
            )
        }
        if ($createdUtc -lt $script:WinsAndroidReviewedIssuanceUtc) {
            throw 'created_utc is stale'
        }
        if ($createdUtc -gt ([datetime]::UtcNow.AddMinutes(5))) {
            throw 'created_utc is future-dated'
        }
        if ([string]$manifest.helper -cne 'tools/release_android_toolchain_archive_custody.sh') {
            throw 'helper path mismatch'
        }
        if ([string]$manifest.provisioner -cne 'tools/provision_macos_release_android_toolchains.sh') {
            throw 'provisioner path mismatch'
        }
        if ([string]$manifest.manifest -cne 'tools/toolchain-pins.json') {
            throw 'manifest path mismatch'
        }
        foreach ($digestField in @('helper_sha256', 'manifest_sha256')) {
            $digest = ([string]$manifest.$digestField).ToLowerInvariant()
            if ($digest -cnotmatch $script:WinsAndroidSha256Pattern -or $digest -ceq ('0' * 64)) {
                throw "$digestField must be an exact lowercase non-zero SHA-256"
            }
        }
        if ([string]$manifest.windows_helper -cne 'tools/android_toolchain_custody.ps1') {
            throw 'windows helper path mismatch'
        }
        $windowsHelperSha = ([string]$manifest.windows_helper_sha256).ToLowerInvariant()
        if ($windowsHelperSha -cnotmatch $script:WinsAndroidSha256Pattern -or $windowsHelperSha -ceq ('0' * 64)) {
            throw 'windows_helper_sha256 must be an exact lowercase non-zero SHA-256'
        }
        $liveHelperSha = Get-WinsAndroidLiveHelperSha256
        if ($liveHelperSha -cne $windowsHelperSha) {
            throw 'malicious or substituted Android Windows helper rejected'
        }
        $platformNames = @($manifest.platforms.PSObject.Properties.Name)
        if ($platformNames.Count -ne 2 -or
            $platformNames -notcontains 'darwin_arm64' -or
            $platformNames -notcontains 'windows_amd64') {
            throw 'platforms must be exactly darwin_arm64 and windows_amd64'
        }
    }
    return $manifest
}

function Assert-WinsAndroidToolchainCustodyRecordComplete {
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][string]$Platform,
        [Parameter(Mandatory)][ValidateSet('python', 'flutter', 'jdk')][string]$Tool
    )

    foreach ($field in @('archive_sha256', 'install_tree_sha256', 'archive_environment', 'version', 'vendor', 'architecture')) {
        if (-not $Record.PSObject.Properties[$field] -or
            [string]::IsNullOrWhiteSpace([string]$Record.$field)) {
            throw "Android $Tool custody pin is missing $field for $Platform."
        }
    }
    if (-not $Record.PSObject.Properties['revision']) {
        throw "Android $Tool custody pin is missing revision for $Platform."
    }
    $revision = [string]$Record.revision
    if ($Tool -eq 'flutter' -and [string]::IsNullOrWhiteSpace($revision)) {
        throw "Android flutter custody pin is missing revision for $Platform."
    }
    $archivePin = ([string]$Record.archive_sha256).ToLowerInvariant()
    $treePin = ([string]$Record.install_tree_sha256).ToLowerInvariant()
    if ($archivePin -cnotmatch $script:WinsAndroidSha256Pattern -or
        $treePin -cnotmatch $script:WinsAndroidSha256Pattern) {
        throw "Android $Tool custody pins must be exact lowercase SHA-256 values."
    }
    if ($archivePin -ceq $treePin) {
        throw "Android $Tool archive and installed-tree custody pins must be independently derived."
    }
}

function Assert-WinsAndroidToolchainCustodyManifestPreflight {
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$Platform
    )

    # ANDROID_WINDOWS_CUSTODY_PREFLIGHT_NO_CANDIDATE_EXECUTION
    $manifest = ConvertFrom-WinsAndroidCustodyManifest -ManifestPath $ManifestPath
    $platformRecord = $manifest.platforms.$Platform
    if (-not $platformRecord) {
        throw "Android toolchain custody manifest has no reviewed platform record for $Platform."
    }
    if ($platformRecord.status -cne 'pinned') {
        throw "Android toolchain custody OWNER INPUT REQUIRED for ${Platform}: $($platformRecord.owner_action)"
    }
    foreach ($tool in @('python', 'flutter', 'jdk')) {
        $record = $platformRecord.tools.$tool
        if (-not $record) {
            throw "Android toolchain custody manifest has no $tool record for $Platform."
        }
        Assert-WinsAndroidToolchainCustodyRecordComplete `
            -Record $record -Platform $Platform -Tool $tool
    }
}

function Read-WinsAndroidToolchainCustodyRecord {
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$Platform,
        [Parameter(Mandatory)][ValidateSet('python', 'flutter', 'jdk')][string]$Tool
    )

    $manifest = ConvertFrom-WinsAndroidCustodyManifest -ManifestPath $ManifestPath
    $platformRecord = $manifest.platforms.$Platform
    if (-not $platformRecord) {
        throw "Android toolchain custody manifest has no reviewed platform record for $Platform."
    }
    if ($platformRecord.status -cne 'pinned') {
        throw "Android toolchain custody OWNER INPUT REQUIRED for ${Platform}: $($platformRecord.owner_action)"
    }
    $record = $platformRecord.tools.$Tool
    if (-not $record) {
        throw "Android toolchain custody manifest has no $Tool record for $Platform."
    }
    Assert-WinsAndroidToolchainCustodyRecordComplete `
        -Record $record -Platform $Platform -Tool $Tool
    return $record
}

function Assert-WinsAndroidToolchainRuntimePins {
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string]$RuntimeVersion,
        [Parameter(Mandatory)][AllowEmptyString()][string]$RuntimeRevision,
        [Parameter(Mandatory)][string]$RuntimeVendor,
        [Parameter(Mandatory)][string]$RuntimeArchitecture
    )

    if ($RuntimeVersion -cne [string]$Record.version) {
        throw "Android $Tool runtime version does not match its complete custody pin."
    }
    if ($RuntimeRevision -cne [string]$Record.revision) {
        throw "Android $Tool runtime revision does not match its complete custody pin."
    }
    if ($RuntimeVendor -cne [string]$Record.vendor) {
        throw "Android $Tool runtime vendor does not match its complete custody pin."
    }
    if ($RuntimeArchitecture -cne [string]$Record.architecture) {
        throw "Android $Tool runtime architecture does not match its complete custody pin."
    }
}

function Assert-WinsAndroidToolchainCustody {
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$Platform,
        [Parameter(Mandatory)][ValidateSet('python', 'flutter', 'jdk')][string]$Tool,
        [Parameter(Mandatory)][string]$Root
    )

    Assert-WinsAndroidWindowsManifestAndTreeTransaction -ManifestPath $ManifestPath -Root $Root
    $record = Read-WinsAndroidToolchainCustodyRecord `
        -ManifestPath $ManifestPath -Platform $Platform -Tool $Tool
    $archiveVariable = [string]$record.archive_environment
    $archivePath = [Environment]::GetEnvironmentVariable($archiveVariable, 'Process')
    if ([string]::IsNullOrWhiteSpace($archivePath)) {
        throw "Android $Tool custody requires owner-provided source archive bytes via $archiveVariable."
    }
    $archivePath = [IO.Path]::GetFullPath($archivePath)
    $repository = [IO.Path]::GetFullPath($RepoRoot).TrimEnd('\', '/')
    if ($archivePath.Equals($repository, [StringComparison]::OrdinalIgnoreCase) -or
        $archivePath.StartsWith(($repository + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Android $Tool custody source archive must remain outside the repository."
    }
    $archiveSha256 = Get-WinsAndroidCustodyFileSha256 `
        -Path $archivePath -Description "Android $Tool source archive"
    if ($archiveSha256 -cne [string]$record.archive_sha256) {
        throw "Android $Tool source archive SHA-256 does not match its independent custody pin."
    }
    $treeSha256 = Get-WinsAndroidToolchainTreeSha256 `
        -Root $Root -Description "Android $Tool installed toolchain"
    if ($treeSha256 -cne [string]$record.install_tree_sha256) {
        throw "Android $Tool installed-tree SHA-256 does not match its independent custody pin."
    }
    # ANDROID_WINDOWS_CUSTODY_TREE_AUTHENTICATED_BEFORE_RUNTIME_IDENTITY
    return [pscustomobject]@{
        Tool = $Tool
        PinVersion = [string]$record.version
        PinRevision = [string]$record.revision
        PinVendor = [string]$record.vendor
        PinArchitecture = [string]$record.architecture
        Record = $record
        ArchiveSha256 = $archiveSha256
        InstallTreeSha256 = $treeSha256
    }
}
