[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Artifact,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedArtifactSha256,
    [Parameter(Mandatory)][string]$PayloadManifest,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPayloadManifestSha256,
    [Parameter(Mandatory)][string]$PayloadRoot,
    [Parameter(Mandatory)][string]$ReleaseInputIndex,
    [Parameter(Mandatory)][string]$BuildReceipt,
    [Parameter(Mandatory)][string]$CandidateManifest,
    [Parameter(Mandatory)][string]$PreviousArtifact,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPreviousArtifactSha256,
    [Parameter(Mandatory)][string]$PreviousPayloadManifest,
    [Parameter(Mandatory)][string]$PreviousReleaseRecord,
    [Parameter(Mandatory)][string]$CredentialStore,
    [Parameter(Mandatory)][string]$Gazetteer,
    [ValidateRange(600, 3600)][int]$WatchdogDeadlineSeconds = 1200
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# OWNER-BLOCKED (R23 W1-07, Arbiter ruling option 1). Below, this collector
# resolves python.exe through PATH and runs tools\release_dependency_freeze.py
# from the repository under elevation to verify the release input index and
# the build receipt. That worker cannot do so on Windows: it imports the
# Unix-only fcntl module and refuses every launch except the macOS parent
# tools/run_release_dependency_freeze.sh, so with a genuine interpreter the
# verification can never pass and only a substituted python.exe could get
# past it. No Windows-verifiable release input receipt route exists yet; the
# signed remote-attested route is the planned fix and replaces this refusal.
# It runs first: no Python is resolved or run, and nothing is created, locked
# or scheduled, before it.
throw ('OWNER-BLOCKED: the Windows lab physical collector is disabled. No ' +
    'Windows-verifiable release input receipt route exists yet (the dependency-freeze ' +
    'worker runs only through tools/run_release_dependency_freeze.sh on the macOS release ' +
    'host); the signed remote-attested route is the planned fix. No Python was resolved or run.')
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $RepoRoot
$RunId = [Guid]::NewGuid().ToString('D')
$EvidenceBase = Join-Path $env:ProgramData 'WinsVPN\LabEvidence'
$RunRoot = Join-Path $EvidenceBase $RunId
$PrivateRoot = Join-Path $RunRoot 'private'
$ReceiptRoot = Join-Path $RunRoot 'receipts'
$ArtifactRoot = Join-Path $RunRoot 'artifacts'
$HelperRoot = Join-Path $RunRoot 'helpers'
$InputRoot = Join-Path $PrivateRoot 'inputs'
$TaskName = "WinsVPN Lab Watchdog $RunId"
$SystemPowerShell = Join-Path $env:SystemRoot `
    'System32\WindowsPowerShell\v1.0\powershell.exe'
$SystemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$AdministratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$CollectorFiles = @(
    'tools/windows_lab_physical_collector.ps1',
    'tools/windows_lab_interactive_worker.ps1',
    'tools/windows_secure_state_helpers.ps1',
    'tools/windows_lab_safe_watchdog.ps1',
    'tools/windows_lab_fixed_ui.ps1',
    'tools/windows_lab_matrix_evidence.py',
    'tools/windows_lab_bundle_index.schema.json',
    'tools/windows_lab_machine_evidence.schema.json',
    'tools/windows_spain_live_observation.py',
    'tools/windows_core_live_observation.py'
)

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-AdministratorInteractive {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        ) -or -not [Environment]::UserInteractive) {
        throw 'The Windows physical collector requires an elevated interactive session.'
    }
}

function Assert-NoReparsePath {
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    $current = $root
    foreach ($part in @($full.Substring($root.Length) -split '[\\/]' |
            Where-Object { $_ })) {
        if ($part -eq '..') { throw 'Parent traversal is forbidden.' }
        $current = Join-Path $current $part
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Collector path contains a reparse point: $current"
        }
    }
}

function New-LockedDirectory {
    param([Parameter(Mandatory)][string]$Path)
    New-Item -ItemType Directory -Path $Path -ErrorAction Stop | Out-Null
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($SystemSid, $AdministratorsSid)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    $acl.SetOwner($AdministratorsSid)
    Set-Acl -LiteralPath $Path -AclObject $acl
    Assert-NoReparsePath $Path
}

function Assert-LockedAcl {
    param([Parameter(Mandatory)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { throw "ACL inheritance remains enabled: $Path" }
    $actual = @($acl.Access | ForEach-Object {
        $_.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    } | Sort-Object -Unique)
    $expected = @($SystemSid.Value, $AdministratorsSid.Value) | Sort-Object
    if (($actual -join '|') -cne ($expected -join '|')) {
        throw "Unexpected release-evidence ACL: $Path"
    }
}

function Protect-LockedFile {
    param([Parameter(Mandatory)][string]$Path)
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($SystemSid, $AdministratorsSid)) {
        [void]$acl.AddAccessRule(
            [Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow
            )
        )
    }
    $acl.SetOwner($AdministratorsSid)
    Set-Acl -LiteralPath $Path -AclObject $acl
    Assert-LockedAcl $Path
}

function Copy-SecureFile {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [ValidateRange(1, 536870912)][long]$MaximumBytes = 536870912
    )
    Assert-NoReparsePath $Source
    $sourceStream = [IO.File]::Open(
        $Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None
    )
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        if ($sourceStream.Length -lt 1 -or $sourceStream.Length -gt $MaximumBytes) {
            throw "Secure source has invalid size: $Source"
        }
        $destinationStream = [IO.File]::Open(
            $Destination,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $buffer = [byte[]]::new(1048576)
            while (($count = $sourceStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                [void]$algorithm.TransformBlock($buffer, 0, $count, $null, 0)
                $destinationStream.Write($buffer, 0, $count)
            }
            [void]$algorithm.TransformFinalBlock([byte[]]::new(0), 0, 0)
            $destinationStream.Flush($true)
        } finally { $destinationStream.Dispose() }
    } finally { $sourceStream.Dispose() }
    $sourceSha = ([BitConverter]::ToString($algorithm.Hash)).Replace(
        '-', ''
    ).ToLowerInvariant()
    $algorithm.Dispose()
    if ($sourceSha -cne (Get-Sha256 $Destination)) {
        throw "Secure copy hash mismatch: $Source"
    }
}

function Write-NewJson {
    param([string]$Path, [object]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Value | ConvertTo-Json -Depth 16 -Compress) + [Environment]::NewLine
    )
    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None
    )
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Get-CompositeClosure {
    param([string[]]$RelativePaths)
    $algorithm = [Security.Cryptography.IncrementalHash]::CreateHash(
        [Security.Cryptography.HashAlgorithmName]::SHA256
    )
    try {
        foreach ($relative in $RelativePaths) {
            $absolute = Join-Path $RepoRoot $relative
            Assert-NoReparsePath $absolute
            $algorithm.AppendData([Text.Encoding]::UTF8.GetBytes("$relative`0"))
            $stream = [IO.File]::Open(
                $absolute, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                [IO.FileShare]::None
            )
            try {
                $buffer = [byte[]]::new(1048576)
                while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $algorithm.AppendData($buffer, 0, $count)
                }
            } finally { $stream.Dispose() }
            $algorithm.AppendData([byte[]]@(0))
        }
        ([BitConverter]::ToString($algorithm.GetHashAndReset())).Replace(
            '-', ''
        ).ToLowerInvariant()
    } finally { $algorithm.Dispose() }
}

function Get-CertificateSha256 {
    param([Parameter(Mandatory)]$Certificate)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString(
            $algorithm.ComputeHash([byte[]]$Certificate.RawData)
        )).Replace('-', '').ToLowerInvariant()
    } finally { $algorithm.Dispose() }
}

function Read-JsonSecure {
    param([Parameter(Mandatory)][string]$Path)
    Assert-NoReparsePath $Path
    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None
    )
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt 16777216) {
            throw "Secure JSON input size is invalid: $Path"
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -le 0) { throw "Secure JSON input changed: $Path" }
            $offset += $count
        }
    } finally { $stream.Dispose() }
    [Text.UTF8Encoding]::new($false, $true).GetString($bytes) |
        ConvertFrom-Json
}

function Wait-JsonSecure {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 60)][int]$TimeoutSeconds = 30
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            try {
                return Read-JsonSecure $Path
            } catch {
                $exception = $_.Exception
                $locked = $exception -is [IO.IOException] -or
                    $exception.InnerException -is [IO.IOException]
                if (-not $locked) { throw }
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Secure JSON input was not atomically readable in time: $Path"
}

function Assert-PreviousLabAuthorization {
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][string]$ArtifactPath,
        [Parameter(Mandatory)][string]$PayloadManifestPath
    )
    if ($Record.schema_version -ne 1 -or $Record.contract -cne
        'winsvpn-windows-lab-previous-release-record-v1' -or
        $Record.evidence_class -cne 'nonpublishable_lab' -or
        $Record.lab_only -ne $true -or
        $Record.publication_authorized -ne $false -or
        $Record.public_release_gate_eligible -ne $false -or
        $Record.unsigned_local_candidate -ne $true -or
        [string]$Record.artifact_sha256 -cne (Get-Sha256 $ArtifactPath) -or
        [long]$Record.artifact_size_bytes -ne
            (Get-Item -LiteralPath $ArtifactPath).Length -or
        [string]$Record.payload_manifest_sha256 -cne
            (Get-Sha256 $PayloadManifestPath)) {
        throw 'Previous lab record does not bind the exact nonpublishable rollback artifact.'
    }
}

function Assert-ExactUnsignedLabArtifact {
    param([string]$Path, [string]$Label)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'NotSigned' -or $signature.SignerCertificate -or
        $signature.TimeStamperCertificate) {
        throw "$Label must be the exact unsigned, nonpublishable lab artifact."
    }
    $signature
}

Assert-AdministratorInteractive
foreach ($entry in @(
    $Artifact, $PayloadManifest, $PayloadRoot, $ReleaseInputIndex,
    $BuildReceipt, $CandidateManifest, $PreviousArtifact,
    $PreviousPayloadManifest,
    $PreviousReleaseRecord, $CredentialStore, $Gazetteer
)) {
    if (-not (Test-Path -LiteralPath $entry)) { throw "Required collector input missing: $entry" }
    Assert-NoReparsePath $entry
}
if (-not (Test-Path -LiteralPath $SystemPowerShell -PathType Leaf)) {
    throw 'Fixed System32 Windows PowerShell is unavailable.'
}

if (-not (Test-Path -LiteralPath $EvidenceBase -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $EvidenceBase | Out-Null
}
foreach ($directory in @($RunRoot, $PrivateRoot, $ReceiptRoot, $ArtifactRoot, $HelperRoot, $InputRoot)) {
    New-LockedDirectory $directory
    Assert-LockedAcl $directory
}

$closureSha = Get-CompositeClosure $CollectorFiles
$closureEntries = foreach ($relative in $CollectorFiles) {
    $source = Join-Path $RepoRoot $relative
    $name = [IO.Path]::GetFileName($source)
    $target = Join-Path $HelperRoot $name
    Copy-SecureFile $source $target 16777216
    [ordered]@{
        name = $name
        source_path = $relative.Replace('\', '/')
        sha256 = Get-Sha256 $target
        size_bytes = (Get-Item -LiteralPath $target).Length
    }
}
Write-NewJson (Join-Path $PrivateRoot 'collector-closure.json') ([ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-lab-collector-closure-v1'
    evidence_class = 'nonpublishable_lab'
    lab_only = $true
    publication_authorized = $false
    public_release_gate_eligible = $false
    unsigned_local_candidate = $true
    sha256 = $closureSha
    files = @($closureEntries)
})

$python = (Get-Command python.exe -ErrorAction Stop).Source
& $python (Join-Path $RepoRoot 'tools\release_dependency_freeze.py') `
    verify-index --repo $RepoRoot --index $ReleaseInputIndex | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Release input index verification failed.' }
& $python (Join-Path $RepoRoot 'tools\release_dependency_freeze.py') `
    verify-receipt --repo $RepoRoot --index $ReleaseInputIndex `
    --platform windows --receipt $BuildReceipt --artifact $Artifact | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Exact Windows build receipt verification failed.' }
$index = Get-Content -LiteralPath $ReleaseInputIndex -Raw | ConvertFrom-Json
$windowsRef = $index.platform_manifests.windows
$producerSha = (& $python -c @'
import pathlib,sys
sys.path.insert(0,'tools')
from public_release_live_smoke_common import producer_contract_hash
print(producer_contract_hash(pathlib.Path('.').resolve(),'tools/windows_public_release_live_smoke.ps1'))
'@).Trim()
if ($producerSha -notmatch '^[0-9a-f]{64}$') { throw 'Producer closure hash is invalid.' }

[void](Assert-ExactUnsignedLabArtifact $Artifact 'Exact candidate installer')
[void](Assert-ExactUnsignedLabArtifact $PreviousArtifact 'Previous rollback installer')
$candidateHash = Get-Sha256 $Artifact
$previousHash = Get-Sha256 $PreviousArtifact
if ($candidateHash -cne $ExpectedArtifactSha256.ToLowerInvariant() -or
    (Get-Sha256 $PayloadManifest) -cne
        $ExpectedPayloadManifestSha256.ToLowerInvariant() -or
    $previousHash -cne $ExpectedPreviousArtifactSha256.ToLowerInvariant()) {
    throw 'A lab artifact or payload manifest does not match its explicit SHA-256 pin.'
}
$previousRecord = Read-JsonSecure $PreviousReleaseRecord
Assert-PreviousLabAuthorization -Record $previousRecord `
    -ArtifactPath $PreviousArtifact -PayloadManifestPath $PreviousPayloadManifest
$previousPayloadDocument = Read-JsonSecure $PreviousPayloadManifest
if ((Get-Sha256 $PreviousPayloadManifest) -cne
        [string]$previousRecord.payload_manifest_sha256 -or
    [string]$previousPayloadDocument.installer.sha256 -cne $previousHash -or
    [long]$previousPayloadDocument.installer.size -ne
        (Get-Item -LiteralPath $PreviousArtifact).Length -or
    $previousPayloadDocument.signing.production_signed -ne $false -or
    $previousPayloadDocument.signing.every_loose_pe_verified -ne $false) {
    throw 'Previous rollback payload manifest is not exact and explicitly unsigned.'
}
$payloadDocument = Read-JsonSecure $PayloadManifest
if ($payloadDocument.schema_version -ne 3 -or
    [string]$payloadDocument.installer.sha256 -cne $candidateHash -or
    [long]$payloadDocument.installer.size -ne
        (Get-Item -LiteralPath $Artifact).Length -or
    $payloadDocument.signing.production_signed -ne $false -or
    $payloadDocument.signing.every_loose_pe_verified -ne $false -or
    $payloadDocument.signing.staged_xray_product_signed -ne $false -or
    $payloadDocument.signing.inno_setup_and_uninstaller_signed -ne $false -or
    @($payloadDocument.payload).Count -lt 1) {
    throw 'Exact lab candidate payload manifest is not explicitly unsigned and complete.'
}
$inputCopies = [ordered]@{}
foreach ($pair in @(
    @('candidate-installer.exe', $Artifact),
    @('candidate-payload-manifest.json', $PayloadManifest),
    @('release-input-index.json', $ReleaseInputIndex),
    @('build-receipt.json', $BuildReceipt),
    @('candidate-manifest.json', $CandidateManifest),
    @('previous-installer.exe', $PreviousArtifact),
    @('previous-payload-manifest.json', $PreviousPayloadManifest),
    @('previous-release-record.json', $PreviousReleaseRecord),
    @('credentials.dat', $CredentialStore),
    @('gazetteer.json', $Gazetteer)
)) {
    $target = Join-Path $InputRoot $pair[0]
    Copy-SecureFile $pair[1] $target
    $inputCopies[$pair[0]] = $target
}
$payloadSnapshotRoot = Join-Path $InputRoot 'payload-files'
New-LockedDirectory $payloadSnapshotRoot
$snapshotEntries = [Collections.Generic.List[object]]::new()
$seenPayloadHashes = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal
)
$payloadRootFull = [IO.Path]::GetFullPath($PayloadRoot).TrimEnd('\') + '\'
foreach ($entry in @($payloadDocument.payload)) {
    $relative = ([string]$entry.path).Replace('/', '\')
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|\\)\.\.(\\|$)' -or
        [string]$entry.sha256 -notmatch '^[0-9a-f]{64}$' -or
        [long]$entry.size -lt 1) {
        throw 'Payload manifest contains an unsafe or invalid entry.'
    }
    $source = [IO.Path]::GetFullPath((Join-Path $PayloadRoot $relative))
    if (-not $source.StartsWith($payloadRootFull, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $source -PathType Leaf) -or
        (Get-Item -LiteralPath $source).Length -ne [long]$entry.size) {
        throw "Payload source is absent or escaped the fixed payload root: $relative"
    }
    $snapshotName = [string]$entry.sha256 + '.bin'
    $snapshot = Join-Path $payloadSnapshotRoot $snapshotName
    if ($seenPayloadHashes.Add([string]$entry.sha256)) {
        Copy-SecureFile $source $snapshot
    }
    if ((Get-Sha256 $snapshot) -cne [string]$entry.sha256) {
        throw "Payload snapshot hash mismatch: $relative"
    }
    $snapshotEntries.Add([ordered]@{
        path = ([string]$entry.path).Replace('\', '/')
        size = [long]$entry.size
        sha256 = [string]$entry.sha256
        snapshot_name = $snapshotName
    })
}
Write-NewJson (Join-Path $PrivateRoot 'payload-snapshot-index.json') ([ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-lab-payload-snapshot-v1'
    manifest_sha256 = Get-Sha256 (Join-Path $InputRoot 'candidate-payload-manifest.json')
    entries = @($snapshotEntries)
})

Copy-SecureFile (Join-Path $InputRoot 'candidate-installer.exe') `
    (Join-Path $ArtifactRoot 'WinsVPN-Setup.exe')
Copy-SecureFile (Join-Path $InputRoot 'previous-installer.exe') `
    (Join-Path $ArtifactRoot 'previous-installer.exe')
Copy-SecureFile (Join-Path $InputRoot 'previous-payload-manifest.json') `
    (Join-Path $ArtifactRoot 'previous-installer.payload-manifest.json')
Copy-SecureFile (Join-Path $InputRoot 'candidate-payload-manifest.json') `
    (Join-Path $ArtifactRoot 'WinsVPN-Setup.exe.payload-manifest.json')
Copy-SecureFile (Join-Path $InputRoot 'candidate-manifest.json') `
    (Join-Path $ArtifactRoot 'candidate-manifest.json')
$sanitizedPreviousRecord = [ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-lab-previous-release-record-v1'
    release_identity = [string]$previousRecord.release_identity
    artifact_sha256 = $previousHash
    artifact_size_bytes = [long](Get-Item -LiteralPath $PreviousArtifact).Length
    payload_manifest_sha256 = [string]$previousRecord.payload_manifest_sha256
    evidence_class = 'nonpublishable_lab'
    lab_only = $true
    publication_authorized = $false
    public_release_gate_eligible = $false
    unsigned_local_candidate = $true
}
Write-NewJson (Join-Path $ArtifactRoot 'previous-release-record.json') `
    $sanitizedPreviousRecord

$context = [ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-lab-collector-context-v1'
    run_id = $RunId
    evidence_class = 'nonpublishable_lab'
    lab_only = $true
    publication_authorized = $false
    public_release_gate_eligible = $false
    unsigned_local_candidate = $true
    collector_closure_sha256 = $closureSha
    release_input_index_sha256 = Get-Sha256 $ReleaseInputIndex
    platform_manifest_sha256 = [string]$windowsRef.sha256
    artifact_input_fingerprint_sha256 = [string]$windowsRef.artifact_input_fingerprint_sha256
    build_receipt_sha256 = Get-Sha256 $BuildReceipt
    producer_contract_sha256 = $producerSha
    artifact_sha256 = $candidateHash
    artifact_size_bytes = (Get-Item -LiteralPath $Artifact).Length
    payload_manifest_sha256 = Get-Sha256 $PayloadManifest
    authenticode_status = 'NotSigned'
    previous_artifact_sha256 = $previousHash
    candidate_signer_certificate_sha256 = ''
    previous_signer_certificate_sha256 = ''
    next_sequence = 1
    created_at_utc = [DateTime]::UtcNow.ToString('o')
}
Write-NewJson (Join-Path $PrivateRoot 'context.json') $context

$worker = Join-Path $HelperRoot 'windows_lab_interactive_worker.ps1'
$taskRegistered = $false
try {
    & $SystemPowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass `
        -File $worker -RunId $RunId -Phase Prepare
    if ($LASTEXITCODE -ne 0) { throw 'Windows physical prepare phase failed.' }
    $runtimeContext = Read-JsonSecure `
        (Join-Path $PrivateRoot 'runtime-context.json')
    $arm = [ordered]@{
        schema_version = 1
        contract = 'winsvpn-windows-lab-watchdog-arm-v1'
        run_id = $RunId
        evidence_class = 'nonpublishable_lab'
        lab_only = $true
        publication_authorized = $false
        public_release_gate_eligible = $false
        unsigned_local_candidate = $true
        collector_closure_sha256 = $closureSha
        armed = $true
        step_nonce = [Guid]::NewGuid().ToString()
        sequence = [int]$runtimeContext.next_sequence
        armed_at_utc = [DateTime]::UtcNow.ToString('o')
    }
    Write-NewJson (Join-Path $PrivateRoot 'arm.json') $arm
    $watchdog = Join-Path $HelperRoot 'windows_lab_safe_watchdog.ps1'
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
        $watchdog + '" -RunId "' + $RunId +
        '" -CollectorClosureSha256 "' + $closureSha +
        '" -DeadlineSeconds ' + $WatchdogDeadlineSeconds
    if ($arguments -notmatch '^-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "[A-Za-z]:\\ProgramData\\WinsVPN\\LabEvidence\\[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\helpers\\windows_lab_safe_watchdog\.ps1" -RunId "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" -CollectorClosureSha256 "[0-9a-f]{64}" -DeadlineSeconds [0-9]{3,4}$') {
        throw 'Fixed watchdog command grammar changed unexpectedly.'
    }
    $action = New-ScheduledTaskAction -Execute $SystemPowerShell -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
        -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit `
        ([TimeSpan]::FromSeconds($WatchdogDeadlineSeconds + 180)) `
        -DeleteExpiredTaskAfter ([TimeSpan]::FromMinutes(5))
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(2)
    $trigger.EndBoundary = (Get-Date).AddSeconds(
        $WatchdogDeadlineSeconds + 120
    ).ToString('s')
    Register-ScheduledTask -TaskName $TaskName -Action $action `
        -Principal $principal -Settings $settings -Trigger $trigger | Out-Null
    $taskRegistered = $true
    Start-ScheduledTask -TaskName $TaskName
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 200
        $state = [string](Get-ScheduledTask -TaskName $TaskName).State
    } while ($state -ne 'Running' -and [DateTime]::UtcNow -lt $deadline)
    if ($state -ne 'Running') { throw 'Fixed SYSTEM watchdog failed to arm.' }
    $readyPath = Join-Path $PrivateRoot 'watchdog-ready.json'
    $watchdogReady = Wait-JsonSecure $readyPath -TimeoutSeconds 30
    if ($watchdogReady.contract -cne
            'winsvpn-windows-lab-watchdog-ready-v1' -or
        $watchdogReady.run_id -cne $RunId -or
        $watchdogReady.evidence_class -cne 'nonpublishable_lab' -or
        $watchdogReady.lab_only -ne $true -or
        $watchdogReady.publication_authorized -ne $false -or
        $watchdogReady.public_release_gate_eligible -ne $false -or
        $watchdogReady.unsigned_local_candidate -ne $true -or
        $watchdogReady.collector_closure_sha256 -cne $closureSha) {
        throw 'Fixed SYSTEM watchdog readiness binding is invalid.'
    }

    & $SystemPowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass `
        -File $worker -RunId $RunId -Phase Execute
    if ($LASTEXITCODE -ne 0) { throw 'Windows physical execute phase failed.' }
    $watchdogReceipt = Join-Path $ReceiptRoot 'watchdog.json'
    $waitDeadline = [DateTime]::UtcNow.AddSeconds($WatchdogDeadlineSeconds + 60)
    while (-not (Test-Path -LiteralPath $watchdogReceipt -PathType Leaf) -and
        [DateTime]::UtcNow -lt $waitDeadline) { Start-Sleep -Milliseconds 250 }
    if (-not (Test-Path -LiteralPath $watchdogReceipt -PathType Leaf)) {
        throw 'Fixed watchdog receipt was not produced.'
    }
    $watchdogResult = Get-Content -LiteralPath $watchdogReceipt -Raw |
        ConvertFrom-Json
    if ($watchdogResult.pass -ne $true -or
        $watchdogResult.evidence_class -cne 'nonpublishable_lab' -or
        $watchdogResult.lab_only -ne $true -or
        $watchdogResult.publication_authorized -ne $false -or
        $watchdogResult.public_release_gate_eligible -ne $false -or
        $watchdogResult.unsigned_local_candidate -ne $true -or
        $watchdogResult.normal_teardown_proven -ne $true -or
        $watchdogResult.fail_safe_triggered -ne $false) {
        throw 'Windows lab run used emergency cleanup or lacked natural teardown.'
    }
    & $SystemPowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass `
        -File $worker -RunId $RunId -Phase Finalize
    if ($LASTEXITCODE -ne 0) { throw 'Windows physical finalize phase failed.' }
} finally {
    if ($taskRegistered) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
}

$machinePath = Join-Path $ReceiptRoot 'machine-evidence.json'
if (-not (Test-Path -LiteralPath $machinePath -PathType Leaf)) {
    throw 'Physical collector did not produce machine evidence.'
}
$indexedFiles = @(
    Get-ChildItem -LiteralPath $ReceiptRoot -File
    Get-ChildItem -LiteralPath $ArtifactRoot -File
)
$entries = foreach ($file in $indexedFiles) {
    $json = if ($file.Extension -eq '.json') {
        try { Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json }
        catch { $null }
    } else { $null }
    $isBoundReceipt = $json -and $json.contract -and $json.run_id -and
        $json.sequence -and $json.step_nonce -and
        $json.collector_closure_sha256
    $contract = if ($isBoundReceipt) { [string]$json.contract } else { '' }
    $sequence = if ($json -and $json.sequence) { [int]$json.sequence } else { 0 }
    $nonce = if ($json -and $json.step_nonce) {
        [string]$json.step_nonce
    } else { [Guid]::NewGuid().ToString() }
    [ordered]@{
        path = $file.FullName.Substring($RunRoot.Length).TrimStart('\').Replace('\', '/')
        sha256 = Get-Sha256 $file.FullName
        size_bytes = [long]$file.Length
        contract = $contract
        sequence = $sequence
        step_nonce = $nonce
    }
}
$usedSequences = @($entries | Where-Object sequence -gt 0 |
    Select-Object -ExpandProperty sequence)
$next = if ($usedSequences.Count) { ($usedSequences | Measure-Object -Maximum).Maximum + 1 } else { 1 }
foreach ($entry in $entries | Where-Object sequence -eq 0) {
    $entry.sequence = $next
    ++$next
}
$entries = @($entries | Sort-Object sequence)
if (@($entries | Select-Object -ExpandProperty sequence) -join '|' -cne
    @(1..$entries.Count) -join '|') {
    throw 'Physical evidence receipt sequence is not consecutive.'
}
$machineRelative = $machinePath.Substring($RunRoot.Length).TrimStart('\').Replace('\', '/')
$bundleIndex = [ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-lab-bundle-index-v1'
    run_id = $RunId
    created_at_utc = [DateTime]::UtcNow.ToString('o')
    secret_material_redacted = $true
    evidence_class = 'nonpublishable_lab'
    lab_only = $true
    publication_authorized = $false
    public_release_gate_eligible = $false
    unsigned_local_candidate = $true
    collector_closure_sha256 = $closureSha
    release_input_index_sha256 = [string]$context.release_input_index_sha256
    platform_manifest_sha256 = [string]$context.platform_manifest_sha256
    artifact_input_fingerprint_sha256 = [string]$context.artifact_input_fingerprint_sha256
    build_receipt_sha256 = [string]$context.build_receipt_sha256
    producer_contract_sha256 = [string]$context.producer_contract_sha256
    artifact_sha256 = $candidateHash
    machine_evidence_path = $machineRelative
    machine_evidence_sha256 = Get-Sha256 $machinePath
    entries = $entries
    sealed = $true
}
$indexPath = Join-Path $RunRoot 'bundle-index.json'
Write-NewJson $indexPath $bundleIndex
$bundleIndexSha256 = Get-Sha256 $indexPath
foreach ($path in @($ReceiptRoot, $ArtifactRoot, $HelperRoot, $PrivateRoot, $RunRoot)) {
    Assert-LockedAcl $path
}
Get-ChildItem -LiteralPath $RunRoot -Recurse -File | ForEach-Object {
    Protect-LockedFile $_.FullName
    $_.IsReadOnly = $true
}
Write-Output "WINDOWS_LAB_PHYSICAL_COLLECTOR=PASS run_id=$RunId"
Write-Output "WINDOWS_LAB_BUNDLE_INDEX=$indexPath"
Write-Output "WINDOWS_LAB_BUNDLE_INDEX_SHA256=$bundleIndexSha256"
