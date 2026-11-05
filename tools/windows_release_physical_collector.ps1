[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Artifact,
    [Parameter(Mandatory)][string]$PayloadManifest,
    [Parameter(Mandatory)][string]$PayloadRoot,
    [Parameter(Mandatory)][string]$ReleaseInputIndex,
    [Parameter(Mandatory)][string]$BuildReceipt,
    [Parameter(Mandatory)][string]$CandidateManifest,
    [Parameter(Mandatory)][string]$PreviousArtifact,
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
throw ('OWNER-BLOCKED: the Windows release physical collector is disabled. No ' +
    'Windows-verifiable release input receipt route exists yet (the dependency-freeze ' +
    'worker runs only through tools/run_release_dependency_freeze.sh on the macOS release ' +
    'host); the signed remote-attested route is the planned fix. No Python was resolved or run.')
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $RepoRoot
$RunId = [Guid]::NewGuid().ToString('D')
$EvidenceBase = Join-Path $env:ProgramData 'WinsVPN\ReleaseEvidence'
$RunRoot = Join-Path $EvidenceBase $RunId
$PrivateRoot = Join-Path $RunRoot 'private'
$ReceiptRoot = Join-Path $RunRoot 'receipts'
$ArtifactRoot = Join-Path $RunRoot 'artifacts'
$HelperRoot = Join-Path $RunRoot 'helpers'
$InputRoot = Join-Path $PrivateRoot 'inputs'
$TaskName = "WinsVPN Release Watchdog $RunId"
$SystemPowerShell = Join-Path $env:SystemRoot `
    'System32\WindowsPowerShell\v1.0\powershell.exe'
$SystemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$AdministratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$OpenReparsePoint = [IO.FileOptions]0x00200000
$PeMachineX64 = 0x8664
$PeMachineArm64 = 0xAA64
$MaxJsonBytes = 16777216
$MaxIndexedFiles = 512
$ReparseAttribute = [uint32]0x400
$CollectorFiles = @(
    'tools/windows_release_physical_collector.ps1',
    'tools/windows_release_interactive_worker.ps1',
    'tools/windows_secure_state_helpers.ps1',
    'tools/windows_release_safe_watchdog.ps1',
    'tools/windows_release_fixed_ui.ps1',
    'tools/windows_release_matrix_evidence.py',
    'tools/windows_release_bundle_index.schema.json',
    'tools/windows_release_machine_evidence.schema.json',
    'tools/windows_spain_live_observation.py',
    'tools/windows_core_live_observation.py'
)

function Assert-OpenedFileIdentity {
    param(
        [Parameter(Mandatory)][IO.FileStream]$Stream,
        [Parameter(Mandatory)][string]$Path
    )
    if (-not ('WinsVpnByHandleInfo' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WinsVpnByHandleInfo {
  [StructLayout(LayoutKind.Sequential)]
  public struct BY_HANDLE_FILE_INFORMATION {
    public uint dwFileAttributes;
    public uint ftCreationTimeLow;
    public uint ftCreationTimeHigh;
    public uint ftLastAccessTimeLow;
    public uint ftLastAccessTimeHigh;
    public uint ftLastWriteTimeLow;
    public uint ftLastWriteTimeHigh;
    public uint dwVolumeSerialNumber;
    public uint nFileSizeHigh;
    public uint nFileSizeLow;
    public uint nNumberOfLinks;
    public uint nFileIndexHigh;
    public uint nFileIndexLow;
  }
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool GetFileInformationByHandle(
      IntPtr handle, out BY_HANDLE_FILE_INFORMATION info);
}
'@
    }
    $info = New-Object WinsVpnByHandleInfo+BY_HANDLE_FILE_INFORMATION
    $handle = $Stream.SafeFileHandle.DangerousGetHandle()
    if (-not [WinsVpnByHandleInfo]::GetFileInformationByHandle(
            $handle, [ref]$info
        )) {
        throw "Collector handle identity is unavailable: $Path"
    }
    if (($info.dwFileAttributes -band $ReparseAttribute) -ne 0) {
        throw "Collector descriptor opened a reparse point: $Path"
    }
    if ($info.nNumberOfLinks -ne 1) {
        throw "Collector path is a hardlink substitution: $Path"
    }
}

function Open-ExclusiveFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][IO.FileMode]$Mode,
        [Parameter(Mandatory)][IO.FileAccess]$Access
    )
    if ($Mode -eq [IO.FileMode]::CreateNew) {
        Assert-NoReparsePath ([IO.Path]::GetDirectoryName((
            [IO.Path]::GetFullPath($Path)
        )))
    } else {
        Assert-NoReparsePath $Path
    }
    $stream = [IO.FileStream]::new(
        $Path, $Mode, $Access, [IO.FileShare]::None, 1048576, $OpenReparsePoint
    )
    try {
        Assert-OpenedFileIdentity $stream $Path
        if ($Mode -ne [IO.FileMode]::CreateNew) {
            $item = Get-Item -LiteralPath $Path -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Collector descriptor opened a reparse point: $Path"
            }
        }
    } catch {
        $stream.Dispose()
        throw
    }
    $stream
}

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    $stream = Open-ExclusiveFile $Path ([IO.FileMode]::Open) ([IO.FileAccess]::Read)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt 536870912) {
            throw "Collector hash input size is unbounded or empty: $Path"
        }
        $buffer = [byte[]]::new(1048576)
        while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            [void]$algorithm.TransformBlock($buffer, 0, $count, $null, 0)
        }
        [void]$algorithm.TransformFinalBlock([byte[]]::new(0), 0, 0)
        ([BitConverter]::ToString($algorithm.Hash)).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

function Get-PeArchitecture {
    param([Parameter(Mandatory)][string]$Path)
    $stream = Open-ExclusiveFile $Path ([IO.FileMode]::Open) ([IO.FileAccess]::Read)
    try {
        if ($stream.Length -lt 64) { throw "PE image is truncated: $Path" }
        $dos = [byte[]]::new(64)
        $read = 0
        while ($read -lt 64) {
            $count = $stream.Read($dos, $read, 64 - $read)
            if ($count -le 0) { throw "PE image changed while reading: $Path" }
            $read += $count
        }
        if ([Text.Encoding]::ASCII.GetString($dos, 0, 2) -cne 'MZ') {
            throw "File is not a PE image: $Path"
        }
        $pe = [BitConverter]::ToInt32($dos, 0x3C)
        if ($pe -lt 64 -or $pe -gt 1048576 -or ($pe + 264) -gt $stream.Length) {
            throw "PE header is truncated: $Path"
        }
        $need = $pe + 264
        [void]$stream.Seek(0, [IO.SeekOrigin]::Begin)
        $header = [byte[]]::new($need)
        $offset = 0
        while ($offset -lt $header.Length) {
            $count = $stream.Read($header, $offset, $header.Length - $offset)
            if ($count -le 0) { throw "PE image changed while reading: $Path" }
            $offset += $count
        }
        if ([Text.Encoding]::ASCII.GetString($header, $pe, 4) -cne "PE`0`0") {
            throw "File is not a PE32+ image: $Path"
        }
        $machine = [BitConverter]::ToUInt16($header, $pe + 4)
        $optional = $pe + 24
        $magic = [BitConverter]::ToUInt16($header, $optional)
        $name = switch ($machine) {
            $PeMachineX64 { 'x64' }
            $PeMachineArm64 { 'arm64' }
            default { $null }
        }
        if ($null -eq $name -or $magic -ne 0x20B) {
            throw "File is not PE32+ x64 or arm64: $Path"
        }
        $directoryBase = $optional + 112
        $certOffset = [BitConverter]::ToInt32($header, $directoryBase + 32)
        $certSize = [BitConverter]::ToInt32($header, $directoryBase + 36)
        if ($certOffset -lt 1 -or $certSize -lt 8 -or
            ($certOffset + $certSize) -gt $stream.Length) {
            throw "PE image lacks an Authenticode certificate table: $Path"
        }
        [ordered]@{
            Name = $name
            Machine = [int]$machine
        }
    } finally { $stream.Dispose() }
}

function Get-NativeWindowsArchitecture {
    if (-not [string]::IsNullOrEmpty(
            [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
        )) {
        throw 'Windows physical collector must not run under WOW64.'
    }
    $osArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $processArch = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    if ($processArch -cne $osArch) {
        throw 'Windows physical collector must not run under WOW64.'
    }
    switch ($osArch) {
        'X64' { 'x64' }
        'Arm64' { 'arm64' }
        default { throw "Unsupported Windows OS architecture: $osArch" }
    }
}

function Get-ReceiptProperty {
    param(
        [Parameter(Mandatory)]$Receipt,
        [Parameter(Mandatory)][string]$Name
    )
    if ($Receipt -is [Collections.IDictionary]) {
        if (-not $Receipt.Contains($Name)) {
            throw "Physical receipt omitted $Name."
        }
        return $Receipt[$Name]
    }
    $property = $Receipt.PSObject.Properties[$Name]
    if (-not $property) {
        throw "Physical receipt omitted $Name."
    }
    $property.Value
}

function Assert-ArchitectureBinding {
    param($Binding)
    if ($null -eq $Binding) {
        throw 'Physical receipt omitted architecture binding.'
    }
    try {
        $architecture = [string](Get-ReceiptProperty $Binding 'architecture')
        $native = [string](Get-ReceiptProperty $Binding 'native_architecture')
        $osArchitecture = [string](Get-ReceiptProperty $Binding 'os_architecture')
        $peMachine = Get-ReceiptProperty $Binding 'pe_machine'
        $wow64 = Get-ReceiptProperty $Binding 'process_wow64'
    } catch {
        throw 'Physical receipt omitted architecture binding.'
    }
    if ([string]::IsNullOrEmpty($architecture) -or
        [string]::IsNullOrEmpty($native) -or
        [string]::IsNullOrEmpty($osArchitecture) -or
        $null -eq $peMachine) {
        throw 'Physical receipt omitted architecture binding.'
    }
    if ($architecture -cne 'x64' -and $architecture -cne 'arm64') {
        throw "Unsupported physical receipt PE architecture: $architecture"
    }
    $expectedMachine = if ($architecture -ceq 'x64') { $PeMachineX64 } else {
        $PeMachineArm64
    }
    $expectedOs = if ($architecture -ceq 'x64') { 'X64' } else { 'Arm64' }
    if ($native -cne $architecture -or
        $osArchitecture -cne $expectedOs -or
        [int]$peMachine -ne [int]$expectedMachine -or
        $wow64 -ne $false) {
        throw 'Physical receipt architecture is mixed, WOW64, omitted, or unsupported.'
    }
    if ($architecture -cne $artifactArch -or
        $native -cne $artifactArch -or
        $osArchitecture -cne $osArchName -or
        [int]$peMachine -ne [int]$candidatePe.Machine) {
        throw 'Physical receipt PE machine does not match the native host and candidate.'
    }
}

function Assert-BoundPhysicalReceipt {
    param(
        [Parameter(Mandatory)]$Receipt,
        [Parameter(Mandatory)][string]$Contract,
        [Parameter(Mandatory)][string]$Label,
        [switch]$RequirePass
    )
    if ([string](Get-ReceiptProperty $Receipt 'contract') -cne $Contract) {
        throw "$Label contract is mixed or stale."
    }
    if ([string](Get-ReceiptProperty $Receipt 'run_id') -cne $RunId) {
        throw "$Label belongs to another live run."
    }
    if ([string](Get-ReceiptProperty $Receipt 'collector_closure_sha256') -cne
            $closureSha) {
        throw "$Label collector closure is stale."
    }
    if ([string](Get-ReceiptProperty $Receipt 'artifact_sha256') -cne
            $candidateHash) {
        throw "$Label is not bound to the exact candidate hash."
    }
    if ([string](Get-ReceiptProperty $Receipt 'release_identity') -cne
            $releaseIdentity) {
        throw "$Label release identity is stale or mixed."
    }
    if ((Get-ReceiptProperty $Receipt 'source_only') -ne $false) {
        throw "$Label is source-only; refusing non-physical substitution."
    }
    if ($RequirePass -and (Get-ReceiptProperty $Receipt 'passed') -ne $true) {
        throw "$Label did not pass; refusing a partial false green."
    }
    Assert-ArchitectureBinding $Receipt
}

function Assert-RequiredBoundReceipts {
    param([Parameter(Mandatory)][object[]]$Receipts)
    $byContract = @{}
    foreach ($receipt in @($Receipts)) {
        $contract = [string](Get-ReceiptProperty $receipt 'contract')
        if ($byContract.ContainsKey($contract)) {
            throw "Duplicate live evidence contract cannot be sealed: $contract"
        }
        $byContract[$contract] = $receipt
    }
    $required = [ordered]@{
        'winsvpn-windows-signature-receipt-v1' =
            'Physical signature receipt'
        'winsvpn-windows-install-receipt-v1' =
            'Physical install receipt'
        'winsvpn-windows-runtime-receipt-v1' =
            'Physical runtime receipt'
        'winsvpn-windows-uninstall-receipt-v1' =
            'Physical uninstall receipt'
        'winsvpn-windows-teardown-rollback-receipt-v1' =
            'Physical rollback receipt'
        'winsvpn-windows-winn-v3-receipt-v1' =
            'Physical Winn v3 primary receipt'
        'winsvpn-windows-winn-v1-awg-receipt-v1' =
            'Physical Winn v1 AWG receipt'
        'winsvpn-windows-winn-v1-xray-receipt-v1' =
            'Physical Winn v1 Xray fallback receipt'
        'winsvpn-windows-native-host-receipt-v1' =
            'Physical native-host receipt'
    }
    foreach ($contract in @($required.Keys)) {
        if (-not $byContract.ContainsKey($contract)) {
            throw "$($required[$contract]) is missing; refusing to seal partial evidence."
        }
        Assert-BoundPhysicalReceipt $byContract[$contract] $contract `
            $required[$contract] -RequirePass
    }
    $v3 = $byContract['winsvpn-windows-winn-v3-receipt-v1']
    $fallback = @(Get-ReceiptProperty $v3 'fallback_transports')
    if ([string](Get-ReceiptProperty $v3 'primary_transport') -cne 'winn_v3' -or
        (Get-ReceiptProperty $v3 'winn_v3_session_observed') -ne $true -or
        $fallback.Count -ne 2 -or
        [string]$fallback[0] -cne 'winn_v1_awg' -or
        [string]$fallback[1] -cne 'winn_v1_xray') {
        throw 'Physical Winn v3 primary receipt is source-only or has mixed fallback order.'
    }
    $awg = $byContract['winsvpn-windows-winn-v1-awg-receipt-v1']
    $xray = $byContract['winsvpn-windows-winn-v1-xray-receipt-v1']
    if ([string](Get-ReceiptProperty $awg 'transport') -cne 'winn_v1_awg' -or
        (Get-ReceiptProperty $awg 'observed') -ne $true) {
        throw 'Physical Winn v1 AWG receipt is source-only or unobserved.'
    }
    if ([string](Get-ReceiptProperty $xray 'transport') -cne 'winn_v1_xray' -or
        (Get-ReceiptProperty $xray 'observed') -ne $true) {
        throw 'Physical Winn v1 Xray fallback receipt is source-only or unobserved.'
    }
    if ([int](Get-ReceiptProperty $awg 'sequence') -ge
            [int](Get-ReceiptProperty $xray 'sequence')) {
        throw 'Physical Winn v1 Xray fallback is not after AWG.'
    }
    if ((Get-ReceiptProperty `
            $byContract['winsvpn-windows-native-host-receipt-v1'] `
            'native_host_observed') -ne $true) {
        throw 'Physical native-host receipt is source-only or unobserved.'
    }
    if ((Get-ReceiptProperty `
            $byContract['winsvpn-windows-uninstall-receipt-v1'] `
            'uninstalled') -ne $true) {
        throw 'Physical uninstall receipt is source-only or unobserved.'
    }
    if ((Get-ReceiptProperty `
            $byContract['winsvpn-windows-runtime-receipt-v1'] `
            'runtime_observed') -ne $true) {
        throw 'Physical runtime receipt is source-only or unobserved.'
    }
}

function Get-MachineGuidSha256 {
    $guid = [string](Get-ItemProperty -LiteralPath `
        'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
    if ($guid -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') {
        throw 'Windows MachineGuid is unavailable.'
    }
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString(
            $algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($guid.ToLowerInvariant()))
        )).Replace('-', '').ToLowerInvariant()
    } finally { $algorithm.Dispose() }
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
    $sourceStream = Open-ExclusiveFile $Source ([IO.FileMode]::Open) ([IO.FileAccess]::Read)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        if ($sourceStream.Length -lt 1 -or $sourceStream.Length -gt $MaximumBytes) {
            throw "Secure source has invalid size: $Source"
        }
        $destinationStream = Open-ExclusiveFile `
            $Destination ([IO.FileMode]::CreateNew) ([IO.FileAccess]::Write)
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
    if ($bytes.Length -lt 2 -or $bytes.Length -gt $MaxJsonBytes) {
        throw "Collector JSON output size is unbounded or empty: $Path"
    }
    $stream = Open-ExclusiveFile $Path ([IO.FileMode]::CreateNew) ([IO.FileAccess]::Write)
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
            $stream = Open-ExclusiveFile $absolute ([IO.FileMode]::Open) ([IO.FileAccess]::Read)
            try {
                if ($stream.Length -lt 1 -or $stream.Length -gt $MaxJsonBytes) {
                    throw "Collector helper closure input is unbounded or empty: $relative"
                }
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
    $stream = Open-ExclusiveFile $Path ([IO.FileMode]::Open) ([IO.FileAccess]::Read)
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt $MaxJsonBytes) {
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

function Assert-PreviousReleaseAuthorization {
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][string]$ArtifactPath,
        [Parameter(Mandatory)]$Signature
    )
    if ($Record.schema_version -ne 1 -or $Record.contract -cne
        'winsvpn-windows-previous-release-record-v1' -or
        [string]$Record.artifact_sha256 -cne (Get-Sha256 $ArtifactPath) -or
        [long]$Record.artifact_size_bytes -ne
            (Get-Item -LiteralPath $ArtifactPath).Length -or
        [string]$Record.signer_certificate_sha256 -cne
            (Get-CertificateSha256 $Signature.SignerCertificate) -or
        [string]$Record.owner_authorization_cms_base64 -notmatch
            '^[A-Za-z0-9+/=]{64,}$') {
        throw 'Previous release record does not bind the signed rollback artifact.'
    }
    $content = [Text.UTF8Encoding]::new($false).GetBytes(
        "winsvpn-rollback-v1`n$($Record.release_identity)`n" +
        "$($Record.artifact_sha256)`n$($Record.artifact_size_bytes)`n" +
        "$($Record.payload_manifest_sha256)`n"
    )
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $contentSha = ([BitConverter]::ToString(
            $algorithm.ComputeHash($content)
        )).Replace('-', '').ToLowerInvariant()
    } finally { $algorithm.Dispose() }
    if ($contentSha -cne [string]$Record.owner_authorization_content_sha256) {
        throw 'Previous release owner authorization content is stale.'
    }
    Add-Type -AssemblyName System.Security
    $cmsBytes = [Convert]::FromBase64String(
        [string]$Record.owner_authorization_cms_base64
    )
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new()
    $cms.Decode($cmsBytes)
    $cms.CheckSignature($true)
    if ([Convert]::ToBase64String($cms.ContentInfo.Content) -cne
        [Convert]::ToBase64String($content) -or $cms.SignerInfos.Count -ne 1) {
        throw 'Previous release CMS does not authorize the exact rollback record.'
    }
    $cmsShaAlgorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $cmsSha = ([BitConverter]::ToString(
            $cmsShaAlgorithm.ComputeHash($cmsBytes)
        )).Replace('-', '').ToLowerInvariant()
    } finally { $cmsShaAlgorithm.Dispose() }
    if ($cmsSha -cne [string]$Record.owner_authorization_cms_sha256) {
        throw 'Previous release CMS digest is invalid.'
    }
}

function Assert-ValidAuthenticode {
    param([string]$Path, [string]$Label)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
        -not $signature.TimeStamperCertificate -or
        $signature.SignerCertificate.Subject -eq $signature.SignerCertificate.Issuer -or
        @($signature.SignerCertificate.EnhancedKeyUsageList | Where-Object {
            $_.ObjectId.Value -eq '1.3.6.1.5.5.7.3.3'
        }).Count -ne 1) {
        throw "$Label lacks valid public-trust Authenticode and timestamp proof."
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
    contract = 'winsvpn-windows-collector-closure-v1'
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
$index = Read-JsonSecure $ReleaseInputIndex
$windowsRef = $index.platform_manifests.windows
$producerSha = (& $python -c @'
import pathlib,sys
sys.path.insert(0,'tools')
from public_release_live_smoke_common import producer_contract_hash
print(producer_contract_hash(pathlib.Path('.').resolve(),'tools/windows_public_release_live_smoke.ps1'))
'@).Trim()
if ($producerSha -notmatch '^[0-9a-f]{64}$') { throw 'Producer closure hash is invalid.' }

$candidateSignature = Assert-ValidAuthenticode $Artifact 'Exact candidate installer'
$previousSignature = Assert-ValidAuthenticode $PreviousArtifact 'Previous rollback installer'
$candidatePe = Get-PeArchitecture $Artifact
$previousPe = Get-PeArchitecture $PreviousArtifact
$hostArch = Get-NativeWindowsArchitecture
if ($candidatePe.Name -cne $previousPe.Name) {
    throw 'Candidate and rollback installer PE architectures are mixed.'
}
if ($hostArch -cne $candidatePe.Name) {
    throw "Host OS architecture $hostArch does not match artifact PE architecture $($candidatePe.Name)."
}
$artifactArch = [string]$candidatePe.Name
$osArchName = if ($artifactArch -ceq 'x64') { 'X64' } else { 'Arm64' }
$machineGuidSha256 = Get-MachineGuidSha256
$candidateHash = Get-Sha256 $Artifact
$previousHash = Get-Sha256 $PreviousArtifact
$candidateManifestDocument = Read-JsonSecure $CandidateManifest
$releaseIdentity = [string]$candidateManifestDocument.release_identity
if ($releaseIdentity -notmatch '^[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+$') {
    throw 'Candidate release identity is omitted or invalid.'
}
$previousRecord = Read-JsonSecure $PreviousReleaseRecord
Assert-PreviousReleaseAuthorization -Record $previousRecord `
    -ArtifactPath $PreviousArtifact -Signature $previousSignature
$previousPayloadDocument = Read-JsonSecure $PreviousPayloadManifest
if ((Get-Sha256 $PreviousPayloadManifest) -cne
        [string]$previousRecord.payload_manifest_sha256 -or
    [string]$previousPayloadDocument.installer.sha256 -cne $previousHash -or
    [long]$previousPayloadDocument.installer.size -ne
        (Get-Item -LiteralPath $PreviousArtifact).Length -or
    $previousPayloadDocument.signing.production_signed -ne $true -or
    $previousPayloadDocument.signing.every_loose_pe_verified -ne $true) {
    throw 'Previous rollback payload manifest is not exact and production-signed.'
}
$payloadDocument = Read-JsonSecure $PayloadManifest
if ($payloadDocument.schema_version -ne 3 -or
    [string]$payloadDocument.installer.sha256 -cne $candidateHash -or
    [long]$payloadDocument.installer.size -ne
        (Get-Item -LiteralPath $Artifact).Length -or
    $payloadDocument.signing.production_signed -ne $true -or
    $payloadDocument.signing.every_loose_pe_verified -ne $true -or
    $payloadDocument.signing.staged_xray_product_signed -ne $true -or
    $payloadDocument.signing.inno_setup_and_uninstaller_signed -ne $true -or
    @($payloadDocument.payload).Count -lt 1) {
    throw 'Exact candidate payload manifest is not production-signed and complete.'
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
    $payloadName = [IO.Path]::GetFileName(([string]$entry.path).Replace('/', '\'))
    if ($payloadName -match '\.(exe|dll|sys)$') {
        $payloadPe = Get-PeArchitecture $snapshot
        if ($payloadPe.Name -cne $artifactArch) {
            throw "Payload PE architecture is mixed with the installer: $relative"
        }
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
    contract = 'winsvpn-windows-payload-snapshot-v1'
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
    contract = 'winsvpn-windows-previous-release-record-v1'
    release_identity = [string]$previousRecord.release_identity
    artifact_sha256 = $previousHash
    artifact_size_bytes = [long](Get-Item -LiteralPath $PreviousArtifact).Length
    payload_manifest_sha256 = [string]$previousRecord.payload_manifest_sha256
    signer_certificate_sha256 = Get-CertificateSha256 `
        $previousSignature.SignerCertificate
    owner_authorization_content_sha256 = `
        [string]$previousRecord.owner_authorization_content_sha256
    owner_authorization_cms_sha256 = `
        [string]$previousRecord.owner_authorization_cms_sha256
}
Write-NewJson (Join-Path $ArtifactRoot 'previous-release-record.json') `
    $sanitizedPreviousRecord

$context = [ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-release-collector-context-v1'
    run_id = $RunId
    collector_closure_sha256 = $closureSha
    release_input_index_sha256 = Get-Sha256 $ReleaseInputIndex
    platform_manifest_sha256 = [string]$windowsRef.sha256
    artifact_input_fingerprint_sha256 = [string]$windowsRef.artifact_input_fingerprint_sha256
    build_receipt_sha256 = Get-Sha256 $BuildReceipt
    producer_contract_sha256 = $producerSha
    artifact_sha256 = $candidateHash
    artifact_size_bytes = (Get-Item -LiteralPath $Artifact).Length
    previous_artifact_sha256 = $previousHash
    candidate_signer_certificate_sha256 = Get-CertificateSha256 `
        $candidateSignature.SignerCertificate
    previous_signer_certificate_sha256 = Get-CertificateSha256 `
        $previousSignature.SignerCertificate
    architecture = $artifactArch
    pe_machine = [int]$candidatePe.Machine
    native_architecture = $artifactArch
    os_architecture = $osArchName
    process_wow64 = $false
    release_identity = $releaseIdentity
    source_only = $false
    next_sequence = 1
    created_at_utc = [DateTime]::UtcNow.ToString('o')
    publication_authorized = $false
}
Write-NewJson (Join-Path $PrivateRoot 'context.json') $context

$worker = Join-Path $HelperRoot 'windows_release_interactive_worker.ps1'
$taskRegistered = $false
$collectionPassed = $false
try {
    & $SystemPowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass `
        -File $worker -RunId $RunId -Phase Prepare
    if ($LASTEXITCODE -ne 0) { throw 'Windows physical prepare phase failed.' }
    $runtimeContext = Read-JsonSecure `
        (Join-Path $PrivateRoot 'runtime-context.json')
    $arm = [ordered]@{
        schema_version = 1
        contract = 'winsvpn-windows-release-watchdog-arm-v1'
        run_id = $RunId
        collector_closure_sha256 = $closureSha
        armed = $true
        step_nonce = [Guid]::NewGuid().ToString()
        sequence = [int]$runtimeContext.next_sequence
        armed_at_utc = [DateTime]::UtcNow.ToString('o')
    }
    Write-NewJson (Join-Path $PrivateRoot 'arm.json') $arm
    $watchdog = Join-Path $HelperRoot 'windows_release_safe_watchdog.ps1'
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
        $watchdog + '" -RunId "' + $RunId +
        '" -CollectorClosureSha256 "' + $closureSha +
        '" -DeadlineSeconds ' + $WatchdogDeadlineSeconds
    if ($arguments -notmatch '^-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "[A-Za-z]:\\ProgramData\\WinsVPN\\ReleaseEvidence\\[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\helpers\\windows_release_safe_watchdog\.ps1" -RunId "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" -CollectorClosureSha256 "[0-9a-f]{64}" -DeadlineSeconds [0-9]{3,4}$') {
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
            'winsvpn-windows-release-watchdog-ready-v1' -or
        $watchdogReady.run_id -cne $RunId -or
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
    $watchdogResult = Wait-JsonSecure $watchdogReceipt -TimeoutSeconds 30
    if ($watchdogResult.pass -ne $true -or
        $watchdogResult.normal_teardown_proven -ne $true -or
        $watchdogResult.fail_safe_triggered -ne $false) {
        throw 'Windows release run used emergency cleanup or lacked natural teardown.'
    }
    & $SystemPowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass `
        -File $worker -RunId $RunId -Phase Finalize
    if ($LASTEXITCODE -ne 0) { throw 'Windows physical finalize phase failed.' }
    $collectionPassed = $true
} finally {
    if ($taskRegistered) {
        try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue }
        catch { }
        try {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        } catch {
            $still = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            if ($still) {
                throw "Failed to unregister release watchdog task: $TaskName"
            }
        }
    }
}

if (-not $collectionPassed) {
    throw 'Windows physical collection did not complete; refusing to seal mixed evidence.'
}

$machinePath = Join-Path $ReceiptRoot 'machine-evidence.json'
if (-not (Test-Path -LiteralPath $machinePath -PathType Leaf)) {
    throw 'Physical collector did not produce machine evidence.'
}
$receiptFiles = @(Get-ChildItem -LiteralPath $ReceiptRoot -File)
if ($receiptFiles.Count -lt 1 -or $receiptFiles.Count -gt $MaxIndexedFiles) {
    throw 'Physical receipt set is empty or unbounded.'
}
$liveReceipts = [Collections.Generic.List[object]]::new()
$maxSequence = 0
foreach ($file in $receiptFiles) {
    if ($file.Extension -cne '.json') {
        throw "Non-JSON physical receipt cannot be sealed: $($file.Name)"
    }
    if ($file.Length -gt $MaxJsonBytes) {
        throw "Physical receipt output is unbounded: $($file.Name)"
    }
    $receipt = Read-JsonSecure $file.FullName
    $contractName = [string](Get-ReceiptProperty $receipt 'contract')
    $looksLikeLiveReceipt = $contractName -match 'receipt-v[0-9]+$' -or
        $contractName -eq 'winsvpn-windows-release-machine-evidence-v1'
    if (-not $looksLikeLiveReceipt) {
        throw "Mixed or stale live receipt cannot be sealed: $($file.Name)"
    }
    $requirePass = $contractName -ne
        'winsvpn-windows-release-machine-evidence-v1'
    Assert-BoundPhysicalReceipt $receipt $contractName `
        "Physical receipt $($file.Name)" -RequirePass:$requirePass
    if ([int](Get-ReceiptProperty $receipt 'sequence') -gt $maxSequence) {
        $maxSequence = [int]$receipt.sequence
    }
    $liveReceipts.Add($receipt)
}
Assert-RequiredBoundReceipts @($liveReceipts)
$identityStarted = [DateTime]::UtcNow.ToString('o')
$identityPath = Join-Path $ArtifactRoot 'machine-identity.json'
Write-NewJson $identityPath ([ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-machine-identity-v1'
    run_id = $RunId
    captured_at_utc = [DateTime]::UtcNow.ToString('o')
    secret_material_redacted = $true
    step_nonce = [Guid]::NewGuid().ToString('D')
    sequence = $maxSequence + 1
    started_at_utc = $identityStarted
    finished_at_utc = [DateTime]::UtcNow.ToString('o')
    collector_closure_sha256 = $closureSha
    release_input_index_sha256 = [string]$context.release_input_index_sha256
    platform_manifest_sha256 = [string]$context.platform_manifest_sha256
    artifact_input_fingerprint_sha256 = [string]$context.artifact_input_fingerprint_sha256
    build_receipt_sha256 = [string]$context.build_receipt_sha256
    producer_contract_sha256 = [string]$context.producer_contract_sha256
    artifact_sha256 = $candidateHash
    architecture = $artifactArch
    pe_machine = [int]$candidatePe.Machine
    native_architecture = $artifactArch
    machine_guid_sha256 = $machineGuidSha256
    os_architecture = $osArchName
    process_wow64 = $false
    release_identity = $releaseIdentity
    source_only = $false
})
Assert-ArchitectureBinding (Read-JsonSecure $identityPath)
$indexedFiles = @(
    Get-ChildItem -LiteralPath $ReceiptRoot -File
    Get-ChildItem -LiteralPath $ArtifactRoot -File
)
if ($indexedFiles.Count -lt 1 -or $indexedFiles.Count -gt $MaxIndexedFiles) {
    throw 'Physical evidence file count is empty or unbounded.'
}
$entries = foreach ($file in $indexedFiles) {
    $json = $null
    if ($file.Extension -eq '.json') {
        if ($file.Length -gt $MaxJsonBytes) {
            throw "Physical evidence JSON output is unbounded: $($file.Name)"
        }
        $json = Read-JsonSecure $file.FullName
    }
    $isBoundReceipt = $json -and [string]$json.contract -and
        [string]$json.run_id -ceq $RunId -and
        $json.sequence -and $json.step_nonce -and
        [string]$json.collector_closure_sha256 -ceq $closureSha
    $contractName = if ($json) { [string]$json.contract } else { '' }
    $looksLikeLiveReceipt = $contractName -match 'receipt-v[0-9]+$' -or
        $contractName -eq 'winsvpn-windows-release-machine-evidence-v1' -or
        $contractName -eq 'winsvpn-windows-machine-identity-v1'
    if ($looksLikeLiveReceipt -and -not $isBoundReceipt) {
        throw "Mixed or stale live receipt cannot be sealed: $($file.Name)"
    }
    if ($looksLikeLiveReceipt) {
        $requirePass = $contractName -ne
            'winsvpn-windows-release-machine-evidence-v1' -and
            $contractName -ne 'winsvpn-windows-machine-identity-v1'
        Assert-BoundPhysicalReceipt $json $contractName `
            "Physical receipt $($file.Name)" -RequirePass:$requirePass
    }
    $contract = if ($isBoundReceipt) { [string]$json.contract } else { '' }
    $sequence = if ($isBoundReceipt) { [int]$json.sequence } else { 0 }
    $nonce = if ($isBoundReceipt) {
        [string]$json.step_nonce
    } else { [Guid]::NewGuid().ToString('D') }
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
$singletonContracts = @(
    'winsvpn-windows-release-machine-evidence-v1',
    'winsvpn-windows-machine-identity-v1',
    'winsvpn-windows-signature-receipt-v1',
    'winsvpn-windows-install-receipt-v1',
    'winsvpn-windows-runtime-receipt-v1',
    'winsvpn-windows-uninstall-receipt-v1',
    'winsvpn-windows-route-advertisement-receipt-v1',
    'winsvpn-windows-rapid-cancel-receipt-v1',
    'winsvpn-windows-split-tunnel-receipt-v1',
    'winsvpn-windows-network-change-receipt-v1',
    'winsvpn-windows-leak-receipt-v1',
    'winsvpn-windows-release-watchdog-receipt-v1',
    'winsvpn-windows-teardown-rollback-receipt-v1',
    'winsvpn-windows-winn-v3-receipt-v1',
    'winsvpn-windows-winn-v1-awg-receipt-v1',
    'winsvpn-windows-winn-v1-xray-receipt-v1',
    'winsvpn-windows-native-host-receipt-v1',
    'winsvpn-windows-map-receipt-v1'
)
foreach ($group in @($entries | Where-Object contract | Group-Object contract)) {
    if ($singletonContracts -contains $group.Name -and $group.Count -ne 1) {
        throw "Duplicate live evidence contract cannot be sealed: $($group.Name)"
    }
}
foreach ($requiredContract in @(
    'winsvpn-windows-signature-receipt-v1',
    'winsvpn-windows-install-receipt-v1',
    'winsvpn-windows-runtime-receipt-v1',
    'winsvpn-windows-uninstall-receipt-v1',
    'winsvpn-windows-teardown-rollback-receipt-v1',
    'winsvpn-windows-winn-v3-receipt-v1',
    'winsvpn-windows-winn-v1-awg-receipt-v1',
    'winsvpn-windows-winn-v1-xray-receipt-v1',
    'winsvpn-windows-native-host-receipt-v1',
    'winsvpn-windows-machine-identity-v1'
)) {
    if (-not ($entries | Where-Object { $_.contract -eq $requiredContract })) {
        throw "Physical collector did not produce $requiredContract evidence."
    }
}
if (-not ($entries | Where-Object {
        $_.contract -eq 'winsvpn-windows-machine-identity-v1'
    })) {
    throw 'Physical collector did not produce machine-identity evidence.'
}
$machineRelative = $machinePath.Substring($RunRoot.Length).TrimStart('\').Replace('\', '/')
$bundleIndex = [ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-release-bundle-index-v1'
    run_id = $RunId
    created_at_utc = [DateTime]::UtcNow.ToString('o')
    secret_material_redacted = $true
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
    publication_authorized = $false
    sealed = $true
}
$indexPath = Join-Path $RunRoot 'bundle-index.json'
Write-NewJson $indexPath $bundleIndex
$bundleIndexSha256 = Get-Sha256 $indexPath
foreach ($path in @($ReceiptRoot, $ArtifactRoot, $HelperRoot, $PrivateRoot, $RunRoot)) {
    Assert-LockedAcl $path
}
$sealedFiles = @(Get-ChildItem -LiteralPath $RunRoot -Recurse -File)
if ($sealedFiles.Count -lt 1 -or $sealedFiles.Count -gt 1024) {
    throw 'Physical evidence tree is empty or unbounded.'
}
foreach ($file in $sealedFiles) {
    Protect-LockedFile $file.FullName
    $file.IsReadOnly = $true
}
Write-Output "WINDOWS_RELEASE_PHYSICAL_COLLECTOR=PASS run_id=$RunId"
Write-Output "WINDOWS_RELEASE_BUNDLE_INDEX=$indexPath"
Write-Output "WINDOWS_RELEASE_BUNDLE_INDEX_SHA256=$bundleIndexSha256"
