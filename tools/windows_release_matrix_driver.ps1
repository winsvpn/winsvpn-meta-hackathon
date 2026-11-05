[CmdletBinding()]
param(
    [string]$EvidenceBundleIndex = '',
    [string]$Artifact = '',
    [string]$MapScreenshot = '',
    [string]$ReleaseInputIndex = '',
    [string]$BuildReceipt = '',
    [string]$Output = '',
    [string]$Assignments = '',
    [string]$ExpectedArchitecture = '',
    [string]$ExpectedSurface = '',
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $RepoRoot
$Python = if (Get-Command python.exe -ErrorAction SilentlyContinue) {
    (Get-Command python.exe).Source
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    (Get-Command python3).Source
} else {
    throw 'Python 3 is required for Windows release-matrix compilation.'
}
$Compiler = Join-Path $PSScriptRoot 'windows_release_matrix_evidence.py'
$WorkerScript = Join-Path $PSScriptRoot 'windows_release_interactive_worker.ps1'
$CollectorScript = Join-Path $PSScriptRoot 'windows_release_physical_collector.ps1'
$SystemPowerShell = if (-not [string]::IsNullOrEmpty($env:SystemRoot)) {
    Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
} else {
    'powershell.exe'
}
$OpenReparsePoint = [IO.FileOptions]0x00200000
$PeMachineX64 = 0x8664
$PeMachineArm64 = 0xAA64
$ReparseAttribute = [uint32]0x400
$MaxJsonBytes = 16777216
$MaxChildOutputBytes = 16777216
$MaxChildTimeoutMs = 120000
$script:MatrixState = $null
$script:WinsVpnByHandleReady = $false

function Get-CanonicalWindowsMatrixTargets {
    [ordered]@{
        'windows-x64-installer' = [ordered]@{
            architecture = 'x64'
            pe_machine = $PeMachineX64
            os_architecture = 'X64'
            surface = 'website'
            filename = 'WinsVPN-Setup.exe'
        }
        'windows-x64-partner-center' = [ordered]@{
            architecture = 'x64'
            pe_machine = $PeMachineX64
            os_architecture = 'X64'
            surface = 'partner-center'
            filename = 'WinsVPN-PartnerCenter.exe'
        }
        'windows-arm64-installer' = [ordered]@{
            architecture = 'arm64'
            pe_machine = $PeMachineArm64
            os_architecture = 'Arm64'
            surface = 'website'
            filename = 'WinsVPN-Setup-arm64.exe'
        }
        'windows-arm64-partner-center' = [ordered]@{
            architecture = 'arm64'
            pe_machine = $PeMachineArm64
            os_architecture = 'Arm64'
            surface = 'partner-center'
            filename = 'WinsVPN-PartnerCenter-arm64.exe'
        }
    }
}

function Test-WindowsReleaseHost {
    [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}

function Initialize-MatrixDriverState {
    if ($null -ne $script:MatrixState) { return }
    $script:MatrixState = @{
        Nonces = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal
        )
        RunIds = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal
        )
        WorkerPhases = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal
        )
    }
}

function Reset-MatrixDriverState {
    $script:MatrixState = $null
    Initialize-MatrixDriverState
}

function Get-AssignmentProperty {
    param(
        [Parameter(Mandatory)]$Assignment,
        [Parameter(Mandatory)][string]$Name
    )
    if ($Assignment -is [Collections.IDictionary]) {
        if (-not $Assignment.Contains($Name)) {
            throw "Windows matrix assignment omitted $Name."
        }
        return $Assignment[$Name]
    }
    $property = $Assignment.PSObject.Properties[$Name]
    if (-not $property) {
        throw "Windows matrix assignment omitted $Name."
    }
    $property.Value
}

function Assert-CanonicalUuid {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Label
    )
    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParseExact($Value, 'D', [ref]$parsed) -or
        $parsed -eq [Guid]::Empty -or
        $Value -cne $parsed.ToString('D')) {
        throw "Windows matrix $Label is not one canonical nonzero UUID."
    }
}

function Assert-SafeChildArgumentList {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ArgumentList)
    foreach ($argument in @($ArgumentList)) {
        if ($null -eq $argument) {
            throw 'Windows matrix child argument is null.'
        }
        $text = [string]$argument
        if ($text.Length -gt 4096) {
            throw 'Windows matrix child argument is unbounded.'
        }
        if ($text -match '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]') {
            throw 'Windows matrix child argument contains a control character.'
        }
        if ($text -match '[\r\n;|&`$]') {
            throw 'Windows matrix child argument contains shell metacharacters.'
        }
        if ($text -ceq '-Command' -or $text -ceq '/c' -or
            $text -ceq 'cmd.exe' -or $text -ceq 'Invoke-Expression') {
            throw 'Windows matrix child argument uses string/shell injection.'
        }
    }
}

function Assert-NoReparsePath {
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -match '(^|[/\\])\.\.([/\\]|$)') {
        throw "Windows matrix path contains parent traversal: $full"
    }
    if (-not (Test-WindowsReleaseHost)) {
        if (Test-Path -LiteralPath $full) {
            $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                $item.LinkType -ceq 'SymbolicLink' -or
                $item.LinkType -ceq 'Junction') {
                throw "Windows matrix path contains a reparse point: $full"
            }
            if ($item.LinkType -ceq 'HardLink') {
                throw "Windows matrix path is a hardlink substitution: $full"
            }
        }
        return
    }
    $root = [IO.Path]::GetPathRoot($full)
    $current = $root
    foreach ($part in @($full.Substring($root.Length) -split '[\\/]' |
            Where-Object { $_ })) {
        if ($part -ceq '..') {
            throw "Windows matrix path contains parent traversal: $full"
        }
        $current = Join-Path $current $part
        if (-not (Test-Path -LiteralPath $current)) { continue }
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Windows matrix path contains a reparse point: $current"
        }
        if ($item.LinkType -ceq 'SymbolicLink' -or
            $item.LinkType -ceq 'Junction') {
            throw "Windows matrix path contains a reparse point: $current"
        }
    }
}

function Initialize-WinsVpnByHandleInfo {
    if ($script:WinsVpnByHandleReady) { return }
    if (-not (Test-WindowsReleaseHost)) { return }
    if (-not ('WinsVpnMatrixByHandleInfo' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WinsVpnMatrixByHandleInfo {
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
    $script:WinsVpnByHandleReady = $true
}

function Assert-OpenedFileIdentity {
    param(
        [Parameter(Mandatory)][IO.FileStream]$Stream,
        [Parameter(Mandatory)][string]$Path
    )
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Windows matrix descriptor opened a reparse point: $Path"
    }
    if ($item.LinkType -ceq 'HardLink' -or
        $item.LinkType -ceq 'SymbolicLink' -or
        $item.LinkType -ceq 'Junction') {
        throw "Windows matrix path is a hardlink substitution: $Path"
    }
    if (-not (Test-WindowsReleaseHost)) { return }
    Initialize-WinsVpnByHandleInfo
    $info = New-Object WinsVpnMatrixByHandleInfo+BY_HANDLE_FILE_INFORMATION
    $handle = $Stream.SafeFileHandle.DangerousGetHandle()
    if (-not [WinsVpnMatrixByHandleInfo]::GetFileInformationByHandle(
            $handle, [ref]$info
        )) {
        throw "Windows matrix handle identity is unavailable: $Path"
    }
    if (($info.dwFileAttributes -band $ReparseAttribute) -ne 0) {
        throw "Windows matrix descriptor opened a reparse point: $Path"
    }
    if ($info.nNumberOfLinks -ne 1) {
        throw "Windows matrix path is a hardlink substitution: $Path"
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
    $options = [IO.FileOptions]::None
    if (Test-WindowsReleaseHost) { $options = $OpenReparsePoint }
    $stream = [IO.FileStream]::new(
        $Path, $Mode, $Access, [IO.FileShare]::None, 1048576, $options
    )
    try {
        if ($Mode -ne [IO.FileMode]::CreateNew) {
            Assert-OpenedFileIdentity $stream $Path
        }
    } catch {
        $stream.Dispose()
        throw
    }
    $stream
}

function Assert-SafeEvidencePath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$AllowedRoot,
        [switch]$MustNotExist
    )
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetFullPath($AllowedRoot).TrimEnd('\', '/') +
        [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Compiled Windows native evidence must stay under the allowed evidence root.'
    }
    Assert-NoReparsePath ([IO.Path]::GetDirectoryName($full))
    if (Test-Path -LiteralPath $full) {
        if ($MustNotExist) {
            throw 'Refusing to overwrite an existing compiled Windows transcript.'
        }
        Assert-NoReparsePath $full
        $stream = Open-ExclusiveFile $full ([IO.FileMode]::Open) (
            [IO.FileAccess]::Read
        )
        $stream.Dispose()
    }
}

function Get-NativeWindowsArchitecture {
    if (-not [string]::IsNullOrEmpty(
            [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
        )) {
        throw 'Windows release matrix driver must not run under WOW64.'
    }
    $osArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $processArch = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    if ($processArch -cne $osArch) {
        throw 'Windows release matrix driver must not run under WOW64.'
    }
    switch ($osArch) {
        'X64' { 'x64' }
        'Arm64' { 'arm64' }
        default { throw "Unsupported Windows OS architecture: $osArch" }
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
        $name = switch ([int]$machine) {
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

function Assert-ArchitectureExpectation {
    param($Binding)
    if ($null -eq $Binding) {
        throw 'Windows matrix assignment omitted architecture binding.'
    }
    $architecture = [string](Get-AssignmentProperty $Binding 'architecture')
    $native = [string](Get-AssignmentProperty $Binding 'native_architecture')
    $osArchitecture = [string](Get-AssignmentProperty $Binding 'os_architecture')
    $peMachine = Get-AssignmentProperty $Binding 'pe_machine'
    $wow64 = Get-AssignmentProperty $Binding 'process_wow64'
    if ([string]::IsNullOrEmpty($architecture) -or
        [string]::IsNullOrEmpty($native) -or
        [string]::IsNullOrEmpty($osArchitecture) -or
        $null -eq $peMachine) {
        throw 'Windows matrix assignment omitted architecture binding.'
    }
    if ($architecture -cne 'x64' -and $architecture -cne 'arm64') {
        throw "Unsupported Windows matrix PE architecture: $architecture"
    }
    $expectedMachine = if ($architecture -ceq 'x64') { $PeMachineX64 } else {
        $PeMachineArm64
    }
    $expectedOs = if ($architecture -ceq 'x64') { 'X64' } else { 'Arm64' }
    if ($native -cne $architecture -or
        $osArchitecture -cne $expectedOs -or
        [int]$peMachine -ne [int]$expectedMachine -or
        $wow64 -ne $false) {
        throw 'Windows matrix architecture is mixed, WOW64, or unsupported.'
    }
}

function New-ArchitectureExpectation {
    param(
        [Parameter(Mandatory)][string]$Architecture,
        [Parameter(Mandatory)][string]$Surface,
        [Parameter(Mandatory)][string]$TargetId,
        [Parameter(Mandatory)][string]$HostId,
        [Parameter(Mandatory)][string]$Candidate
    )
    $canonical = Get-CanonicalWindowsMatrixTargets
    if (-not $canonical.Contains($TargetId)) {
        throw "Windows matrix target is not one of the four native surfaces: $TargetId"
    }
    $expected = $canonical[$TargetId]
    if ($Architecture -cne [string]$expected.architecture -or
        $Surface -cne [string]$expected.surface) {
        throw 'Windows matrix architecture/surface does not match the exact target.'
    }
    $osArchitecture = [string]$expected.os_architecture
    $binding = [ordered]@{
        architecture = $Architecture
        pe_machine = [int]$expected.pe_machine
        native_architecture = $Architecture
        os_architecture = $osArchitecture
        process_wow64 = $false
        surface = $Surface
        target_id = $TargetId
        host_id = $HostId
        host_architecture = $Architecture
        candidate = $Candidate
    }
    Assert-ArchitectureExpectation $binding
    $binding
}

function Assert-ArchitectureAssignment {
    param($Assignment)
    Assert-ArchitectureExpectation $Assignment
    $targetId = [string](Get-AssignmentProperty $Assignment 'target_id')
    $surface = [string](Get-AssignmentProperty $Assignment 'surface')
    $hostId = [string](Get-AssignmentProperty $Assignment 'host_id')
    $hostArch = [string](Get-AssignmentProperty $Assignment 'host_architecture')
    $candidate = [string](Get-AssignmentProperty $Assignment 'candidate')
    $nonce = [string](Get-AssignmentProperty $Assignment 'assignment_nonce')
    $architecture = [string](Get-AssignmentProperty $Assignment 'architecture')
    $canonical = Get-CanonicalWindowsMatrixTargets
    if (-not $canonical.Contains($targetId)) {
        throw "Windows matrix target is not one of the four native surfaces: $targetId"
    }
    $expected = $canonical[$targetId]
    if ($architecture -cne [string]$expected.architecture -or
        $surface -cne [string]$expected.surface -or
        [int](Get-AssignmentProperty $Assignment 'pe_machine') -ne
            [int]$expected.pe_machine) {
        throw 'Windows matrix architecture/surface is mixed with its target.'
    }
    if ($hostArch -cne $architecture) {
        throw 'Windows matrix host architecture is mixed with the candidate.'
    }
    if ($hostId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
        throw 'Windows matrix host id is not one exact native host identity.'
    }
    Assert-CanonicalUuid $nonce 'assignment nonce'
    $leaf = [IO.Path]::GetFileName($candidate)
    if ($leaf -cne [string]$expected.filename) {
        throw 'Windows matrix candidate filename does not match the exact target.'
    }
    if ([string]::IsNullOrWhiteSpace($candidate) -or
        -not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw 'Windows matrix candidate must name an existing regular file.'
    }
    $pe = Get-PeArchitecture $candidate
    if ($pe.Name -cne $architecture -or
        [int]$pe.Machine -ne [int]$expected.pe_machine) {
        throw 'Windows matrix candidate PE architecture is mixed with the native host.'
    }
    if ((Test-WindowsReleaseHost) -and
        ((Get-AssignmentProperty $Assignment 'require_live_host') -eq $true)) {
        $live = Get-NativeWindowsArchitecture
        if ($live -cne $architecture) {
            throw "Host OS architecture $live does not match bound PE architecture $architecture."
        }
    }
}

function ConvertTo-ObjectList {
    param([Parameter(Mandatory)]$Value)
    $source = $Value
    if ($Value -is [Collections.IDictionary] -and $Value.Contains('rows')) {
        $source = $Value['rows']
    }
    $items = [Collections.Generic.List[object]]::new()
    if ($source -is [Collections.IDictionary]) {
        [void]$items.Add($source)
        return ,$items
    }
    foreach ($entry in $source) {
        if ($entry -is [Collections.IDictionary]) {
            [void]$items.Add($entry)
        }
    }
    return ,$items
}

function Assert-FourTargetCoverage {
    param([Parameter(Mandatory)]$AssignmentSet)
    $assignmentItems = ConvertTo-ObjectList $AssignmentSet
    $canonical = Get-CanonicalWindowsMatrixTargets
    $seenTargets = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $seenPairs = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $seenCandidates = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $seenNonces = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $hostByArch = @{}
    foreach ($assignment in $assignmentItems) {
        Assert-ArchitectureAssignment $assignment
        $targetId = [string](Get-AssignmentProperty $assignment 'target_id')
        $architecture = [string](Get-AssignmentProperty $assignment 'architecture')
        $surface = [string](Get-AssignmentProperty $assignment 'surface')
        $hostId = [string](Get-AssignmentProperty $assignment 'host_id')
        $candidate = [IO.Path]::GetFullPath(
            [string](Get-AssignmentProperty $assignment 'candidate')
        )
        $nonce = [string](Get-AssignmentProperty $assignment 'assignment_nonce')
        if (-not $seenTargets.Add($targetId) -or
            -not $seenPairs.Add("$architecture|$surface") -or
            -not $seenCandidates.Add($candidate) -or
            -not $seenNonces.Add($nonce)) {
            throw 'Duplicate Windows matrix assignment is refused.'
        }
        if ($hostByArch.ContainsKey($architecture)) {
            if ($hostByArch[$architecture] -cne $hostId) {
                throw 'Windows matrix host architecture is mixed, WOW64, or unsupported.'
            }
        } else {
            $hostByArch[$architecture] = $hostId
        }
    }
    if ($assignmentItems.Count -ne 4) {
        throw 'Windows matrix has wrong four-target coverage.'
    }
    foreach ($targetId in @($canonical.Keys)) {
        if (-not $seenTargets.Contains($targetId)) {
            throw 'Windows matrix has wrong four-target coverage.'
        }
    }
    if ($hostByArch.Count -ne 2 -or
        -not $hostByArch.ContainsKey('x64') -or
        -not $hostByArch.ContainsKey('arm64') -or
        $hostByArch['x64'] -ceq $hostByArch['arm64']) {
        throw 'Windows matrix architecture is mixed, WOW64, or unsupported.'
    }
}

function Register-AssignmentAttempt {
    param(
        [Parameter(Mandatory)]$Assignment,
        [Parameter(Mandatory)][string]$RunId
    )
    Initialize-MatrixDriverState
    Assert-ArchitectureAssignment $Assignment
    Assert-CanonicalUuid $RunId 'run id'
    $nonce = [string](Get-AssignmentProperty $Assignment 'assignment_nonce')
    if ($script:MatrixState.Nonces.Contains($nonce) -or
        $script:MatrixState.RunIds.Contains($RunId)) {
        throw 'Stale Windows matrix retry is refused.'
    }
    [void]$script:MatrixState.Nonces.Add($nonce)
    [void]$script:MatrixState.RunIds.Add($RunId)
}

function Register-WorkerPhaseAttempt {
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$Phase
    )
    Initialize-MatrixDriverState
    Assert-CanonicalUuid $RunId 'run id'
    if ($Phase -cne 'Prepare' -and $Phase -cne 'Execute' -and
        $Phase -cne 'Finalize') {
        throw "Windows worker phase is not in the accepted contract: $Phase"
    }
    $key = $RunId + '|' + $Phase
    if ($script:MatrixState.WorkerPhases.Contains($key)) {
        throw 'Stale Windows matrix retry is refused.'
    }
    [void]$script:MatrixState.WorkerPhases.Add($key)
}

function New-ArchitectureExpectationFromAssignment {
    param([Parameter(Mandatory)]$Assignment)
    Assert-ArchitectureAssignment $Assignment
    [ordered]@{
        architecture = [string](Get-AssignmentProperty $Assignment 'architecture')
        pe_machine = [int](Get-AssignmentProperty $Assignment 'pe_machine')
        native_architecture = [string](Get-AssignmentProperty $Assignment 'native_architecture')
        os_architecture = [string](Get-AssignmentProperty $Assignment 'os_architecture')
        process_wow64 = $false
        surface = [string](Get-AssignmentProperty $Assignment 'surface')
        target_id = [string](Get-AssignmentProperty $Assignment 'target_id')
        host_id = [string](Get-AssignmentProperty $Assignment 'host_id')
        host_architecture = [string](Get-AssignmentProperty $Assignment 'host_architecture')
        candidate = [string](Get-AssignmentProperty $Assignment 'candidate')
    }
}

function New-WorkerInvocation {
    param(
        [Parameter(Mandatory)]$Assignment,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$Phase
    )
    $expectation = New-ArchitectureExpectationFromAssignment $Assignment
    Register-WorkerPhaseAttempt $RunId $Phase
    $arguments = [Collections.Generic.List[string]]::new()
    foreach ($part in @(
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy',
            'Bypass',
            '-File',
            $WorkerScript,
            '-RunId',
            $RunId,
            '-Phase',
            $Phase
        )) {
        $arguments.Add([string]$part)
    }
    Assert-SafeChildArgumentList @($arguments)
    [ordered]@{
        contract = 'winsvpn-windows-interactive-worker-v1'
        file_name = $SystemPowerShell
        argument_list = @($arguments)
        architecture_expectation = $expectation
        run_id = $RunId
        phase = $Phase
        target_id = [string]$expectation.target_id
    }
}

function New-CollectorInvocation {
    param(
        [Parameter(Mandatory)]$Assignment,
        [Parameter(Mandatory)]$Inputs
    )
    $expectation = New-ArchitectureExpectationFromAssignment $Assignment
    $required = @(
        'PayloadManifest',
        'PayloadRoot',
        'ReleaseInputIndex',
        'BuildReceipt',
        'CandidateManifest',
        'PreviousArtifact',
        'PreviousPayloadManifest',
        'PreviousReleaseRecord',
        'CredentialStore',
        'Gazetteer'
    )
    $map = [ordered]@{
        Artifact = [string]$expectation.candidate
    }
    foreach ($name in $required) {
        $value = [string](Get-AssignmentProperty $Inputs $name)
        if ([string]::IsNullOrWhiteSpace($value)) {
            throw "Collector input omitted $name."
        }
        $map[$name] = $value
    }
    $deadline = 1200
    $deadlineProperty = $null
    if ($Inputs -is [Collections.IDictionary]) {
        if ($Inputs.Contains('WatchdogDeadlineSeconds')) {
            $deadlineProperty = $Inputs['WatchdogDeadlineSeconds']
        }
    } else {
        $deadlineProperty = $Inputs.PSObject.Properties['WatchdogDeadlineSeconds']
        if ($deadlineProperty) { $deadlineProperty = $deadlineProperty.Value }
    }
    if ($null -ne $deadlineProperty -and
        [string]$deadlineProperty -cne '') {
        $deadline = [int]$deadlineProperty
    }
    if ($deadline -lt 600 -or $deadline -gt 3600) {
        throw 'Collector watchdog deadline is outside the accepted contract.'
    }
    $arguments = [Collections.Generic.List[string]]::new()
    foreach ($part in @(
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy',
            'Bypass',
            '-File',
            $CollectorScript
        )) {
        $arguments.Add([string]$part)
    }
    foreach ($name in @($map.Keys)) {
        $arguments.Add("-$name")
        $arguments.Add([string]$map[$name])
    }
    $arguments.Add('-WatchdogDeadlineSeconds')
    $arguments.Add([string]$deadline)
    Assert-SafeChildArgumentList @($arguments)
    [ordered]@{
        contract = 'winsvpn-windows-physical-collector-v1'
        file_name = $SystemPowerShell
        argument_list = @($arguments)
        architecture_expectation = $expectation
        target_id = [string]$expectation.target_id
    }
}

function Get-ReceiptProperty {
    param(
        [Parameter(Mandatory)]$Receipt,
        [Parameter(Mandatory)][string]$Name
    )
    if ($Receipt -is [Collections.IDictionary]) {
        if (-not $Receipt.Contains($Name)) {
            throw "Windows matrix receipt omitted $Name."
        }
        return $Receipt[$Name]
    }
    $property = $Receipt.PSObject.Properties[$Name]
    if (-not $property) {
        throw "Windows matrix receipt omitted $Name."
    }
    $property.Value
}

function Assert-WinnEvidenceOrder {
    param([Parameter(Mandatory)]$ReceiptSet)
    $byContract = @{}
    foreach ($receipt in (ConvertTo-ObjectList $ReceiptSet)) {
        $contract = [string](Get-ReceiptProperty $receipt 'contract')
        if ($byContract.ContainsKey($contract)) {
            throw "Duplicate live evidence contract cannot be sealed: $contract"
        }
        if ((Get-ReceiptProperty $receipt 'passed') -ne $true) {
            throw 'Windows matrix receipt did not pass; refusing a partial false green.'
        }
        Assert-ArchitectureExpectation $receipt
        $byContract[$contract] = $receipt
    }
    $required = [ordered]@{
        'winsvpn-windows-winn-v3-receipt-v1' =
            'Physical Winn v3 primary receipt'
        'winsvpn-windows-winn-v1-awg-receipt-v1' =
            'Physical Winn v1 AWG receipt'
        'winsvpn-windows-winn-v1-xray-receipt-v1' =
            'Physical Winn v1 Xray fallback receipt'
    }
    foreach ($contract in @($required.Keys)) {
        if (-not $byContract.ContainsKey($contract)) {
            throw "$($required[$contract]) is missing; refusing to seal partial evidence."
        }
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
    $v3Seq = [int](Get-ReceiptProperty $v3 'sequence')
    $awgSeq = [int](Get-ReceiptProperty $awg 'sequence')
    $xraySeq = [int](Get-ReceiptProperty $xray 'sequence')
    if ($v3Seq -ge $awgSeq) {
        throw 'Physical Winn v1 AWG is not after Winn v3 primary.'
    }
    if ($awgSeq -ge $xraySeq) {
        throw 'Physical Winn v1 Xray fallback is not after AWG.'
    }
}

function Assert-MatrixSeal {
    param([Parameter(Mandatory)]$ResultSet)
    $resultItems = ConvertTo-ObjectList $ResultSet
    if ($resultItems.Count -ne 4) {
        throw 'Windows matrix has wrong four-target coverage.'
    }
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($result in $resultItems) {
        if ((Get-ReceiptProperty $result 'passed') -ne $true) {
            throw 'Windows matrix result did not pass; refusing a partial false green.'
        }
        $targetId = [string](Get-ReceiptProperty $result 'target_id')
        if (-not $seen.Add($targetId)) {
            throw 'Duplicate Windows matrix assignment is refused.'
        }
        Assert-WinnEvidenceOrder -ReceiptSet (Get-ReceiptProperty $result 'receipts')
    }
    $canonical = Get-CanonicalWindowsMatrixTargets
    foreach ($targetId in @($canonical.Keys)) {
        if (-not $seen.Contains($targetId)) {
            throw 'Windows matrix has wrong four-target coverage.'
        }
    }
}

function Invoke-BoundedNative {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ArgumentList,
        [ValidateRange(1000, 3600000)][int]$TimeoutMilliseconds = 120000,
        [ValidateRange(1, 16777216)][int]$MaxOutputBytes = 16777216
    )
    Assert-SafeChildArgumentList $ArgumentList
    if ([string]::IsNullOrWhiteSpace($FilePath) -or
        $FilePath -match '[\r\n;|&`$]' -or
        $FilePath -ceq 'cmd.exe') {
        throw 'Windows matrix child file path is unsafe.'
    }
    $argProp = [Diagnostics.ProcessStartInfo].GetProperty('ArgumentList')
    if ($null -eq $argProp) {
        $output = & $FilePath @ArgumentList 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            throw "Windows matrix child failed with code $LASTEXITCODE."
        }
        if ([Text.Encoding]::UTF8.GetByteCount($output) -gt $MaxOutputBytes) {
            throw 'Windows matrix child output is unbounded.'
        }
        return $output
    }
    $process = [Diagnostics.Process]::new()
    try {
        $process.StartInfo.FileName = $FilePath
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.WorkingDirectory = $RepoRoot
        foreach ($argument in @($ArgumentList)) {
            [void]$process.StartInfo.ArgumentList.Add([string]$argument)
        }
        if (-not $process.Start()) {
            throw "Windows matrix child failed to start: $FilePath"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            try { $process.Kill() } catch { }
            throw 'Windows matrix child timed out.'
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $total = [Text.Encoding]::UTF8.GetByteCount([string]$stdout) +
            [Text.Encoding]::UTF8.GetByteCount([string]$stderr)
        if ($total -gt $MaxOutputBytes) {
            throw 'Windows matrix child output is unbounded.'
        }
        if ($process.ExitCode -ne 0) {
            throw "Windows matrix child failed with code $($process.ExitCode)."
        }
        [string]$stdout
    } finally { $process.Dispose() }
}

function New-MinimalPe32Plus {
    param(
        [Parameter(Mandatory)][int]$Machine,
        [byte[]]$Payload
    )
    if ($null -eq $Payload -or $Payload.Length -lt 1) {
        $Payload = [byte[]][char[]]'winsvpn'
    }
    $dos = [byte[]]::new(128)
    $dos[0] = [byte][char]'M'
    $dos[1] = [byte][char]'Z'
    [BitConverter]::GetBytes([int]128).CopyTo($dos, 0x3C)
    $coff = [Collections.Generic.List[byte]]::new()
    $coff.AddRange([BitConverter]::GetBytes([uint16]$Machine))
    $coff.AddRange([BitConverter]::GetBytes([uint16]0))
    for ($i = 0; $i -lt 3; ++$i) {
        $coff.AddRange([BitConverter]::GetBytes([int]0))
    }
    $coff.AddRange([BitConverter]::GetBytes([uint16]240))
    $coff.AddRange([BitConverter]::GetBytes([uint16]0x0022))
    $optional = [byte[]]::new(240)
    [BitConverter]::GetBytes([uint16]0x20B).CopyTo($optional, 0)
    [BitConverter]::GetBytes([int]512).CopyTo($optional, 36)
    [BitConverter]::GetBytes([int]16).CopyTo($optional, 108)
    $cert = [Collections.Generic.List[byte]]::new()
    $cert.AddRange([BitConverter]::GetBytes([int](8 + $Payload.Length)))
    $cert.AddRange([BitConverter]::GetBytes([uint16]0x0200))
    $cert.AddRange([BitConverter]::GetBytes([uint16]0x0002))
    $cert.AddRange($Payload)
    while (($cert.Count % 8) -ne 0) { $cert.Add([byte]0) }
    $certBytes = [byte[]]::new($cert.Count)
    $cert.CopyTo($certBytes)
    [BitConverter]::GetBytes([int]$certBytes.Length).CopyTo($certBytes, 0)
    [BitConverter]::GetBytes([int]512).CopyTo($optional, 144)
    [BitConverter]::GetBytes([int]$certBytes.Length).CopyTo($optional, 148)
    $header = [Collections.Generic.List[byte]]::new()
    $header.AddRange($dos)
    $header.AddRange([byte[]]@(80, 69, 0, 0))
    $header.AddRange($coff)
    $header.AddRange($optional)
    $blob = [Collections.Generic.List[byte]]::new()
    $blob.AddRange($header)
    while ($blob.Count -lt 512) { $blob.Add([byte]0) }
    $blob.AddRange($certBytes)
    while ($blob.Count -lt 2048) { $blob.Add([byte]0) }
    ,$blob.ToArray()
}

function New-SelfTestAssignment {
    param(
        [Parameter(Mandatory)][string]$TargetId,
        [Parameter(Mandatory)][string]$HostId,
        [Parameter(Mandatory)][string]$Candidate,
        [Parameter(Mandatory)][string]$Nonce
    )
    $canonical = (Get-CanonicalWindowsMatrixTargets)[$TargetId]
    [ordered]@{
        target_id = $TargetId
        architecture = [string]$canonical.architecture
        pe_machine = [int]$canonical.pe_machine
        native_architecture = [string]$canonical.architecture
        os_architecture = [string]$canonical.os_architecture
        process_wow64 = $false
        surface = [string]$canonical.surface
        host_id = $HostId
        host_architecture = [string]$canonical.architecture
        candidate = $Candidate
        assignment_nonce = $Nonce
        require_live_host = $false
    }
}

function Invoke-MatrixDriverSelfTest {
    Reset-MatrixDriverState
    $native = Get-NativeWindowsArchitecture
    if ($native -cne 'x64' -and $native -cne 'arm64') {
        throw "Unsupported Windows OS architecture: $native"
    }
    $previousWow = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
    [Environment]::SetEnvironmentVariable('PROCESSOR_ARCHITEW6432', 'AMD64')
    $wowRejected = $false
    try {
        [void](Get-NativeWindowsArchitecture)
    } catch {
        if ("$_" -notmatch 'must not run under WOW64') { throw }
        $wowRejected = $true
    } finally {
        [Environment]::SetEnvironmentVariable(
            'PROCESSOR_ARCHITEW6432', $previousWow
        )
    }
    if (-not $wowRejected) {
        throw 'Windows matrix self-test accepted WOW64.'
    }
    $root = Join-Path ([IO.Path]::GetTempPath()) (
        'winsvpn-mx-' + [Guid]::NewGuid().ToString('D')
    )
    New-Item -ItemType Directory -Path $root | Out-Null
    try {
        $files = [ordered]@{
            'windows-x64-installer' = 'WinsVPN-Setup.exe'
            'windows-x64-partner-center' = 'WinsVPN-PartnerCenter.exe'
            'windows-arm64-installer' = 'WinsVPN-Setup-arm64.exe'
            'windows-arm64-partner-center' = 'WinsVPN-PartnerCenter-arm64.exe'
        }
        $matrixRows = [Collections.Generic.List[object]]::new()
        $nonces = @(
            '11111111-1111-1111-1111-111111111111',
            '22222222-2222-2222-2222-222222222222',
            '33333333-3333-3333-3333-333333333333',
            '44444444-4444-4444-4444-444444444444'
        )
        $index = 0
        foreach ($targetId in @($files.Keys)) {
            $canonical = (Get-CanonicalWindowsMatrixTargets)[$targetId]
            $path = Join-Path $root $files[$targetId]
            [IO.File]::WriteAllBytes(
                $path, (New-MinimalPe32Plus ([int]$canonical.pe_machine))
            )
            $hostId = if ($canonical.architecture -ceq 'x64') {
                'windows-x64-host'
            } else {
                'windows-arm64-host'
            }
            [void]$matrixRows.Add((New-SelfTestAssignment `
                $targetId $hostId $path $nonces[$index]))
            $index += 1
        }
        $frozenRows = [object[]]::new($matrixRows.Count)
        $matrixRows.CopyTo($frozenRows)
        $envelope = @{ rows = $frozenRows }
        Assert-FourTargetCoverage -AssignmentSet $envelope
        Register-AssignmentAttempt $matrixRows[0] `
            'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        $staleFailed = $false
        try {
            Register-AssignmentAttempt $matrixRows[0] `
                'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        } catch {
            if ("$_" -notmatch 'Stale Windows matrix retry') { throw }
            $staleFailed = $true
        }
        if (-not $staleFailed) {
            throw 'Windows matrix self-test accepted a stale retry.'
        }
        $worker = New-WorkerInvocation $matrixRows[0] `
            '11111111-1111-1111-1111-111111111111' 'Prepare'
        if ($worker.argument_list -contains '-Command') {
            throw 'Worker invocation used string/shell injection.'
        }
        if ([string]$worker.architecture_expectation.architecture -cne
                [string]$matrixRows[0].architecture) {
            throw 'Worker invocation dropped architecture expectation.'
        }
        $inputs = [ordered]@{
            PayloadManifest = Join-Path $root 'payload.json'
            PayloadRoot = $root
            ReleaseInputIndex = Join-Path $root 'index.json'
            BuildReceipt = Join-Path $root 'receipt.json'
            CandidateManifest = Join-Path $root 'candidate.json'
            PreviousArtifact = Join-Path $root 'previous.exe'
            PreviousPayloadManifest = Join-Path $root 'previous.json'
            PreviousReleaseRecord = Join-Path $root 'previous-record.json'
            CredentialStore = Join-Path $root 'credentials.dat'
            Gazetteer = Join-Path $root 'gazetteer.json'
        }
        $collector = New-CollectorInvocation $matrixRows[0] $inputs
        $artifactIndex = [array]::IndexOf(
            @($collector.argument_list), '-Artifact'
        )
        if ($artifactIndex -lt 0 -or
            $collector.argument_list[$artifactIndex + 1] -cne
                [string]$matrixRows[0].candidate) {
            throw 'Collector invocation dropped the exact native candidate.'
        }
        if ([string]$collector.architecture_expectation.surface -cne
                [string]$matrixRows[0].surface) {
            throw 'Collector invocation dropped architecture/surface expectation.'
        }
        $duplicate = [Collections.Generic.List[object]]::new()
        foreach ($row in $matrixRows) { [void]$duplicate.Add($row) }
        [void]$duplicate.Add($matrixRows[0])
        $dupFailed = $false
        try { Assert-FourTargetCoverage -AssignmentSet @{ rows = $duplicate } } catch {
            if ("$_" -notmatch 'Duplicate Windows matrix assignment') { throw }
            $dupFailed = $true
        }
        if (-not $dupFailed) {
            throw 'Windows matrix self-test accepted duplicate assignments.'
        }
        $missing = [Collections.Generic.List[object]]::new()
        [void]$missing.Add($matrixRows[0])
        [void]$missing.Add($matrixRows[1])
        [void]$missing.Add($matrixRows[2])
        $coverFailed = $false
        try { Assert-FourTargetCoverage -AssignmentSet @{ rows = $missing } } catch {
            if ("$_" -notmatch 'wrong four-target coverage') { throw }
            $coverFailed = $true
        }
        if (-not $coverFailed) {
            throw 'Windows matrix self-test accepted wrong four-target coverage.'
        }
        $v3 = [ordered]@{
            contract = 'winsvpn-windows-winn-v3-receipt-v1'
            passed = $true
            architecture = 'x64'
            pe_machine = $PeMachineX64
            native_architecture = 'x64'
            os_architecture = 'X64'
            process_wow64 = $false
            sequence = 6
            primary_transport = 'winn_v3'
            fallback_transports = @('winn_v1_awg', 'winn_v1_xray')
            winn_v3_session_observed = $true
        }
        $awg = [ordered]@{
            contract = 'winsvpn-windows-winn-v1-awg-receipt-v1'
            passed = $true
            architecture = 'x64'
            pe_machine = $PeMachineX64
            native_architecture = 'x64'
            os_architecture = 'X64'
            process_wow64 = $false
            sequence = 7
            transport = 'winn_v1_awg'
            observed = $true
        }
        $xray = [ordered]@{
            contract = 'winsvpn-windows-winn-v1-xray-receipt-v1'
            passed = $true
            architecture = 'x64'
            pe_machine = $PeMachineX64
            native_architecture = 'x64'
            os_architecture = 'X64'
            process_wow64 = $false
            sequence = 8
            transport = 'winn_v1_xray'
            observed = $true
        }
        Assert-WinnEvidenceOrder -ReceiptSet @($v3, $awg, $xray)
        $swapped = [ordered]@{
            contract = 'winsvpn-windows-winn-v1-awg-receipt-v1'
            passed = $true
            architecture = 'x64'
            pe_machine = $PeMachineX64
            native_architecture = 'x64'
            os_architecture = 'X64'
            process_wow64 = $false
            sequence = 8
            transport = 'winn_v1_awg'
            observed = $true
        }
        $swappedXray = [ordered]@{
            contract = 'winsvpn-windows-winn-v1-xray-receipt-v1'
            passed = $true
            architecture = 'x64'
            pe_machine = $PeMachineX64
            native_architecture = 'x64'
            os_architecture = 'X64'
            process_wow64 = $false
            sequence = 7
            transport = 'winn_v1_xray'
            observed = $true
        }
        $orderFailed = $false
        try { Assert-WinnEvidenceOrder -ReceiptSet @($v3, $swapped, $swappedXray) } catch {
            if ("$_" -notmatch 'not after AWG') { throw }
            $orderFailed = $true
        }
        if (-not $orderFailed) {
            throw 'Windows matrix self-test accepted mixed Winn evidence order.'
        }
    } finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
    [void](Invoke-BoundedNative $Python @($Compiler, '--self-test') `
        -TimeoutMilliseconds $MaxChildTimeoutMs `
        -MaxOutputBytes $MaxChildOutputBytes)
}

function Assert-FixedPhysicalBundle {
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $base = [IO.Path]::GetFullPath(
        (Join-Path $env:ProgramData 'WinsVPN\ReleaseEvidence')
    ).TrimEnd('\') + '\'
    if (-not $full.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Windows bundle index must come from the fixed ProgramData collector root.'
    }
    $relative = $full.Substring($base.Length)
    if ($relative -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\bundle-index\.json$') {
        throw 'Windows bundle index path does not have the fixed run-id grammar.'
    }
    $current = [IO.Path]::GetPathRoot($full)
    foreach ($part in @($full.Substring($current.Length) -split '[\\/]' |
            Where-Object { $_ })) {
        $current = Join-Path $current $part
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Windows physical bundle contains a reparse component: $current"
        }
    }
    $runRoot = Split-Path -Parent $full
    foreach ($item in @(Get-Item -LiteralPath $runRoot -Force) + @(
            Get-ChildItem -LiteralPath $runRoot -Recurse -Force
        )) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Windows physical bundle contains a reparse entry: $($item.FullName)"
        }
        if ($item.LinkType -ceq 'HardLink' -or
            $item.LinkType -ceq 'SymbolicLink' -or
            $item.LinkType -ceq 'Junction') {
            throw "Windows physical bundle contains a hardlink substitution: $($item.FullName)"
        }
        $acl = Get-Acl -LiteralPath $item.FullName
        if (-not $acl.AreAccessRulesProtected) {
            throw "Windows physical bundle ACL is not protected: $($item.FullName)"
        }
        $identities = @($acl.Access | ForEach-Object {
            if ($_.AccessControlType -ne 'Allow' -or
                ($_.FileSystemRights -band
                    [Security.AccessControl.FileSystemRights]::FullControl) -ne
                    [Security.AccessControl.FileSystemRights]::FullControl) {
                throw "Windows physical bundle ACL contains a non-FullControl ACE: $($item.FullName)"
            }
            $_.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]
            ).Value
        } | Sort-Object -Unique)
        if (($identities -join '|') -cne 'S-1-5-18|S-1-5-32-544') {
            throw "Windows physical bundle ACL contains an unexpected identity: $($item.FullName)"
        }
    }
    $runName = Split-Path -Leaf $runRoot
    $parsedRun = [Guid]::Empty
    if (-not [Guid]::TryParseExact($runName, 'D', [ref]$parsedRun) -or
        $parsedRun -eq [Guid]::Empty -or
        $runName -cne $parsedRun.ToString('D')) {
        throw 'Windows physical bundle directory is not one canonical nonzero UUID.'
    }
    $stream = Open-ExclusiveFile $full ([IO.FileMode]::Open) ([IO.FileAccess]::Read)
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt 8388608) {
            throw 'Windows bundle index size is invalid.'
        }
        $reader = [IO.StreamReader]::new(
            $stream, [Text.UTF8Encoding]::new($false, $true), $true, 4096, $true
        )
        try { $document = $reader.ReadToEnd() | ConvertFrom-Json }
        finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
    $indexRun = [Guid]::Empty
    if (-not [Guid]::TryParseExact([string]$document.run_id, 'D', [ref]$indexRun) -or
        $indexRun -eq [Guid]::Empty -or
        [string]$document.run_id -cne $indexRun.ToString('D') -or
        [string]$document.run_id -cne $runName) {
        throw 'Windows bundle directory name does not equal its canonical index run UUID.'
    }
}

function Assert-ExpectedArchitectureToken {
    param([string]$Value, [string]$Label)
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    if ($Value -cne 'x64' -and $Value -cne 'arm64' -and
        $Value -cne 'website' -and $Value -cne 'partner-center') {
        throw "$Label must be one exact native x64/arm64 or website/partner-center token."
    }
}

if ($SelfTest) {
    Invoke-MatrixDriverSelfTest
    Write-Output 'WINDOWS_RELEASE_MATRIX_DRIVER_SELF_TEST=PASS'
    exit 0
}

if (-not [string]::IsNullOrWhiteSpace($Assignments) -and
    -not [string]::IsNullOrWhiteSpace($EvidenceBundleIndex)) {
    throw 'Windows matrix driver refuses mixed assignment and compile modes.'
}

if (-not [string]::IsNullOrWhiteSpace($Assignments)) {
    throw 'Windows matrix collection refuses a partial false green without four native host results; this driver does not invent host evidence.'
}

Assert-ExpectedArchitectureToken $ExpectedArchitecture 'ExpectedArchitecture'
Assert-ExpectedArchitectureToken $ExpectedSurface 'ExpectedSurface'
if ($ExpectedArchitecture -cne '' -and
    $ExpectedArchitecture -cne 'x64' -and
    $ExpectedArchitecture -cne 'arm64') {
    throw 'ExpectedArchitecture must be x64 or arm64.'
}
if ($ExpectedSurface -cne '' -and
    $ExpectedSurface -cne 'website' -and
    $ExpectedSurface -cne 'partner-center') {
    throw 'ExpectedSurface must be website or partner-center.'
}

foreach ($entry in @(
    @{ Name = 'EvidenceBundleIndex'; Value = $EvidenceBundleIndex },
    @{ Name = 'Artifact'; Value = $Artifact },
    @{ Name = 'MapScreenshot'; Value = $MapScreenshot },
    @{ Name = 'ReleaseInputIndex'; Value = $ReleaseInputIndex },
    @{ Name = 'BuildReceipt'; Value = $BuildReceipt }
)) {
    if ([string]::IsNullOrWhiteSpace([string]$entry.Value) -or
        -not (Test-Path -LiteralPath ([string]$entry.Value) -PathType Leaf)) {
        throw "$($entry.Name) must name an existing regular file."
    }
}
if ([string]::IsNullOrWhiteSpace($Output)) {
    throw 'Output is required; the driver never invents or overwrites evidence paths.'
}
Assert-FixedPhysicalBundle $EvidenceBundleIndex
$artifactPe = Get-PeArchitecture $Artifact
if ($ExpectedArchitecture -cne '' -and
    $artifactPe.Name -cne $ExpectedArchitecture) {
    throw 'Windows matrix architecture is mixed, WOW64, or unsupported.'
}
if ($ExpectedSurface -cne '') {
    $leaf = [IO.Path]::GetFileName($Artifact)
    $matchedSurface = $false
    foreach ($target in (Get-CanonicalWindowsMatrixTargets).GetEnumerator()) {
        if ([string]$target.Value.surface -ceq $ExpectedSurface -and
            [string]$target.Value.architecture -ceq $artifactPe.Name -and
            [string]$target.Value.filename -ceq $leaf) {
            $matchedSurface = $true
        }
    }
    if (-not $matchedSurface) {
        throw 'Windows matrix candidate filename does not match the exact target.'
    }
}
$outputFull = [IO.Path]::GetFullPath($Output)
$evidenceRoot = [IO.Path]::GetFullPath(
    (Join-Path $RepoRoot '.artifacts\release-evidence')
).TrimEnd('\') + '\'
Assert-SafeEvidencePath $outputFull $evidenceRoot -MustNotExist
if (-not $outputFull.StartsWith(
        $evidenceRoot,
        [StringComparison]::OrdinalIgnoreCase
    )) {
    throw 'Compiled Windows native evidence must stay under .artifacts\release-evidence.'
}
New-Item -ItemType Directory -Force -Path ([IO.Path]::GetDirectoryName($outputFull)) |
    Out-Null
Assert-NoReparsePath ([IO.Path]::GetDirectoryName($outputFull))

$freeze = Join-Path $PSScriptRoot 'release_dependency_freeze.py'
[void](Invoke-BoundedNative $Python @(
    $freeze, 'verify-index', '--repo', $RepoRoot, '--index', $ReleaseInputIndex
))
[void](Invoke-BoundedNative $Python @(
    $freeze, 'verify-receipt', '--repo', $RepoRoot, '--index', $ReleaseInputIndex,
    '--platform', 'windows', '--receipt', $BuildReceipt, '--artifact', $Artifact
))

$index = Get-Content -LiteralPath $ReleaseInputIndex -Raw | ConvertFrom-Json
$windowsReference = $index.platform_manifests.windows
if ($null -eq $windowsReference -or
    [string]$windowsReference.sha256 -notmatch '^[0-9a-f]{64}$' -or
    [string]$windowsReference.artifact_input_fingerprint_sha256 `
        -notmatch '^[0-9a-f]{64}$') {
    throw 'Release input index lacks the exact Windows platform binding.'
}
$indexSha = (Get-FileHash -LiteralPath $ReleaseInputIndex -Algorithm SHA256).Hash.ToLowerInvariant()
$receiptSha = (Get-FileHash -LiteralPath $BuildReceipt -Algorithm SHA256).Hash.ToLowerInvariant()
$producerFiles = @(
    'tools/windows_public_release_live_smoke.ps1',
    'tools/windows_release_matrix_driver.ps1',
    'tools/windows_release_matrix_evidence.py',
    'tools/windows_invoke_vpn_power.ps1',
    'tools/windows_semantic_transition_probe.ps1',
    'tools/windows_test_failsafe_watchdog.ps1',
    'tools/public_release_live_smoke_common.py',
    'tools/validate_release_artifact_privacy.py',
    'tools/release_obfuscation_contract.py',
    'tools/release_dependency_freeze.py'
)
$producerHash = [Security.Cryptography.IncrementalHash]::CreateHash(
    [Security.Cryptography.HashAlgorithmName]::SHA256
)
try {
    foreach ($relative in $producerFiles) {
        $path = Join-Path $RepoRoot $relative
        $producerHash.AppendData([Text.Encoding]::UTF8.GetBytes("$relative`0"))
        $stream = Open-ExclusiveFile $path ([IO.FileMode]::Open) (
            [IO.FileAccess]::Read
        )
        try {
            $buffer = [byte[]]::new(1048576)
            while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $producerHash.AppendData($buffer, 0, $count)
            }
        } finally { $stream.Dispose() }
        $producerHash.AppendData([byte[]]@(0))
    }
    $producerSha = ([BitConverter]::ToString(
        $producerHash.GetHashAndReset()
    )).Replace('-', '').ToLowerInvariant()
} finally { $producerHash.Dispose() }
if ($producerSha -notmatch '^[0-9a-f]{64}$') {
    throw 'Unable to compute the exact Windows public producer closure.'
}

$collectorFiles = @(
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
$incremental = [Security.Cryptography.IncrementalHash]::CreateHash(
    [Security.Cryptography.HashAlgorithmName]::SHA256
)
try {
    foreach ($relative in $collectorFiles) {
        $path = Join-Path $RepoRoot $relative
        $incremental.AppendData([Text.Encoding]::UTF8.GetBytes("$relative`0"))
        $stream = Open-ExclusiveFile $path ([IO.FileMode]::Open) (
            [IO.FileAccess]::Read
        )
        try {
            $buffer = [byte[]]::new(1048576)
            while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $incremental.AppendData($buffer, 0, $count)
            }
        } finally { $stream.Dispose() }
        $incremental.AppendData([byte[]]@(0))
    }
    $collectorClosure = ([BitConverter]::ToString(
        $incremental.GetHashAndReset()
    )).Replace('-', '').ToLowerInvariant()
} finally { $incremental.Dispose() }

[void](Invoke-BoundedNative $Python @(
    $Compiler,
    '--bundle-index', $EvidenceBundleIndex,
    '--artifact', $Artifact,
    '--map-screenshot', $MapScreenshot,
    '--output', $outputFull,
    '--release-input-index-sha256', $indexSha,
    '--platform-manifest-sha256', ([string]$windowsReference.sha256),
    '--artifact-input-fingerprint-sha256',
        ([string]$windowsReference.artifact_input_fingerprint_sha256),
    '--build-receipt-sha256', $receiptSha,
    '--producer-contract-sha256', $producerSha,
    '--collector-closure-sha256', $collectorClosure
))
Write-Output "WINDOWS_RELEASE_MATRIX_DRIVER=PASS transcript=$outputFull"
