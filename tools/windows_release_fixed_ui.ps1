[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern(
        '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )][string]$RunId,
    [Parameter(Mandatory)][ValidateSet(
        'InspectConnect', 'InspectCancel', 'InspectDisconnect',
        'Connect', 'Cancel', 'Disconnect', 'OpenSplit', 'InspectSplitPanel',
        'InspectMapRadius', 'InspectMapMarker'
    )][string]$Action
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RunRoot = Join-Path $env:ProgramData "WinsVPN\ReleaseEvidence\$RunId"
$PrivateRoot = Join-Path $RunRoot 'private'
$ExpectedSelf = Join-Path $RunRoot 'helpers\windows_release_fixed_ui.ps1'
$InstallRoot = Join-Path $env:ProgramFiles 'WinsVPN'
$InstalledGui = Join-Path $InstallRoot 'wins_vpn.exe'
$InstalledAwgEngine = Join-Path $InstallRoot 'winsvpn_awg_engine.exe'
$InstalledWinn3 = Join-Path $InstallRoot 'winsvpn_winn3_engine.exe'
$InstalledXray = Join-Path $InstallRoot 'xray.exe'
$OpenReparsePoint = [IO.FileOptions]0x00200000
$PeMachineX64 = 0x8664
$PeMachineArm64 = 0xAA64
$ReparseAttribute = [uint32]0x400
$MaxObservationBytes = 65536
$script:ArchitectureBinding = $null

function Get-BytesSha256 {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes
    )
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($algorithm.ComputeHash($Bytes))).Replace(
            '-', ''
        ).ToLowerInvariant()
    } finally { $algorithm.Dispose() }
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
            throw "Fixed UI path contains a reparse point: $current"
        }
    }
}

function Assert-OpenedFileIdentity {
    param(
        [Parameter(Mandatory)][IO.FileStream]$Stream,
        [Parameter(Mandatory)][string]$Path
    )
    if (-not ('WinsVpnFixedUiByHandleInfo' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WinsVpnFixedUiByHandleInfo {
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
    $info = New-Object WinsVpnFixedUiByHandleInfo+BY_HANDLE_FILE_INFORMATION
    $handle = $Stream.SafeFileHandle.DangerousGetHandle()
    if (-not [WinsVpnFixedUiByHandleInfo]::GetFileInformationByHandle(
            $handle, [ref]$info
        )) {
        throw "Fixed UI handle identity is unavailable: $Path"
    }
    if (($info.dwFileAttributes -band $ReparseAttribute) -ne 0) {
        throw "Fixed UI descriptor opened a reparse point: $Path"
    }
    if ($info.nNumberOfLinks -ne 1) {
        throw "Fixed UI path is a hardlink substitution: $Path"
    }
}

function Open-ExclusiveFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][IO.FileMode]$Mode,
        [Parameter(Mandatory)][IO.FileAccess]$Access,
        [IO.FileShare]$Share = [IO.FileShare]::None
    )
    if ($Mode -eq [IO.FileMode]::CreateNew) {
        Assert-NoReparsePath ([IO.Path]::GetDirectoryName((
            [IO.Path]::GetFullPath($Path)
        )))
    } else {
        Assert-NoReparsePath $Path
    }
    $stream = [IO.FileStream]::new(
        $Path, $Mode, $Access, $Share, 1048576, $OpenReparsePoint
    )
    try {
        Assert-OpenedFileIdentity $stream $Path
        if ($Mode -ne [IO.FileMode]::CreateNew) {
            $item = Get-Item -LiteralPath $Path -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Fixed UI descriptor opened a reparse point: $Path"
            }
        }
    } catch {
        $stream.Dispose()
        throw
    }
    $stream
}

function Get-Sha256 {
    param(
        [Parameter(Mandatory)][string]$Path,
        [IO.FileShare]$Share = [IO.FileShare]::None
    )
    $stream = Open-ExclusiveFile $Path ([IO.FileMode]::Open) ([IO.FileAccess]::Read) $Share
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt 536870912) {
            throw "Fixed UI hash input size is unbounded or empty: $Path"
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
    $stream = Open-ExclusiveFile $Path ([IO.FileMode]::Open) ([IO.FileAccess]::Read) `
        ([IO.FileShare]::Read)
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
        throw 'Fixed UI must not run under WOW64.'
    }
    $osArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $processArch = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    if ($processArch -cne $osArch) {
        throw 'Fixed UI must not run under WOW64.'
    }
    switch ($osArch) {
        'X64' { 'x64' }
        'Arm64' { 'arm64' }
        default { throw "Unsupported Windows OS architecture: $osArch" }
    }
}

function Get-BindingProperty {
    param(
        [Parameter(Mandatory)]$Binding,
        [Parameter(Mandatory)][string]$Name
    )
    if ($Binding -is [Collections.IDictionary]) {
        if (-not $Binding.Contains($Name)) {
            throw 'Fixed UI omitted architecture binding.'
        }
        return $Binding[$Name]
    }
    $property = $Binding.PSObject.Properties[$Name]
    if (-not $property) {
        throw 'Fixed UI omitted architecture binding.'
    }
    $property.Value
}

function Assert-ArchitectureBinding {
    param($Binding)
    if ($null -eq $Binding) {
        throw 'Fixed UI omitted architecture binding.'
    }
    $architecture = [string](Get-BindingProperty $Binding 'architecture')
    $native = [string](Get-BindingProperty $Binding 'native_architecture')
    $osArchitecture = [string](Get-BindingProperty $Binding 'os_architecture')
    $peMachine = Get-BindingProperty $Binding 'pe_machine'
    $wow64 = Get-BindingProperty $Binding 'process_wow64'
    if ([string]::IsNullOrEmpty($architecture) -or
        [string]::IsNullOrEmpty($native) -or
        [string]::IsNullOrEmpty($osArchitecture) -or
        $null -eq $peMachine) {
        throw 'Fixed UI omitted architecture binding.'
    }
    if ($architecture -cne 'x64' -and $architecture -cne 'arm64') {
        throw "Unsupported fixed UI PE architecture: $architecture"
    }
    $expectedMachine = if ($architecture -ceq 'x64') { $PeMachineX64 } else {
        $PeMachineArm64
    }
    $expectedOs = if ($architecture -ceq 'x64') { 'X64' } else { 'Arm64' }
    if ($native -cne $architecture -or
        $osArchitecture -cne $expectedOs -or
        [int]$peMachine -ne [int]$expectedMachine -or
        $wow64 -ne $false) {
        throw 'Fixed UI architecture binding is mixed, WOW64, or unsupported.'
    }
    $hostArch = Get-NativeWindowsArchitecture
    if ($hostArch -cne $native) {
        throw "Host OS architecture $hostArch does not match bound PE architecture $native."
    }
}

function Resolve-ObservedTransport {
    param(
        [Parameter(Mandatory)][int]$Winn3Count,
        [Parameter(Mandatory)][int]$AwgCount,
        [Parameter(Mandatory)][int]$XrayCount,
        [Parameter(Mandatory)][int]$UnboundCount
    )
    if ($UnboundCount -ne 0) {
        throw 'Fixed UI observed an unbound engine process.'
    }
    if ($Winn3Count -gt 1 -or $AwgCount -gt 1 -or $XrayCount -gt 1) {
        throw 'Fixed UI observed mixed Winn v3/v1 transports.'
    }
    if ($Winn3Count -eq 1 -and $AwgCount -eq 0 -and $XrayCount -eq 0) {
        return 'winn_v3'
    }
    if ($Winn3Count -eq 0 -and $AwgCount -eq 1 -and $XrayCount -eq 0) {
        return 'winn_v1_awg'
    }
    if ($Winn3Count -eq 0 -and $AwgCount -eq 1 -and $XrayCount -eq 1) {
        return 'winn_v1_xray'
    }
    if ($Winn3Count -eq 0 -and $AwgCount -eq 0 -and $XrayCount -eq 0) {
        return 'disconnected'
    }
    throw 'Fixed UI observed mixed Winn v3/v1 transports.'
}

function Assert-PhaseBoundUiAction {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Observed
    )
    $allowed = @{
        InspectConnect = @('disconnected', 'winn_v3', 'winn_v1_awg', 'winn_v1_xray')
        Connect = @('disconnected')
        InspectCancel = @('disconnected', 'winn_v3', 'winn_v1_awg', 'winn_v1_xray')
        Cancel = @('disconnected', 'winn_v3', 'winn_v1_awg', 'winn_v1_xray')
        InspectDisconnect = @('winn_v3', 'winn_v1_awg', 'winn_v1_xray')
        Disconnect = @('winn_v3', 'winn_v1_awg', 'winn_v1_xray')
        OpenSplit = @('disconnected')
        InspectSplitPanel = @('disconnected')
        InspectMapRadius = @('winn_v3', 'winn_v1_awg', 'winn_v1_xray')
        InspectMapMarker = @('winn_v3', 'winn_v1_awg', 'winn_v1_xray')
    }
    if (-not $allowed.ContainsKey($Action) -or $Observed -cnotin $allowed[$Action]) {
        throw "Fixed UI action $Action is not phase-bound to the observed Winn transport."
    }
}

function Test-ExactImage {
    param([int]$Pid, [string]$Path, [string]$Sha256)
    if ($Pid -le 0 -or [string]::IsNullOrWhiteSpace($Path) -or
        $Sha256 -notmatch '^[0-9a-f]{64}$') { return $false }
    $process = Get-Process -Id $Pid -ErrorAction SilentlyContinue
    if (-not $process) { return $false }
    try { $actualPath = $process.Path } catch { return $false }
    if ([IO.Path]::GetFullPath($actualPath) -cne [IO.Path]::GetFullPath($Path)) {
        return $false
    }
    (Get-Sha256 $actualPath ([IO.FileShare]::Read)) -ceq $Sha256
}

function Get-BoundEngineCount {
    param(
        [Parameter(Mandatory)][string]$ProcessName,
        [Parameter(Mandatory)][string]$Path
    )
    $processes = @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
    if ($processes.Count -eq 0) { return 0 }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Fixed UI observed an unbound $ProcessName process."
    }
    Assert-NoReparsePath $Path
    $sha = Get-Sha256 $Path ([IO.FileShare]::Read)
    $pe = Get-PeArchitecture $Path
    if ($pe.Name -cne [string]$script:ArchitectureBinding.architecture -or
        [int]$pe.Machine -ne [int]$script:ArchitectureBinding.pe_machine) {
        throw "Fixed UI $ProcessName PE architecture is mixed with the native host."
    }
    foreach ($process in $processes) {
        if (-not (Test-ExactImage -Pid $process.Id -Path $Path -Sha256 $sha)) {
            throw "Fixed UI observed an unbound $ProcessName process."
        }
    }
    $processes.Count
}

function Read-JsonOnce {
    param([Parameter(Mandatory)][string]$Path)
    $stream = Open-ExclusiveFile $Path ([IO.FileMode]::Open) ([IO.FileAccess]::Read)
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt 4194304) {
            throw 'Fixed UI context size is invalid.'
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -le 0) { throw 'Fixed UI context changed during read.' }
            $offset += $count
        }
    } finally { $stream.Dispose() }
    ([Text.UTF8Encoding]::new($false, $true).GetString($bytes) |
        ConvertFrom-Json)
}

foreach ($key in @($PSBoundParameters.Keys)) {
    if ($key -cne 'RunId' -and $key -cne 'Action') {
        throw 'Fixed UI rejected unsafe or extra arguments.'
    }
}
if (-not [Environment]::UserInteractive) {
    throw "Win's VPN fixed UI bridge requires the signed-in interactive session."
}
$parsedRunId = [Guid]::Empty
if (-not [Guid]::TryParseExact($RunId, 'D', [ref]$parsedRunId) -or
    $parsedRunId -eq [Guid]::Empty -or
    $RunId -cne $parsedRunId.ToString('D') -or
    (Split-Path -Leaf $RunRoot) -cne $RunId) {
    throw 'Fixed UI run identity/path is not one canonical nonzero UUID.'
}
$expectedRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramData "WinsVPN\ReleaseEvidence\$RunId")
)
if ([IO.Path]::GetFullPath($RunRoot) -cne $expectedRoot) {
    throw 'Fixed UI escaped the fixed ReleaseEvidence root.'
}
[void](Get-NativeWindowsArchitecture)
Assert-NoReparsePath $RunRoot
Assert-NoReparsePath $PrivateRoot
Assert-NoReparsePath $ExpectedSelf
if ([IO.Path]::GetFullPath($PSCommandPath) -cne [IO.Path]::GetFullPath($ExpectedSelf)) {
    throw 'Fixed UI bridge must execute only from the locked helper root.'
}
$context = Read-JsonOnce (Join-Path $PrivateRoot 'context.json')
$runtime = Read-JsonOnce (Join-Path $PrivateRoot 'runtime-context.json')
if ($context.run_id -cne $RunId -or $context.contract -cne
    'winsvpn-windows-release-collector-context-v1' -or
    $runtime.run_id -cne $RunId -or
    $runtime.contract -cne 'winsvpn-windows-release-runtime-context-v1' -or
    $runtime.collector_closure_sha256 -cne
        $context.collector_closure_sha256) {
    throw 'Fixed UI context binding is invalid.'
}
$contextSourceOnly = $context.PSObject.Properties['source_only']
if (-not $contextSourceOnly -or $contextSourceOnly.Value -ne $false) {
    throw 'Fixed UI refused a source-only substitution.'
}
$runtimeSourceOnly = $runtime.PSObject.Properties['source_only']
if ($runtimeSourceOnly -and $runtimeSourceOnly.Value -ne $false) {
    throw 'Fixed UI refused a source-only substitution.'
}
Assert-ArchitectureBinding $context
Assert-ArchitectureBinding $runtime
if ([string](Get-BindingProperty $runtime 'architecture') -cne
        [string](Get-BindingProperty $context 'architecture') -or
    [int](Get-BindingProperty $runtime 'pe_machine') -ne
        [int](Get-BindingProperty $context 'pe_machine') -or
    [string](Get-BindingProperty $runtime 'native_architecture') -cne
        [string](Get-BindingProperty $context 'native_architecture')) {
    throw 'Fixed UI runtime/context architecture binding is mixed.'
}
$script:ArchitectureBinding = [ordered]@{
    architecture = [string](Get-BindingProperty $runtime 'architecture')
    pe_machine = [int](Get-BindingProperty $runtime 'pe_machine')
    native_architecture = [string](Get-BindingProperty $runtime 'native_architecture')
    os_architecture = [string](Get-BindingProperty $runtime 'os_architecture')
    process_wow64 = $false
}
$closure = Read-JsonOnce (Join-Path $PrivateRoot 'collector-closure.json')
$selfEntry = @($closure.files | Where-Object {
    $_.name -ceq 'windows_release_fixed_ui.ps1'
})
if ($closure.sha256 -cne $context.collector_closure_sha256 -or
    $selfEntry.Count -ne 1 -or
    (Get-Sha256 $PSCommandPath) -cne [string]$selfEntry[0].sha256) {
    throw 'Fixed UI helper is not collector-closure-bound.'
}

Add-Type -AssemblyName Accessibility
$accessibilityAssembly = [Accessibility.IAccessible].Assembly.Location
Add-Type -ReferencedAssemblies $accessibilityAssembly -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Accessibility;

public static class WinsVpnFixedMsaa {
    private const uint ObjIdClient = 0xFFFFFFFC;
    private const int ChildSelf = 0;
    private const int MaxNodes = 10000;
    private const int MaxDepth = 64;
    [DllImport("oleacc.dll")]
    private static extern int AccessibleObjectFromWindow(
        IntPtr window, uint objectId, ref Guid iid,
        [MarshalAs(UnmanagedType.Interface)] out object accessible);
    [DllImport("oleacc.dll")]
    private static extern int AccessibleChildren(
        [MarshalAs(UnmanagedType.Interface)] IAccessible container,
        int start, int count,
        [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] object[] children,
        out int obtained);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr FindWindowEx(
        IntPtr parent, IntPtr childAfter, string className, string windowName);
    [DllImport("user32.dll")] private static extern bool EnumWindows(
        EnumWindowCallback callback, IntPtr state);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(
        IntPtr window, out uint processId);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] private static extern IntPtr GetParent(IntPtr window);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassName(
        IntPtr window, System.Text.StringBuilder className, int capacity);
    [DllImport("dwmapi.dll")] private static extern int DwmGetWindowAttribute(
        IntPtr window, uint attribute, out int value, int size);
    private delegate bool EnumWindowCallback(IntPtr window, IntPtr state);
    public static IntPtr FindExactTopLevelWindow(uint expectedProcessId) {
        IntPtr match = IntPtr.Zero;
        int matches = 0;
        EnumWindows(delegate(IntPtr window, IntPtr state) {
            uint processId;
            GetWindowThreadProcessId(window, out processId);
            if (processId != expectedProcessId || !IsWindowVisible(window) ||
                GetParent(window) != IntPtr.Zero) return true;
            var className = new System.Text.StringBuilder(128);
            GetClassName(window, className, className.Capacity);
            if (!String.Equals(className.ToString(), "FLUTTER_RUNNER_WIN32_WINDOW",
                    StringComparison.Ordinal)) return true;
            int cloaked = 0;
            if (DwmGetWindowAttribute(window, 14, out cloaked, 4) == 0 && cloaked != 0)
                return true;
            match = window;
            matches++;
            return true;
        }, IntPtr.Zero);
        return matches == 1 ? match : IntPtr.Zero;
    }
    public sealed class Match {
        internal IAccessible Owner;
        internal object Child;
        public string Label;
        public int Role;
        public int State;
        public string DefaultAction;
    }
    private static Match Candidate(IAccessible owner, object child, string label) {
        try {
            if (!String.Equals(owner.get_accName(child) ?? "", label,
                    StringComparison.Ordinal)) return null;
            return new Match {
                Owner = owner, Child = child, Label = label,
                Role = Convert.ToInt32(owner.get_accRole(child)),
                State = Convert.ToInt32(owner.get_accState(child)),
                DefaultAction = owner.get_accDefaultAction(child) ?? ""
            };
        } catch { return null; }
    }
    private static Match Find(IAccessible node, string label, int depth, ref int seen) {
        if (node == null || depth > MaxDepth || seen++ > MaxNodes) return null;
        // The FLUTTERVIEW root can mirror a descendant's label without an
        // actionable child ID.  Match descendants exactly; never invoke the
        // synthetic root-self mirror.
        Match own = depth > 0 ? Candidate(node, ChildSelf, label) : null;
        if (own != null) return own;
        int count;
        try { count = node.accChildCount; } catch { return null; }
        if (count < 1 || count > MaxNodes - seen) return null;
        object[] children = new object[count]; int obtained;
        if (AccessibleChildren(node, 0, count, children, out obtained) < 0) return null;
        for (int i = 0; i < obtained; i++) {
            IAccessible nested = children[i] as IAccessible;
            Match match = nested != null
                ? Find(nested, label, depth + 1, ref seen)
                : Candidate(node, children[i], label);
            if (match != null) return match;
        }
        return null;
    }
    public static Match Find(IntPtr window, string label) {
        Guid iid = new Guid("618736E0-3C3D-11CF-810C-00AA00389B71");
        object raw;
        if (AccessibleObjectFromWindow(window, ObjIdClient, ref iid, out raw) < 0)
            return null;
        int seen = 0;
        return Find(raw as IAccessible, label, 0, ref seen);
    }
    public static void Invoke(Match match) {
        match.Owner.accDoDefaultAction(match.Child);
    }
}
'@

$pidValue = [int]$runtime.candidate_pid
$expectedPath = [IO.Path]::GetFullPath([string]$runtime.installed_gui_path)
if ($expectedPath -cne [IO.Path]::GetFullPath($InstalledGui)) {
    throw 'Fixed UI candidate path escaped the native install root.'
}
$process = Get-Process -Id $pidValue -ErrorAction Stop
$mainWindowHandle = [WinsVpnFixedMsaa]::FindExactTopLevelWindow([uint32]$pidValue)
if ($process.SessionId -ne (Get-Process -Id $PID).SessionId -or
    $process.SessionId -ne [int]$runtime.candidate_session_id -or
    $mainWindowHandle -eq [IntPtr]::Zero -or
    [IO.Path]::GetFullPath($process.Path) -cne $expectedPath -or
    (Get-Sha256 $process.Path ([IO.FileShare]::Read)) `
        -cne [string]$runtime.installed_gui_sha256) {
    throw 'Fixed UI candidate PID/session/window/path/hash binding failed.'
}
$signature = Get-AuthenticodeSignature -LiteralPath $process.Path
if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) {
    throw 'Fixed UI candidate executable does not retain valid Authenticode.'
}
$candidatePe = Get-PeArchitecture $process.Path
if ($candidatePe.Name -cne [string]$script:ArchitectureBinding.architecture -or
    [int]$candidatePe.Machine -ne [int]$script:ArchitectureBinding.pe_machine) {
    throw 'Fixed UI candidate PE architecture is mixed with the native host.'
}
if ([IO.Path]::GetFullPath([string]$runtime.installed_awg_engine_path) -cne
        [IO.Path]::GetFullPath($InstalledAwgEngine) -or
    [string]$runtime.installed_awg_engine_sha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'Fixed UI AWG engine path is stale or escaped the native install root.'
}

$winn3Count = Get-BoundEngineCount 'winsvpn_winn3_engine' $InstalledWinn3
$awgCount = Get-BoundEngineCount 'winsvpn_awg_engine' $InstalledAwgEngine
$xrayCount = Get-BoundEngineCount 'xray' $InstalledXray
if ($awgCount -gt 0 -and
    (Get-Sha256 $InstalledAwgEngine ([IO.FileShare]::Read)) -cne
        [string]$runtime.installed_awg_engine_sha256) {
    throw 'Fixed UI AWG engine hash is stale or substituted.'
}
$observedTransport = Resolve-ObservedTransport -Winn3Count $winn3Count `
    -AwgCount $awgCount -XrayCount $xrayCount -UnboundCount 0
Assert-PhaseBoundUiAction -Action $Action -Observed $observedTransport

$accessibilityHandle = [WinsVpnFixedMsaa]::FindWindowEx(
    $mainWindowHandle, [IntPtr]::Zero, 'FLUTTERVIEW', $null
)
if ($accessibilityHandle -eq [IntPtr]::Zero) {
    throw 'The exact candidate has no FLUTTERVIEW accessibility root.'
}

$expectedLabel = switch -Regex ($Action) {
    'OpenSplit$' { 'Split Tunneling'; break }
    'InspectSplitPanel$' {
        'Destinations outside VPN (all operating systems)'; break
    }
    'InspectMapRadius$' { 'Approximate IP location'; break }
    'InspectMapMarker$' { 'Your approximate network location'; break }
    'Connect$' { 'Connect VPN'; break }
    'Cancel$' { 'Cancel VPN connection'; break }
    'Disconnect$' { 'Disconnect VPN'; break }
}
$match = $null
$deadline = [DateTime]::UtcNow.AddSeconds(12)
do {
    $match = [WinsVpnFixedMsaa]::Find($accessibilityHandle, $expectedLabel)
    if (-not $match) { Start-Sleep -Milliseconds 200 }
} while (-not $match -and [DateTime]::UtcNow -lt $deadline)
if (-not $match) {
    throw "Exact semantic VPN control is missing: $expectedLabel"
}
$invokableButton = $Action -notin @(
    'InspectSplitPanel', 'InspectMapRadius', 'InspectMapMarker'
)
if ($invokableButton -and $match.Role -ne 43) {
    throw "Exact semantic VPN control has an invalid push-button role: $expectedLabel"
}
$visible = ($match.State -band 0x8000) -eq 0
$accessibilityOffscreen = ($match.State -band 0x10000) -ne 0
$enabled = ($match.State -band 0x1) -eq 0
if (-not $visible -or -not $enabled) {
    throw "Exact semantic VPN control is not visible and enabled: $expectedLabel"
}
$invoked = $invokableButton -and
    -not $Action.StartsWith('Inspect', [StringComparison]::Ordinal)
$invocationMethod = if ($invoked) {
    [WinsVpnFixedMsaa]::Invoke($match)
    'flutterview_semantic_default_action'
} else { 'inspection_only' }
$json = [ordered]@{
    contract = 'winsvpn-windows-fixed-ui-observation-v1'
    run_id = $RunId
    captured_at_utc = [DateTime]::UtcNow.ToString('o')
    action = $Action
    label = $match.Label
    role = $match.Role
    default_action_sha256 = Get-BytesSha256 (
        [Text.UTF8Encoding]::new($false).GetBytes($match.DefaultAction)
    )
    visible = $visible
    accessibility_offscreen = $accessibilityOffscreen
    enabled = $enabled
    invoked = $invoked
    invocation_method = $invocationMethod
    candidate_pid = $pidValue
    session_id = $process.SessionId
    main_window_handle = $mainWindowHandle.ToInt64()
    accessibility_root = 'FLUTTERVIEW'
    primary_transport = 'winn_v3'
    fallback_transports = @('winn_v1_awg', 'winn_v1_xray')
    observed_transport = $observedTransport
    source_only = $false
    architecture = [string]$script:ArchitectureBinding.architecture
    pe_machine = [int]$script:ArchitectureBinding.pe_machine
    native_architecture = [string]$script:ArchitectureBinding.native_architecture
    os_architecture = [string]$script:ArchitectureBinding.os_architecture
    process_wow64 = $false
} | ConvertTo-Json -Depth 4 -Compress
$jsonBytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
if ($jsonBytes.Length -lt 1 -or $jsonBytes.Length -gt $MaxObservationBytes) {
    throw 'Fixed UI JSON output size is unbounded.'
}
$json
