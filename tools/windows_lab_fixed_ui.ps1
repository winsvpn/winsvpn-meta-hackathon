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
$RunRoot = Join-Path $env:ProgramData "WinsVPN\LabEvidence\$RunId"
$PrivateRoot = Join-Path $RunRoot 'private'
$ExpectedSelf = Join-Path $RunRoot 'helpers\windows_lab_fixed_ui.ps1'

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
        $current = Join-Path $current $part
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Fixed UI path contains a reparse point: $current"
        }
    }
}

function Read-JsonOnce {
    param([Parameter(Mandatory)][string]$Path)
    Assert-NoReparsePath $Path
    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None
    )
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
Assert-NoReparsePath $RunRoot
if ([IO.Path]::GetFullPath($PSCommandPath) -cne [IO.Path]::GetFullPath($ExpectedSelf)) {
    throw 'Fixed UI bridge must execute only from the locked helper root.'
}
$context = Read-JsonOnce (Join-Path $PrivateRoot 'context.json')
$runtime = Read-JsonOnce (Join-Path $PrivateRoot 'runtime-context.json')
if ($context.run_id -cne $RunId -or $context.contract -cne
    'winsvpn-windows-lab-collector-context-v1' -or
    $context.evidence_class -cne 'nonpublishable_lab' -or
    $context.lab_only -ne $true -or
    $context.publication_authorized -ne $false -or
    $context.public_release_gate_eligible -ne $false -or
    $context.unsigned_local_candidate -ne $true -or
    $runtime.run_id -cne $RunId -or
    $runtime.collector_closure_sha256 -cne
        $context.collector_closure_sha256) {
    throw 'Fixed UI context binding is invalid.'
}
$closure = Read-JsonOnce (Join-Path $PrivateRoot 'collector-closure.json')
$selfEntry = @($closure.files | Where-Object {
    $_.name -ceq 'windows_lab_fixed_ui.ps1'
})
if ($closure.sha256 -cne $context.collector_closure_sha256 -or
    $selfEntry.Count -ne 1 -or
    (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant() `
        -cne [string]$selfEntry[0].sha256) {
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
$process = Get-Process -Id $pidValue -ErrorAction Stop
$mainWindowHandle = [WinsVpnFixedMsaa]::FindExactTopLevelWindow([uint32]$pidValue)
if ($process.SessionId -ne (Get-Process -Id $PID).SessionId -or
    $process.SessionId -ne [int]$runtime.candidate_session_id -or
    $mainWindowHandle -eq [IntPtr]::Zero -or
    [IO.Path]::GetFullPath($process.Path) -cne $expectedPath -or
    (Get-FileHash -LiteralPath $process.Path -Algorithm SHA256).Hash.ToLowerInvariant() `
        -cne [string]$runtime.installed_gui_sha256) {
    throw 'Fixed UI candidate PID/session/window/path/hash binding failed.'
}
$signature = Get-AuthenticodeSignature -LiteralPath $process.Path
if ($signature.Status -ne 'NotSigned' -or $signature.SignerCertificate -or
    $signature.TimeStamperCertificate) {
    throw 'Lab fixed UI accepts only the exact unsigned nonpublishable candidate.'
}

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
[ordered]@{
    contract = 'winsvpn-windows-lab-fixed-ui-observation-v1'
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
} | ConvertTo-Json -Depth 4 -Compress
