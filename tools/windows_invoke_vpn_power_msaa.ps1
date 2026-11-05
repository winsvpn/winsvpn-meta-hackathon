[CmdletBinding()]
param(
    [ValidateRange(0, 30)][int]$SettleSeconds = 0,
    [ValidateSet('Toggle', 'Cancel')][string]$Action = 'Toggle',
    [string]$ResultPath = '',
    [switch]$InspectOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

trap {
    if (-not [string]::IsNullOrWhiteSpace($ResultPath)) {
        [IO.File]::WriteAllText(
            $ResultPath,
            "WINDOWS_VPN_POWER_MSAA=FAIL $($_.Exception.Message)" +
                [Environment]::NewLine,
            [Text.UTF8Encoding]::new($false)
        )
    }
    throw $_
}

if (-not [Environment]::UserInteractive) {
    throw "Win's VPN accessibility automation must run in the signed-in interactive user session."
}

Add-Type -AssemblyName Accessibility
$accessibilityAssembly = [Accessibility.IAccessible].Assembly.Location
Add-Type -ReferencedAssemblies $accessibilityAssembly -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Accessibility;

public static class WinsVpnMsaaPower {
    private const uint ObjIdClient = 0xFFFFFFFC;
    private const int ChildIdSelf = 0;
    private const int RoleSystemPushButton = 0x2B;
    private const int MaxNodes = 10000;
    private const int MaxDepth = 64;

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr FindWindowEx(
        IntPtr parent,
        IntPtr childAfter,
        string className,
        string windowName
    );

    [DllImport("oleacc.dll")]
    private static extern int AccessibleObjectFromWindow(
        IntPtr window,
        uint objectId,
        ref Guid interfaceId,
        [MarshalAs(UnmanagedType.Interface)] out object accessible
    );

    [DllImport("oleacc.dll")]
    private static extern int AccessibleChildren(
        [MarshalAs(UnmanagedType.Interface)] IAccessible container,
        int childStart,
        int childCount,
        [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)]
            object[] children,
        out int obtained
    );

    public sealed class Match {
        internal IAccessible Owner;
        internal object ChildId;
        public string Label;
        public int Role;
        public string DefaultAction;
        public int VisitedNodes;
    }

    private static string NameOf(IAccessible owner, object childId) {
        try {
            return owner.get_accName(childId) ?? String.Empty;
        } catch (COMException) {
            return String.Empty;
        }
    }

    private static int RoleOf(IAccessible owner, object childId) {
        try {
            object value = owner.get_accRole(childId);
            return value == null ? -1 : Convert.ToInt32(value);
        } catch (Exception) {
            return -1;
        }
    }

    private static string DefaultActionOf(IAccessible owner, object childId) {
        try {
            return owner.get_accDefaultAction(childId) ?? String.Empty;
        } catch (COMException) {
            return String.Empty;
        }
    }

    private static bool Wanted(string value, string[] labels) {
        if (String.IsNullOrEmpty(value)) {
            return false;
        }
        foreach (string label in labels) {
            if (String.Equals(value, label, StringComparison.Ordinal)) {
                return true;
            }
        }
        return false;
    }

    private static Match Candidate(
        IAccessible owner,
        object childId,
        string[] labels,
        int visited
    ) {
        string label = NameOf(owner, childId);
        if (!Wanted(label, labels)) {
            return null;
        }
        return new Match {
            Owner = owner,
            ChildId = childId,
            Label = label,
            Role = RoleOf(owner, childId),
            DefaultAction = DefaultActionOf(owner, childId),
            VisitedNodes = visited,
        };
    }

    private static Match Find(
        IAccessible node,
        string[] labels,
        int depth,
        ref int visited
    ) {
        if (node == null || depth > MaxDepth || visited >= MaxNodes) {
            return null;
        }
        visited++;
        Match self = Candidate(node, ChildIdSelf, labels, visited);
        if (self != null) {
            return self;
        }

        int childCount;
        try {
            childCount = node.accChildCount;
        } catch (COMException) {
            return null;
        }
        if (childCount <= 0 || childCount > MaxNodes - visited) {
            return null;
        }

        object[] children = new object[childCount];
        int obtained;
        int result = AccessibleChildren(
            node,
            0,
            childCount,
            children,
            out obtained
        );
        if (result < 0 || obtained < 0 || obtained > childCount) {
            return null;
        }

        for (int i = 0; i < obtained && visited < MaxNodes; i++) {
            object child = children[i];
            IAccessible childAccessible = child as IAccessible;
            if (childAccessible != null) {
                Match descendant = Find(
                    childAccessible,
                    labels,
                    depth + 1,
                    ref visited
                );
                if (descendant != null) {
                    return descendant;
                }
                continue;
            }

            visited++;
            Match simpleChild = Candidate(node, child, labels, visited);
            if (simpleChild != null) {
                return simpleChild;
            }
        }
        return null;
    }

    public static Match FindPower(IntPtr window, string[] labels) {
        Guid iid = new Guid("618736E0-3C3D-11CF-810C-00AA00389B71");
        object raw;
        int result = AccessibleObjectFromWindow(
            window,
            ObjIdClient,
            ref iid,
            out raw
        );
        if (result < 0 || raw == null) {
            return null;
        }
        IAccessible root = raw as IAccessible;
        if (root == null) {
            return null;
        }
        int visited = 0;
        return Find(root, labels, 0, ref visited);
    }

    public static void Invoke(Match match) {
        if (match == null || match.Owner == null) {
            throw new ArgumentNullException("match");
        }
        if (match.Role != RoleSystemPushButton) {
            throw new InvalidOperationException(
                "The named VPN control is not exposed as an MSAA push button."
            );
        }
        if (String.IsNullOrWhiteSpace(match.DefaultAction)) {
            throw new InvalidOperationException(
                "The named VPN control has no MSAA default action."
            );
        }
        match.Owner.accDoDefaultAction(match.ChildId);
    }
}
'@

$sessionId = (Get-Process -Id $PID).SessionId
$process = Get-Process -Name wins_vpn -ErrorAction Stop |
    Where-Object { $_.SessionId -eq $sessionId } |
    Select-Object -First 1
if (-not $process -or $process.MainWindowHandle -eq [IntPtr]::Zero) {
    throw "Win's VPN does not have an interactive main window in session $sessionId."
}

$flutterViewHandle = [WinsVpnMsaaPower]::FindWindowEx(
    $process.MainWindowHandle,
    [IntPtr]::Zero,
    'FLUTTERVIEW',
    $null
)
$accessibilityHandle = if ($flutterViewHandle -ne [IntPtr]::Zero) {
    $flutterViewHandle
} else {
    $process.MainWindowHandle
}
$labels = if ($Action -eq 'Cancel') {
    [string[]]@('Cancel VPN connection')
} else {
    [string[]]@('Disconnect VPN', 'Connect VPN')
}

$match = $null
$deadline = (Get-Date).AddSeconds(10)
do {
    $match = [WinsVpnMsaaPower]::FindPower($accessibilityHandle, $labels)
    if (-not $match) {
        Start-Sleep -Milliseconds 250
    }
} while (-not $match -and (Get-Date) -lt $deadline)

if (-not $match) {
    throw "Win's VPN power button was not exposed through the compiled MSAA accessibility bridge."
}
if ($match.Role -ne 0x2B) {
    throw "Win's VPN power control has MSAA role $($match.Role), not push-button role 43."
}
if ([string]::IsNullOrWhiteSpace($match.DefaultAction)) {
    throw "Win's VPN power control does not expose an MSAA default action."
}
if (-not $InspectOnly) {
    [WinsVpnMsaaPower]::Invoke($match)
}

if ($SettleSeconds -gt 0) {
    Start-Sleep -Seconds $SettleSeconds
}
$mode = if ($InspectOnly) { 'INSPECT' } else { 'INVOKE' }
$result = "WINDOWS_VPN_POWER_MSAA=$mode label=$($match.Label) role=pushbutton default_action=$($match.DefaultAction) visited=$($match.VisitedNodes)"
if (-not [string]::IsNullOrWhiteSpace($ResultPath)) {
    [IO.File]::WriteAllText(
        $ResultPath,
        $result + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
}
Write-Output $result
