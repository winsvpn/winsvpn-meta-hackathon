[CmdletBinding()]
param(
    [ValidateRange(0, 30)][int]$SettleSeconds = 0,
    [ValidateSet('Toggle', 'Cancel', 'Disconnect')][string]$Action = 'Toggle',
    [string]$ResultPath = '',
    [ValidateRange(0, [int]::MaxValue)][int]$WindowProcessId = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

trap {
    if (-not [string]::IsNullOrWhiteSpace($ResultPath)) {
        [IO.File]::WriteAllText(
            $ResultPath,
            "WINDOWS_VPN_POWER_INVOKE=FAIL $($_.Exception.Message)" +
                [Environment]::NewLine,
            [Text.UTF8Encoding]::new($false)
        )
    }
    throw
}

if (-not [Environment]::UserInteractive) {
    throw "Win's VPN UI automation must run in the signed-in interactive user session."
}

Add-Type -AssemblyName Accessibility
Add-Type -ReferencedAssemblies 'Accessibility.dll' -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Accessibility;

public static class WinsVpnUiaNative {
    private const uint ObjIdClient = 0xFFFFFFFC;
    private const int RoleSystemPushButton = 0x2B;

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
        [MarshalAs(UnmanagedType.Interface)] out IAccessible accessible
    );

    [DllImport("oleacc.dll")]
    private static extern int AccessibleChildren(
        IAccessible container,
        int childStart,
        int childCount,
        [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)]
        object[] children,
        out int obtained
    );

    private sealed class Target {
        internal IAccessible Parent;
        internal object ChildId;
        internal string Name;
        internal int Role;
        internal string DefaultAction;
    }

    private static string SafeName(IAccessible accessible, object childId) {
        try { return accessible.get_accName(childId) ?? string.Empty; }
        catch (COMException) { return string.Empty; }
    }

    private static int SafeRole(IAccessible accessible, object childId) {
        try { return Convert.ToInt32(accessible.get_accRole(childId)); }
        catch (Exception) { return 0; }
    }

    private static string SafeDefaultAction(
        IAccessible accessible,
        object childId
    ) {
        try { return accessible.get_accDefaultAction(childId) ?? string.Empty; }
        catch (COMException) { return string.Empty; }
    }

    private static Target Find(
        IAccessible accessible,
        string expectedName,
        int depth,
        ref int visited
    ) {
        if (accessible == null || depth > 64 || visited > 4096) return null;
        visited++;

        int count;
        try { count = accessible.accChildCount; }
        catch (COMException) { return null; }
        if (count <= 0) return null;

        var children = new object[count];
        int obtained;
        if (AccessibleChildren(accessible, 0, count, children, out obtained) < 0) {
            return null;
        }
        for (var index = 0; index < obtained; index++) {
            var child = children[index];
            var childAccessible = child as IAccessible;
            var parent = childAccessible ?? accessible;
            object childId = childAccessible == null ? child : (object)0;
            var name = SafeName(parent, childId);
            var role = SafeRole(parent, childId);
            if (string.Equals(name, expectedName, StringComparison.Ordinal)) {
                return new Target {
                    Parent = parent,
                    ChildId = childId,
                    Name = name,
                    Role = role,
                    DefaultAction = SafeDefaultAction(parent, childId),
                };
            }
            if (childAccessible != null) {
                var nested = Find(
                    childAccessible,
                    expectedName,
                    depth + 1,
                    ref visited
                );
                if (nested != null) return nested;
            }
        }
        return null;
    }

    public static string InvokeNamedButton(IntPtr window, string expectedName) {
        var interfaceId = typeof(IAccessible).GUID;
        IAccessible root;
        var result = AccessibleObjectFromWindow(
            window,
            ObjIdClient,
            ref interfaceId,
            out root
        );
        if (result < 0 || root == null) {
            throw new InvalidOperationException(
                "Flutter MSAA accessibility root is unavailable. HRESULT=" +
                result
            );
        }
        var visited = 0;
        var target = Find(root, expectedName, 0, ref visited);
        if (target == null) {
            throw new InvalidOperationException(
                "MSAA button was not found: " + expectedName
            );
        }
        if (target.Role != RoleSystemPushButton) {
            throw new InvalidOperationException(
                "MSAA target has unexpected role " + target.Role + ": " +
                expectedName
            );
        }
        target.Parent.accDoDefaultAction(target.ChildId);
        return "label=" + target.Name + " role=" + target.Role +
            " default_action=" + target.DefaultAction;
    }
}
'@

$sessionId = (Get-Process -Id $PID).SessionId
$process = if ($WindowProcessId -gt 0) {
    Get-Process -Id $WindowProcessId -ErrorAction Stop
} else {
    Get-Process -Name wins_vpn -ErrorAction Stop |
        Where-Object {
            $_.SessionId -eq $sessionId -and
            $_.MainWindowHandle -ne [IntPtr]::Zero
        } |
        Select-Object -First 1
}
if (-not $process -or $process.MainWindowHandle -eq [IntPtr]::Zero) {
    throw "Win's VPN does not have an interactive main window in session $sessionId."
}
if ($process.SessionId -ne $sessionId) {
    throw "Win's VPN process $($process.Id) is not in interactive session $sessionId."
}

$flutterViewHandle = [WinsVpnUiaNative]::FindWindowEx(
    $process.MainWindowHandle,
    [IntPtr]::Zero,
    'FLUTTERVIEW',
    $null
)
$automationHandle = if ($flutterViewHandle -ne [IntPtr]::Zero) {
    $flutterViewHandle
} else {
    $process.MainWindowHandle
}
$invocation = $null
$deadline = (Get-Date).AddSeconds(10)
do {
    $labels = switch ($Action) {
        'Cancel' { @('Cancel VPN connection') }
        'Disconnect' { @('Disconnect VPN') }
        default { @('Disconnect VPN', 'Connect VPN') }
    }
    foreach ($label in $labels) {
        try {
            $invocation = [WinsVpnUiaNative]::InvokeNamedButton(
                $automationHandle,
                $label
            )
            break
        } catch [InvalidOperationException] {
            $invocation = $null
        }
    }
    if (-not $invocation) {
        Start-Sleep -Milliseconds 250
    }
} while (-not $invocation -and (Get-Date) -lt $deadline)

if (-not $invocation) {
    throw "Win's VPN power button was not exposed through Windows MSAA."
}

if ($SettleSeconds -gt 0) {
    Start-Sleep -Seconds $SettleSeconds
}
$result = "WINDOWS_VPN_POWER_INVOKE=PASS $invocation"
if (-not [string]::IsNullOrWhiteSpace($ResultPath)) {
    [IO.File]::WriteAllText(
        $ResultPath,
        $result + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
}
Write-Output $result
