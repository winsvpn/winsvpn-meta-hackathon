[CmdletBinding()]
param(
    [ValidateSet('DryRun', 'Execute', 'Watchdog')][string]$Mode = 'DryRun',
    [string]$AppPath = 'C:\Program Files\WinsVPN\wins_vpn.exe',
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedGuiSha256,
    [string]$OutputRoot = 'C:\src\winsvpn-guarded-power',
    [ValidateRange(10, 300)][int]$ReadyLifetimeSeconds = 120,
    [ValidatePattern('^$|^[0-9a-f]{32}$')][string]$ReadyNonce = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:DryRunStage = 'initialization'
$script:DiagnosticAppSha256 = ''
$script:DiagnosticSessionId = $null
$script:DiagnosticProcessId = $null
$script:DiagnosticWindowHandle = $null
$script:DiagnosticWindowTree = @()
$script:DiagnosticAccessibility = $null
$script:DiagnosticBaselineScreenshotSha256 = ''
$script:DiagnosticReadyBaselineScreenshotSha256 = ''
$script:DiagnosticBaselineScreenshotChanged = $null
$script:DiagnosticCancelScreenshotSha256 = ''
$script:DiagnosticTransitionScreenshotChanged = $null
$script:DiagnosticConnectObservation = $null
$script:DiagnosticCancelObservation = $null
$script:DiagnosticControlRelationship = $null
$script:DiagnosticUiSignatureSha256 = ''
$script:ConnectInputSent = $false
$script:CancelInputSent = $false
$script:ExecuteStageAllowList = @(
    'nonce_validated',
    'nonce_consumed',
    'foreground',
    'cursor_verified',
    'connect_input_sent',
    'cancel_label_seen',
    'cancel_image',
    'cancel_geometry_valid',
    'cancel_input_sent',
    'zero_residue'
)
$script:ExecuteStage = 'nonce_validated'
$script:ExecuteCompletedStages = [Collections.Generic.List[string]]::new()
$diagnosticRoot = Join-Path $env:LOCALAPPDATA 'WinsVPN\GuardedPower'
$diagnosticErrorPath = Join-Path $diagnosticRoot 'dry-run-error.json'
$executeErrorPath = Join-Path $OutputRoot 'execute-error.json'
$executeSuccessPath = Join-Path $OutputRoot 'execute-success.json'

function Enter-ExecuteStage([string]$Stage) {
    if (-not $script:ExecuteStageAllowList.Contains($Stage)) {
        throw 'Execute observability stage is outside the bounded allowlist.'
    }
    $script:ExecuteStage = $Stage
}

function Complete-ExecuteStage {
    if (-not $script:ExecuteCompletedStages.Contains($script:ExecuteStage)) {
        $script:ExecuteCompletedStages.Add($script:ExecuteStage)
    }
}

function Get-ZeroResidueSnapshot {
    $services = @(
        @('AmneziaWGTunnel$winsvpn','AmneziaWGTunnel$awg2','WinsVPNSplitTunnel') |
            Where-Object {
                $service = Get-Service -Name $_ -ErrorAction SilentlyContinue
                $service -and $service.Status -eq 'Running'
            }
    )
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Status -eq 'Up' -and
            $_.Name -match '(?i)winsvpn|amnezia|awg'
        })
    $routes = @(Get-NetRoute -ErrorAction SilentlyContinue |
        Where-Object {
            $_.InterfaceAlias -match '(?i)winsvpn|amnezia|awg'
        })
    $xray = @(Get-Process xray -ErrorAction SilentlyContinue)
    [ordered]@{
        running_guard_services = @($services).Count
        up_guard_adapters = $adapters.Count
        guard_routes = $routes.Count
        xray_processes = $xray.Count
        is_zero = (
            @($services).Count -eq 0 -and
            $adapters.Count -eq 0 -and
            $routes.Count -eq 0 -and
            $xray.Count -eq 0
        )
    }
}

function Test-ZeroResidue {
    [bool](Get-ZeroResidueSnapshot).is_zero
}

function Get-SanitizedExceptionMessage([Exception]$Exception) {
    $message = [string]$Exception.Message
    $message = $message -replace '(?i)[A-Z]:\\[^\r\n]*', '<redacted-path>'
    $message = $message -replace '(?i)\\Users\\[^\\\s]+', '\\Users\\<redacted>'
    if ($message.Length -gt 512) {
        $message = $message.Substring(0, 512)
    }
    $message
}

function Set-OwnerOnlyAcl([string]$Path) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $item = Get-Item -LiteralPath $Path -Force
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Access
    $acl = if ($item.PSObject.Methods.Name -contains 'GetAccessControl') {
        $item.GetAccessControl($sections)
    } else {
        [IO.FileSystemAclExtensions]::GetAccessControl($item, $sections)
    }
    $owner = $acl.GetOwner(
        [Security.Principal.SecurityIdentifier]
    )
    if (-not $owner.Equals($identity)) {
        throw 'Private receipt owner does not match the current user.'
    }

    $acl.SetAccessRuleProtection($true, $false)
    $existingRules = @(
        $acl.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        )
    )
    foreach ($rule in $existingRules) {
        [void]$acl.RemoveAccessRuleSpecific($rule)
    }
    $acl.AddAccessRule(
        [Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
    )
    if ($item.PSObject.Methods.Name -contains 'SetAccessControl') {
        $item.SetAccessControl($acl)
    } else {
        [IO.FileSystemAclExtensions]::SetAccessControl($item, $acl)
    }

    $verified = if (
        $item.PSObject.Methods.Name -contains 'GetAccessControl'
    ) {
        $item.GetAccessControl($sections)
    } else {
        [IO.FileSystemAclExtensions]::GetAccessControl($item, $sections)
    }
    $verifiedOwner = $verified.GetOwner(
        [Security.Principal.SecurityIdentifier]
    )
    $verifiedRules = @(
        $verified.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        )
    )
    $allowRules = @(
        $verifiedRules | Where-Object {
            $_.AccessControlType -eq
                [Security.AccessControl.AccessControlType]::Allow
        }
    )
    $foreignAllowRules = @(
        $allowRules | Where-Object {
            -not $_.IdentityReference.Equals($identity)
        }
    )
    $currentFullControlRules = @(
        $allowRules | Where-Object {
            $_.IdentityReference.Equals($identity) -and
            (
                [int]$_.FileSystemRights -band
                [int][Security.AccessControl.FileSystemRights]::FullControl
            ) -eq
                [int][Security.AccessControl.FileSystemRights]::FullControl
        }
    )
    if (
        -not $verifiedOwner.Equals($identity) -or
        -not $verified.AreAccessRulesProtected -or
        $foreignAllowRules.Count -ne 0 -or
        $allowRules.Count -ne 1 -or
        $currentFullControlRules.Count -ne 1 -or
        $verifiedRules.Count -ne 1
    ) {
        throw 'Private receipt ACL verification failed.'
    }
}

function Write-PrivateJson([string]$Path, $Value) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) |
        Out-Null
    [IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 12),
        [Text.UTF8Encoding]::new($false)
    )
    Set-OwnerOnlyAcl $Path
}

try {
if (-not [Environment]::UserInteractive) {
    throw 'Guarded power harness requires the signed-in interactive session.'
}
if (-not (Test-Path -LiteralPath $AppPath -PathType Leaf)) {
    throw 'Exact installed GUI is missing.'
}

$script:DryRunStage = 'native_types'
Add-Type -AssemblyName Accessibility
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$accessibilityAssembly = [Accessibility.IAccessible].Assembly.Location
Add-Type -ReferencedAssemblies $accessibilityAssembly -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Accessibility;

public static class WinsVpnGuardedPowerNative {
  private const uint ObjIdClient = 0xFFFFFFFC;
  private const int ChildSelf = 0;
  private const int MaxNodes = 2048;
  private const int MaxDepth = 32;
  private const int MaxWindows = 128;
  private delegate bool EnumWindowCallback(IntPtr window, IntPtr state);
  [StructLayout(LayoutKind.Sequential)] public struct RECT {
    public int Left; public int Top; public int Right; public int Bottom;
  }
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
  [DllImport("user32.dll")] public static extern bool SetProcessDpiAwarenessContext(IntPtr value);
  [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowCallback callback, IntPtr state);
  [DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr parent, EnumWindowCallback callback, IntPtr state);
  [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
  [DllImport("user32.dll")] private static extern bool IsWindow(IntPtr window);
  [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr window);
  [DllImport("user32.dll")] private static extern bool IsIconic(IntPtr window);
  [DllImport("user32.dll")] private static extern IntPtr GetParent(IntPtr window);
  [DllImport("user32.dll")] private static extern IntPtr GetWindow(IntPtr window, uint command);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(IntPtr window, StringBuilder text, int count);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassName(IntPtr window, StringBuilder text, int count);
  [DllImport("dwmapi.dll")] private static extern int DwmGetWindowAttribute(IntPtr window, uint attribute, out int value, int size);
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr window, out RECT rect);
  [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr window, ref POINT point);
  [DllImport("user32.dll")] public static extern uint GetDpiForWindow(IntPtr window);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr window);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT point);
  [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extraInfo);
  [DllImport("oleacc.dll")] private static extern int AccessibleObjectFromWindow(IntPtr window, uint objectId, ref Guid iid, [MarshalAs(UnmanagedType.Interface)] out object accessible);
  [DllImport("oleacc.dll")] private static extern int AccessibleChildren([MarshalAs(UnmanagedType.Interface)] IAccessible container, int start, int count, [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)] object[] children, out int obtained);

  public static IntPtr FindExactWindow(uint expectedProcessId) {
    IntPtr match = IntPtr.Zero; int matches = 0;
    EnumWindows(delegate(IntPtr window, IntPtr state) {
      uint processId; GetWindowThreadProcessId(window, out processId);
      if (processId != expectedProcessId || !IsWindow(window) ||
          !IsWindowVisible(window) || IsIconic(window) ||
          GetParent(window) != IntPtr.Zero || GetWindow(window, 4) != IntPtr.Zero)
        return true;
      var title = new StringBuilder(128); GetWindowText(window, title, title.Capacity);
      var className = new StringBuilder(128); GetClassName(window, className, className.Capacity);
      if (!String.Equals(title.ToString(), "Win's VPN", StringComparison.Ordinal) ||
          !String.Equals(className.ToString(), "FLUTTER_RUNNER_WIN32_WINDOW", StringComparison.Ordinal))
        return true;
      int cloaked = 0;
      if (DwmGetWindowAttribute(window, 14, out cloaked, 4) == 0 && cloaked != 0)
        return true;
      match = window; matches++; return true;
    }, IntPtr.Zero);
    return matches == 1 ? match : IntPtr.Zero;
  }

  public sealed class WindowInfo {
    public long Handle; public long Parent; public uint ProcessId;
    public bool Visible; public string ClassName;
  }
  public static WindowInfo[] EnumerateDescendants(
      IntPtr topLevel, uint expectedProcessId) {
    var windows = new List<WindowInfo>();
    EnumChildWindows(topLevel, delegate(IntPtr window, IntPtr state) {
      if (windows.Count >= MaxWindows) return false;
      uint processId; GetWindowThreadProcessId(window, out processId);
      if (processId != expectedProcessId || !IsWindow(window)) return true;
      var className = new StringBuilder(128);
      GetClassName(window, className, className.Capacity);
      windows.Add(new WindowInfo {
        Handle = window.ToInt64(), Parent = GetParent(window).ToInt64(),
        ProcessId = processId, Visible = IsWindowVisible(window),
        ClassName = className.ToString()
      });
      return true;
    }, IntPtr.Zero);
    return windows.ToArray();
  }
  public static IntPtr FindExactFlutterView(
      IntPtr topLevel, uint expectedProcessId) {
    IntPtr match = IntPtr.Zero; int matches = 0;
    foreach (WindowInfo window in EnumerateDescendants(
                 topLevel, expectedProcessId)) {
      if (!window.Visible || !String.Equals(window.ClassName, "FLUTTERVIEW",
              StringComparison.Ordinal)) continue;
      match = new IntPtr(window.Handle); matches++;
    }
    return matches == 1 ? match : IntPtr.Zero;
  }

  public sealed class Match {
    public string Label; public int Role; public int State;
    public int Left; public int Top; public int Width; public int Height;
  }
  private static Match Candidate(IAccessible owner, object child, string label) {
    try {
      if (!String.Equals(owner.get_accName(child) ?? "", label,
              StringComparison.Ordinal)) return null;
      int left, top, width, height;
      owner.accLocation(out left, out top, out width, out height, child);
      return new Match { Label = label,
        Role = Convert.ToInt32(owner.get_accRole(child)),
        State = Convert.ToInt32(owner.get_accState(child)),
        Left = left, Top = top, Width = width, Height = height };
    } catch { return null; }
  }
  private static void FindMatches(IAccessible node, string label, int depth,
      ref int seen, List<Match> matches) {
    if (node == null || depth > MaxDepth || seen++ >= MaxNodes ||
        matches.Count > 1) return;
    Match own = depth > 0 ? Candidate(node, ChildSelf, label) : null;
    if (own != null) {
      matches.Add(own);
      if (matches.Count > 1) return;
    }
    int count; try { count = node.accChildCount; } catch { return; }
    if (count < 1 || count > MaxNodes - seen) return;
    object[] children = new object[count]; int obtained;
    if (AccessibleChildren(node, 0, count, children, out obtained) < 0) return;
    for (int index = 0; index < obtained; index++) {
      IAccessible nested = children[index] as IAccessible;
      if (nested != null) {
        FindMatches(nested, label, depth + 1, ref seen, matches);
      } else {
        Match match = Candidate(node, children[index], label);
        if (match != null) matches.Add(match);
      }
      if (matches.Count > 1) return;
    }
  }
  public static Match FindLabel(IntPtr flutterView, string label) {
    Guid iid = new Guid("618736E0-3C3D-11CF-810C-00AA00389B71");
    object raw;
    if (AccessibleObjectFromWindow(flutterView, ObjIdClient, ref iid, out raw) < 0)
      return null;
    int seen = 0; var matches = new List<Match>();
    FindMatches(raw as IAccessible, label, 0, ref seen, matches);
    return matches.Count == 1 ? matches[0] : null;
  }
}
'@

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-JsonSha256($Value) {
    $json = $Value | ConvertTo-Json -Depth 12 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($sha256.ComputeHash($bytes)) -replace '-', '').
            ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Get-StructuralUiSignature(
    [string]$AppSha256,
    [int]$ProcessId,
    [int]$SessionId,
    [IntPtr]$TopLevelWindow,
    $FlutterBinding,
    $Client,
    [int]$Dpi,
    $ConnectObservation
) {
    [ordered]@{
        app_sha256 = $AppSha256
        process_id = $ProcessId
        session_id = $SessionId
        top_level_hwnd = $TopLevelWindow.ToInt64()
        flutter_view = [ordered]@{
            hwnd = [long]$FlutterBinding.hwnd
            parent = [long]$FlutterBinding.parent
            process_id = [uint32]$FlutterBinding.process_id
            class_name = [string]$FlutterBinding.class_name
            visible = [bool]$FlutterBinding.visible
            direct_child = (
                [long]$FlutterBinding.parent -eq
                $TopLevelWindow.ToInt64()
            )
        }
        client = [ordered]@{
            left = [int]$Client.left
            top = [int]$Client.top
            width = [int]$Client.width
            height = [int]$Client.height
        }
        dpi = $Dpi
        connect = [ordered]@{
            label = [string]$ConnectObservation.label
            role = [int]$ConnectObservation.role
            state = [int]$ConnectObservation.state
            bounds = [ordered]@{
                left = [int]$ConnectObservation.bounds.left
                top = [int]$ConnectObservation.bounds.top
                width = [int]$ConnectObservation.bounds.width
                height = [int]$ConnectObservation.bounds.height
            }
            center = [ordered]@{
                x = [int]$ConnectObservation.center.x
                y = [int]$ConnectObservation.center.y
                x_fraction =
                    [double]$ConnectObservation.center.x_fraction
                y_fraction =
                    [double]$ConnectObservation.center.y_fraction
            }
        }
    }
}

function Write-Json([string]$Path, $Value) {
    [IO.File]::WriteAllText(
        $Path, ($Value | ConvertTo-Json -Depth 10),
        [Text.UTF8Encoding]::new($false)
    )
}

function Get-UiaButtonObservation(
    [IntPtr]$RootWindow, [string]$Label) {
    $observation = [ordered]@{
        provider = 'uia'
        root_hwnd = $RootWindow.ToInt64()
        root_name = ''
        root_control_type = ''
        name_match_count = 0
        exact_button_match_count = 0
        error_type = ''
    }
    try {
        $root = [Windows.Automation.AutomationElement]::FromHandle($RootWindow)
        $rootName = [string]$root.Current.Name
        $observation.root_name = if ($rootName -ceq 'FLUTTERVIEW') {
            'FLUTTERVIEW'
        } else { '<other>' }
        $observation.root_control_type =
            [string]$root.Current.ControlType.ProgrammaticName
        $nameCondition = [Windows.Automation.PropertyCondition]::new(
            [Windows.Automation.AutomationElement]::NameProperty, $Label)
        $buttonCondition = [Windows.Automation.PropertyCondition]::new(
            [Windows.Automation.AutomationElement]::ControlTypeProperty,
            [Windows.Automation.ControlType]::Button)
        $exactCondition = [Windows.Automation.AndCondition]::new(
            [Windows.Automation.Condition[]]@($nameCondition, $buttonCondition))
        $nameMatches = $root.FindAll(
            [Windows.Automation.TreeScope]::Subtree, $nameCondition)
        $exactMatches = $root.FindAll(
            [Windows.Automation.TreeScope]::Subtree, $exactCondition)
        $observation.name_match_count = $nameMatches.Count
        $observation.exact_button_match_count = $exactMatches.Count
        if ($exactMatches.Count -eq 1) {
            $match = $exactMatches.Item(0)
            $bounds = $match.Current.BoundingRectangle
            $observation.match = [ordered]@{
                enabled = [bool]$match.Current.IsEnabled
                offscreen = [bool]$match.Current.IsOffscreen
                left = [int][Math]::Round($bounds.Left)
                top = [int][Math]::Round($bounds.Top)
                width = [int][Math]::Round($bounds.Width)
                height = [int][Math]::Round($bounds.Height)
            }
        }
    } catch {
        $observation.error_type = $_.Exception.GetType().FullName
    }
    [pscustomobject]$observation
}

function Capture-Client([IntPtr]$Window, [string]$Path) {
    $rect = [WinsVpnGuardedPowerNative+RECT]::new()
    if (-not [WinsVpnGuardedPowerNative]::GetClientRect($Window, [ref]$rect)) {
        throw 'Client rectangle is unavailable.'
    }
    $origin = [WinsVpnGuardedPowerNative+POINT]::new()
    if (-not [WinsVpnGuardedPowerNative]::ClientToScreen($Window, [ref]$origin)) {
        throw 'Client origin is unavailable.'
    }
    $width = $rect.Right - $rect.Left
    $height = $rect.Bottom - $rect.Top
    if ($width -lt 800 -or $height -lt 500 -or $width -gt 3840 -or $height -gt 2160) {
        throw "Client dimensions are outside the guarded range: ${width}x${height}."
    }
    $bitmap = [Drawing.Bitmap]::new($width, $height)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.CopyFromScreen($origin.X, $origin.Y, 0, 0, $bitmap.Size)
        $bitmap.Save($Path, [Drawing.Imaging.ImageFormat]::Png)
    } finally { $graphics.Dispose(); $bitmap.Dispose() }
    [ordered]@{ left=$origin.X; top=$origin.Y; width=$width; height=$height }
}

function Assert-Button($Match, [string]$Label, $Client) {
    if (-not $Match -or $Match.Label -cne $Label -or $Match.Role -ne 43 -or
        ($Match.State -band 0x8000) -ne 0 -or
        ($Match.State -band 0x10000) -ne 0 -or
        ($Match.State -band 0x1) -ne 0 -or
        $Match.Width -lt 32 -or $Match.Height -lt 32) {
        throw "Exact guarded state label is unavailable: $Label"
    }
    if ($Match.Left -lt $Client.left -or $Match.Top -lt $Client.top -or
        ($Match.Left + $Match.Width) -gt ($Client.left + $Client.width) -or
        ($Match.Top + $Match.Height) -gt ($Client.top + $Client.height)) {
        throw "Guarded control is outside the exact client rectangle: $Label"
    }
}

function Get-ControlObservation($Match, $Client) {
    $centerX = $Match.Left + [int][Math]::Floor($Match.Width / 2)
    $centerY = $Match.Top + [int][Math]::Floor($Match.Height / 2)
    [ordered]@{
        label = $Match.Label
        role = $Match.Role
        state = $Match.State
        bounds = [ordered]@{
            left = $Match.Left
            top = $Match.Top
            width = $Match.Width
            height = $Match.Height
        }
        center = [ordered]@{
            x = $centerX
            y = $centerY
            x_fraction = ($centerX - $Client.left) /
                [double]$Client.width
            y_fraction = ($centerY - $Client.top) /
                [double]$Client.height
        }
    }
}

function Get-ControlRelationship($ConnectObservation, $CancelObservation) {
    $connectBounds = $ConnectObservation.bounds
    $cancelBounds = $CancelObservation.bounds
    $overlapLeft = [Math]::Max($connectBounds.left, $cancelBounds.left)
    $overlapTop = [Math]::Max($connectBounds.top, $cancelBounds.top)
    $overlapRight = [Math]::Min(
        $connectBounds.left + $connectBounds.width,
        $cancelBounds.left + $cancelBounds.width
    )
    $overlapBottom = [Math]::Min(
        $connectBounds.top + $connectBounds.height,
        $cancelBounds.top + $cancelBounds.height
    )
    $overlapWidth = [Math]::Max(0, $overlapRight - $overlapLeft)
    $overlapHeight = [Math]::Max(0, $overlapBottom - $overlapTop)
    $overlapArea = $overlapWidth * $overlapHeight
    $smallerArea = [Math]::Min(
        $connectBounds.width * $connectBounds.height,
        $cancelBounds.width * $cancelBounds.height
    )
    [ordered]@{
        center_delta_x = $CancelObservation.center.x -
            $ConnectObservation.center.x
        center_delta_y = $CancelObservation.center.y -
            $ConnectObservation.center.y
        center_fraction_delta_x = [Math]::Abs(
            $CancelObservation.center.x_fraction -
            $ConnectObservation.center.x_fraction
        )
        center_fraction_delta_y = [Math]::Abs(
            $CancelObservation.center.y_fraction -
            $ConnectObservation.center.y_fraction
        )
        overlap = [ordered]@{
            left = $overlapLeft
            top = $overlapTop
            width = $overlapWidth
            height = $overlapHeight
            fraction_of_smaller = if ($smallerArea -gt 0) {
                $overlapArea / [double]$smallerArea
            } else {
                0.0
            }
        }
        guard = [ordered]@{
            max_center_fraction_delta_x = 0.08
            max_center_fraction_delta_y = 0.25
            overlap_required = $false
        }
    }
}

function Assert-DynamicCancel(
    $Match,
    $Client,
    $Observation,
    $Relationship
) {
    Assert-Button $Match 'Cancel VPN connection' $Client
    if (
        $Observation.center.x_fraction -lt 0.40 -or
        $Observation.center.x_fraction -gt 0.60 -or
        $Observation.center.y_fraction -lt 0.55 -or
        $Observation.center.y_fraction -gt 0.75
    ) {
        throw 'Cancel center is outside the guarded current-layout region.'
    }
    if (
        $Relationship.center_fraction_delta_x -gt
            $Relationship.guard.max_center_fraction_delta_x -or
        $Relationship.center_fraction_delta_y -gt
            $Relationship.guard.max_center_fraction_delta_y
    ) {
        throw 'Cancel control is not the guarded central power control.'
    }
}

[WinsVpnGuardedPowerNative]::SetProcessDpiAwarenessContext([IntPtr]::new(-4)) | Out-Null
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$script:DryRunStage = 'exact_binary'
$actualHash = Get-Sha256 $AppPath
$script:DiagnosticAppSha256 = $actualHash
if ($actualHash -cne $ExpectedGuiSha256.ToLowerInvariant()) {
    throw 'Installed GUI hash does not match the exact candidate.'
}
$script:DryRunStage = 'exact_process'
$sessionId = (Get-Process -Id $PID).SessionId
$script:DiagnosticSessionId = $sessionId
$processes = @(Get-Process wins_vpn -ErrorAction SilentlyContinue |
    Where-Object { $_.SessionId -eq $sessionId } | Sort-Object StartTime -Descending)
if ($processes.Count -ne 1) { throw 'Exactly one same-session GUI process is required.' }
$process = $processes[0]
$script:DiagnosticProcessId = $process.Id
$script:DryRunStage = 'exact_window'
$window = [WinsVpnGuardedPowerNative]::FindExactWindow([uint32]$process.Id)
if ($window -eq [IntPtr]::Zero -or -not $process.Responding) {
    throw 'Exact visible, uncloaked, non-minimized GUI window is unavailable.'
}
$script:DiagnosticWindowHandle = $window.ToInt64()
$script:DryRunStage = 'flutter_view'
$script:DiagnosticWindowTree = @(
    [WinsVpnGuardedPowerNative]::EnumerateDescendants(
        $window, [uint32]$process.Id) | ForEach-Object {
        [ordered]@{
            hwnd = $_.Handle
            parent = $_.Parent
            process_id = $_.ProcessId
            visible = $_.Visible
            class_name = $_.ClassName
        }
    }
)
$flutterView = [WinsVpnGuardedPowerNative]::FindExactFlutterView(
    $window, [uint32]$process.Id)
if ($flutterView -eq [IntPtr]::Zero) { throw 'Exact FLUTTERVIEW child is unavailable.' }
$flutterBinding = @($script:DiagnosticWindowTree | Where-Object {
    $_.hwnd -eq $flutterView.ToInt64()
})
if ($flutterBinding.Count -ne 1) {
    throw 'Exact FLUTTERVIEW binding evidence is ambiguous.'
}

$script:DryRunStage = 'client_capture'
$screenshot = Join-Path $OutputRoot 'baseline.png'
$client = Capture-Client $window $screenshot
$dpi = [int][WinsVpnGuardedPowerNative]::GetDpiForWindow($window)
if ($dpi -lt 96 -or $dpi -gt 480) { throw "Window DPI is invalid: $dpi" }
$script:DryRunStage = 'guarded_connect'
$connect = $null
$connectAttempts = 0
$connectDeadline = [DateTime]::UtcNow.AddSeconds(5)
do {
    $connectAttempts++
    $connect = [WinsVpnGuardedPowerNative]::FindLabel($flutterView, 'Connect VPN')
    if (-not $connect) { Start-Sleep -Milliseconds 100 }
} while (-not $connect -and [DateTime]::UtcNow -lt $connectDeadline)
if (-not $connect) {
    $script:DiagnosticAccessibility = Get-UiaButtonObservation `
        $flutterView 'Connect VPN'
}
Assert-Button $connect 'Connect VPN' $client
$connectObservation = Get-ControlObservation $connect $client
$script:DiagnosticConnectObservation = $connectObservation
$x = $connectObservation.center.x
$y = $connectObservation.center.y
$xFraction = $connectObservation.center.x_fraction
$yFraction = $connectObservation.center.y_fraction
if ($xFraction -lt 0.40 -or $xFraction -gt 0.60 -or
    $yFraction -lt 0.70 -or $yFraction -gt 0.90) {
    throw 'Live Connect control is outside the guarded current-layout region.'
}
$screenshotHash = Get-Sha256 $screenshot
$script:DiagnosticBaselineScreenshotSha256 = $screenshotHash
$uiSignature = Get-StructuralUiSignature $actualHash $process.Id $sessionId $window $flutterBinding[0] $client $dpi $connectObservation
$uiSignatureHash = Get-JsonSha256 $uiSignature
$script:DiagnosticUiSignatureSha256 = $uiSignatureHash

if ($Mode -eq 'DryRun') {
    $script:DryRunStage = 'zero_residue'
    if (-not (Test-ZeroResidue)) { throw 'Dry-run requires zero tunnel residue.' }
    $nonce = [Guid]::NewGuid().ToString('N')
    $expires = [DateTime]::UtcNow.AddSeconds($ReadyLifetimeSeconds)
    $readyPath = Join-Path $OutputRoot "ready-$nonce.json"
    $ready = [ordered]@{
        schema_version=1; contract='winsvpn-guarded-power-ready-v1'
        nonce=$nonce; expires_utc=$expires.ToString('o'); consumed=$false
        app_sha256=$actualHash; pid=$process.Id; session_id=$sessionId
        hwnd=$window.ToInt64(); client=$client; dpi=$dpi
        flutter_view=[ordered]@{
            hwnd=$flutterView.ToInt64()
            parent=[long]$flutterBinding[0].parent
            process_id=[uint32]$flutterBinding[0].process_id
            visible=[bool]$flutterBinding[0].visible
            class_name=[string]$flutterBinding[0].class_name
            direct_child=([long]$flutterBinding[0].parent -eq $window.ToInt64())
            msaa_label_root=$flutterView.ToInt64()
            msaa_ready_attempts=$connectAttempts
        }
        window_tree=$script:DiagnosticWindowTree
        screenshot_sha256=$screenshotHash
        ui_signature=$uiSignature
        ui_signature_sha256=$uiSignatureHash
        connect=$connectObservation
        cancel=[ordered]@{
            expected_label='Cancel VPN connection'
            expected_role=43
            dynamic_center=$true
            center_x_fraction_min=0.40
            center_x_fraction_max=0.60
            center_y_fraction_min=0.55
            center_y_fraction_max=0.75
            max_center_fraction_delta_x=0.08
            max_center_fraction_delta_y=0.25
            overlap_required=$false
        }
        zero_residue=$true
    }
    $script:DryRunStage = 'ready_receipt'
    Write-Json $readyPath $ready
    Write-Json (Join-Path $OutputRoot 'dry-run.json') $ready
    $script:DryRunStage = 'complete'
    Remove-Item -LiteralPath $diagnosticErrorPath -Force -ErrorAction SilentlyContinue
    Write-Output ($ready | ConvertTo-Json -Depth 8 -Compress)
    exit 0
}

Enter-ExecuteStage 'nonce_validated'
if ([string]::IsNullOrWhiteSpace($ReadyNonce)) { throw 'A one-use READY nonce is required.' }
$readyPath = Join-Path $OutputRoot "ready-$ReadyNonce.json"
if (-not (Test-Path -LiteralPath $readyPath -PathType Leaf)) { throw 'READY nonce is absent or consumed.' }
$ready = Get-Content -Raw -LiteralPath $readyPath | ConvertFrom-Json
if ($ready.contract -cne 'winsvpn-guarded-power-ready-v1' -or
    $ready.nonce -cne $ReadyNonce -or $ready.consumed -ne $false -or
    [DateTime]::Parse([string]$ready.expires_utc).ToUniversalTime() -le
        [DateTime]::UtcNow) {
    throw 'READY nonce validity guard failed.'
}
if (
    $ready.PSObject.Properties.Name -notcontains 'ui_signature' -or
    $ready.PSObject.Properties.Name -notcontains 'ui_signature_sha256'
) {
    throw 'READY structural UI signature is missing.'
}
$script:DiagnosticReadyBaselineScreenshotSha256 =
    [string]$ready.screenshot_sha256
$script:DiagnosticBaselineScreenshotChanged = (
    $script:DiagnosticReadyBaselineScreenshotSha256 -cne $screenshotHash
)
$readySignatureHash = Get-JsonSha256 $ready.ui_signature
$readySignatureJson = $ready.ui_signature |
    ConvertTo-Json -Depth 12 -Compress
$currentSignatureJson = $uiSignature |
    ConvertTo-Json -Depth 12 -Compress
if (
    [string]$ready.ui_signature_sha256 -cne $readySignatureHash -or
    $readySignatureHash -cne $uiSignatureHash -or
    $readySignatureJson -cne $currentSignatureJson
) {
    throw 'READY structural UI signature guard failed.'
}
Complete-ExecuteStage

# Consume before any input so a retry can never double-click.
Enter-ExecuteStage 'nonce_consumed'
Remove-Item -LiteralPath $readyPath -Force
Complete-ExecuteStage
Enter-ExecuteStage 'foreground'
if (-not [WinsVpnGuardedPowerNative]::SetForegroundWindow($window)) {
    throw 'Exact window could not become the input target.'
}
Complete-ExecuteStage
Enter-ExecuteStage 'cursor_verified'
if (-not [WinsVpnGuardedPowerNative]::SetCursorPos($x, $y)) {
    throw 'Guarded cursor placement failed.'
}
$cursor = [WinsVpnGuardedPowerNative+POINT]::new()
if (-not [WinsVpnGuardedPowerNative]::GetCursorPos([ref]$cursor) -or
    $cursor.X -ne $x -or $cursor.Y -ne $y) { throw 'Guarded cursor verification failed.' }
Complete-ExecuteStage
Enter-ExecuteStage 'connect_input_sent'
$script:ConnectInputSent = $true
[WinsVpnGuardedPowerNative]::mouse_event(0x0002,0,0,0,[UIntPtr]::Zero)
[WinsVpnGuardedPowerNative]::mouse_event(0x0004,0,0,0,[UIntPtr]::Zero)
Complete-ExecuteStage

Enter-ExecuteStage 'cancel_label_seen'
$deadline = [DateTime]::UtcNow.AddSeconds(3)
$cancel = $null
do {
    $cancel = [WinsVpnGuardedPowerNative]::FindLabel($flutterView, 'Cancel VPN connection')
    if (-not $cancel) { Start-Sleep -Milliseconds 100 }
} while (-not $cancel -and [DateTime]::UtcNow -lt $deadline)
if (-not $cancel) {
    throw 'Exact guarded state label is unavailable: Cancel VPN connection'
}
$cancelObservation = Get-ControlObservation $cancel $client
$script:DiagnosticCancelObservation = $cancelObservation
Complete-ExecuteStage
Enter-ExecuteStage 'cancel_image'
$transitionPath = Join-Path $OutputRoot 'cancel-state.png'
$null = Capture-Client $window $transitionPath
$transitionHash = Get-Sha256 $transitionPath
$script:DiagnosticCancelScreenshotSha256 = $transitionHash
$script:DiagnosticTransitionScreenshotChanged = (
    $transitionHash -cne $screenshotHash
)
if (-not $script:DiagnosticTransitionScreenshotChanged) {
    throw 'Visual state did not change after Connect input.'
}
Complete-ExecuteStage
Enter-ExecuteStage 'cancel_geometry_valid'
$controlRelationship = Get-ControlRelationship $connectObservation $cancelObservation
$script:DiagnosticControlRelationship = $controlRelationship
Assert-DynamicCancel $cancel $client $cancelObservation $controlRelationship
$cancelX = $cancelObservation.center.x
$cancelY = $cancelObservation.center.y
Complete-ExecuteStage

# Hard bounded cancel: the same exact, still-guarded control is clicked immediately.
Enter-ExecuteStage 'cancel_input_sent'
if (-not [WinsVpnGuardedPowerNative]::SetCursorPos($cancelX, $cancelY)) {
    throw 'Guarded cancel cursor placement failed.'
}
$script:CancelInputSent = $true
[WinsVpnGuardedPowerNative]::mouse_event(0x0002,0,0,0,[UIntPtr]::Zero)
[WinsVpnGuardedPowerNative]::mouse_event(0x0004,0,0,0,[UIntPtr]::Zero)
Complete-ExecuteStage
Enter-ExecuteStage 'zero_residue'
$cleanDeadline = [DateTime]::UtcNow.AddSeconds(12)
do {
    if (Test-ZeroResidue) { break }
    Start-Sleep -Milliseconds 200
} while ([DateTime]::UtcNow -lt $cleanDeadline)
$finalResidue = Get-ZeroResidueSnapshot
if (-not $finalResidue.is_zero) { throw 'Hard cancel did not restore zero tunnel residue.' }
Complete-ExecuteStage
$successReceipt = [ordered]@{
    schema_version = 1
    contract = 'winsvpn-guarded-power-execute-success-v1'
    observed_utc = [DateTime]::UtcNow.ToString('o')
    ready_nonce = $ReadyNonce
    stage = $script:ExecuteStage
    completed_stages = @($script:ExecuteCompletedStages)
    connect_input_sent = $script:ConnectInputSent
    cancel_input_sent = $script:CancelInputSent
    app_sha256 = $script:DiagnosticAppSha256
    process_id = $script:DiagnosticProcessId
    session_id = $script:DiagnosticSessionId
    hwnd = $script:DiagnosticWindowHandle
    ui_signature_sha256 = $script:DiagnosticUiSignatureSha256
    controls = [ordered]@{
        connect = $script:DiagnosticConnectObservation
        cancel = $script:DiagnosticCancelObservation
        relationship = $script:DiagnosticControlRelationship
    }
    screenshots = [ordered]@{
        baseline = [ordered]@{
            file_name = [IO.Path]::GetFileName($screenshot)
            ready_sha256 =
                $script:DiagnosticReadyBaselineScreenshotSha256
            execute_sha256 =
                $script:DiagnosticBaselineScreenshotSha256
            baseline_screenshot_changed =
                $script:DiagnosticBaselineScreenshotChanged
        }
        cancel_state = [ordered]@{
            file_name = [IO.Path]::GetFileName($transitionPath)
            sha256 = $script:DiagnosticCancelScreenshotSha256
            transition_screenshot_changed =
                $script:DiagnosticTransitionScreenshotChanged
        }
    }
    final_zero_residue = $finalResidue
    secret_material_redacted = $true
}
Remove-Item -LiteralPath $executeErrorPath -Force -ErrorAction SilentlyContinue
Write-PrivateJson $executeSuccessPath $successReceipt
Write-Output 'WINDOWS_GUARDED_POWER_CANCEL=PASS'
} catch {
    if ($Mode -eq 'DryRun') {
        $allowedStages = @(
            'initialization','native_types','exact_binary','exact_process',
            'exact_window','flutter_view','client_capture','guarded_connect',
            'zero_residue','ready_receipt','complete'
        )
        $stage = if ($script:DryRunStage -in $allowedStages) {
            $script:DryRunStage
        } else { 'initialization' }
        $message = Get-SanitizedExceptionMessage $_.Exception
        $errorReceipt = [ordered]@{
            schema_version = 1
            contract = 'winsvpn-guarded-power-dry-run-error-v1'
            observed_utc = [DateTime]::UtcNow.ToString('o')
            stage = $stage
            exception_type = $_.Exception.GetType().FullName
            sanitized_message = $message
            app_sha256 = $script:DiagnosticAppSha256
            session_id = $script:DiagnosticSessionId
            process_id = $script:DiagnosticProcessId
            window_tree = $script:DiagnosticWindowTree
            accessibility_observation = $script:DiagnosticAccessibility
            secret_material_redacted = $true
        }
        try {
            New-Item -ItemType Directory -Force -Path $diagnosticRoot | Out-Null
            [IO.File]::WriteAllText(
                $diagnosticErrorPath,
                ($errorReceipt | ConvertTo-Json -Depth 4),
                [Text.UTF8Encoding]::new($false)
            )
        } catch {}
    } elseif ($Mode -eq 'Execute') {
        $stage = if (
            $script:ExecuteStageAllowList.Contains($script:ExecuteStage)
        ) {
            $script:ExecuteStage
        } else {
            'nonce_validated'
        }
        $errorReceipt = [ordered]@{
            schema_version = 1
            contract = 'winsvpn-guarded-power-execute-error-v1'
            observed_utc = [DateTime]::UtcNow.ToString('o')
            ready_nonce = $ReadyNonce
            stage = $stage
            completed_stages = @($script:ExecuteCompletedStages)
            exception_type = $_.Exception.GetType().FullName
            sanitized_message =
                Get-SanitizedExceptionMessage $_.Exception
            connect_input_sent = $script:ConnectInputSent
            cancel_input_sent = $script:CancelInputSent
            app_sha256 = $script:DiagnosticAppSha256
            process_id = $script:DiagnosticProcessId
            session_id = $script:DiagnosticSessionId
            hwnd = $script:DiagnosticWindowHandle
            ui_signature_sha256 = $script:DiagnosticUiSignatureSha256
            controls = [ordered]@{
                connect = $script:DiagnosticConnectObservation
                cancel = $script:DiagnosticCancelObservation
                relationship = $script:DiagnosticControlRelationship
            }
            screenshots = [ordered]@{
                baseline_ready_sha256 =
                    $script:DiagnosticReadyBaselineScreenshotSha256
                baseline_execute_sha256 =
                    $script:DiagnosticBaselineScreenshotSha256
                baseline_screenshot_changed =
                    $script:DiagnosticBaselineScreenshotChanged
                cancel_state_sha256 =
                    $script:DiagnosticCancelScreenshotSha256
                transition_screenshot_changed =
                    $script:DiagnosticTransitionScreenshotChanged
            }
            final_zero_residue = Get-ZeroResidueSnapshot
            secret_material_redacted = $true
        }
        Remove-Item -LiteralPath $executeSuccessPath -Force -ErrorAction SilentlyContinue
        Write-PrivateJson $executeErrorPath $errorReceipt
    }
    exit 1
} finally {
    # Diagnostic finalization must never perform input or alter tunnel state.
}
