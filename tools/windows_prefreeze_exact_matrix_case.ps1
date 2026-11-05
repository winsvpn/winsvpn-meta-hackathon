[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet(
        'double-natural',
        'double-xray80',
        'double-xray443',
        'single-natural',
        'single-xray80',
        'single-xray443',
        'single-split-curl'
    )][string]$Case,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedRunnerSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedGuiSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedServiceSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPublicEgressSha256,
    [Parameter(Mandatory)][string]$RunRoot,
    [ValidateRange(60, 120)][int]$ConnectTimeoutSeconds = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$InstallRoot = Join-Path $env:ProgramFiles 'WinsVPN'
$InstalledGui = Join-Path $InstallRoot 'wins_vpn.exe'
$InstalledService = Join-Path $InstallRoot 'wins_vpn_tunnel_service.exe'
$InstalledXray = Join-Path $InstallRoot 'xray.exe'
$SecureStateRoot = Join-Path $env:LOCALAPPDATA 'WinsVPN\SecureState'
$LegacyStateRoot = Join-Path $env:APPDATA 'wins_vpn'
$AllowedEvidenceRoot = Join-Path $env:ProgramData 'WinsVPN\PreFreezeMatrix'
$RunRoot = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
$RunLeaf = Split-Path -Leaf $RunRoot
$EvidenceRoot = Join-Path $RunRoot 'evidence'
$PrivateRoot = Join-Path $RunRoot 'private'
$BackupRoot = Join-Path $PrivateRoot 'state-backup'
$StatusPath = Join-Path $RunRoot 'case-status.json'
$LogPath = Join-Path $RunRoot 'case-output.log'
$StagePath = Join-Path $RunRoot 'case-stage.json'
$LiveCycle = Join-Path $PSScriptRoot 'windows_interactive_live_cycle.ps1'
$CaptureTool = Join-Path $PSScriptRoot 'windows_interactive_uia_probe.ps1'
$FirewallGroup = "WinsVPN-PreFreeze-$RunLeaf"
$ManagerService = 'WinsVpnTunnelManager'
$ExpectedGuiSha256 = $ExpectedGuiSha256.ToLowerInvariant()
$ExpectedRunnerSha256 = $ExpectedRunnerSha256.ToLowerInvariant()
$ExpectedServiceSha256 = $ExpectedServiceSha256.ToLowerInvariant()
$ExpectedPublicEgressSha256 = $ExpectedPublicEgressSha256.ToLowerInvariant()
$SystemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$AdministratorsSid = [Security.Principal.SecurityIdentifier]::new(
    'S-1-5-32-544'
)
$started = [DateTime]::UtcNow
$stage = 'initialization'
$result = 'failed'
$failure = ''
$emergencyCleanupUsed = $false
$stateRestored = $false
$forcingRemoved = $false
$guiRestored = $false
$liveGuiNormalTokenVerified = $false
$finalGuiNormalTokenVerified = $false
$liveEvidence = $null
$liveEvidencePath = ''
$observedXrayPorts = @()
$portObserver = $null
$canaryPath = ''
$originalState = @()
$originalLegacyState = @()
$secureStateRootExisted = $false
$legacyStateRootExisted = $false
$TargetUserSid = ''
$strictSecureAclRestored = $false
$stableStateHandoffVerified = $false
$baselineArmed = $false
$baselineSecureClosure = ''
$baselineLegacyClosure = ''
$baselineLegacyTopology = ''
$baselineSecureAclContract = $false
$residueProviderErrors = @()
$guiStopEvidence = @()
$guiLaunchTimingEvidence = @()
$retiredExactGuiPids = @()
$runnerSelfHashVerified = $false

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class WinsVpnPreFreezeNativeV1 {
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint ProtectedDaclSecurityInformation = 0x80000000;
    private const int TokenElevation = 20;
    private const uint GwOwner = 4;
    private const int DwmwaCloaked = 14;

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate bool EnumWindowsProc(IntPtr window, IntPtr parameter);

    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access,
        out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool GetTokenInformation(IntPtr token, int informationClass,
        out int information, int informationLength, out int returnLength);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string sddl, uint revision, out IntPtr descriptor, IntPtr size);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool SetFileSecurityW(string path,
        uint securityInformation, IntPtr descriptor);
    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr parameter);
    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")]
    private static extern bool IsIconic(IntPtr window);
    [DllImport("user32.dll")]
    private static extern IntPtr GetParent(IntPtr window);
    [DllImport("user32.dll")]
    private static extern IntPtr GetWindow(IntPtr window, uint command);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    private static extern int GetClassName(IntPtr window, StringBuilder value, int maximum);
    [DllImport("dwmapi.dll")]
    private static extern int DwmGetWindowAttribute(IntPtr window, int attribute,
        out int value, int valueSize);

    public static bool IsProcessElevated(uint pid) {
        IntPtr process = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (process == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            IntPtr token;
            if (!OpenProcessToken(process, TokenQuery, out token))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                int elevated, returned;
                if (!GetTokenInformation(token, TokenElevation, out elevated,
                        sizeof(int), out returned))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return elevated != 0;
            } finally { CloseHandle(token); }
        } finally { CloseHandle(process); }
    }

    public static IntPtr FindExactWindow(uint pid) {
        var matches = new List<IntPtr>();
        EnumWindows(delegate(IntPtr window, IntPtr unused) {
            uint ownerPid;
            GetWindowThreadProcessId(window, out ownerPid);
            if (ownerPid != pid || !IsWindowVisible(window) || IsIconic(window) ||
                    GetParent(window) != IntPtr.Zero ||
                    GetWindow(window, GwOwner) != IntPtr.Zero) return true;
            var name = new StringBuilder(256);
            GetClassName(window, name, name.Capacity);
            if (!String.Equals(name.ToString(), "FLUTTER_RUNNER_WIN32_WINDOW",
                    StringComparison.Ordinal)) return true;
            int cloaked = 0;
            if (DwmGetWindowAttribute(window, DwmwaCloaked, out cloaked,
                    sizeof(int)) == 0 && cloaked != 0) return true;
            matches.Add(window);
            return true;
        }, IntPtr.Zero);
        return matches.Count == 1 ? matches[0] : IntPtr.Zero;
    }

    public static void ApplyProtectedDacl(string path, string sddl) {
        IntPtr descriptor;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, out descriptor, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            if (!SetFileSecurityW(path,
                    DaclSecurityInformation | ProtectedDaclSecurityInformation,
                    descriptor))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        } finally { LocalFree(descriptor); }
    }
}
'@

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-BytesSha256 {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($algorithm.ComputeHash($Bytes))).Replace(
            '-', ''
        ).ToLowerInvariant()
    } finally { $algorithm.Dispose() }
}

function Get-StringSha256 {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($Value))
}

function Write-PrivateJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Value | ConvertTo-Json -Depth 12) + [Environment]::NewLine
    )
    [IO.File]::WriteAllBytes($Path, $bytes)
}

function Set-Stage {
    param([Parameter(Mandatory)][string]$Value)
    $script:stage = $Value
    Write-PrivateJson $StagePath ([ordered]@{
        schema_version = 1
        contract = 'winsvpn-windows-prefreeze-stage-v1'
        case = $Case
        stage = $Value
        observed_at_utc = [DateTime]::UtcNow.ToString('o')
        secret_material_redacted = $true
    })
}

function Assert-ElevatedInteractive {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not [Environment]::UserInteractive -or -not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )) {
        throw 'The pre-freeze matrix case requires an elevated interactive session.'
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
        if (Test-Path -LiteralPath $current -ErrorAction Stop) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "A matrix path contains a reparse point: $current"
            }
        }
    }
}

function Get-VerifiedStateFiles {
    param([Parameter(Mandatory)][string]$Root)
    Assert-NoReparsePath $Root
    if (-not (Test-Path -LiteralPath $Root -ErrorAction Stop)) { return @() }
    if (-not (Test-Path -LiteralPath $Root -PathType Container `
            -ErrorAction Stop)) {
        throw "A protected state root is not a directory: $Root"
    }
    $items = @(Get-ChildItem -LiteralPath $Root -Force -ErrorAction Stop |
        Sort-Object Name)
    foreach ($item in $items) {
        Assert-NoReparsePath $item.FullName
        if ($item.PSIsContainer) {
            throw "A protected state root contains a non-file entry: $($item.FullName)"
        }
        $item
    }
}

function Set-PrivateDirectoryAcl {
    param([Parameter(Mandatory)][string]$Path)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($SystemSid, $AdministratorsSid)) {
        [void]$acl.AddAccessRule(
            [Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance,
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow
            )
        )
    }
    $acl.SetOwner($AdministratorsSid)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-ExactInstalledPayload {
    foreach ($path in @($InstalledGui, $InstalledService, $InstalledXray,
            $LiveCycle, $CaptureTool)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required exact matrix input is missing: $path"
        }
    }
    if ((Get-Sha256 $InstalledGui) -cne $ExpectedGuiSha256 -or
        (Get-Sha256 $InstalledService) -cne $ExpectedServiceSha256) {
        throw 'Installed Windows payload does not match the exact candidate.'
    }
    $manager = Get-CimInstance Win32_Service -Filter "Name='$ManagerService'"
    if (-not $manager -or $manager.State -cne 'Running' -or
        $manager.StartMode -cne 'Auto' -or $manager.StartName -cne 'LocalSystem') {
        throw 'The protected tunnel manager is absent or misconfigured.'
    }
    foreach ($process in @(Get-Process wins_vpn -ErrorAction SilentlyContinue)) {
        if ((Get-Sha256 $process.Path) -ceq $ExpectedGuiSha256 -and
            [WinsVpnPreFreezeNativeV1]::IsProcessElevated([uint32]$process.Id)) {
            throw 'The exact GUI was already running with an elevated token.'
        }
    }
}

function Invoke-ResidueProviderQuery {
    param(
        [Parameter(Mandatory)][ValidateSet('service', 'adapter', 'route', 'wfp')]
        [string]$Provider,
        [Parameter(Mandatory)][scriptblock]$Query
    )
    try {
        & $Query
    } catch {
        $record = [ordered]@{
            error_id = 'WINS_PREFREEZE_RESIDUE_PROVIDER_FAILURE'
            provider = $Provider
            exception_type = $_.Exception.GetType().FullName
            message = [string]$_.Exception.Message
            observed_at_utc = [DateTime]::UtcNow.ToString('o')
        }
        $script:residueProviderErrors += [pscustomobject]$record
        throw [InvalidOperationException]::new(
            ($record | ConvertTo-Json -Compress),
            $_.Exception
        )
    }
}

function Get-OwnedWfpFilterCount {
    $path = Join-Path $PrivateRoot (
        'wfp-residue-' + [Guid]::NewGuid().ToString('N') + '.xml'
    )
    try {
        [int](Invoke-ResidueProviderQuery -Provider wfp -Query {
            Assert-NoReparsePath $PrivateRoot
            & netsh.exe wfp show state "file=$path" 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0 -or
                -not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw 'Windows Filtering Platform state enumeration failed.'
            }
            Assert-NoReparsePath $path
            [xml]$document = Get-Content -LiteralPath $path -Raw `
                -ErrorAction Stop
            $filterNodes = @()
            foreach ($container in @($document.SelectNodes(
                        "//*[local-name()='filters']"
                    ))) {
                $filterNodes += @($container.ChildNodes | Where-Object {
                    $_.NodeType -eq [Xml.XmlNodeType]::Element
                })
            }
            if ($filterNodes.Count -eq 0) {
                $filterNodes = @($document.SelectNodes(
                    "//*[local-name()='filter']"
                ))
            }
            $ownedGuids = @(
                '21e068a2-2851-43c5-8a29-7afe3f260384',
                'e65841b6-82f6-4d55-bde2-61f84d4508d4'
            )
            @($filterNodes | Where-Object {
                $xml = $_.InnerXml
                @($ownedGuids | Where-Object {
                    $xml -match [regex]::Escape($_)
                }).Count -gt 0
            }).Count
        })
    } finally {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

function Get-ResidueState {
    $services = @(Invoke-ResidueProviderQuery -Provider service -Query {
        Get-Service -ErrorAction Stop | Where-Object {
            ($_.Name -eq 'WinsVPNSplitTunnel' -or
             $_.Name -like 'AmneziaWGTunnel$winsvpn*') -and
            $_.Status -ne 'Stopped'
        }
    })
    $adapters = @(Invoke-ResidueProviderQuery -Provider adapter -Query {
        Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
            $_.Name -eq 'winsvpn' -and $_.Status -ne 'Disabled'
        }
    })
    $routes = @(Invoke-ResidueProviderQuery -Provider route -Query {
        Get-NetRoute -ErrorAction Stop | Where-Object {
            $_.InterfaceAlias -eq 'winsvpn'
        }
    })
    # An absent xray process is expected and is deliberately not treated as a
    # service/network provider failure.
    $xray = @(Get-Process xray -ErrorAction SilentlyContinue)
    $awgEngine = @(Get-Process winsvpn_awg_engine `
        -ErrorAction SilentlyContinue)
    $ownedWfpFilterCount = Get-OwnedWfpFilterCount
    [ordered]@{
        tunnel_service_count = $services.Count
        tunnel_adapter_count = $adapters.Count
        tunnel_route_count = $routes.Count
        xray_process_count = $xray.Count
        awg_engine_process_count = $awgEngine.Count
        owned_wfp_filter_count = $ownedWfpFilterCount
        is_zero = $services.Count -eq 0 -and $adapters.Count -eq 0 -and
            $routes.Count -eq 0 -and $xray.Count -eq 0 -and
            $awgEngine.Count -eq 0 -and
            $ownedWfpFilterCount -eq 0
    }
}

function Get-ExactGuiProcesses {
    @(Get-Process wins_vpn -ErrorAction SilentlyContinue | Where-Object {
        try {
            [IO.Path]::GetFullPath($_.Path) -ceq
                [IO.Path]::GetFullPath($InstalledGui) -and
            (Get-Sha256 $_.Path) -ceq $ExpectedGuiSha256
        } catch { $false }
    })
}

function Stop-ExactGui {
    param([string]$Purpose = 'unspecified')
    $startedAt = [DateTime]::UtcNow
    $oldPids = @()
    $remainingPids = @()
    $failureMessage = ''
    try {
        $oldPids = @(Get-ExactGuiProcesses | ForEach-Object { [int]$_.Id })
        $combinedRetiredPids = @($script:retiredExactGuiPids) + @($oldPids)
        $script:retiredExactGuiPids = @(
            $combinedRetiredPids | Sort-Object -Unique
        )
        foreach ($processId in $oldPids) {
            $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($null -ne $process) {
                Stop-Process -Id $processId -Force -ErrorAction Stop
            }
        }
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            $remainingPids = @($oldPids | Where-Object {
                $null -ne (Get-Process -Id $_ -ErrorAction SilentlyContinue)
            })
            if ($remainingPids.Count -eq 0) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($remainingPids.Count -ne 0) {
            throw 'An old exact-hash GUI PID did not exit within 10 seconds.'
        }
    } catch {
        $failureMessage = [string]$_.Exception.Message
        $remainingPids = @($oldPids | Where-Object {
            $null -ne (Get-Process -Id $_ -ErrorAction SilentlyContinue)
        })
        throw
    } finally {
        $script:guiStopEvidence += [pscustomobject][ordered]@{
            purpose = $Purpose
            started_at_utc = $startedAt.ToString('o')
            completed_at_utc = [DateTime]::UtcNow.ToString('o')
            deadline_seconds = 10
            old_exact_hash_pids = @($oldPids)
            remaining_old_pids = @($remainingPids)
            all_old_pids_exited = $remainingPids.Count -eq 0
            failure = $failureMessage
        }
    }
    $oldPids
}

function Get-OnlyNormalExactGui {
    param(
        [Parameter(Mandatory)][int]$SessionId,
        [int[]]$ExcludedPids = @()
    )
    $matches = @(Get-Process wins_vpn -ErrorAction SilentlyContinue |
        Where-Object {
            if ($_.SessionId -ne $SessionId -or
                $ExcludedPids -contains [int]$_.Id) { return $false }
            try { (Get-Sha256 $_.Path) -ceq $ExpectedGuiSha256 }
            catch { $false }
        })
    if ($matches.Count -ne 1 -or -not $matches[0].Responding -or
        [WinsVpnPreFreezeNativeV1]::IsProcessElevated([uint32]$matches[0].Id) -or
        [WinsVpnPreFreezeNativeV1]::FindExactWindow(
            [uint32]$matches[0].Id
        ) -eq [IntPtr]::Zero) {
        return $null
    }
    $matches[0]
}

function Invoke-GuiLaunchTimedStep {
    param(
        [Parameter(Mandatory)][Collections.IDictionary]$Evidence,
        [Parameter(Mandatory)][ValidateSet('register', 'semantic', 'start')]
        [string]$Step,
        [Parameter(Mandatory)][ValidateRange(1, 60)][int]$LimitSeconds,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    $startedAt = [DateTime]::UtcNow
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $succeeded = $false
    try {
        $null = & $Action
        $succeeded = $true
    } finally {
        $stopwatch.Stop()
        $Evidence[($Step + '_started_at_utc')] = $startedAt.ToString('o')
        $Evidence[($Step + '_duration_ms')] = [int64]$stopwatch.ElapsedMilliseconds
        $Evidence[($Step + '_limit_seconds')] = $LimitSeconds
        $Evidence[($Step + '_succeeded')] = $succeeded
        $Evidence[($Step + '_within_limit')] =
            $stopwatch.Elapsed.TotalSeconds -le $LimitSeconds
    }
    if ($stopwatch.Elapsed.TotalSeconds -gt $LimitSeconds) {
        throw "The GUI task $Step step exceeded its $LimitSeconds-second bound."
    }
}

function Assert-GuiTaskSemanticContract {
    param(
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][ValidatePattern('^S-1-5-21(?:-[0-9]+){4}$')]
        [string]$UserSid
    )
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    $actions = @($task.Actions)
    [xml]$definition = Export-ScheduledTask -TaskName $TaskName
    $namespace = [Xml.XmlNamespaceManager]::new($definition.NameTable)
    $namespace.AddNamespace(
        't', 'http://schemas.microsoft.com/windows/2004/02/mit/task'
    )
    $principals = @($definition.SelectNodes(
        '/t:Task/t:Principals/t:Principal', $namespace
    ))
    $xmlActions = @($definition.SelectNodes(
        '/t:Task/t:Actions/t:Exec', $namespace
    ))
    $actionsNode = $definition.SelectSingleNode(
        '/t:Task/t:Actions', $namespace
    )
    $xmlTriggers = @($definition.SelectNodes(
        '/t:Task/t:Triggers/*', $namespace
    ))
    if ($principals.Count -ne 1 -or $xmlActions.Count -ne 1) {
        throw 'The GUI launch task does not have one principal and action.'
    }
    $principal = $principals[0]
    $runLevel = $principal.SelectSingleNode('t:RunLevel', $namespace)
    $xmlCommand = $xmlActions[0].SelectSingleNode('t:Command', $namespace)
    $xmlArguments = $xmlActions[0].SelectSingleNode('t:Arguments', $namespace)
    $xmlWorkingDirectory = $xmlActions[0].SelectSingleNode(
        't:WorkingDirectory', $namespace
    )
    $registeredPathMatches = try {
        [string]::Equals(
            [IO.Path]::GetFullPath([string]$actions[0].Execute),
            [IO.Path]::GetFullPath($InstalledGui),
            [StringComparison]::OrdinalIgnoreCase
        )
    } catch { $false }
    $xmlPathMatches = try {
        [string]::Equals(
            [IO.Path]::GetFullPath([string]$xmlCommand.InnerText),
            [IO.Path]::GetFullPath($InstalledGui),
            [StringComparison]::OrdinalIgnoreCase
        )
    } catch { $false }
    if ([string]$task.Principal.LogonType -cne 'Interactive' -or
        [string]$task.Principal.RunLevel -cne 'Limited' -or
        $actions.Count -ne 1 -or -not $registeredPathMatches -or
        -not [string]::IsNullOrWhiteSpace([string]$actions[0].Arguments) -or
        -not [string]::IsNullOrWhiteSpace(
            [string]$actions[0].WorkingDirectory
        ) -or [string]$principal.UserId -cne $UserSid -or
        [string]$principal.LogonType -cne 'InteractiveToken' -or
        ($null -ne $runLevel -and
            $runLevel.InnerText -cne 'LeastPrivilege') -or
        $xmlTriggers.Count -ne 0 -or -not $xmlPathMatches -or
        [string]$actionsNode.Context -cne [string]$principal.id -or
        ($null -ne $xmlArguments -and -not
            [string]::IsNullOrWhiteSpace($xmlArguments.InnerText)) -or
        ($null -ne $xmlWorkingDirectory -and -not
            [string]::IsNullOrWhiteSpace($xmlWorkingDirectory.InnerText))) {
        throw 'The GUI launch task semantic contract is invalid.'
    }
}

function Start-ExactGuiLeastPrivilege {
    param(
        [Parameter(Mandatory)][ValidateSet('live', 'restore')]
        [string]$Purpose
    )
    $launchStartedAt = [DateTime]::UtcNow
    $timing = [ordered]@{
        purpose = $Purpose
        started_at_utc = $launchStartedAt.ToString('o')
        post_start_observation_limit_seconds = 20
        register_started_at_utc = ''
        register_duration_ms = 0
        register_limit_seconds = 30
        register_succeeded = $false
        register_within_limit = $false
        semantic_started_at_utc = ''
        semantic_duration_ms = 0
        semantic_limit_seconds = 30
        semantic_succeeded = $false
        semantic_within_limit = $false
        start_started_at_utc = ''
        start_duration_ms = 0
        start_limit_seconds = 30
        start_succeeded = $false
        start_within_limit = $false
        process_observation_started_at_utc = ''
        process_observation_deadline_utc = ''
        process_observation_duration_ms = 0
        process_observation_within_limit = $false
        stopped_exact_hash_pids = @()
        launched_pid = 0
        new_pid_verified = $false
        outcome = 'failed'
        failure_step = ''
        failure = ''
        completed_at_utc = ''
    }
    $activeStep = 'stop_old_gui'
    $process = $null
    $stoppedPids = @()
    try {
        $null = Stop-ExactGui -Purpose "$Purpose-prelaunch"
        $stoppedPids = @($script:retiredExactGuiPids)
        $timing.stopped_exact_hash_pids = @($stoppedPids)
    $sessionId = (Get-Process -Id $PID).SessionId
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $taskName = "WinsVPN-PreFreeze-GUI-$RunLeaf"
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        throw 'The one-use least-privilege GUI task already exists.'
    }
    $escapedGui = [Security.SecurityElement]::Escape($InstalledGui)
    $escapedSid = [Security.SecurityElement]::Escape($identity.User.Value)
    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>One-use Win's VPN pre-freeze normal-token launch</Description></RegistrationInfo>
  <Principals><Principal id="Author"><UserId>$escapedSid</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy></Settings>
  <Triggers />
  <Actions Context="Author"><Exec><Command>$escapedGui</Command></Exec></Actions>
</Task>
"@
        try {
            $activeStep = 'register'
            Invoke-GuiLaunchTimedStep -Evidence $timing -Step register `
                -LimitSeconds 30 -Action {
                    Register-ScheduledTask -TaskName $taskName -Xml $taskXml |
                        Out-Null
                }
            $activeStep = 'semantic'
            Invoke-GuiLaunchTimedStep -Evidence $timing -Step semantic `
                -LimitSeconds 30 -Action {
                    Assert-GuiTaskSemanticContract -TaskName $taskName `
                        -UserSid $identity.User.Value
                }
            $activeStep = 'start'
            Invoke-GuiLaunchTimedStep -Evidence $timing -Step start `
                -LimitSeconds 30 -Action {
                    Start-ScheduledTask -TaskName $taskName
                }
            $activeStep = 'process_observation'
            $observationStartedAt = [DateTime]::UtcNow
            $deadline = $observationStartedAt.AddSeconds(20)
            do {
                Start-Sleep -Milliseconds 250
                $process = Get-OnlyNormalExactGui -SessionId $sessionId `
                    -ExcludedPids $stoppedPids
            } while ($null -eq $process -and [DateTime]::UtcNow -lt $deadline)
            $timing.process_observation_started_at_utc =
                $observationStartedAt.ToString('o')
            $timing.process_observation_deadline_utc = $deadline.ToString('o')
            $timing.process_observation_duration_ms = [int64](
                ([DateTime]::UtcNow - $observationStartedAt).TotalMilliseconds
            )
            $timing.process_observation_within_limit =
                [DateTime]::UtcNow -le $deadline
            if ($null -eq $process) {
                throw 'The least-privilege task did not expose one new exact normal-token GUI.'
            }
            $timing.launched_pid = [int]$process.Id
            $timing.new_pid_verified =
                $stoppedPids -notcontains [int]$process.Id
            if (-not $timing.new_pid_verified) {
                throw 'The GUI launch reused a PID from the stopped exact process set.'
            }
        } finally {
            $activeStep = 'task_cleanup'
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false `
                -ErrorAction SilentlyContinue
        }
        $activeStep = 'post_cleanup_persistence'
        Start-Sleep -Milliseconds 750
        $persisted = Get-OnlyNormalExactGui -SessionId $sessionId `
            -ExcludedPids $stoppedPids
        if ($null -eq $persisted -or $persisted.Id -ne $process.Id -or
            $null -ne (Get-ScheduledTask -TaskName $taskName `
                -ErrorAction SilentlyContinue)) {
            throw 'The new exact normal-token GUI or one-use task cleanup did not persist.'
        }
        $process = $persisted
        $timing.outcome = 'passed'
        $process
    } catch {
        $timing.failure_step = $activeStep
        $timing.failure = [string]$_.Exception.Message
        throw
    } finally {
        $timing.completed_at_utc = [DateTime]::UtcNow.ToString('o')
        $script:guiLaunchTimingEvidence += [pscustomobject]$timing
    }
}

function Invoke-EmergencyCleanup {
    $script:emergencyCleanupUsed = $true
    $null = Stop-ExactGui -Purpose 'emergency-cleanup'
    try {
        $manager = Get-Service $ManagerService -ErrorAction Stop
        if ($manager.Status -ne 'Stopped') {
            Stop-Service $ManagerService -Force -ErrorAction Stop
            $manager = Get-Service $ManagerService -ErrorAction Stop
            $manager.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(45))
        }
    } finally {
        $manager = Get-Service $ManagerService -ErrorAction Stop
        if ($manager.Status -ne 'Running') {
            Start-Service $ManagerService -ErrorAction Stop
            $manager = Get-Service $ManagerService -ErrorAction Stop
            $manager.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        }
        $manager = Get-Service $ManagerService -ErrorAction Stop
        if ($manager.Status -ne 'Running') {
            throw 'WinsVpnTunnelManager was not restored to Running.'
        }
    }
}

function Get-StateFiles {
    param([Parameter(Mandatory)][string]$Root)
    $files = @(Get-VerifiedStateFiles -Root $Root)
    if (-not (Test-Path -LiteralPath $Root -PathType Container `
            -ErrorAction Stop)) { return @() }
    @($files | ForEach-Object {
            Assert-NoReparsePath $_.FullName
            $bytes = [IO.File]::ReadAllBytes($_.FullName)
            Assert-NoReparsePath $_.FullName
            [ordered]@{
                name = $_.Name
                bytes = $bytes
                sha256 = Get-Sha256 $_.FullName
            }
        })
}

function Backup-StateFiles {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)]$Files
    )
    Assert-NoReparsePath $Root
    Assert-NoReparsePath $Destination
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Assert-NoReparsePath $Destination
    if (@(Get-VerifiedStateFiles -Root $Destination).Count -ne 0) {
        throw "A protected state backup destination is not empty: $Destination"
    }
    foreach ($entry in @($Files)) {
        $path = Join-Path $Destination ([string]$entry.name)
        Assert-NoReparsePath $path
        [IO.File]::WriteAllBytes($path, [byte[]]$entry.bytes)
        Assert-NoReparsePath $path
        if ((Get-Sha256 $path) -cne [string]$entry.sha256) {
            throw "Protected state backup hash mismatch: $Root"
        }
    }
}

function Get-StrictSecureStateDaclSddl {
    param(
        [Parameter(Mandatory)][ValidatePattern('^S-1-5-21(?:-[0-9]+){4}$')]
        [string]$UserSid
    )
    "D:P(A;;FA;;;SY)(A;;FA;;;$UserSid)"
}

function Set-StrictSecureStatePathAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidatePattern('^S-1-5-21(?:-[0-9]+){4}$')]
        [string]$UserSid
    )
    Assert-NoReparsePath $Path
    [WinsVpnPreFreezeNativeV1]::ApplyProtectedDacl(
        $Path,
        (Get-StrictSecureStateDaclSddl -UserSid $UserSid)
    )
}

function Test-StrictSecureStatePathAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidatePattern('^S-1-5-21(?:-[0-9]+){4}$')]
        [string]$UserSid
    )
    try {
        Assert-NoReparsePath $Path
        $acl = Get-Acl -LiteralPath $Path
        $entries = @($acl.Access)
        $actualSids = @($entries | ForEach-Object {
            $_.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]
            ).Value
        } | Sort-Object -Unique)
        $expectedSids = @('S-1-5-18', $UserSid) | Sort-Object
        $acl.AreAccessRulesProtected -and $entries.Count -eq 2 -and
            ($actualSids -join '|') -ceq ($expectedSids -join '|') -and
            @($entries | Where-Object {
                $_.AccessControlType -ne
                    [Security.AccessControl.AccessControlType]::Allow -or
                $_.FileSystemRights -ne
                    [Security.AccessControl.FileSystemRights]::FullControl -or
                $_.IsInherited
            }).Count -eq 0
    } catch { $false }
}

function Set-StrictSecureStateAcl {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidatePattern('^S-1-5-21(?:-[0-9]+){4}$')]
        [string]$UserSid
    )
    Set-StrictSecureStatePathAcl -Path $Root -UserSid $UserSid
    foreach ($file in @(Get-VerifiedStateFiles -Root $Root)) {
        Set-StrictSecureStatePathAcl -Path $file.FullName -UserSid $UserSid
    }
}

function Test-StrictSecureStateAcl {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidatePattern('^S-1-5-21(?:-[0-9]+){4}$')]
        [string]$UserSid
    )
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        return $false
    }
    foreach ($path in @($Root) + @(
            Get-VerifiedStateFiles -Root $Root |
                Select-Object -ExpandProperty FullName
        )) {
        if (-not (Test-StrictSecureStatePathAcl -Path $path `
                -UserSid $UserSid)) { return $false }
    }
    $true
}

function Test-StateFilesExact {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]$Files,
        [Parameter(Mandatory)][bool]$RootExisted
    )
    $exists = Test-Path -LiteralPath $Root -PathType Container
    if (-not $RootExisted) { return -not $exists }
    if (-not $exists) { return $false }
    $expected = @($Files | Sort-Object name | ForEach-Object {
        ([string]$_.name) + ':' + ([string]$_.sha256)
    })
    $actual = @(Get-StateFiles $Root | Sort-Object name | ForEach-Object {
        ([string]$_.name) + ':' + ([string]$_.sha256)
    })
    ($actual -join '|') -ceq ($expected -join '|')
}

function Restore-StateFiles {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)]$Files,
        [Parameter(Mandatory)][bool]$RootExisted,
        [Parameter(Mandatory)][bool]$BaselineArmed,
        [ValidatePattern('^$|^S-1-5-21(?:-[0-9]+){4}$')]
        [string]$StrictDaclUserSid = ''
    )
    if (-not $BaselineArmed) {
        throw 'State restoration is unavailable before the baseline is armed.'
    }
    Assert-NoReparsePath $Root
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    Assert-NoReparsePath $Root
    $expectedNames = @($Files | ForEach-Object { [string]$_.name })
    Get-VerifiedStateFiles -Root $Root |
        Where-Object { $_.Name -notin $expectedNames } |
        ForEach-Object {
            Assert-NoReparsePath $_.FullName
            Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
        }
    foreach ($entry in @($Files)) {
        $target = Join-Path $Root ([string]$entry.name)
        $temporary = "$target.prefreeze-restore.tmp"
        Assert-NoReparsePath $target
        Assert-NoReparsePath $temporary
        if (Test-Path -LiteralPath $temporary -ErrorAction Stop) {
            throw 'A stale protected-state restore temporary blocks recovery.'
        }
        [IO.File]::WriteAllBytes($temporary, [byte[]]$entry.bytes)
        Assert-NoReparsePath $temporary
        Move-Item -LiteralPath $temporary -Destination $target -Force
        Assert-NoReparsePath $target
        if ((Get-Sha256 $target) -cne [string]$entry.sha256) {
            throw 'Protected app state did not restore byte-for-byte.'
        }
    }
    $actualNames = @(Get-VerifiedStateFiles -Root $Root |
        Sort-Object Name | Select-Object -ExpandProperty Name)
    if (($actualNames -join '|') -cne (($expectedNames | Sort-Object) -join '|')) {
        throw 'Protected app state file set did not restore exactly.'
    }
    if (-not [string]::IsNullOrWhiteSpace($StrictDaclUserSid)) {
        Set-StrictSecureStateAcl -Root $Root -UserSid $StrictDaclUserSid
        if (-not (Test-StrictSecureStateAcl -Root $Root `
                -UserSid $StrictDaclUserSid)) {
            throw 'The strict SecureState DACL did not restore exactly.'
        }
    }
    if (-not $RootExisted) {
        if (@(Get-VerifiedStateFiles -Root $Root).Count -ne 0) {
            throw 'A previously absent app-state directory is not empty after restore.'
        }
        Assert-NoReparsePath $Root
        Remove-Item -LiteralPath $Root -Force -ErrorAction Stop
    }
}

function Read-ProtectedJson {
    param([Parameter(Mandatory)][string]$Name)
    Add-Type -AssemblyName System.Security
    $path = Join-Path $SecureStateRoot ($Name + '.wvdp')
    Assert-NoReparsePath $SecureStateRoot
    Assert-NoReparsePath $path
    [byte[]]$encoded = [IO.File]::ReadAllBytes($path)
    [byte[]]$magic = [byte[]](0x57, 0x56, 0x44, 0x50, 1, 0, 0, 0)
    if ($encoded.Length -le $magic.Length) { throw 'Protected state is truncated.' }
    for ($index = 0; $index -lt $magic.Length; ++$index) {
        if ($encoded[$index] -ne $magic[$index]) {
            throw 'Protected state framing is invalid.'
        }
    }
    [byte[]]$ciphertext = [byte[]]::new($encoded.Length - $magic.Length)
    [Array]::Copy($encoded, $magic.Length, $ciphertext, 0, $ciphertext.Length)
    [byte[]]$entropy = [Text.Encoding]::UTF8.GetBytes(
        'WinsVPN:WindowsSecureText:v1:' + $Name
    )
    [byte[]]$plaintext = $null
    try {
        $plaintext = [Security.Cryptography.ProtectedData]::Unprotect(
            $ciphertext,
            $entropy,
            [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        [Text.UTF8Encoding]::new($false, $true).GetString($plaintext) |
            ConvertFrom-Json
    } finally {
        if ($null -ne $plaintext) { [Array]::Clear($plaintext, 0, $plaintext.Length) }
        [Array]::Clear($entropy, 0, $entropy.Length)
        [Array]::Clear($ciphertext, 0, $ciphertext.Length)
        [Array]::Clear($encoded, 0, $encoded.Length)
    }
}

function Write-ProtectedJson {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][ValidatePattern('^S-1-5-21(?:-[0-9]+){4}$')]
        [string]$StrictDaclUserSid
    )
    Add-Type -AssemblyName System.Security
    [byte[]]$magic = [byte[]](0x57, 0x56, 0x44, 0x50, 1, 0, 0, 0)
    [byte[]]$plaintext = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Value | ConvertTo-Json -Depth 20 -Compress)
    )
    [byte[]]$entropy = [Text.Encoding]::UTF8.GetBytes(
        'WinsVPN:WindowsSecureText:v1:' + $Name
    )
    [byte[]]$ciphertext = $null
    [byte[]]$framed = $null
    $temporary = ''
    try {
        $ciphertext = [Security.Cryptography.ProtectedData]::Protect(
            $plaintext,
            $entropy,
            [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        $framed = [byte[]]::new($magic.Length + $ciphertext.Length)
        [Array]::Copy($magic, 0, $framed, 0, $magic.Length)
        [Array]::Copy($ciphertext, 0, $framed, $magic.Length, $ciphertext.Length)
        $path = Join-Path $SecureStateRoot ($Name + '.wvdp')
        $temporary = "$path.prefreeze-write.tmp"
        Assert-NoReparsePath $SecureStateRoot
        Assert-NoReparsePath $path
        Assert-NoReparsePath $temporary
        if (Test-Path -LiteralPath $temporary -ErrorAction Stop) {
            throw 'A stale protected-state temporary file blocks the write.'
        }
        [IO.File]::WriteAllBytes($temporary, $framed)
        Assert-NoReparsePath $temporary
        Set-StrictSecureStatePathAcl -Path $temporary `
            -UserSid $StrictDaclUserSid
        if (-not (Test-StrictSecureStatePathAcl -Path $temporary `
                -UserSid $StrictDaclUserSid)) {
            throw 'The protected-state temporary DACL is not strict.'
        }
        Move-Item -LiteralPath $temporary -Destination $path -Force
        Assert-NoReparsePath $path
        Set-StrictSecureStatePathAcl -Path $path `
            -UserSid $StrictDaclUserSid
        if (-not (Test-StrictSecureStateAcl -Root $SecureStateRoot `
                -UserSid $StrictDaclUserSid)) {
            throw 'The atomic protected-state replacement weakened its DACL.'
        }
    } finally {
        if (-not [string]::IsNullOrWhiteSpace($temporary) -and
            (Test-Path -LiteralPath $temporary)) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
        if ($null -ne $framed) { [Array]::Clear($framed, 0, $framed.Length) }
        if ($null -ne $ciphertext) { [Array]::Clear($ciphertext, 0, $ciphertext.Length) }
        [Array]::Clear($plaintext, 0, $plaintext.Length)
        [Array]::Clear($entropy, 0, $entropy.Length)
    }
}

function Set-TestPreference {
    $settings = Read-ProtectedJson 'vpn_settings.txt'
    $double = $Case -like 'double-*'
    $settings | Add-Member -NotePropertyName double_vpn_requested `
        -NotePropertyValue $double -Force
    if ($Case -eq 'single-split-curl') {
        $settings | Add-Member -NotePropertyName excluded_vpn_packages `
            -NotePropertyValue @($canaryPath) -Force
    } else {
        $settings | Add-Member -NotePropertyName excluded_vpn_packages `
            -NotePropertyValue @() -Force
    }
    Write-ProtectedJson -Name 'vpn_settings.txt' -Value $settings `
        -StrictDaclUserSid $TargetUserSid
    if (-not (Test-StrictSecureStateAcl -Root $SecureStateRoot `
            -UserSid $TargetUserSid)) {
        throw 'The test preference write did not preserve the strict DACL.'
    }
}

function Add-ForcingRules {
    if ($Case -notmatch '^.+-xray(80|443)$') { return }
    if (Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue) {
        throw 'The matrix forcing firewall group already exists.'
    }
    $targetPort = [int]$Matches[1]
    foreach ($port in @(9110, 9210)) {
        New-NetFirewallRule -Name "$FirewallGroup-udp-$port" `
            -DisplayName "$FirewallGroup UDP $port" -Group $FirewallGroup `
            -Direction Outbound -Action Block -Enabled True -Profile Any `
            -Protocol UDP -RemotePort $port | Out-Null
    }
    $otherPort = if ($targetPort -eq 80) { 443 } else { 80 }
    # Only xray.exe owns the carrier socket. Blocking the Flutter GUI on 443
    # would also block its authenticated config refresh and would not isolate
    # the transport being tested.
    foreach ($program in @($InstalledXray)) {
        New-NetFirewallRule -Name (
            "$FirewallGroup-tcp-$otherPort-" +
            (Get-StringSha256 $program).Substring(0, 12)
        ) -DisplayName "$FirewallGroup TCP $otherPort" -Group $FirewallGroup `
            -Direction Outbound -Action Block -Enabled True -Profile Any `
            -Program $program -Protocol TCP -RemotePort $otherPort | Out-Null
    }
    $rules = @(Get-NetFirewallRule -Group $FirewallGroup -ErrorAction Stop)
    if ($rules.Count -ne 3 -or @($rules | Where-Object {
                $_.Enabled -ne 'True' -or $_.Direction -ne 'Outbound' -or
                $_.Action -ne 'Block'
            }).Count -ne 0) {
        throw 'The exact fallback forcing transaction did not converge.'
    }
}

function Remove-ForcingRules {
    Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction Stop
    if (Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue) {
        throw 'Temporary fallback forcing rules remained after cleanup.'
    }
    $script:forcingRemoved = $true
}

function Start-XrayPortObserver {
    if ($Case -notmatch '^.+-xray(80|443)$') { return $null }
    Start-Job -ScriptBlock {
        param([DateTime]$Deadline)
        while ([DateTime]::UtcNow -lt $Deadline) {
            foreach ($process in @(Get-Process xray -ErrorAction SilentlyContinue)) {
                foreach ($connection in @(Get-NetTCPConnection `
                            -OwningProcess $process.Id -State Established `
                            -ErrorAction SilentlyContinue)) {
                    [int]$connection.RemotePort
                }
            }
            Start-Sleep -Milliseconds 100
        }
    } -ArgumentList ([DateTime]::UtcNow.AddSeconds(
        [Math]::Min(300, $ConnectTimeoutSeconds + 75)
    ))
}

function Stop-XrayPortObserver {
    if ($null -eq $script:portObserver) { return @() }
    Stop-Job -Job $script:portObserver -ErrorAction SilentlyContinue
    $ports = @(Receive-Job -Job $script:portObserver -ErrorAction SilentlyContinue |
        ForEach-Object { [int]$_ } | Sort-Object -Unique)
    Remove-Job -Job $script:portObserver -Force -ErrorAction SilentlyContinue
    $script:portObserver = $null
    $ports
}

function Assert-LiveEvidence {
    param([Parameter(Mandatory)]$Evidence)
    if ([string]$Evidence.app_sha256 -cne $ExpectedGuiSha256 -or
        [string]$Evidence.service_sha256 -cne $ExpectedServiceSha256 -or
        [string]$Evidence.expected_public_egress_sha256 -cne
            $ExpectedPublicEgressSha256 -or
        [string]$Evidence.connected_public_egress_sha256 -cne
            $ExpectedPublicEgressSha256 -or
        $Evidence.disconnect_ok -ne $true -or
        $Evidence.original_routes_restored -ne $true -or
        $Evidence.original_public_egress_restored -ne $true -or
        $Evidence.cleanup_fallback_used -ne $false -or
        $Evidence.baseline_external_dns_resolution_succeeded -ne $true -or
        $Evidence.tunnel_dns_resolution_succeeded -ne $true -or
        $Evidence.direct_external_dns_blocked_while_connected -ne $true -or
        $Evidence.direct_external_dns_restored_after_disconnect -ne $true -or
        $Evidence.connected_ipv6_fail_closed_passed -ne $true -or
        [int]$Evidence.connected_ipv6_non_tunnel_default_route_count -ne 0 -or
        $Evidence.connected_ipv6_tunnel_route_ownership_verified -ne $true -or
        $Evidence.connected_ipv6_forced_literal_egress_failed -ne $true -or
        $Evidence.original_ipv6_default_routes_restored -ne $true -or
        $Evidence.original_physical_ms_tcpip6_bindings_restored -ne $true -or
        [int]$Evidence.baseline_owned_wfp_filter_count -ne 0 -or
        [int]$Evidence.final_owned_wfp_filter_count -ne 0 -or
        $Evidence.final_owned_wfp_filters_zero -ne $true -or
        $Evidence.final_xray_process_zero -ne $true -or
        $Evidence.connected_config_stable_within_manager_generation -ne $true -or
        $Evidence.secure_state_preferred_over_legacy -ne $true -or
        [string]$Evidence.connected_config_projection_sha256 -notmatch
            '^[0-9a-f]{64}$' -or
        [uint64]$Evidence.connected_config_manager_generation_before -eq 0 -or
        [uint64]$Evidence.connected_config_manager_generation_before -ne
            [uint64]$Evidence.connected_config_manager_generation_after) {
        throw 'Nested live-cycle evidence did not satisfy the exact v10 contract.'
    }
    if ($Evidence.baseline_ipv6_egress_required -eq $true -and
        $Evidence.baseline_ipv6_literal_egress_available -ne $true) {
        throw 'Nested live-cycle evidence lacks a valid physical IPv6 baseline.'
    }
    if ($Evidence.connected_config_generation_field_present -eq $true -and
        [uint64]$Evidence.connected_config_generation -ne
            [uint64]$Evidence.connected_config_manager_generation_before) {
        throw 'Nested SecureState generation contradicts the manager generation.'
    }
    $expectDouble = $Case -like 'double-*'
    if ([bool]$Evidence.double_vpn_requested -ne $expectDouble -or
        [bool]$Evidence.double_vpn_active -ne $expectDouble -or
        [bool]$Evidence.client_config_double_vpn_observed -ne $expectDouble -or
        [bool]$Evidence.external_core_pairing_required -ne $expectDouble -or
        $Evidence.client_physical_two_hop_proven -ne $false) {
        throw 'Nested live-cycle evidence used the wrong VPN hop mode.'
    }
    if ($expectDouble) {
        $emptyDigest = Get-StringSha256 ''
        foreach ($digest in @(
                [string]$Evidence.double_vpn_core_id_sha256,
                [string]$Evidence.double_vpn_exit_slug_sha256,
                [string]$Evidence.configured_first_hop_sha256
            )) {
            if ($digest -notmatch '^[0-9a-f]{64}$' -or
                $digest -ceq $emptyDigest) {
                throw 'Double VPN identity evidence is empty or malformed.'
            }
        }
    }
    if ($Case -match '^.+-natural$' -and
        [string]$Evidence.transport -cne 'direct_awg') {
        throw 'Natural transport case fell back instead of proving direct AWG.'
    }
    if ($Case -match '^.+-xray(80|443)$') {
        $target = [int]$Matches[1]
        if ([string]$Evidence.transport -cne 'xray_fallback' -or
            $observedXrayPorts -notcontains $target -or
            @($observedXrayPorts | Where-Object { $_ -in @(80, 443) -and
                    $_ -ne $target }).Count -ne 0) {
            throw 'Observed Xray socket did not prove the forced target TCP route.'
        }
    }
    if ($Case -eq 'single-split-curl' -and
        ($Evidence.split_tunnel_tested -ne $true -or
         $Evidence.split_driver_service_running -ne $true -or
         [int]$Evidence.excluded_app_canary_count -lt 2 -or
         [string]$Evidence.excluded_app_bypass_egress_sha256 -eq
            $ExpectedPublicEgressSha256)) {
        throw 'Native per-app split-tunnel evidence did not pass.'
    }
}

try {
    Assert-ElevatedInteractive
    if ((Get-Sha256 $PSCommandPath) -cne $ExpectedRunnerSha256) {
        throw 'The running matrix Case script changed after binding.'
    }
    $runnerSelfHashVerified = $true
    $TargetUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowedFull = [IO.Path]::GetFullPath($AllowedEvidenceRoot).TrimEnd('\') + '\'
    if (-not ($RunRoot + '\').StartsWith(
            $allowedFull, [StringComparison]::OrdinalIgnoreCase
        ) -or $RunLeaf -notmatch '^[0-9a-f]{32}$') {
        throw 'RunRoot must be a canonical nonce below the fixed pre-freeze root.'
    }
    Assert-NoReparsePath $AllowedEvidenceRoot
    Assert-NoReparsePath $RunRoot
    if (Test-Path -LiteralPath $RunRoot -ErrorAction Stop) {
        throw 'The one-use pre-freeze matrix root already exists.'
    }
    New-Item -ItemType Directory -Path $RunRoot -Force | Out-Null
    Assert-NoReparsePath $RunRoot
    Set-PrivateDirectoryAcl $RunRoot
    foreach ($path in @($EvidenceRoot, $PrivateRoot, $BackupRoot)) {
        Assert-NoReparsePath $path
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        Assert-NoReparsePath $path
    }
    Assert-NoReparsePath $SecureStateRoot
    Assert-NoReparsePath $LegacyStateRoot
    Set-Stage 'exact_payload'
    Assert-ExactInstalledPayload
    $initialResidue = Get-ResidueState
    if (-not $initialResidue.is_zero) {
        throw 'A pre-existing native tunnel prevents an isolated matrix case.'
    }

    Set-Stage 'state_backup'
    $null = Stop-ExactGui -Purpose 'state-backup'
    $secureStateRootExisted = Test-Path -LiteralPath $SecureStateRoot -PathType Container
    $legacyStateRootExisted = Test-Path -LiteralPath $LegacyStateRoot -PathType Container
    $originalState = @(Get-StateFiles $SecureStateRoot)
    $originalLegacyState = @(Get-StateFiles $LegacyStateRoot)
    if (@($originalState | Where-Object name -eq 'vpn_settings.txt.wvdp').Count -ne 1 -or
        @($originalState | Where-Object name -eq 'vpn_config.txt.wvdp').Count -ne 1) {
        throw 'The exact protected runtime state is incomplete.'
    }
    foreach ($entry in @($originalState) + @($originalLegacyState)) {
        if ((Get-BytesSha256 ([byte[]]$entry.bytes)) -cne
                [string]$entry.sha256) {
            throw 'The captured runtime-state bytes do not match their hash.'
        }
    }
    $baselineSecureClosure = Get-StringSha256 (
        @($originalState | ForEach-Object {
            ([string]$_.name) + ':' + ([string]$_.sha256)
        }) -join '|'
    )
    $baselineLegacyClosure = Get-StringSha256 (
        @($originalLegacyState | ForEach-Object {
            ([string]$_.name) + ':' + ([string]$_.sha256)
        }) -join '|'
    )
    $baselineLegacyTopology = if ($legacyStateRootExisted) {
        'present'
    } else { 'absent' }
    $baselineSecureAclContract = Test-StrictSecureStateAcl `
        -Root $SecureStateRoot -UserSid $TargetUserSid
    if (-not $baselineSecureAclContract) {
        throw 'The protected runtime state does not have the source DACL contract.'
    }
    Backup-StateFiles $SecureStateRoot (Join-Path $BackupRoot 'secure') $originalState
    Backup-StateFiles $LegacyStateRoot (Join-Path $BackupRoot 'legacy') $originalLegacyState
    if (-not (Test-StateFilesExact (Join-Path $BackupRoot 'secure') `
            $originalState $true) -or
        -not (Test-StateFilesExact (Join-Path $BackupRoot 'legacy') `
            $originalLegacyState $true)) {
        throw 'The private state backup is not the captured baseline.'
    }
    $baselineArmed = $true

    if ($Case -eq 'single-split-curl') {
        Set-Stage 'split_canary'
        $source = Join-Path $env:SystemRoot 'System32\curl.exe'
        $signature = Get-AuthenticodeSignature -LiteralPath $source
        if ($signature.Status -ne 'Valid' -or
            $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
            throw 'The split canary source lacks a valid Microsoft signature.'
        }
        $canaryPath = Join-Path $PrivateRoot 'winsvpn-split-canary-curl.exe'
        Copy-Item -LiteralPath $source -Destination $canaryPath
        if ((Get-Sha256 $source) -cne (Get-Sha256 $canaryPath)) {
            throw 'The signed split canary copy changed bytes.'
        }
    }

    Set-Stage 'test_preference'
    Set-TestPreference
    Set-Stage 'transport_forcing'
    Add-ForcingRules
    $portObserver = Start-XrayPortObserver

    Set-Stage 'normal_gui_launch'
    $normalGui = Start-ExactGuiLeastPrivilege -Purpose live
    $liveGuiNormalTokenVerified = $null -ne $normalGui

    Set-Stage 'live_cycle'
    $arguments = @{
        ExpectedPublicEgressSha256 = $ExpectedPublicEgressSha256
        AppPath = $InstalledGui
        OutputRoot = $EvidenceRoot
        CaptureTool = $CaptureTool
        ConnectTimeoutSeconds = $ConnectTimeoutSeconds
    }
    if ($Case -like 'single-*') { $arguments.AllowSingleHop = $true }
    if ($Case -eq 'single-split-curl') {
        $arguments.ExcludedCurlExecutable = $canaryPath
    }
    & $LiveCycle @arguments *>&1 | Tee-Object -FilePath $LogPath
    $retainedLiveGui = Get-OnlyNormalExactGui `
        -SessionId $normalGui.SessionId
    if ($null -eq $retainedLiveGui -or
        $retainedLiveGui.Id -ne $normalGui.Id) {
        throw 'The elevated observer did not retain one normal-token exact GUI.'
    }
    $observedXrayPorts = @(Stop-XrayPortObserver)
    $liveEvidenceFile = @(Get-ChildItem -LiteralPath $EvidenceRoot `
        -Filter 'windows-live-cycle-*.json' -File | Sort-Object LastWriteTimeUtc |
        Select-Object -Last 1)
    if ($liveEvidenceFile.Count -ne 1) {
        throw 'The bounded live cycle did not emit exactly one final evidence file.'
    }
    $liveEvidencePath = $liveEvidenceFile[0].FullName
    $liveEvidence = Get-Content -LiteralPath $liveEvidencePath -Raw |
        ConvertFrom-Json
    Assert-LiveEvidence $liveEvidence
    $result = 'passed'
} catch {
    $failure = [string]$_.Exception.Message
    try { $_ | Out-String | Add-Content -LiteralPath $LogPath -Encoding UTF8 } catch {}
} finally {
    if ($null -ne $portObserver) {
        try { $observedXrayPorts = @(Stop-XrayPortObserver) } catch {}
    }
    try {
        Set-Stage 'forcing_cleanup'
        Remove-ForcingRules
    } catch {
        if ([string]::IsNullOrWhiteSpace($failure)) {
            $failure = 'Temporary forcing-rule cleanup failed.'
        }
        $result = 'failed'
    }
    try {
        Set-Stage 'native_cleanup'
        $null = Stop-ExactGui -Purpose 'native-cleanup'
        $residue = Get-ResidueState
        if (-not $residue.is_zero) { Invoke-EmergencyCleanup }
        if (-not (Get-ResidueState).is_zero) {
            throw 'Final native tunnel residue remains.'
        }
    } catch {
        if ([string]::IsNullOrWhiteSpace($failure)) {
            $failure = 'Final native cleanup failed.'
        }
        $result = 'failed'
    }
    if ($baselineArmed) {
        try {
            Set-Stage 'state_restore'
            $null = Stop-ExactGui -Purpose 'state-restore'
            Restore-StateFiles $SecureStateRoot $originalState `
                $secureStateRootExisted $baselineArmed `
                -StrictDaclUserSid $TargetUserSid
            Restore-StateFiles $LegacyStateRoot $originalLegacyState `
                $legacyStateRootExisted $baselineArmed
            $stateRestored = (Test-StateFilesExact $SecureStateRoot `
                    $originalState $secureStateRootExisted) -and
                (Test-StateFilesExact $LegacyStateRoot $originalLegacyState `
                    $legacyStateRootExisted)
            $strictSecureAclRestored = Test-StrictSecureStateAcl `
                -Root $SecureStateRoot -UserSid $TargetUserSid
        } catch {
            if ([string]::IsNullOrWhiteSpace($failure)) {
                $failure = 'Protected runtime state restoration failed.'
            }
            $result = 'failed'
        }
    }
    try {
        Set-Stage 'gui_restore'
        if (-not $baselineArmed) {
            throw 'The GUI cannot be restored without an armed state baseline.'
        }
        $restoredGui = Start-ExactGuiLeastPrivilege -Purpose restore
        if ($null -eq $restoredGui) {
            throw 'Exact normal-token GUI did not restore.'
        }
        Start-Sleep -Seconds 8
        Restore-StateFiles $SecureStateRoot $originalState `
            $secureStateRootExisted $baselineArmed `
            -StrictDaclUserSid $TargetUserSid
        Restore-StateFiles $LegacyStateRoot $originalLegacyState `
            $legacyStateRootExisted $baselineArmed
        $firstStableRead = (Test-StateFilesExact $SecureStateRoot `
                $originalState $secureStateRootExisted) -and
            (Test-StateFilesExact $LegacyStateRoot $originalLegacyState `
                $legacyStateRootExisted) -and
            (Test-StrictSecureStateAcl -Root $SecureStateRoot `
                -UserSid $TargetUserSid)
        Start-Sleep -Seconds 2
        $secondStableRead = (Test-StateFilesExact $SecureStateRoot `
                $originalState $secureStateRootExisted) -and
            (Test-StateFilesExact $LegacyStateRoot $originalLegacyState `
                $legacyStateRootExisted) -and
            (Test-StrictSecureStateAcl -Root $SecureStateRoot `
                -UserSid $TargetUserSid)
        $persistedRestoredGui = Get-OnlyNormalExactGui `
            -SessionId $restoredGui.SessionId
        $stableStateHandoffVerified = $firstStableRead -and
            $secondStableRead -and $null -ne $persistedRestoredGui -and
            $persistedRestoredGui.Id -eq $restoredGui.Id
        if (-not $stableStateHandoffVerified) {
            $null = Stop-ExactGui -Purpose 'unstable-restore-cleanup'
            Restore-StateFiles $SecureStateRoot $originalState `
                $secureStateRootExisted $baselineArmed `
                -StrictDaclUserSid $TargetUserSid
            Restore-StateFiles $LegacyStateRoot $originalLegacyState `
                $legacyStateRootExisted $baselineArmed
            throw 'The restored GUI state did not remain stable after startup.'
        }
        $guiRestored = $true
        $finalGuiNormalTokenVerified = $true
        $stateRestored = $true
        $strictSecureAclRestored = $true
    } catch {
        $guiRestored = $false
        $finalGuiNormalTokenVerified = $false
        $stableStateHandoffVerified = $false
        if ([string]::IsNullOrWhiteSpace($failure)) {
            $failure = 'Exact GUI restoration failed.'
        }
        $result = 'failed'
    }
    try {
        $finalResidue = Get-ResidueState
        if (-not $finalResidue.is_zero) {
            $result = 'failed'
            if ([string]::IsNullOrWhiteSpace($failure)) {
                $failure = 'Final native, Xray, or WFP residue remained.'
            }
        }
        $stateDigestBefore = Get-StringSha256 (
            @($originalState | ForEach-Object {
                ([string]$_.name) + ':' + ([string]$_.sha256)
            }) -join '|'
        )
        $currentState = @(Get-StateFiles $SecureStateRoot)
        $stateDigestAfter = Get-StringSha256 (
            @($currentState | ForEach-Object {
                ([string]$_.name) + ':' + ([string]$_.sha256)
            }) -join '|'
        )
        $legacyStateExact = $baselineArmed -and
            (Test-StateFilesExact $LegacyStateRoot $originalLegacyState `
                $legacyStateRootExisted)
        $strictSecureAclRestored = $baselineArmed -and
            (Test-StrictSecureStateAcl -Root $SecureStateRoot `
                -UserSid $TargetUserSid)
        if ($stateRestored -and ($stateDigestBefore -cne $stateDigestAfter -or
                -not $legacyStateExact -or -not $strictSecureAclRestored)) {
            $stateRestored = $false
            $result = 'failed'
            if ([string]::IsNullOrWhiteSpace($failure)) {
                $failure = 'Final protected state digest changed.'
            }
        }
        $receipt = [ordered]@{
            schema_version = 1
            contract = 'winsvpn-windows-prefreeze-exact-matrix-case-v1'
            evidence_class = 'prefreeze_nonpublishable'
            publication_authorized = $false
            public_release_gate_eligible = $false
            unsigned_local_candidate = $true
            case = $Case
            result = $result
            failure = $failure
            started_at_utc = $started.ToString('o')
            completed_at_utc = [DateTime]::UtcNow.ToString('o')
            exact_gui_sha256 = Get-Sha256 $InstalledGui
            exact_service_sha256 = Get-Sha256 $InstalledService
            expected_runner_sha256 = $ExpectedRunnerSha256
            runner_sha256 = Get-Sha256 $PSCommandPath
            runner_self_hash_verified = $runnerSelfHashVerified
            live_cycle_sha256 = Get-Sha256 $LiveCycle
            capture_tool_sha256 = Get-Sha256 $CaptureTool
            expected_public_egress_sha256 = $ExpectedPublicEgressSha256
            nested_evidence_file = if ($liveEvidencePath) {
                [IO.Path]::GetFileName($liveEvidencePath)
            } else { '' }
            nested_evidence_sha256 = if ($liveEvidencePath -and
                (Test-Path -LiteralPath $liveEvidencePath)) {
                Get-Sha256 $liveEvidencePath
            } else { '' }
            observed_xray_remote_ports = @($observedXrayPorts)
            protected_state_sha256_before = $stateDigestBefore
            protected_state_sha256_after = $stateDigestAfter
            baseline_armed = $baselineArmed
            baseline_secure_closure_sha256 = $baselineSecureClosure
            baseline_legacy_closure_sha256 = $baselineLegacyClosure
            baseline_legacy_topology = $baselineLegacyTopology
            baseline_secure_acl_contract = $baselineSecureAclContract
            protected_state_restored_byte_for_byte = $stateRestored
            legacy_state_restored_exactly = $legacyStateExact
            strict_secure_acl_restored = $strictSecureAclRestored
            stable_state_handoff_verified = $stableStateHandoffVerified
            temporary_forcing_rules_removed = $forcingRemoved
            emergency_cleanup_used = $emergencyCleanupUsed
            final_zero_residue = [bool]$finalResidue.is_zero
            final_awg_engine_process_count = `
                [int]$finalResidue.awg_engine_process_count
            exact_gui_restored = $guiRestored
            live_gui_normal_token_verified = $liveGuiNormalTokenVerified
            final_gui_normal_token_verified = $finalGuiNormalTokenVerified
            gui_launch_logon_type = 'InteractiveToken'
            gui_launch_run_level = 'LeastPrivilege'
            gui_stop_evidence = @($guiStopEvidence)
            gui_launch_timing_evidence = @($guiLaunchTimingEvidence)
            residue_provider_errors = @($residueProviderErrors)
            xray_absence_is_expected_zero = $true
            awg_engine_absence_is_expected_zero = $true
            state_reparse_checks_enforced = $true
            secret_material_redacted = $true
        }
        Write-PrivateJson $StatusPath $receipt
        Set-Stage 'complete'
    } catch {
        try {
            Write-PrivateJson $StatusPath ([ordered]@{
                schema_version = 1
                contract = 'winsvpn-windows-prefreeze-exact-matrix-case-v1'
                evidence_class = 'prefreeze_nonpublishable'
                publication_authorized = $false
                public_release_gate_eligible = $false
                unsigned_local_candidate = $true
                case = $Case
                result = 'failed'
                failure = 'Final receipt generation failed.'
                started_at_utc = $started.ToString('o')
                completed_at_utc = [DateTime]::UtcNow.ToString('o')
                gui_stop_evidence = @($guiStopEvidence)
                gui_launch_timing_evidence = @($guiLaunchTimingEvidence)
                residue_provider_errors = @($residueProviderErrors)
                xray_absence_is_expected_zero = $true
                state_reparse_checks_enforced = $true
                secret_material_redacted = $true
            })
        } catch {}
        $result = 'failed'
    }
}

if ($result -ne 'passed') { exit 1 }
Write-Output "WINDOWS_PREFREEZE_EXACT_CASE=PASS case=$Case"
exit 0
