[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('double-natural')][string]$Case,
    [Parameter(Mandatory)][string]$ToolRoot,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedRunnerSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedWatchdogSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedGuiVerifierSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedGuiSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedServiceSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPublicEgressSha256,
    [ValidateRange(60, 120)][int]$ConnectTimeoutSeconds = 90,
    [ValidateRange(600, 720)][int]$MainExecutionLimitSeconds = 600,
    [ValidateRange(660, 900)][int]$WatchdogDeadlineSeconds = 660,
    [ValidateRange(300, 360)][int]$WatchdogRecoveryReserveSeconds = 360
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ToolRoot = [IO.Path]::GetFullPath($ToolRoot).TrimEnd('\')
$AllowedToolRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramData 'WinsVPN\PreFreezeMatrix')
).TrimEnd('\') + '\'
$runner = Join-Path $ToolRoot 'windows_prefreeze_exact_matrix_case.ps1'
$watchdog = Join-Path $ToolRoot 'windows_prefreeze_exact_watchdog.ps1'
$guiVerifier = Join-Path $ToolRoot 'windows_prefreeze_interactive_gui_verify.ps1'
$powershellExe = Join-Path $env:SystemRoot `
    'System32\WindowsPowerShell\v1.0\powershell.exe'
$gui = Join-Path $env:ProgramFiles 'WinsVPN\wins_vpn.exe'
$service = Join-Path $env:ProgramFiles 'WinsVPN\wins_vpn_tunnel_service.exe'
$secure = Join-Path $env:LOCALAPPDATA 'WinsVPN\SecureState'
$legacy = Join-Path $env:APPDATA 'wins_vpn'
$ExpectedRunnerSha256 = $ExpectedRunnerSha256.ToLowerInvariant()
$ExpectedWatchdogSha256 = $ExpectedWatchdogSha256.ToLowerInvariant()
$ExpectedGuiVerifierSha256 = $ExpectedGuiVerifierSha256.ToLowerInvariant()
$ExpectedGuiSha256 = $ExpectedGuiSha256.ToLowerInvariant()
$ExpectedServiceSha256 = $ExpectedServiceSha256.ToLowerInvariant()
$ExpectedPublicEgressSha256 = $ExpectedPublicEgressSha256.ToLowerInvariant()
$residueProviderErrors = @()
$taskTerminationMarginSeconds = 30
$watchdogExecutionLimitSeconds = $WatchdogDeadlineSeconds +
    $WatchdogRecoveryReserveSeconds + $taskTerminationMarginSeconds
if ($WatchdogDeadlineSeconds -lt ($MainExecutionLimitSeconds + 60)) {
    throw 'The watchdog wait deadline must exceed the bounded Case task by 60 seconds.'
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class WinsVpnPreFreezeBindNativeV1 {
 const uint QueryLimited=0x1000,TokenQuery=8,GwOwner=4; const int TokenElevation=20,DwmwaCloaked=14;
 delegate bool EnumWindowsProc(IntPtr w,IntPtr p);
 [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint a,bool i,uint p);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool GetTokenInformation(IntPtr t,int c,out int v,int l,out int r);
 [DllImport("user32.dll")]static extern bool EnumWindows(EnumWindowsProc c,IntPtr p);
 [DllImport("user32.dll")]static extern uint GetWindowThreadProcessId(IntPtr w,out uint p);
 [DllImport("user32.dll")]static extern bool IsWindowVisible(IntPtr w);
 [DllImport("user32.dll")]static extern bool IsIconic(IntPtr w);
 [DllImport("user32.dll")]static extern IntPtr GetParent(IntPtr w);
 [DllImport("user32.dll")]static extern IntPtr GetWindow(IntPtr w,uint c);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)]static extern int GetClassName(IntPtr w,StringBuilder s,int m);
 [DllImport("dwmapi.dll")]static extern int DwmGetWindowAttribute(IntPtr w,int a,out int v,int s);
 public static bool Elevated(uint id){IntPtr p=OpenProcess(QueryLimited,false,id);if(p==IntPtr.Zero)throw new Win32Exception();try{IntPtr t;if(!OpenProcessToken(p,TokenQuery,out t))throw new Win32Exception();try{int v,r;if(!GetTokenInformation(t,TokenElevation,out v,4,out r))throw new Win32Exception();return v!=0;}finally{CloseHandle(t);}}finally{CloseHandle(p);}}
 public static IntPtr Window(uint id){var a=new List<IntPtr>();EnumWindows(delegate(IntPtr w,IntPtr p){uint x;GetWindowThreadProcessId(w,out x);if(x!=id||!IsWindowVisible(w)||IsIconic(w)||GetParent(w)!=IntPtr.Zero||GetWindow(w,GwOwner)!=IntPtr.Zero)return true;var s=new StringBuilder(256);GetClassName(w,s,s.Capacity);if(s.ToString()!="FLUTTER_RUNNER_WIN32_WINDOW")return true;int c=0;if(DwmGetWindowAttribute(w,DwmwaCloaked,out c,4)==0&&c!=0)return true;a.Add(w);return true;},IntPtr.Zero);return a.Count==1?a[0]:IntPtr.Zero;}
}
'@

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StringSha256([AllowEmptyString()][string]$Value) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($algorithm.ComputeHash(
            [Text.UTF8Encoding]::new($false).GetBytes($Value)
        ))).Replace('-', '').ToLowerInvariant()
    } finally { $algorithm.Dispose() }
}

function Assert-NoReparsePath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    $current = $root
    foreach ($part in @($full.Substring($root.Length) -split '[\\/]' |
            Where-Object { $_ })) {
        if ($part -eq '..') { throw 'Parent traversal is forbidden.' }
        $current = Join-Path $current $part
        if (Test-Path -LiteralPath $current -ErrorAction Stop) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "A protected state path contains a reparse point: $current"
            }
        }
    }
}

function Get-VerifiedStateFiles([string]$Root) {
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

function Get-StateClosure([string]$Root) {
    $files = @(Get-VerifiedStateFiles $Root)
    if (-not (Test-Path -LiteralPath $Root -PathType Container `
            -ErrorAction Stop)) {
        return (Get-StringSha256 '')
    }
    $parts = @($files | ForEach-Object {
            Assert-NoReparsePath $_.FullName
            $_.Name + ':' + (Get-Sha256 $_.FullName)
        })
    Get-StringSha256 ($parts -join '|')
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
    $path = Join-Path $ToolRoot (
        'wfp-bind-' + [Guid]::NewGuid().ToString('N') + '.xml'
    )
    try {
        [int](Invoke-ResidueProviderQuery -Provider wfp -Query {
            Assert-NoReparsePath $ToolRoot
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

function Get-ResidueCount {
    @(Invoke-ResidueProviderQuery -Provider service -Query {
        Get-Service -ErrorAction Stop | Where-Object {
        ($_.Name -eq 'WinsVPNSplitTunnel' -or
         $_.Name -like 'AmneziaWGTunnel$winsvpn*') -and
        $_.Status -ne 'Stopped'
        }
    }).Count +
    @(Invoke-ResidueProviderQuery -Provider adapter -Query {
        Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
            $_.Name -eq 'winsvpn' -and $_.Status -ne 'Disabled'
        }
    }).Count +
    @(Invoke-ResidueProviderQuery -Provider route -Query {
        Get-NetRoute -ErrorAction Stop | Where-Object {
            $_.InterfaceAlias -eq 'winsvpn'
        }
    }).Count +
    # Process absence is an expected zero-result condition, unlike a provider
    # failure from the service/network cmdlets above.
    @(Get-Process xray -ErrorAction SilentlyContinue).Count +
    @(Get-Process winsvpn_awg_engine -ErrorAction SilentlyContinue).Count +
    (Get-OwnedWfpFilterCount)
}

function Assert-RegisteredTaskContract {
    param(
        [Parameter(Mandatory)]$Task,
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][string]$ExpectedUserId,
        [Parameter(Mandatory)][string]$ExpectedXmlUserSid,
        [Parameter(Mandatory)][ValidateSet('Interactive', 'ServiceAccount')]
        [string]$ExpectedLogonType,
        [Parameter(Mandatory)][ValidateSet('Highest', 'Limited')]
        [string]$ExpectedRunLevel,
        [Parameter(Mandatory)][string]$ExpectedExecute,
        [Parameter(Mandatory)][string]$ExpectedArguments,
        [Parameter(Mandatory)][ValidateRange(1, 1800)]
        [int]$ExpectedExecutionLimitSeconds
    )
    [xml]$definition = Export-ScheduledTask -TaskName $TaskName `
        -ErrorAction Stop
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
    $xmlTriggers = @($definition.SelectNodes(
        '/t:Task/t:Triggers/*', $namespace
    ))
    $xmlLimit = $definition.SelectSingleNode(
        '/t:Task/t:Settings/t:ExecutionTimeLimit', $namespace
    )
    $xmlCommand = if ($xmlActions.Count -eq 1) {
        $xmlActions[0].SelectSingleNode('t:Command', $namespace)
    } else { $null }
    $xmlArguments = if ($xmlActions.Count -eq 1) {
        $xmlActions[0].SelectSingleNode('t:Arguments', $namespace)
    } else { $null }
    $xmlWorkingDirectory = if ($xmlActions.Count -eq 1) {
        $xmlActions[0].SelectSingleNode('t:WorkingDirectory', $namespace)
    } else { $null }
    $xmlUserId = if ($principals.Count -eq 1) {
        $principals[0].SelectSingleNode('t:UserId', $namespace)
    } else { $null }
    $xmlRunLevel = if ($principals.Count -eq 1) {
        $principals[0].SelectSingleNode('t:RunLevel', $namespace)
    } else { $null }
    $xmlLogonType = if ($principals.Count -eq 1) {
        $principals[0].SelectSingleNode('t:LogonType', $namespace)
    } else { $null }
    $registeredActions = @($Task.Actions)
    $registeredTriggers = @($Task.Triggers)
    $registeredPathMatches = $registeredActions.Count -eq 1 -and (
        try {
            [string]::Equals(
                [IO.Path]::GetFullPath([string]$registeredActions[0].Execute),
                [IO.Path]::GetFullPath($ExpectedExecute),
                [StringComparison]::OrdinalIgnoreCase
            )
        } catch { $false }
    )
    $xmlPathMatches = $null -ne $xmlCommand -and (
        try {
            [string]::Equals(
                [IO.Path]::GetFullPath([string]$xmlCommand.InnerText),
                [IO.Path]::GetFullPath($ExpectedExecute),
                [StringComparison]::OrdinalIgnoreCase
            )
        } catch { $false }
    )
    $limitSeconds = try {
        [int][Math]::Round(
            [System.Xml.XmlConvert]::ToTimeSpan(
                [string]$xmlLimit.InnerText
            ).TotalSeconds
        )
    } catch { -1 }
    $expectedXmlLogon = if ($ExpectedLogonType -ceq 'Interactive') {
        'InteractiveToken'
    } else { 'ServiceAccount' }
    $expectedXmlRunLevel = if ($ExpectedRunLevel -ceq 'Highest') {
        'HighestAvailable'
    } else { 'LeastPrivilege' }
    $xmlLogonMatches = if ($ExpectedLogonType -ceq 'ServiceAccount') {
        $null -eq $xmlLogonType -or
            [string]$xmlLogonType.InnerText -ceq $expectedXmlLogon
    } else {
        $null -ne $xmlLogonType -and
            [string]$xmlLogonType.InnerText -ceq $expectedXmlLogon
    }
    if ([string]$Task.Principal.UserId -cne $ExpectedUserId -or
        [string]$Task.Principal.LogonType -cne $ExpectedLogonType -or
        [string]$Task.Principal.RunLevel -cne $ExpectedRunLevel -or
        $principals.Count -ne 1 -or $registeredActions.Count -ne 1 -or
        $xmlActions.Count -ne 1 -or $registeredTriggers.Count -ne 0 -or
        $xmlTriggers.Count -ne 0 -or -not $registeredPathMatches -or
        -not $xmlPathMatches -or
        [string]$registeredActions[0].Arguments -cne $ExpectedArguments -or
        -not [string]::IsNullOrWhiteSpace(
            [string]$registeredActions[0].WorkingDirectory
        ) -or $null -eq $xmlArguments -or
        [string]$xmlArguments.InnerText -cne $ExpectedArguments -or
        ($null -ne $xmlWorkingDirectory -and -not
            [string]::IsNullOrWhiteSpace($xmlWorkingDirectory.InnerText)) -or
        $null -eq $xmlUserId -or
        [string]$xmlUserId.InnerText -cne $ExpectedXmlUserSid -or
        -not $xmlLogonMatches -or $null -eq $xmlRunLevel -or
        [string]$xmlRunLevel.InnerText -cne $expectedXmlRunLevel -or
        $limitSeconds -ne $ExpectedExecutionLimitSeconds) {
        throw "The registered task contract is invalid: $TaskName"
    }
}

if (-not ($ToolRoot + '\').StartsWith(
        $AllowedToolRoot, [StringComparison]::OrdinalIgnoreCase
    ) -or (Get-Sha256 $runner) -cne $ExpectedRunnerSha256 -or
    (Get-Sha256 $watchdog) -cne $ExpectedWatchdogSha256 -or
    (Get-Sha256 $guiVerifier) -cne $ExpectedGuiVerifierSha256 -or
    (Get-Sha256 $gui) -cne $ExpectedGuiSha256 -or
    (Get-Sha256 $service) -cne $ExpectedServiceSha256) {
    throw 'The staged tools or installed exact payload changed before binding.'
}
foreach ($path in @($ToolRoot, $runner, $watchdog, $guiVerifier)) {
    Assert-NoReparsePath $path
}
Assert-NoReparsePath $secure
Assert-NoReparsePath $legacy
$acl = Get-Acl $ToolRoot
$actualSids = @($acl.Access | ForEach-Object {
    $_.IdentityReference.Translate(
        [Security.Principal.SecurityIdentifier]
    ).Value
} | Sort-Object -Unique)
$expectedSids = @('S-1-5-18', 'S-1-5-32-544') | Sort-Object
if (-not $acl.AreAccessRulesProtected -or
    ($actualSids -join '|') -cne ($expectedSids -join '|')) {
    throw 'The staged tool ACL is not SYSTEM/Administrators-only.'
}
if ((Get-ResidueCount) -ne 0) { throw 'Native tunnel residue exists before binding.' }
$exactGui = @(Get-Process wins_vpn -ErrorAction Stop | Where-Object {
    try { (Get-Sha256 $_.Path) -ceq $ExpectedGuiSha256 } catch { $false }
})
if ($exactGui.Count -ne 1 -or
    [WinsVpnPreFreezeBindNativeV1]::Elevated([uint32]$exactGui[0].Id) -or
    [WinsVpnPreFreezeBindNativeV1]::Window([uint32]$exactGui[0].Id) -eq
        [IntPtr]::Zero) {
    throw 'The exact disconnected GUI is not one normal-token visible window.'
}
$secureClosure = Get-StateClosure $secure
$legacyClosure = Get-StateClosure $legacy
$legacyTopology = if (Test-Path -LiteralPath $legacy -PathType Container) {
    'present'
} else { 'absent' }
$nonce = [Guid]::NewGuid().ToString('N')
$runRoot = Join-Path (Split-Path -Parent $ToolRoot) $nonce
$mainTask = "WinsVPN-PreFreeze-Case-$nonce"
$watchdogTask = "WinsVPN-PreFreeze-Watchdog-$nonce"
$guiTask = "WinsVPN-PreFreeze-GUI-$nonce"
$guiVerifyTask = "WinsVPN-PreFreeze-VerifyGUI-$nonce"
$targetIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$targetUser = $targetIdentity.Name
$targetSid = $targetIdentity.User.Value
foreach ($name in @($mainTask, $watchdogTask, $guiTask, $guiVerifyTask)) {
    if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
        throw 'A one-use matrix task name already exists.'
    }
}
if (Test-Path -LiteralPath $runRoot) {
    throw 'A one-use matrix run root already exists.'
}

$mainArguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
    '-File "' + $runner + '" -Case ' + $Case +
    ' -ExpectedRunnerSha256 ' + $ExpectedRunnerSha256 +
    ' -ExpectedGuiSha256 ' + $ExpectedGuiSha256 +
    ' -ExpectedServiceSha256 ' + $ExpectedServiceSha256 +
    ' -ExpectedPublicEgressSha256 ' + $ExpectedPublicEgressSha256 +
    ' -RunRoot "' + $runRoot + '" -ConnectTimeoutSeconds ' +
    $ConnectTimeoutSeconds
$watchdogArguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
    '-File "' + $watchdog + '" -RunRoot "' + $runRoot + '"' +
    ' -Case ' + $Case +
    ' -ExpectedWatchdogSha256 ' + $ExpectedWatchdogSha256 +
    ' -ExpectedRunnerSha256 ' + $ExpectedRunnerSha256 +
    ' -ExpectedGuiVerifierSha256 ' + $ExpectedGuiVerifierSha256 +
    ' -ExpectedGuiSha256 ' + $ExpectedGuiSha256 +
    ' -ExpectedServiceSha256 ' + $ExpectedServiceSha256 +
    ' -ExpectedSecureStateClosureSha256 ' + $secureClosure +
    ' -ExpectedLegacyStateClosureSha256 ' + $legacyClosure +
    ' -ExpectedLegacyRootTopology ' + $legacyTopology +
    ' -TargetUserSid ' + $targetSid +
    ' -TargetSessionId ' + $exactGui[0].SessionId +
    ' -MainTaskName ' + $mainTask +
    ' -MainTaskExecutionLimitSeconds ' + $MainExecutionLimitSeconds +
    ' -DeadlineSeconds ' + $WatchdogDeadlineSeconds +
    ' -RecoveryReserveSeconds ' + $WatchdogRecoveryReserveSeconds +
    ' -TaskExecutionLimitSeconds ' + $watchdogExecutionLimitSeconds

$mainAction = New-ScheduledTaskAction -Execute $powershellExe `
    -Argument $mainArguments
$mainPrincipal = New-ScheduledTaskPrincipal -UserId $targetUser `
    -LogonType Interactive -RunLevel Highest
$mainSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (
    New-TimeSpan -Seconds $MainExecutionLimitSeconds
) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$watchdogAction = New-ScheduledTaskAction -Execute $powershellExe `
    -Argument $watchdogArguments
$watchdogPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
    -LogonType ServiceAccount -RunLevel Highest
$watchdogSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (
    New-TimeSpan -Seconds $watchdogExecutionLimitSeconds
) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

try {
    Register-ScheduledTask -TaskName $mainTask -Action $mainAction `
        -Principal $mainPrincipal -Settings $mainSettings | Out-Null
    Register-ScheduledTask -TaskName $watchdogTask -Action $watchdogAction `
        -Principal $watchdogPrincipal -Settings $watchdogSettings | Out-Null
    $registeredMain = Get-ScheduledTask -TaskName $mainTask -ErrorAction Stop
    $registeredWatchdog = Get-ScheduledTask -TaskName $watchdogTask `
        -ErrorAction Stop
    Assert-RegisteredTaskContract -Task $registeredMain -TaskName $mainTask `
        -ExpectedUserId $targetUser -ExpectedXmlUserSid $targetSid `
        -ExpectedLogonType Interactive -ExpectedRunLevel Highest `
        -ExpectedExecute $powershellExe -ExpectedArguments $mainArguments `
        -ExpectedExecutionLimitSeconds $MainExecutionLimitSeconds
    Assert-RegisteredTaskContract -Task $registeredWatchdog `
        -TaskName $watchdogTask -ExpectedUserId 'SYSTEM' `
        -ExpectedXmlUserSid 'S-1-5-18' -ExpectedLogonType ServiceAccount `
        -ExpectedRunLevel Highest -ExpectedExecute $powershellExe `
        -ExpectedArguments $watchdogArguments `
        -ExpectedExecutionLimitSeconds $watchdogExecutionLimitSeconds
} catch {
    Unregister-ScheduledTask -TaskName $mainTask -Confirm:$false `
        -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $watchdogTask -Confirm:$false `
        -ErrorAction SilentlyContinue
    throw
}

[ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-prefreeze-ready-v1'
    ready = $true
    case = $Case
    nonce = $nonce
    run_root = $runRoot
    main_task = $mainTask
    watchdog_task = $watchdogTask
    gui_verify_task = $guiVerifyTask
    runner_sha256 = Get-Sha256 $runner
    watchdog_sha256 = Get-Sha256 $watchdog
    gui_verifier_sha256 = Get-Sha256 $guiVerifier
    secure_state_closure_sha256 = $secureClosure
    legacy_state_closure_sha256 = $legacyClosure
    legacy_root_topology = $legacyTopology
    target_user_sid = $targetSid
    target_session_id = [int]$exactGui[0].SessionId
    exact_gui_pid = [int]$exactGui[0].Id
    exact_gui_normal_token = $true
    exact_gui_window_verified = $true
    zero_residue = $true
    residue_provider_errors = @($residueProviderErrors)
    xray_absence_is_expected_zero = $true
    state_reparse_checks_enforced = $true
    tasks_started = $false
    main_execution_limit_seconds = $MainExecutionLimitSeconds
    watchdog_deadline_seconds = $WatchdogDeadlineSeconds
    watchdog_recovery_reserve_seconds = $WatchdogRecoveryReserveSeconds
    watchdog_execution_limit_seconds = $watchdogExecutionLimitSeconds
    task_termination_margin_seconds = $taskTerminationMarginSeconds
    exact_task_actions_arguments_triggers_limits_verified = $true
    secret_material_redacted = $true
} | ConvertTo-Json -Depth 5 -Compress
