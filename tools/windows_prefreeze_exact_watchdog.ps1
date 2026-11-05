[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunRoot,
    [Parameter(Mandatory)][ValidateSet('double-natural')][string]$Case,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedWatchdogSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedRunnerSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedGuiVerifierSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedGuiSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedServiceSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedSecureStateClosureSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedLegacyStateClosureSha256,
    [Parameter(Mandatory)][ValidateSet('present', 'absent')]
    [string]$ExpectedLegacyRootTopology,
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-21(?:-[0-9]+){4}$')]
    [string]$TargetUserSid,
    [Parameter(Mandatory)][ValidateRange(1, 255)][int]$TargetSessionId,
    [Parameter(Mandatory)][ValidatePattern('^WinsVPN-PreFreeze-Case-[0-9a-f]{32}$')]
    [string]$MainTaskName,
    [Parameter(Mandatory)][ValidateRange(600, 720)]
    [int]$MainTaskExecutionLimitSeconds,
    [ValidateRange(660, 900)][int]$DeadlineSeconds = 660,
    [ValidateRange(300, 360)][int]$RecoveryReserveSeconds = 360,
    [Parameter(Mandatory)][ValidateRange(990, 1290)]
    [int]$TaskExecutionLimitSeconds
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RunRoot = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
$RunLeaf = Split-Path -Leaf $RunRoot
$AllowedRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramData 'WinsVPN\PreFreezeMatrix')
).TrimEnd('\') + '\'
$InstallRoot = Join-Path $env:ProgramFiles 'WinsVPN'
$InstalledGui = Join-Path $InstallRoot 'wins_vpn.exe'
$InstalledService = Join-Path $InstallRoot 'wins_vpn_tunnel_service.exe'
$GuiVerifier = Join-Path $PSScriptRoot `
    'windows_prefreeze_interactive_gui_verify.ps1'
$PowerShellExe = Join-Path $env:SystemRoot `
    'System32\WindowsPowerShell\v1.0\powershell.exe'
$TargetProfile = [Environment]::GetFolderPath('UserProfile')
$TargetProfile = (Get-CimInstance Win32_UserProfile -ErrorAction Stop |
    Where-Object SID -eq $TargetUserSid | Select-Object -First 1 -ExpandProperty LocalPath)
$SecureStateRoot = Join-Path $TargetProfile 'AppData\Local\WinsVPN\SecureState'
$LegacyStateRoot = Join-Path $TargetProfile 'AppData\Roaming\wins_vpn'
$SecureBackup = Join-Path $RunRoot 'private\state-backup\secure'
$LegacyBackup = Join-Path $RunRoot 'private\state-backup\legacy'
$StatusPath = Join-Path $RunRoot 'case-status.json'
$StagePath = Join-Path $RunRoot 'case-stage.json'
$ReceiptPath = Join-Path $RunRoot 'watchdog-receipt.json'
$GuiVerifyReceiptPath = Join-Path $RunRoot 'watchdog-gui-proof.json'
$FirewallGroup = "WinsVPN-PreFreeze-$RunLeaf"
$GuiTaskName = "WinsVPN-PreFreeze-GUI-$RunLeaf"
$GuiVerifyTaskName = "WinsVPN-PreFreeze-VerifyGUI-$RunLeaf"
$ExpectedWatchdogSha256 = $ExpectedWatchdogSha256.ToLowerInvariant()
$ExpectedRunnerSha256 = $ExpectedRunnerSha256.ToLowerInvariant()
$ExpectedGuiVerifierSha256 = $ExpectedGuiVerifierSha256.ToLowerInvariant()
$ExpectedGuiSha256 = $ExpectedGuiSha256.ToLowerInvariant()
$ExpectedServiceSha256 = $ExpectedServiceSha256.ToLowerInvariant()
$ExpectedSecureStateClosureSha256 =
    $ExpectedSecureStateClosureSha256.ToLowerInvariant()
$ExpectedLegacyStateClosureSha256 =
    $ExpectedLegacyStateClosureSha256.ToLowerInvariant()
$started = [DateTime]::UtcNow
$deadline = $started.AddSeconds($DeadlineSeconds)
$taskHardDeadline = $started.AddSeconds($TaskExecutionLimitSeconds)
$recoveryMustStartBy = $taskHardDeadline.AddSeconds(
    -$RecoveryReserveSeconds
)
$triggered = $false
$managerRestarted = $false
$stateRestored = $false
$rulesRemoved = $false
$mainTaskRemoved = $false
$guiTaskRemoved = $false
$guiVerifyTaskRemoved = $false
$normalGuiVerified = $false
$failure = ''
$pass = $false
$finalResidue = $null
$baselineArmed = $false
$strictSecureAclRestored = $false
$stableStateHandoffVerified = $false
$secureDaclContractSddl = ''
$residueProviderErrors = @()
$guiStopEvidence = @()
$guiLaunchTimingEvidence = @()
$retiredExactGuiPids = @()
$terminalStatusObserved = $false
$terminalStatusResult = ''
$freshStageObserved = $false
$lastFreshStage = ''
$mainTaskRunningObserved = $false
$waitEndedAtUtc = ''
$recoveryStartedAtUtc = ''
$managerRecoveryAttempted = $false
$managerRunningVerified = $false
$managerRecoveryFailure = ''
$interactiveVisibleWindowVerified = $false
$interactiveVisibleWindowProofSha256 = ''
$watchdogSelfHashVerified = $false

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class WinsVpnPreFreezeWatchdogNativeV1 {
  const uint QueryLimited=0x1000, TokenQuery=0x0008;
  const uint DaclSecurity=0x4, ProtectedDacl=0x80000000;
  const int TokenElevation=20;
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint a,bool i,uint p);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr t,int c,out int v,int l,out int r);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string s,uint r,out IntPtr d,IntPtr n);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool SetFileSecurityW(string p,uint i,IntPtr d);
  public static bool IsElevated(uint pid) {
    IntPtr p=OpenProcess(QueryLimited,false,pid); if(p==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
    try { IntPtr t; if(!OpenProcessToken(p,TokenQuery,out t)) throw new Win32Exception(Marshal.GetLastWin32Error());
      try { int v,r; if(!GetTokenInformation(t,TokenElevation,out v,sizeof(int),out r)) throw new Win32Exception(Marshal.GetLastWin32Error()); return v!=0; }
      finally { CloseHandle(t); }
    } finally { CloseHandle(p); }
  }
  public static void ApplyProtectedDacl(string path,string sddl) {
    IntPtr d;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,out d,IntPtr.Zero))
      throw new Win32Exception(Marshal.GetLastWin32Error());
    try {
      if(!SetFileSecurityW(path,DaclSecurity|ProtectedDacl,d))
        throw new Win32Exception(Marshal.GetLastWin32Error());
    } finally { LocalFree(d); }
  }
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

function Write-Json([string]$Path, $Value) {
    Assert-NoReparsePath $Path
    [IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 10) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
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
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "A watchdog path contains a reparse point: $current"
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

function Test-LegacyTopology {
    $exists = Test-Path -LiteralPath $LegacyStateRoot -PathType Container
    if ($ExpectedLegacyRootTopology -eq 'present') {
        $exists -and (Get-StateClosure $LegacyStateRoot) -ceq
            $ExpectedLegacyStateClosureSha256
    } else {
        -not $exists
    }
}

function Assert-ArmRecoveryBaseline {
    if ($script:baselineArmed) { return }
    if (-not (Test-Path -LiteralPath $SecureBackup -PathType Container) -or
        -not (Test-Path -LiteralPath $LegacyBackup -PathType Container)) {
        throw 'The complete state backup is unavailable; recovery remains disarmed.'
    }
    $secureFiles = @(Get-VerifiedStateFiles $SecureBackup)
    $legacyFiles = @(Get-VerifiedStateFiles $LegacyBackup)
    if (@($secureFiles | Where-Object {
                $_.Name -eq 'vpn_settings.txt.wvdp'
            }).Count -ne 1 -or
        @($secureFiles | Where-Object {
                $_.Name -eq 'vpn_config.txt.wvdp'
            }).Count -ne 1 -or
        (Get-StateClosure $SecureBackup) -cne
            $ExpectedSecureStateClosureSha256 -or
        (Get-StateClosure $LegacyBackup) -cne
            $ExpectedLegacyStateClosureSha256) {
        throw 'The state backup does not match the complete armed baseline.'
    }
    foreach ($file in @($secureFiles) + @($legacyFiles)) {
        Assert-NoReparsePath $file.FullName
        if ([string]::IsNullOrWhiteSpace((Get-Sha256 $file.FullName))) {
            throw 'A baseline state file could not be hashed.'
        }
    }
    $script:secureDaclContractSddl =
        "D:P(A;;FA;;;SY)(A;;FA;;;$TargetUserSid)"
    $script:baselineArmed = $true
}

function Set-StrictSecureStateAcl {
    if (-not $script:baselineArmed -or
        [string]::IsNullOrWhiteSpace($script:secureDaclContractSddl)) {
        throw 'The SecureState DACL contract is not armed.'
    }
    Assert-NoReparsePath $SecureStateRoot
    [WinsVpnPreFreezeWatchdogNativeV1]::ApplyProtectedDacl(
        $SecureStateRoot, $script:secureDaclContractSddl
    )
    foreach ($file in @(Get-VerifiedStateFiles $SecureStateRoot)) {
        Assert-NoReparsePath $file.FullName
        [WinsVpnPreFreezeWatchdogNativeV1]::ApplyProtectedDacl(
            $file.FullName, $script:secureDaclContractSddl
        )
    }
}

function Test-StrictSecureStateAcl {
    if (-not (Test-Path -LiteralPath $SecureStateRoot -PathType Container)) {
        return $false
    }
    $expectedSids = @('S-1-5-18', $TargetUserSid) | Sort-Object
    foreach ($path in @($SecureStateRoot) + @(
            Get-VerifiedStateFiles $SecureStateRoot |
                Select-Object -ExpandProperty FullName
        )) {
        try {
            Assert-NoReparsePath $path
            $acl = Get-Acl -LiteralPath $path
            $entries = @($acl.Access)
            $actualSids = @($entries | ForEach-Object {
                $_.IdentityReference.Translate(
                    [Security.Principal.SecurityIdentifier]
                ).Value
            } | Sort-Object -Unique)
            if (-not $acl.AreAccessRulesProtected -or $entries.Count -ne 2 -or
                ($actualSids -join '|') -cne ($expectedSids -join '|') -or
                @($entries | Where-Object {
                    $_.AccessControlType -ne
                        [Security.AccessControl.AccessControlType]::Allow -or
                    $_.FileSystemRights -ne
                        [Security.AccessControl.FileSystemRights]::FullControl -or
                    $_.IsInherited
                }).Count -ne 0) {
                return $false
            }
        } catch { return $false }
    }
    $true
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
    $privateRoot = Join-Path $RunRoot 'private'
    $path = Join-Path $privateRoot (
        'wfp-residue-' + [Guid]::NewGuid().ToString('N') + '.xml'
    )
    try {
        [int](Invoke-ResidueProviderQuery -Provider wfp -Query {
            Assert-NoReparsePath $privateRoot
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
    # Process absence is an expected zero-result condition.
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
            [string]::Equals(
                [IO.Path]::GetFullPath($_.Path),
                [IO.Path]::GetFullPath($InstalledGui),
                [StringComparison]::OrdinalIgnoreCase
            ) -and (Get-Sha256 $_.Path) -ceq $ExpectedGuiSha256
        } catch { $false }
    })
}

function Get-NormalGuiProcess {
    param([int[]]$ExcludedPids = @())
    $matches = @(Get-Process wins_vpn -ErrorAction SilentlyContinue |
        Where-Object {
            if ($ExcludedPids -contains [int]$_.Id) { return $false }
            try {
                [string]::Equals(
                    [IO.Path]::GetFullPath($_.Path),
                    [IO.Path]::GetFullPath($InstalledGui),
                    [StringComparison]::OrdinalIgnoreCase
                ) -and (Get-Sha256 $_.Path) -ceq $ExpectedGuiSha256
            }
            catch { $false }
        })
    if ($matches.Count -ne 1 -or
        $matches[0].SessionId -ne $TargetSessionId -or
        [WinsVpnPreFreezeWatchdogNativeV1]::IsElevated(
            [uint32]$matches[0].Id
        )) { return $null }
    $matches[0]
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
    $task = Get-ScheduledTask -TaskName $GuiTaskName -ErrorAction Stop
    $actions = @($task.Actions)
    [xml]$definition = Export-ScheduledTask -TaskName $GuiTaskName
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
        throw 'The watchdog GUI task does not have one principal and action.'
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
        ) -or [string]$principal.UserId -cne $TargetUserSid -or
        [string]$principal.LogonType -cne 'InteractiveToken' -or
        ($null -ne $runLevel -and
            $runLevel.InnerText -cne 'LeastPrivilege') -or
        $xmlTriggers.Count -ne 0 -or -not $xmlPathMatches -or
        [string]$actionsNode.Context -cne [string]$principal.id -or
        ($null -ne $xmlArguments -and -not
            [string]::IsNullOrWhiteSpace($xmlArguments.InnerText)) -or
        ($null -ne $xmlWorkingDirectory -and -not
            [string]::IsNullOrWhiteSpace($xmlWorkingDirectory.InnerText))) {
        throw 'The watchdog GUI task semantic contract is invalid.'
    }
}

function Assert-GuiVerifierTaskSemanticContract {
    param([Parameter(Mandatory)][string]$ExpectedArguments)
    $task = Get-ScheduledTask -TaskName $GuiVerifyTaskName -ErrorAction Stop
    $actions = @($task.Actions)
    [xml]$definition = Export-ScheduledTask -TaskName $GuiVerifyTaskName `
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
    if ($principals.Count -ne 1 -or $xmlActions.Count -ne 1 -or
        $actions.Count -ne 1) {
        throw 'The interactive GUI verifier task topology is invalid.'
    }
    $xmlCommand = $xmlActions[0].SelectSingleNode('t:Command', $namespace)
    $xmlArguments = $xmlActions[0].SelectSingleNode('t:Arguments', $namespace)
    $xmlWorkingDirectory = $xmlActions[0].SelectSingleNode(
        't:WorkingDirectory', $namespace
    )
    $principal = $principals[0]
    $xmlUserId = $principal.SelectSingleNode('t:UserId', $namespace)
    $xmlLogon = $principal.SelectSingleNode('t:LogonType', $namespace)
    $xmlRunLevel = $principal.SelectSingleNode('t:RunLevel', $namespace)
    $registeredPathMatches = try {
        [string]::Equals(
            [IO.Path]::GetFullPath([string]$actions[0].Execute),
            [IO.Path]::GetFullPath($PowerShellExe),
            [StringComparison]::OrdinalIgnoreCase
        )
    } catch { $false }
    $xmlPathMatches = try {
        [string]::Equals(
            [IO.Path]::GetFullPath([string]$xmlCommand.InnerText),
            [IO.Path]::GetFullPath($PowerShellExe),
            [StringComparison]::OrdinalIgnoreCase
        )
    } catch { $false }
    if ([string]$task.Principal.UserId -cne $TargetUserSid -or
        [string]$task.Principal.LogonType -cne 'Interactive' -or
        [string]$task.Principal.RunLevel -cne 'Limited' -or
        [string]$xmlUserId.InnerText -cne $TargetUserSid -or
        [string]$xmlLogon.InnerText -cne 'InteractiveToken' -or
        ($null -ne $xmlRunLevel -and
            [string]$xmlRunLevel.InnerText -cne 'LeastPrivilege') -or
        $xmlTriggers.Count -ne 0 -or -not $registeredPathMatches -or
        -not $xmlPathMatches -or
        [string]$actions[0].Arguments -cne $ExpectedArguments -or
        -not [string]::IsNullOrWhiteSpace(
            [string]$actions[0].WorkingDirectory
        ) -or $null -eq $xmlArguments -or
        [string]$xmlArguments.InnerText -cne $ExpectedArguments -or
        ($null -ne $xmlWorkingDirectory -and -not
            [string]::IsNullOrWhiteSpace($xmlWorkingDirectory.InnerText))) {
        throw 'The interactive GUI verifier task semantic contract is invalid.'
    }
}

function Start-NormalGui {
    $timing = [ordered]@{
        purpose = 'watchdog-recovery'
        started_at_utc = [DateTime]::UtcNow.ToString('o')
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
        $null = Stop-ExactGui -Purpose 'watchdog-recovery-prelaunch'
        $stoppedPids = @($script:retiredExactGuiPids)
        $timing.stopped_exact_hash_pids = @($stoppedPids)
        if (Get-ScheduledTask -TaskName $GuiTaskName `
                -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $GuiTaskName -Confirm:$false
        }
        $gui = [Security.SecurityElement]::Escape($InstalledGui)
        $sid = [Security.SecurityElement]::Escape($TargetUserSid)
        $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
 <Principals><Principal id="A"><UserId>$sid</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
 <Settings><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
 <Triggers/><Actions Context="A"><Exec><Command>$gui</Command></Exec></Actions>
</Task>
"@
        try {
            $activeStep = 'register'
            Invoke-GuiLaunchTimedStep -Evidence $timing -Step register `
                -LimitSeconds 30 -Action {
                    Register-ScheduledTask -TaskName $GuiTaskName -Xml $xml |
                        Out-Null
                }
            $activeStep = 'semantic'
            Invoke-GuiLaunchTimedStep -Evidence $timing -Step semantic `
                -LimitSeconds 30 -Action { Assert-GuiTaskSemanticContract }
            $activeStep = 'start'
            Invoke-GuiLaunchTimedStep -Evidence $timing -Step start `
                -LimitSeconds 30 -Action {
                    Start-ScheduledTask -TaskName $GuiTaskName
                }
            $activeStep = 'process_observation'
            $observationStartedAt = [DateTime]::UtcNow
            $limit = $observationStartedAt.AddSeconds(20)
            do {
                Start-Sleep -Milliseconds 250
                $process = Get-NormalGuiProcess -ExcludedPids $stoppedPids
            } while ($null -eq $process -and [DateTime]::UtcNow -lt $limit)
            $timing.process_observation_started_at_utc =
                $observationStartedAt.ToString('o')
            $timing.process_observation_deadline_utc = $limit.ToString('o')
            $timing.process_observation_duration_ms = [int64](
                ([DateTime]::UtcNow - $observationStartedAt).TotalMilliseconds
            )
            $timing.process_observation_within_limit =
                [DateTime]::UtcNow -le $limit
            if ($null -eq $process) {
                throw 'The watchdog GUI task did not expose one new exact process.'
            }
            $timing.launched_pid = [int]$process.Id
            $timing.new_pid_verified =
                $stoppedPids -notcontains [int]$process.Id
            if (-not $timing.new_pid_verified) {
                throw 'The watchdog GUI launch reused a stopped exact PID.'
            }
        } finally {
            $activeStep = 'task_cleanup'
            Unregister-ScheduledTask -TaskName $GuiTaskName -Confirm:$false `
                -ErrorAction SilentlyContinue
            $script:guiTaskRemoved = $null -eq (
                Get-ScheduledTask -TaskName $GuiTaskName `
                    -ErrorAction SilentlyContinue
            )
        }
        $activeStep = 'post_cleanup_persistence'
        Start-Sleep -Milliseconds 750
        $persisted = Get-NormalGuiProcess -ExcludedPids $stoppedPids
        if ($null -eq $persisted -or $persisted.Id -ne $process.Id -or
            -not $script:guiTaskRemoved) {
            throw 'The watchdog new GUI process or task cleanup did not persist.'
        }
        $timing.outcome = 'passed'
        $true
    } catch {
        $timing.failure_step = $activeStep
        $timing.failure = [string]$_.Exception.Message
        throw
    } finally {
        $timing.completed_at_utc = [DateTime]::UtcNow.ToString('o')
        $script:guiLaunchTimingEvidence += [pscustomobject]$timing
    }
}

function Invoke-InteractiveVisibleGuiProof {
    param(
        [Parameter(Mandatory)][ValidateRange(1, 2147483647)]
        [int]$ExpectedPid
    )
    if ((Get-Sha256 $GuiVerifier) -cne $ExpectedGuiVerifierSha256) {
        throw 'The staged interactive GUI verifier changed before use.'
    }
    Assert-NoReparsePath $GuiVerifyReceiptPath
    if (Test-Path -LiteralPath $GuiVerifyReceiptPath -ErrorAction Stop) {
        throw 'The one-use interactive GUI proof receipt already exists.'
    }
    if (Get-ScheduledTask -TaskName $GuiVerifyTaskName `
            -ErrorAction SilentlyContinue) {
        throw 'The one-use interactive GUI verifier task already exists.'
    }
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
        '-File "' + $GuiVerifier + '"' +
        ' -ExpectedVerifierSha256 ' + $ExpectedGuiVerifierSha256 +
        ' -ExpectedGuiSha256 ' + $ExpectedGuiSha256 +
        ' -ExpectedSessionId ' + $TargetSessionId +
        ' -ExpectedPid ' + $ExpectedPid +
        ' -OutputPath "' + $GuiVerifyReceiptPath + '"'
    $action = New-ScheduledTaskAction -Execute $PowerShellExe `
        -Argument $arguments
    $principal = New-ScheduledTaskPrincipal -UserId $TargetUserSid `
        -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (
        New-TimeSpan -Seconds 60
    ) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $timing = [ordered]@{
        purpose = 'watchdog-visible-window-verifier'
        started_at_utc = [DateTime]::UtcNow.ToString('o')
        post_start_observation_limit_seconds = 30
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
        launched_pid = $ExpectedPid
        new_pid_verified = $true
        outcome = 'failed'
        failure_step = ''
        failure = ''
        completed_at_utc = ''
    }
    $activeStep = 'register'
    try {
        Invoke-GuiLaunchTimedStep -Evidence $timing -Step register `
            -LimitSeconds 30 -Action {
                Register-ScheduledTask -TaskName $GuiVerifyTaskName `
                    -Action $action -Principal $principal -Settings $settings |
                    Out-Null
            }
        $activeStep = 'semantic'
        Invoke-GuiLaunchTimedStep -Evidence $timing -Step semantic `
            -LimitSeconds 30 -Action {
                Assert-GuiVerifierTaskSemanticContract `
                    -ExpectedArguments $arguments
            }
        $activeStep = 'start'
        Invoke-GuiLaunchTimedStep -Evidence $timing -Step start `
            -LimitSeconds 30 -Action {
                Start-ScheduledTask -TaskName $GuiVerifyTaskName `
                    -ErrorAction Stop
            }
        $activeStep = 'proof_observation'
        $observationStarted = [DateTime]::UtcNow
        $proofDeadline = $observationStarted.AddSeconds(30)
        do {
            Start-Sleep -Milliseconds 200
        } while (-not (Test-Path -LiteralPath $GuiVerifyReceiptPath `
                    -PathType Leaf -ErrorAction Stop) -and
            [DateTime]::UtcNow -lt $proofDeadline)
        $timing.process_observation_started_at_utc =
            $observationStarted.ToString('o')
        $timing.process_observation_deadline_utc = $proofDeadline.ToString('o')
        $timing.process_observation_duration_ms = [int64](
            ([DateTime]::UtcNow - $observationStarted).TotalMilliseconds
        )
        $timing.process_observation_within_limit =
            [DateTime]::UtcNow -le $proofDeadline
        if (-not (Test-Path -LiteralPath $GuiVerifyReceiptPath `
                -PathType Leaf -ErrorAction Stop)) {
            throw 'The interactive GUI verifier did not emit its bounded receipt.'
        }
        Assert-NoReparsePath $GuiVerifyReceiptPath
        $proof = Get-Content -LiteralPath $GuiVerifyReceiptPath -Raw `
            -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($proof.contract -cne
                'winsvpn-windows-prefreeze-interactive-gui-proof-v1' -or
            $proof.verified -ne $true -or
            [string]$proof.verifier_sha256 -cne
                $ExpectedGuiVerifierSha256 -or
            [string]$proof.exact_gui_sha256 -cne $ExpectedGuiSha256 -or
            [int]$proof.gui_pid -ne $ExpectedPid -or
            [int]$proof.session_id -ne $TargetSessionId -or
            $proof.normal_token -ne $true -or
            $proof.responsive -ne $true -or
            $proof.exact_visible_flutter_window -ne $true) {
            throw 'The interactive GUI verifier receipt did not prove the exact window.'
        }
        $persisted = Get-NormalGuiProcess
        if ($null -eq $persisted -or $persisted.Id -ne $ExpectedPid) {
            throw 'The verified visible GUI did not remain the exact watchdog process.'
        }
        $script:interactiveVisibleWindowVerified = $true
        $script:interactiveVisibleWindowProofSha256 =
            Get-Sha256 $GuiVerifyReceiptPath
        $timing.outcome = 'passed'
    } catch {
        $timing.failure_step = $activeStep
        $timing.failure = [string]$_.Exception.Message
        throw
    } finally {
        Unregister-ScheduledTask -TaskName $GuiVerifyTaskName -Confirm:$false `
            -ErrorAction SilentlyContinue
        $script:guiVerifyTaskRemoved = $null -eq (
            Get-ScheduledTask -TaskName $GuiVerifyTaskName `
                -ErrorAction SilentlyContinue
        )
        $timing.completed_at_utc = [DateTime]::UtcNow.ToString('o')
        $script:guiLaunchTimingEvidence += [pscustomobject]$timing
    }
    if (-not $script:guiVerifyTaskRemoved) {
        throw 'The interactive GUI verifier task remained after proof.'
    }
    $true
}

function Restore-StateFromBackup {
    param([switch]$KeepGui)
    if (-not $script:baselineArmed) {
        throw 'State restoration is unavailable before the baseline is armed.'
    }
    if ((Get-StateClosure $SecureBackup) -cne
            $ExpectedSecureStateClosureSha256 -or
        (Get-StateClosure $LegacyBackup) -cne
            $ExpectedLegacyStateClosureSha256) {
        throw 'The state backup changed after the baseline was armed.'
    }
    Assert-NoReparsePath $SecureBackup
    Assert-NoReparsePath $LegacyBackup
    Assert-NoReparsePath $SecureStateRoot
    Assert-NoReparsePath $LegacyStateRoot
    if (-not $KeepGui) {
        $null = Stop-ExactGui -Purpose 'watchdog-state-restore'
    }
    New-Item -ItemType Directory -Path $SecureStateRoot -Force | Out-Null
    Assert-NoReparsePath $SecureStateRoot
    $backupFiles = @(Get-VerifiedStateFiles $SecureBackup)
    $names = @($backupFiles | Select-Object -ExpandProperty Name)
    Get-VerifiedStateFiles $SecureStateRoot |
        Where-Object Name -notin $names | ForEach-Object {
            Assert-NoReparsePath $_.FullName
            Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
        }
    foreach ($source in $backupFiles) {
        Assert-NoReparsePath $source.FullName
        $target = Join-Path $SecureStateRoot $source.Name
        $temporary = "$target.watchdog.tmp"
        Assert-NoReparsePath $target
        Assert-NoReparsePath $temporary
        if (Test-Path -LiteralPath $temporary -ErrorAction Stop) {
            throw "A stale watchdog restore temporary file exists: $temporary"
        }
        Copy-Item -LiteralPath $source.FullName -Destination $temporary `
            -ErrorAction Stop
        Assert-NoReparsePath $temporary
        Assert-NoReparsePath $source.FullName
        if ((Get-Sha256 $temporary) -cne (Get-Sha256 $source.FullName)) {
            throw 'Watchdog state restore copy changed bytes.'
        }
        Move-Item -LiteralPath $temporary -Destination $target -Force `
            -ErrorAction Stop
        Assert-NoReparsePath $target
    }
    Set-StrictSecureStateAcl
    if (-not (Test-StrictSecureStateAcl)) {
        throw 'The strict SecureState DACL did not restore exactly.'
    }
    New-Item -ItemType Directory -Path $LegacyStateRoot -Force | Out-Null
    Assert-NoReparsePath $LegacyStateRoot
    $legacyBackupFiles = @(Get-VerifiedStateFiles $LegacyBackup)
    $legacyNames = @($legacyBackupFiles | Select-Object -ExpandProperty Name)
    Get-VerifiedStateFiles $LegacyStateRoot |
        Where-Object Name -notin $legacyNames | ForEach-Object {
            Assert-NoReparsePath $_.FullName
            Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
        }
    foreach ($source in $legacyBackupFiles) {
        Assert-NoReparsePath $source.FullName
        $target = Join-Path $LegacyStateRoot $source.Name
        $temporary = "$target.watchdog.tmp"
        Assert-NoReparsePath $target
        Assert-NoReparsePath $temporary
        if (Test-Path -LiteralPath $temporary -ErrorAction Stop) {
            throw "A stale watchdog legacy restore temporary file exists: $temporary"
        }
        Copy-Item -LiteralPath $source.FullName -Destination $temporary `
            -ErrorAction Stop
        Assert-NoReparsePath $temporary
        Assert-NoReparsePath $source.FullName
        if ((Get-Sha256 $temporary) -cne (Get-Sha256 $source.FullName)) {
            throw 'Watchdog legacy state restore copy changed bytes.'
        }
        Move-Item -LiteralPath $temporary -Destination $target -Force `
            -ErrorAction Stop
        Assert-NoReparsePath $target
    }
    if ($ExpectedLegacyRootTopology -eq 'absent') {
        if (@(Get-VerifiedStateFiles $LegacyStateRoot).Count -ne 0) {
            throw 'The initially absent legacy root is not empty after restore.'
        }
        Assert-NoReparsePath $LegacyStateRoot
        Remove-Item -LiteralPath $LegacyStateRoot -Force -ErrorAction Stop
    }
    if ((Get-StateClosure $SecureStateRoot) -cne
        $ExpectedSecureStateClosureSha256 -or
        -not (Test-LegacyTopology) -or
        -not (Test-StrictSecureStateAcl)) {
        throw 'Watchdog state/topology restoration did not converge.'
    }
    $script:stateRestored = $true
    $script:strictSecureAclRestored = $true
}

function Test-RecoveredStateContract {
    (Get-StateClosure $SecureStateRoot) -ceq
        $ExpectedSecureStateClosureSha256 -and
    (Test-LegacyTopology) -and
    (Test-StrictSecureStateAcl) -and
    $null -ne (Get-NormalGuiProcess)
}

function Confirm-StableRecoveredHandoff {
    Start-Sleep -Seconds 8
    Restore-StateFromBackup -KeepGui
    $firstStableRead = Test-RecoveredStateContract
    Start-Sleep -Seconds 2
    $secondStableRead = Test-RecoveredStateContract
    $script:stableStateHandoffVerified = $firstStableRead -and
        $secondStableRead
    if (-not $script:stableStateHandoffVerified) {
        $null = Stop-ExactGui -Purpose 'watchdog-unstable-recovery-cleanup'
        Restore-StateFromBackup
        throw 'The watchdog recovery state did not remain stable after startup.'
    }
}

function Assert-RecoveryBudgetRemaining {
    param([ValidateRange(1, 360)][int]$MinimumSeconds = 1)
    if ([DateTime]::UtcNow.AddSeconds($MinimumSeconds) -ge
            $taskHardDeadline.AddSeconds(-30)) {
        throw 'The watchdog cannot begin a recovery step inside its termination margin.'
    }
}

function Restore-TunnelManagerRunning {
    $script:managerRecoveryAttempted = $true
    $stopFailure = ''
    $startFailure = ''
    try {
        $manager = Get-Service 'WinsVpnTunnelManager' -ErrorAction Stop
        if ($manager.Status -ne 'Stopped') {
            Stop-Service 'WinsVpnTunnelManager' -Force -ErrorAction Stop
            $manager.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(45))
        }
    } catch {
        $stopFailure = [string]$_.Exception.Message
    } finally {
        try {
            $manager = Get-Service 'WinsVpnTunnelManager' -ErrorAction Stop
            if ($manager.Status -ne 'Running') {
                Start-Service 'WinsVpnTunnelManager' -ErrorAction Stop
                $manager = Get-Service 'WinsVpnTunnelManager' -ErrorAction Stop
                $manager.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
            }
            $manager = Get-Service 'WinsVpnTunnelManager' -ErrorAction Stop
            $script:managerRunningVerified = $manager.Status -eq 'Running'
        } catch {
            $startFailure = [string]$_.Exception.Message
            $script:managerRunningVerified = $false
        }
    }
    $script:managerRecoveryFailure = @($stopFailure, $startFailure) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $script:managerRecoveryFailure =
        $script:managerRecoveryFailure -join ' | '
    if (-not $script:managerRunningVerified) {
        throw 'The watchdog could not restore WinsVpnTunnelManager to Running.'
    }
    $script:managerRestarted = $true
}

function Remove-ScopedResidue {
    Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction Stop
    $script:rulesRemoved = $null -eq (
        Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue
    )
    if (Get-ScheduledTask -TaskName $MainTaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $MainTaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $MainTaskName -Confirm:$false
    }
    $script:mainTaskRemoved = $null -eq (
        Get-ScheduledTask -TaskName $MainTaskName -ErrorAction SilentlyContinue
    )
    if (Get-ScheduledTask -TaskName $GuiTaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $GuiTaskName -Confirm:$false
    }
    $script:guiTaskRemoved = $null -eq (
        Get-ScheduledTask -TaskName $GuiTaskName -ErrorAction SilentlyContinue
    )
    if (Get-ScheduledTask -TaskName $GuiVerifyTaskName `
            -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $GuiVerifyTaskName `
            -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $GuiVerifyTaskName -Confirm:$false
    }
    $script:guiVerifyTaskRemoved = $null -eq (
        Get-ScheduledTask -TaskName $GuiVerifyTaskName `
            -ErrorAction SilentlyContinue
    )
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -cne 'S-1-5-18') {
        throw 'The pre-freeze watchdog must run as LocalSystem.'
    }
    if (-not ($RunRoot + '\').StartsWith(
            $AllowedRoot, [StringComparison]::OrdinalIgnoreCase
        ) -or $RunLeaf -notmatch '^[0-9a-f]{32}$' -or
        $TaskExecutionLimitSeconds -ne ($DeadlineSeconds +
            $RecoveryReserveSeconds + 30) -or
        $DeadlineSeconds -lt ($MainTaskExecutionLimitSeconds + 60) -or
        (Get-Sha256 $PSCommandPath) -cne $ExpectedWatchdogSha256 -or
        (Get-Sha256 $GuiVerifier) -cne $ExpectedGuiVerifierSha256 -or
        (Get-Sha256 $InstalledGui) -cne $ExpectedGuiSha256 -or
        (Get-Sha256 $InstalledService) -cne $ExpectedServiceSha256) {
        throw 'The watchdog run identity or exact payload is invalid.'
    }
    $watchdogSelfHashVerified = $true
    Assert-NoReparsePath $TargetProfile
    foreach ($path in @(
            $RunRoot, $SecureStateRoot, $LegacyStateRoot,
            $SecureBackup, $LegacyBackup, $StatusPath, $StagePath,
            $ReceiptPath, $GuiVerifyReceiptPath, $GuiVerifier
        )) {
        Assert-NoReparsePath $path
    }
    $stageFreshSeconds = 180
    do {
        $now = [DateTime]::UtcNow
        $mainTask = Get-ScheduledTask -TaskName $MainTaskName `
            -ErrorAction Stop
        if ([string]$mainTask.State -ceq 'Running') {
            $mainTaskRunningObserved = $true
        }
        if (Test-Path -LiteralPath $StatusPath -PathType Leaf) {
            try {
                Assert-NoReparsePath $StatusPath
                $status = Get-Content -LiteralPath $StatusPath -Raw |
                    ConvertFrom-Json
                $statusIdentityValid = $status.contract -ceq
                    'winsvpn-windows-prefreeze-exact-matrix-case-v1' -and
                    [string]$status.case -ceq $Case -and
                    [string]$status.exact_gui_sha256 -ceq $ExpectedGuiSha256 -and
                    [string]$status.exact_service_sha256 -ceq
                        $ExpectedServiceSha256 -and
                    [string]$status.expected_runner_sha256 -ceq
                        $ExpectedRunnerSha256 -and
                    [string]$status.runner_sha256 -ceq $ExpectedRunnerSha256 -and
                    $status.runner_self_hash_verified -eq $true
                if ($statusIdentityValid -and
                    [string]$status.result -in @('passed', 'failed')) {
                    $terminalStatusObserved = $true
                    $terminalStatusResult = [string]$status.result
                }
                if ($statusIdentityValid -and
                    [string]$status.result -ceq 'failed') {
                    break
                }
                if ($statusIdentityValid -and
                    [string]$status.result -ceq 'passed' -and
                    $status.protected_state_restored_byte_for_byte -eq $true -and
                    $status.temporary_forcing_rules_removed -eq $true -and
                    $status.final_zero_residue -eq $true -and
                    $status.final_gui_normal_token_verified -eq $true) {
                    break
                }
            } catch {}
        }
        if (Test-Path -LiteralPath $StagePath -PathType Leaf) {
            try {
                Assert-NoReparsePath $StagePath
                $stageReceipt = Get-Content -LiteralPath $StagePath -Raw `
                    -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                $stageTime = [DateTime]::Parse(
                    [string]$stageReceipt.observed_at_utc,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::RoundtripKind
                ).ToUniversalTime()
                $stageAge = ($now - $stageTime).TotalSeconds
                $stageIdentityValid = $stageReceipt.contract -ceq
                        'winsvpn-windows-prefreeze-stage-v1' -and
                    [string]$stageReceipt.case -ceq $Case -and
                    $stageAge -ge -5 -and $stageAge -le $stageFreshSeconds
                if ($stageIdentityValid) {
                    $freshStageObserved = $true
                    $lastFreshStage = [string]$stageReceipt.stage
                }
                if ($stageIdentityValid -and
                    [string]$stageReceipt.stage -ceq 'complete') {
                    if (-not $terminalStatusObserved) {
                        $terminalStatusResult = 'stage_complete_without_terminal_status'
                    }
                    break
                }
            } catch {}
        }
        if ($now -ge $deadline) { break }
        Start-Sleep -Milliseconds 250
    } while ($true)
    $waitEndedAtUtc = [DateTime]::UtcNow.ToString('o')
    if ([DateTime]::UtcNow -ge $recoveryMustStartBy) {
        throw 'The watchdog wait exhausted its protected recovery-start margin.'
    }
    $recoveryStartedAtUtc = [DateTime]::UtcNow.ToString('o')
    Assert-RecoveryBudgetRemaining -MinimumSeconds 300

    Assert-ArmRecoveryBaseline
    $cleanWithoutTrigger =
        (Get-StateClosure $SecureStateRoot) -ceq
            $ExpectedSecureStateClosureSha256 -and
        (Test-LegacyTopology) -and
        (Test-StrictSecureStateAcl) -and
        (Get-ResidueState).is_zero -and
        $null -eq (Get-NetFirewallRule -Group $FirewallGroup `
            -ErrorAction SilentlyContinue) -and
        $null -ne (Get-NormalGuiProcess)

    if (-not $cleanWithoutTrigger) {
        $triggered = $true
        $null = Stop-ExactGui -Purpose 'watchdog-triggered-recovery'
        Remove-ScopedResidue
        if (-not (Get-ResidueState).is_zero) {
            Assert-RecoveryBudgetRemaining -MinimumSeconds 180
            Restore-TunnelManagerRunning
            if (-not (Get-ResidueState).is_zero) {
                throw 'Native tunnel residue remained after manager recovery.'
            }
        }
        Restore-StateFromBackup
        $normalGuiVerified = Start-NormalGui
        if (-not $normalGuiVerified) {
            throw 'The watchdog task did not launch the exact normal GUI process.'
        }
        Confirm-StableRecoveredHandoff
        $normalGui = Get-NormalGuiProcess
        $normalGuiVerified = $null -ne $normalGui
        if ($normalGuiVerified) {
            $normalGuiVerified = Invoke-InteractiveVisibleGuiProof `
                -ExpectedPid ([int]$normalGui.Id)
        }
    } else {
        Remove-ScopedResidue
        $stateRestored = $true
        $strictSecureAclRestored = Test-StrictSecureStateAcl
        $firstStableRead = Test-RecoveredStateContract
        Start-Sleep -Seconds 2
        $secondStableRead = Test-RecoveredStateContract
        $stableStateHandoffVerified = $firstStableRead -and $secondStableRead
        if (-not $stableStateHandoffVerified) {
            $null = Stop-ExactGui -Purpose 'watchdog-clean-handoff-failure'
            Restore-StateFromBackup
            throw 'The clean runner handoff did not remain stable.'
        }
        $normalGui = Get-NormalGuiProcess
        $normalGuiVerified = $stableStateHandoffVerified -and
            $null -ne $normalGui
        if ($normalGuiVerified) {
            $normalGuiVerified = Invoke-InteractiveVisibleGuiProof `
                -ExpectedPid ([int]$normalGui.Id)
        }
    }

    $manager = Get-Service 'WinsVpnTunnelManager' -ErrorAction Stop
    if ($manager.Status -ne 'Running') {
        Assert-RecoveryBudgetRemaining -MinimumSeconds 90
        Restore-TunnelManagerRunning
    } else {
        $managerRunningVerified = $true
    }
    $finalResidue = Get-ResidueState
    $pass = $finalResidue.is_zero -and $rulesRemoved -and $mainTaskRemoved -and
        $guiTaskRemoved -and $guiVerifyTaskRemoved -and $stateRestored -and
        $normalGuiVerified -and $interactiveVisibleWindowVerified -and
        $managerRunningVerified -and
        $baselineArmed -and $strictSecureAclRestored -and
        $stableStateHandoffVerified -and
        (Get-StateClosure $SecureStateRoot) -ceq
            $ExpectedSecureStateClosureSha256 -and
        (Test-LegacyTopology) -and (Test-StrictSecureStateAcl)
    if (-not $pass) { throw 'The watchdog could not prove final restored state.' }
} catch {
    $failure = [string]$_.Exception.Message
    $pass = $false
    try { $finalResidue = Get-ResidueState } catch { $finalResidue = $null }
} finally {
    if (Test-Path -LiteralPath $RunRoot -PathType Container) {
        $finalStateClosure = try {
            Get-StateClosure $SecureStateRoot
        } catch { '' }
        $finalLegacyClosure = try {
            Get-StateClosure $LegacyStateRoot
        } catch { '' }
        $finalLegacyTopology = try {
            Test-LegacyTopology
        } catch { $false }
        $finalStrictSecureAcl = try {
            Test-StrictSecureStateAcl
        } catch { $false }
        Write-Json $ReceiptPath ([ordered]@{
            schema_version = 1
            contract = 'winsvpn-windows-prefreeze-watchdog-v1'
            evidence_class = 'prefreeze_nonpublishable'
            publication_authorized = $false
            run_nonce_sha256 = Get-StringSha256 $RunLeaf
            watchdog_sha256 = Get-Sha256 $PSCommandPath
            gui_verifier_sha256 = Get-Sha256 $GuiVerifier
            exact_gui_sha256 = if (Test-Path $InstalledGui) {
                Get-Sha256 $InstalledGui
            } else { '' }
            exact_service_sha256 = if (Test-Path $InstalledService) {
                Get-Sha256 $InstalledService
            } else { '' }
            started_at_utc = $started.ToString('o')
            completed_at_utc = [DateTime]::UtcNow.ToString('o')
            case = $Case
            expected_watchdog_sha256 = $ExpectedWatchdogSha256
            self_hash_verified = $watchdogSelfHashVerified
            deadline_seconds = $DeadlineSeconds
            main_task_execution_limit_seconds =
                $MainTaskExecutionLimitSeconds
            recovery_reserve_seconds = $RecoveryReserveSeconds
            task_execution_limit_seconds = $TaskExecutionLimitSeconds
            task_termination_margin_seconds = 30
            recovery_must_start_by_utc = $recoveryMustStartBy.ToString('o')
            wait_ended_at_utc = $waitEndedAtUtc
            recovery_started_at_utc = $recoveryStartedAtUtc
            terminal_status_observed = $terminalStatusObserved
            terminal_status_result = $terminalStatusResult
            main_task_running_observed = $mainTaskRunningObserved
            fresh_stage_observed = $freshStageObserved
            last_fresh_stage = $lastFreshStage
            fail_safe_triggered = $triggered
            manager_restarted = $managerRestarted
            manager_recovery_attempted = $managerRecoveryAttempted
            manager_running_verified = $managerRunningVerified
            manager_recovery_failure = $managerRecoveryFailure
            baseline_armed = $baselineArmed
            protected_state_restored = $stateRestored
            secure_state_closure_sha256 = $finalStateClosure
            expected_legacy_root_topology = $ExpectedLegacyRootTopology
            legacy_state_closure_sha256 = $finalLegacyClosure
            legacy_topology_restored = $finalLegacyTopology
            strict_secure_acl_restored = $strictSecureAclRestored
            final_strict_secure_acl_contract = $finalStrictSecureAcl
            stable_state_handoff_verified = $stableStateHandoffVerified
            forcing_rules_removed = $rulesRemoved
            main_task_removed = $mainTaskRemoved
            gui_task_removed = $guiTaskRemoved
            gui_verify_task_removed = $guiVerifyTaskRemoved
            normal_gui_verified = $normalGuiVerified
            interactive_visible_window_verified =
                $interactiveVisibleWindowVerified
            interactive_visible_window_proof_sha256 =
                $interactiveVisibleWindowProofSha256
            gui_stop_evidence = @($guiStopEvidence)
            gui_launch_timing_evidence = @($guiLaunchTimingEvidence)
            residue_provider_errors = @($residueProviderErrors)
            xray_absence_is_expected_zero = $true
            awg_engine_absence_is_expected_zero = $true
            state_reparse_checks_enforced = $true
            final_zero_residue = if ($null -ne $finalResidue) {
                [bool]$finalResidue.is_zero
            } else { $false }
            final_awg_engine_process_count = if ($null -ne $finalResidue) {
                [int]$finalResidue.awg_engine_process_count
            } else { -1 }
            pass = $pass
            failure = $failure
            secret_material_redacted = $true
        })
    }
}

if (-not $pass) { exit 1 }
Write-Output "WINDOWS_PREFREEZE_WATCHDOG=PASS triggered=$triggered"
