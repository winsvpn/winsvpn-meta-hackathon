[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern(
        '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )][string]$RunId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$CollectorClosureSha256,
    [ValidateRange(180, 3600)][int]$DeadlineSeconds = 900
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgramDataRoot = Join-Path $env:ProgramData 'WinsVPN\ReleaseEvidence'
$RunRoot = Join-Path $ProgramDataRoot $RunId
$PrivateRoot = Join-Path $RunRoot 'private'
$ReceiptRoot = Join-Path $RunRoot 'receipts'
$HelperRoot = Join-Path $RunRoot 'helpers'
$InstallRoot = Join-Path $env:ProgramFiles 'WinsVPN'
$InstalledGui = Join-Path $InstallRoot 'wins_vpn.exe'
$InstalledAwgEngine = Join-Path $InstallRoot 'winsvpn_awg_engine.exe'
$InstalledWinn3 = Join-Path $InstallRoot 'winsvpn_winn3_engine.exe'
$InstalledXray = Join-Path $InstallRoot 'xray.exe'
$FirewallGroup = "WinsVPN-Release-$RunId"
$TaskName = "WinsVPN Release Watchdog $RunId"
$SystemSid = 'S-1-5-18'
$AdministratorsSid = 'S-1-5-32-544'
$OpenReparsePoint = [IO.FileOptions]0x00200000
$PeMachineX64 = 0x8664
$PeMachineArm64 = 0xAA64
$ReparseAttribute = [uint32]0x400
$MaxJsonBytes = 4194304
$script:ArchitectureBinding = $null

function Get-BytesSha256 {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($algorithm.ComputeHash($Bytes))).Replace(
            '-', ''
        ).ToLowerInvariant()
    } finally { $algorithm.Dispose() }
}

function Assert-CanonicalRunIdentity {
    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParseExact($RunId, 'D', [ref]$parsed) -or
        $parsed -eq [Guid]::Empty -or $RunId -cne $parsed.ToString('D') -or
        (Split-Path -Leaf $RunRoot) -cne $RunId) {
        throw 'Release watchdog run identity/path is not one canonical nonzero UUID.'
    }
    $expectedRoot = [IO.Path]::GetFullPath(
        (Join-Path $env:ProgramData "WinsVPN\ReleaseEvidence\$RunId")
    )
    if ([IO.Path]::GetFullPath($RunRoot) -cne $expectedRoot) {
        throw 'Release watchdog escaped the fixed ReleaseEvidence root.'
    }
}

function Assert-SystemIdentity {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -cne $SystemSid) {
        throw 'Windows release watchdog must execute as LocalSystem.'
    }
}

function Assert-OpenedFileIdentity {
    param(
        [Parameter(Mandatory)][IO.FileStream]$Stream,
        [Parameter(Mandatory)][string]$Path
    )
    if (-not ('WinsVpnWatchdogByHandleInfo' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WinsVpnWatchdogByHandleInfo {
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
    $info = New-Object WinsVpnWatchdogByHandleInfo+BY_HANDLE_FILE_INFORMATION
    $handle = $Stream.SafeFileHandle.DangerousGetHandle()
    if (-not [WinsVpnWatchdogByHandleInfo]::GetFileInformationByHandle(
            $handle, [ref]$info
        )) {
        throw "Release watchdog handle identity is unavailable: $Path"
    }
    if (($info.dwFileAttributes -band $ReparseAttribute) -ne 0) {
        throw "Release watchdog descriptor opened a reparse point: $Path"
    }
    if ($info.nNumberOfLinks -ne 1) {
        throw "Release watchdog path is a hardlink substitution: $Path"
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
                throw "Release watchdog descriptor opened a reparse point: $Path"
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
            throw "Release watchdog hash input size is unbounded or empty: $Path"
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
        throw 'Release watchdog must not run under WOW64.'
    }
    $osArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $processArch = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    if ($processArch -cne $osArch) {
        throw 'Release watchdog must not run under WOW64.'
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
            throw 'Release watchdog omitted architecture binding.'
        }
        return $Binding[$Name]
    }
    $property = $Binding.PSObject.Properties[$Name]
    if (-not $property) {
        throw 'Release watchdog omitted architecture binding.'
    }
    $property.Value
}

function Assert-ArchitectureBinding {
    param($Binding)
    if ($null -eq $Binding) {
        throw 'Release watchdog omitted architecture binding.'
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
        throw 'Release watchdog omitted architecture binding.'
    }
    if ($architecture -cne 'x64' -and $architecture -cne 'arm64') {
        throw "Unsupported release watchdog PE architecture: $architecture"
    }
    $expectedMachine = if ($architecture -ceq 'x64') { $PeMachineX64 } else {
        $PeMachineArm64
    }
    $expectedOs = if ($architecture -ceq 'x64') { 'X64' } else { 'Arm64' }
    if ($native -cne $architecture -or
        $osArchitecture -cne $expectedOs -or
        [int]$peMachine -ne [int]$expectedMachine -or
        $wow64 -ne $false) {
        throw 'Release watchdog architecture binding is mixed, WOW64, or unsupported.'
    }
    $hostArch = Get-NativeWindowsArchitecture
    if ($hostArch -cne $native) {
        throw "Host OS architecture $hostArch does not match bound PE architecture $native."
    }
}

function Invoke-CleanupStep {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)]$Errors
    )
    try { & $Action } catch { $Errors.Add("$Label`: $($_.Exception.Message)") }
}

function Assert-ExactHelperClosure {
    param([Parameter(Mandatory)]$Closure)
    $expected = @(
        [ordered]@{ source = 'tools/windows_release_physical_collector.ps1'; name = 'windows_release_physical_collector.ps1' },
        [ordered]@{ source = 'tools/windows_release_interactive_worker.ps1'; name = 'windows_release_interactive_worker.ps1' },
        [ordered]@{ source = 'tools/windows_secure_state_helpers.ps1'; name = 'windows_secure_state_helpers.ps1' },
        [ordered]@{ source = 'tools/windows_release_safe_watchdog.ps1'; name = 'windows_release_safe_watchdog.ps1' },
        [ordered]@{ source = 'tools/windows_release_fixed_ui.ps1'; name = 'windows_release_fixed_ui.ps1' },
        [ordered]@{ source = 'tools/windows_release_matrix_evidence.py'; name = 'windows_release_matrix_evidence.py' },
        [ordered]@{ source = 'tools/windows_release_bundle_index.schema.json'; name = 'windows_release_bundle_index.schema.json' },
        [ordered]@{ source = 'tools/windows_release_machine_evidence.schema.json'; name = 'windows_release_machine_evidence.schema.json' },
        [ordered]@{ source = 'tools/windows_spain_live_observation.py'; name = 'windows_spain_live_observation.py' },
        [ordered]@{ source = 'tools/windows_core_live_observation.py'; name = 'windows_core_live_observation.py' }
    )
    if ($Closure.schema_version -ne 1 -or $Closure.contract -cne
        'winsvpn-windows-collector-closure-v1' -or
        [string]$Closure.sha256 -notmatch '^[0-9a-f]{64}$' -or
        @($Closure.files).Count -ne $expected.Count) {
        throw 'Release watchdog helper closure document is invalid.'
    }
    $actualNames = @(Get-ChildItem -LiteralPath $HelperRoot -File -Force |
        Select-Object -ExpandProperty Name | Sort-Object)
    if (($actualNames -join '|') -cne (($expected.name | Sort-Object) -join '|')) {
        throw 'Release watchdog helper root contains unexpected execution material.'
    }
    $composite = [Security.Cryptography.IncrementalHash]::CreateHash(
        [Security.Cryptography.HashAlgorithmName]::SHA256
    )
    try {
        for ($index = 0; $index -lt $expected.Count; ++$index) {
            $entry = @($Closure.files)[$index]
            if ([string]$entry.source_path -cne $expected[$index].source -or
                [string]$entry.name -cne $expected[$index].name -or
                [string]$entry.sha256 -notmatch '^[0-9a-f]{64}$' -or
                [long]$entry.size_bytes -lt 1) {
                throw 'Release watchdog helper closure entry contract changed.'
            }
            $path = Join-Path $HelperRoot ([string]$entry.name)
            $composite.AppendData([Text.Encoding]::UTF8.GetBytes(
                ([string]$entry.source_path) + [char]0
            ))
            $fileHash = [Security.Cryptography.IncrementalHash]::CreateHash(
                [Security.Cryptography.HashAlgorithmName]::SHA256
            )
            try {
                $stream = Open-ExclusiveFile $path ([IO.FileMode]::Open) `
                    ([IO.FileAccess]::Read)
                try {
                    if ($stream.Length -ne [long]$entry.size_bytes) {
                        throw 'Release watchdog helper closure entry size changed.'
                    }
                    $buffer = [byte[]]::new(1048576)
                    while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $composite.AppendData($buffer, 0, $count)
                        $fileHash.AppendData($buffer, 0, $count)
                    }
                } finally { $stream.Dispose() }
                $digest = ([BitConverter]::ToString(
                    $fileHash.GetHashAndReset()
                )).Replace('-', '').ToLowerInvariant()
            } finally { $fileHash.Dispose() }
            if ($digest -cne [string]$entry.sha256) {
                throw 'Release watchdog helper closure entry digest changed.'
            }
            $composite.AppendData([byte[]]@(0))
        }
        $closureDigest = ([BitConverter]::ToString(
            $composite.GetHashAndReset()
        )).Replace('-', '').ToLowerInvariant()
    } finally { $composite.Dispose() }
    if ($closureDigest -cne [string]$Closure.sha256 -or
        $closureDigest -cne $CollectorClosureSha256) {
        throw 'Release watchdog full helper composite closure digest changed.'
    }
    $closureDigest
}

function Assert-NoReparsePath {
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    $relative = $full.Substring($root.Length)
    $current = $root
    foreach ($part in @($relative -split '[\\/]' | Where-Object { $_ })) {
        if ($part -eq '..') { throw 'Parent traversal is forbidden.' }
        $current = Join-Path $current $part
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release evidence path contains a reparse point: $current"
        }
    }
}

function Assert-OwnerOnlyAcl {
    param([Parameter(Mandatory)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.AreAccessRulesProtected -ne $true) {
        throw "Release evidence ACL inherits unexpected permissions: $Path"
    }
    $allowed = @($SystemSid, $AdministratorsSid)
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
        if ($sid -notin $allowed -or $rule.AccessControlType -ne 'Allow' -or
            ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) `
                -ne [Security.AccessControl.FileSystemRights]::FullControl) {
            throw "Release evidence ACL contains an unexpected ACE: $Path"
        }
    }
    $present = @($acl.Access | ForEach-Object {
        $_.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    } | Sort-Object -Unique)
    if (($present -join '|') -cne (($allowed | Sort-Object) -join '|')) {
        throw "Release evidence ACL is missing SYSTEM or Administrators: $Path"
    }
}

function Read-JsonOnce {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 16777216)][int]$MaximumBytes = 4194304
    )
    $stream = Open-ExclusiveFile $Path ([IO.FileMode]::Open) ([IO.FileAccess]::Read)
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt $MaximumBytes) {
            throw "Bounded JSON input has invalid size: $Path"
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -le 0) { throw "JSON input changed during read: $Path" }
            $offset += $count
        }
    } finally {
        $stream.Dispose()
    }
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    [pscustomobject]@{
        Bytes = $bytes
        Sha256 = Get-BytesSha256 $bytes
        Json = $text | ConvertFrom-Json
    }
}

function Write-NewJson {
    param([string]$Path, [object]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Value | ConvertTo-Json -Depth 12 -Compress) + [Environment]::NewLine
    )
    if ($bytes.Length -lt 1 -or $bytes.Length -gt $MaxJsonBytes) {
        throw 'Release watchdog JSON output size is unbounded.'
    }
    $stream = Open-ExclusiveFile $Path ([IO.FileMode]::CreateNew) `
        ([IO.FileAccess]::Write)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Get-StateDocument {
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop |
        Sort-Object InterfaceGuid | ForEach-Object {
            [ordered]@{
                guid = [string]$_.InterfaceGuid
                index = [int]$_.ifIndex
                name_sha256 = Get-BytesSha256 (
                    [Text.Encoding]::UTF8.GetBytes([string]$_.Name)
                )
                status = [string]$_.Status
                media = [string]$_.MediaType
                physical = [bool]$_.HardwareInterface
            }
        })
    $routes = @(Get-NetRoute -ErrorAction Stop | Sort-Object `
        AddressFamily, InterfaceIndex, DestinationPrefix, NextHop, RouteMetric |
        ForEach-Object {
            [ordered]@{
                family = [string]$_.AddressFamily
                index = [int]$_.InterfaceIndex
                prefix = [string]$_.DestinationPrefix
                next_hop = [string]$_.NextHop
                metric = [int]$_.RouteMetric
                protocol = [string]$_.Protocol
            }
        })
    $dns = @(Get-DnsClientServerAddress -ErrorAction Stop | Sort-Object `
        InterfaceIndex, AddressFamily | ForEach-Object {
            [ordered]@{
                index = [int]$_.InterfaceIndex
                family = [string]$_.AddressFamily
                servers = @($_.ServerAddresses)
            }
        })
    $ip = @(Get-NetIPInterface -ErrorAction Stop | Sort-Object `
        InterfaceIndex, AddressFamily | ForEach-Object {
            [ordered]@{
                index = [int]$_.InterfaceIndex
                family = [string]$_.AddressFamily
                dhcp = [string]$_.Dhcp
                connection = [string]$_.ConnectionState
                forwarding = [string]$_.Forwarding
                metric = [int]$_.InterfaceMetric
            }
        })
    $firewall = @(Get-NetFirewallProfile -ErrorAction Stop | Sort-Object Name |
        ForEach-Object {
            [ordered]@{
                name = [string]$_.Name
                enabled = [bool]$_.Enabled
                inbound = [string]$_.DefaultInboundAction
                outbound = [string]$_.DefaultOutboundAction
            }
        })
    $services = foreach ($name in @(
        'BFE', 'MpsSvc', 'WinsVpnTunnelManager', 'WinsVPNSplitTunnel',
        'AmneziaWGTunnel$winsvpn'
    )) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        [ordered]@{
            name = $name
            present = $null -ne $service
            status = if ($service) { [string]$service.Status } else { '' }
        }
    }
    $killSwitchRules = @(Get-NetFirewallRule -PolicyStore ActiveStore `
        -ErrorAction Stop | Where-Object {
            [string]$_.DisplayName -match '(?i)wins\s*vpn|winsvpn' -or
            [string]$_.Name -match '(?i)wins\s*vpn|winsvpn' -or
            [string]$_.Group -match '(?i)wins\s*vpn|winsvpn'
        } | Sort-Object Name | ForEach-Object {
            $port = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $application = $_ | Get-NetFirewallApplicationFilter `
                -ErrorAction SilentlyContinue
            $address = $_ | Get-NetFirewallAddressFilter `
                -ErrorAction SilentlyContinue
            [ordered]@{
                name = [string]$_.Name
                enabled = [string]$_.Enabled
                direction = [string]$_.Direction
                action = [string]$_.Action
                profile = [string]$_.Profile
                edge_traversal = [string]$_.EdgeTraversalPolicy
                protocol = if ($port) { [string]$port.Protocol } else { '' }
                local_port = if ($port) { [string]$port.LocalPort } else { '' }
                remote_port = if ($port) { [string]$port.RemotePort } else { '' }
                program_sha256 = if ($application -and $application.Program) {
                    Get-BytesSha256 ([Text.Encoding]::UTF8.GetBytes(
                        [string]$application.Program
                    ))
                } else { '' }
                local_address = if ($address) {
                    @($address.LocalAddress | Sort-Object)
                } else { @() }
                remote_address = if ($address) {
                    @($address.RemoteAddress | Sort-Object)
                } else { @() }
            }
        })
    [ordered]@{
        adapters = $adapters
        routes = $routes
        dns = $dns
        ip_interfaces = $ip
        firewall_profiles = $firewall
        kill_switch_wfp_state = [ordered]@{
            base_filtering_engine_running = [bool](
                (Get-Service -Name BFE -ErrorAction Stop).Status -eq 'Running'
            )
            windows_firewall_running = [bool](
                (Get-Service -Name MpsSvc -ErrorAction Stop).Status -eq 'Running'
            )
            winsvpn_firewall_rules = $killSwitchRules
        }
        services = @($services)
        awg_engine_pids = @(Get-Process winsvpn_awg_engine `
            -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id |
            Sort-Object)
        xray_pids = @(Get-Process xray -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Id | Sort-Object)
    }
}

function Get-CanonicalSha256 {
    param([object]$Value)
    $json = $Value | ConvertTo-Json -Depth 12 -Compress
    Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($json))
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

foreach ($key in @($PSBoundParameters.Keys)) {
    if ($key -cne 'RunId' -and $key -cne 'CollectorClosureSha256' -and
        $key -cne 'DeadlineSeconds') {
        throw 'Release watchdog rejected unsafe or extra arguments.'
    }
}
Assert-SystemIdentity
Assert-CanonicalRunIdentity
[void](Get-NativeWindowsArchitecture)
Assert-NoReparsePath $RunRoot
Assert-NoReparsePath $PrivateRoot
Assert-NoReparsePath $ReceiptRoot
Assert-NoReparsePath $HelperRoot
foreach ($path in @($RunRoot, $PrivateRoot, $ReceiptRoot, $HelperRoot)) {
    Assert-OwnerOnlyAcl $path
}
$expectedSelf = Join-Path $HelperRoot 'windows_release_safe_watchdog.ps1'
if ([IO.Path]::GetFullPath($PSCommandPath) -cne [IO.Path]::GetFullPath($expectedSelf)) {
    throw 'Release watchdog must execute only from the locked helper root.'
}
$closure = Read-JsonOnce (Join-Path $PrivateRoot 'collector-closure.json')
if ($closure.Json.contract -cne 'winsvpn-windows-collector-closure-v1' -or
    $closure.Json.sha256 -cne $CollectorClosureSha256) {
    throw 'Release watchdog collector closure is invalid.'
}
$verifiedClosureSha256 = Assert-ExactHelperClosure $closure.Json
if ($verifiedClosureSha256 -cne $CollectorClosureSha256) {
    throw 'Release watchdog source is not bound to its full helper closure.'
}
$context = (Read-JsonOnce (Join-Path $PrivateRoot 'context.json')).Json
$runtime = (Read-JsonOnce (Join-Path $PrivateRoot 'runtime-context.json')).Json
$baseline = (Read-JsonOnce (Join-Path $PrivateRoot 'baseline.json') 16777216).Json
$arm = (Read-JsonOnce (Join-Path $PrivateRoot 'arm.json')).Json
if ($context.run_id -cne $RunId -or $arm.run_id -cne $RunId -or
    $context.contract -cne 'winsvpn-windows-release-collector-context-v1' -or
    $context.collector_closure_sha256 -cne $CollectorClosureSha256 -or
    $runtime.run_id -cne $RunId -or
    $runtime.collector_closure_sha256 -cne $CollectorClosureSha256 -or
    $runtime.contract -cne 'winsvpn-windows-release-runtime-context-v1' -or
    [IO.Path]::GetFullPath([string]$runtime.installed_gui_path) -cne
        [IO.Path]::GetFullPath($InstalledGui) -or
    [string]$runtime.installed_gui_sha256 -notmatch '^[0-9a-f]{64}$' -or
    [IO.Path]::GetFullPath([string]$runtime.installed_awg_engine_path) -cne
        [IO.Path]::GetFullPath($InstalledAwgEngine) -or
    [string]$runtime.installed_awg_engine_sha256 -notmatch '^[0-9a-f]{64}$' -or
    $arm.collector_closure_sha256 -cne $CollectorClosureSha256 -or
    $arm.contract -cne 'winsvpn-windows-release-watchdog-arm-v1' -or
    $arm.armed -ne $true) {
    throw 'Release watchdog context/arm binding is invalid.'
}
$contextSourceOnly = $context.PSObject.Properties['source_only']
if (-not $contextSourceOnly -or $contextSourceOnly.Value -ne $false) {
    throw 'Release watchdog refused a source-only PASS.'
}
$runtimeSourceOnly = $runtime.PSObject.Properties['source_only']
if ($runtimeSourceOnly -and $runtimeSourceOnly.Value -ne $false) {
    throw 'Release watchdog refused a source-only PASS.'
}
Assert-ArchitectureBinding $context
Assert-ArchitectureBinding $runtime
if ([string](Get-BindingProperty $runtime 'architecture') -cne
        [string](Get-BindingProperty $context 'architecture') -or
    [int](Get-BindingProperty $runtime 'pe_machine') -ne
        [int](Get-BindingProperty $context 'pe_machine')) {
    throw 'Release watchdog runtime/context architecture binding is mixed.'
}
$script:ArchitectureBinding = [ordered]@{
    architecture = [string](Get-BindingProperty $runtime 'architecture')
    pe_machine = [int](Get-BindingProperty $runtime 'pe_machine')
    native_architecture = [string](Get-BindingProperty $runtime 'native_architecture')
    os_architecture = [string](Get-BindingProperty $runtime 'os_architecture')
    process_wow64 = $false
}
$guiPe = Get-PeArchitecture $InstalledGui
$awgPe = Get-PeArchitecture $InstalledAwgEngine
if ($guiPe.Name -cne [string]$script:ArchitectureBinding.architecture -or
    [int]$guiPe.Machine -ne [int]$script:ArchitectureBinding.pe_machine -or
    $awgPe.Name -cne [string]$script:ArchitectureBinding.architecture -or
    [int]$awgPe.Machine -ne [int]$script:ArchitectureBinding.pe_machine) {
    throw 'Release watchdog candidate PE architecture is mixed with the native host.'
}
if ((Get-Sha256 $InstalledGui ([IO.FileShare]::Read)) -cne
        [string]$runtime.installed_gui_sha256 -or
    (Get-Sha256 $InstalledAwgEngine ([IO.FileShare]::Read)) -cne
        [string]$runtime.installed_awg_engine_sha256) {
    throw 'Release watchdog installed image hash is stale or substituted.'
}
$installedXraySha256 = ''
if (Test-Path -LiteralPath $InstalledXray -PathType Leaf) {
    $xrayPe = Get-PeArchitecture $InstalledXray
    if ($xrayPe.Name -cne [string]$script:ArchitectureBinding.architecture -or
        [int]$xrayPe.Machine -ne [int]$script:ArchitectureBinding.pe_machine) {
        throw 'Release watchdog Xray PE architecture is mixed with the native host.'
    }
    $installedXraySha256 = Get-Sha256 $InstalledXray ([IO.FileShare]::Read)
}
if (Test-Path -LiteralPath $InstalledWinn3 -PathType Leaf) {
    $winn3Pe = Get-PeArchitecture $InstalledWinn3
    if ($winn3Pe.Name -cne [string]$script:ArchitectureBinding.architecture -or
        [int]$winn3Pe.Machine -ne [int]$script:ArchitectureBinding.pe_machine) {
        throw 'Release watchdog Winn v3 PE architecture is mixed with the native host.'
    }
}
$readyStateSha256 = Get-CanonicalSha256 (Get-StateDocument)
$readyDns = $null -ne (Resolve-DnsName winsvpn.org -Type A -DnsOnly `
    -QuickTimeout -ErrorAction SilentlyContinue)
$readyManagement = Test-NetConnection `
    -ComputerName ([string]$baseline.management_probe_host) `
    -Port ([int]$baseline.management_probe_port) -InformationLevel Quiet `
    -WarningAction SilentlyContinue
$readyEgressValue = try {
    (Invoke-WebRequest -UseBasicParsing -Uri 'https://api.ipify.org' `
        -TimeoutSec 15).Content.Trim()
} catch { '' }
$readyEgressSha256 = Get-CanonicalSha256 ([ordered]@{ value = $readyEgressValue })
if ($readyStateSha256 -cne [string]$baseline.state_sha256 -or
    $readyEgressSha256 -cne [string]$baseline.egress_state_sha256 -or
    -not $readyDns -or -not $readyManagement) {
    throw 'Release watchdog refused to arm away from its exact healthy baseline.'
}
$readyPath = Join-Path $PrivateRoot 'watchdog-ready.json'
Write-NewJson $readyPath ([ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-release-watchdog-ready-v1'
    run_id = $RunId
    collector_closure_sha256 = $CollectorClosureSha256
    architecture = [string]$script:ArchitectureBinding.architecture
    pe_machine = [int]$script:ArchitectureBinding.pe_machine
    native_architecture = [string]$script:ArchitectureBinding.native_architecture
    os_architecture = [string]$script:ArchitectureBinding.os_architecture
    process_wow64 = $false
    source_only = $false
    ready_at_utc = [DateTime]::UtcNow.ToString('o')
})

$started = [DateTime]::UtcNow
$deadline = $started.AddSeconds($DeadlineSeconds)
$normal = $false
$emergency = $false
$cleanupErrors = [Collections.Generic.List[string]]::new()
$taskRemoved = $false
try {
    do {
        $disarmPath = Join-Path $PrivateRoot 'normal-disarm.json'
        if (Test-Path -LiteralPath $disarmPath -PathType Leaf) {
            try {
                $disarm = (Read-JsonOnce $disarmPath).Json
                $state = Get-StateDocument
                $stateSha = Get-CanonicalSha256 $state
                if ($disarm.contract -ceq 'winsvpn-windows-release-watchdog-disarm-v1' -and
                    $disarm.run_id -ceq $RunId -and
                    $disarm.collector_closure_sha256 -ceq $CollectorClosureSha256 -and
                    $disarm.normal_teardown_proven -eq $true -and
                    $disarm.fail_safe_triggered -eq $false -and
                    ($null -eq $disarm.PSObject.Properties['source_only'] -or
                        $disarm.source_only -eq $false) -and
                    $disarm.baseline_state_sha256 -ceq $baseline.state_sha256 -and
                    $stateSha -ceq $baseline.state_sha256) {
                    $normal = $true
                    break
                }
            } catch {}
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)

    if (-not $normal) {
        $emergency = $true
        $latestRuntime = (Read-JsonOnce `
            (Join-Path $PrivateRoot 'runtime-context.json')).Json
        if ($latestRuntime.run_id -cne $RunId -or
            $latestRuntime.collector_closure_sha256 -cne
                $CollectorClosureSha256) {
            throw 'Emergency cleanup rejected a stale runtime process pin.'
        }
        $runtime = $latestRuntime
        try { Assert-ArchitectureBinding $runtime } catch {
            $cleanupErrors.Add("runtime_architecture: $($_.Exception.Message)")
        }
        if ($cleanupErrors.Count -eq 0 -and
            [IO.Path]::GetFullPath([string]$runtime.installed_gui_path) -cne
                [IO.Path]::GetFullPath($InstalledGui)) {
            $cleanupErrors.Add('Emergency cleanup rejected a substituted GUI path.')
        }
        if ($cleanupErrors.Count -eq 0) {
            if (Test-ExactImage -Pid ([int]$runtime.candidate_pid) `
                    -Path ([string]$runtime.installed_gui_path) `
                    -Sha256 ([string]$runtime.installed_gui_sha256)) {
                Invoke-CleanupStep 'candidate_gui' {
                    Stop-Process -Id ([int]$runtime.candidate_pid) -Force `
                        -ErrorAction Stop
                } $cleanupErrors
            }
            Invoke-CleanupStep 'release_firewall_group' {
                Get-NetFirewallRule -Group $FirewallGroup `
                    -ErrorAction SilentlyContinue | Remove-NetFirewallRule `
                    -ErrorAction Stop
            } $cleanupErrors
            foreach ($name in @('WinsVPNSplitTunnel', 'AmneziaWGTunnel$winsvpn')) {
                Invoke-CleanupStep "service_$name" {
                    Stop-Service -Name ([string]$name) -Force `
                        -ErrorAction SilentlyContinue
                } $cleanupErrors
            }
            Get-Process winsvpn_awg_engine -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $awgProcess = $_
                    if (Test-ExactImage -Pid $awgProcess.Id `
                            -Path $InstalledAwgEngine `
                            -Sha256 ([string]$runtime.installed_awg_engine_sha256)) {
                        Invoke-CleanupStep "awg_engine_$($awgProcess.Id)" {
                            Stop-Process -Id $awgProcess.Id -Force `
                                -ErrorAction Stop
                        } $cleanupErrors
                    }
                }
            if ($installedXraySha256 -match '^[0-9a-f]{64}$') {
                Get-Process xray -ErrorAction SilentlyContinue | ForEach-Object {
                    $xrayProcess = $_
                    if (Test-ExactImage -Pid $xrayProcess.Id `
                            -Path $InstalledXray -Sha256 $installedXraySha256) {
                        Invoke-CleanupStep "xray_$($xrayProcess.Id)" {
                            Stop-Process -Id $xrayProcess.Id -Force `
                                -ErrorAction Stop
                        } $cleanupErrors
                    }
                }
            }
            Get-Process winsvpn_winn3_engine -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $winn3Process = $_
                    if (Test-Path -LiteralPath $InstalledWinn3 -PathType Leaf) {
                        $winn3Sha = Get-Sha256 $InstalledWinn3 ([IO.FileShare]::Read)
                        if (Test-ExactImage -Pid $winn3Process.Id `
                                -Path $InstalledWinn3 -Sha256 $winn3Sha) {
                            Invoke-CleanupStep "winn3_$($winn3Process.Id)" {
                                Stop-Process -Id $winn3Process.Id -Force `
                                    -ErrorAction Stop
                            } $cleanupErrors
                        }
                    }
                }
            Invoke-CleanupStep 'manager_restart' {
                Restart-Service -Name 'WinsVpnTunnelManager' -Force `
                    -ErrorAction Stop
                (Get-Service WinsVpnTunnelManager).WaitForStatus(
                    'Running', [TimeSpan]::FromSeconds(45)
                )
            } $cleanupErrors
        }
    }

    $taskRemoved = $false
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        $taskRemoved = $true
    } catch {
        $cleanupErrors.Add("unregister_task: $($_.Exception.Message)")
    }
    if (-not $taskRemoved) {
        $still = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($still) {
            $cleanupErrors.Add("Failed to unregister release watchdog task: $TaskName")
        } else {
            $taskRemoved = $true
        }
    }

    $finalState = Get-StateDocument
    $finalSha = Get-CanonicalSha256 $finalState
    $dnsOk = $null -ne (Resolve-DnsName winsvpn.org -Type A `
        -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue)
    $managementOk = Test-NetConnection `
        -ComputerName ([string]$baseline.management_probe_host) `
        -Port ([int]$baseline.management_probe_port) `
        -InformationLevel Quiet -WarningAction SilentlyContinue
    $egressValue = try {
        (Invoke-WebRequest -UseBasicParsing -Uri 'https://api.ipify.org' `
            -TimeoutSec 15).Content.Trim()
    } catch { '' }
    $egressSha = Get-CanonicalSha256 ([ordered]@{ value = $egressValue })
    $sourceOnlyClosed = $contextSourceOnly -and $contextSourceOnly.Value -eq $false
    $pass = $normal -and -not $emergency -and
        $cleanupErrors.Count -eq 0 -and $sourceOnlyClosed -and
        $finalSha -ceq $baseline.state_sha256 -and $dnsOk -and
        $managementOk -and $egressSha -ceq $baseline.egress_state_sha256
    $finishedAt = [DateTime]::UtcNow.ToString('o')
    $receipt = [ordered]@{
        schema_version = 1
        contract = 'winsvpn-windows-release-watchdog-receipt-v1'
        run_id = $RunId
        captured_at_utc = $finishedAt
        secret_material_redacted = $true
        release_input_index_sha256 = [string]$context.release_input_index_sha256
        platform_manifest_sha256 = [string]$context.platform_manifest_sha256
        artifact_input_fingerprint_sha256 = [string]$context.artifact_input_fingerprint_sha256
        build_receipt_sha256 = [string]$context.build_receipt_sha256
        producer_contract_sha256 = [string]$context.producer_contract_sha256
        collector_closure_sha256 = $CollectorClosureSha256
        artifact_sha256 = [string]$context.artifact_sha256
        release_identity = [string](Get-BindingProperty $context 'release_identity')
        source_only = $false
        architecture = [string]$script:ArchitectureBinding.architecture
        pe_machine = [int]$script:ArchitectureBinding.pe_machine
        native_architecture = [string]$script:ArchitectureBinding.native_architecture
        os_architecture = [string]$script:ArchitectureBinding.os_architecture
        process_wow64 = $false
        step_nonce = [string]$arm.step_nonce
        sequence = [int]$arm.sequence
        started_at_utc = $started.ToString('o')
        finished_at_utc = $finishedAt
        normal_teardown_proven = $normal
        fail_safe_triggered = $emergency
        cleanup_errors = @($cleanupErrors)
        baseline_state_sha256 = [string]$baseline.state_sha256
        final_state_sha256 = $finalSha
        dns_restored = [bool]$dnsOk
        lan_management_restored = [bool]$managementOk
        egress_restored = $egressSha -ceq $baseline.egress_state_sha256
        pass = $pass
        passed = $pass
    }
    Write-NewJson (Join-Path $ReceiptRoot 'watchdog.json') $receipt
    if (-not $pass) {
        throw 'Release watchdog did not observe natural teardown and exact baseline restoration.'
    }
} finally {
    if (-not $taskRemoved) {
        try {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false `
                -ErrorAction SilentlyContinue
        } catch {}
    }
}
