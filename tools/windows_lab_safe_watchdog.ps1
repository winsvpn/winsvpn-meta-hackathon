[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern(
        '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )][string]$RunId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')]
    [string]$CollectorClosureSha256,
    [ValidateRange(90, 3600)][int]$DeadlineSeconds = 1200
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgramDataRoot = Join-Path $env:ProgramData 'WinsVPN\LabEvidence'
$RunRoot = Join-Path $ProgramDataRoot $RunId
$PrivateRoot = Join-Path $RunRoot 'private'
$ReceiptRoot = Join-Path $RunRoot 'receipts'
$HelperRoot = Join-Path $RunRoot 'helpers'
$TaskName = "WinsVPN Lab Watchdog $RunId"
$SystemSid = 'S-1-5-18'
$AdministratorsSid = 'S-1-5-32-544'
$InstallRoot = Join-Path $env:ProgramFiles 'WinsVPN'
$InstalledGui = Join-Path $InstallRoot 'wins_vpn.exe'
$InstalledXray = Join-Path $InstallRoot 'xray.exe'
$InstalledAwgEngine = Join-Path $InstallRoot 'winsvpn_awg_engine.exe'
$FirewallGroup = "WinsVPN-Lab-$RunId"

function Get-BytesSha256 {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($algorithm.ComputeHash($Bytes))).Replace(
            '-', ''
        ).ToLowerInvariant()
    } finally { $algorithm.Dispose() }
}

function Assert-SystemIdentity {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -cne $SystemSid) {
        throw 'Windows lab watchdog must execute as LocalSystem.'
    }
}

function Assert-CanonicalRunIdentity {
    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParseExact($RunId, 'D', [ref]$parsed) -or
        $parsed -eq [Guid]::Empty -or $RunId -cne $parsed.ToString('D') -or
        (Split-Path -Leaf $RunRoot) -cne $RunId) {
        throw 'Lab watchdog run identity/path is not one canonical nonzero UUID.'
    }
    $expectedRoot = [IO.Path]::GetFullPath(
        (Join-Path $env:ProgramData "WinsVPN\LabEvidence\$RunId")
    )
    if ([IO.Path]::GetFullPath($RunRoot) -cne $expectedRoot) {
        throw 'Lab watchdog escaped the fixed LabEvidence root.'
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
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Lab evidence path contains a reparse point: $current"
        }
    }
}

function Assert-OwnerOnlyAcl {
    param([Parameter(Mandatory)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.AreAccessRulesProtected -ne $true) {
        throw "Lab evidence ACL inherits unexpected permissions: $Path"
    }
    $allowed = @($SystemSid, $AdministratorsSid)
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
        if ($sid -notin $allowed -or $rule.AccessControlType -ne 'Allow' -or
            ($rule.FileSystemRights -band
                [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl) {
            throw "Lab evidence ACL contains an unexpected ACE: $Path"
        }
    }
    $present = @($acl.Access | ForEach-Object {
        $_.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    } | Sort-Object -Unique)
    if (($present -join '|') -cne (($allowed | Sort-Object) -join '|')) {
        throw "Lab evidence ACL is missing SYSTEM or Administrators: $Path"
    }
}

function Read-JsonOnce {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 16777216)][int]$MaximumBytes = 4194304
    )
    Assert-NoReparsePath $Path
    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::None
    )
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
    } finally { $stream.Dispose() }
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    [pscustomobject]@{
        Bytes = $bytes
        Sha256 = Get-BytesSha256 $bytes
        Json = $text | ConvertFrom-Json
    }
}

function Write-NewJson {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Value | ConvertTo-Json -Depth 12 -Compress) + [Environment]::NewLine
    )
    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
}

function Assert-ExactHelperClosure {
    param([Parameter(Mandatory)]$Closure)
    $expected = @(
        [ordered]@{ source = 'tools/windows_lab_physical_collector.ps1'; name = 'windows_lab_physical_collector.ps1' },
        [ordered]@{ source = 'tools/windows_lab_interactive_worker.ps1'; name = 'windows_lab_interactive_worker.ps1' },
        [ordered]@{ source = 'tools/windows_secure_state_helpers.ps1'; name = 'windows_secure_state_helpers.ps1' },
        [ordered]@{ source = 'tools/windows_lab_safe_watchdog.ps1'; name = 'windows_lab_safe_watchdog.ps1' },
        [ordered]@{ source = 'tools/windows_lab_fixed_ui.ps1'; name = 'windows_lab_fixed_ui.ps1' },
        [ordered]@{ source = 'tools/windows_lab_matrix_evidence.py'; name = 'windows_lab_matrix_evidence.py' },
        [ordered]@{ source = 'tools/windows_lab_bundle_index.schema.json'; name = 'windows_lab_bundle_index.schema.json' },
        [ordered]@{ source = 'tools/windows_lab_machine_evidence.schema.json'; name = 'windows_lab_machine_evidence.schema.json' },
        [ordered]@{ source = 'tools/windows_spain_live_observation.py'; name = 'windows_spain_live_observation.py' },
        [ordered]@{ source = 'tools/windows_core_live_observation.py'; name = 'windows_core_live_observation.py' }
    )
    if ($Closure.schema_version -ne 1 -or $Closure.contract -cne
        'winsvpn-windows-lab-collector-closure-v1' -or
        [string]$Closure.sha256 -notmatch '^[0-9a-f]{64}$' -or
        @($Closure.files).Count -ne $expected.Count) {
        throw 'Lab watchdog helper closure document is invalid.'
    }
    $actualNames = @(Get-ChildItem -LiteralPath $HelperRoot -File -Force |
        Select-Object -ExpandProperty Name | Sort-Object)
    if (($actualNames -join '|') -cne (($expected.name | Sort-Object) -join '|')) {
        throw 'Lab watchdog helper root contains unexpected execution material.'
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
                throw 'Lab watchdog helper closure entry contract changed.'
            }
            $path = Join-Path $HelperRoot ([string]$entry.name)
            Assert-NoReparsePath $path
            $composite.AppendData([Text.Encoding]::UTF8.GetBytes(
                ([string]$entry.source_path) + [char]0
            ))
            $fileHash = [Security.Cryptography.IncrementalHash]::CreateHash(
                [Security.Cryptography.HashAlgorithmName]::SHA256
            )
            try {
                $stream = [IO.File]::Open(
                    $path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                    [IO.FileShare]::None
                )
                try {
                    if ($stream.Length -ne [long]$entry.size_bytes) {
                        throw 'Lab watchdog helper closure entry size changed.'
                    }
                    $buffer = [byte[]]::new(1048576)
                    while (($count = $stream.Read(
                                $buffer, 0, $buffer.Length
                            )) -gt 0) {
                        $composite.AppendData($buffer, 0, $count)
                        $fileHash.AppendData($buffer, 0, $count)
                    }
                } finally { $stream.Dispose() }
                $digest = ([BitConverter]::ToString(
                    $fileHash.GetHashAndReset()
                )).Replace('-', '').ToLowerInvariant()
            } finally { $fileHash.Dispose() }
            if ($digest -cne [string]$entry.sha256) {
                throw 'Lab watchdog helper closure entry digest changed.'
            }
            $composite.AppendData([byte[]]@(0))
        }
        $closureDigest = ([BitConverter]::ToString(
            $composite.GetHashAndReset()
        )).Replace('-', '').ToLowerInvariant()
    } finally { $composite.Dispose() }
    if ($closureDigest -cne [string]$Closure.sha256 -or
        $closureDigest -cne $CollectorClosureSha256) {
        throw 'Lab watchdog full helper composite closure digest changed.'
    }
    $closureDigest
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
        'AmneziaWGTunnel$winsvpn', 'AmneziaWGTunnel$awg2'
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
    param([Parameter(Mandatory)]$Value)
    $json = $Value | ConvertTo-Json -Depth 12 -Compress
    Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($json))
}

function Get-EgressStateSha256 {
    $value = try {
        (Invoke-WebRequest -UseBasicParsing -Uri 'https://api.ipify.org' `
            -TimeoutSec 15).Content.Trim()
    } catch { '' }
    Get-CanonicalSha256 ([ordered]@{ value = $value })
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
    (Get-FileHash -LiteralPath $actualPath -Algorithm SHA256).Hash.ToLowerInvariant() `
        -ceq $Sha256
}

function Assert-NonpublishableContext {
    param([Parameter(Mandatory)]$Context)
    if ($Context.schema_version -ne 1 -or
        $Context.contract -cne 'winsvpn-windows-lab-collector-context-v1' -or
        $Context.run_id -cne $RunId -or
        $Context.collector_closure_sha256 -cne $CollectorClosureSha256 -or
        $Context.evidence_class -cne 'nonpublishable_lab' -or
        $Context.lab_only -ne $true -or
        $Context.publication_authorized -ne $false -or
        $Context.public_release_gate_eligible -ne $false -or
        $Context.unsigned_local_candidate -ne $true -or
        $Context.authenticode_status -cne 'NotSigned' -or
        [string]$Context.artifact_sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$Context.payload_manifest_sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Lab watchdog context is not exact and nonpublishable.'
    }
}

function Assert-RuntimeContext {
    param([Parameter(Mandatory)]$Runtime)
    if ($Runtime.schema_version -ne 1 -or
        $Runtime.contract -cne 'winsvpn-windows-lab-runtime-context-v1' -or
        $Runtime.run_id -cne $RunId -or
        $Runtime.collector_closure_sha256 -cne $CollectorClosureSha256 -or
        $Runtime.evidence_class -cne 'nonpublishable_lab' -or
        $Runtime.lab_only -ne $true -or
        $Runtime.publication_authorized -ne $false -or
        $Runtime.public_release_gate_eligible -ne $false -or
        $Runtime.unsigned_local_candidate -ne $true -or
        [IO.Path]::GetFullPath([string]$Runtime.installed_gui_path) -cne
            [IO.Path]::GetFullPath($InstalledGui) -or
        [string]$Runtime.installed_gui_sha256 -notmatch '^[0-9a-f]{64}$' -or
        [IO.Path]::GetFullPath([string]$Runtime.installed_service_path) -cne
            [IO.Path]::GetFullPath((Join-Path $InstallRoot `
                'wins_vpn_tunnel_service.exe')) -or
        [string]$Runtime.installed_service_sha256 -notmatch '^[0-9a-f]{64}$' -or
        [IO.Path]::GetFullPath([string]$Runtime.installed_awg_engine_path) -cne
            [IO.Path]::GetFullPath($InstalledAwgEngine) -or
        [string]$Runtime.installed_awg_engine_sha256 -notmatch `
            '^[0-9a-f]{64}$' -or
        -not (Test-Path -LiteralPath $InstalledAwgEngine -PathType Leaf) -or
        ([string](Get-FileHash -LiteralPath $InstalledAwgEngine `
            -Algorithm SHA256).Hash).ToLowerInvariant() -cne `
            [string]$Runtime.installed_awg_engine_sha256 -or
        [int]$Runtime.candidate_pid -le 0) {
        throw 'Lab watchdog runtime context is invalid.'
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

Assert-SystemIdentity
Assert-CanonicalRunIdentity
Assert-NoReparsePath $RunRoot
foreach ($path in @($RunRoot, $PrivateRoot, $ReceiptRoot, $HelperRoot)) {
    Assert-OwnerOnlyAcl $path
}
$expectedSelf = Join-Path $HelperRoot 'windows_lab_safe_watchdog.ps1'
if ([IO.Path]::GetFullPath($PSCommandPath) -cne
    [IO.Path]::GetFullPath($expectedSelf)) {
    throw 'Lab watchdog must execute only from the locked helper root.'
}
$closure = (Read-JsonOnce (
    Join-Path $PrivateRoot 'collector-closure.json'
)).Json
if ($closure.contract -cne 'winsvpn-windows-lab-collector-closure-v1' -or
    $closure.sha256 -cne $CollectorClosureSha256) {
    throw 'Lab watchdog collector closure is invalid.'
}
$verifiedClosureSha256 = Assert-ExactHelperClosure $closure
if ($verifiedClosureSha256 -cne $CollectorClosureSha256) {
    throw 'Lab watchdog source is not bound to its full helper closure.'
}
$context = (Read-JsonOnce (Join-Path $PrivateRoot 'context.json')).Json
$runtime = (Read-JsonOnce (Join-Path $PrivateRoot 'runtime-context.json')).Json
$baseline = (Read-JsonOnce (
    (Join-Path $PrivateRoot 'baseline.json')
) 16777216).Json
$arm = (Read-JsonOnce (Join-Path $PrivateRoot 'arm.json')).Json
Assert-NonpublishableContext $context
Assert-RuntimeContext $runtime
if ($baseline.schema_version -ne 1 -or
    $baseline.contract -cne 'winsvpn-windows-lab-baseline-v1' -or
    $baseline.run_id -cne $RunId -or
    $baseline.collector_closure_sha256 -cne $CollectorClosureSha256 -or
    $baseline.evidence_class -cne 'nonpublishable_lab' -or
    $baseline.lab_only -ne $true -or
    $baseline.publication_authorized -ne $false -or
    $baseline.public_release_gate_eligible -ne $false -or
    $baseline.unsigned_local_candidate -ne $true -or
    [string]$baseline.state_sha256 -notmatch '^[0-9a-f]{64}$' -or
    [string]$baseline.egress_state_sha256 -notmatch '^[0-9a-f]{64}$' -or
    [string]$baseline.management_probe_host -notmatch
        '^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$' -or
    [int]$baseline.management_probe_port -notin 1..65535) {
    throw 'Lab watchdog baseline contract is invalid.'
}
if ($arm.schema_version -ne 1 -or
    $arm.contract -cne 'winsvpn-windows-lab-watchdog-arm-v1' -or
    $arm.run_id -cne $RunId -or
    $arm.collector_closure_sha256 -cne $CollectorClosureSha256 -or
    $arm.evidence_class -cne 'nonpublishable_lab' -or
    $arm.lab_only -ne $true -or
    $arm.publication_authorized -ne $false -or
    $arm.public_release_gate_eligible -ne $false -or
    $arm.unsigned_local_candidate -ne $true -or
    $arm.armed -ne $true -or
    [string]$arm.step_nonce -notmatch
        '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -or
    [int]$arm.sequence -lt 1) {
    throw 'Lab watchdog arm contract is invalid.'
}

# This proof is deliberately completed before watchdog-ready.json exists.
# A collector must not permit its first live transition until it validates the
# ready document and the exact baseline digest recorded here.
$readyStateSha256 = Get-CanonicalSha256 (Get-StateDocument)
$readyEgressSha256 = Get-EgressStateSha256
$installedXraySha256 = if (Test-Path -LiteralPath $InstalledXray -PathType Leaf) {
    (Get-FileHash -LiteralPath $InstalledXray -Algorithm SHA256).Hash.ToLowerInvariant()
} else { '' }
if ($installedXraySha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'Lab watchdog cannot bind the installed Xray recovery image.'
}
$readyDns = $null -ne (Resolve-DnsName winsvpn.org -Type A -DnsOnly `
    -QuickTimeout -ErrorAction SilentlyContinue)
$readyManagement = Test-NetConnection `
    -ComputerName ([string]$baseline.management_probe_host) `
    -Port ([int]$baseline.management_probe_port) -InformationLevel Quiet `
    -WarningAction SilentlyContinue
if ($readyStateSha256 -cne [string]$baseline.state_sha256 -or
    $readyEgressSha256 -cne [string]$baseline.egress_state_sha256 -or
    -not $readyDns -or -not $readyManagement) {
    throw 'Lab watchdog refused to arm away from its exact healthy baseline.'
}
$readyPath = Join-Path $PrivateRoot 'watchdog-ready.json'
Write-NewJson $readyPath ([ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-lab-watchdog-ready-v1'
    run_id = $RunId
    evidence_class = 'nonpublishable_lab'
    collector_closure_sha256 = $CollectorClosureSha256
    step_nonce = [string]$arm.step_nonce
    baseline_state_sha256 = [string]$baseline.state_sha256
    lab_only = $true
    publication_authorized = $false
    public_release_gate_eligible = $false
    unsigned_local_candidate = $true
    ready_at_utc = [DateTime]::UtcNow.ToString('o')
})

$started = [DateTime]::UtcNow
$deadline = $started.AddSeconds($DeadlineSeconds)
$normal = $false
$emergency = $false
$cleanupErrors = [Collections.Generic.List[string]]::new()
try {
    do {
        $disarmPath = Join-Path $PrivateRoot 'normal-disarm.json'
        if (Test-Path -LiteralPath $disarmPath -PathType Leaf) {
            try {
                $disarm = (Read-JsonOnce $disarmPath).Json
                $stateSha256 = Get-CanonicalSha256 (Get-StateDocument)
                if ($disarm.schema_version -eq 1 -and
                    $disarm.contract -ceq
                        'winsvpn-windows-lab-watchdog-disarm-v1' -and
                    $disarm.run_id -ceq $RunId -and
                    $disarm.collector_closure_sha256 -ceq
                        $CollectorClosureSha256 -and
                    $disarm.step_nonce -ceq [string]$arm.step_nonce -and
                    [int]$disarm.sequence -eq [int]$arm.sequence -and
                    $disarm.normal_teardown_proven -eq $true -and
                    $disarm.fail_safe_triggered -eq $false -and
                    $disarm.lab_only -eq $true -and
                    $disarm.publication_authorized -eq $false -and
                    $disarm.public_release_gate_eligible -eq $false -and
                    $disarm.baseline_state_sha256 -ceq
                        [string]$baseline.state_sha256 -and
                    $stateSha256 -ceq [string]$baseline.state_sha256) {
                    $normal = $true
                    break
                }
            } catch {}
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)

    if (-not $normal) {
        # Emergency cleanup is recovery evidence only and can never be a pass.
        $emergency = $true
        try {
            $runtime = (Read-JsonOnce (
                Join-Path $PrivateRoot 'runtime-context.json'
            )).Json
            Assert-RuntimeContext $runtime
        } catch {
            $cleanupErrors.Add("runtime_context: $($_.Exception.Message)")
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
            Invoke-CleanupStep 'lab_firewall_group' {
                Get-NetFirewallRule -Group $FirewallGroup `
                    -ErrorAction SilentlyContinue | Remove-NetFirewallRule `
                    -ErrorAction Stop
            } $cleanupErrors
            foreach ($serviceName in @(
                'WinsVPNSplitTunnel', 'AmneziaWGTunnel$winsvpn',
                'AmneziaWGTunnel$awg2'
            )) {
                Invoke-CleanupStep "service_$serviceName" {
                    Stop-Service -Name ([string]$serviceName) -Force `
                        -ErrorAction SilentlyContinue
                } $cleanupErrors
            }
            Get-Process xray -ErrorAction SilentlyContinue | ForEach-Object {
                $xrayProcess = $_
                if (Test-ExactImage -Pid $xrayProcess.Id `
                        -Path $InstalledXray -Sha256 $installedXraySha256) {
                    Invoke-CleanupStep "xray_$($xrayProcess.Id)" {
                        Stop-Process -Id $xrayProcess.Id -Force -ErrorAction Stop
                    } $cleanupErrors
                }
            }
            Get-Process winsvpn_awg_engine -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $awgProcess = $_
                    if (Test-ExactImage -Pid $awgProcess.Id `
                            -Path $InstalledAwgEngine `
                            -Sha256 ([string]$runtime.installed_awg_engine_sha256)) {
                        Invoke-CleanupStep "awg_engine_$($awgProcess.Id)" {
                            Stop-Process -Id $awgProcess.Id -Force -ErrorAction Stop
                        } $cleanupErrors
                    }
                }
            Invoke-CleanupStep 'manager_restart' {
                Restart-Service -Name 'WinsVpnTunnelManager' -Force `
                    -ErrorAction Stop
                (Get-Service -Name 'WinsVpnTunnelManager').WaitForStatus(
                    'Running', [TimeSpan]::FromSeconds(45)
                )
            } $cleanupErrors
        }
    }

    $finalStateSha256 = Get-CanonicalSha256 (Get-StateDocument)
    $finalDns = $null -ne (Resolve-DnsName winsvpn.org -Type A -DnsOnly `
        -QuickTimeout -ErrorAction SilentlyContinue)
    $finalManagement = Test-NetConnection `
        -ComputerName ([string]$baseline.management_probe_host) `
        -Port ([int]$baseline.management_probe_port) -InformationLevel Quiet `
        -WarningAction SilentlyContinue
    $finalEgressSha256 = Get-EgressStateSha256
    $finalAwgEngineAbsent = @(Get-Process winsvpn_awg_engine `
        -ErrorAction SilentlyContinue).Count -eq 0
    $pass = $normal -and -not $emergency -and
        $cleanupErrors.Count -eq 0 -and
        $finalAwgEngineAbsent -and
        $finalStateSha256 -ceq [string]$baseline.state_sha256 -and
        $finalDns -and $finalManagement -and
        $finalEgressSha256 -ceq [string]$baseline.egress_state_sha256
    $receipt = [ordered]@{
        schema_version = 1
        contract = 'winsvpn-windows-lab-watchdog-receipt-v1'
        run_id = $RunId
        captured_at_utc = [DateTime]::UtcNow.ToString('o')
        evidence_class = 'nonpublishable_lab'
        lab_only = $true
        publication_authorized = $false
        public_release_gate_eligible = $false
        unsigned_local_candidate = $true
        secret_material_redacted = $true
        collector_closure_sha256 = $CollectorClosureSha256
        artifact_sha256 = [string]$context.artifact_sha256
        payload_manifest_sha256 = [string]$context.payload_manifest_sha256
        step_nonce = [string]$arm.step_nonce
        sequence = [int]$arm.sequence
        started_at_utc = $started.ToString('o')
        finished_at_utc = [DateTime]::UtcNow.ToString('o')
        normal_teardown_proven = $normal
        fail_safe_triggered = $emergency
        cleanup_errors = @($cleanupErrors)
        baseline_state_sha256 = [string]$baseline.state_sha256
        final_state_sha256 = $finalStateSha256
        dns_restored = [bool]$finalDns
        lan_management_restored = [bool]$finalManagement
        egress_restored = $finalEgressSha256 -ceq
            [string]$baseline.egress_state_sha256
        awg_engine_absent = $finalAwgEngineAbsent
        pass = $pass
    }
    Write-NewJson (Join-Path $ReceiptRoot 'watchdog.json') $receipt
    if (-not $pass) {
        throw 'Lab watchdog did not observe natural teardown and exact baseline restoration.'
    }
} finally {
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false `
            -ErrorAction SilentlyContinue
    } catch {}
}
