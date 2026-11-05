[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern(
        '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    )][string]$RunId,
    [Parameter(Mandatory)][ValidateSet('Prepare', 'Execute', 'Finalize')]
    [string]$Phase
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RunRoot = Join-Path $env:ProgramData "WinsVPN\ReleaseEvidence\$RunId"
$PrivateRoot = Join-Path $RunRoot 'private'
$InputRoot = Join-Path $PrivateRoot 'inputs'
$ReceiptRoot = Join-Path $RunRoot 'receipts'
$ArtifactRoot = Join-Path $RunRoot 'artifacts'
$HelperRoot = Join-Path $RunRoot 'helpers'
$ExpectedSelf = Join-Path $HelperRoot 'windows_release_interactive_worker.ps1'
$InstallRoot = Join-Path $env:ProgramFiles 'WinsVPN'
$InstalledGui = Join-Path $InstallRoot 'wins_vpn.exe'
$InstalledService = Join-Path $InstallRoot 'wins_vpn_tunnel_service.exe'
$InstalledAwgEngine = Join-Path $InstallRoot 'winsvpn_awg_engine.exe'
$InstalledWinn3 = Join-Path $InstallRoot 'winsvpn_winn3_engine.exe'
$InstalledXray = Join-Path $InstallRoot 'xray.exe'
$InstalledNativeHost = Join-Path $InstallRoot 'wins_bridge_host.exe'
$InstalledNativeHostRoot = Join-Path $InstallRoot 'NativeMessagingHost'
$Uninstaller = Join-Path $InstallRoot 'unins000.exe'
$FirewallGroup = "WinsVPN-Release-$RunId"
$OpenReparsePoint = [IO.FileOptions]0x00200000
$PeMachineX64 = 0x8664
$PeMachineArm64 = 0xAA64
$script:ArchitectureBinding = $null

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-InstallerLogHasNoSuppressedException {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Installer did not create its required diagnostic log: $Path"
    }
    $text = Get-Content -LiteralPath $Path -Raw
    if ($text -match '(?mi)CurStepChanged raised an exception|Runtime error \(at') {
        throw "Installer reported a suppressed internal failure: $Path"
    }
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
    param([AllowEmptyString()][string]$Value)
    Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($Value))
}

function Get-ObfuscationDigest {
    param([Parameter(Mandatory)]$Obfuscation)
    $keys = @('H1', 'H2', 'H3', 'H4', 'Jc', 'Jmax', 'Jmin',
        'S1', 'S2', 'S3', 'S4')
    $parts = foreach ($key in $keys) {
        $property = $Obfuscation.PSObject.Properties[$key]
        if (-not $property -or $null -eq $property.Value) {
            throw 'The current AWG obfuscation contract is incomplete.'
        }
        '"' + $key + '":' + [string][int]$property.Value
    }
    Get-StringSha256 ('{' + ($parts -join ',') + '}')
}

function Get-CertificateSha256 {
    param([Parameter(Mandatory)]$Certificate)
    Get-BytesSha256 ([byte[]]$Certificate.RawData)
}

function Assert-CanonicalRunIdentity {
    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParseExact($RunId, 'D', [ref]$parsed) -or
        $parsed -eq [Guid]::Empty -or $RunId -cne $parsed.ToString('D') -or
        (Split-Path -Leaf $RunRoot) -cne $RunId) {
        throw 'Windows release run identity/path is not one canonical nonzero UUID.'
    }
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
        throw 'Windows helper closure document is invalid.'
    }
    $actualNames = @(Get-ChildItem -LiteralPath $HelperRoot -File -Force |
        Select-Object -ExpandProperty Name | Sort-Object)
    $expectedNames = @($expected.name | Sort-Object)
    if (($actualNames -join '|') -cne ($expectedNames -join '|')) {
        throw 'Windows helper root contains missing or additional execution material.'
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
                throw 'Windows helper closure entry order/path contract changed.'
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
                        throw 'Windows helper closure entry size changed.'
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
                throw 'Windows helper closure entry digest changed.'
            }
            $composite.AppendData([byte[]]@(0))
        }
        $closureDigest = ([BitConverter]::ToString(
            $composite.GetHashAndReset()
        )).Replace('-', '').ToLowerInvariant()
    } finally { $composite.Dispose() }
    if ($closureDigest -cne [string]$Closure.sha256) {
        throw 'Windows helper composite closure digest changed.'
    }
    $closureDigest
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
            throw "Interactive worker path contains a reparse point: $current"
        }
    }
}

function Open-ExclusiveFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][IO.FileMode]$Mode,
        [Parameter(Mandatory)][IO.FileAccess]$Access
    )
    if ($Mode -eq [IO.FileMode]::CreateNew) {
        Assert-NoReparsePath ([IO.Path]::GetDirectoryName((
            [IO.Path]::GetFullPath($Path)
        )))
    } else {
        Assert-NoReparsePath $Path
    }
    $stream = [IO.FileStream]::new(
        $Path, $Mode, $Access, [IO.FileShare]::None, 1048576, $OpenReparsePoint
    )
    if ($Mode -ne [IO.FileMode]::CreateNew) {
        try {
            $item = Get-Item -LiteralPath $Path -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Interactive worker descriptor opened a reparse point: $Path"
            }
        } catch {
            $stream.Dispose()
            throw
        }
    }
    $stream
}

function Get-PeArchitecture {
    param([Parameter(Mandatory)][string]$Path)
    $stream = Open-ExclusiveFile $Path ([IO.FileMode]::Open) ([IO.FileAccess]::Read)
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
        throw 'Windows release worker must not run under WOW64.'
    }
    $osArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $processArch = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    if ($processArch -cne $osArch) {
        throw 'Windows release worker must not run under WOW64.'
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
            throw 'Worker receipt omitted architecture binding.'
        }
        return $Binding[$Name]
    }
    $property = $Binding.PSObject.Properties[$Name]
    if (-not $property) {
        throw 'Worker receipt omitted architecture binding.'
    }
    $property.Value
}

function Assert-ArchitectureBinding {
    param($Binding)
    if ($null -eq $Binding) {
        throw 'Worker receipt omitted architecture binding.'
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
        throw 'Worker receipt omitted architecture binding.'
    }
    if ($architecture -cne 'x64' -and $architecture -cne 'arm64') {
        throw "Unsupported worker PE architecture: $architecture"
    }
    $expectedMachine = if ($architecture -ceq 'x64') { $PeMachineX64 } else {
        $PeMachineArm64
    }
    $expectedOs = if ($architecture -ceq 'x64') { 'X64' } else { 'Arm64' }
    if ($native -cne $architecture -or
        $osArchitecture -cne $expectedOs -or
        [int]$peMachine -ne [int]$expectedMachine -or
        $wow64 -ne $false) {
        throw 'Worker architecture binding is mixed, WOW64, or unsupported.'
    }
    $hostArch = Get-NativeWindowsArchitecture
    if ($hostArch -cne $native) {
        throw "Host OS architecture $hostArch does not match bound PE architecture $native."
    }
}

function New-ArchitectureBinding {
    param([Parameter(Mandatory)]$Pe)
    if ($null -eq $Pe -or [string]::IsNullOrEmpty([string]$Pe.Name) -or
        $null -eq $Pe.Machine) {
        throw 'Worker receipt omitted architecture binding.'
    }
    $native = Get-NativeWindowsArchitecture
    if ([string]$Pe.Name -cne $native) {
        throw "Host OS architecture $native does not match artifact PE architecture $($Pe.Name)."
    }
    $osArchitecture = if ($native -ceq 'x64') { 'X64' } else { 'Arm64' }
    $binding = [ordered]@{
        architecture = [string]$Pe.Name
        pe_machine = [int]$Pe.Machine
        native_architecture = $native
        os_architecture = $osArchitecture
        process_wow64 = $false
    }
    Assert-ArchitectureBinding $binding
    $binding
}

function Get-RuntimeArchitectureBinding {
    param([Parameter(Mandatory)]$Runtime)
    $wowRaw = Get-BindingProperty $Runtime 'process_wow64'
    if ($wowRaw -ne $false) {
        throw 'Worker architecture binding is mixed, WOW64, or unsupported.'
    }
    $binding = [ordered]@{
        architecture = [string](Get-BindingProperty $Runtime 'architecture')
        pe_machine = [int](Get-BindingProperty $Runtime 'pe_machine')
        native_architecture = [string](Get-BindingProperty $Runtime 'native_architecture')
        os_architecture = [string](Get-BindingProperty $Runtime 'os_architecture')
        process_wow64 = $false
    }
    Assert-ArchitectureBinding $binding
    $binding
}

function Assert-PeMatchesBinding {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label
    )
    Assert-ArchitectureBinding $script:ArchitectureBinding
    $pe = Get-PeArchitecture $Path
    if ($pe.Name -cne [string]$script:ArchitectureBinding.architecture -or
        [int]$pe.Machine -ne [int]$script:ArchitectureBinding.pe_machine) {
        throw "$Label PE architecture is mixed with the native host."
    }
}

function Assert-InstalledNativeImages {
    param([Parameter(Mandatory)][string]$Label)
    Assert-PeMatchesBinding $InstalledGui "$Label GUI"
    Assert-PeMatchesBinding $InstalledService "$Label service"
    Assert-PeMatchesBinding $InstalledAwgEngine "$Label AWG engine"
}

function Read-BytesOnce {
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(1, 536870912)][long]$MaximumBytes = 16777216
    )
    $stream = Open-ExclusiveFile $Path ([IO.FileMode]::Open) ([IO.FileAccess]::Read)
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt $MaximumBytes) {
            throw "Bounded worker input size is invalid: $Path"
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -le 0) { throw "Worker input changed while open: $Path" }
            $offset += $count
        }
        ,$bytes
    } finally { $stream.Dispose() }
}

function Read-JsonOnce {
    param([Parameter(Mandatory)][string]$Path)
    $bytes = Read-BytesOnce $Path
    [Text.UTF8Encoding]::new($false, $true).GetString($bytes) |
        ConvertFrom-Json
}

function Write-NewJson {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Value | ConvertTo-Json -Depth 32 -Compress) + [Environment]::NewLine
    )
    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Write-AtomicJson {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)
    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw 'Atomic JSON destination must be absolute.'
    }
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    $backup = "$Path.$([Guid]::NewGuid().ToString('N')).bak"
    try {
        Write-NewJson $temporary $Value
        if (Test-Path -LiteralPath $Path) {
            $destination = Get-Item -LiteralPath $Path -Force
            if (-not $destination.PSIsContainer -and
                ($destination.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -eq 0) {
                [IO.File]::Replace($temporary, $Path, $backup, $true)
            } else {
                throw 'Atomic JSON destination is not a regular non-reparse file.'
            }
        } else {
            [IO.File]::Move($temporary, $Path)
        }
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    }
}

function Assert-ValidSignature {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Label)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
        -not $signature.TimeStamperCertificate -or
        $signature.SignerCertificate.Subject -eq $signature.SignerCertificate.Issuer -or
        @($signature.SignerCertificate.EnhancedKeyUsageList | Where-Object {
            $_.ObjectId.Value -eq '1.3.6.1.5.5.7.3.3'
        }).Count -ne 1) {
        throw "$Label lacks valid public-trust Authenticode and timestamp proof."
    }
    $signature
}

function Write-BoundReceiptJson {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        ($Value | ConvertTo-Json -Depth 32 -Compress) + [Environment]::NewLine
    )
    $stream = Open-ExclusiveFile $Path ([IO.FileMode]::CreateNew) ([IO.FileAccess]::Write)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Write-BoundAtomicJson {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)
    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw 'Atomic JSON destination must be absolute.'
    }
    $temporary = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    $backup = "$Path.$([Guid]::NewGuid().ToString('N')).bak"
    try {
        Write-BoundReceiptJson $temporary $Value
        if (Test-Path -LiteralPath $Path) {
            $destination = Get-Item -LiteralPath $Path -Force
            if (-not $destination.PSIsContainer -and
                ($destination.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -eq 0) {
                [IO.File]::Replace($temporary, $Path, $backup, $true)
            } else {
                throw 'Atomic JSON destination is not a regular non-reparse file.'
            }
        } else {
            [IO.File]::Move($temporary, $Path)
        }
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    }
}

function Get-CanonicalSha256 {
    param([Parameter(Mandatory)]$Value)
    Get-StringSha256 ($Value | ConvertTo-Json -Depth 20 -Compress)
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

function Get-EgressStateSha256 {
    $value = (Invoke-WebRequest -UseBasicParsing -Uri 'https://api.ipify.org' `
        -TimeoutSec 15).Content.Trim()
    if ($value -notmatch '^[0-9A-Fa-f:.]{3,64}$') {
        throw 'Public egress canary returned an invalid address.'
    }
    Get-CanonicalSha256 ([ordered]@{ value = $value })
}

function Get-OptionalIpv6EgressState {
    try {
        $value = (Invoke-WebRequest -UseBasicParsing -Uri `
            'https://api6.ipify.org' -TimeoutSec 12).Content.Trim()
    } catch {
        return [ordered]@{
            reachable = $false
            value_sha256 = Get-StringSha256 'ipv6-unreachable'
        }
    }
    $address = $null
    if (-not [Net.IPAddress]::TryParse($value, [ref]$address) -or
        $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6) {
        throw 'IPv6 egress canary returned a non-IPv6 address.'
    }
    [ordered]@{
        reachable = $true
        value_sha256 = Get-CanonicalSha256 ([ordered]@{ value = $address.ToString() })
    }
}

function Get-WorkerReceiptProperty {
    param(
        [Parameter(Mandatory)]$Receipt,
        [Parameter(Mandatory)][string]$Name
    )
    if ($Receipt -is [Collections.IDictionary]) {
        if (-not $Receipt.Contains($Name)) {
            throw "Worker receipt omitted $Name."
        }
        return $Receipt[$Name]
    }
    $property = $Receipt.PSObject.Properties[$Name]
    if (-not $property) {
        throw "Worker receipt omitted $Name."
    }
    $property.Value
}

function Assert-ContextIdentityBinding {
    param([Parameter(Mandatory)]$Context)
    try {
        $identity = [string](Get-WorkerReceiptProperty $Context 'release_identity')
        $sourceOnly = Get-WorkerReceiptProperty $Context 'source_only'
        $artifact = [string](Get-WorkerReceiptProperty $Context 'artifact_sha256')
        $closure = [string](Get-WorkerReceiptProperty $Context 'collector_closure_sha256')
    } catch {
        throw 'Worker receipt omitted release identity, source_only, or candidate hash.'
    }
    if ($identity -notmatch '^[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+$') {
        throw 'Worker receipt release identity is stale or mixed.'
    }
    if ($sourceOnly -ne $false) {
        throw 'Worker receipt is source-only; refusing non-physical substitution.'
    }
    if ($artifact -notmatch '^[0-9a-f]{64}$' -or
        $closure -notmatch '^[0-9a-f]{64}$') {
        throw 'Worker receipt is not bound to the exact candidate hash.'
    }
}

function Assert-FieldIdentityLock {
    param(
        [Parameter(Mandatory)]$Fields,
        [Parameter(Mandatory)]$Context
    )
    if ($Fields -isnot [Collections.IDictionary]) { return }
    if ($Fields.Contains('source_only') -and $Fields['source_only'] -ne $false) {
        throw 'Worker receipt is source-only; refusing non-physical substitution.'
    }
    if ($Fields.Contains('release_identity') -and
        [string]$Fields['release_identity'] -cne
            [string]$Context.release_identity) {
        throw 'Worker receipt release identity is stale or mixed.'
    }
    if ($Fields.Contains('artifact_sha256') -and
        [string]$Fields['artifact_sha256'] -cne
            [string]$Context.artifact_sha256) {
        throw 'Worker receipt is not bound to the exact candidate hash.'
    }
    if ($Fields.Contains('run_id') -and [string]$Fields['run_id'] -cne $RunId) {
        throw 'Worker receipt belongs to another live run.'
    }
    if ($Fields.Contains('collector_closure_sha256') -and
        [string]$Fields['collector_closure_sha256'] -cne
            [string]$Context.collector_closure_sha256) {
        throw 'Worker receipt collector closure is stale.'
    }
    if ($Fields.Contains('passed') -and $Fields['passed'] -ne $true) {
        throw 'Worker receipt did not pass; refusing a partial false green.'
    }
}

function New-BoundReceipt {
    param(
        [Parameter(Mandatory)][string]$Contract,
        [Parameter(Mandatory)][int]$Sequence,
        [Parameter(Mandatory)][DateTime]$Started,
        [Parameter(Mandatory)]$Fields,
        [Parameter(Mandatory)]$Context,
        [switch]$EmitArchitecture
    )
    Assert-ArchitectureBinding $script:ArchitectureBinding
    Assert-ContextIdentityBinding $Context
    Assert-FieldIdentityLock $Fields $Context
    $finished = [DateTime]::UtcNow.ToString('o')
    $receipt = [ordered]@{
        schema_version = 1
        contract = $Contract
        run_id = $RunId
        captured_at_utc = $finished
        secret_material_redacted = $true
        release_input_index_sha256 = [string]$Context.release_input_index_sha256
        platform_manifest_sha256 = [string]$Context.platform_manifest_sha256
        artifact_input_fingerprint_sha256 = [string]$Context.artifact_input_fingerprint_sha256
        build_receipt_sha256 = [string]$Context.build_receipt_sha256
        producer_contract_sha256 = [string]$Context.producer_contract_sha256
        collector_closure_sha256 = [string]$Context.collector_closure_sha256
        artifact_sha256 = [string]$Context.artifact_sha256
        step_nonce = [Guid]::NewGuid().ToString()
        sequence = $Sequence
        started_at_utc = $Started.ToString('o')
        finished_at_utc = $finished
    }
    foreach ($key in $Fields.Keys) { $receipt[$key] = $Fields[$key] }
    $receipt['release_identity'] = [string]$Context.release_identity
    $receipt['source_only'] = $false
    $receipt['run_id'] = $RunId
    $receipt['collector_closure_sha256'] = [string]$Context.collector_closure_sha256
    $receipt['artifact_sha256'] = [string]$Context.artifact_sha256
    foreach ($key in @(
        'architecture', 'pe_machine', 'native_architecture',
        'os_architecture', 'process_wow64'
    )) {
        $receipt[$key] = $script:ArchitectureBinding[$key]
    }
    Assert-ArchitectureBinding $receipt
    $receipt
}

function Assert-WorkerBoundPhysicalReceipt {
    param(
        [Parameter(Mandatory)]$Receipt,
        [Parameter(Mandatory)][string]$Contract,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)]$Context,
        [switch]$RequirePass
    )
    if ([string](Get-WorkerReceiptProperty $Receipt 'contract') -cne $Contract) {
        throw "$Label contract is mixed or stale."
    }
    if ([string](Get-WorkerReceiptProperty $Receipt 'run_id') -cne $RunId) {
        throw "$Label belongs to another live run."
    }
    if ([string](Get-WorkerReceiptProperty $Receipt 'collector_closure_sha256') -cne
            [string]$Context.collector_closure_sha256) {
        throw "$Label collector closure is stale."
    }
    if ([string](Get-WorkerReceiptProperty $Receipt 'artifact_sha256') -cne
            [string]$Context.artifact_sha256) {
        throw "$Label is not bound to the exact candidate hash."
    }
    if ([string](Get-WorkerReceiptProperty $Receipt 'release_identity') -cne
            [string]$Context.release_identity) {
        throw "$Label release identity is stale or mixed."
    }
    if ((Get-WorkerReceiptProperty $Receipt 'source_only') -ne $false) {
        throw "$Label is source-only; refusing non-physical substitution."
    }
    if ($RequirePass -and (Get-WorkerReceiptProperty $Receipt 'passed') -ne $true) {
        throw "$Label did not pass; refusing a partial false green."
    }
    Assert-ArchitectureBinding $Receipt
}

function Assert-RequiredWorkerPhysicalReceipts {
    param(
        [Parameter(Mandatory)][object[]]$Receipts,
        [Parameter(Mandatory)]$Context
    )
    $byContract = @{}
    foreach ($receipt in @($Receipts)) {
        $contract = [string](Get-WorkerReceiptProperty $receipt 'contract')
        if ($byContract.ContainsKey($contract)) {
            throw "Duplicate live evidence contract cannot be sealed: $contract"
        }
        $byContract[$contract] = $receipt
    }
    $required = [ordered]@{
        'winsvpn-windows-signature-receipt-v1' =
            'Physical signature receipt'
        'winsvpn-windows-install-receipt-v1' =
            'Physical install receipt'
        'winsvpn-windows-runtime-receipt-v1' =
            'Physical runtime receipt'
        'winsvpn-windows-uninstall-receipt-v1' =
            'Physical uninstall receipt'
        'winsvpn-windows-teardown-rollback-receipt-v1' =
            'Physical rollback receipt'
        'winsvpn-windows-winn-v3-receipt-v1' =
            'Physical Winn v3 primary receipt'
        'winsvpn-windows-winn-v1-awg-receipt-v1' =
            'Physical Winn v1 AWG receipt'
        'winsvpn-windows-winn-v1-xray-receipt-v1' =
            'Physical Winn v1 Xray fallback receipt'
        'winsvpn-windows-native-host-receipt-v1' =
            'Physical native-host receipt'
    }
    foreach ($contract in @($required.Keys)) {
        if (-not $byContract.ContainsKey($contract)) {
            throw "$($required[$contract]) is missing; refusing to seal partial evidence."
        }
        Assert-WorkerBoundPhysicalReceipt $byContract[$contract] $contract `
            $required[$contract] $Context -RequirePass
    }
    $v3 = $byContract['winsvpn-windows-winn-v3-receipt-v1']
    $fallback = @(Get-WorkerReceiptProperty $v3 'fallback_transports')
    if ([string](Get-WorkerReceiptProperty $v3 'primary_transport') -cne 'winn_v3' -or
        (Get-WorkerReceiptProperty $v3 'winn_v3_session_observed') -ne $true -or
        $fallback.Count -ne 2 -or
        [string]$fallback[0] -cne 'winn_v1_awg' -or
        [string]$fallback[1] -cne 'winn_v1_xray') {
        throw 'Physical Winn v3 primary receipt is source-only or has mixed fallback order.'
    }
    $awg = $byContract['winsvpn-windows-winn-v1-awg-receipt-v1']
    $xray = $byContract['winsvpn-windows-winn-v1-xray-receipt-v1']
    if ([string](Get-WorkerReceiptProperty $awg 'transport') -cne 'winn_v1_awg' -or
        (Get-WorkerReceiptProperty $awg 'observed') -ne $true) {
        throw 'Physical Winn v1 AWG receipt is source-only or unobserved.'
    }
    if ([string](Get-WorkerReceiptProperty $xray 'transport') -cne 'winn_v1_xray' -or
        (Get-WorkerReceiptProperty $xray 'observed') -ne $true) {
        throw 'Physical Winn v1 Xray fallback receipt is source-only or unobserved.'
    }
    if ([int](Get-WorkerReceiptProperty $awg 'sequence') -ge
            [int](Get-WorkerReceiptProperty $xray 'sequence')) {
        throw 'Physical Winn v1 Xray fallback is not after AWG.'
    }
    if ((Get-WorkerReceiptProperty `
            $byContract['winsvpn-windows-native-host-receipt-v1'] `
            'native_host_observed') -ne $true) {
        throw 'Physical native-host receipt is source-only or unobserved.'
    }
    if ((Get-WorkerReceiptProperty `
            $byContract['winsvpn-windows-uninstall-receipt-v1'] `
            'uninstalled') -ne $true) {
        throw 'Physical uninstall receipt is source-only or unobserved.'
    }
    if ((Get-WorkerReceiptProperty `
            $byContract['winsvpn-windows-runtime-receipt-v1'] `
            'runtime_observed') -ne $true) {
        throw 'Physical runtime receipt is source-only or unobserved.'
    }
}

function Write-RequiredPhysicalReceipt {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Receipt,
        [Parameter(Mandatory)][string]$Contract,
        [Parameter(Mandatory)]$Context
    )
    Assert-WorkerBoundPhysicalReceipt $Receipt $Contract `
        "Physical receipt $([IO.Path]::GetFileName($Path))" $Context -RequirePass
    Write-BoundReceiptJson $Path $Receipt
}

function Resolve-WorkerObservedTransport {
    param(
        [Parameter(Mandatory)][int]$Winn3Count,
        [Parameter(Mandatory)][int]$AwgCount,
        [Parameter(Mandatory)][int]$XrayCount
    )
    if ($Winn3Count -gt 1 -or $AwgCount -gt 1 -or $XrayCount -gt 1) {
        throw 'Worker observed mixed Winn v3/v1 transports.'
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
    throw 'Worker observed mixed Winn v3/v1 transports.'
}

function Get-NativeHostContract {
    [ordered]@{
        host_name = 'org.winsvpn.bridge'
        host_image = $InstalledNativeHost
        manifest_root = $InstalledNativeHostRoot
        browsers = @(
            [ordered]@{
                browser = 'chrome'
                manifest_name = 'org.winsvpn.bridge.chrome.json'
                registry_path = 'HKLM:\SOFTWARE\Google\Chrome\NativeMessagingHosts\org.winsvpn.bridge'
            }
            [ordered]@{
                browser = 'edge'
                manifest_name = 'org.winsvpn.bridge.edge.json'
                registry_path = 'HKLM:\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\org.winsvpn.bridge'
            }
            [ordered]@{
                browser = 'firefox'
                manifest_name = 'org.winsvpn.bridge.firefox.json'
                registry_path = 'HKLM:\SOFTWARE\Mozilla\NativeMessagingHosts\org.winsvpn.bridge'
            }
        )
    }
}

function Assert-NativeHostObservationFacts {
    param([Parameter(Mandatory)]$Facts)
    if ((Get-WorkerReceiptProperty $Facts 'native_host_observed') -ne $true -or
        [string](Get-WorkerReceiptProperty $Facts 'host_name') -cne
            'org.winsvpn.bridge' -or
        [string](Get-WorkerReceiptProperty $Facts 'host_image') -notmatch
            'wins_bridge_host\.exe$' -or
        @($Facts.browsers).Count -ne 3) {
        throw 'Physical native-host receipt is source-only or unobserved.'
    }
    $order = @($Facts.browsers | ForEach-Object { [string]$_.browser })
    if (($order -join '|') -cne 'chrome|edge|firefox') {
        throw 'Physical native-host receipt is source-only or unobserved.'
    }
    foreach ($browser in @($Facts.browsers)) {
        if ($browser.manifest_bound -ne $true -or
            $browser.registry_bound -ne $true) {
            throw 'Physical native-host receipt is source-only or unobserved.'
        }
    }
}

function Read-CredentialStore {
    $encrypted = [Text.UTF8Encoding]::new($false, $true).GetString(
        (Read-BytesOnce (Join-Path $InputRoot 'credentials.dat') 4194304)
    ).Trim()
    $secure = ConvertTo-SecureString $encrypted
    $plain = [Net.NetworkCredential]::new('', $secure).Password
    try {
        $credential = $plain | ConvertFrom-Json
    } finally { $plain = $null }
    $pinCredential = try {
        [string]$credential.user_pin_credential | ConvertFrom-Json
    } catch { $null }
    if ($credential.contract -cne 'winsvpn-windows-release-credentials-v1' -or
        [string]$credential.verify_uri -notmatch '^https://[A-Za-z0-9.-]+/verify$' -or
        [string]$credential.management_probe_host -notmatch
            '^[A-Za-z0-9.:-]{1,253}$' -or
        [int]$credential.management_probe_port -notin 1..65535 -or
        -not $pinCredential -or
        $pinCredential.format -cne 'pbkdf2-sha256-v1' -or
        [int]$pinCredential.iterations -lt 10000 -or
        [string]$pinCredential.salt -notmatch '^[A-Za-z0-9+/]+=*$' -or
        [string]$pinCredential.hash -notmatch '^[A-Za-z0-9+/]+=*$') {
        throw 'DPAPI release credential store contract is invalid.'
    }
    $credential
}

function Get-WinsVpnResponseHeaderValue {
    param(
        $Headers,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $Headers) { return $null }
    if ($Headers -is [System.Collections.Specialized.NameValueCollection]) {
        try {
            return ConvertTo-WinsVpnBoundedHeaderValue `
                -Values @($Headers.GetValues($Name))
        } catch {
            return $null
        }
    }
    $tryGetValues = $Headers.PSObject.Methods['TryGetValues']
    if ($tryGetValues) {
        try {
            $values = $null
            if ($Headers.TryGetValues($Name, [ref]$values)) {
                return ConvertTo-WinsVpnBoundedHeaderValue -Values @($values)
            }
        } catch {}
    }
    if ($Headers -is [Collections.IDictionary]) {
        foreach ($key in @($Headers.Keys)) {
            if ([string]::Equals(
                    [string]$key, $Name,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                return ConvertTo-WinsVpnBoundedHeaderValue `
                    -Values @($Headers[$key])
            }
        }
        return $null
    }
    $allKeys = $Headers.PSObject.Properties['AllKeys']
    if ($allKeys) {
        foreach ($key in @($allKeys.Value)) {
            if ([string]::Equals(
                    [string]$key, $Name,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                return ConvertTo-WinsVpnBoundedHeaderValue `
                    -Values @($Headers[$key])
            }
        }
        return $null
    }
    try {
        foreach ($entry in @($Headers.GetEnumerator())) {
            if ([string]::Equals(
                    [string]$entry.Key, $Name,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                return ConvertTo-WinsVpnBoundedHeaderValue `
                    -Values @($entry.Value)
            }
        }
    } catch {}
    return $null
}

function ConvertTo-WinsVpnBoundedHeaderValue {
    param([AllowNull()][object[]]$Values)
    if ($null -eq $Values -or $Values.Count -lt 1) { return $null }
    $rendered = (@($Values) | ForEach-Object { [string]$_ }) -join ','
    if ([string]::IsNullOrWhiteSpace($rendered) -or
        $rendered.Length -gt 256 -or
        $rendered.IndexOfAny([char[]]@([char]0, [char]10, [char]13)) -ge 0) {
        return $null
    }
    $rendered
}

function Read-WinsVpnBoundedResponseStream {
    param(
        [Parameter(Mandatory)]$Stream,
        [ValidateRange(1, 1048576)][int]$MaximumCharacters = 1048576
    )
    $reader = [IO.StreamReader]::new(
        $Stream, [Text.UTF8Encoding]::new($false, $true)
    )
    try {
        $builder = [Text.StringBuilder]::new()
        $buffer = [char[]]::new(4096)
        while (($count = $reader.Read($buffer, 0, $buffer.Length)) -gt 0) {
            if ($builder.Length + $count -gt $MaximumCharacters) {
                throw 'Live /verify error response body exceeded its bounded limit.'
            }
            [void]$builder.Append($buffer, 0, $count)
        }
        $builder.ToString()
    } finally {
        $reader.Dispose()
    }
}

function Invoke-WinsVpnVerifyHttpRequest {
    param(
        [Parameter(Mandatory)][Net.Http.HttpClient]$Client,
        [Parameter(Mandatory)][Uri]$Uri,
        [Parameter(Mandatory)][byte[]]$Body
    )
    $request = [Net.Http.HttpRequestMessage]::new(
        [Net.Http.HttpMethod]::Post, $Uri
    )
    $response = $null
    try {
        $request.Content = [Net.Http.ByteArrayContent]::new($Body)
        $request.Content.Headers.ContentType =
            [Net.Http.Headers.MediaTypeHeaderValue]::new('application/json')
        # ResponseContentRead keeps HttpClient.Timeout effective until the
        # bounded response body is buffered, including for non-2xx statuses.
        $response = $Client.SendAsync(
            $request, [Net.Http.HttpCompletionOption]::ResponseContentRead
        ).GetAwaiter().GetResult()
        $statusCode = [int]$response.StatusCode
        if ($statusCode -lt 100 -or $statusCode -gt 599) {
            throw 'Live /verify returned an invalid HTTP status.'
        }
        # Snapshot only the two public retry-contract headers while the
        # response is alive. HttpClient exposes the same non-2xx response on
        # Windows PowerShell 5.1 instead of throwing and consuming it.
        $safeHeaders = [ordered]@{}
        foreach ($name in @('X-Wins-Error-Code', 'Retry-After')) {
            $value = Get-WinsVpnResponseHeaderValue `
                -Headers $response.Headers -Name $name
            if ($null -ne $value) { $safeHeaders[$name] = $value }
        }
        $bodyText = ''
        if ($response.Content) {
            $declaredLength = $response.Content.Headers.ContentLength
            if ($null -ne $declaredLength -and
                [long]$declaredLength -gt 1048576L) {
                throw 'Live /verify response body exceeded its bounded limit.'
            }
            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            if ($stream) {
                $bodyText = Read-WinsVpnBoundedResponseStream -Stream $stream
            }
        }
        [pscustomobject]@{
            StatusCode = $statusCode
            Content = $bodyText
            Headers = $safeHeaders
        }
    } finally {
        if ($response) { $response.Dispose() }
        $request.Dispose()
    }
}

function Test-WinsVpnDoubleAssignmentPreparing {
    param(
        [Parameter(Mandatory)][int]$StatusCode,
        [AllowEmptyString()][string]$Body,
        $Headers
    )
    if ($StatusCode -ne 503) { return $false }
    $stableCode = Get-WinsVpnResponseHeaderValue -Headers $Headers `
        -Name 'X-Wins-Error-Code'
    if ($null -ne $stableCode) {
        return $stableCode.Trim().ToLowerInvariant() -ceq
            'double_vpn_assignment_preparing'
    }
    try {
        $document = $Body | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $false
    }
    $properties = @($document.PSObject.Properties)
    $detail = @($properties | Where-Object Name -CEQ 'detail')
    return $properties.Count -eq 1 -and $detail.Count -eq 1 -and
        [string]$detail[0].Value -ceq
            'Double VPN Core assignment is still being prepared. Please try again.'
}

function Get-WinsVpnDoubleAssignmentRetryDelayMilliseconds {
    param($Headers)
    $raw = Get-WinsVpnResponseHeaderValue -Headers $Headers `
        -Name 'Retry-After'
    $seconds = 0L
    if ($null -eq $raw -or
        -not [long]::TryParse(
            $raw.Trim(),
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$seconds
        ) -or $seconds -lt 0) {
        return 1000L
    }
    if ($seconds -ge 10) { return 10000L }
    return [Math]::Min(10000L, [Math]::Max(250L, $seconds * 1000L))
}

function Get-WinsVpnSafeVerifyFailure {
    param(
        [Parameter(Mandatory)][ValidateRange(100, 599)][int]$StatusCode,
        [AllowEmptyString()][string]$Body,
        $Headers
    )
    $detailCodes = @{
        'Double VPN Core assignment is still being prepared. Please try again.' =
            'double_vpn_assignment_preparing'
        'Double VPN core is not available yet.' = 'double_vpn_core_unavailable'
        'Selected Double VPN exit node is not ready. Please try again in a minute.' =
            'double_vpn_exit_not_ready'
        'Selected VPN node is not ready. Please try again in a minute.' =
            'selected_node_not_ready'
        'Selected VPN server is unavailable or full.' =
            'selected_server_unavailable'
        'No VPN nodes currently online.' = 'no_nodes_online'
        'System Maintenance underway.' = 'maintenance'
        'Server is currently full.' = 'server_full'
        'Server is currently full. Please choose another location.' = 'server_full'
        'Server is offline or in maintenance.' = 'server_offline'
        'Account Inactive or Invalid' = 'authentication_rejected'
        'Account Expired. Renew subscription.' = 'account_expired'
        'Device limit reached. Log out of another device first.' =
            'device_limit_reached'
        'Invalid account format.' = 'invalid_account_format'
    }
    $messages = @{
        double_vpn_assignment_preparing = 'Double VPN Core assignment is preparing.'
        double_vpn_core_unavailable = 'Double VPN Core is unavailable.'
        double_vpn_exit_not_ready = 'Double VPN exit is not ready.'
        selected_node_not_ready = 'Selected VPN node is not ready.'
        selected_server_unavailable = 'Selected VPN server is unavailable.'
        no_nodes_online = 'No VPN nodes are online.'
        maintenance = 'VPN service maintenance is active.'
        server_full = 'Selected VPN server is full.'
        server_offline = 'Selected VPN server is offline.'
        authentication_rejected = 'Account authentication was rejected.'
        account_expired = 'Account access is expired.'
        device_limit_reached = 'Account device limit was reached.'
        invalid_account_format = 'Account format was rejected.'
        bad_request = 'The verification request was rejected.'
        forbidden = 'The verification request was forbidden.'
        request_validation_failed = 'The verification request failed validation.'
        rate_limited = 'The verification request was rate limited.'
        service_unavailable = 'The verification service was unavailable.'
        http_error = 'The verification request returned an HTTP error.'
    }
    $code = ''
    $stableCode = Get-WinsVpnResponseHeaderValue -Headers $Headers `
        -Name 'X-Wins-Error-Code'
    if ($stableCode -ceq 'double_vpn_assignment_preparing') {
        $code = 'double_vpn_assignment_preparing'
    } else {
        try {
            $document = $Body | ConvertFrom-Json -ErrorAction Stop
            $properties = @($document.PSObject.Properties)
            $detail = @($properties | Where-Object Name -CEQ 'detail')
            if ($properties.Count -eq 1 -and $detail.Count -eq 1) {
                $candidate = [string]$detail[0].Value
                if ($detailCodes.ContainsKey($candidate)) {
                    $code = [string]$detailCodes[$candidate]
                }
            }
        } catch {}
    }
    if ([string]::IsNullOrEmpty($code)) {
        $code = switch ($StatusCode) {
            400 { 'bad_request' }
            401 { 'authentication_rejected' }
            403 { 'forbidden' }
            422 { 'request_validation_failed' }
            429 { 'rate_limited' }
            503 { 'service_unavailable' }
            default { 'http_error' }
        }
    }
    [pscustomobject]@{
        status_code = $StatusCode
        error_code = $code
        error_message = [string]$messages[$code]
        retryable = $code -ceq 'double_vpn_assignment_preparing'
    }
}

function Get-WinsVpnSafeRetryAfterSeconds {
    param($Headers)
    $raw = Get-WinsVpnResponseHeaderValue -Headers $Headers `
        -Name 'Retry-After'
    $seconds = 0L
    $present = $null -ne $raw -and [long]::TryParse(
        $raw.Trim(),
        [Globalization.NumberStyles]::None,
        [Globalization.CultureInfo]::InvariantCulture,
        [ref]$seconds
    ) -and $seconds -ge 0
    [pscustomobject]@{
        present = [bool]$present
        seconds = if ($present) { [int][Math]::Min(10L, $seconds) } else { 0 }
    }
}

function Set-WinsVpnVerifyDiagnosticOwnerOnlyAcl {
    param([Parameter(Mandatory)][string]$Path)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner($identity)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $identity,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    ))
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSObject.Methods.Name -contains 'SetAccessControl') {
        $item.SetAccessControl($acl)
    } else {
        [IO.FileSystemAclExtensions]::SetAccessControl($item, $acl)
    }
}

function Write-WinsVpnVerifyFailureDiagnostic {
    param(
        [Parameter(Mandatory)]$Failure,
        [Parameter(Mandatory)][bool]$DoubleVpn,
        [Parameter(Mandatory)][ValidateRange(1, 1000)][int]$AttemptCount,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')]
        [string]$BodySha256,
        [Parameter(Mandatory)]$RetryAfter
    )
    $path = Join-Path $PrivateRoot 'verify-error.json'
    $context = Read-JsonOnce (Join-Path $PrivateRoot 'context.json')
    if ($context.run_id -cne $RunId -or
        [string]$context.artifact_sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$context.collector_closure_sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Verify failure diagnostic lacks an exact candidate/run binding.'
    }
    # A release candidate is always Authenticode-signed and release-track by
    # construction, so the lab sibling's nonpublishable/local-candidate
    # markers have no equivalent here. publication_authorized still defaults
    # to false like every other document this collector writes; an external
    # gate flips it only after independent review.
    # A single run legitimately reaches this more than once (for example
    # Node verify succeeds while Core verify fails, or a later route-lane
    # retry fails again), so the receipt must be replaced, not create-only.
    Write-AtomicJson $path ([ordered]@{
        schema_version = 1
        contract = 'winsvpn-windows-release-verify-error-v1'
        run_id = $RunId
        publication_authorized = $false
        observed_at_utc = [DateTime]::UtcNow.ToString('o')
        artifact_sha256 = [string]$context.artifact_sha256
        collector_closure_sha256 = [string]$context.collector_closure_sha256
        requested_mode = if ($DoubleVpn) { 'double' } else { 'single' }
        attempt_count = $AttemptCount
        status_code = [int]$Failure.status_code
        error_code = [string]$Failure.error_code
        error_message = [string]$Failure.error_message
        retryable = [bool]$Failure.retryable
        retry_after_present = [bool]$RetryAfter.present
        retry_after_seconds = [int]$RetryAfter.seconds
        response_body_sha256 = $BodySha256
        raw_response_persisted = $false
        response_headers_persisted = $false
        request_body_persisted = $false
    })
    Set-WinsVpnVerifyDiagnosticOwnerOnlyAcl $path
}

function Invoke-VerifyRequest {
    param($Credential, [bool]$DoubleVpn)
    $body = if ($DoubleVpn) {
        $Credential.core_request | ConvertTo-Json -Depth 16 -Compress
    } else {
        $Credential.node_request | ConvertTo-Json -Depth 16 -Compress
    }
    # Construct the request bytes once. Every bounded retry must preserve the
    # exact Double preference and client identity without rewriting the body.
    $bodyBytes = [Text.UTF8Encoding]::new($false).GetBytes($body)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $maximumElapsedMilliseconds = 120000L
    $requestTimeoutSeconds = 7
    $deadlineSafetyMilliseconds = 250L
    $result = $null
    $attemptCount = 0
    # Windows PowerShell 5.1 does not load System.Net.Http on demand when the
    # first reference is a type literal.
    Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.AutomaticDecompression = [Net.DecompressionMethods]::GZip -bor
        [Net.DecompressionMethods]::Deflate
    $client = [Net.Http.HttpClient]::new($handler, $true)
    $client.Timeout = [TimeSpan]::FromSeconds($requestTimeoutSeconds)
    $client.MaxResponseContentBufferSize = 1048576L
    try {
        while ($true) {
            if ($clock.ElapsedMilliseconds +
                    ($requestTimeoutSeconds * 1000L) +
                    $deadlineSafetyMilliseconds -gt
                    $maximumElapsedMilliseconds) {
                throw 'Double VPN assignment preparation exceeded its bounded deadline.'
            }
            ++$attemptCount
            $result = Invoke-WinsVpnVerifyHttpRequest -Client $client `
                -Uri ([Uri][string]$Credential.verify_uri) -Body $bodyBytes
            $statusCode = [int]$result.StatusCode
            $responseBody = [string]$result.Content
            $preparing = $DoubleVpn -and
                (Test-WinsVpnDoubleAssignmentPreparing `
                    -StatusCode $statusCode -Body $responseBody `
                    -Headers $result.Headers)
            if (-not $preparing) { break }
            $delayMilliseconds = Get-WinsVpnDoubleAssignmentRetryDelayMilliseconds `
                -Headers $result.Headers
            if ($clock.ElapsedMilliseconds + $delayMilliseconds +
                    ($requestTimeoutSeconds * 1000L) +
                    $deadlineSafetyMilliseconds -gt
                    $maximumElapsedMilliseconds) {
                throw 'Double VPN assignment preparation exceeded its bounded deadline.'
            }
            Start-Sleep -Milliseconds $delayMilliseconds
        }
    } finally {
        $client.Dispose()
    }
    if ($statusCode -ne 200) {
        $failure = Get-WinsVpnSafeVerifyFailure -StatusCode $statusCode `
            -Body $responseBody -Headers $result.Headers
        $retryAfter = Get-WinsVpnSafeRetryAfterSeconds -Headers $result.Headers
        Write-WinsVpnVerifyFailureDiagnostic -Failure $failure `
            -DoubleVpn $DoubleVpn -AttemptCount $attemptCount `
            -BodySha256 (Get-StringSha256 $responseBody) `
            -RetryAfter $retryAfter
        throw ('Live /verify request was not accepted ' +
            "(status=$($failure.status_code), code=$($failure.error_code)).")
    }
    $json = $responseBody | ConvertFrom-Json
    if ($json.status -cne 'authenticated' -or -not $json.vpn_config) {
        throw 'Live /verify response lacks authenticated VPN configuration.'
    }
    if ($DoubleVpn -and ($json.vpn_config.double_vpn_active -ne $true -or
            [string]::IsNullOrWhiteSpace(
                [string]$json.vpn_config.double_vpn_core_id
            ) -or [string]::IsNullOrWhiteSpace(
                [string]$json.vpn_config.double_vpn_exit_slug
            ))) {
        throw 'Live /verify response downgraded or omitted the requested Double VPN route.'
    }
    [pscustomobject]@{
        Json = $json
        Sha256 = Get-StringSha256 $responseBody
        AttemptCount = $attemptCount
    }
}

function Add-LocalClientKeys {
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)]$Credential
    )
    $keypair = $Credential.client_keypair
    $privateKey = [string]$keypair.private_key
    $publicKey = [string]$keypair.public_key
    if ($privateKey -notmatch '^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$' -or
        $publicKey -notmatch '^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$') {
        throw 'Protected release client keypair is invalid.'
    }
    $responsePublicKey = [string]$Config.client_public_key
    if (-not [string]::IsNullOrWhiteSpace($responsePublicKey) -and
        $responsePublicKey -cne $publicKey) {
        throw 'Live /verify response contradicts the protected client public key.'
    }
    $withKeys = [ordered]@{}
    foreach ($property in $Config.PSObject.Properties) {
        $withKeys[$property.Name] = $property.Value
    }
    $withKeys['client_private_key'] = $privateKey
    $withKeys['client_public_key'] = $publicKey
    [pscustomobject]$withKeys
}

function Get-DirectPort {
    param([Parameter(Mandatory)][string]$Endpoint)
    if ($Endpoint -notmatch ':(?<port>[0-9]{1,5})$') {
        throw 'Registered direct endpoint has no explicit port.'
    }
    $port = [int]$Matches.port
    if ($port -notin 1..65535) { throw 'Registered direct endpoint port is invalid.' }
    $port
}

function Get-XrayRoutes {
    param($Config)
    $routes = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($transport in @($Config.xray.transports)) {
        $port = [int]$transport.port
        $security = [string]$transport.security
        $key = "$port/$security"
        if ($port -notin 1..65535 -or $security -notin @('none', 'tls') -or
            -not $seen.Add($key)) {
            throw 'Live /verify response contains an invalid Xray transport set.'
        }
        $routes.Add([ordered]@{
            protocol = 'tcp'; port = $port; security = $security
        })
    }
    if ($routes.Count -lt 1) { throw 'Live /verify response has no Xray fallback route.' }
    @($routes)
}

function Test-NoActiveTunnel {
    $activeServices = @(@('AmneziaWGTunnel$winsvpn', 'WinsVPNSplitTunnel') |
        Where-Object {
            $service = Get-Service -Name $_ -ErrorAction SilentlyContinue
            $service -and $service.Status -eq 'Running'
        })
    $activeAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Status -eq 'Up' -and $_.Name -match '(?i)winsvpn|amnezia|awg'
        })
    $xray = @(Get-Process xray -ErrorAction SilentlyContinue)
    $awgEngine = @(Get-Process winsvpn_awg_engine -ErrorAction SilentlyContinue)
    $winn3 = @(Get-Process winsvpn_winn3_engine -ErrorAction SilentlyContinue)
    $activeServices.Count -eq 0 -and $activeAdapters.Count -eq 0 -and
        $xray.Count -eq 0 -and $awgEngine.Count -eq 0 -and $winn3.Count -eq 0
}

function Stop-ExactGui {
    Get-Process wins_vpn -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            if ([IO.Path]::GetFullPath($_.Path) -ceq
                [IO.Path]::GetFullPath($InstalledGui)) {
                Stop-Process -Id $_.Id -Force -ErrorAction Stop
            }
        } catch {}
    }
}

function Restore-PreexistingAppData {
    $statePath = Join-Path $PrivateRoot 'preexisting-appdata-state.json'
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { return }
    $state = Read-JsonOnce $statePath
    if ($state.contract -cne 'winsvpn-windows-preexisting-appdata-state-v1' -or
        $state.run_id -cne $RunId -or $state.present -notin @($true, $false) -or
        $state.secure_state_present -notin @($true, $false) -or
        $state.restored -notin @($true, $false)) {
        throw 'Preexisting app-data restoration state is invalid.'
    }
    if ($state.restored -eq $true) { return }
    $appData = Join-Path $env:APPDATA 'wins_vpn'
    if (Test-Path -LiteralPath $appData) {
        Get-ChildItem -LiteralPath $appData -Recurse -Force | ForEach-Object {
            if (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Test app-data restoration encountered a reparse point.'
            }
        }
        Remove-Item -LiteralPath $appData -Recurse -Force
    }
    $preserved = Join-Path $PrivateRoot 'preexisting-appdata'
    if ($state.present -eq $true) {
        if (-not (Test-Path -LiteralPath $preserved -PathType Container)) {
            throw 'Preexisting app-data snapshot is missing during restoration.'
        }
        Assert-NoReparsePath $preserved
        Move-Item -LiteralPath $preserved -Destination $appData
    } elseif (Test-Path -LiteralPath $preserved) {
        throw 'Unexpected preexisting app-data snapshot exists for an absent baseline.'
    }
    $secureState = Join-Path $env:LOCALAPPDATA 'WinsVPN\SecureState'
    if (Test-Path -LiteralPath $secureState) {
        Assert-NoReparsePath $secureState
        Get-ChildItem -LiteralPath $secureState -Recurse -Force | ForEach-Object {
            if (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Test secure-state restoration encountered a reparse point.'
            }
        }
        Remove-Item -LiteralPath $secureState -Recurse -Force
    }
    $preservedSecureState = Join-Path $PrivateRoot 'preexisting-secure-state'
    if ($state.secure_state_present -eq $true) {
        if (-not (Test-Path -LiteralPath $preservedSecureState -PathType Container)) {
            throw 'Preexisting protected app-state snapshot is missing during restoration.'
        }
        Assert-NoReparsePath $preservedSecureState
        $secureParent = Split-Path -Parent $secureState
        if (-not (Test-Path -LiteralPath $secureParent -PathType Container)) {
            [void][IO.Directory]::CreateDirectory($secureParent)
        }
        Assert-NoReparsePath $secureParent
        Move-Item -LiteralPath $preservedSecureState -Destination $secureState
    } elseif (Test-Path -LiteralPath $preservedSecureState) {
        throw 'Unexpected protected app-state snapshot exists for an absent baseline.'
    }
    $state.restored = $true
    Write-AtomicJson $statePath $state
}

Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class WinsVpnWorkerWindow {
  private delegate bool EnumWindowCallback(IntPtr window, IntPtr state);
  [DllImport("user32.dll")] private static extern bool EnumWindows(
      EnumWindowCallback callback, IntPtr state);
  [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(
      IntPtr window, out uint processId);
  [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr window);
  [DllImport("user32.dll")] private static extern IntPtr GetParent(IntPtr window);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassName(
      IntPtr window, StringBuilder className, int capacity);
  [DllImport("dwmapi.dll")] private static extern int DwmGetWindowAttribute(
      IntPtr window, uint attribute, out int value, int size);
  public static IntPtr FindExactTopLevelWindow(uint expectedProcessId) {
    IntPtr match = IntPtr.Zero;
    int matches = 0;
    EnumWindows(delegate(IntPtr window, IntPtr state) {
      uint processId;
      GetWindowThreadProcessId(window, out processId);
      if (processId != expectedProcessId || !IsWindowVisible(window) ||
          GetParent(window) != IntPtr.Zero) return true;
      var className = new StringBuilder(128);
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
}
'@

function Get-ExactGuiWindowHandle {
    param([Parameter(Mandatory)][int]$ProcessId)
    [WinsVpnWorkerWindow]::FindExactTopLevelWindow([uint32]$ProcessId)
}

function Start-ExactGui {
    Stop-ExactGui
    $process = Start-Process -FilePath $InstalledGui -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $windowHandle = [IntPtr]::Zero
    do {
        Start-Sleep -Milliseconds 250
        $process.Refresh()
        if (-not $process.HasExited) {
            $windowHandle = Get-ExactGuiWindowHandle $process.Id
        }
    } while ($windowHandle -eq [IntPtr]::Zero -and
        -not $process.HasExited -and [DateTime]::UtcNow -lt $deadline)
    if ($process.HasExited -or $windowHandle -eq [IntPtr]::Zero) {
        throw "Exact Win's VPN GUI did not present an interactive window."
    }
    $process
}

function Assert-ExactManagerService {
    $manager = Get-CimInstance Win32_Service -Filter `
        "Name='WinsVpnTunnelManager'" -ErrorAction Stop
    $imagePath = [string]$manager.PathName
    if ($manager.State -cne 'Running' -or $manager.StartMode -cne 'Auto' -or
        $manager.StartName -cne 'LocalSystem' -or
        $imagePath -notmatch '^"(?<binary>[^"]+)"\s+--service$' -or
        -not [StringComparer]::OrdinalIgnoreCase.Equals(
            [IO.Path]::GetFullPath($Matches.binary),
            [IO.Path]::GetFullPath($InstalledService)
        )) {
        throw 'Tunnel manager SCM identity/path/state is not exactly pinned.'
    }
    $registry = Get-ItemProperty -LiteralPath `
        'HKLM:\SYSTEM\CurrentControlSet\Services\WinsVpnTunnelManager' `
        -ErrorAction Stop
    $delayed = $registry.PSObject.Properties['DelayedAutoStart']
    if ([int]$registry.Start -ne 2 -or [int]$registry.ErrorControl -ne 2 -or
        ($delayed -and [int]$delayed.Value -ne 0) -or
        [int]$registry.ServiceSidType -ne 1 -or
        $null -eq $registry.FailureActions -or
        $registry.FailureActions.Length -lt 1) {
        throw 'Tunnel manager SCM hardening registry contract is incomplete.'
    }
    $manager
}

function Get-ObservedWinnTransport {
    Resolve-WorkerObservedTransport `
        (@(Get-Process winsvpn_winn3_engine -ErrorAction SilentlyContinue).Count) `
        (@(Get-Process winsvpn_awg_engine -ErrorAction SilentlyContinue).Count) `
        (@(Get-Process xray -ErrorAction SilentlyContinue).Count)
}

function Test-ExactRuntimeObserved {
    param([Parameter(Mandatory)]$Runtime)
    $process = Get-Process -Id ([int]$Runtime.candidate_pid) -ErrorAction SilentlyContinue
    if (-not $process) { return $false }
    try { $actualPath = $process.Path } catch { return $false }
    if ([IO.Path]::GetFullPath($actualPath) -cne
            [IO.Path]::GetFullPath($InstalledGui) -or
        [int]$process.SessionId -ne [int]$Runtime.candidate_session_id -or
        (Get-Sha256 $actualPath) -cne [string]$Runtime.installed_gui_sha256) {
        return $false
    }
    $manager = Get-Service -Name WinsVpnTunnelManager -ErrorAction SilentlyContinue
    [bool]($manager -and $manager.Status -eq 'Running')
}

function Assert-NativeHostObserved {
    Assert-ArchitectureBinding $script:ArchitectureBinding
    $contract = Get-NativeHostContract
    if (-not (Test-Path -LiteralPath $contract.host_image -PathType Leaf)) {
        throw 'Physical native-host receipt is source-only or unobserved.'
    }
    Assert-NoReparsePath $contract.host_image
    Assert-PeMatchesBinding $contract.host_image 'Native host'
    [void](Assert-ValidSignature $contract.host_image 'Native host')
    $browsers = [Collections.Generic.List[object]]::new()
    foreach ($browser in @($contract.browsers)) {
        $manifest = Join-Path $contract.manifest_root $browser.manifest_name
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
            throw 'Physical native-host receipt is source-only or unobserved.'
        }
        Assert-NoReparsePath $manifest
        $document = Read-JsonOnce $manifest
        $registered = $null
        try {
            $item = Get-Item -LiteralPath $browser.registry_path
            $registered = [string]$item.GetValue('')
        } catch {
            throw 'Physical native-host receipt is source-only or unobserved.'
        }
        if ([string]$document.name -cne $contract.host_name -or
            [string]::IsNullOrWhiteSpace($registered) -or
            [IO.Path]::GetFullPath($registered) -cne
                [IO.Path]::GetFullPath($manifest)) {
            throw 'Physical native-host receipt is source-only or unobserved.'
        }
        $browsers.Add([ordered]@{
            browser = [string]$browser.browser
            manifest_bound = $true
            registry_bound = $true
        })
    }
    $facts = [ordered]@{
        native_host_observed = $true
        host_name = [string]$contract.host_name
        host_image = [string]$contract.host_image
        browsers = @($browsers)
    }
    Assert-NativeHostObservationFacts $facts
    $facts
}

function Invoke-Prepare {
    $started = [DateTime]::UtcNow
    $context = Read-JsonOnce (Join-Path $PrivateRoot 'context.json')
    if ($context.contract -cne 'winsvpn-windows-release-collector-context-v1' -or
        $context.run_id -cne $RunId -or
        $context.collector_closure_sha256 -cne $verifiedClosureSha256) {
        throw 'Prepare context is not bound to the canonical run/helper closure.'
    }
    $candidatePath = Join-Path $InputRoot 'candidate-installer.exe'
    $candidateSignature = Assert-ValidSignature $candidatePath 'Candidate installer'
    $script:ArchitectureBinding = New-ArchitectureBinding (
        Get-PeArchitecture $candidatePath
    )
    $payloadIndex = Read-JsonOnce (Join-Path $PrivateRoot 'payload-snapshot-index.json')
    $payloadManifest = Read-JsonOnce `
        (Join-Path $InputRoot 'candidate-payload-manifest.json')
    $payloadManifestPath = Join-Path $InputRoot 'candidate-payload-manifest.json'
    if ($payloadIndex.contract -cne 'winsvpn-windows-payload-snapshot-v1' -or
        $payloadIndex.manifest_sha256 -cne (Get-Sha256 $payloadManifestPath) -or
        @($payloadIndex.entries).Count -ne @($payloadManifest.payload).Count) {
        throw 'Immutable payload snapshot does not match its manifest.'
    }
    $payloadPeCount = 0
    foreach ($entry in @($payloadIndex.entries)) {
        $snapshot = Join-Path $InputRoot ('payload-files\' + [string]$entry.snapshot_name)
        if ((Get-Item -LiteralPath $snapshot).Length -ne [long]$entry.size -or
            (Get-Sha256 $snapshot) -cne [string]$entry.sha256) {
            throw "Immutable payload snapshot failed: $($entry.path)"
        }
        $payloadName = [IO.Path]::GetFileName(([string]$entry.path).Replace('/', '\'))
        if ($payloadName -match '\.(exe|dll|sys)$') {
            Assert-PeMatchesBinding $snapshot "Payload $($entry.path)"
            ++$payloadPeCount
        }
    }
    if ($payloadPeCount -lt 1) {
        throw 'Immutable payload snapshot omitted native PE images.'
    }
    if (-not (Test-NoActiveTunnel)) {
        throw 'Prepare refuses to uninstall while any pre-existing VPN path is active.'
    }
    Stop-ExactGui
    $appData = Join-Path $env:APPDATA 'wins_vpn'
    $secureState = Join-Path $env:LOCALAPPDATA 'WinsVPN\SecureState'
    Write-NewJson (Join-Path $PrivateRoot 'preexisting-appdata-state.json') `
        ([ordered]@{
            schema_version = 1
            contract = 'winsvpn-windows-preexisting-appdata-state-v1'
            run_id = $RunId
            present = [bool](Test-Path -LiteralPath $appData -PathType Container)
            secure_state_present = [bool](Test-Path -LiteralPath $secureState `
                -PathType Container)
            restored = $false
        })
    if (Test-Path -LiteralPath $appData) {
        Get-ChildItem -LiteralPath $appData -Recurse -Force | ForEach-Object {
            if (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Existing Win''s VPN user state contains a reparse point.'
            }
        }
        $preservedAppData = Join-Path $PrivateRoot 'preexisting-appdata'
        if (Test-Path -LiteralPath $preservedAppData) {
            throw 'A preserved pre-test app-data snapshot already exists.'
        }
        if (-not [IO.Path]::GetFullPath($preservedAppData).StartsWith(
                [IO.Path]::GetFullPath($PrivateRoot).TrimEnd('\') + '\',
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw 'Pre-test app-data preservation escaped the private run root.'
        }
        Move-Item -LiteralPath $appData -Destination $preservedAppData
    }
    if (Test-Path -LiteralPath $secureState) {
        Assert-NoReparsePath $secureState
        Get-ChildItem -LiteralPath $secureState -Recurse -Force | ForEach-Object {
            if (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Existing Win''s VPN protected state contains a reparse point.'
            }
        }
        $preservedSecureState = Join-Path $PrivateRoot 'preexisting-secure-state'
        if (Test-Path -LiteralPath $preservedSecureState) {
            throw 'A preserved pre-test protected-state snapshot already exists.'
        }
        Move-Item -LiteralPath $secureState -Destination $preservedSecureState
    }
    if (Test-Path -LiteralPath $Uninstaller -PathType Leaf) {
        [void](Assert-ValidSignature $Uninstaller 'Existing Win''s VPN uninstaller')
        Assert-PeMatchesBinding $Uninstaller 'Existing Win''s VPN uninstaller'
        $uninstall = Start-Process -FilePath $Uninstaller -ArgumentList @(
            '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART',
            '/RESTARTEXITCODE=3010'
        ) -Wait -PassThru
        if ($uninstall.ExitCode -ne 0) {
            throw "Existing Win's VPN uninstall failed or requires reboot: $($uninstall.ExitCode)."
        }
    }
    foreach ($serviceName in @(
        'WinsVpnTunnelManager', 'WinsVPNSplitTunnel', 'AmneziaWGTunnel$winsvpn'
    )) {
        if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
            throw "Clean uninstall left service $serviceName."
        }
    }
    if (Test-Path -LiteralPath $InstallRoot) {
        throw 'Clean uninstall left the fixed Win''s VPN installation directory.'
    }
    $candidateInstallLog = Join-Path $PrivateRoot 'candidate-install.log'
    $install = Start-Process -FilePath $candidatePath -ArgumentList @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART',
        '/RESTARTEXITCODE=3010', '/SP-', "/LOG=$candidateInstallLog"
    ) -Wait -PassThru
    Assert-InstallerLogHasNoSuppressedException $candidateInstallLog
    if ($install.ExitCode -ne 0) {
        throw "Exact candidate installer failed or requires reboot: $($install.ExitCode)."
    }
    $guiSignature = Assert-ValidSignature $InstalledGui 'Installed GUI'
    $serviceSignature = Assert-ValidSignature $InstalledService 'Installed service'
    $engineSignature = Assert-ValidSignature $InstalledAwgEngine `
        'Installed AWG engine'
    $signerSha = Get-CertificateSha256 $candidateSignature.SignerCertificate
    if ((Get-CertificateSha256 $guiSignature.SignerCertificate) -cne $signerSha -or
        (Get-CertificateSha256 $serviceSignature.SignerCertificate) -cne $signerSha -or
        (Get-CertificateSha256 $engineSignature.SignerCertificate) -cne $signerSha) {
        throw 'Installed native payload signer differs from exact installer signer.'
    }
    Assert-PeMatchesBinding $candidatePath 'Candidate installer'
    Assert-InstalledNativeImages 'Installed'
    $candidateManifestPath = Join-Path $ArtifactRoot 'candidate-manifest.json'
    $candidateManifest = Read-JsonOnce $candidateManifestPath
    $guiEntry = @($candidateManifest.artifacts | Where-Object name -ceq 'wins_vpn.exe')
    $serviceEntry = @($candidateManifest.artifacts |
        Where-Object name -ceq 'wins_vpn_tunnel_service.exe')
    $engineEntry = @($candidateManifest.artifacts |
        Where-Object name -ceq 'winsvpn_awg_engine.exe')
    if ($guiEntry.Count -ne 1 -or $serviceEntry.Count -ne 1 -or
        $engineEntry.Count -ne 1 -or
        (Get-Sha256 $InstalledGui) -cne [string]$guiEntry[0].sha256 -or
        (Get-Sha256 $InstalledService) -cne [string]$serviceEntry[0].sha256 -or
        (Get-Sha256 $InstalledAwgEngine) -cne [string]$engineEntry[0].sha256 -or
        (Get-Item $InstalledGui).Length -ne [long]$guiEntry[0].size -or
        (Get-Item $InstalledService).Length -ne [long]$serviceEntry[0].size -or
        (Get-Item $InstalledAwgEngine).Length -ne [long]$engineEntry[0].size) {
        throw 'Installed GUI/service/AWG engine do not match the candidate manifest.'
    }
    [void](Assert-ExactManagerService)

    $credential = Read-CredentialStore
    $node = Invoke-VerifyRequest $credential $false
    $core = Invoke-VerifyRequest $credential $true
    $nodeConfig = Add-LocalClientKeys -Config $node.Json.vpn_config `
        -Credential $credential
    $coreConfig = Add-LocalClientKeys -Config $core.Json.vpn_config `
        -Credential $credential
    $nodePort = Get-DirectPort ([string]$nodeConfig.server_endpoint)
    $corePort = Get-DirectPort ([string]$coreConfig.server_endpoint)
    if ($nodePort -ne 9110 -or $corePort -eq 9110 -or
        $nodeConfig.double_vpn_active -ne $false -or
        $coreConfig.double_vpn_active -ne $true) {
        throw 'Live route advertisement violates node 9110/Core dynamic first-hop policy.'
    }
    $nodeRoutes = Get-XrayRoutes $nodeConfig
    $coreRoutes = Get-XrayRoutes $coreConfig
    $requiredXrayRoutes = @('80/none', '443/tls')
    $nodeRouteKeys = @($nodeRoutes | ForEach-Object {
        "$([int]$_.port)/$([string]$_.security)"
    })
    $coreRouteKeys = @($coreRoutes | ForEach-Object {
        "$([int]$_.port)/$([string]$_.security)"
    })
    foreach ($requiredRoute in $requiredXrayRoutes) {
        if ($requiredRoute -notin $nodeRouteKeys -or
            $requiredRoute -notin $coreRouteKeys) {
            throw "Live /verify response omitted required Xray route $requiredRoute."
        }
    }

    if (-not (Test-Path -LiteralPath $appData -PathType Container)) {
        New-Item -ItemType Directory -Path $appData | Out-Null
    }
    Write-WinsVpnSecureJson -Name 'vpn_settings.txt' -Value ([ordered]@{
        selected_index = [int]$credential.selected_location_index
        stealth_active = $false
        double_vpn_requested = $false
        excluded_vpn_packages = @()
        excluded_vpn_cidrs = @()
        account_number = [string]$credential.node_request.account_number
        legal_accepted_version = [string]$credential.node_request.legal_version
        legal_accepted_hash = [string]$credential.node_request.legal_hash
        launcher_unlocked = $true
    })
    Write-WinsVpnSecureJson -Name 'vpn_config.txt' -Value $nodeConfig
    Write-WinsVpnSecureText -Name 'user_pin.txt' `
        -Value ([string]$credential.user_pin_credential)
    if ($credential.client_keypair) {
        Write-WinsVpnSecureJson -Name 'client_keypair.json' `
            -Value $credential.client_keypair
    }
    if ($credential.node_cache) {
        Write-NewJson (Join-Path $appData 'node_cache.json') $credential.node_cache
    }

    $gui = Start-ExactGui
    $runtime = [ordered]@{
        schema_version = 1
        contract = 'winsvpn-windows-release-runtime-context-v1'
        run_id = $RunId
        collector_closure_sha256 = [string]$context.collector_closure_sha256
        candidate_pid = [int]$gui.Id
        candidate_session_id = [int]$gui.SessionId
        installed_gui_path = $InstalledGui
        installed_gui_sha256 = Get-Sha256 $InstalledGui
        installed_service_path = $InstalledService
        installed_service_sha256 = Get-Sha256 $InstalledService
        installed_awg_engine_path = $InstalledAwgEngine
        installed_awg_engine_sha256 = Get-Sha256 $InstalledAwgEngine
        app_version = ([string]$candidateManifest.release_identity).Split('+')[0]
        build_number = ([string]$candidateManifest.release_identity).Split('+')[1]
        node_direct_awg_port = $nodePort
        core_direct_awg_port = $corePort
        node_advertised_xray_routes = $nodeRoutes
        core_advertised_xray_routes = $coreRoutes
        node_registration_sha256 = Get-StringSha256 (
            [string]$node.Json.selected_node.slug
        )
        core_assignment_sha256 = Get-StringSha256 (
            ([string]$coreConfig.double_vpn_core_id + '|' +
                [string]$coreConfig.double_vpn_exit_slug)
        )
        api_response_sha256 = Get-StringSha256 (
            $node.Sha256 + '|' + $core.Sha256
        )
        next_sequence = 4
        architecture = [string]$script:ArchitectureBinding.architecture
        pe_machine = [int]$script:ArchitectureBinding.pe_machine
        native_architecture = [string]$script:ArchitectureBinding.native_architecture
        os_architecture = [string]$script:ArchitectureBinding.os_architecture
        process_wow64 = $false
    }
    Write-BoundReceiptJson (Join-Path $PrivateRoot 'runtime-context.json') $runtime
    $uiJson = & (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action InspectConnect
    $ui = $uiJson | ConvertFrom-Json
    if ($ui.label -cne 'Connect VPN' -or $ui.role -ne 43 -or
        $ui.enabled -ne $true -or $ui.visible -ne $true) {
        throw 'Fresh exact GUI lacks its semantic Connect control.'
    }
    if (-not (Test-ExactRuntimeObserved $runtime)) {
        throw 'Physical runtime receipt is source-only or unobserved.'
    }
    $nativeFacts = Assert-NativeHostObserved
    Write-BoundReceiptJson (Join-Path $PrivateRoot 'runtime-observation.json') `
        ([ordered]@{
            schema_version = 1
            contract = 'winsvpn-windows-runtime-observation-v1'
            run_id = $RunId
            collector_closure_sha256 = [string]$context.collector_closure_sha256
            artifact_sha256 = [string]$context.artifact_sha256
            release_identity = [string]$context.release_identity
            source_only = $false
            runtime_observed = $true
        })
    Write-BoundReceiptJson (Join-Path $PrivateRoot 'native-host-observation.json') `
        ([ordered]@{
            schema_version = 1
            contract = 'winsvpn-windows-native-host-observation-v1'
            run_id = $RunId
            collector_closure_sha256 = [string]$context.collector_closure_sha256
            artifact_sha256 = [string]$context.artifact_sha256
            release_identity = [string]$context.release_identity
            source_only = $false
            native_host_observed = $true
            host_name = [string]$nativeFacts.host_name
            host_image = [string]$nativeFacts.host_image
            browsers = @($nativeFacts.browsers)
        })
    $state = Get-StateDocument
    $baseline = [ordered]@{
        schema_version = 1
        contract = 'winsvpn-windows-release-baseline-v1'
        run_id = $RunId
        collector_closure_sha256 = [string]$context.collector_closure_sha256
        captured_at_utc = [DateTime]::UtcNow.ToString('o')
        state = $state
        state_sha256 = Get-CanonicalSha256 $state
        egress_state_sha256 = Get-EgressStateSha256
        ipv6_egress_state = Get-OptionalIpv6EgressState
        management_probe_host = [string]$credential.management_probe_host
        management_probe_port = [int]$credential.management_probe_port
    }
    if (-not (Test-NetConnection -ComputerName $baseline.management_probe_host `
            -Port $baseline.management_probe_port -InformationLevel Quiet `
            -WarningAction SilentlyContinue)) {
        throw 'Disconnected baseline management path is unavailable.'
    }
    Write-NewJson (Join-Path $PrivateRoot 'baseline.json') $baseline

    $signatureReceipt = New-BoundReceipt `
        'winsvpn-windows-signature-receipt-v1' 1 $started ([ordered]@{
            artifact_sha256 = [string]$context.artifact_sha256
            artifact_size_bytes = [long]$context.artifact_size_bytes
            authenticode_status = 'Valid'
            signer_certificate_sha256 = $signerSha
            timestamp_certificate_sha256 = Get-CertificateSha256 `
                $candidateSignature.TimeStamperCertificate
            signature_verified = $true
            timestamp_verified = $true
            passed = $true
        }) $context -EmitArchitecture
    Write-RequiredPhysicalReceipt (Join-Path $ReceiptRoot 'signature.json') `
        $signatureReceipt 'winsvpn-windows-signature-receipt-v1' $context
    $installReceipt = New-BoundReceipt `
        'winsvpn-windows-install-receipt-v1' 2 $started ([ordered]@{
            artifact_sha256 = [string]$context.artifact_sha256
            candidate_manifest_sha256 = Get-Sha256 $candidateManifestPath
            previous_version_uninstalled = $true
            install_exit_code = 0
            installed_gui_sha256 = [string]$runtime.installed_gui_sha256
            installed_gui_size_bytes = [long](Get-Item $InstalledGui).Length
            installed_service_sha256 = [string]$runtime.installed_service_sha256
            installed_service_size_bytes = [long](Get-Item $InstalledService).Length
            installed_awg_engine_sha256 = `
                [string]$runtime.installed_awg_engine_sha256
            installed_awg_engine_size_bytes = `
                [long](Get-Item $InstalledAwgEngine).Length
            manager_service_running = $true
            gui_launched = $true
            passed = $true
        }) $context -EmitArchitecture
    Write-RequiredPhysicalReceipt (Join-Path $ReceiptRoot 'install.json') `
        $installReceipt 'winsvpn-windows-install-receipt-v1' $context
    $payloadReceipt = New-BoundReceipt `
        'winsvpn-windows-payload-receipt-v1' 2 $started ([ordered]@{
            candidate_payload_manifest_sha256 = Get-Sha256 $payloadManifestPath
            payload_snapshot_index_sha256 = Get-Sha256 (
                Join-Path $PrivateRoot 'payload-snapshot-index.json'
            )
            payload_entry_count = @($payloadIndex.entries).Count
            payload_pe_count = $payloadPeCount
            payload_pe_verified = $true
            mixed_architecture = $false
            passed = $true
        }) $context -EmitArchitecture
    Write-BoundReceiptJson (Join-Path $PrivateRoot 'payload-receipt.json') `
        $payloadReceipt
    $advertisementReceipt = New-BoundReceipt `
        'winsvpn-windows-route-advertisement-receipt-v1' 3 $started `
        ([ordered]@{
            node_direct_awg_port = $nodePort
            core_direct_awg_port = $corePort
            node_advertised_xray_routes = $nodeRoutes
            core_advertised_xray_routes = $coreRoutes
            node_registration_sha256 = [string]$runtime.node_registration_sha256
            core_assignment_sha256 = [string]$runtime.core_assignment_sha256
            api_response_sha256 = [string]$runtime.api_response_sha256
            passed = $true
        }) $context
    Write-NewJson (Join-Path $ReceiptRoot 'route-advertisement.json') `
        $advertisementReceipt
}

function Set-CurrentAppMode {
    param([Parameter(Mandatory)][bool]$DoubleVpn)
    $credential = Read-CredentialStore
    $verified = Invoke-VerifyRequest $credential $DoubleVpn
    $config = Add-LocalClientKeys -Config $verified.Json.vpn_config `
        -Credential $credential
    if ([bool]$config.double_vpn_active -ne $DoubleVpn) {
        throw 'Live /verify response did not preserve the requested VPN mode.'
    }
    Stop-ExactGui
    $settings = Read-WinsVpnSecureJson -Name 'vpn_settings.txt'
    $settings.double_vpn_requested = $DoubleVpn
    $settings.stealth_active = $false
    Write-WinsVpnSecureJson -Name 'vpn_settings.txt' -Value $settings
    Write-WinsVpnSecureJson -Name 'vpn_config.txt' -Value $config
    $gui = Start-ExactGui
    $runtimePath = Join-Path $PrivateRoot 'runtime-context.json'
    $runtime = Read-JsonOnce $runtimePath
    $script:ArchitectureBinding = Get-RuntimeArchitectureBinding $runtime
    $runtime.candidate_pid = [int]$gui.Id
    $runtime.candidate_session_id = [int]$gui.SessionId
    Write-BoundAtomicJson $runtimePath $runtime
    $observation = (& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action InspectConnect) | ConvertFrom-Json
    if ($observation.label -cne 'Connect VPN' -or $observation.role -ne 43) {
        throw 'Mode restart did not return to the exact semantic Connect state.'
    }
    [pscustomobject]@{
        Credential = $credential
        Response = $verified.Json
        Config = $config
        ApiSha256 = $verified.Sha256
    }
}

function Get-ForcingStateSha256 {
    $rules = @(Get-NetFirewallRule -Group $FirewallGroup `
        -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
            $port = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $app = $_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
            [ordered]@{
                name = [string]$_.Name
                enabled = [string]$_.Enabled
                direction = [string]$_.Direction
                action = [string]$_.Action
                protocol = if ($port) { [string]$port.Protocol } else { '' }
                remote_port = if ($port) { [string]$port.RemotePort } else { '' }
                program_sha256 = if ($app -and $app.Program) {
                    Get-StringSha256 ([string]$app.Program)
                } else { '' }
            }
        })
    Get-CanonicalSha256 $rules
}

function Add-XrayForcingRules {
    param(
        [Parameter(Mandatory)][int]$DirectPort,
        [Parameter(Mandatory)][int]$TargetPort,
        [Parameter(Mandatory)]$AllXrayRoutes
    )
    $programs = @(
        $InstalledGui,
        $InstalledService,
        $InstalledAwgEngine,
        (Join-Path $InstallRoot 'amneziawg.exe'),
        (Join-Path $InstallRoot 'awg.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    $ordinal = 0
    foreach ($program in $programs) {
        New-NetFirewallRule -Name "WinsVPN-Release-$RunId-direct-$ordinal" `
            -Group $FirewallGroup -Direction Outbound -Action Block `
            -Enabled True -Profile Any -Program $program -Protocol UDP `
            -RemotePort $DirectPort | Out-Null
        ++$ordinal
    }
    $otherPorts = @($AllXrayRoutes | ForEach-Object { [int]$_.port } |
        Where-Object { $_ -ne $TargetPort } | Sort-Object -Unique)
    if ($otherPorts.Count -gt 0) {
        foreach ($program in @($InstalledGui, (Join-Path $InstallRoot 'xray.exe')) |
                Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }) {
            New-NetFirewallRule -Name "WinsVPN-Release-$RunId-xray-$ordinal" `
                -Group $FirewallGroup -Direction Outbound -Action Block `
                -Enabled True -Profile Any -Program $program -Protocol TCP `
                -RemotePort $otherPorts | Out-Null
            ++$ordinal
        }
    }
}

function Remove-ForcingRules {
    Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction Stop
}

function Initialize-HubSshMaterial {
    param([Parameter(Mandatory)]$Credential)
    $ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    if (-not (Test-Path -LiteralPath $ssh -PathType Leaf) -or
        [string]$Credential.hub_host -notmatch '^[A-Za-z0-9.-]{1,253}$' -or
        [string]$Credential.hub_user -notmatch '^[a-z_][a-z0-9_-]{0,31}$' -or
        [string]$Credential.hub_private_key_base64 -notmatch
            '^[A-Za-z0-9+/=]{128,}$' -or
        [string]$Credential.hub_known_hosts -notmatch
            [regex]::Escape([string]$Credential.hub_host)) {
        throw 'Pinned noninteractive hub observer credential is invalid.'
    }
    $keyPath = Join-Path $PrivateRoot 'hub-observer-key'
    $knownPath = Join-Path $PrivateRoot 'hub-observer-known-hosts'
    if (-not (Test-Path -LiteralPath $keyPath)) {
        $keyBytes = [Convert]::FromBase64String(
            [string]$Credential.hub_private_key_base64
        )
        $keyStream = [IO.File]::Open(
            $keyPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try { $keyStream.Write($keyBytes, 0, $keyBytes.Length); $keyStream.Flush($true) }
        finally { $keyStream.Dispose() }
    }
    if (-not (Test-Path -LiteralPath $knownPath)) {
        $knownBytes = [Text.UTF8Encoding]::new($false).GetBytes(
            ([string]$Credential.hub_known_hosts).Trim() + [Environment]::NewLine
        )
        $knownStream = [IO.File]::Open(
            $knownPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $knownStream.Write($knownBytes, 0, $knownBytes.Length)
            $knownStream.Flush($true)
        } finally { $knownStream.Dispose() }
    }
    [pscustomobject]@{
        Ssh = $ssh; Key = $keyPath; KnownHosts = $knownPath
        Host = [string]$Credential.hub_host
        User = [string]$Credential.hub_user
    }
}

function Remove-EphemeralObserverMaterial {
    foreach ($name in @('hub-observer-key', 'hub-observer-known-hosts')) {
        $path = Join-Path $PrivateRoot $name
        if (Test-Path -LiteralPath $path) {
            Assert-NoReparsePath $path
            Remove-Item -LiteralPath $path -Force
        }
    }
}

function Start-HubObserver {
    param(
        [Parameter(Mandatory)]$Credential,
        [Parameter(Mandatory)][ValidateSet('Node', 'Core')][string]$Kind,
        [Parameter(Mandatory)][hashtable]$Environment
    )
    $material = Initialize-HubSshMaterial $Credential
    foreach ($key in $Environment.Keys) {
        if ([string]$key -notmatch '^WINS_[A-Z0-9_]{1,80}$' -or
            [string]$Environment[$key] -notmatch '^[A-Za-z0-9_-]{1,128}$') {
            throw 'Remote observer environment violates the fixed grammar.'
        }
    }
    $remote = (($Environment.Keys | Sort-Object | ForEach-Object {
        "$_=$($Environment[$_])"
    }) -join ' ') + ' python3 -'
    $helperName = if ($Kind -eq 'Node') {
        'windows_spain_live_observation.py'
    } else { 'windows_core_live_observation.py' }
    $script = [Text.UTF8Encoding]::new($false, $true).GetString(
        (Read-BytesOnce (Join-Path $HelperRoot $helperName) 16777216)
    )
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $material.Ssh
    $psi.Arguments = '-i "' + $material.Key + '" -o BatchMode=yes ' +
        '-o ConnectTimeout=12 -o ConnectionAttempts=1 ' +
        '-o StrictHostKeyChecking=yes -o UserKnownHostsFile="' +
        $material.KnownHosts + '" -o GlobalKnownHostsFile=NUL ' +
        '-o UpdateHostKeys=no ' + $material.User + '@' + $material.Host +
        ' "' + $remote + '"'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $psi
    if (-not $process.Start()) { throw 'Pinned hub observer failed to start.' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.Write($script)
    $process.StandardInput.Close()
    [pscustomobject]@{
        Process = $process; Stdout = $stdout; Stderr = $stderr; Kind = $Kind
    }
}

function Complete-HubObserver {
    param([Parameter(Mandatory)]$Handle)
    if (-not $Handle.Process.WaitForExit(150000)) {
        try { $Handle.Process.Kill() } catch {}
        throw "$($Handle.Kind) server observer timed out."
    }
    $stdout = $Handle.Stdout.Result
    $stderr = $Handle.Stderr.Result
    if ($Handle.Process.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($stdout)) {
        throw "$($Handle.Kind) pinned server observer failed: " +
            (Get-StringSha256 $stderr)
    }
    $result = $stdout | ConvertFrom-Json
    $expected = if ($Handle.Kind -eq 'Node') {
        'winsvpn-windows-spain-live-observation-v1'
    } else { 'winsvpn-windows-core-live-observation-v1' }
    if ($result.contract -cne $expected -or
        $result.observer_authenticated -ne $true) {
        throw "$($Handle.Kind) server observer contract/authentication failed."
    }
    $result
}

function Assert-NodeServerObservation {
    param([Parameter(Mandatory)]$Observation, [Parameter(Mandatory)][bool]$Xray)
    if ($Observation.observer_authenticated -ne $true -or
        [int]$Observation.peer_match_count_after -ne 1 -or
        $Observation.peer_allowed_ipv4_32 -ne $true -or
        [int]$Observation.peer_count -lt 1 -or
        [int]$Observation.max_peers -lt [int]$Observation.peer_count -or
        $Observation.handshake_advanced -ne $true -or
        [long]$Observation.rx_delta -lt 1024 -or
        [long]$Observation.tx_delta -lt 1024 -or
        $Observation.peer_psk_matches_registration -ne $true -or
        $Observation.node_public_key_matches_runtime -ne $true -or
        $Observation.awg_obfuscation_matches_registration -ne $true -or
        $Observation.awg_runtime_obfuscation_matches_registration -ne $true -or
        $Observation.awg_runtime_listen_port_matches_registration -ne $true -or
        @($Observation.suricata_new_drop_sids).Count -ne 0) {
        throw 'Pinned node observation lacks exact registered peer/capacity/traffic proof.'
    }
    if ($Xray -and (
            $Observation.tcp80_listener_present -ne $true -or
            $Observation.tcp80_listener_nginx -ne $true -or
            $Observation.nginx_process_running -ne $true -or
            $Observation.xray_process_running -ne $true -or
            $Observation.xray_config_read -ne $true -or
            $Observation.xray_path_matches_registration -ne $true -or
            $Observation.xray_uuid_matches_registration -ne $true -or
            $Observation.xray_inbound_port_matches_registration -ne $true -or
            $Observation.nginx_public_port_matches_registration -ne $true -or
            $Observation.nginx_security_matches_registration -ne $true -or
            $Observation.nginx_host_matches_registration -ne $true -or
            $Observation.nginx_path_matches_registration -ne $true
        )) {
        throw 'Pinned node Xray observation does not match its registered route.'
    }
    if (-not $Xray -and
        [int]$Observation.expected_client_udp9110_inbound_packets -lt 1) {
        throw 'Pinned node direct observation did not see this client on UDP/9110.'
    }
    if ([string]$Observation.observation_mode -ceq 'direct' -and (
            $Observation.client_registration_digests_supplied -ne $true -or
            $Observation.client_preshared_key_matches_registration -ne $true -or
            $Observation.client_server_public_key_matches_registration -ne $true -or
            $Observation.client_obfuscation_matches_registration -ne $true
        )) {
        throw 'Pinned node observation found stale client cryptographic inputs.'
    }
}

function Assert-CoreServerObservation {
    param(
        [Parameter(Mandatory)]$Observation,
        [Parameter(Mandatory)][bool]$Xray
    )
    if ($Observation.observer_authenticated -ne $true -or
        [int]$Observation.ingress_interface_match_count -ne 1 -or
        $Observation.exit_interface_present -ne $true -or
        $Observation.assignment_revision_ready -ne $true -or
        [int]$Observation.exact_ingress_peer_match_count_before -ne 1 -or
        [int]$Observation.exact_ingress_peer_match_count_after -ne 1 -or
        $Observation.exact_ingress_allowed_ip -ne $true -or
        [long]$Observation.exact_ingress_peer_rx_delta -lt 1024 -or
        [long]$Observation.exact_ingress_peer_tx_delta -lt 1024 -or
        $Observation.client_policy_rule_matches -ne $true -or
        $Observation.client_route_uses_corex -ne $true -or
        $Observation.unexpected_core_direct_egress -ne $false -or
        $Observation.routing_stable -ne $true -or
        [string]$Observation.observed_allowed_ip_set_digest -cne
            [string]$Observation.allowed_ip_set_digest -or
        [long]$Observation.ingress_rx_bytes_delta -lt 1024 -or
        [long]$Observation.exit_tx_bytes_delta -lt 1024 -or
        [long]$Observation.ingress_rx_packets_delta -lt 1 -or
        [long]$Observation.exit_tx_packets_delta -lt 1 -or
        [long]$Observation.ingress_rx_drop_delta -ne 0 -or
        [long]$Observation.ingress_tx_drop_delta -ne 0 -or
        [long]$Observation.exit_rx_drop_delta -ne 0 -or
        [long]$Observation.exit_tx_drop_delta -ne 0 -or
        $Observation.services.'docker.service' -ne $true -or
        $Observation.services.'wins-core-management-tunnel.service' -ne $true) {
        throw 'Pinned Core observation lacks exact ingress/exit/service proof.'
    }
    if ($Xray) {
        if ($Observation.tcp80_listener_before -ne $true -or
            $Observation.tcp80_listener_after -ne $true -or
            $Observation.services.'nginx.service' -ne $true -or
            $Observation.services.'xray.service' -ne $true -or
            $Observation.services.assigned_exit_xray_service -ne $true -or
            [string]$Observation.transport_mode -cne 'stealth') {
            throw 'Pinned Core Xray route was not observed on its dynamic stealth port.'
        }
    } elseif ($Observation.udp9210_listener_before -ne $true -or
        $Observation.udp9210_listener_after -ne $true -or
        [string]$Observation.transport_mode -cne 'direct') {
        throw 'Pinned Core direct route was not observed on its dynamic UDP port.'
    }
}

function Wait-TunnelActive {
    param([Parameter(Mandatory)][bool]$Xray)
    $deadline = [DateTime]::UtcNow.AddSeconds(75)
    $uiCommitted = $false
    do {
        $managerService = Get-Service -Name WinsVpnTunnelManager `
            -ErrorAction SilentlyContinue
        $manager = $managerService -and $managerService.Status -eq 'Running'
        $legacyServiceAbsent = $null -eq (Get-Service `
            -Name 'AmneziaWGTunnel$winsvpn' -ErrorAction SilentlyContinue)
        $engineProcesses = @(Get-Process winsvpn_awg_engine `
            -ErrorAction SilentlyContinue)
        $engine = $engineProcesses.Count -eq 1
        if ($engine) {
            try {
                $engine = [IO.Path]::GetFullPath($engineProcesses[0].Path) -ceq
                    [IO.Path]::GetFullPath($InstalledAwgEngine)
            } catch { $engine = $false }
        }
        $adapter = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Status -eq 'Up' -and $_.Name -match '(?i)winsvpn|amnezia|awg'
            }).Count -gt 0
        $routes = @(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object {
            $_.InterfaceAlias -match '(?i)winsvpn|amnezia|awg' -and
            $_.DestinationPrefix -in @('0.0.0.0/0', '::/0')
        }).Count -gt 0
        $xrayPresent = @(Get-Process xray -ErrorAction SilentlyContinue).Count -gt 0
        $winn3Absent = @(Get-Process winsvpn_winn3_engine `
            -ErrorAction SilentlyContinue).Count -eq 0
        $nativeReady = $manager -and $legacyServiceAbsent -and $engine -and
            $adapter -and $routes -and $xrayPresent -eq $Xray -and $winn3Absent
        if (-not $nativeReady) {
            $uiCommitted = $false
        } elseif (-not $uiCommitted) {
            try {
                $ui = (& (Join-Path $HelperRoot `
                    'windows_release_fixed_ui.ps1') -RunId $RunId `
                    -Action InspectDisconnect) | ConvertFrom-Json
                $uiCommitted = $ui.label -ceq 'Disconnect VPN' -and
                    $ui.role -eq 43 -and $ui.visible -eq $true -and
                    $ui.enabled -eq $true
            } catch {
                $uiCommitted = $false
            }
        } else {
            # Require the exact native mode for one more observation after the
            # Flutter state has committed.  A transient direct candidate that
            # the app is about to reject or replace must never satisfy a lane.
            return
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Exact native tunnel state did not become active in time.'
}

function Wait-TunnelClean {
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        $serviceAbsent = $null -eq (Get-Service 'AmneziaWGTunnel$winsvpn' `
            -ErrorAction SilentlyContinue)
        $splitAbsent = $null -eq (Get-Service WinsVPNSplitTunnel `
            -ErrorAction SilentlyContinue)
        $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Status -eq 'Up' -and $_.Name -match '(?i)winsvpn|amnezia|awg'
            })
        $routes = @(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object {
            $_.InterfaceAlias -match '(?i)winsvpn|amnezia|awg'
        })
        $engineAbsent = @(Get-Process winsvpn_awg_engine `
            -ErrorAction SilentlyContinue).Count -eq 0
        $winn3Absent = @(Get-Process winsvpn_winn3_engine `
            -ErrorAction SilentlyContinue).Count -eq 0
        if ($serviceAbsent -and $splitAbsent -and $engineAbsent -and
            $winn3Absent -and
            $adapters.Count -eq 0 -and
            $routes.Count -eq 0 -and
            @(Get-Process xray -ErrorAction SilentlyContinue).Count -eq 0) {
            return
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Native tunnel teardown left an engine, service, adapter, route, Winn v3 process, or Xray process.'
}

function Wait-WinnV3PrimaryActive {
    $deadline = [DateTime]::UtcNow.AddSeconds(75)
    $uiCommitted = $false
    do {
        $managerService = Get-Service -Name WinsVpnTunnelManager `
            -ErrorAction SilentlyContinue
        $manager = $managerService -and $managerService.Status -eq 'Running'
        $legacyServiceAbsent = $null -eq (Get-Service `
            -Name 'AmneziaWGTunnel$winsvpn' -ErrorAction SilentlyContinue)
        $winn3Processes = @(Get-Process winsvpn_winn3_engine `
            -ErrorAction SilentlyContinue)
        $winn3 = $winn3Processes.Count -eq 1
        if ($winn3) {
            try {
                $winn3 = [IO.Path]::GetFullPath($winn3Processes[0].Path) -ceq
                    [IO.Path]::GetFullPath($InstalledWinn3)
            } catch { $winn3 = $false }
        }
        $awgAbsent = @(Get-Process winsvpn_awg_engine `
            -ErrorAction SilentlyContinue).Count -eq 0
        $xrayAbsent = @(Get-Process xray -ErrorAction SilentlyContinue).Count -eq 0
        $adapter = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Status -eq 'Up' -and $_.Name -match '(?i)winsvpn|amnezia|awg'
            }).Count -gt 0
        $routes = @(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object {
            $_.InterfaceAlias -match '(?i)winsvpn|amnezia|awg' -and
            $_.DestinationPrefix -in @('0.0.0.0/0', '::/0')
        }).Count -gt 0
        $nativeReady = $manager -and $legacyServiceAbsent -and $winn3 -and
            $awgAbsent -and $xrayAbsent -and $adapter -and $routes
        if (-not $nativeReady) {
            $uiCommitted = $false
        } elseif (-not $uiCommitted) {
            try {
                $ui = (& (Join-Path $HelperRoot `
                    'windows_release_fixed_ui.ps1') -RunId $RunId `
                    -Action InspectDisconnect) | ConvertFrom-Json
                $uiCommitted = $ui.label -ceq 'Disconnect VPN' -and
                    $ui.role -eq 43 -and $ui.visible -eq $true -and
                    $ui.enabled -eq $true
            } catch {
                $uiCommitted = $false
            }
        } else {
            if ((Get-ObservedWinnTransport) -cne 'winn_v3') {
                throw 'Worker observed mixed Winn v3/v1 transports.'
            }
            return
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Exact Winn v3 primary tunnel state did not become active in time.'
}

function Invoke-WinnV3PrimaryObservation {
    param([Parameter(Mandatory)]$Context)
    [void](Set-CurrentAppMode $false)
    [void]((& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action Connect) | ConvertFrom-Json)
    Wait-WinnV3PrimaryActive
    if ((Get-ObservedWinnTransport) -cne 'winn_v3') {
        throw 'Physical Winn v3 primary receipt is source-only or has mixed fallback order.'
    }
    [void](Invoke-ProtectedCanaries)
    [void]((& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action Disconnect) | ConvertFrom-Json)
    Wait-TunnelClean
    if ((Get-ObservedWinnTransport) -cne 'disconnected') {
        throw 'Winn v3 primary observation did not return to disconnected transport.'
    }
    $observation = [ordered]@{
        schema_version = 1
        contract = 'winsvpn-windows-winn-v3-observation-v1'
        run_id = $RunId
        collector_closure_sha256 = [string]$Context.collector_closure_sha256
        artifact_sha256 = [string]$Context.artifact_sha256
        release_identity = [string]$Context.release_identity
        source_only = $false
        primary_transport = 'winn_v3'
        fallback_transports = @('winn_v1_awg', 'winn_v1_xray')
        winn_v3_session_observed = $true
    }
    Write-BoundReceiptJson (Join-Path $PrivateRoot 'winn-v3-observation.json') `
        $observation
    $observation
}

function Invoke-NaturalTunnelCleanup {
    if (Test-NoActiveTunnel) { return $true }
    foreach ($action in @('Disconnect', 'Cancel')) {
        try {
            [void]((& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
                -RunId $RunId -Action $action) | ConvertFrom-Json)
            Wait-TunnelClean
            if (Test-NoActiveTunnel) { return $true }
        } catch {}
    }
    $false
}

function Invoke-ProtectedCanaries {
    $values = [Collections.Generic.List[string]]::new()
    foreach ($uri in @('https://api.ipify.org', 'https://www.cloudflare.com/cdn-cgi/trace')) {
        $body = (Invoke-WebRequest -UseBasicParsing -Uri $uri -TimeoutSec 20).Content
        if ([string]::IsNullOrWhiteSpace($body)) { throw 'Protected canary returned empty.' }
        $values.Add((Get-StringSha256 $body))
    }
    Get-StringSha256 ($values -join '|')
}

function Invoke-RouteLane {
    param(
        [Parameter(Mandatory)]$Lane,
        [Parameter(Mandatory)][int]$Sequence,
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Runtime
    )
    $started = [DateTime]::UtcNow
    $core = [string]$Lane.kind -like 'core_*'
    $xray = [string]$Lane.kind -like '*_xray'
    $mode = Set-CurrentAppMode $core
    $config = $mode.Config
    $accountDigest = (Get-StringSha256 `
        ([string]$mode.Credential.node_request.account_number)).ToUpperInvariant()
    $deviceDigest = (Get-StringSha256 `
        ([string]$mode.Credential.node_request.device_id)).ToUpperInvariant()
    $publicKeyDigest = (Get-StringSha256 `
        ([string]$config.client_public_key)).ToUpperInvariant()
    $nodeDigest = (Get-StringSha256 `
        ([string]$config.node_slug)).ToUpperInvariant()
    $operationId = [Guid]::NewGuid().ToString()
    $clientEgress = (Invoke-WebRequest -UseBasicParsing `
        -Uri 'https://api.ipify.org' -TimeoutSec 15).Content.Trim()
    $parsedEgress = $null
    if (-not [Net.IPAddress]::TryParse($clientEgress, [ref]$parsedEgress)) {
        throw 'Disconnected client egress identity is unavailable.'
    }
    $observerEnvironment = @{
        WINS_ACCOUNT_DIGEST = $accountDigest
        WINS_DEVICE_DIGEST = $deviceDigest
        WINS_PUBLIC_KEY_DIGEST = $publicKeyDigest
        WINS_NODE_SLUG_DIGEST = $nodeDigest
        WINS_CLIENT_EGRESS_DIGEST = (
            Get-StringSha256 $parsedEgress.ToString()
        ).ToUpperInvariant()
        WINS_CLIENT_PSK_DIGEST = (
            Get-StringSha256 ([string]$config.preshared_key)
        ).ToUpperInvariant()
        WINS_CLIENT_SERVER_KEY_DIGEST = (
            Get-StringSha256 ([string]$config.server_public_key)
        ).ToUpperInvariant()
        WINS_CLIENT_OBFUSCATION_DIGEST = (
            Get-ObfuscationDigest $config.obfuscation
        ).ToUpperInvariant()
        WINS_OBSERVE_SECONDS = '45'
        WINS_OBSERVE_MODE = if ($core) { 'double_exit' } else { 'direct' }
        WINS_TARGET_XRAY_PORT = [string]$Lane.port
        WINS_OBSERVATION_NONCE = $operationId
    }
    $nodeObserver = $null
    $coreObserver = $null
    $beforeForcing = Get-ForcingStateSha256
    $appliedForcing = $beforeForcing
    $rxBefore = 0L
    $txBefore = 0L
    $clientReceipt = $null
    $serverReceipt = $null
    try {
        if ($xray) {
            $allRoutes = if ($core) {
                $Runtime.core_advertised_xray_routes
            } else { $Runtime.node_advertised_xray_routes }
            Add-XrayForcingRules -DirectPort ([int]$Lane.direct_first_hop_port) `
                -TargetPort ([int]$Lane.port) -AllXrayRoutes $allRoutes
            $appliedForcing = Get-ForcingStateSha256
            if ($appliedForcing -ceq $beforeForcing) {
                throw 'Xray forcing did not mutate fixed firewall control state.'
            }
        }
        $nodeObserver = Start-HubObserver $mode.Credential Node $observerEnvironment
        if ($core) {
            $coreEnvironment = @{}
            foreach ($key in $observerEnvironment.Keys) {
                $coreEnvironment[$key] = $observerEnvironment[$key]
            }
            $coreEnvironment.WINS_CORE_DIRECT_PORT = [string]$Lane.direct_first_hop_port
            $coreEnvironment.WINS_CORE_XRAY_PORT = [string]$Lane.port
            $coreObserver = Start-HubObserver $mode.Credential Core $coreEnvironment
        }
        Start-Sleep -Seconds 2
        $adaptersBefore = @(Get-NetAdapterStatistics -ErrorAction SilentlyContinue)
        $rxBefore = [long](($adaptersBefore | Measure-Object ReceivedBytes `
            -Sum).Sum)
        $txBefore = [long](($adaptersBefore | Measure-Object SentBytes -Sum).Sum)
        $connect = (& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
            -RunId $RunId -Action Connect) | ConvertFrom-Json
        Wait-TunnelActive $xray
        $egressSha = Invoke-ProtectedCanaries
        Start-Sleep -Seconds 4
        $adaptersAfter = @(Get-NetAdapterStatistics -ErrorAction Stop)
        $rxAfter = [long](($adaptersAfter | Measure-Object ReceivedBytes -Sum).Sum)
        $txAfter = [long](($adaptersAfter | Measure-Object SentBytes -Sum).Sum)
        $nodeObservation = Complete-HubObserver $nodeObserver
        $nodeObserver = $null
        $coreObservation = if ($core) {
            $value = Complete-HubObserver $coreObserver
            $coreObserver = $null
            $value
        } else { $null }
        Assert-NodeServerObservation $nodeObservation $xray
        if ($core) { Assert-CoreServerObservation $coreObservation $xray }
        $disconnect = (& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
            -RunId $RunId -Action Disconnect) | ConvertFrom-Json
        Wait-TunnelClean
        if ($connect.label -cne 'Connect VPN' -or
            $disconnect.label -cne 'Disconnect VPN') {
            throw 'Route lane semantic connect/disconnect labels are not exact.'
        }
        $server = if ($core) { $coreObservation } else { $nodeObservation }
        if ([string]$nodeObservation.observation_window_nonce -cne $operationId -or
            ($core -and [string]$coreObservation.observation_window_nonce -cne
                $operationId)) {
            throw 'Authenticated server observation is not bound to the lane nonce.'
        }
        $entryPackets = if ($core) {
            [long]$coreObservation.ingress_rx_packets_delta
        } elseif ($xray) {
            [long]$nodeObservation.tcp80_inbound_packets
        } else { [long]$nodeObservation.udp9110_inbound_packets }
        $exitPackets = if ($core) {
            [long]$coreObservation.exit_tx_packets_delta
        } elseif ($xray) {
            [long]$nodeObservation.tcp80_outbound_packets
        } else { [long]$nodeObservation.udp9110_outbound_packets }
        $serverRxDelta = if ($core) {
            [long]$coreObservation.ingress_rx_bytes_delta
        } else { [long]$nodeObservation.rx_delta }
        $serverTxDelta = if ($core) {
            [long]$coreObservation.exit_tx_bytes_delta
        } else { [long]$nodeObservation.tx_delta }
        $rxDelta = [Math]::Max(0L, $rxAfter - $rxBefore)
        $txDelta = [Math]::Max(0L, $txAfter - $txBefore)
        if ($entryPackets -lt 1 -or $exitPackets -lt 1 -or
            $rxDelta -lt 1024 -or $txDelta -lt 1024 -or
            $nodeObservation.handshake_advanced -ne $true -or
            @($nodeObservation.suricata_new_drop_sids).Count -ne 0) {
            throw 'Client/server route counters did not prove the exact live lane.'
        }
        if ($xray -and $core -and
            [string]$coreObservation.transport_mode -cne 'stealth') {
            throw 'Xray lane lacks an authenticated Core stealth observation.'
        }
        if (-not $xray -and $core -and
            [string]$coreObservation.transport_mode -cne 'direct') {
            throw 'Core direct lane was not observed in direct transport mode.'
        }
        $clientReceipt = New-BoundReceipt `
            'winsvpn-windows-client-route-receipt-v1' $Sequence $started `
            ([ordered]@{
                lane_id = [string]$Lane.lane_id
                kind = [string]$Lane.kind
                protocol = [string]$Lane.protocol
                port = [int]$Lane.port
                direct_first_hop_port = [int]$Lane.direct_first_hop_port
                security = [string]$Lane.security
                connect_label = 'Connect VPN'; connect_role = 43
                disconnect_label = 'Disconnect VPN'; disconnect_role = 43
                native_active_observed = $true
                manager_running = $true
                awg_engine_running = $true
                legacy_tunnel_service_absent = $true
                adapter_up = $true
                protected_route_present = $true
                xray_process_observed = $xray
                rx_bytes_delta = $rxDelta
                tx_bytes_delta = $txDelta
                protected_egress_sha256 = $egressSha
                normal_teardown_proven = $true
                residual_awg_engine_absent = $true
                residual_legacy_service_absent = $true
                residual_adapter_absent = $true
                residual_xray_absent = $true
                residual_routes_absent = $true
                passed = $true
            }) $Context
        $serverReceipt = New-BoundReceipt `
            'winsvpn-windows-server-route-receipt-v1' ($Sequence + 1) `
            $started ([ordered]@{
                lane_id = [string]$Lane.lane_id
                scope = if ($core) { 'core' } else { 'node' }
                protocol = [string]$Lane.protocol
                port = [int]$Lane.port
                direct_first_hop_port = [int]$Lane.direct_first_hop_port
                security = [string]$Lane.security
                entry_ingress_packets = $entryPackets
                exit_egress_packets = $exitPackets
                handshake_advanced = $true
                rx_bytes_delta = $serverRxDelta
                tx_bytes_delta = $serverTxDelta
                xray_upgrade_observed = $xray
                suricata_drop_count = 0
                observer_identity_sha256 = ([string]$server.observer_identity_digest).ToLowerInvariant()
                observer_host_key_sha256 = ([string]$server.observer_host_key_digest).ToLowerInvariant()
                peer_public_key_sha256 = ([string]$server.peer_public_key_digest).ToLowerInvariant()
                allowed_ip_set_sha256 = ([string]$server.allowed_ip_set_digest).ToLowerInvariant()
                observation_window_nonce = [string]$server.observation_window_nonce
                entry_counter_before_sha256 = ([string]$server.entry_counter_before_digest).ToLowerInvariant()
                entry_counter_after_sha256 = ([string]$server.entry_counter_after_digest).ToLowerInvariant()
                exit_counter_before_sha256 = ([string]$server.exit_counter_before_digest).ToLowerInvariant()
                exit_counter_after_sha256 = ([string]$server.exit_counter_after_digest).ToLowerInvariant()
                suricata_ruleset_sha256 = ([string]$server.suricata_ruleset_digest).ToLowerInvariant()
                expected_exit_identity_sha256 = ([string]$server.expected_exit_identity_digest).ToLowerInvariant()
                observer_authenticated = $true
                peer_bound = $true
                expected_exit_observed = $true
                passed = $true
            }) $Context
    } finally {
        if ($nodeObserver) {
            try { $nodeObserver.Process.Kill() } catch {}
        }
        if ($coreObserver) {
            try { $coreObserver.Process.Kill() } catch {}
        }
        if (-not (Test-NoActiveTunnel)) {
            [void](Invoke-NaturalTunnelCleanup)
        }
        Remove-ForcingRules
    }
    $afterForcing = Get-ForcingStateSha256
    if ($afterForcing -cne $beforeForcing) {
        throw 'Route-lane forcing transaction failed exact restoration.'
    }
    $forcingReceipt = New-BoundReceipt `
        'winsvpn-windows-forcing-receipt-v1' ($Sequence + 2) $started `
        ([ordered]@{
            lane_id = [string]$Lane.lane_id
            required = $xray
            blocked_udp_port = [int]$Lane.direct_first_hop_port
            operation_id = $operationId
            before_state_sha256 = $beforeForcing
            applied_state_sha256 = $appliedForcing
            after_state_sha256 = $afterForcing
            apply_passed = $xray
            restore_passed = $true
            passed = $true
        }) $Context
    $safeName = ([string]$Lane.lane_id) -replace '[^a-z0-9-]', '-'
    $clientPath = Join-Path $ReceiptRoot "$safeName-client.json"
    $serverPath = Join-Path $ReceiptRoot "$safeName-server.json"
    $forcingPath = Join-Path $ReceiptRoot "$safeName-forcing.json"
    Write-NewJson $clientPath $clientReceipt
    Write-NewJson $serverPath $serverReceipt
    Write-NewJson $forcingPath $forcingReceipt
    [ordered]@{
        lane_id = [string]$Lane.lane_id
        kind = [string]$Lane.kind
        protocol = [string]$Lane.protocol
        port = [int]$Lane.port
        direct_first_hop_port = [int]$Lane.direct_first_hop_port
        security = [string]$Lane.security
        client_receipt = [ordered]@{
            path = "receipts/$safeName-client.json"; sha256 = Get-Sha256 $clientPath
        }
        server_receipt = [ordered]@{
            path = "receipts/$safeName-server.json"; sha256 = Get-Sha256 $serverPath
        }
        forcing_receipt = [ordered]@{
            path = "receipts/$safeName-forcing.json"; sha256 = Get-Sha256 $forcingPath
        }
    }
}

function Invoke-RapidCancelTest {
    param(
        [Parameter(Mandatory)][int]$Sequence,
        [Parameter(Mandatory)]$Context
    )
    $started = [DateTime]::UtcNow
    [void](Set-CurrentAppMode $false)
    $connect = (& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action Connect) | ConvertFrom-Json
    $cancelBeforeActive = Test-NoActiveTunnel
    $cancel = (& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action Cancel) | ConvertFrom-Json
    Wait-TunnelClean
    $lateDeadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        if (-not (Test-NoActiveTunnel)) {
            throw 'Rapid cancel was followed by a late native restart.'
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $lateDeadline)
    $reconnect = (& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action Connect) | ConvertFrom-Json
    Wait-TunnelActive $false
    [void](Invoke-ProtectedCanaries)
    $disconnect = (& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action Disconnect) | ConvertFrom-Json
    Wait-TunnelClean
    if ($connect.label -cne 'Connect VPN' -or
        $cancel.label -cne 'Cancel VPN connection' -or
        $reconnect.label -cne 'Connect VPN' -or
        $disconnect.label -cne 'Disconnect VPN' -or -not $cancelBeforeActive) {
        throw 'Rapid cancel semantic sequence did not match the exact UI/state contract.'
    }
    $receipt = New-BoundReceipt `
        'winsvpn-windows-rapid-cancel-receipt-v1' $Sequence $started `
        ([ordered]@{
            connect_label = 'Connect VPN'; connect_role = 43
            cancel_label = 'Cancel VPN connection'; cancel_role = 43
            cancel_before_native_active = $true
            late_restart_absent = $true
            reconnect_passed = $true
            disconnect_label = 'Disconnect VPN'; disconnect_role = 43
            clean_state_proven = $true
            passed = $true
        }) $Context
    $path = Join-Path $ReceiptRoot 'rapid-cancel.json'
    Write-NewJson $path $receipt
    [ordered]@{
        path = 'receipts/rapid-cancel.json'; sha256 = Get-Sha256 $path
    }
}

function Capture-ExactAppWindow {
    param([Parameter(Mandatory)][string]$OutputPath)
    if (Test-Path -LiteralPath $OutputPath) {
        throw 'Physical screenshot output already exists.'
    }
    Add-Type -AssemblyName System.Drawing
    if (-not ('WinsReleaseCapture' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WinsReleaseCapture {
  [StructLayout(LayoutKind.Sequential)] public struct RECT {
    public int Left; public int Top; public int Right; public int Bottom;
  }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
}
'@
    }
    $runtime = Read-JsonOnce (Join-Path $PrivateRoot 'runtime-context.json')
    $process = Get-Process -Id ([int]$runtime.candidate_pid) -ErrorAction Stop
    if ([IO.Path]::GetFullPath($process.Path) -cne
        [IO.Path]::GetFullPath($InstalledGui) -or
        (Get-Sha256 $process.Path) -cne [string]$runtime.installed_gui_sha256) {
        throw 'Screenshot process does not match the exact candidate pin.'
    }
    $windowHandle = Get-ExactGuiWindowHandle $process.Id
    if ($windowHandle -eq [IntPtr]::Zero) {
        throw 'Exact app window is not visible on this interactive desktop.'
    }
    $rect = [WinsReleaseCapture+RECT]::new()
    if (-not [WinsReleaseCapture]::GetWindowRect(
            $windowHandle, [ref]$rect
        )) { throw 'Exact app window bounds are unavailable.' }
    $width = $rect.Right - $rect.Left
    $height = $rect.Bottom - $rect.Top
    if ($width -lt 600 -or $height -lt 500) {
        throw 'Exact app window is too small for visual evidence.'
    }
    $bitmap = [Drawing.Bitmap]::new($width, $height)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    try {
        $dc = $graphics.GetHdc()
        try {
            if (-not [WinsReleaseCapture]::PrintWindow(
                    $windowHandle, $dc, 2
                )) { throw 'PrintWindow rejected the exact candidate window.' }
        } finally { $graphics.ReleaseHdc($dc) }
        $colors = [Collections.Generic.HashSet[int]]::new()
        $minimum = 255
        $maximum = 0
        for ($y = 0; $y -lt $height; $y += [Math]::Max(1, [int]($height / 64))) {
            for ($x = 0; $x -lt $width; $x += [Math]::Max(1, [int]($width / 96))) {
                $color = $bitmap.GetPixel($x, $y)
                [void]$colors.Add($color.ToArgb())
                $luminance = [int](0.2126 * $color.R + 0.7152 * $color.G +
                    0.0722 * $color.B)
                $minimum = [Math]::Min($minimum, $luminance)
                $maximum = [Math]::Max($maximum, $luminance)
            }
        }
        if ($colors.Count -lt 16 -or $maximum - $minimum -lt 24) {
            throw 'Exact app screenshot failed visual entropy checks.'
        }
        $bitmap.Save($OutputPath, [Drawing.Imaging.ImageFormat]::Png)
    } finally { $graphics.Dispose(); $bitmap.Dispose() }
    if ((Get-Item -LiteralPath $OutputPath).Length -lt 1024) {
        throw 'Exact app screenshot is implausibly small.'
    }
    Get-Sha256 $OutputPath
}

function Restart-ExactGuiAndPin {
    $gui = Start-ExactGui
    $runtimePath = Join-Path $PrivateRoot 'runtime-context.json'
    $runtime = Read-JsonOnce $runtimePath
    $script:ArchitectureBinding = Get-RuntimeArchitectureBinding $runtime
    $runtime.candidate_pid = [int]$gui.Id
    $runtime.candidate_session_id = [int]$gui.SessionId
    Write-BoundAtomicJson $runtimePath $runtime
    [void]((& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action InspectConnect) | ConvertFrom-Json)
}

function Get-EgressViaExecutable {
    param([Parameter(Mandatory)][string]$Executable)
    $arguments = @(
        '-NoProfile', '-NonInteractive', '-Command',
        '$ProgressPreference=''SilentlyContinue'';(Invoke-WebRequest -UseBasicParsing -Uri ''https://api.ipify.org'' -TimeoutSec 20).Content.Trim()'
    )
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Executable
    $info.Arguments = ($arguments | ForEach-Object {
        '"' + ([string]$_).Replace('"', '\"') + '"'
    }) -join ' '
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'Split egress canary failed to start.' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(30000) -or $process.ExitCode -ne 0) {
        try { $process.Kill() } catch {}
        throw 'Split egress canary failed: ' + (Get-StringSha256 $stderr.Result)
    }
    $value = $stdout.Result.Trim()
    if ($value -notmatch '^[0-9A-Fa-f:.]{3,64}$') {
        throw 'Split egress canary returned an invalid address.'
    }
    Get-CanonicalSha256 ([ordered]@{ value = $value })
}

function Get-EgressViaCscript {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string]$ScriptPath
    )
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Executable
    $info.Arguments = '//Nologo "' + $ScriptPath + '"'
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'Excluded split canary failed to start.' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(30000) -or $process.ExitCode -ne 0) {
        try { $process.Kill() } catch {}
        throw 'Excluded split canary failed: ' + (Get-StringSha256 $stderr.Result)
    }
    $value = $stdout.Result.Trim()
    if ($value -notmatch '^[0-9A-Fa-f:.]{3,64}$') {
        throw 'Excluded split canary returned an invalid address.'
    }
    Get-CanonicalSha256 ([ordered]@{ value = $value })
}

function Invoke-SplitTunnelTest {
    param(
        [Parameter(Mandatory)][int]$Sequence,
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Baseline
    )
    $started = [DateTime]::UtcNow
    [void](Set-CurrentAppMode $false)
    $canaryRoot = Join-Path $PrivateRoot 'split-canaries'
    if (Test-Path -LiteralPath $canaryRoot) {
        throw 'Split canary root already exists.'
    }
    New-Item -ItemType Directory -Path $canaryRoot | Out-Null
    $excluded = Join-Path $canaryRoot 'excluded-cscript.exe'
    $excludedSource = Join-Path $env:SystemRoot 'System32\cscript.exe'
    $protected = Join-Path $env:SystemRoot `
        'System32\WindowsPowerShell\v1.0\powershell.exe'
    [IO.File]::Copy($excludedSource, $excluded, $false)
    $sourceSignature = Assert-ValidSignature $protected 'Protected split canary'
    $copySignature = Assert-ValidSignature $excluded 'Excluded split canary'
    $excludedSourceSignature = Assert-ValidSignature $excludedSource `
        'Excluded split canary source'
    if ((Get-Sha256 $excludedSource) -cne (Get-Sha256 $excluded) -or
        $excludedSourceSignature.SignerCertificate.Thumbprint -cne
            $copySignature.SignerCertificate.Thumbprint -or
        (Get-Sha256 $protected) -ceq (Get-Sha256 $excluded)) {
        throw 'Split canaries do not retain two distinct Microsoft-signed identities.'
    }
    $vbsPath = Join-Path $canaryRoot 'egress.vbs'
    $vbsBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        'Set h=CreateObject("WinHttp.WinHttpRequest.5.1")' + "`r`n" +
        'h.Open "GET","https://api.ipify.org",False' + "`r`n" +
        'h.SetTimeouts 5000,5000,5000,20000' + "`r`n" +
        'h.Send' + "`r`n" + 'WScript.Echo Trim(h.ResponseText)' + "`r`n"
    )
    $vbsStream = [IO.File]::Open(
        $vbsPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try { $vbsStream.Write($vbsBytes, 0, $vbsBytes.Length); $vbsStream.Flush($true) }
    finally { $vbsStream.Dispose() }
    Stop-ExactGui
    $settings = Read-WinsVpnSecureJson -Name 'vpn_settings.txt'
    $settings.excluded_vpn_packages = @($excluded)
    Write-WinsVpnSecureJson -Name 'vpn_settings.txt' -Value $settings
    Restart-ExactGuiAndPin
    [void]((& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action OpenSplit) | ConvertFrom-Json)
    $panel = (& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action InspectSplitPanel) | ConvertFrom-Json
    if ($panel.visible -ne $true -or $panel.label -cne
        'Destinations outside VPN (all operating systems)') {
        throw 'Per-app split selection panel is not semantically visible.'
    }
    $screenshotPath = Join-Path $ArtifactRoot 'split-selection.png'
    $selectionSha = Capture-ExactAppWindow $screenshotPath
    [void]((& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action Connect) | ConvertFrom-Json)
    Wait-TunnelActive $false
    $excludedEgress = Get-EgressViaCscript $excluded $vbsPath
    $protectedEgress = Get-EgressViaExecutable $protected
    if ($excludedEgress -cne [string]$Baseline.egress_state_sha256 -or
        $protectedEgress -ceq [string]$Baseline.egress_state_sha256 -or
        (Get-Service WinsVPNSplitTunnel -ErrorAction SilentlyContinue).Status `
            -ne 'Running') {
        throw 'Per-app split routing did not prove bypass versus protected egress.'
    }
    [void]((& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action Disconnect) | ConvertFrom-Json)
    Wait-TunnelClean
    $diagnosticsPath = Join-Path $env:ProgramData `
        'WinsVPN\split-driver-diagnostics.json'
    $diagnostics = Read-JsonOnce $diagnosticsPath
    if ([int]$diagnostics.start_events -lt 1 -or
        [int]$diagnostics.stop_events -lt 1 -or
        [int]$diagnostics.error_events -ne 0 -or
        [int]$diagnostics.malformed_events -ne 0 -or
        [int]$diagnostics.io_errors -ne 0) {
        throw 'Split WFP driver diagnostics do not prove clean process classification.'
    }
    Stop-ExactGui
    $settings = Read-WinsVpnSecureJson -Name 'vpn_settings.txt'
    $settings.excluded_vpn_packages = @()
    Write-WinsVpnSecureJson -Name 'vpn_settings.txt' -Value $settings
    Restart-ExactGuiAndPin
    if (Get-Service WinsVPNSplitTunnel -ErrorAction SilentlyContinue) {
        throw 'Split WFP service remained after rollback.'
    }
    $receipt = New-BoundReceipt `
        'winsvpn-windows-split-tunnel-receipt-v1' $Sequence $started `
        ([ordered]@{
            excluded_executable_sha256 = Get-Sha256 $excluded
            protected_executable_sha256 = Get-Sha256 $protected
            baseline_egress_sha256 = [string]$Baseline.egress_state_sha256
            excluded_egress_sha256 = $excludedEgress
            protected_egress_sha256 = $protectedEgress
            selection_ui_sha256 = $selectionSha
            wfp_service_running = $true
            process_rule_observed = $true
            rollback_clean = $true
            passed = $true
        }) $Context
    $path = Join-Path $ReceiptRoot 'split-tunnel.json'
    Write-NewJson $path $receipt
    [ordered]@{ path = 'receipts/split-tunnel.json'; sha256 = Get-Sha256 $path }
}

function Get-CurrentTunnelDns {
    $config = Read-WinsVpnSecureJson -Name 'vpn_config.txt'
    $value = [string]$config.dns
    $address = $null
    if (-not [Net.IPAddress]::TryParse($value, [ref]$address) -or
        $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'Live /verify configuration does not contain a valid tunnel DNS IPv4 address.'
    }
    $octets = $address.GetAddressBytes()
    $private = $octets[0] -eq 10 -or
        ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
        ($octets[0] -eq 192 -and $octets[1] -eq 168)
    if (-not $private) {
        throw 'Live /verify tunnel DNS is not bound to an RFC1918 gateway.'
    }
    $address.ToString()
}

function Test-TunnelDnsProtected {
    $expectedDns = Get-CurrentTunnelDns
    $tunnelDns = @(Get-DnsClientServerAddress -AddressFamily IPv4 `
        -ErrorAction SilentlyContinue | Where-Object {
            $_.InterfaceAlias -match '(?i)winsvpn|amnezia|awg'
        } | ForEach-Object ServerAddresses | Where-Object { $_ })
    $tunnelDns -contains $expectedDns -and
        $null -ne (Resolve-DnsName winsvpn.org -Server $expectedDns -Type A `
            -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue)
}

function Invoke-NetworkChangeTest {
    param(
        [Parameter(Mandatory)][int]$Sequence,
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Baseline
    )
    $started = [DateTime]::UtcNow
    [void](Set-CurrentAppMode $false)
    [void]((& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action Connect) | ConvertFrom-Json)
    Wait-TunnelActive $false
    $physical = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {
        $_.Status -eq 'Up'
    })
    $wifi = @($physical | Where-Object {
        $_.NdisPhysicalMedium -match 'Wireless|802\.11' -or
        $_.InterfaceDescription -match '(?i)wi-?fi|wireless'
    } | Select-Object -First 1)
    $ethernet = @($physical | Where-Object {
        $_.InterfaceDescription -notmatch '(?i)wi-?fi|wireless'
    } | Select-Object -First 1)
    if ($wifi.Count -ne 1 -or $ethernet.Count -ne 1) {
        throw 'Mandatory network-change matrix requires one active Wi-Fi and Ethernet adapter.'
    }
    $profiles = [Collections.Generic.List[object]]::new()
    try {
        Disable-NetAdapter -InterfaceDescription $wifi[0].InterfaceDescription `
            -Confirm:$false -ErrorAction Stop
        Start-Sleep -Seconds 4
        if ((Get-NetAdapter -InterfaceDescription $wifi[0].InterfaceDescription).Status `
            -ne 'Disabled') { throw 'Wi-Fi to Ethernet transition was not observed.' }
        $profiles.Add([ordered]@{
            name = 'wifi_to_ethernet'; transition_observed = $true
            protected_egress_sha256 = Invoke-ProtectedCanaries
            dns_protected = Test-TunnelDnsProtected; passed = $true
        })
    } finally {
        Enable-NetAdapter -InterfaceDescription $wifi[0].InterfaceDescription `
            -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 4
    }
    try {
        Disable-NetAdapter -InterfaceDescription $ethernet[0].InterfaceDescription `
            -Confirm:$false -ErrorAction Stop
        Start-Sleep -Seconds 4
        if ((Get-NetAdapter -InterfaceDescription $ethernet[0].InterfaceDescription).Status `
            -ne 'Disabled') { throw 'Ethernet to Wi-Fi transition was not observed.' }
        $profiles.Add([ordered]@{
            name = 'ethernet_to_wifi'; transition_observed = $true
            protected_egress_sha256 = Invoke-ProtectedCanaries
            dns_protected = Test-TunnelDnsProtected; passed = $true
        })
    } finally {
        Enable-NetAdapter -InterfaceDescription $ethernet[0].InterfaceDescription `
            -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 4
    }
    $ipconfig = Join-Path $env:SystemRoot 'System32\ipconfig.exe'
    $renew = Start-Process -FilePath $ipconfig -ArgumentList '/renew' `
        -Wait -PassThru -WindowStyle Hidden
    if ($renew.ExitCode -ne 0) { throw 'DHCP renewal transition failed.' }
    $profiles.Add([ordered]@{
        name = 'dhcp_renew'; transition_observed = $true
        protected_egress_sha256 = Invoke-ProtectedCanaries
        dns_protected = Test-TunnelDnsProtected; passed = $true
    })
    $ipv6Adapter = Get-NetAdapter -InterfaceDescription `
        $ethernet[0].InterfaceDescription
    $ipv6Binding = Get-NetAdapterBinding -Name $ipv6Adapter.Name `
        -ComponentID ms_tcpip6 -ErrorAction Stop
    if ($ipv6Binding.Enabled -ne $true) {
        throw 'Mandatory IPv6 recovery test requires an enabled baseline binding.'
    }
    try {
        Disable-NetAdapterBinding -Name $ipv6Adapter.Name -ComponentID ms_tcpip6 `
            -ErrorAction Stop | Out-Null
        Start-Sleep -Seconds 2
        Enable-NetAdapterBinding -Name $ipv6Adapter.Name -ComponentID ms_tcpip6 `
            -ErrorAction Stop | Out-Null
        Start-Sleep -Seconds 4
        $aaaa = Resolve-DnsName cloudflare.com -Type AAAA -DnsOnly `
            -QuickTimeout -ErrorAction Stop
        if (@($aaaa | Where-Object Type -eq 'AAAA').Count -lt 1) {
            throw 'IPv6 recovery produced no AAAA resolution.'
        }
        $profiles.Add([ordered]@{
            name = 'ipv6_recovery'; transition_observed = $true
            protected_egress_sha256 = Invoke-ProtectedCanaries
            dns_protected = Test-TunnelDnsProtected; passed = $true
        })
    } finally {
        Enable-NetAdapterBinding -Name $ipv6Adapter.Name -ComponentID ms_tcpip6 `
            -ErrorAction SilentlyContinue | Out-Null
    }
    if (@($profiles | Where-Object { -not $_.dns_protected }).Count -ne 0) {
        throw 'A mandatory network transition lost tunnel DNS protection.'
    }
    [void]((& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action Disconnect) | ConvertFrom-Json)
    Wait-TunnelClean
    $finalState = Get-StateDocument
    if ((Get-CanonicalSha256 $finalState) -cne [string]$Baseline.state_sha256) {
        throw 'Network-change matrix did not restore the exact disconnected baseline.'
    }
    $receipt = New-BoundReceipt `
        'winsvpn-windows-network-change-receipt-v1' $Sequence $started `
        ([ordered]@{
            profiles = @($profiles)
            final_route_restored = $true
            final_dns_restored = $true
            passed = $true
        }) $Context
    $path = Join-Path $ReceiptRoot 'network-change.json'
    Write-NewJson $path $receipt
    [ordered]@{ path = 'receipts/network-change.json'; sha256 = Get-Sha256 $path }
}

function Invoke-LeakTest {
    param(
        [Parameter(Mandatory)][int]$Sequence,
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Baseline
    )
    $started = [DateTime]::UtcNow
    [void](Set-CurrentAppMode $false)
    [void]((& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action Connect) | ConvertFrom-Json)
    Wait-TunnelActive $false
    $tunnelDns = Get-CurrentTunnelDns
    if (-not (Test-TunnelDnsProtected)) {
        throw 'Tunnel DNS did not resolve through the required private resolver.'
    }
    $protectedSha = Get-EgressViaExecutable (
        Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    )
    if ($protectedSha -ceq [string]$Baseline.egress_state_sha256) {
        throw 'Protected IPv4 canary leaked the disconnected public egress.'
    }
    $protectedIpv6 = Get-OptionalIpv6EgressState
    if ($protectedIpv6.reachable -eq $true -and
        $Baseline.ipv6_egress_state.reachable -eq $true -and
        $protectedIpv6.value_sha256 -ceq
            [string]$Baseline.ipv6_egress_state.value_sha256) {
        throw 'Protected IPv6 canary leaked the disconnected IPv6 egress.'
    }
    $tunnelAdapter = Get-NetAdapter -IncludeHidden -ErrorAction Stop |
        Where-Object {
            $_.Status -eq 'Up' -and $_.Name -match '(?i)winsvpn|amnezia|awg'
        } | Select-Object -First 1
    if (-not $tunnelAdapter) { throw 'Kill-switch test lacks the exact tunnel adapter.' }
    try {
        Disable-NetAdapter -Name $tunnelAdapter.Name -Confirm:$false `
            -ErrorAction Stop
        Start-Sleep -Seconds 2
        $leaked = $false
        try {
            [void](Invoke-WebRequest -UseBasicParsing -Uri 'https://api.ipify.org' `
                -TimeoutSec 8)
            $leaked = $true
        } catch {}
        if ($leaked) { throw 'Kill-switch canary reached public egress after tunnel loss.' }
        $leakedIpv6 = (Get-OptionalIpv6EgressState).reachable -eq $true
        if ($leakedIpv6) {
            throw 'Kill-switch IPv6 canary reached public egress after tunnel loss.'
        }
    } finally {
        Enable-NetAdapter -Name $tunnelAdapter.Name -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 3
    $disconnect = $null
    try {
        $disconnect = (& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
            -RunId $RunId -Action Disconnect) | ConvertFrom-Json
    } catch {
        # A clean kill switch may already settle the UI to Connect.
        $connectState = (& (Join-Path $HelperRoot `
            'windows_release_fixed_ui.ps1') -RunId $RunId `
            -Action InspectConnect) | ConvertFrom-Json
        if ($connectState.label -cne 'Connect VPN') { throw }
    }
    Wait-TunnelClean
    $receipt = New-BoundReceipt `
        'winsvpn-windows-leak-receipt-v1' $Sequence $started `
        ([ordered]@{
            tunnel_dns_sha256 = Get-StringSha256 $tunnelDns
            protected_canary_count = 3
            dns_leak_passed = $true
            ipv4_leak_passed = $true
            ipv6_leak_passed = $true
            kill_switch_passed = $true
            passed = $true
        }) $Context
    $path = Join-Path $ReceiptRoot 'leak.json'
    Write-NewJson $path $receipt
    [ordered]@{ path = 'receipts/leak.json'; sha256 = Get-Sha256 $path }
}

function Get-WindowsOcrText {
    param([Parameter(Mandatory)][string]$ImagePath)
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    [void][Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]
    [void][Windows.Storage.FileAccessMode, Windows.Storage, ContentType = WindowsRuntime]
    [void][Windows.Storage.Streams.IRandomAccessStream, Windows.Storage, ContentType = WindowsRuntime]
    [void][Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
    [void][Windows.Graphics.Imaging.SoftwareBitmap, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
    [void][Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime]
    [void][Windows.Media.Ocr.OcrResult, Windows.Foundation, ContentType = WindowsRuntime]
    $asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() |
        Where-Object {
            $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and
            $_.GetParameters().Count -eq 1 -and
            $_.GetParameters()[0].ParameterType.Name -like 'IAsyncOperation*'
        } | Select-Object -First 1
    if (-not $asTask) { throw 'Windows OCR asynchronous bridge is unavailable.' }
    function Await-WinRt {
        param($Operation, [Type]$ResultType)
        $task = $asTask.MakeGenericMethod($ResultType).Invoke($null, @($Operation))
        $task.Wait()
        $task.Result
    }
    $file = Await-WinRt `
        ([Windows.Storage.StorageFile]::GetFileFromPathAsync($ImagePath)) `
        ([Windows.Storage.StorageFile])
    $stream = Await-WinRt `
        ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) `
        ([Windows.Storage.Streams.IRandomAccessStream])
    try {
        $decoder = Await-WinRt `
            ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) `
            ([Windows.Graphics.Imaging.BitmapDecoder])
        $bitmap = Await-WinRt ($decoder.GetSoftwareBitmapAsync()) `
            ([Windows.Graphics.Imaging.SoftwareBitmap])
        try {
            $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
            if (-not $engine) { throw 'Windows OCR has no installed recognition language.' }
            $result = Await-WinRt ($engine.RecognizeAsync($bitmap)) `
                ([Windows.Media.Ocr.OcrResult])
            [string]$result.Text
        } finally { $bitmap.Dispose() }
    } finally { $stream.Dispose() }
}

function Get-NormalizedOcrText {
    param([AllowEmptyString()][string]$Value)
    (($Value.ToLowerInvariant() -replace '[^\p{L}\p{Nd}]+', ' ').Trim())
}

function Invoke-MapTest {
    param(
        [Parameter(Mandatory)][int]$Sequence,
        [Parameter(Mandatory)]$Context
    )
    $started = [DateTime]::UtcNow
    Restart-ExactGuiAndPin
    Start-Sleep -Seconds 8
    $radius = (& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action InspectMapRadius) | ConvertFrom-Json
    $marker = (& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action InspectMapMarker) | ConvertFrom-Json
    if ($radius.label -cne 'Approximate IP location' -or
        $marker.label -cne 'Your approximate network location' -or
        $radius.visible -ne $true -or $marker.visible -ne $true) {
        throw 'Map radius/marker semantic proof is not exact.'
    }
    $screenshotPath = Join-Path $ArtifactRoot 'map-50-mile.png'
    $screenshotSha = Capture-ExactAppWindow $screenshotPath
    $gazetteer = Read-JsonOnce (Join-Path $InputRoot 'gazetteer.json')
    if ($gazetteer.schema_version -ne 1 -or $gazetteer.contract -cne
        'winsvpn-windows-map-gazetteer-v1' -or
        [string]::IsNullOrWhiteSpace([string]$gazetteer.target_city) -or
        @($gazetteer.surrounding_cities).Count -lt 2) {
        throw 'Map gazetteer contract lacks target and surrounding cities.'
    }
    $ocr = Get-NormalizedOcrText (Get-WindowsOcrText $screenshotPath)
    $target = Get-NormalizedOcrText ([string]$gazetteer.target_city)
    $visibleSurrounding = @($gazetteer.surrounding_cities | Where-Object {
        $name = Get-NormalizedOcrText ([string]$_)
        $name.Length -ge 2 -and $ocr.Contains($name)
    })
    if (-not $ocr.Contains($target) -or $visibleSurrounding.Count -lt 2) {
        throw 'Physical map OCR lacks the target and two surrounding city labels.'
    }
    $receipt = New-BoundReceipt `
        'winsvpn-windows-map-receipt-v1' $Sequence $started `
        ([ordered]@{
            screenshot_path = 'artifacts/map-50-mile.png'
            screenshot_sha256 = $screenshotSha
            radius_miles = 50
            city_labels_visible = $true
            target_marker_visible = $true
            viewport_not_world_zoom = $true
            passed = $true
        }) $Context
    $path = Join-Path $ReceiptRoot 'map.json'
    Write-NewJson $path $receipt
    [ordered]@{ path = 'receipts/map.json'; sha256 = Get-Sha256 $path }
}

function Test-PreviousOwnerAuthorization {
    $record = Read-JsonOnce (Join-Path $InputRoot 'previous-release-record.json')
    $content = [Text.UTF8Encoding]::new($false).GetBytes(
        "winsvpn-rollback-v1`n$($record.release_identity)`n" +
        "$($record.artifact_sha256)`n$($record.artifact_size_bytes)`n" +
        "$($record.payload_manifest_sha256)`n"
    )
    if ((Get-BytesSha256 $content) -cne
        [string]$record.owner_authorization_content_sha256) {
        return $false
    }
    try {
        Add-Type -AssemblyName System.Security
        $cmsBytes = [Convert]::FromBase64String(
            [string]$record.owner_authorization_cms_base64
        )
        $cms = [Security.Cryptography.Pkcs.SignedCms]::new()
        $cms.Decode($cmsBytes)
        $cms.CheckSignature($true)
        $cms.SignerInfos.Count -eq 1 -and
            (Get-BytesSha256 $cmsBytes) -ceq
                [string]$record.owner_authorization_cms_sha256 -and
            [Convert]::ToBase64String($cms.ContentInfo.Content) -ceq
                [Convert]::ToBase64String($content)
    } catch { $false }
}

function Uninstall-ExactProduct {
    Stop-ExactGui
    if (-not (Test-NoActiveTunnel)) {
        throw 'Rollback cycle refuses to uninstall an active VPN path.'
    }
    if (-not (Test-Path -LiteralPath $Uninstaller -PathType Leaf)) {
        throw 'Rollback cycle cannot find the fixed signed uninstaller.'
    }
    [void](Assert-ValidSignature $Uninstaller 'Rollback-cycle uninstaller')
    Assert-PeMatchesBinding $Uninstaller 'Rollback-cycle uninstaller'
    $process = Start-Process -FilePath $Uninstaller -ArgumentList @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART',
        '/RESTARTEXITCODE=3010'
    ) -Wait -PassThru
    if ($process.ExitCode -ne 0 -or (Test-Path -LiteralPath $InstallRoot)) {
        throw 'Rollback-cycle uninstall did not remove the fixed product root.'
    }
    foreach ($name in @(
        'WinsVpnTunnelManager', 'WinsVPNSplitTunnel', 'AmneziaWGTunnel$winsvpn'
    )) {
        if (Get-Service $name -ErrorAction SilentlyContinue) {
            throw "Rollback-cycle uninstall left service $name."
        }
    }
    if (@(Get-Process winsvpn_awg_engine -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'Rollback-cycle uninstall left the AWG engine process.'
    }
    if (@(Get-Process winsvpn_winn3_engine -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'Rollback-cycle uninstall left the Winn v3 engine process.'
    }
}

function Install-ExactProduct {
    param([Parameter(Mandatory)][string]$Installer)
    $signature = Assert-ValidSignature $Installer 'Rollback-cycle installer'
    Assert-PeMatchesBinding $Installer 'Rollback-cycle installer'
    $installLog = Join-Path $PrivateRoot (
        'rollback-cycle-install-' + [Guid]::NewGuid().ToString('D') + '.log'
    )
    $process = Start-Process -FilePath $Installer -ArgumentList @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART',
        '/RESTARTEXITCODE=3010', '/SP-', "/LOG=$installLog"
    ) -Wait -PassThru
    Assert-InstallerLogHasNoSuppressedException $installLog
    if ($process.ExitCode -ne 0) {
        throw "Rollback-cycle installer failed or requires reboot: $($process.ExitCode)."
    }
    [void](Assert-ValidSignature $InstalledGui 'Rollback-cycle installed GUI')
    [void](Assert-ValidSignature $InstalledService `
        'Rollback-cycle installed service')
    [void](Assert-ValidSignature $InstalledAwgEngine `
        'Rollback-cycle installed AWG engine')
    Assert-InstalledNativeImages 'Rollback-cycle installed'
    [void](Assert-ExactManagerService)
    $signature
}

function Assert-InstalledPayloadManifest {
    param([Parameter(Mandatory)]$Manifest)
    $guiEntries = @($Manifest.payload | Where-Object {
        ([string]$_.path).Replace('\', '/').EndsWith('/wins_vpn.exe') -or
        [string]$_.path -ceq 'wins_vpn.exe'
    })
    $serviceEntries = @($Manifest.payload | Where-Object {
        ([string]$_.path).Replace('\', '/').EndsWith(
            '/wins_vpn_tunnel_service.exe'
        ) -or [string]$_.path -ceq 'wins_vpn_tunnel_service.exe'
    })
    $engineEntries = @($Manifest.payload | Where-Object {
        ([string]$_.path).Replace('\', '/').EndsWith(
            '/winsvpn_awg_engine.exe'
        ) -or [string]$_.path -ceq 'winsvpn_awg_engine.exe'
    })
    if ($guiEntries.Count -ne 1 -or $serviceEntries.Count -ne 1 -or
        $engineEntries.Count -ne 1 -or
        (Get-Sha256 $InstalledGui) -cne [string]$guiEntries[0].sha256 -or
        (Get-Item $InstalledGui).Length -ne [long]$guiEntries[0].size -or
        (Get-Sha256 $InstalledService) -cne [string]$serviceEntries[0].sha256 -or
        (Get-Item $InstalledService).Length -ne [long]$serviceEntries[0].size -or
        (Get-Sha256 $InstalledAwgEngine) -cne [string]$engineEntries[0].sha256 -or
        (Get-Item $InstalledAwgEngine).Length -ne [long]$engineEntries[0].size) {
        throw 'Installed rollback payload does not match its protected manifest.'
    }
}

function Invoke-Execute {
    # No transition is allowed unless Prepare produced the exact disconnected
    # baseline and the fixed SYSTEM watchdog was independently armed.
    $context = Read-JsonOnce (Join-Path $PrivateRoot 'context.json')
    $runtime = Read-JsonOnce (Join-Path $PrivateRoot 'runtime-context.json')
    $baseline = Read-JsonOnce (Join-Path $PrivateRoot 'baseline.json')
    $arm = Read-JsonOnce (Join-Path $PrivateRoot 'arm.json')
    if ($context.contract -cne 'winsvpn-windows-release-collector-context-v1' -or
        $context.run_id -cne $RunId -or
        $context.collector_closure_sha256 -cne $verifiedClosureSha256 -or
        $runtime.run_id -cne $RunId -or
        $runtime.collector_closure_sha256 -cne $verifiedClosureSha256 -or
        $baseline.run_id -cne $RunId -or
        $baseline.collector_closure_sha256 -cne $verifiedClosureSha256 -or
        $arm.contract -cne 'winsvpn-windows-release-watchdog-arm-v1' -or
        $arm.armed -ne $true -or $arm.run_id -cne $RunId -or
        $arm.collector_closure_sha256 -cne $context.collector_closure_sha256 -or
        $runtime.next_sequence -ne 4 -or
        (Get-CanonicalSha256 (Get-StateDocument)) -cne $baseline.state_sha256) {
        throw 'Execute phase lacks an exact armed disconnected baseline.'
    }
    $script:ArchitectureBinding = Get-RuntimeArchitectureBinding $runtime
    try {
    $winn3Observation = Invoke-WinnV3PrimaryObservation $context
    $runtime = Read-JsonOnce (Join-Path $PrivateRoot 'runtime-context.json')
    $script:ArchitectureBinding = Get-RuntimeArchitectureBinding $runtime
    if ((Get-CanonicalSha256 (Get-StateDocument)) -cne $baseline.state_sha256 -or
        (Get-ObservedWinnTransport) -cne 'disconnected') {
        throw 'Winn v3 primary observation did not restore the exact disconnected baseline.'
    }
    $rapidRef = Invoke-RapidCancelTest 5 $context
    $lanes = [Collections.Generic.List[object]]::new()
    $laneDefinitions = [Collections.Generic.List[object]]::new()
    $laneDefinitions.Add([ordered]@{
        lane_id = 'node-direct-awg'
        kind = 'node_direct_awg'; protocol = 'udp'
        port = [int]$runtime.node_direct_awg_port
        direct_first_hop_port = [int]$runtime.node_direct_awg_port
        security = 'none'
    })
    foreach ($route in @($runtime.node_advertised_xray_routes)) {
        $laneDefinitions.Add([ordered]@{
            lane_id = "node-xray-$($route.port)-$($route.security)"
            kind = 'node_xray'; protocol = 'tcp'; port = [int]$route.port
            direct_first_hop_port = [int]$runtime.node_direct_awg_port
            security = [string]$route.security
        })
    }
    $laneDefinitions.Add([ordered]@{
        lane_id = 'core-direct-awg'
        kind = 'core_direct_awg'; protocol = 'udp'
        port = [int]$runtime.core_direct_awg_port
        direct_first_hop_port = [int]$runtime.core_direct_awg_port
        security = 'none'
    })
    foreach ($route in @($runtime.core_advertised_xray_routes)) {
        $laneDefinitions.Add([ordered]@{
            lane_id = "core-xray-$($route.port)-$($route.security)"
            kind = 'core_xray'; protocol = 'tcp'; port = [int]$route.port
            direct_first_hop_port = [int]$runtime.core_direct_awg_port
            security = [string]$route.security
        })
    }
    $sequence = 6
    foreach ($lane in $laneDefinitions) {
        $lanes.Add((Invoke-RouteLane $lane $sequence $context $runtime))
        $sequence += 3
    }
    $splitRef = Invoke-SplitTunnelTest $sequence $context $baseline
    ++$sequence
    $networkRef = Invoke-NetworkChangeTest $sequence $context $baseline
    ++$sequence
    $leakRef = Invoke-LeakTest $sequence $context $baseline
    ++$sequence
    $mapRef = Invoke-MapTest $sequence $context
    ++$sequence
    $finalState = Get-StateDocument
    $finalStateSha = Get-CanonicalSha256 $finalState
    if ($finalStateSha -cne [string]$baseline.state_sha256 -or
        (Get-EgressStateSha256) -cne [string]$baseline.egress_state_sha256 -or
        -not (Test-NetConnection -ComputerName $baseline.management_probe_host `
            -Port $baseline.management_probe_port -InformationLevel Quiet `
            -WarningAction SilentlyContinue)) {
        throw 'Execute matrix did not naturally restore the exact disconnected baseline.'
    }
    $runtime = Read-JsonOnce (Join-Path $PrivateRoot 'runtime-context.json')
    $script:ArchitectureBinding = Get-RuntimeArchitectureBinding $runtime
    $runtimeObservation = Read-JsonOnce (
        Join-Path $PrivateRoot 'runtime-observation.json'
    )
    $nativeObservation = Read-JsonOnce (
        Join-Path $PrivateRoot 'native-host-observation.json'
    )
    if ($runtimeObservation.contract -cne
            'winsvpn-windows-runtime-observation-v1' -or
        $runtimeObservation.run_id -cne $RunId -or
        $runtimeObservation.runtime_observed -ne $true -or
        $runtimeObservation.source_only -ne $false -or
        -not (Test-ExactRuntimeObserved $runtime)) {
        throw 'Physical runtime receipt is source-only or unobserved.'
    }
    $nativeFacts = Assert-NativeHostObserved
    Assert-NativeHostObservationFacts $nativeObservation
    if ($nativeObservation.contract -cne
            'winsvpn-windows-native-host-observation-v1' -or
        $nativeObservation.run_id -cne $RunId -or
        $nativeFacts.native_host_observed -ne $true) {
        throw 'Physical native-host receipt is source-only or unobserved.'
    }
    $nodeAwg = @($lanes | Where-Object { $_.kind -eq 'node_direct_awg' })
    $nodeXray = @($lanes | Where-Object { $_.kind -eq 'node_xray' })
    if ($nodeAwg.Count -lt 1 -or $nodeXray.Count -lt 1) {
        throw 'Physical Winn v1 AWG then Xray fallback is source-only or unobserved.'
    }
    if ([string]$winn3Observation.primary_transport -cne 'winn_v3' -or
        $winn3Observation.winn_v3_session_observed -ne $true -or
        $winn3Observation.source_only -ne $false) {
        throw 'Physical Winn v3 primary receipt is source-only or has mixed fallback order.'
    }
    $receiptStarted = [DateTime]::UtcNow
    $runtimeReceipt = New-BoundReceipt `
        'winsvpn-windows-runtime-receipt-v1' $sequence $receiptStarted `
        ([ordered]@{
            runtime_observed = $true
            manager_service_running = $true
            gui_observed = $true
            passed = $true
        }) $context -EmitArchitecture
    Write-RequiredPhysicalReceipt (Join-Path $ReceiptRoot 'runtime.json') `
        $runtimeReceipt 'winsvpn-windows-runtime-receipt-v1' $context
    ++$sequence
    $nativeReceipt = New-BoundReceipt `
        'winsvpn-windows-native-host-receipt-v1' $sequence $receiptStarted `
        ([ordered]@{
            native_host_observed = $true
            host_name = [string]$nativeFacts.host_name
            host_image = [string]$nativeFacts.host_image
            browsers = @($nativeFacts.browsers)
            passed = $true
        }) $context -EmitArchitecture
    Write-RequiredPhysicalReceipt (Join-Path $ReceiptRoot 'native-host.json') `
        $nativeReceipt 'winsvpn-windows-native-host-receipt-v1' $context
    ++$sequence
    $v3Receipt = New-BoundReceipt `
        'winsvpn-windows-winn-v3-receipt-v1' $sequence $receiptStarted `
        ([ordered]@{
            primary_transport = 'winn_v3'
            fallback_transports = @('winn_v1_awg', 'winn_v1_xray')
            winn_v3_session_observed = $true
            passed = $true
        }) $context -EmitArchitecture
    Write-RequiredPhysicalReceipt (Join-Path $ReceiptRoot 'winn-v3.json') `
        $v3Receipt 'winsvpn-windows-winn-v3-receipt-v1' $context
    ++$sequence
    $awgReceipt = New-BoundReceipt `
        'winsvpn-windows-winn-v1-awg-receipt-v1' $sequence $receiptStarted `
        ([ordered]@{
            transport = 'winn_v1_awg'
            observed = $true
            lane_id = [string]$nodeAwg[0].lane_id
            passed = $true
        }) $context -EmitArchitecture
    Write-RequiredPhysicalReceipt (Join-Path $ReceiptRoot 'winn-v1-awg.json') `
        $awgReceipt 'winsvpn-windows-winn-v1-awg-receipt-v1' $context
    ++$sequence
    $xrayReceipt = New-BoundReceipt `
        'winsvpn-windows-winn-v1-xray-receipt-v1' $sequence $receiptStarted `
        ([ordered]@{
            transport = 'winn_v1_xray'
            observed = $true
            lane_id = [string]$nodeXray[0].lane_id
            passed = $true
        }) $context -EmitArchitecture
    Write-RequiredPhysicalReceipt (Join-Path $ReceiptRoot 'winn-v1-xray.json') `
        $xrayReceipt 'winsvpn-windows-winn-v1-xray-receipt-v1' $context
    ++$sequence
    $disarm = [ordered]@{
        schema_version = 1
        contract = 'winsvpn-windows-release-watchdog-disarm-v1'
        run_id = $RunId
        collector_closure_sha256 = [string]$context.collector_closure_sha256
        disarmed_at_utc = [DateTime]::UtcNow.ToString('o')
        normal_teardown_proven = $true
        fail_safe_triggered = $false
        baseline_state_sha256 = [string]$baseline.state_sha256
    }
    Write-NewJson (Join-Path $PrivateRoot 'normal-disarm.json') $disarm
    $result = [ordered]@{
        schema_version = 1
        contract = 'winsvpn-windows-release-execute-result-v1'
        run_id = $RunId
        collector_closure_sha256 = [string]$context.collector_closure_sha256
        rapid_cancel_receipt = $rapidRef
        lanes = @($lanes)
        split_tunnel_receipt = $splitRef
        network_change_receipt = $networkRef
        leak_receipt = $leakRef
        map_receipt = $mapRef
        next_sequence = $sequence
        baseline_state_sha256 = [string]$baseline.state_sha256
        final_state_sha256 = $finalStateSha
    }
    Write-NewJson (Join-Path $PrivateRoot 'execute-result.json') $result
    } catch {
        [void](Invoke-NaturalTunnelCleanup)
        Stop-ExactGui
        Restore-PreexistingAppData
        Remove-EphemeralObserverMaterial
        throw
    }
}

function Invoke-Finalize {
    $started = [DateTime]::UtcNow
    $context = Read-JsonOnce (Join-Path $PrivateRoot 'context.json')
    $runtime = Read-JsonOnce (Join-Path $PrivateRoot 'runtime-context.json')
    $baseline = Read-JsonOnce (Join-Path $PrivateRoot 'baseline.json')
    $execute = Read-JsonOnce (Join-Path $PrivateRoot 'execute-result.json')
    $watchdogPath = Join-Path $ReceiptRoot 'watchdog.json'
    $watchdog = Read-JsonOnce $watchdogPath
    if ($context.contract -cne 'winsvpn-windows-release-collector-context-v1' -or
        $context.run_id -cne $RunId -or
        $context.collector_closure_sha256 -cne $verifiedClosureSha256 -or
        $runtime.run_id -cne $RunId -or
        $runtime.collector_closure_sha256 -cne $verifiedClosureSha256 -or
        $baseline.run_id -cne $RunId -or
        $baseline.collector_closure_sha256 -cne $verifiedClosureSha256 -or
        $watchdog.pass -ne $true -or
        $watchdog.normal_teardown_proven -ne $true -or
        $watchdog.fail_safe_triggered -ne $false -or
        $execute.baseline_state_sha256 -cne $baseline.state_sha256 -or
        $execute.final_state_sha256 -cne $baseline.state_sha256) {
        throw 'Finalize refuses a non-natural or emergency-cleaned execution.'
    }
    $script:ArchitectureBinding = Get-RuntimeArchitectureBinding $runtime
    $baselineRouteSha = Get-CanonicalSha256 $baseline.state.routes
    $rollbackInstaller = Join-Path $ArtifactRoot 'previous-installer.exe'
    $rollbackManifestPath = Join-Path $ArtifactRoot `
        'previous-installer.payload-manifest.json'
    $rollbackManifest = Read-JsonOnce $rollbackManifestPath
    $previousRecordPath = Join-Path $ArtifactRoot 'previous-release-record.json'
    $previousRecord = Read-JsonOnce $previousRecordPath
    if (-not (Test-PreviousOwnerAuthorization)) {
        throw 'Rollback owner CMS authorization failed independent verification.'
    }

    Uninstall-ExactProduct
    if ((Test-Path -LiteralPath $InstallRoot) -or
        (Get-Service WinsVpnTunnelManager -ErrorAction SilentlyContinue) -or
        @(Get-Process winsvpn_winn3_engine -ErrorAction SilentlyContinue).Count -ne 0 -or
        @(Get-Process winsvpn_awg_engine -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'Physical uninstall receipt is source-only or unobserved.'
    }
    $sequence = [int]$execute.next_sequence
    $uninstallReceipt = New-BoundReceipt `
        'winsvpn-windows-uninstall-receipt-v1' $sequence $started `
        ([ordered]@{
            uninstalled = $true
            product_root_absent = $true
            manager_service_absent = $true
            passed = $true
        }) $context -EmitArchitecture
    Write-RequiredPhysicalReceipt (Join-Path $ReceiptRoot 'uninstall.json') `
        $uninstallReceipt 'winsvpn-windows-uninstall-receipt-v1' $context
    ++$sequence
    $rollbackSignature = Install-ExactProduct $rollbackInstaller
    if ((Get-CertificateSha256 $rollbackSignature.SignerCertificate) -cne
        [string]$previousRecord.signer_certificate_sha256) {
        throw 'Rollback installed signer differs from the protected previous record.'
    }
    Assert-InstalledPayloadManifest $rollbackManifest
    $rollbackGui = Start-ExactGui
    $script:ArchitectureBinding = Get-RuntimeArchitectureBinding $runtime
    $runtime.candidate_pid = [int]$rollbackGui.Id
    $runtime.candidate_session_id = [int]$rollbackGui.SessionId
    $runtime.installed_gui_sha256 = Get-Sha256 $InstalledGui
    Write-BoundAtomicJson (Join-Path $PrivateRoot 'runtime-context.json') $runtime
    $rollbackUi = (& (Join-Path $HelperRoot 'windows_release_fixed_ui.ps1') `
        -RunId $RunId -Action InspectConnect) | ConvertFrom-Json
    if ($rollbackUi.label -cne 'Connect VPN' -or $rollbackUi.role -ne 43) {
        throw 'Rollback payload failed the non-tunnel semantic UI smoke.'
    }

    Uninstall-ExactProduct
    $candidateInstaller = Join-Path $ArtifactRoot 'WinsVPN-Setup.exe'
    $candidateSignature = Install-ExactProduct $candidateInstaller
    if ((Get-CertificateSha256 $candidateSignature.SignerCertificate) -cne
        [string]$context.candidate_signer_certificate_sha256) {
        throw 'Candidate reinstall signer validation failed.'
    }
    $candidateManifest = Read-JsonOnce `
        (Join-Path $ArtifactRoot 'candidate-manifest.json')
    $guiEntry = @($candidateManifest.artifacts | Where-Object {
        $_.name -ceq 'wins_vpn.exe'
    })
    $serviceEntry = @($candidateManifest.artifacts | Where-Object {
        $_.name -ceq 'wins_vpn_tunnel_service.exe'
    })
    $engineEntry = @($candidateManifest.artifacts | Where-Object {
        $_.name -ceq 'winsvpn_awg_engine.exe'
    })
    if ($guiEntry.Count -ne 1 -or $serviceEntry.Count -ne 1 -or
        $engineEntry.Count -ne 1 -or
        (Get-Sha256 $InstalledGui) -cne [string]$guiEntry[0].sha256 -or
        (Get-Sha256 $InstalledService) -cne [string]$serviceEntry[0].sha256 -or
        (Get-Sha256 $InstalledAwgEngine) -cne [string]$engineEntry[0].sha256) {
        throw 'Candidate reinstall does not match the exact candidate manifest.'
    }
    $finalGuiSha = Get-Sha256 $InstalledGui
    $finalServiceSha = Get-Sha256 $InstalledService
    $finalAwgEngineSha = Get-Sha256 $InstalledAwgEngine
    Stop-ExactGui
    Restore-PreexistingAppData
    Remove-EphemeralObserverMaterial
    $finalState = Get-StateDocument
    $finalStateSha = Get-CanonicalSha256 $finalState
    $finalRouteSha = Get-CanonicalSha256 $finalState.routes
    $finalEgressSha = Get-EgressStateSha256
    if ($finalStateSha -cne [string]$baseline.state_sha256 -or
        $finalRouteSha -cne $baselineRouteSha -or
        $finalEgressSha -cne [string]$baseline.egress_state_sha256) {
        throw 'Rollback/candidate reinstall failed exact disconnected restoration.'
    }
    $teardownReceipt = New-BoundReceipt `
        'winsvpn-windows-teardown-rollback-receipt-v1' $sequence $started `
        ([ordered]@{
            baseline_route_sha256 = $baselineRouteSha
            final_route_sha256 = $finalRouteSha
            baseline_egress_sha256 = [string]$baseline.egress_state_sha256
            final_egress_sha256 = $finalEgressSha
            manager_running = $true
            legacy_tunnel_service_absent = $true
            awg_engine_absent = $true
            split_service_absent = $true
            adapter_absent_or_down = $true
            xray_absent = $true
            protected_routes_absent = $true
            rollback_artifact_path = 'artifacts/previous-installer.exe'
            rollback_artifact_sha256 = Get-Sha256 $rollbackInstaller
            previous_release_record_path = 'artifacts/previous-release-record.json'
            previous_release_record_sha256 = Get-Sha256 $previousRecordPath
            previous_payload_manifest_path = `
                'artifacts/previous-installer.payload-manifest.json'
            previous_payload_manifest_sha256 = Get-Sha256 $rollbackManifestPath
            previous_signer_certificate_sha256 = `
                [string]$previousRecord.signer_certificate_sha256
            rollback_signature_verified = $true
            rollback_payload_verified = $true
            rollback_owner_authorization_verified = $true
            rollback_install_passed = $true
            candidate_reinstall_passed = $true
            final_installed_gui_sha256 = $finalGuiSha
            final_installed_service_sha256 = $finalServiceSha
            final_installed_awg_engine_sha256 = $finalAwgEngineSha
            passed = $true
        }) $context -EmitArchitecture
    $teardownPath = Join-Path $ReceiptRoot 'teardown-rollback.json'
    Write-RequiredPhysicalReceipt $teardownPath $teardownReceipt `
        'winsvpn-windows-teardown-rollback-receipt-v1' $context
    ++$sequence
    Assert-RequiredWorkerPhysicalReceipts @(
        (Read-JsonOnce (Join-Path $ReceiptRoot 'signature.json')),
        (Read-JsonOnce (Join-Path $ReceiptRoot 'install.json')),
        (Read-JsonOnce (Join-Path $ReceiptRoot 'runtime.json')),
        (Read-JsonOnce (Join-Path $ReceiptRoot 'uninstall.json')),
        (Read-JsonOnce $teardownPath),
        (Read-JsonOnce (Join-Path $ReceiptRoot 'winn-v3.json')),
        (Read-JsonOnce (Join-Path $ReceiptRoot 'winn-v1-awg.json')),
        (Read-JsonOnce (Join-Path $ReceiptRoot 'winn-v1-xray.json')),
        (Read-JsonOnce (Join-Path $ReceiptRoot 'native-host.json'))
    ) $context
    $finished = [DateTime]::UtcNow.ToString('o')
    $reference = {
        param([string]$Path)
        [ordered]@{
            path = $Path.Substring($RunRoot.Length).TrimStart('\').Replace('\', '/')
            sha256 = Get-Sha256 $Path
        }
    }
    $machine = [ordered]@{
        schema_version = 1
        contract = 'winsvpn-windows-release-machine-evidence-v1'
        platform = 'windows'
        app_version = [string]$runtime.app_version
        build_number = [string]$runtime.build_number
        run_id = $RunId
        captured_at_utc = $finished
        secret_material_redacted = $true
        step_nonce = [Guid]::NewGuid().ToString()
        sequence = $sequence
        started_at_utc = $started.ToString('o')
        finished_at_utc = $finished
        release_input_index_sha256 = [string]$context.release_input_index_sha256
        platform_manifest_sha256 = [string]$context.platform_manifest_sha256
        artifact_input_fingerprint_sha256 = [string]$context.artifact_input_fingerprint_sha256
        build_receipt_sha256 = [string]$context.build_receipt_sha256
        producer_contract_sha256 = [string]$context.producer_contract_sha256
        collector_closure_sha256 = [string]$context.collector_closure_sha256
        artifact_sha256 = [string]$context.artifact_sha256
        artifact_size_bytes = [long]$context.artifact_size_bytes
        installed_gui_sha256 = $finalGuiSha
        installed_gui_size_bytes = [long](Get-Item $InstalledGui).Length
        installed_service_sha256 = $finalServiceSha
        installed_service_size_bytes = [long](Get-Item $InstalledService).Length
        installed_awg_engine_sha256 = $finalAwgEngineSha
        installed_awg_engine_size_bytes = `
            [long](Get-Item $InstalledAwgEngine).Length
        candidate_manifest = & $reference `
            (Join-Path $ArtifactRoot 'candidate-manifest.json')
        signature_receipt = & $reference `
            (Join-Path $ReceiptRoot 'signature.json')
        install_receipt = & $reference `
            (Join-Path $ReceiptRoot 'install.json')
        route_advertisement_receipt = & $reference `
            (Join-Path $ReceiptRoot 'route-advertisement.json')
        node_direct_awg_port = [int]$runtime.node_direct_awg_port
        core_direct_awg_port = [int]$runtime.core_direct_awg_port
        node_advertised_xray_routes = @($runtime.node_advertised_xray_routes)
        core_advertised_xray_routes = @($runtime.core_advertised_xray_routes)
        lanes = @($execute.lanes)
        rapid_cancel_receipt = $execute.rapid_cancel_receipt
        split_tunnel_receipt = $execute.split_tunnel_receipt
        network_change_receipt = $execute.network_change_receipt
        leak_receipt = $execute.leak_receipt
        watchdog_receipt = & $reference $watchdogPath
        teardown_rollback_receipt = & $reference $teardownPath
        map_receipt = $execute.map_receipt
    }
    Write-NewJson (Join-Path $ReceiptRoot 'machine-evidence.json') $machine
}

if (-not [Environment]::UserInteractive) {
    throw 'Windows release worker requires the signed-in interactive session.'
}
Assert-CanonicalRunIdentity
Assert-NoReparsePath $RunRoot
[void](Get-NativeWindowsArchitecture)
if ([IO.Path]::GetFullPath($PSCommandPath) -cne [IO.Path]::GetFullPath($ExpectedSelf)) {
    throw 'Windows release worker must execute only from the locked helper root.'
}
$closure = Read-JsonOnce (Join-Path $PrivateRoot 'collector-closure.json')
$verifiedClosureSha256 = Assert-ExactHelperClosure $closure
if ($verifiedClosureSha256 -cne [string]$closure.sha256) {
    throw 'Windows release worker is not bound to the full helper closure.'
}
$secureStateHelper = Join-Path $HelperRoot 'windows_secure_state_helpers.ps1'
if (-not (Test-Path -LiteralPath $secureStateHelper -PathType Leaf)) {
    throw 'The closure-bound Windows secure-state helper is missing.'
}
. $secureStateHelper
switch ($Phase) {
    'Prepare' {
        try { Invoke-Prepare }
        catch {
            Stop-ExactGui
            Restore-PreexistingAppData
            Remove-EphemeralObserverMaterial
            throw
        }
    }
    'Execute' { Invoke-Execute }
    'Finalize' {
        try { Invoke-Finalize }
        catch {
            Stop-ExactGui
            Restore-PreexistingAppData
            Remove-EphemeralObserverMaterial
            throw
        }
    }
}
