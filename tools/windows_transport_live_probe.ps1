[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedGuiSha256,
    [Parameter(Mandatory)][string]$CredentialStore,
    [Parameter(Mandatory)][string]$ObserverScript,
    [Parameter(Mandatory)][string]$Output,
    [ValidateRange(30, 180)][int]$ObserveSeconds = 90,
    [switch]$DiagnosticOnLinkDefaultRoute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Accessibility.IAccessible is a .NET Framework COM interop assembly. Re-enter
# through the in-box Windows PowerShell host when a caller uses PowerShell 7,
# whose newer System.Runtime identity cannot compile the MSAA helper reliably.
if ($PSVersionTable.PSEdition -eq 'Core') {
    $windowsPowerShell = Join-Path $env:SystemRoot `
        'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) {
        throw 'The Windows PowerShell compatibility host is unavailable.'
    }
    $compatibilityArguments = @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $PSCommandPath,
        '-ExpectedGuiSha256', $ExpectedGuiSha256,
        '-CredentialStore', $CredentialStore,
        '-ObserverScript', $ObserverScript,
        '-Output', $Output,
        '-ObserveSeconds', [string]$ObserveSeconds
    )
    if ($DiagnosticOnLinkDefaultRoute) {
        $compatibilityArguments += '-DiagnosticOnLinkDefaultRoute'
    }
    & $windowsPowerShell @compatibilityArguments
    exit $LASTEXITCODE
}

$diagnosticHelpers = Join-Path $PSScriptRoot `
    'windows_transport_diagnostic_helpers.ps1'
if (-not (Test-Path -LiteralPath $diagnosticHelpers -PathType Leaf)) {
    throw 'The sanitized Windows transport diagnostic helpers are unavailable.'
}
. $diagnosticHelpers

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StringSha256 {
    param([AllowEmptyString()][string]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace(
            '-', ''
        ).ToUpperInvariant()
    } finally { $algorithm.Dispose() }
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

function Read-DpapiCredential {
    $encrypted = [IO.File]::ReadAllText(
        (Resolve-Path -LiteralPath $CredentialStore),
        [Text.UTF8Encoding]::new($false, $true)
    ).Trim()
    $secure = ConvertTo-SecureString $encrypted
    $plain = [Net.NetworkCredential]::new('', $secure).Password
    try { $credential = $plain | ConvertFrom-Json }
    finally { $plain = $null }
    if ($credential.contract -cne 'winsvpn-windows-lab-credentials-v1' -or
        [string]$credential.hub_host -notmatch '^[A-Za-z0-9.-]{1,253}$' -or
        [string]$credential.hub_user -notmatch '^[a-z_][a-z0-9_-]{0,31}$' -or
        [string]$credential.hub_private_key_base64 -notmatch
            '^[A-Za-z0-9+/=]{128,}$') {
        throw 'The protected lab observer credential contract is invalid.'
    }
    $credential
}

function Set-OwnerOnlyAcl {
    param([Parameter(Mandatory)][string]$Path, [switch]$Directory)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($Directory) {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
    } else {
        $acl = [Security.AccessControl.FileSecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
    }
    [void]$acl.AddAccessRule($rule)
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    if ($Directory) {
        $systemRule = [Security.AccessControl.FileSystemAccessRule]::new(
            $systemSid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
    } else {
        $systemRule = [Security.AccessControl.FileSystemAccessRule]::new(
            $systemSid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
    }
    [void]$acl.AddAccessRule($systemRule)
    $acl.SetOwner($sid)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Write-PrivateBytes {
    param([Parameter(Mandatory)][string]$Path,
          [Parameter(Mandatory)][byte[]]$Bytes)
    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    Set-OwnerOnlyAcl $Path
}

function Get-ExactGui {
    $path = Join-Path $env:ProgramFiles 'WinsVPN\wins_vpn.exe'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
        (Get-Sha256 $path) -cne $ExpectedGuiSha256.ToLowerInvariant()) {
        throw 'The installed GUI is not the pinned Windows candidate.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne 'NotSigned' -or $signature.SignerCertificate -or
        $signature.TimeStamperCertificate) {
        throw 'This diagnostic accepts only the exact unsigned lab candidate.'
    }
    $processes = @(Get-Process wins_vpn -ErrorAction SilentlyContinue |
        Where-Object {
            try {
                [IO.Path]::GetFullPath($_.Path) -ceq [IO.Path]::GetFullPath($path)
            } catch { $false }
        })
    if ($processes.Count -gt 1) {
        throw 'More than one exact Win''s VPN GUI process is running.'
    }
    $process = if ($processes.Count -eq 1) {
        $processes[0]
    } else { Start-Process -FilePath $path -PassThru }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 250
        $process.Refresh()
    } while (-not $process.HasExited -and
        $process.MainWindowHandle -eq [IntPtr]::Zero -and
        [DateTime]::UtcNow -lt $deadline)
    if ($process.HasExited -or $process.MainWindowHandle -eq [IntPtr]::Zero) {
        throw 'The exact Win''s VPN GUI did not present its interactive window.'
    }
    $process
}

Add-Type -AssemblyName Accessibility
$accessibilityAssembly = [Accessibility.IAccessible].Assembly.Location
Add-Type -ReferencedAssemblies $accessibilityAssembly -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Accessibility;
public static class WinsVpnTransportProbeMsaa {
  private const uint ObjIdClient = 0xFFFFFFFC;
  private const int ChildSelf = 0;
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
  [DllImport("user32.dll", CharSet=CharSet.Unicode)]
  public static extern IntPtr FindWindowEx(
      IntPtr parent,IntPtr childAfter,string className,string windowName);
  public sealed class Match {
    internal IAccessible Owner; internal object Child;
    public string Label; public int Role; public int State;
    public string DefaultAction;
  }
  private static Match Candidate(IAccessible owner, object child, string label) {
    try {
      if (!String.Equals(owner.get_accName(child) ?? "", label,
          StringComparison.Ordinal)) return null;
      return new Match { Owner=owner, Child=child, Label=label,
        Role=Convert.ToInt32(owner.get_accRole(child)),
        State=Convert.ToInt32(owner.get_accState(child)),
        DefaultAction=owner.get_accDefaultAction(child) ?? "" };
    } catch { return null; }
  }
  private static Match Walk(IAccessible node, string label, int depth,
                            ref int seen) {
    if (node == null || depth > 64 || seen++ > 10000) return null;
    Match own=depth > 0 ? Candidate(node,ChildSelf,label) : null;
    if (own != null) return own;
    int count; try { count=node.accChildCount; } catch { return null; }
    if (count < 1 || count > 10000-seen) return null;
    object[] children=new object[count]; int obtained;
    if (AccessibleChildren(node,0,count,children,out obtained)<0) return null;
    for (int i=0;i<obtained;i++) {
      IAccessible nested=children[i] as IAccessible;
      Match found=nested != null ? Walk(nested,label,depth+1,ref seen)
                                 : Candidate(node,children[i],label);
      if (found != null) return found;
    }
    return null;
  }
  public static Match Find(IntPtr window, string label) {
    Guid iid=new Guid("618736E0-3C3D-11CF-810C-00AA00389B71"); object raw;
    if (AccessibleObjectFromWindow(window,ObjIdClient,ref iid,out raw)<0)
      return null;
    int seen=0; return Walk(raw as IAccessible,label,0,ref seen);
  }
  public static void Invoke(Match match) {
    match.Owner.accDoDefaultAction(match.Child);
  }
}
'@

function Find-Control {
    param([Parameter(Mandatory)]$Process,
          [Parameter(Mandatory)][string]$Label)
    $Process.Refresh()
    if ($Process.HasExited -or $Process.MainWindowHandle -eq [IntPtr]::Zero) {
        return $null
    }
    $view = [WinsVpnTransportProbeMsaa]::FindWindowEx(
        $Process.MainWindowHandle, [IntPtr]::Zero, 'FLUTTERVIEW', $null
    )
    if ($view -eq [IntPtr]::Zero) { return $null }
    $match = [WinsVpnTransportProbeMsaa]::Find($view, $Label)
    if (-not $match -or $match.Role -ne 43) {
        return $null
    }
    $match
}

function Wait-Control {
    param([Parameter(Mandatory)]$Process,
          [Parameter(Mandatory)][string]$Label,
          [ValidateRange(1, 60)][int]$Seconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $match = Find-Control $Process $Label
        if ($match) { return $match }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "The exact semantic control is unavailable: $Label"
}

function Test-NativeActive {
    $manager = Get-Service -Name 'WinsVpnTunnelManager' `
        -ErrorAction SilentlyContinue
    $legacyService = Get-Service -Name 'AmneziaWGTunnel$winsvpn' `
        -ErrorAction SilentlyContinue
    $engine = @(Get-Process winsvpn_awg_engine -ErrorAction SilentlyContinue)
    $adapter = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ceq 'winsvpn' -and $_.Status -eq 'Up' })
    $runtimeRunning = $engine.Count -eq 1 -or
        ($legacyService -and $legacyService.Status -eq 'Running')
    [bool]($manager -and $manager.Status -eq 'Running' -and
        $runtimeRunning -and $adapter.Count -eq 1)
}

function Get-AwgRuntimeProcessIds {
    $ids = [Collections.Generic.HashSet[uint32]]::new()
    foreach ($engine in @(Get-Process winsvpn_awg_engine `
            -ErrorAction SilentlyContinue)) {
        if ([uint32]$engine.Id -gt 0) { [void]$ids.Add([uint32]$engine.Id) }
    }
    $legacy = Get-CimInstance Win32_Service -Filter `
        'Name=''AmneziaWGTunnel$winsvpn''' -ErrorAction SilentlyContinue
    if ($legacy -and [uint32]$legacy.ProcessId -gt 0) {
        [void]$ids.Add([uint32]$legacy.ProcessId)
    }
    @($ids)
}

function Wait-NativeClean {
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        $legacyService = Get-Service -Name 'AmneziaWGTunnel$winsvpn' `
            -ErrorAction SilentlyContinue
        $engine = @(Get-Process winsvpn_awg_engine -ErrorAction SilentlyContinue)
        $adapter = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ceq 'winsvpn' -and $_.Status -eq 'Up' })
        $xray = @(Get-Process xray -ErrorAction SilentlyContinue)
        if (-not $legacyService -and $engine.Count -eq 0 -and
            $adapter.Count -eq 0 -and $xray.Count -eq 0) {
            return $true
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    $false
}

function ConvertTo-PrivateIPv4 {
    param([Parameter(Mandatory)][string]$Value,
          [Parameter(Mandatory)][string]$Label)
    $raw = ($Value.Trim() -split '/', 2)[0]
    $address = $null
    if (-not [Net.IPAddress]::TryParse($raw, [ref]$address) -or
        $address.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "$Label is not a valid IPv4 address."
    }
    $bytes = $address.GetAddressBytes()
    $private = $bytes[0] -eq 10 -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168)
    if (-not $private) { throw "$Label is not an RFC1918 IPv4 address." }
    $address
}

function Get-LocalTunnelState {
    param([Parameter(Mandatory)][Net.IPAddress]$ExpectedClient,
          [Parameter(Mandatory)][Net.IPAddress[]]$ExpectedDns,
          [ValidateRange(576, 9000)][int]$ExpectedMtu)
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ceq 'winsvpn' -and $_.Status -eq 'Up' })
    $clientMatches = $false
    $fullRoute = $false
    $dnsMatches = $false
    $mtuMatches = $false
    $routeCount = 0
    if ($adapters.Count -eq 1) {
        $indexProperty = $adapters[0].PSObject.Properties['ifIndex']
        if (-not $indexProperty) { return [ordered]@{
            adapter_count = $adapters.Count
            tunnel_ipv4_matches_config = $false
            full_tunnel_route_present = $false
            tunnel_route_count = 0
            dns_matches_config = $false
            mtu_matches_config = $false
        } }
        $index = [int]$indexProperty.Value
        $addresses = @(Get-NetIPAddress -InterfaceIndex $index `
            -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        $clientMatches = @($addresses | Where-Object {
            $property = $_.PSObject.Properties['IPAddress']
            $property -and [string]$property.Value -ceq $ExpectedClient.ToString()
        }).Count -eq 1
        $routes = @(Get-NetRoute -InterfaceIndex $index -AddressFamily IPv4 `
            -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
        $routeCount = $routes.Count
        $prefixes = @($routes | ForEach-Object {
            $property = $_.PSObject.Properties['DestinationPrefix']
            if ($property) { [string]$property.Value }
        })
        $fullRoute = $prefixes -contains '0.0.0.0/0' -or
            (($prefixes -contains '0.0.0.0/1') -and
             ($prefixes -contains '128.0.0.0/1'))
        $dnsRecords = @(Get-DnsClientServerAddress -InterfaceIndex $index `
            -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        $observedDns = @($dnsRecords | ForEach-Object {
            $property = $_.PSObject.Properties['ServerAddresses']
            if ($property -and $null -ne $property.Value) {
                @($property.Value)
            }
        })
        $expectedDnsText = @($ExpectedDns | ForEach-Object { $_.ToString() })
        $dnsMatches = $expectedDnsText.Count -gt 0 -and
            @($expectedDnsText | Where-Object {
                $observedDns -notcontains $_
            }).Count -eq 0
        $interfaces = @(Get-NetIPInterface -InterfaceIndex $index `
            -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        $mtuProperty = if ($interfaces.Count -eq 1) {
            $interfaces[0].PSObject.Properties['NlMtu']
        } else { $null }
        $mtuMatches = $null -ne $mtuProperty -and
            [int]$mtuProperty.Value -eq $ExpectedMtu
    }
    [ordered]@{
        adapter_count = $adapters.Count
        tunnel_ipv4_matches_config = $clientMatches
        full_tunnel_route_present = $fullRoute
        tunnel_route_count = $routeCount
        dns_matches_config = $dnsMatches
        mtu_matches_config = $mtuMatches
    }
}

function Invoke-VpnEchoProbe {
    param([Parameter(Mandatory)][Net.IPAddress]$Gateway,
          [Parameter(Mandatory)][Net.IPAddress]$ExpectedClient,
          [Parameter(Mandatory)][string]$Payload)
    $udp = $null
    try {
        $udp = [Net.Sockets.UdpClient]::new(
            [Net.Sockets.AddressFamily]::InterNetwork
        )
        $udp.Client.ReceiveTimeout = 1200
        $udp.Connect($Gateway, 49152)
        $bytes = [Text.Encoding]::ASCII.GetBytes($Payload)
        [void]$udp.Send($bytes, $bytes.Length)
        $local = $udp.Client.LocalEndPoint
        $remote = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
        $reply = $udp.Receive([ref]$remote)
        [ordered]@{
            attempted = $true
            source_matches_config = [bool]($local -and
                $local.Address.Equals($ExpectedClient))
            remote_matches_gateway = [bool]($remote -and
                $remote.Address.Equals($Gateway) -and $remote.Port -eq 49152)
            round_trip = [bool]($reply.Length -eq $bytes.Length -and
                [Text.Encoding]::ASCII.GetString($reply) -ceq $Payload)
        }
    } catch {
        [ordered]@{
            attempted = $true
            source_matches_config = $false
            remote_matches_gateway = $false
            round_trip = $false
        }
    } finally {
        if ($udp) { $udp.Dispose() }
    }
}

function Invoke-BoundHttpsProbe {
    param([Parameter(Mandatory)][Net.IPAddress]$ClientAddress,
          [Parameter(Mandatory)][Net.IPAddress]$DisconnectedEgress)
    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    if (-not (Test-Path -LiteralPath $curl -PathType Leaf)) {
        return [ordered]@{ attempted = $false; reachable = $false;
            exit_differs_from_disconnected = $false }
    }
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $curl
    $psi.Arguments = '--interface "' + $ClientAddress.ToString() +
        '" --connect-timeout 5 --max-time 12 --silent --show-error ' +
        'https://api.ipify.org'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $probe = [Diagnostics.Process]::new()
    $probe.StartInfo = $psi
    if (-not $probe.Start()) {
        return [ordered]@{ attempted = $true; reachable = $false;
            exit_differs_from_disconnected = $false }
    }
    $stdout = $probe.StandardOutput.ReadToEndAsync()
    $stderr = $probe.StandardError.ReadToEndAsync()
    if (-not $probe.WaitForExit(15000)) {
        try { $probe.Kill() } catch {}
        return [ordered]@{ attempted = $true; reachable = $false;
            exit_differs_from_disconnected = $false }
    }
    $observed = $null
    $valid = $probe.ExitCode -eq 0 -and
        [Net.IPAddress]::TryParse($stdout.Result.Trim(), [ref]$observed)
    [ordered]@{
        attempted = $true
        reachable = [bool]$valid
        exit_differs_from_disconnected = [bool]($valid -and
            -not $observed.Equals($DisconnectedEgress))
    }
}

function Get-TunnelManagerAwgStatus {
    $result = [ordered]@{
        query_ok = $false
        handshake_present = $false
        received_bytes_nonzero = $false
        sent_bytes_nonzero = $false
        handshake_unix = [uint64]0
        received_bytes = [uint64]0
        sent_bytes = [uint64]0
    }
    # The tunnel manager intentionally authenticates the calling executable and
    # rejects status frames sent by PowerShell. Querying that pipe from this
    # collector would therefore manufacture a permanent false negative. The
    # installed AWG CLI is a read-only client of the same protected UAPI; these
    # two subcommands expose only liveness counters (never private keys, PSKs,
    # endpoints, AllowedIPs, or obfuscation parameters).
    $awg = Join-Path $env:ProgramFiles 'WinsVPN\awg.exe'
    if (-not (Test-Path -LiteralPath $awg -PathType Leaf)) { return $result }
    $isAdministrator = (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdministrator) { return $result }

    function Invoke-AwgCounterQuery {
        param(
            [Parameter(Mandatory)]
            [ValidateSet('latest-handshakes', 'transfer')]
            [string]$Field
        )
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $awg
        # The collector intentionally re-enters Windows PowerShell 5.1 for its
        # MSAA bridge. .NET Framework does not expose ProcessStartInfo.ArgumentList,
        # so use a fixed, ValidateSet-bounded argument string.
        $start.Arguments = "show winsvpn $Field"
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $start
        try {
            if (-not $process.Start()) { return $null }
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(5000)) {
                try { $process.Kill() } catch {}
                return $null
            }
            if ($process.ExitCode -ne 0 -or
                -not [string]::IsNullOrWhiteSpace($stderr.Result)) {
                return $null
            }
            $stdout.Result.Trim()
        } finally { $process.Dispose() }
    }

    try {
        $handshakes = Invoke-AwgCounterQuery -Field 'latest-handshakes'
        $transfer = Invoke-AwgCounterQuery -Field 'transfer'
        if ($null -eq $handshakes -or $null -eq $transfer) { return $result }
        $handshakeRows = @($handshakes -split "`r?`n" | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        })
        $transferRows = @($transfer -split "`r?`n" | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        })
        if ($handshakeRows.Count -ne 1 -or $transferRows.Count -ne 1) {
            return $result
        }
        $handshakeParts = @($handshakeRows[0] -split "`t")
        $transferParts = @($transferRows[0] -split "`t")
        if ($handshakeParts.Count -ne 2 -or $transferParts.Count -ne 3 -or
            $handshakeParts[0] -cne $transferParts[0]) {
            return $result
        }
        $handshake = [uint64]0
        $received = [uint64]0
        $sent = [uint64]0
        if (-not [uint64]::TryParse($handshakeParts[1], [ref]$handshake) -or
            -not [uint64]::TryParse($transferParts[1], [ref]$received) -or
            -not [uint64]::TryParse($transferParts[2], [ref]$sent)) {
            return $result
        }
        $result.query_ok = $true
        $result.handshake_present = $handshake -gt 0
        $result.received_bytes_nonzero = $received -gt 0
        $result.sent_bytes_nonzero = $sent -gt 0
        $result.handshake_unix = $handshake
        $result.received_bytes = $received
        $result.sent_bytes = $sent
        $result
    } catch {
        $result
    }
}

function Get-AwgLogClassification {
    $emptySignatures = [ordered]@{
        initiation_sends = @{}
        unknown_message_types = @{}
        invalid_mac1_packets = @{}
        invalid_responses = @{}
        valid_responses = @{}
        decode_response_failures = @{}
        derive_keypair_failures = @{}
        receive_failures = @{}
        handshake_retries = @{}
        keepalive_sends = @{}
        data_send_failures = @{}
        tun_read_failures = @{}
        tun_reader_starts = @{}
        tun_reader_stops = @{}
        encryption_worker_starts = @{}
        encryption_worker_stops = @{}
        sequential_sender_starts = @{}
        sequential_sender_stops = @{}
    }
    $empty = [ordered]@{
        accessible = $false
        initiation_sends = 0
        unknown_message_types = 0
        invalid_mac1_packets = 0
        invalid_responses = 0
        valid_responses = 0
        decode_response_failures = 0
        derive_keypair_failures = 0
        receive_failures = 0
        handshake_retries = 0
        keepalive_sends = 0
        data_send_failures = 0
        tun_read_failures = 0
        tun_reader_starts = 0
        tun_reader_stops = 0
        encryption_worker_starts = 0
        encryption_worker_stops = 0
        sequential_sender_starts = 0
        sequential_sender_stops = 0
        event_signatures = $emptySignatures
    }
    $isAdministrator = ([Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdministrator) { return $empty }
    $awg = Join-Path $env:ProgramFiles 'AmneziaWG\amneziawg.exe'
    if (-not (Test-Path -LiteralPath $awg -PathType Leaf)) { return $empty }
    $signature = Get-AuthenticodeSignature -LiteralPath $awg
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch
            'O=Privacy Technologies OU') {
        return $empty
    }
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $awg
    $psi.Arguments = '/dumplog'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $dump = [Diagnostics.Process]::new()
    $dump.StartInfo = $psi
    if (-not $dump.Start()) { return $empty }
    $stdout = $dump.StandardOutput.ReadToEndAsync()
    $stderr = $dump.StandardError.ReadToEndAsync()
    if (-not $dump.WaitForExit(10000)) {
        try { $dump.Kill() } catch {}
        return $empty
    }
    $text = $stdout.Result
    if ($dump.ExitCode -ne 0 -or $text.Length -gt 16MB) { return $empty }
    $patterns = [ordered]@{
        initiation_sends = 'Sending handshake initiation'
        unknown_message_types = 'Received message with unknown type'
        invalid_mac1_packets = 'Received packet with invalid mac1'
        invalid_responses = 'Received invalid response message'
        valid_responses = 'Received handshake response'
        decode_response_failures = 'Failed to decode response message'
        derive_keypair_failures = 'Failed to derive keypair'
        receive_failures = 'Failed to receive IPv4 packet'
        handshake_retries = 'Handshake did not complete .* retrying'
        keepalive_sends = 'Sending keepalive packet'
        data_send_failures = 'Failed to send data packets'
        tun_read_failures = 'Failed to read packet from TUN device'
        tun_reader_starts = 'Routine: TUN reader - started'
        tun_reader_stops = 'Routine: TUN reader - stopped'
        encryption_worker_starts = 'Routine: encryption worker .* - started'
        encryption_worker_stops = 'Routine: encryption worker .* - stopped'
        sequential_sender_starts = 'Routine: sequential sender - started'
        sequential_sender_stops = 'Routine: sequential sender - stopped'
    }
    $signatures = [ordered]@{}
    foreach ($name in $patterns.Keys) {
        $counts = @{}
        $linePattern = '(?im)^[^\r\n]*' + $patterns[$name] + '[^\r\n]*$'
        foreach ($match in [regex]::Matches($text, $linePattern)) {
            $signature = Get-StringSha256 $match.Value
            if ($counts.ContainsKey($signature)) {
                $counts[$signature] = [int]$counts[$signature] + 1
            } else {
                $counts[$signature] = 1
            }
        }
        $signatures[$name] = $counts
    }
    [ordered]@{
        accessible = $true
        initiation_sends = [regex]::Matches(
            $text, 'Sending handshake initiation', 'IgnoreCase').Count
        unknown_message_types = [regex]::Matches(
            $text, 'Received message with unknown type', 'IgnoreCase').Count
        invalid_mac1_packets = [regex]::Matches(
            $text, 'Received packet with invalid mac1', 'IgnoreCase').Count
        invalid_responses = [regex]::Matches(
            $text, 'Received invalid response message', 'IgnoreCase').Count
        valid_responses = [regex]::Matches(
            $text, 'Received handshake response', 'IgnoreCase').Count
        decode_response_failures = [regex]::Matches(
            $text, 'Failed to decode response message', 'IgnoreCase').Count
        derive_keypair_failures = [regex]::Matches(
            $text, 'Failed to derive keypair', 'IgnoreCase').Count
        receive_failures = [regex]::Matches(
            $text, 'Failed to receive IPv4 packet', 'IgnoreCase').Count
        handshake_retries = [regex]::Matches(
            $text, 'Handshake did not complete .* retrying', 'IgnoreCase').Count
        keepalive_sends = [regex]::Matches(
            $text, 'Sending keepalive packet', 'IgnoreCase').Count
        data_send_failures = [regex]::Matches(
            $text, 'Failed to send data packets', 'IgnoreCase').Count
        tun_read_failures = [regex]::Matches(
            $text, 'Failed to read packet from TUN device', 'IgnoreCase').Count
        tun_reader_starts = [regex]::Matches(
            $text, 'Routine: TUN reader - started', 'IgnoreCase').Count
        tun_reader_stops = [regex]::Matches(
            $text, 'Routine: TUN reader - stopped', 'IgnoreCase').Count
        encryption_worker_starts = [regex]::Matches(
            $text, 'Routine: encryption worker .* - started', 'IgnoreCase').Count
        encryption_worker_stops = [regex]::Matches(
            $text, 'Routine: encryption worker .* - stopped', 'IgnoreCase').Count
        sequential_sender_starts = [regex]::Matches(
            $text, 'Routine: sequential sender - started', 'IgnoreCase').Count
        sequential_sender_stops = [regex]::Matches(
            $text, 'Routine: sequential sender - stopped', 'IgnoreCase').Count
        event_signatures = $signatures
    }
}

function Get-WinsAwgSignatureDelta {
    param(
        [Parameter(Mandatory)]$Before,
        [Parameter(Mandatory)]$After,
        [Parameter(Mandatory)][string]$EventName
    )
    if (-not $Before.accessible -or -not $After.accessible) { return 0 }
    $beforeCounts = $Before.event_signatures[$EventName]
    $afterCounts = $After.event_signatures[$EventName]
    if ($null -eq $beforeCounts -or $null -eq $afterCounts) { return 0 }
    $delta = 0
    foreach ($signature in $afterCounts.Keys) {
        $beforeCount = if ($beforeCounts.ContainsKey($signature)) {
            [int]$beforeCounts[$signature]
        } else { 0 }
        $delta += [Math]::Max(0, [int]$afterCounts[$signature] - $beforeCount)
    }
    $delta
}

function Set-WinsDiagnosticOnLinkDefault {
    param([Parameter(Mandatory)][Net.IPAddress]$ExpectedGateway)
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop |
        Where-Object { $_.Name -ceq 'winsvpn' -and $_.Status -eq 'Up' })
    if ($adapters.Count -ne 1) {
        throw 'The diagnostic route mutation requires one active winsvpn adapter.'
    }
    $interfaceIndex = [int]$adapters[0].ifIndex
    $routes = @(Get-NetRoute -AddressFamily IPv4 `
        -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $interfaceIndex `
        -PolicyStore ActiveStore -ErrorAction Stop)
    if ($routes.Count -ne 1 -or
        [string]$routes[0].NextHop -cne $ExpectedGateway.ToString()) {
        throw 'The diagnostic route mutation rejected a non-exact owned route.'
    }
    $metric = [uint32]$routes[0].RouteMetric
    $routes[0] | Remove-NetRoute -Confirm:$false -ErrorAction Stop
    try {
        New-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
            -InterfaceIndex $interfaceIndex -NextHop '0.0.0.0' `
            -RouteMetric $metric -PolicyStore ActiveStore `
            -ErrorAction Stop | Out-Null
        $onLink = @(Get-NetRoute -AddressFamily IPv4 `
            -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $interfaceIndex `
            -PolicyStore ActiveStore -ErrorAction Stop)
        if ($onLink.Count -ne 1 -or [string]$onLink[0].NextHop -cne '0.0.0.0') {
            throw 'The diagnostic on-link route did not verify exactly.'
        }
    } catch {
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
            -InterfaceIndex $interfaceIndex -PolicyStore ActiveStore `
            -ErrorAction SilentlyContinue |
            Where-Object { [string]$_.NextHop -ceq '0.0.0.0' } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        New-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
            -InterfaceIndex $interfaceIndex `
            -NextHop $ExpectedGateway.ToString() -RouteMetric $metric `
            -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
        throw
    }
    [ordered]@{ interface_index = $interfaceIndex; route_metric = $metric }
}

function Restore-WinsDiagnosticGatewayDefault {
    param([Parameter(Mandatory)]$Mutation,
          [Parameter(Mandatory)][Net.IPAddress]$ExpectedGateway)
    $interfaceIndex = [int]$Mutation.interface_index
    $routes = @(Get-NetRoute -AddressFamily IPv4 `
        -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $interfaceIndex `
        -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
    if ($routes.Count -eq 1 -and
        [string]$routes[0].NextHop -ceq $ExpectedGateway.ToString()) {
        return $true
    }
    if ($routes.Count -ne 1 -or [string]$routes[0].NextHop -cne '0.0.0.0') {
        return $false
    }
    $routes[0] | Remove-NetRoute -Confirm:$false -ErrorAction Stop
    New-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
        -InterfaceIndex $interfaceIndex -NextHop $ExpectedGateway.ToString() `
        -RouteMetric ([uint32]$Mutation.route_metric) `
        -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
    $restored = @(Get-NetRoute -AddressFamily IPv4 `
        -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $interfaceIndex `
        -PolicyStore ActiveStore -ErrorAction Stop)
    $restored.Count -eq 1 -and
        [string]$restored[0].NextHop -ceq $ExpectedGateway.ToString()
}

$secureStateHelpers = Join-Path $PSScriptRoot 'windows_secure_state_helpers.ps1'
$secureStateHelperItem = Get-Item -LiteralPath $secureStateHelpers -Force `
    -ErrorAction Stop
if ($secureStateHelperItem.PSIsContainer -or
    ($secureStateHelperItem.Attributes -band
        [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The fail-closed Windows secure-state helpers are unavailable.'
}
. $secureStateHelpers

$outputFull = [IO.Path]::GetFullPath($Output)
$outputParent = Split-Path -Parent $outputFull
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    throw 'The diagnostic output parent does not exist.'
}
if (Test-Path -LiteralPath $outputFull) {
    throw 'The diagnostic output already exists.'
}

$credential = Read-DpapiCredential
$keypair = Read-WinsVpnSecureJson -Name 'client_keypair.json'
$config = Read-WinsVpnSecureJson -Name 'vpn_config.txt'
$expectedClient = ConvertTo-PrivateIPv4 ([string]$config.client_ip) `
    'The cached tunnel client address'
$expectedGateway = ConvertTo-PrivateIPv4 `
    ([string]$config.tunnel_gateway_ipv4) 'The cached tunnel gateway address'
$expectedDns = @(([string]$config.dns -split '[,\s]+' |
    Where-Object { $_ }) | ForEach-Object {
        ConvertTo-PrivateIPv4 $_ 'A cached tunnel DNS address'
    })
if ($expectedDns.Count -lt 1) { throw 'The cached tunnel DNS contract is empty.' }
if ((Get-StringSha256 ([string]$keypair.public_key)) -cne
        (Get-StringSha256 ([string]$credential.client_keypair.public_key)) -or
    (Get-StringSha256 ([string]$config.client_public_key)) -cne
        (Get-StringSha256 ([string]$credential.client_keypair.public_key)) -or
    (Get-StringSha256 ([string]$config.node_slug)) -cne
        (Get-StringSha256 ([string]$credential.node_cache.selected_slug)) -or
    [string]$config.server_endpoint -notmatch ':9110$' -or
    [int]$config.xray.port -notin 1..65535) {
    throw 'The restored app state does not match the pinned lab identity/route.'
}

$ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
if (-not (Test-Path -LiteralPath $ssh -PathType Leaf)) {
    throw 'Windows OpenSSH is unavailable.'
}
$observerSource = [IO.File]::ReadAllText(
    (Resolve-Path -LiteralPath $ObserverScript),
    [Text.UTF8Encoding]::new($false, $true)
)
$clientEgress = (Invoke-WebRequest -UseBasicParsing `
    -Uri 'https://api.ipify.org' -TimeoutSec 15).Content.Trim()
$parsedEgress = $null
if (-not [Net.IPAddress]::TryParse($clientEgress, [ref]$parsedEgress)) {
    throw 'The disconnected client egress identity is unavailable.'
}
$nonce = [Guid]::NewGuid().ToString('D')
$payloadNonce = 'WINSXRAY' + [Guid]::NewGuid().ToString('N').ToUpperInvariant()
$environment = [ordered]@{
    WINS_ACCOUNT_DIGEST = Get-StringSha256 `
        ([string]$credential.node_request.account_number)
    WINS_DEVICE_DIGEST = Get-StringSha256 `
        ([string]$credential.node_request.device_id)
    WINS_PUBLIC_KEY_DIGEST = Get-StringSha256 `
        ([string]$credential.client_keypair.public_key)
    WINS_NODE_SLUG_DIGEST = Get-StringSha256 ([string]$config.node_slug)
    WINS_CLIENT_EGRESS_DIGEST = Get-StringSha256 $parsedEgress.ToString()
    WINS_CLIENT_PSK_DIGEST = Get-StringSha256 ([string]$config.preshared_key)
    WINS_CLIENT_SERVER_KEY_DIGEST = Get-StringSha256 `
        ([string]$config.server_public_key)
    WINS_CLIENT_OBFUSCATION_DIGEST = Get-ObfuscationDigest `
        $config.obfuscation
    WINS_OBSERVE_SECONDS = [string]$ObserveSeconds
    WINS_OBSERVE_MODE = 'direct'
    WINS_TARGET_XRAY_PORT = [string][int]$config.xray.port
    WINS_OBSERVATION_NONCE = $nonce
    WINS_PROBE_PAYLOAD_NONCE = $payloadNonce
    WINS_PROBE_ECHO_PORT = '49152'
    WINS_PROBE_GATEWAY_DIGEST = Get-StringSha256 $expectedGateway.ToString()
}
$remote = (($environment.Keys | ForEach-Object {
    "$_=$($environment[$_])"
}) -join ' ') + ' python3 -'

$privateRoot = Join-Path $env:LOCALAPPDATA (
    'WinsVPN\TransportProbe\' + [Guid]::NewGuid().ToString('D')
)
New-Item -ItemType Directory -Path $privateRoot | Out-Null
Set-OwnerOnlyAcl $privateRoot -Directory
$keyPath = Join-Path $privateRoot 'observer-key'
$knownPath = Join-Path $privateRoot 'known-hosts'
Write-PrivateBytes $keyPath ([Convert]::FromBase64String(
    [string]$credential.hub_private_key_base64
))
Write-PrivateBytes $knownPath ([Text.UTF8Encoding]::new($false).GetBytes(
    ([string]$credential.hub_known_hosts).Trim() + [Environment]::NewLine
))

$observer = $null
$process = $null
$observation = $null
$nativeSeen = $false
$xraySeen = $false
$disconnectSeen = $false
$cancelSeen = $false
$connectInvoked = $false
$cleanupPassed = $false
$localState = [ordered]@{
    adapter_count = 0
    tunnel_ipv4_matches_config = $false
    full_tunnel_route_present = $false
    tunnel_route_count = 0
    dns_matches_config = $false
    mtu_matches_config = $false
}
$echoResult = [ordered]@{
    attempted = $false
    source_matches_config = $false
    remote_matches_gateway = $false
    round_trip = $false
}
$httpsResult = [ordered]@{
    attempted = $false
    reachable = $false
    exit_differs_from_disconnected = $false
}
$awgStatus = [ordered]@{
    query_ok = $false
    handshake_present = $false
    received_bytes_nonzero = $false
    sent_bytes_nonzero = $false
    handshake_unix = [uint64]0
    received_bytes = [uint64]0
    sent_bytes = [uint64]0
}
$echoAttempts = 0
$httpsAttempts = 0
$lastLocalAttempt = [DateTime]::MinValue
$lastAwgDiagnosticPoll = [DateTime]::MinValue
$awgLogBefore = Get-AwgLogClassification
$awgLogAfter = $awgLogBefore
$diagnosticMutation = $null
$diagnosticRouteAb = [ordered]@{
    requested = [bool]$DiagnosticOnLinkDefaultRoute
    release_gate_eligible = $false
    authenticated_response_seen_before_mutation = $false
    original_gateway_route_verified = $false
    mutation_committed = $false
    on_link_route_verified = $false
    probes_started_after_mutation = $false
    restoration_attempted = $false
    original_gateway_restored = $false
    data_path_fixed = $false
}
$kernelNetworkCapture = New-WinsKernelNetworkCaptureState `
    -PrivateRoot $privateRoot `
    -LocalPort ([int]$config.xray.local_port)
$kernelNetworkSummary = $null
$kernelCaptureStartedUtc = $null
$xrayCarrierState = New-WinsXrayCarrierState
$awgServiceProcessIds = @{}
$adapterStatisticsBefore = $null
$adapterStatisticsAfter = $null
$bestRouteSelection = [ordered]@{
    gateway = [ordered]@{ query_ok = $false
        interface_index_matches_winsvpn = $false
        selected_source_matches_config = $false }
    public_ipv4 = [ordered]@{ query_ok = $false
        interface_index_matches_winsvpn = $false
        selected_source_matches_config = $false }
}
try {
    $process = Get-ExactGui
    $uiTool = Join-Path $PSScriptRoot 'windows_invoke_vpn_power.ps1'
    if (-not (Test-Path -LiteralPath $uiTool -PathType Leaf)) {
        throw 'The proven FLUTTERVIEW UI bridge is unavailable.'
    }
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $ssh
    $psi.Arguments = '-i "' + $keyPath + '" -o BatchMode=yes ' +
        '-o ConnectTimeout=12 -o ConnectionAttempts=1 ' +
        '-o StrictHostKeyChecking=yes -o UserKnownHostsFile="' +
        $knownPath + '" -o GlobalKnownHostsFile=NUL -o UpdateHostKeys=no ' +
        [string]$credential.hub_user + '@' + [string]$credential.hub_host +
        ' "' + $remote + '"'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $observer = [Diagnostics.Process]::new()
    $observer.StartInfo = $psi
    if (-not $observer.Start()) { throw 'The pinned observer did not start.' }
    $stdout = $observer.StandardOutput.ReadToEndAsync()
    $stderr = $observer.StandardError.ReadToEndAsync()
    $observer.StandardInput.Write($observerSource)
    $observer.StandardInput.Close()
    Start-Sleep -Seconds 2
    $uiResult = & $uiTool -Action Toggle -SettleSeconds 0 `
        -WindowProcessId $process.Id
    if ([string]$uiResult -notmatch
        '^WINDOWS_VPN_POWER_INVOKE=PASS label=Connect VPN role=43 ') {
        throw 'The proven FLUTTERVIEW UI bridge did not invoke Connect.'
    }
    $invocationMethod = 'flutterview_semantic_default_action'
    $connectInvoked = $true
    $deadline = [DateTime]::UtcNow.AddSeconds($ObserveSeconds + 30)
    do {
        if (Test-NativeActive) {
            $nativeSeen = $true
            if ($null -eq $adapterStatisticsBefore -or
                -not $adapterStatisticsBefore.query_ok) {
                $candidateStatistics = Get-WinsAdapterStatisticsSnapshot
                if ($candidateStatistics.query_ok) {
                    $adapterStatisticsBefore = $candidateStatistics
                }
            }
            if (-not $bestRouteSelection.gateway.query_ok -or
                -not $bestRouteSelection.public_ipv4.query_ok) {
                $bestRouteSelection = Get-WinsBestRouteSelection `
                    -ExpectedClient $expectedClient -Gateway $expectedGateway
            }
            foreach ($runtimeProcessId in @(Get-AwgRuntimeProcessIds)) {
                $awgServiceProcessIds[[string][uint32]$runtimeProcessId] = $true
            }
            if (([DateTime]::UtcNow - $lastLocalAttempt).TotalSeconds -ge 2) {
                $lastLocalAttempt = [DateTime]::UtcNow
                $localState = Get-LocalTunnelState `
                    -ExpectedClient $expectedClient -ExpectedDns $expectedDns `
                    -ExpectedMtu ([int]$config.mtu)
                $currentAwgStatus = Get-TunnelManagerAwgStatus
                if ($currentAwgStatus.query_ok) { $awgStatus = $currentAwgStatus }
                if ($DiagnosticOnLinkDefaultRoute -and
                    -not $diagnosticRouteAb.mutation_committed -and
                    ([DateTime]::UtcNow -
                        $lastAwgDiagnosticPoll).TotalSeconds -ge 2) {
                    $lastAwgDiagnosticPoll = [DateTime]::UtcNow
                    $diagnosticLog = Get-AwgLogClassification
                    if ((Get-WinsAwgSignatureDelta -Before $awgLogBefore `
                            -After $diagnosticLog `
                            -EventName 'valid_responses') -gt 0) {
                        $diagnosticRouteAb.`
                            authenticated_response_seen_before_mutation = $true
                        $diagnosticRouteAb.original_gateway_route_verified = $true
                        $diagnosticMutation = Set-WinsDiagnosticOnLinkDefault `
                            -ExpectedGateway $expectedGateway
                        $diagnosticRouteAb.mutation_committed = $true
                        $diagnosticRouteAb.on_link_route_verified = $true
                        $adapterStatisticsBefore = `
                            Get-WinsAdapterStatisticsSnapshot
                        $adapterStatisticsAfter = $null
                        $bestRouteSelection = Get-WinsBestRouteSelection `
                            -ExpectedClient $expectedClient `
                            -Gateway $expectedGateway
                    }
                }
                $probeRouteReady = -not $DiagnosticOnLinkDefaultRoute -or
                    $diagnosticRouteAb.mutation_committed
                if ($probeRouteReady -and -not $echoResult.round_trip -and
                    $echoAttempts -lt 8) {
                    $echoAttempts++
                    if ($DiagnosticOnLinkDefaultRoute) {
                        $diagnosticRouteAb.probes_started_after_mutation = $true
                    }
                    $echoResult = Invoke-VpnEchoProbe `
                        -Gateway $expectedGateway -ExpectedClient $expectedClient `
                        -Payload $payloadNonce
                }
                if ($probeRouteReady -and
                    $localState.full_tunnel_route_present -and
                    -not $httpsResult.reachable -and $httpsAttempts -lt 3) {
                    $httpsAttempts++
                    $httpsResult = Invoke-BoundHttpsProbe `
                        -ClientAddress $expectedClient `
                        -DisconnectedEgress $parsedEgress
                }
                $candidateStatistics = Get-WinsAdapterStatisticsSnapshot
                if ($candidateStatistics.query_ok) {
                    $adapterStatisticsAfter = $candidateStatistics
                }
            }
        }
        if (@(Get-Process xray -ErrorAction SilentlyContinue).Count -gt 0) {
            $xraySeen = $true
            Update-WinsXrayCarrierState -State $xrayCarrierState `
                -RemotePort ([int]$config.xray.port)
            if (-not $kernelNetworkCapture.started -and
                -not $kernelNetworkCapture.stopped) {
                Start-WinsKernelNetworkCapture -State $kernelNetworkCapture
                if ($kernelNetworkCapture.started) {
                    $kernelCaptureStartedUtc = [DateTime]::UtcNow
                }
            }
        }
        if ($null -eq $kernelNetworkSummary -and
            $kernelNetworkCapture.started -and
            $kernelCaptureStartedUtc -and
            ([DateTime]::UtcNow - $kernelCaptureStartedUtc).TotalSeconds -ge
                15) {
            $kernelNetworkSummary = Stop-WinsKernelNetworkCapture `
                -State $kernelNetworkCapture `
                -ExpectedXrayProcessIds @($xrayCarrierState.process_ids.Keys) `
                -ExpectedAwgProcessIds @($awgServiceProcessIds.Keys) `
                -ExpectedClientAddress $expectedClient.ToString() `
                -ExpectedGatewayAddress $expectedGateway.ToString() `
                -ExpectedProbeProcessId ([string]$PID) -ProbeEchoPort 49152 `
                -ExpectedEchoPayloadLength (
                    [Text.Encoding]::ASCII.GetByteCount($payloadNonce)
                )
        }
        if (Find-Control $process 'Disconnect VPN') { $disconnectSeen = $true }
        if (Find-Control $process 'Cancel VPN connection') { $cancelSeen = $true }
        if ($observer.HasExited) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $observer.HasExited -and -not $observer.WaitForExit(15000)) {
        try { $observer.Kill() } catch {}
        throw 'The pinned server observation timed out.'
    }
    $observerText = $stdout.Result
    if ($observer.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($observerText)) {
        throw 'The pinned server observation failed: ' +
            (Get-StringSha256 $stderr.Result)
    }
    $observation = $observerText | ConvertFrom-Json
    if ($observation.contract -cne
            'winsvpn-windows-spain-live-observation-v1' -or
        $observation.observer_authenticated -ne $true -or
        [string]$observation.observation_window_nonce -cne $nonce) {
        throw 'The pinned server observation contract is invalid.'
    }
    $awgLogAfter = Get-AwgLogClassification
    Update-WinsXrayCarrierState -State $xrayCarrierState `
        -RemotePort ([int]$config.xray.port)
    $candidateStatistics = Get-WinsAdapterStatisticsSnapshot
    if ($candidateStatistics.query_ok) {
        $adapterStatisticsAfter = $candidateStatistics
    }
    $kernelNetworkSummary = Stop-WinsKernelNetworkCapture `
        -State $kernelNetworkCapture `
        -ExpectedXrayProcessIds @($xrayCarrierState.process_ids.Keys) `
        -ExpectedAwgProcessIds @($awgServiceProcessIds.Keys) `
        -ExpectedClientAddress $expectedClient.ToString() `
        -ExpectedGatewayAddress $expectedGateway.ToString() `
        -ExpectedProbeProcessId ([string]$PID) -ProbeEchoPort 49152 `
        -ExpectedEchoPayloadLength (
            [Text.Encoding]::ASCII.GetByteCount($payloadNonce)
        )
} finally {
    if ($observer -and -not $observer.HasExited) {
        try { $observer.Kill() } catch {}
    }
    if ($process -and -not $process.HasExited) {
        try {
            Update-WinsXrayCarrierState -State $xrayCarrierState `
                -RemotePort ([int]$config.xray.port)
        } catch {}
        if ($null -eq $kernelNetworkSummary) {
            try {
                $candidateStatistics = Get-WinsAdapterStatisticsSnapshot
                if ($candidateStatistics.query_ok) {
                    $adapterStatisticsAfter = $candidateStatistics
                }
                $kernelNetworkSummary = Stop-WinsKernelNetworkCapture `
                    -State $kernelNetworkCapture `
                    -ExpectedXrayProcessIds @(
                        $xrayCarrierState.process_ids.Keys
                    ) -ExpectedAwgProcessIds @($awgServiceProcessIds.Keys) `
                    -ExpectedClientAddress $expectedClient.ToString() `
                    -ExpectedGatewayAddress $expectedGateway.ToString() `
                    -ExpectedProbeProcessId ([string]$PID) `
                    -ProbeEchoPort 49152 -ExpectedEchoPayloadLength (
                        [Text.Encoding]::ASCII.GetByteCount($payloadNonce)
                    )
            } catch {}
        }
        if ($diagnosticRouteAb.mutation_committed -and $diagnosticMutation) {
            $diagnosticRouteAb.restoration_attempted = $true
            try {
                $diagnosticRouteAb.original_gateway_restored = [bool](
                    Restore-WinsDiagnosticGatewayDefault `
                        -Mutation $diagnosticMutation `
                        -ExpectedGateway $expectedGateway
                )
            } catch {
                $diagnosticRouteAb.original_gateway_restored = $false
            }
        }
        foreach ($cleanupAction in @('Disconnect', 'Cancel')) {
            try {
                $cleanupResult = & (Join-Path $PSScriptRoot `
                    'windows_invoke_vpn_power.ps1') -Action $cleanupAction `
                    -SettleSeconds 0 -WindowProcessId $process.Id
                if ([string]$cleanupResult -match
                    '^WINDOWS_VPN_POWER_INVOKE=PASS ') { break }
            } catch {}
        }
    }
    if ($null -eq $kernelNetworkSummary) {
        try {
            $kernelNetworkSummary = Stop-WinsKernelNetworkCapture `
                -State $kernelNetworkCapture `
                -ExpectedXrayProcessIds @($xrayCarrierState.process_ids.Keys) `
                -ExpectedAwgProcessIds @($awgServiceProcessIds.Keys) `
                -ExpectedClientAddress $expectedClient.ToString() `
                -ExpectedGatewayAddress $expectedGateway.ToString() `
                -ExpectedProbeProcessId ([string]$PID) -ProbeEchoPort 49152 `
                -ExpectedEchoPayloadLength (
                    [Text.Encoding]::ASCII.GetByteCount($payloadNonce)
                )
        } catch {}
    }
    $cleanupPassed = Wait-NativeClean
    if (Test-Path -LiteralPath $privateRoot -PathType Container) {
        $resolvedPrivate = [IO.Path]::GetFullPath($privateRoot)
        $expectedBase = [IO.Path]::GetFullPath(
            (Join-Path $env:LOCALAPPDATA 'WinsVPN\TransportProbe')
        ).TrimEnd('\') + '\'
        if ($resolvedPrivate.StartsWith(
                $expectedBase, [StringComparison]::OrdinalIgnoreCase
            )) {
            Remove-Item -LiteralPath $privateRoot -Recurse -Force
        }
    }
}

if ($null -eq $kernelNetworkSummary) {
    $kernelNetworkSummary = [ordered]@{
        available = $false
        capture_started = $false
        parse_ok = $false
        unavailability_reason = 'capture_cleanup_failed'
        provider = 'Microsoft-Windows-Kernel-Network'
        keyword = '0x10'
        level = 4
        payload_capture_enabled = $false
        udp_send_event_id = 42
        udp_receive_event_id = 43
        logical_packet_count = 0
        awg_to_xray_packet_count = 0
        xray_to_awg_packet_count = 0
        awg_to_xray_payload_lengths = [ordered]@{}
        xray_to_awg_payload_lengths = [ordered]@{}
        awg_initiation_164_seen = $false
        xray_response_172_seen = $false
        response_returned_to_initiating_socket = $false
        xray_response_pid_matches = $false
        response_receive_event_seen = $false
        response_receive_pid_matches_awg_service = $false
        awg_udp_send_packet_count = 0
        awg_udp_send_to_expected_loopback_count = 0
        awg_udp_send_elsewhere_count = 0
        awg_udp_send_elsewhere_payload_lengths = [ordered]@{}
        awg_udp_send_elsewhere_destination_ports = [ordered]@{}
        echo_send_probe_attempted = $true
        echo_send_candidate_count = 0
        echo_send_source_matches_config = $false
        echo_send_destination_matches_gateway = $false
        echo_send_pid_matches_probe = $false
        echo_send_metadata_correlated = $false
        initiating_socket_count = 0
        response_socket_count = 0
        raw_trace_preserved = $false
        raw_trace_delete_verified = $false
    }
}
$xrayCarrierSummary = Get-WinsXrayCarrierSummary -State $xrayCarrierState
$adapterStatisticsDelta = Get-WinsAdapterStatisticsDelta `
    -Before $adapterStatisticsBefore -After $adapterStatisticsAfter
if ($DiagnosticOnLinkDefaultRoute) {
    $diagnosticRouteAb.data_path_fixed = [bool](
        $diagnosticRouteAb.mutation_committed -and
        ($echoResult.round_trip -or $httpsResult.reachable -or
            $adapterStatisticsDelta.received_bytes_delta -gt 0 -or
            $adapterStatisticsDelta.sent_bytes_delta -gt 0 -or
            ($observation -and
                ($observation.handshake_advanced -eq $true -or
                    [long]$observation.rx_delta -gt 0 -or
                    [long]$observation.tx_delta -gt 0)))
    )
}

$result = [ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-transport-live-probe-v1'
    captured_at_utc = [DateTime]::UtcNow.ToString('o')
    secret_material_redacted = $true
    publication_authorized = $false
    public_release_gate_eligible = $false
    expected_gui_sha256 = $ExpectedGuiSha256.ToLowerInvariant()
    connection = [ordered]@{
        connect_invoked = $connectInvoked
        invocation_method = $invocationMethod
        native_tunnel_seen = $nativeSeen
        xray_carrier_seen = $xraySeen
        cancel_state_seen = $cancelSeen
        committed_disconnect_state_seen = $disconnectSeen
        teardown_clean = $cleanupPassed
    }
    local = [ordered]@{
        adapter_count = $localState.adapter_count
        tunnel_ipv4_matches_config = $localState.tunnel_ipv4_matches_config
        full_tunnel_route_present = $localState.full_tunnel_route_present
        tunnel_route_count = $localState.tunnel_route_count
        dns_matches_config = $localState.dns_matches_config
        mtu_matches_config = $localState.mtu_matches_config
        awg_runtime_query = $awgStatus.query_ok
        awg_handshake_present = $awgStatus.handshake_present
        awg_received_bytes_nonzero = $awgStatus.received_bytes_nonzero
        awg_sent_bytes_nonzero = $awgStatus.sent_bytes_nonzero
        awg_handshake_unix = $awgStatus.handshake_unix
        awg_received_bytes = $awgStatus.received_bytes
        awg_sent_bytes = $awgStatus.sent_bytes
        vpn_echo_attempt_count = $echoAttempts
        vpn_echo_source_matches_config = $echoResult.source_matches_config
        vpn_echo_remote_matches_gateway = $echoResult.remote_matches_gateway
        vpn_echo_round_trip = $echoResult.round_trip
        bound_https_attempt_count = $httpsAttempts
        bound_https_reachable = $httpsResult.reachable
        bound_https_exit_differs_from_disconnected = `
            $httpsResult.exit_differs_from_disconnected
        awg_log_accessible = [bool]($awgLogBefore.accessible -and
            $awgLogAfter.accessible)
        awg_log_initiation_send_delta = [Math]::Max(0,
            (Get-WinsAwgSignatureDelta -Before $awgLogBefore `
                -After $awgLogAfter -EventName 'initiation_sends'))
        awg_log_unknown_message_type_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'unknown_message_types'
        awg_log_invalid_mac1_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'invalid_mac1_packets'
        awg_log_invalid_response_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'invalid_responses'
        awg_log_valid_response_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'valid_responses'
        awg_log_decode_response_failure_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'decode_response_failures'
        awg_log_derive_keypair_failure_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'derive_keypair_failures'
        awg_log_receive_failure_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'receive_failures'
        awg_log_handshake_retry_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'handshake_retries'
        awg_log_keepalive_send_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'keepalive_sends'
        awg_log_data_send_failure_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'data_send_failures'
        awg_log_tun_read_failure_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'tun_read_failures'
        awg_log_tun_reader_start_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'tun_reader_starts'
        awg_log_tun_reader_stop_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'tun_reader_stops'
        awg_log_encryption_worker_start_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'encryption_worker_starts'
        awg_log_encryption_worker_stop_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'encryption_worker_stops'
        awg_log_sequential_sender_start_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'sequential_sender_starts'
        awg_log_sequential_sender_stop_delta = Get-WinsAwgSignatureDelta `
            -Before $awgLogBefore -After $awgLogAfter `
            -EventName 'sequential_sender_stops'
        transport_path_diagnostic = [ordered]@{
            loopback_udp = $kernelNetworkSummary
            pktmon_loopback_udp = [ordered]@{
                supported_on_this_host = $false
                live_capture_attempted = $false
                reason = 'deterministic_loopback_selftest_observed_zero_events'
                false_zero_interpretation_prohibited = $true
            }
            xray_carrier = $xrayCarrierSummary
            winsvpn_adapter_statistics = $adapterStatisticsDelta
            best_route_selection = $bestRouteSelection
            diagnostic_on_link_route_ab = $diagnosticRouteAb
            raw_secrets_or_packet_payloads_emitted = $false
        }
    }
    server = $observation
}
$bytes = [Text.UTF8Encoding]::new($false).GetBytes(
    ($result | ConvertTo-Json -Depth 16) + [Environment]::NewLine
)
$stream = [IO.File]::Open(
    $outputFull, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
    [IO.FileShare]::None
)
try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
finally { $stream.Dispose() }
Write-Output "WINDOWS_TRANSPORT_LIVE_PROBE=$outputFull"
