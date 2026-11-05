[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExpectedPublicEgressSha256,
    [string]$AppPath = 'C:\Program Files\WinsVPN\wins_vpn.exe',
    [string]$OutputRoot = 'C:\ProgramData\WinsVPN\live-cycle',
    [string]$CaptureTool = '',
    [string]$ExcludedCurlExecutable = '',
    [string]$ExcludedBrowserExecutable = '',
    [string]$ExcludedCscriptExecutable = '',
    [string]$ExcludedCscriptScript = '',
    [string]$ExcludedRawExecutable = '',
    [string]$ExcludedRawScript = '',
    [switch]$DiagnosticRemoveManualTunnelDefault,
    [switch]$DiagnosticReplaceManualTunnelGateway,
    [switch]$RunNetworkChangeMatrix,
    [switch]$AllowSingleHop,
    [ValidateRange(0.0, 1.0)][double]$PowerXFraction = 0.5,
    [ValidateRange(0.0, 1.0)][double]$PowerYFraction = 0.80,
    [ValidateRange(60, 120)][int]$ConnectTimeoutSeconds = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$secureStateHelper = Join-Path $PSScriptRoot 'windows_secure_state_helpers.ps1'
if (-not (Test-Path -LiteralPath $secureStateHelper -PathType Leaf)) {
    throw "Win's VPN secure-state helper is missing: $secureStateHelper"
}
. $secureStateHelper

if ($ExpectedPublicEgressSha256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'ExpectedPublicEgressSha256 must be an exact SHA-256 digest.'
}
if ($DiagnosticRemoveManualTunnelDefault -and
    $DiagnosticReplaceManualTunnelGateway) {
    throw 'Configure only one diagnostic route mutation per live cycle.'
}
if (-not [string]::IsNullOrWhiteSpace($ExcludedCurlExecutable) -and
    -not (Test-Path -LiteralPath $ExcludedCurlExecutable -PathType Leaf)) {
    throw "Excluded curl canary executable not found: $ExcludedCurlExecutable"
}
if (-not [string]::IsNullOrWhiteSpace($ExcludedBrowserExecutable) -and
    -not (Test-Path -LiteralPath $ExcludedBrowserExecutable -PathType Leaf)) {
    throw "Excluded browser canary executable not found: $ExcludedBrowserExecutable"
}
if (-not [string]::IsNullOrWhiteSpace($ExcludedCscriptExecutable) -and
    -not (Test-Path -LiteralPath $ExcludedCscriptExecutable -PathType Leaf)) {
    throw "Excluded cscript canary executable not found: $ExcludedCscriptExecutable"
}
if (-not [string]::IsNullOrWhiteSpace($ExcludedRawExecutable) -and
    (-not (Test-Path -LiteralPath $ExcludedRawExecutable -PathType Leaf) -or
     -not (Test-Path -LiteralPath $ExcludedRawScript -PathType Leaf))) {
    throw 'The excluded raw TCP diagnostic executable or script is missing.'
}
$excludedCanaryKinds = @(@(
    $ExcludedCurlExecutable,
    $ExcludedBrowserExecutable,
    $ExcludedCscriptExecutable
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($excludedCanaryKinds.Count -gt 1) {
    throw 'Configure only one excluded-app canary kind per live cycle.'
}
if (-not [string]::IsNullOrWhiteSpace($ExcludedCscriptExecutable) -and
    (-not (Test-Path -LiteralPath $ExcludedCscriptScript -PathType Leaf))) {
    throw "Excluded cscript HTTPS canary script not found: $ExcludedCscriptScript"
}
if (-not [Environment]::UserInteractive) {
    throw "Win's VPN live cycle must run in the signed-in interactive user session."
}
$isAdministrator = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdministrator) {
    throw "Win's VPN live cycle requires an elevated interactive session."
}
if (-not (Test-Path -LiteralPath $AppPath -PathType Leaf)) {
    throw "Win's VPN executable not found: $AppPath"
}
if ([string]::IsNullOrWhiteSpace($CaptureTool)) {
    $CaptureTool = Join-Path $PSScriptRoot 'windows_interactive_uia_probe.ps1'
}
if (-not (Test-Path -LiteralPath $CaptureTool -PathType Leaf)) {
    throw "Win's VPN capture tool not found: $CaptureTool"
}

Add-Type @'
using System;
using System.Runtime.InteropServices;

public static class WinsVpnLiveNative {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [DllImport("user32.dll")]
    public static extern bool SetProcessDpiAwarenessContext(IntPtr value);

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr window, out RECT rect);

    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr window);

    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    public static extern bool BringWindowToTop(IntPtr window);

    [DllImport("user32.dll")]
    public static extern void keybd_event(byte virtualKey, byte scanCode,
        uint flags, UIntPtr extraInfo);

    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync(IntPtr window, int command);

    [DllImport("user32.dll")]
    public static extern bool SetWindowPos(IntPtr window, IntPtr insertAfter,
        int x, int y, int width, int height, uint flags);

    [DllImport("user32.dll")]
    public static extern bool SetCursorPos(int x, int y);

    [DllImport("user32.dll")]
    public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extraInfo);
}
'@
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

[WinsVpnLiveNative]::SetProcessDpiAwarenessContext([IntPtr]::new(-4)) | Out-Null
$ExpectedPublicEgressSha256 = $ExpectedPublicEgressSha256.ToLowerInvariant()
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$evidencePath = Join-Path $OutputRoot "windows-live-cycle-$stamp.json"

function Get-Sha256Text {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
        return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Get-PublicEgressDigest {
    $digests = foreach ($url in @('https://api.ipify.org', 'https://checkip.amazonaws.com')) {
        # Never reuse the baseline probe's pre-tunnel HTTP connection. A
        # keep-alive socket remains bound to its original physical path and can
        # therefore make a healthy split tunnel look disconnected after the
        # route/WFP policy changes. Each observation must create a new flow so
        # the evidence measures the current routing policy.
        $value = (Invoke-WebRequest -UseBasicParsing -DisableKeepAlive `
            -Uri $url -TimeoutSec 15).Content.Trim()
        if ($value -notmatch '^(?:\d{1,3}\.){3}\d{1,3}$') {
            throw 'A public-egress canary did not return an IPv4 address.'
        }
        $octets = $value -split '\.'
        if (@($octets | Where-Object { [int]$_ -gt 255 }).Count -ne 0) {
            throw 'A public-egress canary returned an invalid IPv4 address.'
        }
        Get-Sha256Text $value
    }
    if (@($digests | Select-Object -Unique).Count -ne 1) {
        throw 'Independent public-egress canaries disagreed.'
    }
    return $digests[0]
}

function Test-DirectDnsResolution {
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$Name
    )
    try {
        $answers = @(Resolve-DnsName $Name -Server $Server -Type A `
            -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
        @($answers | Where-Object { $_.Type -eq 'A' }).Count -gt 0
    } catch { $false }
}

function Get-Ipv6DefaultRouteRecords {
    @(Get-NetRoute -AddressFamily IPv6 -ErrorAction Stop |
        Where-Object { $_.DestinationPrefix -eq '::/0' } |
        Sort-Object InterfaceAlias, ifIndex, NextHop, RouteMetric |
        ForEach-Object {
            [pscustomobject][ordered]@{
                interface_alias = [string]$_.InterfaceAlias
                interface_index = [int]$_.ifIndex
                next_hop = [string]$_.NextHop
                route_metric = [int]$_.RouteMetric
                interface_metric = [int]$_.InterfaceMetric
                protocol = [string]$_.Protocol
            }
        })
}

function Get-Ipv6DefaultRouteSignature {
    @(Get-Ipv6DefaultRouteRecords | ForEach-Object {
        'alias={0};index={1};next={2};route={3};interface={4};protocol={5}' -f
            $_.interface_alias, $_.interface_index, $_.next_hop,
            $_.route_metric, $_.interface_metric, $_.protocol
    })
}

function Get-PhysicalIpv6BindingSignature {
    @(Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop |
        Where-Object { $_.Name -ne 'winsvpn' } |
        Sort-Object Name, InterfaceDescription |
        ForEach-Object {
            'name={0};description={1};enabled={2}' -f
                [string]$_.Name, [string]$_.InterfaceDescription,
                [bool]$_.Enabled
        })
}

function Test-Ipv6TcpEgress {
    param(
        [Parameter(Mandatory)][string]$Address,
        [ValidateRange(1, 65535)][int]$Port = 443,
        [ValidateRange(1000, 15000)][int]$TimeoutMilliseconds = 5000
    )
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed) -or
        $parsed.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetworkV6) {
        throw 'The forced IPv6 canary address is invalid.'
    }
    $socket = [Net.Sockets.Socket]::new(
        [Net.Sockets.AddressFamily]::InterNetworkV6,
        [Net.Sockets.SocketType]::Stream,
        [Net.Sockets.ProtocolType]::Tcp
    )
    $operation = $null
    try {
        $operation = $socket.BeginConnect($parsed, $Port, $null, $null)
        if (-not $operation.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) {
            return $false
        }
        try {
            $socket.EndConnect($operation)
            $socket.Connected
        } catch { $false }
    } catch { $false } finally {
        if ($null -ne $operation) { $operation.AsyncWaitHandle.Close() }
        $socket.Dispose()
    }
}

function Get-OwnedWfpFilterState {
    $path = Join-Path $OutputRoot (
        'wfp-owned-filter-state-' + [Guid]::NewGuid().ToString('N') + '.xml'
    )
    try {
        & netsh.exe wfp show state "file=$path" 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0 -or
            -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'Windows Filtering Platform state enumeration failed.'
        }
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
        $baselineGuid = '21e068a2-2851-43c5-8a29-7afe3f260384'
        $dnsGuid = 'e65841b6-82f6-4d55-bde2-61f84d4508d4'
        $baseline = @($filterNodes | Where-Object {
            $_.InnerXml -match [regex]::Escape($baselineGuid)
        }).Count
        $dns = @($filterNodes | Where-Object {
            $_.InnerXml -match [regex]::Escape($dnsGuid)
        }).Count
        [pscustomobject][ordered]@{
            enumeration_succeeded = $true
            baseline_filter_count = $baseline
            dns_filter_count = $dns
            total_owned_filter_count = $baseline + $dns
        }
    } finally {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

function Test-ConnectedIpv6FailClosed {
    param([Parameter(Mandatory)][string]$CanaryAddress)
    $routes = @(Get-Ipv6DefaultRouteRecords)
    $nonTunnelRoutes = @($routes | Where-Object {
        $_.interface_alias -ne 'winsvpn'
    })
    $ownedRoutes = @($routes | Where-Object {
        $_.interface_alias -eq 'winsvpn'
    })
    $adapter = @(Get-NetAdapter -Name 'winsvpn' -IncludeHidden `
        -ErrorAction Stop)
    $ownedRouteVerified = $ownedRoutes.Count -eq 0 -or
        ($ownedRoutes.Count -eq 1 -and $adapter.Count -eq 1 -and
         $ownedRoutes[0].interface_index -eq [int]$adapter.ifIndex)
    if ($nonTunnelRoutes.Count -ne 0 -or -not $ownedRouteVerified) {
        throw 'A connected IPv6 default route is not exclusively tunnel-owned.'
    }
    $forcedEgressSucceeded = Test-Ipv6TcpEgress -Address $CanaryAddress
    if ($forcedEgressSucceeded) {
        throw 'Forced literal IPv6 egress succeeded while the VPN was connected.'
    }
    [pscustomobject][ordered]@{
        default_route_count = $routes.Count
        non_tunnel_default_route_count = $nonTunnelRoutes.Count
        tunnel_owned_default_route_count = $ownedRoutes.Count
        tunnel_route_ownership_verified = $ownedRouteVerified
        forced_literal_egress_failed = $true
        physical_binding_signature_sha256 = Get-Sha256Text (
            (Get-PhysicalIpv6BindingSignature) -join '|'
        )
        passed = $nonTunnelRoutes.Count -eq 0 -and
            $ownedRouteVerified -and -not $forcedEgressSucceeded
    }
}

function Get-CurlEgressDigest {
    param([string]$InterfaceAddress = '')

    if ([string]::IsNullOrWhiteSpace($ExcludedCurlExecutable)) {
        throw 'The excluded curl canary executable was not configured.'
    }
    if (@($script:ResolvedCurlCanaries).Count -ne 2) {
        throw 'The excluded curl canaries were not resolved on the physical route before connection.'
    }
    $digests = foreach ($canary in $script:ResolvedCurlCanaries) {
        # The live comparison is explicitly an IPv4 egress proof.  Force the
        # excluded process onto the registered physical IPv4 address. Resolve
        # each hostname before the VPN connects because Windows intentionally
        # keeps DNS on the protected path even when an app's data path is
        # excluded; --resolve tests the selected process rather than DNSClient.
        $value = ''
        $curlExitCode = -1
        foreach ($revocationOption in @('--ssl-revoke-best-effort', '--ssl-no-revoke')) {
            $arguments = @(
                '--ipv4', '--fail', '--silent', '--show-error',
                # Windows' curl uses Schannel. First retain revocation checks
                # with curl's official best-effort handling of missing/offline
                # CRL endpoints. A code-35 Schannel handshake can still occur
                # after the WFP-excluded socket has established over the
                # physical path. For this route-only canary, retry once without
                # revocation lookup while retaining the normal CA chain,
                # hostname, expiry, and independent-endpoint checks. This does
                # not change any VPN or application TLS policy.
                $revocationOption,
                '--max-time', '15', '--resolve', $canary.resolve
            )
            if (-not [string]::IsNullOrWhiteSpace($InterfaceAddress)) {
                $arguments += @('--interface', $InterfaceAddress)
            }
            $arguments += $canary.url
            $previousErrorAction = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                $raw = @(& $ExcludedCurlExecutable @arguments 2>&1)
                $curlExitCode = $LASTEXITCODE
            } finally {
                $ErrorActionPreference = $previousErrorAction
            }
            $value = ([string]::Join("`n", @($raw | ForEach-Object { [string]$_ }))).Trim()
            if ($curlExitCode -eq 0 -and $value -match '^(?:\d{1,3}\.){3}\d{1,3}$') {
                if ($revocationOption -eq '--ssl-no-revoke') {
                    $script:ExcludedCanaryRevocationFallbackUsed = $true
                }
                break
            }
            if ($revocationOption -eq '--ssl-revoke-best-effort' -and $curlExitCode -ne 35) {
                break
            }
        }
        if ($curlExitCode -ne 0 -or $value -notmatch '^(?:\d{1,3}\.){3}\d{1,3}$') {
            throw "The excluded curl canary failed with exit code $curlExitCode."
        }
        $octets = $value -split '\.'
        if (@($octets | Where-Object { [int]$_ -gt 255 }).Count -ne 0) {
            throw 'The excluded curl canary returned an invalid IPv4 address.'
        }
        Get-Sha256Text $value
    }
    if (@($digests | Select-Object -Unique).Count -ne 1) {
        throw 'Independent excluded curl canaries disagreed.'
    }
    return $digests[0]
}

function Get-ChromiumBodyText {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$ProfilePath
    )

    $windowProcess = if ($script:BrowserCanaryWindowProcessId -gt 0) {
        Get-Process -Id $script:BrowserCanaryWindowProcessId `
            -ErrorAction SilentlyContinue
    } else { $null }
    $reuseExistingWindow =
        $null -ne $windowProcess -and $windowProcess.MainWindowHandle -ne 0
    if (-not $reuseExistingWindow) {
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $Executable
        $startInfo.UseShellExecute = $false
        $startInfo.Arguments = [string]::Join(' ', @(
            '--new-window',
            '--no-first-run',
            '--no-default-browser-check',
            '--disable-background-networking',
            '--disable-component-update',
            ('--user-data-dir="{0}"' -f $ProfilePath.Replace('"', '')),
            ('"{0}"' -f $Url)
        ))
        $launcher = [Diagnostics.Process]::new()
        $launcher.StartInfo = $startInfo
        if (-not $launcher.Start()) {
            throw 'The excluded browser canary process could not start.'
        }
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    if (-not $reuseExistingWindow) {
        $windowProcess = $null
        do {
            $profileProcesses = @(Get-CimInstance Win32_Process `
                -ErrorAction SilentlyContinue | Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_.CommandLine) -and
                    $_.CommandLine.Contains($ProfilePath)
                })
            foreach ($profileProcess in $profileProcesses) {
                $candidate = Get-Process -Id $profileProcess.ProcessId `
                    -ErrorAction SilentlyContinue
                if ($null -ne $candidate -and $candidate.MainWindowHandle -ne 0) {
                    $windowProcess = $candidate
                    break
                }
            }
            if ($null -ne $windowProcess) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $deadline)
    }
    if ($null -eq $windowProcess) {
        throw 'The excluded browser did not create an interactive test window.'
    }
    $script:BrowserCanaryWindowProcessId = $windowProcess.Id

    $savedClipboard = [Windows.Forms.Clipboard]::GetDataObject()
    $lastBodyText = ''
    try {
        if ($reuseExistingWindow) {
            [Windows.Forms.Clipboard]::SetText($Url)
            [WinsVpnLiveNative]::SetForegroundWindow(
                $windowProcess.MainWindowHandle
            ) | Out-Null
            [Windows.Forms.SendKeys]::SendWait('^l')
            [Windows.Forms.SendKeys]::SendWait('^v')
            [Windows.Forms.SendKeys]::SendWait('{ENTER}')
            Start-Sleep -Milliseconds 500
        }
        do {
            $marker = 'WINSVPN_BROWSER_CANARY_' + [Guid]::NewGuid().ToString('N')
            [Windows.Forms.Clipboard]::SetText($marker)
            [WinsVpnLiveNative]::SetForegroundWindow(
                $windowProcess.MainWindowHandle
            ) | Out-Null
            Start-Sleep -Milliseconds 250
            $rect = [WinsVpnLiveNative+RECT]::new()
            if (-not [WinsVpnLiveNative]::GetWindowRect(
                    $windowProcess.MainWindowHandle,
                    [ref]$rect
                )) {
                throw 'The excluded browser window bounds were unavailable.'
            }
            $contentX = $rect.Left + [int](($rect.Right - $rect.Left) * 0.5)
            $contentY = $rect.Top + [int](($rect.Bottom - $rect.Top) * 0.65)
            [WinsVpnLiveNative]::SetCursorPos($contentX, $contentY) | Out-Null
            [WinsVpnLiveNative]::mouse_event(0x0002, 0, 0, 0, [UIntPtr]::Zero)
            [WinsVpnLiveNative]::mouse_event(0x0004, 0, 0, 0, [UIntPtr]::Zero)
            Start-Sleep -Milliseconds 100
            [Windows.Forms.SendKeys]::SendWait('^a')
            [Windows.Forms.SendKeys]::SendWait('^c')
            Start-Sleep -Milliseconds 150
            $bodyText = if ([Windows.Forms.Clipboard]::ContainsText()) {
                [Windows.Forms.Clipboard]::GetText()
            } else { '' }
            $lastBodyText = $bodyText
            if ($bodyText -ne $marker -and
                $bodyText -match '(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)') {
                return $bodyText
            }
            Start-Sleep -Milliseconds 350
        } while ([DateTime]::UtcNow -lt $deadline)
    } finally {
        if ($null -ne $savedClipboard) {
            [Windows.Forms.Clipboard]::SetDataObject($savedClipboard, $true)
        }
    }
    $browserFailureStem = Join-Path $OutputRoot (
        'browser-ui-failure-' + [Guid]::NewGuid().ToString('N')
    )
    $browserFailureObservation = [ordered]@{
        schema_version = 1
        tested_at_utc = [DateTime]::UtcNow.ToString('o')
        secret_material_redacted = $true
        copied_text_length = $lastBodyText.Length
        copied_text_sha256 = Get-Sha256Text $lastBodyText
        copied_text_looks_like_url = $lastBodyText -match '^https?://'
        copied_text_contains_canary_host =
            $lastBodyText -match 'api\.ipify\.org|checkip\.amazonaws\.com'
        copied_ipv4_candidate_count = @([regex]::Matches(
            $lastBodyText,
            '(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)'
        )).Count
        screenshot_created = $false
        screenshot_sha256 = ''
        screenshot_error_sha256 = ''
    }
    try {
        $failureRect = [WinsVpnLiveNative+RECT]::new()
        if (-not [WinsVpnLiveNative]::GetWindowRect(
                $windowProcess.MainWindowHandle,
                [ref]$failureRect
            )) {
            throw 'The browser failure window bounds were unavailable.'
        }
        $failureWidth = $failureRect.Right - $failureRect.Left
        $failureHeight = $failureRect.Bottom - $failureRect.Top
        $bitmap = [Drawing.Bitmap]::new($failureWidth, $failureHeight)
        $graphics = [Drawing.Graphics]::FromImage($bitmap)
        try {
            $graphics.CopyFromScreen(
                $failureRect.Left,
                $failureRect.Top,
                0,
                0,
                [Drawing.Size]::new($failureWidth, $failureHeight)
            )
            $bitmap.Save(
                "$browserFailureStem.png",
                [Drawing.Imaging.ImageFormat]::Png
            )
        } finally {
            $graphics.Dispose()
            $bitmap.Dispose()
        }
        $browserFailureObservation.screenshot_created = $true
        $browserFailureObservation.screenshot_sha256 = (
            Get-FileHash -LiteralPath "$browserFailureStem.png" -Algorithm SHA256
        ).Hash
    } catch {
        $browserFailureObservation.screenshot_error_sha256 = Get-Sha256Text (
            [string]$_.Exception.Message
        )
    }
    $browserFailureObservation | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath `
        "$browserFailureStem-observation.json" -Encoding UTF8
    throw 'The excluded browser page did not expose a valid canary response.'
}

function Get-BrowserEgressDigest {
    if ([string]::IsNullOrWhiteSpace($ExcludedBrowserExecutable)) {
        throw 'The excluded browser canary executable was not configured.'
    }
    $browserCanaryIndex = 0
    $digests = foreach ($url in @(
        'https://api.ipify.org',
        'https://checkip.amazonaws.com'
    )) {
        ++$browserCanaryIndex
        $stdout = Get-ChromiumBodyText `
            -Executable $ExcludedBrowserExecutable `
            -Url $url `
            -ProfilePath $script:BrowserCanaryProfilePath
        $stderr = ''
        $matches = [regex]::Matches(
            [Net.WebUtility]::HtmlDecode($stdout),
            '(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)'
        ) | ForEach-Object Value | Select-Object -Unique
        $valid = @($matches | Where-Object {
            $octets = $_ -split '\.'
            $octets.Count -eq 4 -and
                @($octets | Where-Object { [int]$_ -gt 255 }).Count -eq 0
        })
        $browserObservation = [ordered]@{
            schema_version = 1
            tested_at_utc = [DateTime]::UtcNow.ToString('o')
            secret_material_redacted = $true
            canary_ordinal = $browserCanaryIndex
            process_exit_code = 0
            stdout_length = $stdout.Length
            stdout_sha256 = Get-Sha256Text $stdout
            stderr_length = $stderr.Length
            stderr_sha256 = Get-Sha256Text $stderr
            ipv4_candidate_count = $valid.Count
            ipv4_candidate_sha256 = @($valid | ForEach-Object {
                Get-Sha256Text $_
            })
        }
        $browserObservation | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath (Join-Path $OutputRoot (
                'browser-canary-observation-{0}-{1}.json' -f
                    $stamp, $browserCanaryIndex
            )) -Encoding UTF8
        if ($valid.Count -ne 1) {
            throw 'The excluded browser canary did not return one valid IPv4 address.'
        }
        Get-Sha256Text $valid[0]
    }
    if (@($digests | Select-Object -Unique).Count -ne 1) {
        throw 'Independent excluded browser canaries disagreed.'
    }
    return $digests[0]
}

function Get-CscriptEgressDigest {
    param([switch]$Http)
    if ([string]::IsNullOrWhiteSpace($ExcludedCscriptExecutable)) {
        throw 'The excluded cscript canary executable was not configured.'
    }
    $scheme = if ($Http) { 'http' } else { 'https' }
    $digests = foreach ($hostName in @('api.ipify.org', 'checkip.amazonaws.com')) {
        $url = "$scheme`://$hostName"
        $previousErrorAction = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $startInfo = [Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = $ExcludedCscriptExecutable
            $startInfo.Arguments = '//nologo "' +
                $ExcludedCscriptScript.Replace('"', '') + '" "' +
                $url.Replace('"', '') + '"'
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true
            $process = [Diagnostics.Process]::new()
            $process.StartInfo = $startInfo
            if (-not $process.Start()) {
                throw 'The excluded cscript canary process could not start.'
            }
            $deadline = [DateTime]::UtcNow.AddSeconds(35)
            do {
                $connections = @(Get-NetTCPConnection `
                    -ErrorAction SilentlyContinue | Where-Object {
                        $_.RemoteAddress -in $script:CscriptCanaryAddresses
                    } | Select-Object LocalAddress,LocalPort,RemoteAddress,
                        RemotePort,State,OwningProcess)
                if ($connections.Count -gt 0) {
                    $script:CscriptTcpObservations += $connections
                }
                if ($process.HasExited) { break }
                Start-Sleep -Milliseconds 100
            } while([DateTime]::UtcNow -lt $deadline)
            if (-not $process.HasExited) {
                $process.Kill()
                [void]$process.WaitForExit(5000)
            }
            $stdout = $process.StandardOutput.ReadToEnd()
            $stderr = $process.StandardError.ReadToEnd()
            $exitCode = $process.ExitCode
            $raw = @($stdout, $stderr)
            $process.Dispose()
        } finally {
            $ErrorActionPreference = $previousErrorAction
        }
        $value = ([string]::Join('', @($raw | ForEach-Object { [string]$_ }))).Trim()
        if ($exitCode -ne 0 -or
            $value -notmatch '^(?:\d{1,3}\.){3}\d{1,3}$') {
            $safeError = [regex]::Match($value, 'WINHTTP_ERROR_HEX=[0-9A-Fa-f]+').Value
            throw ("An excluded cscript WinHTTP $scheme canary failed with exit " +
                "code $exitCode" + $(if ($safeError) { " ($safeError)" } else { '' }) + '.')
        }
        $octets = $value -split '\.'
        if (@($octets | Where-Object { [int]$_ -gt 255 }).Count -ne 0) {
            throw 'An excluded cscript WinHTTP canary returned invalid IPv4.'
        }
        Get-Sha256Text $value
    }
    if (@($digests | Select-Object -Unique).Count -ne 1) {
        throw 'Independent excluded cscript WinHTTP canaries disagreed.'
    }
    return $digests[0]
}

function Get-RawTcpEgressDigest {
    if ([string]::IsNullOrWhiteSpace($ExcludedRawExecutable)) { return '' }
    $digests = foreach ($hostName in @('api.ipify.org','checkip.amazonaws.com')) {
        $raw = @(& $ExcludedRawExecutable -NoProfile -NonInteractive `
            -ExecutionPolicy Bypass -File $ExcludedRawScript `
            -HostName $hostName 2>&1)
        $exitCode = $LASTEXITCODE
        $value = ([string]::Join('', @($raw | ForEach-Object {
                    [string]$_
                }))).Trim()
        if ($exitCode -ne 0 -or $value -notmatch '^(?:\d{1,3}\.){3}\d{1,3}$') {
            $safeMarker = [regex]::Match(
                $value,
                'TCP_CONNECT_TIMEOUT|HTTP_RESPONSE_TOO_LARGE|HTTP_RESPONSE_INVALID|HTTP_BODY_INVALID|timed out'
            ).Value
            throw ("The raw TCP excluded diagnostic failed with exit code " +
                "$exitCode" + $(if ($safeMarker) { " ($safeMarker)" } else { '' }) + '.')
        }
        Get-Sha256Text $value
    }
    if (@($digests | Select-Object -Unique).Count -ne 1) {
        throw 'The raw TCP excluded diagnostics disagreed.'
    }
    return $digests[0]
}

function Start-SplitPacketCounters {
    if (@($script:CscriptCanaryAddresses).Count -eq 0) { return $false }
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & pktmon.exe stop 2>&1 | Out-Null
        & pktmon.exe filter remove 2>&1 | Out-Null
        $index = 0
        foreach ($address in $script:CscriptCanaryAddresses) {
            ++$index
            & pktmon.exe filter add "WinsVpnCanary$index" -i $address -t TCP `
                2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                & pktmon.exe filter remove 2>&1 | Out-Null
                return $false
            }
        }
        $script:PacketCaptureEtlPath = Join-Path $OutputRoot `
            "pktmon-headers-$stamp.etl"
        $script:PacketCaptureTextPath = Join-Path $OutputRoot `
            "pktmon-headers-$stamp.txt"
        Remove-Item -LiteralPath $script:PacketCaptureEtlPath,
            $script:PacketCaptureTextPath -Force -ErrorAction SilentlyContinue
        # The filters restrict this diagnostic to the two public canary IPs.
        # A 96-byte snapshot is sufficient for IP/TCP headers and cannot retain
        # an application response body.
        & pktmon.exe start --capture --comp nics --pkt-size 96 `
            --flags 0x017 `
            --file-name $script:PacketCaptureEtlPath --file-size 16 `
            --log-mode circular 2>&1 | Out-Null
        $script:PacketCountersRunning = $LASTEXITCODE -eq 0
        return $script:PacketCountersRunning
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
}

function Stop-SplitPacketCounters {
    if (-not $script:PacketCountersRunning) { return '' }
    $path = Join-Path $OutputRoot "pktmon-counters-$stamp.json"
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = @(& pktmon.exe counters --json 2>&1)
        $counterExit = $LASTEXITCODE
    } finally {
        & pktmon.exe stop 2>&1 | Out-Null
        if (-not [string]::IsNullOrWhiteSpace($script:PacketCaptureEtlPath) -and
            (Test-Path -LiteralPath $script:PacketCaptureEtlPath -PathType Leaf)) {
            & pktmon.exe etl2txt $script:PacketCaptureEtlPath `
                --out $script:PacketCaptureTextPath --verbose --hex `
                2>&1 | Out-Null
        }
        & pktmon.exe filter remove 2>&1 | Out-Null
        $script:PacketCountersRunning = $false
        $ErrorActionPreference = $previousErrorAction
    }
    if ($counterExit -eq 0 -and -not [string]::IsNullOrWhiteSpace(
            [string]::Join('', @($raw)))) {
        [IO.File]::WriteAllText(
            $path,
            [string]::Join([Environment]::NewLine, @($raw)),
            [Text.UTF8Encoding]::new($false)
        )
        return $path
    }
    return ''
}

function Save-SplitWfpNetEvents {
    $paths = @()
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $index = 0
        foreach ($address in $script:CscriptCanaryAddresses) {
            ++$index
            $path = Join-Path $OutputRoot "wfp-netevents-$stamp-$index.xml"
            & netsh.exe wfp show netevents "file=$path" protocol=6 `
                "remoteaddr=$address" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0 -and
                (Test-Path -LiteralPath $path -PathType Leaf)) {
                $paths += $path
            }
        }
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    return @($paths)
}

function Save-SplitWfpState {
    $path = Join-Path $OutputRoot "wfp-state-$stamp.xml"
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & netsh.exe wfp show state "file=$path" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0 -and
            (Test-Path -LiteralPath $path -PathType Leaf)) {
            return $path
        }
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    return ''
}

function Save-ExcludedSocketDiagnostic {
    param(
        [Parameter(Mandatory)][string]$PhysicalAddress,
        [Parameter(Mandatory)][string]$Path
    )

    $canary = $script:ResolvedCurlCanaries | Select-Object -First 1
    $tunnelAddress = Get-NetIPAddress -AddressFamily IPv4 `
        -InterfaceAlias 'winsvpn' -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty IPAddress
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $ExcludedCurlExecutable
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.Arguments = ('--ipv4 --fail --silent --show-error --ssl-revoke-best-effort --max-time 20 ' +
        '--resolve "{0}" "{1}"' -f $canary.resolve, $canary.url)
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'The excluded socket diagnostic process could not start.'
    }

    $states = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $connectionCount = 0
    $physicalBindSeen = $false
    $tunnelBindSeen = $false
    $deadline = [DateTime]::UtcNow.AddSeconds(22)
    while (-not $process.HasExited -and [DateTime]::UtcNow -lt $deadline) {
        foreach ($connection in @(Get-NetTCPConnection -OwningProcess $process.Id `
            -ErrorAction SilentlyContinue)) {
            ++$connectionCount
            [void]$states.Add($connection.State.ToString())
            if ($connection.LocalAddress -ceq $PhysicalAddress) {
                $physicalBindSeen = $true
            }
            if (-not [string]::IsNullOrWhiteSpace($tunnelAddress) -and
                $connection.LocalAddress -ceq $tunnelAddress) {
                $tunnelBindSeen = $true
            }
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not $process.HasExited) { $process.Kill() }
    $process.WaitForExit()
    $stdout = $process.StandardOutput.ReadToEnd().Trim()
    $stderr = $process.StandardError.ReadToEnd().Trim()
    $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
        -ErrorAction SilentlyContinue | Sort-Object RouteMetric, InterfaceMetric |
        ForEach-Object {
            [ordered]@{
                interface_alias = [string]$_.InterfaceAlias
                interface_index = [int]$_.InterfaceIndex
                route_metric = [int]$_.RouteMetric
                interface_metric = [int]$_.InterfaceMetric
                next_hop_on_link = [string]$_.NextHop -eq '0.0.0.0'
            }
        })
    $physicalInterfaceIndexes = @(
        Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
            ForEach-Object { [int]$_.InterfaceIndex }
    )
    $interfaces = @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $physicalInterfaceIndexes -contains [int]$_.InterfaceIndex -or
            $_.InterfaceAlias -match '(?i)winsvpn|amnezia|awg'
        } |
        ForEach-Object {
            [ordered]@{
                interface_alias = [string]$_.InterfaceAlias
                interface_index = [int]$_.InterfaceIndex
                connection_state = [string]$_.ConnectionState
                interface_metric = [int]$_.InterfaceMetric
                weak_host_send = [bool]$_.WeakHostSend
                weak_host_receive = [bool]$_.WeakHostReceive
            }
        })
    $diagnostic = [ordered]@{
        schema_version = 1
        tested_at_utc = [DateTime]::UtcNow.ToString('o')
        secret_material_redacted = $true
        process_started = $true
        exit_code = [int]$process.ExitCode
        tcp_connection_observation_count = $connectionCount
        tcp_states = @($states | Sort-Object)
        physical_source_bind_seen = $physicalBindSeen
        tunnel_source_bind_seen = $tunnelBindSeen
        stdout_was_ipv4 = $stdout -match '^(?:\d{1,3}\.){3}\d{1,3}$'
        stderr_sha256 = if ([string]::IsNullOrEmpty($stderr)) { '' } else {
            Get-Sha256Text $stderr
        }
        ipv4_default_routes = $routes
        relevant_interfaces = $interfaces
    }
    [IO.File]::WriteAllText(
        $Path,
        ($diagnostic | ConvertTo-Json -Depth 8),
        [Text.UTF8Encoding]::new($false)
    )
    return $diagnostic
}

function Get-WfpSplitReferenceCounts {
    $path = Join-Path $OutputRoot "wfp-split-$stamp.xml"
    try {
        & netsh.exe wfp show state "file=$path" 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw 'Windows Filtering Platform state capture failed.'
        }
        $state = [IO.File]::ReadAllText($path)
        return [pscustomobject]@{
            baseline = [regex]::Matches(
                $state,
                '21e068a2-2851-43c5-8a29-7afe3f260384',
                [Text.RegularExpressions.RegexOptions]::IgnoreCase
            ).Count
            dns = [regex]::Matches(
                $state,
                'e65841b6-82f6-4d55-bde2-61f84d4508d4',
                [Text.RegularExpressions.RegexOptions]::IgnoreCase
            ).Count
        }
    } finally {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

function Get-DefaultRouteSignature {
    $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Sort-Object RouteMetric, InterfaceMetric, ifIndex)
    if ($routes.Count -eq 0) { throw 'No IPv4 default route is present.' }
    return @($routes | ForEach-Object {
        "if=$($_.ifIndex);next=$($_.NextHop);route=$($_.RouteMetric);interface=$($_.InterfaceMetric)"
    })
}

function Get-WinsVpnProcess {
    $sessionId = (Get-Process -Id $PID).SessionId
    $process = Get-Process -Name wins_vpn -ErrorAction SilentlyContinue |
        Where-Object {
            $_.SessionId -eq $sessionId -and
            $_.MainWindowHandle -ne [IntPtr]::Zero
        } |
        Select-Object -First 1
    if (-not $process) {
        # A just-installed single-instance app can exist before Flutter has
        # published its top-level window. Launching again merely activates that
        # instance, so poll every same-session candidate for the actual handle
        # instead of treating process existence as UI readiness.
        Start-Process -FilePath $AppPath | Out-Null
        for ($attempt = 0; $attempt -lt 40; ++$attempt) {
            Start-Sleep -Milliseconds 250
            $process = Get-Process -Name wins_vpn -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.SessionId -eq $sessionId -and
                    $_.MainWindowHandle -ne [IntPtr]::Zero
                } |
                Select-Object -First 1
            if ($process) { break }
        }
    }
    if (-not $process) {
        throw "Win's VPN did not expose its interactive main window within 10 seconds."
    }
    return (Get-Process -Id $process.Id -ErrorAction Stop)
}

function Assert-NoPrivacyConsentOverlay {
    param([Parameter(Mandatory)]$Process)
    $root = [Windows.Automation.AutomationElement]::FromHandle(
        $Process.MainWindowHandle
    )
    if ($null -eq $root) {
        throw 'The app UI could not be inspected before the power action.'
    }
    $elements = @($root.FindAll(
        [Windows.Automation.TreeScope]::Subtree,
        [Windows.Automation.Condition]::TrueCondition
    ))
    $names = @($elements | ForEach-Object { [string]$_.Current.Name } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $privacyGatePresent = @($names | Where-Object {
        $_ -in @(
            'Privacy Policy and Legal Consent',
            'Accept Privacy Policy',
            'Privacy Policy and Legal Acceptance Required',
            'Review Privacy Policy to continue',
            'Datenschutzerklärung und rechtliche Zustimmung',
            'Privacy Policy နှင့် တရားဝင်သဘောတူညီချက် လိုအပ်သည်'
        ) -or $_ -like 'I have read and agree to the Privacy Policy*'
    }).Count -gt 0
    if ($privacyGatePresent) {
        throw 'WINS_PREFREEZE_PRIVACY_CONSENT_REQUIRED: complete first-run privacy/legal consent before the VPN matrix.'
    }
}

function Invoke-PowerButton {
    # Fractions bind the click to the exact app window rather than a monitor.
    # The defaults target the power control on the verified current main-map
    # layout; callers can override them for a deliberately changed layout.
    $process = Get-WinsVpnProcess
    Assert-NoPrivacyConsentOverlay -Process $process
    [WinsVpnLiveNative]::ShowWindowAsync($process.MainWindowHandle, 9) | Out-Null
    [WinsVpnLiveNative]::SetWindowPos(
        $process.MainWindowHandle, [IntPtr]::new(-1), 0, 0, 0, 0, 0x0043) | Out-Null
    [WinsVpnLiveNative]::SetWindowPos(
        $process.MainWindowHandle, [IntPtr]::new(-2), 0, 0, 0, 0, 0x0043) | Out-Null
    for ($focusAttempt = 0; $focusAttempt -lt 3; ++$focusAttempt) {
        # A synthetic Alt transition permits SetForegroundWindow under the
        # documented foreground-lock rules without crossing an integrity
        # boundary; the harness and target already share the elevated session.
        [WinsVpnLiveNative]::keybd_event(0x12, 0, 0, [UIntPtr]::Zero)
        [WinsVpnLiveNative]::keybd_event(0x12, 0, 2, [UIntPtr]::Zero)
        [WinsVpnLiveNative]::BringWindowToTop($process.MainWindowHandle) | Out-Null
        [WinsVpnLiveNative]::SetForegroundWindow($process.MainWindowHandle) | Out-Null
        Start-Sleep -Milliseconds 350
        if ([WinsVpnLiveNative]::GetForegroundWindow() -eq $process.MainWindowHandle) {
            break
        }
    }
    if ([WinsVpnLiveNative]::GetForegroundWindow() -ne $process.MainWindowHandle) {
        throw "Win's VPN did not become the verified foreground window before input."
    }
    # ShowWindowAsync may restore the app from a maximized rectangle to its
    # saved rectangle. Read the bounds only after that transition; otherwise a
    # stale coordinate can miss the control while still landing in the window.
    $rect = [WinsVpnLiveNative+RECT]::new()
    if (-not [WinsVpnLiveNative]::GetWindowRect($process.MainWindowHandle, [ref]$rect)) {
        throw "Win's VPN physical window rectangle could not be read after restore."
    }
    $x = $rect.Left + [Math]::Round(($rect.Right - $rect.Left) * $PowerXFraction)
    $y = $rect.Top + [Math]::Round(($rect.Bottom - $rect.Top) * $PowerYFraction)
    if (-not [WinsVpnLiveNative]::SetCursorPos($x, $y)) {
        throw "Windows rejected the verified Win's VPN power-button coordinate."
    }
    Assert-NoPrivacyConsentOverlay -Process $process
    Start-Sleep -Milliseconds 500
    [WinsVpnLiveNative]::mouse_event(0x0002, 0, 0, 0, [UIntPtr]::Zero)
    Start-Sleep -Milliseconds 100
    [WinsVpnLiveNative]::mouse_event(0x0004, 0, 0, 0, [UIntPtr]::Zero)
}

function Get-TunnelManagerCommitState {
    $result = [ordered]@{
        known = $false
        generation = [uint64]0
        phase = ''
        route_committed = $false
    }
    $pipe = $null
    $reader = $null
    $writer = $null
    try {
        $pipe = [IO.Pipes.NamedPipeClientStream]::new(
            '.', 'WinsVPN.TunnelManager.v1',
            [IO.Pipes.PipeDirection]::InOut,
            [IO.Pipes.PipeOptions]::Asynchronous,
            [Security.Principal.TokenImpersonationLevel]::Identification,
            [IO.HandleInheritability]::None
        )
        $pipe.Connect(300)
        $pipe.ReadMode = [IO.Pipes.PipeTransmissionMode]::Message
        $writer = [IO.BinaryWriter]::new($pipe, [Text.Encoding]::UTF8, $true)
        # WVP1, protocol v4, kStatus. Elevated-admin canaries may read status
        # only; start/stop success verbs are kStartSucceeded/kStopSucceeded.
        $writer.Write([uint32]0x31505657)
        $writer.Write([uint16]4)
        $writer.Write([uint16]3)
        $writer.Write([uint32]0)
        $writer.Write([uint32]0)
        $writer.Write([uint64]0)
        $writer.Flush()
        $reader = [IO.BinaryReader]::new($pipe, [Text.Encoding]::UTF8, $true)
        if ($reader.ReadUInt32() -ne [uint32]0x31505657 -or
            $reader.ReadUInt16() -ne [uint16]4) {
            return [pscustomobject]$result
        }
        $status = $reader.ReadUInt16()
        $payloadSize = $reader.ReadUInt32()
        if ($status -ne 0 -or $payloadSize -gt 8192) {
            return [pscustomobject]$result
        }
        $payload = [Text.Encoding]::UTF8.GetString(
            $reader.ReadBytes([int]$payloadSize)
        )
        $fields = @{}
        foreach ($part in ($payload -split ';')) {
            $equals = $part.IndexOf('=')
            if ($equals -gt 0) {
                $fields[$part.Substring(0, $equals)] =
                    $part.Substring($equals + 1)
            }
        }
        [uint64]$generation = 0
        if (-not [uint64]::TryParse(
                [string]$fields['generation'], [ref]$generation)) {
            return [pscustomobject]$result
        }
        $result.known = $true
        $result.generation = $generation
        $result.phase = [string]$fields['phase']
        $result.route_committed =
            [string]$fields['route_committed'] -ceq '1'
        return [pscustomobject]$result
    } catch {
        return [pscustomobject]$result
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $writer) { $writer.Dispose() }
        if ($null -ne $pipe) { $pipe.Dispose() }
    }
}

function Get-TunnelState {
    $legacyService = Get-Service -Name 'AmneziaWGTunnel$winsvpn' -ErrorAction SilentlyContinue
    $productEngine = Get-Process -Name 'winsvpn_awg_engine' -ErrorAction SilentlyContinue
    $splitService = Get-Service -Name 'WinsVPNSplitTunnel' -ErrorAction SilentlyContinue
    $adapter = Get-NetAdapter -Name 'winsvpn' -IncludeHidden -ErrorAction SilentlyContinue
    $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
        -InterfaceAlias 'winsvpn' -ErrorAction SilentlyContinue
    # Windows per-app mode deliberately keeps /0 out of the AWG config because
    # WireGuard for Windows interprets it as a kill-switch request. The
    # privileged manager may safely install a manual /0, plus more-specific
    # physical routes for every AllowedIPs gap, so a split-driver physical
    # source bind can participate in an equal-prefix route decision. Accept
    # that preferred plan, while retaining the exact-prefix check as a clear
    # diagnostic for older candidates.
    $configPath = 'C:\ProgramData\WinsVPN\winsvpn.conf'
    $expectedRoutePrefixes = @()
    if (Test-Path -LiteralPath $configPath -PathType Leaf) {
        $allowedLine = Get-Content -LiteralPath $configPath -ErrorAction SilentlyContinue |
            Where-Object { $_ -match '^AllowedIPs\s*=' } |
            Select-Object -First 1
        if ($allowedLine) {
            $expectedRoutePrefixes = @(
                (($allowedLine -replace '^AllowedIPs\s*=\s*', '') -split ',') |
                    ForEach-Object { $_.Trim() } |
                    Where-Object { $_ -match '^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$' } |
                    Select-Object -Unique
            )
        }
    }
    $actualRoutePrefixes = @(Get-NetRoute -AddressFamily IPv4 `
        -InterfaceAlias 'winsvpn' -ErrorAction SilentlyContinue |
        ForEach-Object DestinationPrefix | Select-Object -Unique)
    $configuredRoutesPresent = $expectedRoutePrefixes.Count -gt 0 -and
        @($expectedRoutePrefixes | Where-Object {
            $actualRoutePrefixes -notcontains $_
        }).Count -eq 0
    $fullTunnelRoutePresent = $null -ne $route -or $configuredRoutesPresent
    $manager = Get-TunnelManagerCommitState
    [pscustomobject]@{
        service_running = ($null -ne $legacyService -and
            $legacyService.Status -eq 'Running') -or $null -ne $productEngine
        adapter_up = $null -ne $adapter -and $adapter.Status -eq 'Up'
        default_route = $fullTunnelRoutePresent
        xray_running = $null -ne (Get-Process -Name xray -ErrorAction SilentlyContinue)
        split_service_running = $null -ne $splitService -and $splitService.Status -eq 'Running'
        manager_known = [bool]$manager.known
        generation = [uint64]$manager.generation
        phase = [string]$manager.phase
        route_committed = [bool]$manager.route_committed
    }
}

function Restore-TunnelManagerRunning {
    param([Parameter(Mandatory)][bool]$Recycle)

    $stopAttempted = $false
    $stopFailure = ''
    $startAttempted = $false
    $startFailure = ''
    $finalStatus = ''
    try {
        if ($Recycle) {
            $stopAttempted = $true
            try {
                Stop-Service -Name 'WinsVpnTunnelManager' -Force `
                    -ErrorAction Stop
                (Get-Service -Name 'WinsVpnTunnelManager' -ErrorAction Stop).
                    WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
            } catch {
                $stopFailure = $_.Exception.GetType().FullName
            }
        }
    } finally {
        try {
            $manager = Get-Service -Name 'WinsVpnTunnelManager' `
                -ErrorAction Stop
            if ($manager.Status -ne 'Running') {
                $startAttempted = $true
                Start-Service -Name 'WinsVpnTunnelManager' -ErrorAction Stop
                $manager = Get-Service -Name 'WinsVpnTunnelManager' `
                    -ErrorAction Stop
                $manager.WaitForStatus(
                    'Running', [TimeSpan]::FromSeconds(30)
                )
            }
            $finalStatus = [string](Get-Service `
                -Name 'WinsVpnTunnelManager' -ErrorAction Stop).Status
        } catch {
            $startFailure = $_.Exception.GetType().FullName
        }
    }
    if ($finalStatus -cne 'Running') {
        throw 'WinsVpnTunnelManager could not be verified Running after cleanup.'
    }
    [pscustomobject][ordered]@{
        recycle_requested = $Recycle
        stop_attempted = $stopAttempted
        stop_failure_type = $stopFailure
        start_attempted = $startAttempted
        start_failure_type = $startFailure
        final_status = $finalStatus
        running_verified = $true
    }
}

function Get-ConnectedEgressDisposition {
    param(
        [AllowEmptyString()][string]$Digest,
        [Parameter(Mandatory = $true)][string]$ExpectedDigest
    )
    if ([string]::IsNullOrWhiteSpace($Digest)) { return 'probe_failed' }
    if ($Digest -cne $ExpectedDigest) { return 'mismatch' }
    return 'match'
}

function Wait-PhysicalAdapterUp {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$WifiProfileName = ''
    )
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        Start-Sleep -Seconds 2
        $adapter = Get-NetAdapter -Name $Name -ErrorAction SilentlyContinue
        $address = Get-NetIPAddress -InterfaceAlias $Name -AddressFamily IPv4 `
            -ErrorAction SilentlyContinue | Where-Object {
                $_.IPAddress -notlike '169.254.*'
            } | Select-Object -First 1
        if ($null -ne $adapter -and $adapter.Status -eq 'Up' -and
            $null -ne $address) { return }
        if (-not [string]::IsNullOrWhiteSpace($WifiProfileName) -and
            $null -ne $adapter -and $adapter.Status -ne 'Disabled') {
            $netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
            & $netsh wlan connect "name=$WifiProfileName" "interface=$Name" |
                Out-Null
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Physical adapter did not recover with IPv4: $Name"
}

function Test-TransitionProtection {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$TunnelDns
    )
    $deadline = [DateTime]::UtcNow.AddSeconds(75)
    do {
        Start-Sleep -Seconds 2
        $egressMismatch = $false
        try {
            $state = Get-TunnelState
            if (-not ($state.service_running -and $state.adapter_up -and
                    $state.default_route)) { continue }
            $egress = Get-PublicEgressDigest
            if ($egress -cne $ExpectedPublicEgressSha256) {
                $egressMismatch = $true
                throw 'Network transition exposed unexpected public egress.'
            }
            $tunnelDnsServers = @(Get-DnsClientServerAddress -AddressFamily IPv4 `
                -ErrorAction SilentlyContinue | Where-Object {
                    $_.InterfaceAlias -match '(?i)winsvpn|amnezia|awg'
                } | ForEach-Object ServerAddresses | Where-Object { $_ })
            if ($tunnelDnsServers -notcontains $TunnelDns) { continue }
            $answer = Resolve-DnsName winsvpn.org -Server $TunnelDns -Type A `
                -DnsOnly -QuickTimeout -ErrorAction Stop
            if (@($answer | Where-Object Type -eq 'A').Count -lt 1) { continue }
            return [ordered]@{
                name = $Name
                transition_observed = $true
                protected_egress_sha256 = $egress
                dns_protected = $true
                passed = $true
            }
        } catch {
            if ($egressMismatch) { throw }
            # A physical transition is expected to invalidate sockets briefly.
            # Retrying creates new flows and never accepts an unprotected result.
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Tunnel protection did not recover after network transition: $Name"
}

function Invoke-NetworkChangeMatrix {
    param([Parameter(Mandatory = $true)][string]$TunnelDns)
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
        throw 'Network-change matrix requires active Wi-Fi and Ethernet adapters.'
    }
    $wifiName = [string]$wifi[0].Name
    $ethernetName = [string]$ethernet[0].Name
    $netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
    $wlanState = [string]::Join("`n", @(& $netsh wlan show interfaces 2>&1))
    $profileMatch = [regex]::Match(
        $wlanState,
        '(?im)^\s*Profile\s*:\s*(?<profile>.+?)\s*$'
    )
    $wifiProfileName = if ($profileMatch.Success) {
        [string]$profileMatch.Groups['profile'].Value
    } else { '' }
    if ([string]::IsNullOrWhiteSpace($wifiProfileName)) {
        throw 'Active Wi-Fi connection has no reconnectable profile name.'
    }
    $profiles = [Collections.Generic.List[object]]::new()
    $ipv6Binding = Get-NetAdapterBinding -Name $ethernetName `
        -ComponentID ms_tcpip6 -ErrorAction Stop
    $ipv6BaselineEnabled = [bool]$ipv6Binding.Enabled
    try {
        try {
            Disable-NetAdapter -Name $wifiName -Confirm:$false -ErrorAction Stop
            Start-Sleep -Seconds 4
            if ((Get-NetAdapter -Name $wifiName).Status -ne 'Disabled') {
                throw 'Wi-Fi to Ethernet transition was not observed.'
            }
            [void]$profiles.Add((Test-TransitionProtection `
                -Name 'wifi_to_ethernet' -TunnelDns $TunnelDns))
        } finally {
            Enable-NetAdapter -Name $wifiName -Confirm:$false `
                -ErrorAction SilentlyContinue
            Wait-PhysicalAdapterUp -Name $wifiName `
                -WifiProfileName $wifiProfileName
        }

        try {
            Disable-NetAdapter -Name $ethernetName -Confirm:$false -ErrorAction Stop
            Start-Sleep -Seconds 4
            if ((Get-NetAdapter -Name $ethernetName).Status -ne 'Disabled') {
                throw 'Ethernet to Wi-Fi transition was not observed.'
            }
            [void]$profiles.Add((Test-TransitionProtection `
                -Name 'ethernet_to_wifi' -TunnelDns $TunnelDns))
        } finally {
            Enable-NetAdapter -Name $ethernetName -Confirm:$false `
                -ErrorAction SilentlyContinue
            Wait-PhysicalAdapterUp -Name $ethernetName
        }

        $ipconfig = Join-Path $env:SystemRoot 'System32\ipconfig.exe'
        foreach ($adapterName in @($wifiName, $ethernetName)) {
            $renew = Start-Process -FilePath $ipconfig `
                -ArgumentList @('/renew', ('"{0}"' -f $adapterName)) `
                -Wait -PassThru `
                -WindowStyle Hidden
            if ($renew.ExitCode -ne 0) {
                throw "DHCP renewal failed for physical adapter: $adapterName"
            }
        }
        [void]$profiles.Add((Test-TransitionProtection `
            -Name 'dhcp_renew' -TunnelDns $TunnelDns))

        if ($ipv6BaselineEnabled) {
            Disable-NetAdapterBinding -Name $ethernetName -ComponentID ms_tcpip6 `
                -ErrorAction Stop | Out-Null
            Start-Sleep -Seconds 2
            Enable-NetAdapterBinding -Name $ethernetName -ComponentID ms_tcpip6 `
                -ErrorAction Stop | Out-Null
        } else {
            Enable-NetAdapterBinding -Name $ethernetName -ComponentID ms_tcpip6 `
                -ErrorAction Stop | Out-Null
            Start-Sleep -Seconds 2
            Disable-NetAdapterBinding -Name $ethernetName -ComponentID ms_tcpip6 `
                -ErrorAction Stop | Out-Null
        }
        Start-Sleep -Seconds 4
        [void]$profiles.Add((Test-TransitionProtection `
            -Name 'ipv6_binding_recovery' -TunnelDns $TunnelDns))
    } finally {
        if ($ipv6BaselineEnabled) {
            Enable-NetAdapterBinding -Name $ethernetName -ComponentID ms_tcpip6 `
                -ErrorAction SilentlyContinue | Out-Null
        } else {
            Disable-NetAdapterBinding -Name $ethernetName -ComponentID ms_tcpip6 `
                -ErrorAction SilentlyContinue | Out-Null
        }
        Enable-NetAdapter -Name $wifiName -Confirm:$false `
            -ErrorAction SilentlyContinue
        Enable-NetAdapter -Name $ethernetName -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
    return [ordered]@{
        profiles = @($profiles)
        profile_count = $profiles.Count
        ipv6_baseline_enabled = $ipv6BaselineEnabled
        passed = $profiles.Count -eq 4 -and
            @($profiles | Where-Object { -not $_.passed }).Count -eq 0
    }
}

function Invoke-Capture {
    param([Parameter(Mandatory = $true)][string]$Phase)
    $json = Join-Path $OutputRoot "$Phase-$stamp.json"
    $png = Join-Path $OutputRoot "$Phase-$stamp.png"
    # A cold Flutter/DWM start can expose the native window before its surface
    # is rendered. Wait long enough that the subsequent coordinate-bound click
    # targets the actual app UI instead of a transparent first frame.
    & $CaptureTool -AppPath $AppPath -OutputPath $json -ScreenshotPath $png -WarmupSeconds 5 | Out-Null
    if (-not (Test-Path -LiteralPath $png -PathType Leaf)) {
        throw "Win's VPN $Phase screenshot was not created."
    }
    return [pscustomobject]@{
        json = $json
        png = $png
        screenshot_sha256 = (Get-FileHash -LiteralPath $png -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Get-OptionalJsonValue {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )
    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    $property.Value
}

function Get-ConnectedConfigProjectionDigest {
    param([Parameter(Mandatory)]$Config)
    $projection = [ordered]@{
        double_vpn_active = [bool](Get-OptionalJsonValue $Config `
            'double_vpn_active' $false)
        double_vpn_core_id = [string](Get-OptionalJsonValue $Config `
            'double_vpn_core_id' '')
        double_vpn_exit_slug = [string](Get-OptionalJsonValue $Config `
            'double_vpn_exit_slug' '')
        server_endpoint = [string](Get-OptionalJsonValue $Config `
            'server_endpoint' '')
        node_slug = [string](Get-OptionalJsonValue $Config 'node_slug' '')
        dns = [string](Get-OptionalJsonValue $Config 'dns' '')
    }
    Get-Sha256Text ($projection | ConvertTo-Json -Compress)
}

function Get-StableConnectedConfig {
    param(
        [Parameter(Mandatory)][uint64]$ExpectedGeneration
    )
    if ($ExpectedGeneration -eq 0) {
        throw 'The expected manager generation must be nonzero.'
    }
    $before = Get-TunnelManagerCommitState
    if (-not $before.known -or -not $before.route_committed -or
        $before.phase -cne 'committed' -or
        [uint64]$before.generation -ne $ExpectedGeneration) {
        throw 'The manager generation changed before connected config observation.'
    }
    $first = Read-WinsVpnSecureJson -Name 'vpn_config.txt'
    $firstDigest = Get-ConnectedConfigProjectionDigest $first
    Start-Sleep -Milliseconds 500
    $second = Read-WinsVpnSecureJson -Name 'vpn_config.txt'
    $secondDigest = Get-ConnectedConfigProjectionDigest $second
    $after = Get-TunnelManagerCommitState
    if (-not $after.known -or -not $after.route_committed -or
        $after.phase -cne 'committed' -or
        [uint64]$after.generation -ne $ExpectedGeneration -or
        $firstDigest -cne $secondDigest) {
        throw 'Connected SecureState config was not stable within one manager generation.'
    }
    $configGeneration = [uint64]0
    $configGenerationPresent = $false
    foreach ($name in @('manager_generation', 'tunnel_generation', 'generation')) {
        $raw = Get-OptionalJsonValue $second $name $null
        if ($null -eq $raw) { continue }
        if (-not [uint64]::TryParse([string]$raw, [ref]$configGeneration) -or
            $configGeneration -ne $ExpectedGeneration) {
            throw 'Connected SecureState config generation contradicts the manager.'
        }
        $configGenerationPresent = $true
        break
    }
    [pscustomobject][ordered]@{
        config = $second
        projection_sha256 = $secondDigest
        manager_generation_before = [uint64]$before.generation
        manager_generation_after = [uint64]$after.generation
        config_generation_field_present = $configGenerationPresent
        config_generation = $configGeneration
        stable_within_manager_generation = $true
        secure_state_preferred_over_legacy = $true
    }
}

$settings = Read-WinsVpnSecureJson -Name 'vpn_settings.txt'
$doubleVpnExpected = -not $AllowSingleHop
if ($doubleVpnExpected -and $settings.double_vpn_requested -ne $true) {
    throw 'Double VPN is not enabled in the exact installed app settings.'
}
if (-not $doubleVpnExpected -and $settings.double_vpn_requested -eq $true) {
    throw 'The single-hop live cycle requires Double VPN to be disabled.'
}
$splitTunnelTested = (-not [string]::IsNullOrWhiteSpace($ExcludedCurlExecutable)) -or
    (-not [string]::IsNullOrWhiteSpace($ExcludedBrowserExecutable)) -or
    (-not [string]::IsNullOrWhiteSpace($ExcludedCscriptExecutable))
$excludedCanaryExecutable = if (-not [string]::IsNullOrWhiteSpace($ExcludedCscriptExecutable)) {
    $ExcludedCscriptExecutable
} elseif (-not [string]::IsNullOrWhiteSpace($ExcludedBrowserExecutable)) {
    $ExcludedBrowserExecutable
} else { $ExcludedCurlExecutable }
$excludedCanaryKind = if (-not [string]::IsNullOrWhiteSpace($ExcludedCscriptExecutable)) {
    'cscript_winhttp_https'
} elseif (-not [string]::IsNullOrWhiteSpace($ExcludedBrowserExecutable)) {
    'chromium_headless_https'
} else { 'curl_https' }
if ($splitTunnelTested) {
    $savedExclusions = @($settings.excluded_vpn_packages | ForEach-Object { [string]$_ })
    if (-not ($savedExclusions -ccontains $excludedCanaryExecutable)) {
        throw 'The exact excluded canary executable is not selected in the app settings.'
    }
}

$appHash = (Get-FileHash -LiteralPath $AppPath -Algorithm SHA256).Hash.ToLowerInvariant()
$servicePath = 'C:\Program Files\WinsVPN\wins_vpn_tunnel_service.exe'
if (-not (Test-Path -LiteralPath $servicePath -PathType Leaf)) {
    throw "Win's VPN protected service executable is missing."
}
$serviceHash = (Get-FileHash -LiteralPath $servicePath -Algorithm SHA256).Hash.ToLowerInvariant()
$originalRoutes = Get-DefaultRouteSignature
$originalIpv6Routes = @(Get-Ipv6DefaultRouteSignature)
$originalIpv6Bindings = @(Get-PhysicalIpv6BindingSignature)
$originalIpv6RoutesSha256 = Get-Sha256Text ($originalIpv6Routes -join '|')
$originalIpv6BindingsSha256 = Get-Sha256Text (
    $originalIpv6Bindings -join '|'
)
$externalDnsServer = '1.1.1.1'
$baselineExternalDnsAvailable = Test-DirectDnsResolution `
    -Server $externalDnsServer -Name 'winsvpn.org'
if (-not $baselineExternalDnsAvailable) {
    throw 'The direct external DNS baseline is unavailable; a negative leak test would be invalid.'
}
$baselineWfp = Get-OwnedWfpFilterState
if (-not $baselineWfp.enumeration_succeeded -or
    $baselineWfp.total_owned_filter_count -ne 0) {
    throw 'Owned Win''s VPN WFP filters exist before the live cycle.'
}
$ipv6CanaryAddress = '2606:4700:4700::1111'
$baselineIpv6EgressRequired = $originalIpv6Routes.Count -gt 0
$baselineIpv6EgressAvailable = Test-Ipv6TcpEgress `
    -Address $ipv6CanaryAddress
if ($baselineIpv6EgressRequired -and -not $baselineIpv6EgressAvailable) {
    throw 'A physical IPv6 default exists, but the literal IPv6 baseline is unavailable.'
}
$physicalConfiguration = Get-NetIPConfiguration -ErrorAction Stop |
    Where-Object {
        $null -ne $_.IPv4DefaultGateway -and
        $null -ne $_.IPv4Address -and
        $_.NetAdapter.Status -eq 'Up'
    } |
    Sort-Object @{ Expression = { $_.NetIPv4Interface.InterfaceMetric } } |
    Select-Object -First 1
if ($null -eq $physicalConfiguration) {
    throw 'The physical IPv4 default route is unavailable before connection.'
}
$physicalInterfaceAddress = [string]$physicalConfiguration.IPv4Address.IPAddress
if ($physicalInterfaceAddress -notmatch '^(?:\d{1,3}\.){3}\d{1,3}$') {
    throw 'The physical IPv4 address could not be determined safely.'
}
$script:ResolvedCurlCanaries = @()
$script:CscriptCanaryAddresses = @()
$script:PacketCountersRunning = $false
$script:PacketCaptureEtlPath = ''
$script:PacketCaptureTextPath = ''
$script:CscriptTcpObservations = @()
$script:ExcludedCanaryRevocationFallbackUsed = $false
$script:DiagnosticHalfRoutesInstalled = $false
$script:DiagnosticGatewayRouteInstalled = $false
$script:DiagnosticGatewayAddress = ''
$script:BrowserCanaryWindowProcessId = 0
$browserProfileRoot = Join-Path $env:LOCALAPPDATA `
    'WinsVPN\browser-canary-profiles'
New-Item -ItemType Directory -Force -Path $browserProfileRoot | Out-Null
$script:BrowserCanaryProfilePath = Join-Path $browserProfileRoot (
    'browser-canary-profile-' + [Guid]::NewGuid().ToString('N')
)
if (-not [string]::IsNullOrWhiteSpace($ExcludedCurlExecutable)) {
    $script:ResolvedCurlCanaries = foreach ($url in @(
        'https://api.ipify.org',
        'https://checkip.amazonaws.com'
    )) {
        $uri = [Uri]$url
        $address = [Net.Dns]::GetHostAddresses($uri.DnsSafeHost) |
            Where-Object AddressFamily -eq ([Net.Sockets.AddressFamily]::InterNetwork) |
            Select-Object -First 1
        if ($null -eq $address) {
            throw 'An excluded curl canary did not resolve to IPv4 before connection.'
        }
        [pscustomobject]@{
            url = $url
            resolve = '{0}:443:{1}' -f $uri.DnsSafeHost, $address.IPAddressToString
        }
    }
}
if (-not [string]::IsNullOrWhiteSpace($ExcludedCscriptExecutable)) {
    $script:CscriptCanaryAddresses = @(
        'api.ipify.org',
        'checkip.amazonaws.com'
    ) | ForEach-Object {
        [Net.Dns]::GetHostAddresses($_) |
            Where-Object AddressFamily -eq ([Net.Sockets.AddressFamily]::InterNetwork) |
            Select-Object -First 1 -ExpandProperty IPAddressToString
    } | Where-Object { $_ -match '^(?:\d{1,3}\.){3}\d{1,3}$' } |
        Select-Object -Unique
    if (@($script:CscriptCanaryAddresses).Count -eq 0) {
        throw 'The cscript packet-counter canaries did not resolve to IPv4.'
    }
}
$originalEgressDigest = Get-PublicEgressDigest
if ($ExpectedPublicEgressSha256 -ceq $originalEgressDigest) {
    throw 'Expected protected VPN egress must differ from disconnected egress.'
}
$baselineExcludedEgressDigest = if (-not [string]::IsNullOrWhiteSpace($ExcludedCscriptExecutable)) {
    Get-CscriptEgressDigest
} elseif (-not [string]::IsNullOrWhiteSpace($ExcludedBrowserExecutable)) {
    Get-BrowserEgressDigest
} elseif ($splitTunnelTested) { Get-CurlEgressDigest } else { '' }
if ($splitTunnelTested -and $baselineExcludedEgressDigest -cne $originalEgressDigest) {
    throw 'The excluded-app canary did not match the original egress before connection.'
}
$baselineCapture = Invoke-Capture -Phase 'baseline'
$connected = $false
$cleanupFallbackUsed = $false
$liveCyclePassed = $false
$connectionAttempts = [Collections.Generic.List[object]]::new()
$connectedEgressMismatchObserved = $false
$connectedEgressMismatchCount = 0
$connectionAttemptsPath = Join-Path $OutputRoot `
    "connection-attempts-$stamp.json"
$configObservation = $null
$connectedIpv6Evidence = $null
$connectedWfp = $null
$tunnelDnsResolutionSucceeded = $false
$externalDnsResolutionBlocked = $false
$externalDnsResolutionRestored = $false
$managerCleanupEvidence = $null

try {
    Invoke-PowerButton
    $deadline = [DateTime]::UtcNow.AddSeconds($ConnectTimeoutSeconds)
    $tunnel = $null
    $connectedEgressDigest = ''
    do {
        Start-Sleep -Seconds 2
        $tunnel = Get-TunnelState
        $attempt = [ordered]@{
            observed_at_utc = [DateTime]::UtcNow.ToString('o')
            service_running = [bool]$tunnel.service_running
            adapter_up = [bool]$tunnel.adapter_up
            default_route = [bool]$tunnel.default_route
            split_service_running = [bool]$tunnel.split_service_running
            connected_egress_sha256 = ''
            egress_disposition = 'not_probed'
            egress_probe_error = ''
            pre_manager_known = [bool]$tunnel.manager_known
            pre_generation = [uint64]$tunnel.generation
            pre_phase = [string]$tunnel.phase
            pre_route_committed = [bool]$tunnel.route_committed
            post_manager_known = $false
            post_generation = [uint64]0
            post_phase = ''
            post_route_committed = $false
            generation_stable_across_canary = $false
        }
        # Route exposure begins as soon as the adapter and its full-tunnel route
        # are active. Probe that state even if process/service discovery is one
        # polling interval behind, and make any observed mismatch sticky.
        if ($tunnel.adapter_up -and $tunnel.default_route -and
            $tunnel.manager_known -and $tunnel.route_committed -and
            $tunnel.phase -ceq 'committed' -and $tunnel.generation -gt 0) {
            try {
                $connectedEgressDigest = Get-PublicEgressDigest
                $attempt.connected_egress_sha256 = $connectedEgressDigest
            } catch {
                $connectedEgressDigest = ''
                $attempt.egress_disposition = 'probe_failed'
                # Get-PublicEgressDigest emits only fixed diagnostic messages;
                # retain that classification, never the response body or IP.
                $attempt.egress_probe_error = [string]$_.Exception.Message
            }
            $postTunnel = Get-TunnelState
            $attempt.post_manager_known = [bool]$postTunnel.manager_known
            $attempt.post_generation = [uint64]$postTunnel.generation
            $attempt.post_phase = [string]$postTunnel.phase
            $attempt.post_route_committed = [bool]$postTunnel.route_committed
            $attempt.generation_stable_across_canary =
                $postTunnel.manager_known -and $postTunnel.route_committed -and
                $postTunnel.phase -ceq 'committed' -and
                $postTunnel.generation -eq $tunnel.generation -and
                $postTunnel.adapter_up -and $postTunnel.default_route
            if (-not $attempt.generation_stable_across_canary) {
                $attempt.egress_disposition = 'state_changed'
                $connectedEgressDigest = ''
            } elseif ($attempt.egress_disposition -cne 'probe_failed') {
                $attempt.egress_disposition = Get-ConnectedEgressDisposition `
                    -Digest $connectedEgressDigest `
                    -ExpectedDigest $ExpectedPublicEgressSha256
            }
            if ($attempt.egress_disposition -ceq 'mismatch' -and
                $attempt.generation_stable_across_canary) {
                $connectedEgressMismatchObserved = $true
                ++$connectedEgressMismatchCount
            } elseif ($attempt.egress_disposition -ceq 'match' -and
                $attempt.generation_stable_across_canary -and
                $postTunnel.service_running) {
                $connected = $true
                $tunnel = $postTunnel
            }
        }
        [void]$connectionAttempts.Add([pscustomobject]$attempt)
        if ($connected -or $connectedEgressMismatchObserved) { break }
    } while ([DateTime]::UtcNow -lt $deadline)
    [ordered]@{
        schema_version = 2
        platform = 'windows'
        tested_at_utc = [DateTime]::UtcNow.ToString('o')
        secret_material_redacted = $true
        expected_public_egress_sha256 = $ExpectedPublicEgressSha256
        connected_egress_mismatch_observed = $connectedEgressMismatchObserved
        connected_egress_mismatch_count = $connectedEgressMismatchCount
        attempts = @($connectionAttempts)
    } | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath $connectionAttemptsPath -Encoding UTF8
    if ($connectedEgressMismatchObserved) {
        throw 'An active Win''s VPN route exposed unexpected public egress.'
    }
    if (-not $connected) {
        throw "Exact Windows tunnel did not establish the expected routed egress."
    }
    $connectedTunnel = $tunnel
    $configObservation = Get-StableConnectedConfig `
        -ExpectedGeneration ([uint64]$connectedTunnel.generation)
    $config = $configObservation.config
    $tunnelDns = [string](Get-OptionalJsonValue $config 'dns' '')
    $parsedTunnelDns = $null
    if (-not [Net.IPAddress]::TryParse($tunnelDns, [ref]$parsedTunnelDns) -or
        $parsedTunnelDns.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork -or
        $tunnelDns -ceq $externalDnsServer) {
        throw 'Connected SecureState has no distinct tunnel DNS IPv4 address.'
    }
    $tunnelDnsResolutionSucceeded = Test-DirectDnsResolution `
        -Server $tunnelDns -Name 'winsvpn.org'
    if (-not $tunnelDnsResolutionSucceeded) {
        throw 'The configured tunnel DNS resolver did not answer while connected.'
    }
    $externalDnsResolutionBlocked = -not (Test-DirectDnsResolution `
        -Server $externalDnsServer -Name 'winsvpn.org')
    if (-not $externalDnsResolutionBlocked) {
        throw 'Direct 1.1.1.1 DNS resolution remained reachable while connected.'
    }
    $connectedIpv6Evidence = Test-ConnectedIpv6FailClosed `
        -CanaryAddress $ipv6CanaryAddress
    if (-not $connectedIpv6Evidence.passed) {
        throw 'Connected IPv6 fail-closed evidence did not pass.'
    }
    $connectedWfp = Get-OwnedWfpFilterState
    $diagnosticTunnelDefaultRemoved = $false
    $diagnosticTunnelGatewayReplaced = $false
    $diagnosticTunnelGatewayDerivation = ''
    $diagnosticPairedHalfRoutesPresent = $false
    $diagnosticNonExcludedEgressPreserved = $false
    if ($DiagnosticRemoveManualTunnelDefault) {
        $ownedDefaults = @(Get-NetRoute -AddressFamily IPv4 `
            -DestinationPrefix '0.0.0.0/0' -InterfaceAlias 'winsvpn' `
            -ErrorAction Stop)
        if ($ownedDefaults.Count -ne 1) {
            throw 'The diagnostic expected exactly one Win''s VPN IPv4 default route.'
        }
        $ownedDefaults | Remove-NetRoute -Confirm:$false -ErrorAction Stop
        Start-Sleep -Seconds 2
        if (Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
                -InterfaceAlias 'winsvpn' -ErrorAction SilentlyContinue) {
            throw 'The diagnostic Win''s VPN IPv4 default route remained installed.'
        }
        $diagnosticTunnelDefaultRemoved = $true
        $existingHalfRoutes = @(Get-NetRoute -AddressFamily IPv4 `
            -InterfaceAlias 'winsvpn' -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DestinationPrefix -in @('0.0.0.0/1', '128.0.0.0/1')
            })
        if ($existingHalfRoutes.Count -ne 0) {
            throw 'The diagnostic found pre-existing Win''s VPN half routes.'
        }
        foreach ($prefix in @('0.0.0.0/1', '128.0.0.0/1')) {
            New-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix `
                -InterfaceAlias 'winsvpn' -NextHop '0.0.0.0' -RouteMetric 0 `
                -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
        }
        $script:DiagnosticHalfRoutesInstalled = $true
        $remainingTunnelPrefixes = @(Get-NetRoute -AddressFamily IPv4 `
            -InterfaceAlias 'winsvpn' -ErrorAction SilentlyContinue |
            ForEach-Object { [string]$_.DestinationPrefix })
        $diagnosticPairedHalfRoutesPresent =
            ($remainingTunnelPrefixes -contains '0.0.0.0/1') -and
            ($remainingTunnelPrefixes -contains '128.0.0.0/1')
        if (-not $diagnosticPairedHalfRoutesPresent) {
            throw 'Removing the manual default route left incomplete tunnel coverage.'
        }
        $postRemovalNonExcludedDigest = Get-PublicEgressDigest
        $diagnosticNonExcludedEgressPreserved =
            $postRemovalNonExcludedDigest -ceq $ExpectedPublicEgressSha256
        if (-not $diagnosticNonExcludedEgressPreserved) {
            throw 'Non-excluded traffic escaped after the diagnostic route removal.'
        }
        if (-not [string]::IsNullOrWhiteSpace($ExcludedBrowserExecutable)) {
            $previousProfile = $script:BrowserCanaryProfilePath
            Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_.CommandLine) -and
                    $_.CommandLine.Contains($previousProfile)
                } | ForEach-Object {
                    Invoke-CimMethod -InputObject $_ -MethodName Terminate `
                        -ErrorAction SilentlyContinue | Out-Null
                }
            Start-Sleep -Seconds 2
            $resolvedPreviousProfile = Resolve-Path -LiteralPath $previousProfile `
                -ErrorAction SilentlyContinue
            if ($null -ne $resolvedPreviousProfile -and
                $resolvedPreviousProfile.Path.StartsWith(
                    [IO.Path]::GetFullPath($browserProfileRoot),
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                Remove-Item -LiteralPath $resolvedPreviousProfile.Path -Recurse `
                    -Force -ErrorAction SilentlyContinue
            }
            $script:BrowserCanaryWindowProcessId = 0
            $script:BrowserCanaryProfilePath = Join-Path $browserProfileRoot (
                'browser-canary-profile-' + [Guid]::NewGuid().ToString('N')
            )
        }
    }
    if ($DiagnosticReplaceManualTunnelGateway) {
        $ownedDefaults = @(Get-NetRoute -AddressFamily IPv4 `
            -DestinationPrefix '0.0.0.0/0' -InterfaceAlias 'winsvpn' `
            -ErrorAction Stop)
        if ($ownedDefaults.Count -ne 1 -or
            [string]$ownedDefaults[0].NextHop -cne '0.0.0.0') {
            throw 'The gateway diagnostic expected one on-link Win''s VPN IPv4 default route.'
        }
        $tunnelAddressText = Get-NetIPAddress -AddressFamily IPv4 `
            -InterfaceAlias 'winsvpn' -ErrorAction Stop |
            Where-Object { $_.IPAddress -notlike '169.254.*' } |
            Select-Object -First 1 -ExpandProperty IPAddress
        $octets = @($tunnelAddressText -split '\.')
        if ($octets.Count -ne 4 -or
            @($octets | Where-Object {
                $_ -notmatch '^\d{1,3}$' -or [int]$_ -gt 255
            }).Count -ne 0) {
            throw 'The gateway diagnostic could not validate the tunnel IPv4 address.'
        }
        $script:DiagnosticGatewayAddress = '{0}.{1}.{2}.1' -f `
            $octets[0], $octets[1], $octets[2]
        if ($script:DiagnosticGatewayAddress -ceq $tunnelAddressText) {
            throw 'The gateway diagnostic derived the local tunnel address as its gateway.'
        }
        $ownedDefaults | Remove-NetRoute -Confirm:$false -ErrorAction Stop
        New-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
            -InterfaceAlias 'winsvpn' -NextHop $script:DiagnosticGatewayAddress `
            -RouteMetric 0 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
        $script:DiagnosticGatewayRouteInstalled = $true
        $gatewayDefaults = @(Get-NetRoute -AddressFamily IPv4 `
            -DestinationPrefix '0.0.0.0/0' -InterfaceAlias 'winsvpn' `
            -ErrorAction Stop)
        if ($gatewayDefaults.Count -ne 1 -or
            [string]$gatewayDefaults[0].NextHop -cne
                $script:DiagnosticGatewayAddress) {
            throw 'The diagnostic tunnel-gateway route did not converge.'
        }
        $diagnosticTunnelGatewayReplaced = $true
        $diagnosticTunnelGatewayDerivation = 'tunnel_ipv4_24_host_one'
        $postReplacementNonExcludedDigest = Get-PublicEgressDigest
        $diagnosticNonExcludedEgressPreserved =
            $postReplacementNonExcludedDigest -ceq $ExpectedPublicEgressSha256
        if (-not $diagnosticNonExcludedEgressPreserved) {
            throw 'Non-excluded traffic escaped after the diagnostic gateway replacement.'
        }
    }
    $excludedConnectedEgressDigest = ''
    if ($splitTunnelTested) {
        if (-not $connectedTunnel.split_service_running) {
            throw 'The signed Windows split-tunnel driver service is not running.'
        }
        $wfpReferences = Get-WfpSplitReferenceCounts
        $packetCountersStarted = if (-not [string]::IsNullOrWhiteSpace(
                $ExcludedCscriptExecutable)) {
            Start-SplitPacketCounters
        } else { $false }
        try {
            $excludedConnectedEgressDigest = if (-not [string]::IsNullOrWhiteSpace(
                    $ExcludedCscriptExecutable)) {
                Get-CscriptEgressDigest
            } elseif (-not [string]::IsNullOrWhiteSpace(
                    $ExcludedBrowserExecutable)) {
                Get-BrowserEgressDigest
            } else { Get-CurlEgressDigest }
        } catch {
            if (-not [string]::IsNullOrWhiteSpace($ExcludedCscriptExecutable)) {
                $httpsFailure = $_.Exception.Message
                try {
                    $httpDigest = Get-CscriptEgressDigest -Http
                } catch {
                    $rawDiagnostic = try {
                        $rawDigest = Get-RawTcpEgressDigest
                        if ($rawDigest -ceq $originalEgressDigest) {
                            'RAW_TCP_PHYSICAL_EGRESS_PASS'
                        } elseif ([string]::IsNullOrWhiteSpace($rawDigest)) {
                            'RAW_TCP_NOT_CONFIGURED'
                        } else { 'RAW_TCP_WRONG_EGRESS' }
                    } catch {
                        $rawMarker = [regex]::Match(
                            $_.Exception.Message,
                            'TCP_CONNECT_TIMEOUT|HTTP_RESPONSE_TOO_LARGE|HTTP_RESPONSE_INVALID|HTTP_BODY_INVALID|timed out'
                        ).Value
                        if ($rawMarker) { "RAW_TCP_FAILED_$rawMarker" } else { 'RAW_TCP_FAILED' }
                    }
                    $wfpEventPaths = @(Save-SplitWfpNetEvents)
                    $wfpStatePath = Save-SplitWfpState
                    $packetCounterPath = Stop-SplitPacketCounters
                    $tcpEvidencePath = Join-Path $OutputRoot `
                        "cscript-tcp-observations-$stamp.json"
                    $tcpEvidence = @($script:CscriptTcpObservations | Sort-Object `
                        LocalAddress,LocalPort,RemoteAddress,RemotePort,State,
                        OwningProcess -Unique)
                    [IO.File]::WriteAllText(
                        $tcpEvidencePath,
                        [string]($tcpEvidence | ConvertTo-Json -Depth 4),
                        [Text.UTF8Encoding]::new($false)
                    )
                    throw ("The excluded cscript WinHTTP HTTPS and HTTP canaries failed " +
                        "($httpsFailure; $($_.Exception.Message); WFP references: " +
                        "baseline=$($wfpReferences.baseline), dns=$($wfpReferences.dns); " +
                        "packet counters: $packetCounterPath; packet trace: " +
                        "$script:PacketCaptureTextPath; TCP observations: " +
                        "$tcpEvidencePath; raw TCP: $rawDiagnostic; WFP events: " +
                        "$([string]::Join(',', $wfpEventPaths)); WFP state: " +
                        "$wfpStatePath).")
                }
                if ($httpDigest -ceq $originalEgressDigest) {
                    $packetCounterPath = Stop-SplitPacketCounters
                    throw ("The split driver reached the physical egress over HTTP but " +
                        "excluded HTTPS failed ($httpsFailure; WFP references: " +
                        "baseline=$($wfpReferences.baseline), dns=$($wfpReferences.dns); " +
                        "packet counters: $packetCounterPath).")
                }
                throw ("The excluded HTTP diagnostic used unexpected egress after HTTPS " +
                    "failed ($httpsFailure).")
            }
            if (-not [string]::IsNullOrWhiteSpace($ExcludedBrowserExecutable)) {
                throw ("The excluded Chromium browser HTTPS canaries failed " +
                    "($($_.Exception.Message); WFP references: " +
                    "baseline=$($wfpReferences.baseline), dns=$($wfpReferences.dns)).")
            }
            $socketDiagnosticPath = Join-Path $OutputRoot `
                "excluded-socket-diagnostic-$stamp.json"
            $socketDiagnostic = Save-ExcludedSocketDiagnostic `
                -PhysicalAddress $physicalInterfaceAddress `
                -Path $socketDiagnosticPath
            try {
                $forcedPhysicalDigest = Get-CurlEgressDigest `
                    -InterfaceAddress $physicalInterfaceAddress
            } catch {
                throw ('Both driver-selected and explicit physical-interface excluded canaries failed ' +
                    "(WFP references: baseline=$($wfpReferences.baseline), dns=$($wfpReferences.dns); " +
                    "socket diagnostic: $socketDiagnosticPath).")
            }
            if ($forcedPhysicalDigest -ceq $originalEgressDigest) {
                throw 'The split driver did not redirect the excluded process, although explicit physical-interface binding passed.'
            }
            throw 'The explicit physical-interface excluded canary did not restore the original egress.'
        }
        if ($excludedConnectedEgressDigest -cne $originalEgressDigest) {
            throw 'The selected Windows app did not bypass the VPN egress.'
        }
        if ($packetCountersStarted) { [void](Stop-SplitPacketCounters) }
    }

    $observedDoubleVpnActive = [bool](Get-OptionalJsonValue $config `
        'double_vpn_active' $false)
    $doubleVpnCoreId = ([string](Get-OptionalJsonValue $config `
        'double_vpn_core_id' '')).Trim()
    $doubleVpnExitSlug = ([string](Get-OptionalJsonValue $config `
        'double_vpn_exit_slug' '')).Trim()
    $configuredFirstHop = ([string](Get-OptionalJsonValue $config `
        'server_endpoint' '')).Trim()
    if ($doubleVpnExpected -and -not $observedDoubleVpnActive) {
        throw 'The connected Windows runtime configuration does not prove Double VPN active.'
    }
    if (-not $doubleVpnExpected -and $observedDoubleVpnActive) {
        throw 'The single-hop Windows runtime unexpectedly activated Double VPN.'
    }
    if ($doubleVpnExpected -and
        ([string]::IsNullOrWhiteSpace($doubleVpnCoreId) -or
         [string]::IsNullOrWhiteSpace($doubleVpnExitSlug) -or
         [string]::IsNullOrWhiteSpace($configuredFirstHop))) {
        throw 'Double VPN SecureState lacks its core, exit, or configured first-hop identity.'
    }
    $networkChangeEvidence = [ordered]@{
        profiles = @()
        profile_count = 0
        ipv6_baseline_enabled = $false
        passed = $false
    }
    if ($RunNetworkChangeMatrix) {
        $networkChangeEvidence = Invoke-NetworkChangeMatrix -TunnelDns $tunnelDns
        if (-not $networkChangeEvidence.passed) {
            throw 'Windows network-change matrix did not pass every profile.'
        }
    }
    $connectedCapture = Invoke-Capture -Phase 'connected'

    if ($script:DiagnosticHalfRoutesInstalled) {
        Get-NetRoute -AddressFamily IPv4 -InterfaceAlias 'winsvpn' `
            -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DestinationPrefix -in @('0.0.0.0/1', '128.0.0.0/1')
            } | Remove-NetRoute -Confirm:$false -ErrorAction Stop
        $script:DiagnosticHalfRoutesInstalled = $false
    }
    if ($script:DiagnosticGatewayRouteInstalled) {
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
            -InterfaceAlias 'winsvpn' -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction Stop
        New-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
            -InterfaceAlias 'winsvpn' -NextHop '0.0.0.0' -RouteMetric 0 `
            -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
        $script:DiagnosticGatewayRouteInstalled = $false
    }
    Invoke-PowerButton
    $disconnectDeadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        Start-Sleep -Seconds 2
        $tunnel = Get-TunnelState
        if (-not $tunnel.service_running -and -not $tunnel.adapter_up -and
            -not $tunnel.default_route -and -not $tunnel.split_service_running -and
            -not $tunnel.xray_running) {
            $connected = $false
            break
        }
    } while ([DateTime]::UtcNow -lt $disconnectDeadline)
    if ($connected) {
        throw 'Exact Windows tunnel did not tear down through the app UI.'
    }

    $restoredRoutes = Get-DefaultRouteSignature
    if (($restoredRoutes -join '|') -cne ($originalRoutes -join '|')) {
        throw 'Windows default routes were not restored exactly after disconnect.'
    }
    $restoredEgressDigest = Get-PublicEgressDigest
    if ($restoredEgressDigest -cne $originalEgressDigest) {
        throw 'Windows public egress was not restored after disconnect.'
    }
    $restoredIpv6Routes = @(Get-Ipv6DefaultRouteSignature)
    $restoredIpv6Bindings = @(Get-PhysicalIpv6BindingSignature)
    $restoredIpv6RoutesSha256 = Get-Sha256Text (
        $restoredIpv6Routes -join '|'
    )
    $restoredIpv6BindingsSha256 = Get-Sha256Text (
        $restoredIpv6Bindings -join '|'
    )
    if (($restoredIpv6Routes -join '|') -cne
            ($originalIpv6Routes -join '|')) {
        throw 'Windows IPv6 default routes were not restored exactly after disconnect.'
    }
    if (($restoredIpv6Bindings -join '|') -cne
            ($originalIpv6Bindings -join '|')) {
        throw 'Physical ms_tcpip6 bindings were not restored exactly after disconnect.'
    }
    $externalDnsResolutionRestored = Test-DirectDnsResolution `
        -Server $externalDnsServer -Name 'winsvpn.org'
    if (-not $externalDnsResolutionRestored) {
        throw 'Direct external DNS resolution was not restored after disconnect.'
    }
    $finalWfp = Get-OwnedWfpFilterState
    if (-not $finalWfp.enumeration_succeeded -or
        $finalWfp.total_owned_filter_count -ne 0) {
        throw 'Owned Win''s VPN WFP filters remained after disconnect.'
    }
    $finalTunnelState = Get-TunnelState
    if ($finalTunnelState.service_running -or $finalTunnelState.adapter_up -or
        $finalTunnelState.default_route -or
        $finalTunnelState.split_service_running -or
        $finalTunnelState.xray_running) {
        throw 'Native tunnel, split-driver, route, adapter, or Xray residue remained after disconnect.'
    }
    $disconnectedCapture = Invoke-Capture -Phase 'disconnected'

    $evidence = [ordered]@{
        schema_version = 2
        platform = 'windows'
        tested_at_utc = [DateTime]::UtcNow.ToString('o')
        secret_material_redacted = $true
        app_sha256 = $appHash
        service_sha256 = $serviceHash
        double_vpn_requested = $doubleVpnExpected
        double_vpn_active = $observedDoubleVpnActive
        client_config_double_vpn_observed = $observedDoubleVpnActive
        double_vpn_core_id_sha256 = if ($doubleVpnExpected) {
            Get-Sha256Text $doubleVpnCoreId
        } else { '' }
        double_vpn_exit_slug_sha256 = if ($doubleVpnExpected) {
            Get-Sha256Text $doubleVpnExitSlug
        } else { '' }
        configured_first_hop_sha256 = if ($doubleVpnExpected) {
            Get-Sha256Text $configuredFirstHop
        } else { '' }
        connected_config_projection_sha256 =
            $configObservation.projection_sha256
        connected_config_manager_generation_before =
            [uint64]$configObservation.manager_generation_before
        connected_config_manager_generation_after =
            [uint64]$configObservation.manager_generation_after
        connected_config_generation_field_present =
            [bool]$configObservation.config_generation_field_present
        connected_config_generation = [uint64]$configObservation.config_generation
        connected_config_stable_within_manager_generation =
            [bool]$configObservation.stable_within_manager_generation
        secure_state_preferred_over_legacy =
            [bool]$configObservation.secure_state_preferred_over_legacy
        external_core_pairing_required = $doubleVpnExpected
        client_physical_two_hop_proven = $false
        tunnel_service_running = $true
        tunnel_adapter_up = $true
        tunnel_default_route_present = $true
        transport = if ($connectedTunnel.xray_running) { 'xray_fallback' } else { 'direct_awg' }
        external_canary_count = 2
        expected_public_egress_sha256 = $ExpectedPublicEgressSha256
        connected_public_egress_sha256 = $connectedEgressDigest
        baseline_external_dns_resolution_succeeded =
            $baselineExternalDnsAvailable
        tunnel_dns_resolution_succeeded = $tunnelDnsResolutionSucceeded
        direct_external_dns_blocked_while_connected =
            $externalDnsResolutionBlocked
        direct_external_dns_restored_after_disconnect =
            $externalDnsResolutionRestored
        ipv6_literal_canary_sha256 = Get-Sha256Text $ipv6CanaryAddress
        baseline_ipv6_default_routes = @($originalIpv6Routes)
        baseline_ipv6_default_routes_sha256 = $originalIpv6RoutesSha256
        baseline_physical_ms_tcpip6_bindings = @($originalIpv6Bindings)
        baseline_physical_ms_tcpip6_bindings_sha256 =
            $originalIpv6BindingsSha256
        baseline_ipv6_egress_required = $baselineIpv6EgressRequired
        baseline_ipv6_literal_egress_available = $baselineIpv6EgressAvailable
        connected_ipv6_default_route_count =
            [int]$connectedIpv6Evidence.default_route_count
        connected_ipv6_non_tunnel_default_route_count =
            [int]$connectedIpv6Evidence.non_tunnel_default_route_count
        connected_ipv6_tunnel_owned_default_route_count =
            [int]$connectedIpv6Evidence.tunnel_owned_default_route_count
        connected_ipv6_tunnel_route_ownership_verified =
            [bool]$connectedIpv6Evidence.tunnel_route_ownership_verified
        connected_ipv6_forced_literal_egress_failed =
            [bool]$connectedIpv6Evidence.forced_literal_egress_failed
        connected_ipv6_fail_closed_passed =
            [bool]$connectedIpv6Evidence.passed
        restored_ipv6_default_routes = @($restoredIpv6Routes)
        restored_ipv6_default_routes_sha256 = $restoredIpv6RoutesSha256
        restored_physical_ms_tcpip6_bindings = @($restoredIpv6Bindings)
        restored_physical_ms_tcpip6_bindings_sha256 =
            $restoredIpv6BindingsSha256
        original_ipv6_default_routes_restored = $true
        original_physical_ms_tcpip6_bindings_restored = $true
        baseline_owned_wfp_filter_count =
            [int]$baselineWfp.total_owned_filter_count
        connected_owned_wfp_filter_count =
            [int]$connectedWfp.total_owned_filter_count
        final_owned_wfp_filter_count =
            [int]$finalWfp.total_owned_filter_count
        final_owned_wfp_filters_zero = $true
        final_xray_process_zero = -not $finalTunnelState.xray_running
        split_tunnel_tested = $splitTunnelTested
        split_driver_service_running = if ($splitTunnelTested) { $true } else { $false }
        excluded_app_canary_count = if ($splitTunnelTested) { 2 } else { 0 }
        excluded_app_canary_kind = if ($splitTunnelTested) { $excludedCanaryKind } else { '' }
        excluded_app_sha256 = if ($splitTunnelTested) {
            (Get-FileHash -LiteralPath $excludedCanaryExecutable `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        } else { '' }
        excluded_app_bypass_egress_sha256 = $excludedConnectedEgressDigest
        excluded_canary_revocation_fallback_used = $script:ExcludedCanaryRevocationFallbackUsed
        network_change_tested = [bool]$RunNetworkChangeMatrix
        network_change_profile_count = [int]$networkChangeEvidence.profile_count
        network_change_profiles = @($networkChangeEvidence.profiles)
        network_change_ipv6_baseline_enabled =
            [bool]$networkChangeEvidence.ipv6_baseline_enabled
        network_change_passed = [bool]$networkChangeEvidence.passed
        connection_attempt_count = $connectionAttempts.Count
        connected_egress_mismatch_observed = $connectedEgressMismatchObserved
        connected_egress_mismatch_count = $connectedEgressMismatchCount
        all_connected_egress_attempts_matched_expected =
            @($connectionAttempts | Where-Object {
                $_.egress_disposition -ceq 'match'
            }).Count -gt 0 -and
            @($connectionAttempts | Where-Object {
                $_.egress_disposition -ceq 'mismatch'
            }).Count -eq 0
        connection_attempts_sha256 = (Get-FileHash -LiteralPath `
            $connectionAttemptsPath -Algorithm SHA256).Hash.ToLowerInvariant()
        disconnect_ok = $true
        original_routes_restored = $true
        original_public_egress_restored = $true
        cleanup_fallback_used = $cleanupFallbackUsed
        diagnostic_route_mutation = $diagnosticTunnelDefaultRemoved
        diagnostic_tunnel_gateway_replaced = $diagnosticTunnelGatewayReplaced
        diagnostic_tunnel_gateway_derivation = $diagnosticTunnelGatewayDerivation
        diagnostic_paired_half_routes_present = $diagnosticPairedHalfRoutesPresent
        diagnostic_non_excluded_egress_preserved =
            $diagnosticNonExcludedEgressPreserved
        release_gate_eligible = -not ($diagnosticTunnelDefaultRemoved -or
            $diagnosticTunnelGatewayReplaced)
        baseline_screenshot_sha256 = $baselineCapture.screenshot_sha256
        connected_screenshot_sha256 = $connectedCapture.screenshot_sha256
        disconnected_screenshot_sha256 = $disconnectedCapture.screenshot_sha256
    }
    $evidence | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $evidencePath -Encoding UTF8
    $liveCyclePassed = $true
    if ($diagnosticTunnelDefaultRemoved -or $diagnosticTunnelGatewayReplaced) {
        Write-Output 'WINDOWS_SPLIT_ROUTE_DIAGNOSTIC=PASS'
    } else {
        if ($doubleVpnExpected) {
            Write-Output 'WINDOWS_EXACT_DOUBLE_VPN_LIVE_CYCLE=PASS'
        } else {
            Write-Output 'WINDOWS_EXACT_SINGLE_HOP_LIVE_CYCLE=PASS'
        }
    }
    Write-Output "WINDOWS_LIVE_EVIDENCE=$evidencePath"
} finally {
    $managerRecycleRequired = -not $liveCyclePassed
    try {
    if ($script:DiagnosticHalfRoutesInstalled) {
        Get-NetRoute -AddressFamily IPv4 -InterfaceAlias 'winsvpn' `
            -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DestinationPrefix -in @('0.0.0.0/1', '128.0.0.0/1')
            } | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        $script:DiagnosticHalfRoutesInstalled = $false
    }
    if ($script:DiagnosticGatewayRouteInstalled) {
        Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
            -InterfaceAlias 'winsvpn' -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        if (Get-NetAdapter -Name 'winsvpn' -ErrorAction SilentlyContinue) {
            New-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' `
                -InterfaceAlias 'winsvpn' -NextHop '0.0.0.0' -RouteMetric 0 `
                -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
        }
        $script:DiagnosticGatewayRouteInstalled = $false
    }
    if ($script:PacketCountersRunning) { [void](Stop-SplitPacketCounters) }
    if (-not [string]::IsNullOrWhiteSpace($script:BrowserCanaryProfilePath)) {
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_.CommandLine) -and
                $_.CommandLine.Contains($script:BrowserCanaryProfilePath)
            } | ForEach-Object {
                Invoke-CimMethod -InputObject $_ -MethodName Terminate `
                    -ErrorAction SilentlyContinue | Out-Null
            }
        $resolvedBrowserProfile = Resolve-Path -LiteralPath `
            $script:BrowserCanaryProfilePath -ErrorAction SilentlyContinue
        if ($null -ne $resolvedBrowserProfile -and
            $resolvedBrowserProfile.Path.StartsWith(
                [IO.Path]::GetFullPath($browserProfileRoot),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            Remove-Item -LiteralPath $resolvedBrowserProfile.Path -Recurse -Force `
                -ErrorAction SilentlyContinue
        }
    }
    # A failed proof can outlive the test's outer deadline while Flutter is
    # still advancing through fallback candidates. Terminate that ordinary UI
    # process before privileged cleanup so it cannot recreate the tunnel after
    # the manager service has restored the physical route.
    if (-not $liveCyclePassed) {
        Get-Process -Name wins_vpn -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
    $state = Get-TunnelState
    if ($connected -or $state.service_running -or $state.adapter_up -or
        $state.default_route -or $state.split_service_running -or
        $state.xray_running) {
        if ($liveCyclePassed) {
            try {
                Invoke-PowerButton
                Start-Sleep -Seconds 10
            } catch {}
        }
        $state = Get-TunnelState
        if ($state.service_running -or $state.adapter_up -or
            $state.default_route -or $state.split_service_running -or
            $state.xray_running) {
            $cleanupFallbackUsed = $true
            $managerRecycleRequired = $true
        }
    }
    } finally {
        # Recovery must never strand the privileged manager in Stopped merely
        # because Stop-Service/WaitForStatus threw. The helper attempts and
        # verifies Running from its own finally path.
        $managerCleanupEvidence = Restore-TunnelManagerRunning `
            -Recycle $managerRecycleRequired
    }
    $cleanupState = Get-TunnelState
    $cleanupWfp = Get-OwnedWfpFilterState
    if ($cleanupState.service_running -or $cleanupState.adapter_up -or
        $cleanupState.default_route -or $cleanupState.split_service_running -or
        $cleanupState.xray_running -or
        $cleanupWfp.total_owned_filter_count -ne 0) {
        throw 'The live-cycle finally block could not prove zero native/WFP/Xray residue.'
    }
}
