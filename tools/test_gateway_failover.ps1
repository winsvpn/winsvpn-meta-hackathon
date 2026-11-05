param(
    [string]$ActiveGatewayUrl = "https://gist.githubusercontent.com/winsvpn/325d9caf5c3cda5d6f933e0ac5ba8a02/raw/active-gateway.txt",
    [switch]$IncludeAliasCandidates,
    [switch]$Json,
    # Shared secret matching NODE_HEALTH_PROBE_TOKEN on the nodes being probed.
    # As of 2026-08-06 a node's /healthz answers on loopback only unless a token
    # is configured, because "404 on everything, 200 on /healthz" was a
    # two-request confirmation to anyone who could reach the node through
    # Cloudflare -- which is everyone. Without a token the node-health checks
    # below report "loopback-only" instead of failing; that is the expected
    # posture, not an outage.
    [string]$HealthProbeToken = $env:WINS_HEALTH_PROBE_TOKEN
)

$ErrorActionPreference = "Continue"

function Invoke-GatewayCheck {
    param(
        [string]$Name,
        [string]$Method,
        [string]$Url,
        [string]$ExpectedShape
    )

    $headers = @{}
    if ($ExpectedShape -eq "node-health" -and -not [string]::IsNullOrWhiteSpace($HealthProbeToken)) {
        $headers["X-Wins-Health-Probe"] = $HealthProbeToken
    }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        if ($Method -eq "POST") {
            $body = @{
                account_number = "0000-0000-0000"
                device_id = "route-test"
                device_model = "route-test"
                location = "auto"
                stealth_mode = $false
                client_public_key = "invalid"
            } | ConvertTo-Json -Compress
            $res = Invoke-WebRequest -Uri $Url -Method Post -Body $body -ContentType "application/json" -TimeoutSec 12 -UseBasicParsing
        } else {
            $res = Invoke-WebRequest -Uri $Url -Method Get -Headers $headers -TimeoutSec 12 -UseBasicParsing
        }
        $sw.Stop()
        New-GatewayResult -Name $Name -Url $Url -Status ([int]$res.StatusCode) -Content $res.Content -Ms $sw.ElapsedMilliseconds -ExpectedShape $ExpectedShape
    } catch {
        $sw.Stop()
        $response = $_.Exception.Response
        if ($response) {
            try {
                $content = $_.ErrorDetails.Message
                if ([string]::IsNullOrWhiteSpace($content)) {
                    $stream = $response.GetResponseStream()
                    $reader = New-Object System.IO.StreamReader($stream)
                    $content = $reader.ReadToEnd()
                    $reader.Close()
                }
                return New-GatewayResult -Name $Name -Url $Url -Status ([int]$response.StatusCode) -Content $content -Ms $sw.ElapsedMilliseconds -ExpectedShape $ExpectedShape
            } catch {}
        }
        [pscustomobject]@{
            Ok = $false
            Name = $Name
            Status = "ERR"
            Shape = "error"
            Ms = $sw.ElapsedMilliseconds
            Url = $Url
            Preview = $_.Exception.Message
        }
    }
}

function New-GatewayResult {
    param(
        [string]$Name,
        [string]$Url,
        [int]$Status,
        [string]$Content,
        [int64]$Ms,
        [string]$ExpectedShape
    )

    $contentText = (($Content | Out-String) + "").Trim()
    $shape = if (Test-HostnameOnlyGatewayRecord -Value $contentText) {
        "gateway-record"
    } elseif ($contentText -eq "ok") {
        "node-health"
    } elseif ($contentText -match '"nodes"') {
        "nodes-json"
    } elseif ($contentText -match '"detail"|"status"') {
        "api-json"
    } elseif ($contentText -match '<!doctype|<html|error code') {
        "cloudflare-error/html"
    } else {
        "other"
    }
    # A node with no probe token answers /healthz on loopback only, and returns
    # the same bare 404 it returns for any unknown path. That is the hardened
    # posture succeeding, so it must not read as a failed gateway. With a token
    # supplied, a 404 IS a failure -- either the token is wrong or the node is.
    if ($ExpectedShape -eq "node-health" -and $Status -eq 404 -and
        [string]::IsNullOrWhiteSpace($HealthProbeToken)) {
        $shape = "node-health"
        return [pscustomobject]@{
            Ok = $true
            Name = $Name
            Status = $Status
            Shape = "node-health(loopback-only)"
            Ms = $Ms
            Url = $Url
            Preview = "health endpoint is loopback-only; pass -HealthProbeToken to probe it remotely"
        }
    }
    $ok = $Status -lt 500 -and $shape -eq $ExpectedShape
    [pscustomobject]@{
        Ok = $ok
        Name = $Name
        Status = $Status
        Shape = $shape
        Ms = $Ms
        Url = $Url
        Preview = ($contentText.Substring(0, [Math]::Min(110, $contentText.Length)) -replace "`r|`n", " ")
    }
}

function Get-EndpointParts {
    param(
        [string]$Endpoint,
        [int]$DefaultPort = 443
    )
    $clean = ($Endpoint + "").Trim()
    $clean = $clean -replace '^https?://', ''
    $clean = ($clean -split '/')[0]
    if ($clean.StartsWith('[') -and $clean.Contains(']')) {
        $hostPart = $clean.Substring(1, $clean.IndexOf(']') - 1)
        $portPart = $DefaultPort
        if ($clean -match '\]:(\d+)$') { $portPart = [int]$Matches[1] }
        return @{ Host = $hostPart; Port = $portPart }
    }
    if ($clean -match '^(?<host>.+):(?<port>\d+)$') {
        return @{ Host = $Matches.host; Port = [int]$Matches.port }
    }
    return @{ Host = $clean; Port = $DefaultPort }
}

function New-NodeHealthUrl {
    param(
        [string]$HostName,
        [int]$Port = 443,
        [string]$Security = "tls"
    )
    $scheme = if ($Security.Trim().ToLowerInvariant() -eq "tls") { "https" } else { "http" }
    $suffix = ""
    if (($scheme -eq "https" -and $Port -ne 443) -or ($scheme -eq "http" -and $Port -ne 80)) {
        $suffix = ":$Port"
    }
    return "${scheme}://${HostName}${suffix}/healthz"
}

function Get-RegisteredNodeChecks {
    param([string]$NodesUrl)
    $nodeChecks = @()
    try {
        $nodesResponse = Invoke-WebRequest -Uri $NodesUrl -Method Get -TimeoutSec 10 -UseBasicParsing
        $data = $nodesResponse.Content | ConvertFrom-Json
        foreach ($node in @($data.nodes)) {
            $endpoint = $node.stealth_endpoint
            if (-not $endpoint) { $endpoint = $node.stealthendpoint }
            if (-not $endpoint) { continue }
            $security = if ($node.xray_security) { $node.xray_security } else { "none" }
            $defaultPort = if ($node.stealth_public_port) { [int]$node.stealth_public_port } else { 80 }
            $parts = Get-EndpointParts -Endpoint $endpoint -DefaultPort $defaultPort
            $rawTransports = $node.stealth_transports
            if ($rawTransports -is [string] -and -not [string]::IsNullOrWhiteSpace($rawTransports)) {
                try { $rawTransports = $rawTransports | ConvertFrom-Json } catch { $rawTransports = $null }
            }
            $transports = @($rawTransports)
            if ($transports.Count -eq 0 -or $null -eq $transports[0]) {
                $transports = @([pscustomobject]@{ port = $parts.Port; security = $security })
            }
            $aliases = @()
            if ($node.regional_aliases) { $aliases += @($node.regional_aliases) }
            if ($node.regionalaliases) { $aliases += @($node.regionalaliases) }
            foreach ($transport in $transports) {
                try { $routePort = if ($transport.port) { [int]$transport.port } else { $parts.Port } } catch { continue }
                if ($routePort -lt 1 -or $routePort -gt 65535) { continue }
                $routeSecurity = if ($transport.security) { ([string]$transport.security).Trim().ToLowerInvariant() } else { $security }
                if ($routeSecurity -notin @("none", "tls")) { continue }
                if ($parts.Host) {
                    $nodeChecks += @{
                        Name = "Node $($node.slug) transport $routePort/$routeSecurity"
                        Method = "GET"
                        Url = New-NodeHealthUrl -HostName $parts.Host -Port $routePort -Security $routeSecurity
                        ExpectedShape = "node-health"
                    }
                }
                foreach ($alias in ($aliases | Select-Object -Unique)) {
                    if (-not $alias) { continue }
                    $nodeChecks += @{
                        Name = "Node $($node.slug) alias $alias $routePort/$routeSecurity"
                        Method = "GET"
                        Url = New-NodeHealthUrl -HostName $alias -Port $routePort -Security $routeSecurity
                        ExpectedShape = "node-health"
                    }
                }
            }
        }
    } catch {
        $nodeChecks += @{
            Name = "Registered node canary discovery"
            Method = "GET"
            Url = $NodesUrl
            ExpectedShape = "nodes-json"
        }
    }
    return $nodeChecks
}

function Test-HostnameOnlyGatewayRecord {
    param([string]$Value)

    $record = (($Value + "") -split "`r?`n")[0].Trim()
    if ([string]::IsNullOrWhiteSpace($record) -or $record.Contains('|')) {
        return $false
    }
    try {
        $uri = [Uri]$record
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or $uri.UserInfo) {
            return $false
        }
        if ($uri.Port -ne 443 -or ($uri.AbsolutePath -ne '/' -and $uri.AbsolutePath -ne '')) {
            return $false
        }
        if ($uri.Query -or $uri.Fragment -or -not $uri.DnsSafeHost.Contains('.')) {
            return $false
        }
        $parsedAddress = $null
        if ([Net.IPAddress]::TryParse($uri.DnsSafeHost, [ref]$parsedAddress)) {
            return $false
        }
        return $uri.DnsSafeHost -match '[A-Za-z]'
    } catch {
        return $false
    }
}

$checks = @(
    @{Name = "Active gateway record"; Method = "GET"; Url = $ActiveGatewayUrl; ExpectedShape = "gateway-record"},
    @{Name = "Cloudflare sync.winsvpn.org nodes"; Method = "GET"; Url = "https://sync.winsvpn.org/nodes"; ExpectedShape = "nodes-json"},
    @{Name = "Cloudflare sync.winsvpn.com nodes"; Method = "GET"; Url = "https://sync.winsvpn.com/nodes"; ExpectedShape = "nodes-json"},
    @{Name = "Cloudflare hub.winsvpn.org nodes"; Method = "GET"; Url = "https://hub.winsvpn.org/nodes"; ExpectedShape = "nodes-json"},
    @{Name = "Cloudflare sync.winsvpn.org verify route"; Method = "POST"; Url = "https://sync.winsvpn.org/verify"; ExpectedShape = "api-json"},
    @{Name = "Cloudflare sync.winsvpn.com verify route"; Method = "POST"; Url = "https://sync.winsvpn.com/verify"; ExpectedShape = "api-json"},
    @{Name = "Cloudflare hub verify route"; Method = "POST"; Url = "https://hub.winsvpn.org/verify"; ExpectedShape = "api-json"}
)

$checks += Get-RegisteredNodeChecks -NodesUrl "https://sync.winsvpn.org/nodes"

if ($IncludeAliasCandidates) {
    $checks += @(
        @{Name = "Website active gateway"; Method = "GET"; Url = "https://winsvpn.org/active-gateway.txt"; ExpectedShape = "gateway-record"}
    )
}

$results = foreach ($check in $checks) {
    Invoke-GatewayCheck @check
}

if ($Json) {
    $results | ConvertTo-Json -Depth 4
} else {
    $results | Format-Table -AutoSize
}

if (($results | Where-Object { -not $_.Ok }).Count -gt 0) {
    exit 1
}
