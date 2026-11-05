param(
    [string]$Package = "org.winsvpn.app",
    [string]$ExpectedDns = "10.8.1.1",
    [int]$ExpectedMtu = 1280,
    [int]$LogcatLines = 1800
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$OutDir = Join-Path $RepoRoot ".artifacts\phone-stress"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"

function Invoke-AdbText {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $output = & adb @Args 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "adb $($Args -join ' ') failed with exit code $LASTEXITCODE`n$output"
    }
    return ($output -join "`n")
}

Write-Host "[TUNNEL] Checking connected device"
Invoke-AdbText devices | Write-Host

$connectivityPath = Join-Path $OutDir "connectivity-$stamp.txt"
$routePath = Join-Path $OutDir "routes-$stamp.txt"
$addrPath = Join-Path $OutDir "addr-$stamp.txt"
$logPath = Join-Path $OutDir "tunnel-logcat-$stamp.txt"

Invoke-AdbText shell dumpsys connectivity | Set-Content -Path $connectivityPath -Encoding UTF8
Invoke-AdbText shell ip route show table all | Set-Content -Path $routePath -Encoding UTF8
Invoke-AdbText shell ip addr show | Set-Content -Path $addrPath -Encoding UTF8
& adb logcat -d -t $LogcatLines > $logPath

$connectivity = Get-Content $connectivityPath -Raw
$routes = Get-Content $routePath -Raw
$addr = Get-Content $addrPath -Raw

if ($connectivity -notmatch "VPN:$([regex]::Escape($Package))") {
    throw "Wins VPN is not the active Android VPN. See $connectivityPath"
}
if ($connectivity -notmatch "Transports:\s*(?:\w+\|)*VPN" -or $connectivity -notmatch "Capabilities:.*VALIDATED") {
    throw "Android VPN network is not validated. See $connectivityPath"
}
if ($connectivity -notmatch "InterfaceName:\s*tun0") {
    throw "Android VPN network does not expose tun0. See $connectivityPath"
}
if ($connectivity -notmatch "DnsAddresses:\s*\[\s*/$([regex]::Escape($ExpectedDns))") {
    throw "Tunnel DNS is not $ExpectedDns. See $connectivityPath"
}
if ($connectivity -notmatch "MTU:\s*$ExpectedMtu\b") {
    throw "Tunnel MTU is not $ExpectedMtu. See $connectivityPath"
}
if ($routes -notmatch "default\s+dev\s+tun0" -or $routes -notmatch "default\s+dev\s+tun0.*pref medium") {
    throw "Default tunnel routes were not found. See $routePath"
}
if ($routes -notmatch "::/0.*dev\s+tun0" -and $routes -notmatch "default\s+dev\s+tun0.*pref medium") {
    throw "IPv6 fail-closed route into tun0 was not found. See $routePath"
}
if ($addr -notmatch "tun0:.*mtu\s+$ExpectedMtu" -or $addr -notmatch "inet\s+10\.8\.") {
    throw "tun0 address/MTU check failed. See $addrPath"
}

$badLogs = Select-String -Path $logPath -Pattern "FATAL EXCEPTION|WinsVpnService.*(Tunnel engine failure|Tunnel engine crashed|Failed to allocate|Xray stealth transport failed)" -CaseSensitive:$false
if ($badLogs) {
    Write-Host "[TUNNEL] Suspicious log lines:"
    $badLogs | Select-Object -First 40 | ForEach-Object { Write-Host $_.Line }
    throw "Tunnel logcat contains fatal VPN errors. See $logPath"
}

Write-Host "[TUNNEL] PASS"
Write-Host "[TUNNEL] Connectivity: $connectivityPath"
Write-Host "[TUNNEL] Routes: $routePath"
Write-Host "[TUNNEL] Addresses: $addrPath"
Write-Host "[TUNNEL] Logcat: $logPath"
