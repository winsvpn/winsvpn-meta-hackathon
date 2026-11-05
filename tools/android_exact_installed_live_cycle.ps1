[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Serial,
    [Parameter(Mandatory = $true)][string]$ExpectedPublicEgressSha256,
    [string]$Adb = (Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'),
    [string]$PackageName = 'org.winsvpn.app',
    [string]$Pin = '1357',
    [string]$BrowserPackage = 'com.android.chrome',
    [string]$PublicEgressCanaryUrl = 'https://api.ipify.org',
    [ValidateRange(30, 240)][int]$ConnectTimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Adb -PathType Leaf)) { throw "adb not found: $Adb" }
if ($ExpectedPublicEgressSha256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'ExpectedPublicEgressSha256 must be an exact SHA-256 digest.'
}
if ($Pin -notmatch '^\d{4}$') { throw 'Pin must contain exactly four digits.' }

function Invoke-Adb {
    param([string[]]$Arguments, [switch]$ReadOnly)
    $attempts = if ($ReadOnly -and $Serial -match ':') { 10 } else { 1 }
    for ($attempt = 1; $attempt -le $attempts; $attempt++) {
        # ADB writes successful transfer progress to stderr. Windows
        # PowerShell turns native stderr records into terminating errors when
        # ErrorActionPreference is Stop, so capture both streams and decide
        # success strictly from the native exit code.
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $output = @(& $Adb -s $Serial @Arguments 2>&1 | ForEach-Object { [string]$_ })
            $adbExitCode = $LASTEXITCODE
            if ($adbExitCode -eq 0) { return $output }
            if ($attempt -lt $attempts) {
                # Preserve an authenticated wireless transport while the VPN
                # changes routes.  Killing the global daemon here turns a brief
                # full-tunnel transition into a guaranteed false disconnect.
                & $Adb connect $Serial 2>&1 | Out-Null
                Start-Sleep -Seconds 1
            }
        } finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
    }
    throw "adb failed ($adbExitCode): $($Arguments -join ' ')"
}

function Get-UiNodes {
    $raw = (Invoke-Adb -ReadOnly -Arguments @('exec-out', 'uiautomator', 'dump', '/dev/tty')) -join ''
    $start = $raw.IndexOf('<?xml', [StringComparison]::Ordinal)
    $finish = $raw.LastIndexOf('</hierarchy>', [StringComparison]::Ordinal)
    if ($start -lt 0 -or $finish -lt $start) { throw 'Android UI hierarchy was unavailable.' }
    [xml]$document = $raw.Substring($start, $finish + 12 - $start)
    return @($document.SelectNodes('//node'))
}

function Find-UiNode {
    param([Parameter(Mandatory = $true)][string]$Prefix)
    return Get-UiNodes | Where-Object {
        $_.GetAttribute('content-desc').StartsWith($Prefix, [StringComparison]::Ordinal)
    } | Select-Object -First 1
}

function Tap-UiNode {
    param([Parameter(Mandatory = $true)]$Node)
    $match = [regex]::Match($Node.GetAttribute('bounds'), '^\[(\d+),(\d+)\]\[(\d+),(\d+)\]$')
    if (-not $match.Success) { throw 'Android UI control had invalid bounds.' }
    $x = [int](([int]$match.Groups[1].Value + [int]$match.Groups[3].Value) / 2)
    $y = [int](([int]$match.Groups[2].Value + [int]$match.Groups[4].Value) / 2)
    Invoke-Adb -Arguments @('shell', 'input', 'tap', [string]$x, [string]$y) | Out-Null
}

function Find-UiNodeAfterScroll {
    param(
        [Parameter(Mandatory = $true)][string]$Prefix,
        [ValidateSet('Up', 'Down')][string]$Direction = 'Up'
    )
    foreach ($attempt in 1..12) {
        $node = Find-UiNode $Prefix
        if ($null -ne $node) { return $node }
        $startY = if ($Direction -eq 'Up') { '1848' } else { '696' }
        $endY = if ($Direction -eq 'Up') { '696' } else { '1848' }
        Invoke-Adb -Arguments @('shell', 'input', 'swipe', '540', $startY, '540', $endY, '450') | Out-Null
        Start-Sleep -Milliseconds 300
    }
    throw "Android control not found: $Prefix"
}

function Get-Sha256Text {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
        return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '').ToUpperInvariant()
    } finally {
        $sha256.Dispose()
    }
}

& $Adb connect $Serial | Out-Null
$connected = $false
try {
    Invoke-Adb -Arguments @(
        'shell', 'monkey', '-p', $PackageName,
        '-c', 'android.intent.category.LAUNCHER', '1'
    ) | Out-Null
    Start-Sleep -Seconds 2

    if ($null -ne (Find-UiNode 'Calculator 1')) {
        foreach ($digit in $Pin.ToCharArray()) {
            Tap-UiNode (Find-UiNode "Calculator $digit")
            Start-Sleep -Milliseconds 250
        }
        Start-Sleep -Seconds 8
    }

    $doubleVpn = Find-UiNodeAfterScroll -Prefix 'Double VPN' -Direction Up
    if ($doubleVpn.GetAttribute('checked') -ne 'true') {
        Tap-UiNode $doubleVpn
        Start-Sleep -Seconds 2
        $doubleVpn = Find-UiNode 'Double VPN'
        if ($null -eq $doubleVpn -or $doubleVpn.GetAttribute('checked') -ne 'true') {
            throw 'Double VPN could not be enabled for the exact live cycle.'
        }
        Write-Output 'ANDROID_EXACT_DOUBLE_VPN_ACTION=enabled'
    } else {
        Write-Output 'ANDROID_EXACT_DOUBLE_VPN_ACTION=retained'
    }
    Tap-UiNode (Find-UiNodeAfterScroll -Prefix 'Connect VPN' -Direction Down)

    $deadline = [DateTime]::UtcNow.AddSeconds($ConnectTimeoutSeconds)
    do {
        Start-Sleep -Seconds 2
        if ($null -ne (Find-UiNode 'Disconnect VPN') -and $null -ne (Find-UiNode 'SECURED')) {
            $connected = $true
            break
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    if (-not $connected) { throw 'Exact Android candidate did not reach SECURED.' }

    $deviceStats = (Invoke-Adb -ReadOnly -Arguments @('shell', 'cat', '/proc/net/dev')) -join "`n"
    $counterMatch = [regex]::Match(
        $deviceStats,
        '(?m)^\s*tun0:\s*(\d+)(?:\s+\d+){7}\s+(\d+)'
    )
    if (-not $counterMatch.Success -or
        [long]$counterMatch.Groups[1].Value -lt 96 -or
        [long]$counterMatch.Groups[2].Value -lt 96) {
        throw 'Exact Android tunnel lacked bidirectional traffic.'
    }
    $processes = (Invoke-Adb -ReadOnly -Arguments @('shell', 'ps', '-A')) -join "`n"
    if ($processes -match 'libxray|/xray(?:\s|$)') {
        Write-Output 'ANDROID_EXACT_TRANSPORT=xray_fallback'
    } else {
        Write-Output 'ANDROID_EXACT_TRANSPORT=direct_awg'
    }

    Invoke-Adb -Arguments @(
        'shell', 'am', 'start', '-W', '-a', 'android.intent.action.VIEW',
        '-d', $PublicEgressCanaryUrl, '-p', $BrowserPackage
    ) | Out-Null
    Start-Sleep -Seconds 10
    $visibleText = Get-UiNodes | ForEach-Object {
        $_.GetAttribute('text')
        $_.GetAttribute('content-desc')
    }
    $ipCandidates = @($visibleText | ForEach-Object {
        [regex]::Matches([string]$_, '(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)') |
            ForEach-Object { $_.Value }
    } | Where-Object {
        $octets = $_ -split '\.'
        $octets.Count -eq 4 -and @($octets | Where-Object { [int]$_ -gt 255 }).Count -eq 0
    } | Select-Object -Unique)
    $expected = $ExpectedPublicEgressSha256.ToUpperInvariant()
    $matches = @($ipCandidates | Where-Object { (Get-Sha256Text $_) -eq $expected })
    if ($matches.Count -ne 1) { throw 'Browser egress did not match the expected exit digest.' }
    Write-Output 'ANDROID_EXACT_BROWSER_EGRESS=PASS'

    Invoke-Adb -Arguments @(
        'shell', 'monkey', '-p', $PackageName,
        '-c', 'android.intent.category.LAUNCHER', '1'
    ) | Out-Null
    Start-Sleep -Seconds 2
    Tap-UiNode (Find-UiNode 'Disconnect VPN')

    $clean = $false
    foreach ($second in 1..30) {
        Start-Sleep -Seconds 1
        # Android 16 may deny rtnetlink enumeration to adb shell.  The kernel
        # interface counters remain readable and are already the authoritative
        # connected-state proof used above.
        $netDevices = (Invoke-Adb -ReadOnly -Arguments @('shell', 'cat', '/proc/net/dev')) -join "`n"
        $services = (Invoke-Adb -ReadOnly -Arguments @(
            'shell', 'dumpsys', 'activity', 'services', $PackageName
        )) -join "`n"
        $processes = (Invoke-Adb -ReadOnly -Arguments @('shell', 'ps', '-A')) -join "`n"
        $tunPresent = $netDevices -match '(?m)^\s*tun0:'
        $servicePresent = $services -match (
            '(?:' + [regex]::Escape($PackageName) + '/\.?|' +
            [regex]::Escape("$PackageName.") + ')VpnTunnelService'
        )
        $xrayPresent = $processes -match 'libxray|/xray(?:\s|$)'
        if (-not $tunPresent -and -not $servicePresent -and -not $xrayPresent) {
            $clean = $true
            Write-Output "ANDROID_EXACT_DISCONNECT=PASS seconds=$second"
            break
        }
    }
    if (-not $clean) {
        throw "Android teardown residue: tun=$tunPresent service=$servicePresent xray=$xrayPresent"
    }
    $connected = $false
    Write-Output 'ANDROID_EXACT_LIVE_CYCLE=PASS'
} finally {
    if ($connected) {
        Invoke-Adb -Arguments @('shell', 'am', 'force-stop', $PackageName) | Out-Null
    }
}
