[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Apk,
    [string]$Serial,
    [string]$Pin = '1357',
    [string]$PackageName = 'org.winsvpn.app',
    [string]$Adb = '',
    [string]$ApkSigner = '',
    [string]$ExpectedSignerSha256 = '4ebbff15a1274e7b072767fa37f00e8ffbeafab80cb61b51a5ab598af6dbe6ee',
    [switch]$LiveDoubleVpn,
    [switch]$RequireXrayFallback,
    [string]$BrowserPackage = 'com.android.chrome',
    [string]$PublicEgressCanaryUrl = 'https://api.ipify.org',
    [string]$ExpectedPublicEgressSha256 = '',
    [string]$WirelessMonitorScript = '',
    [switch]$AcknowledgeThirdPartySecuritySheet,
    [ValidateRange(30, 180)]
    [int]$ConnectTimeoutSeconds = 100
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Resolve adb on both Windows and macOS/Linux. The original default
# (Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe') only
# exists on Windows. On this Mac the SDK lives at ~/.local/android-sdk
# and the binary is `adb` (no .exe). Honor an explicit -Adb first, then
# probe common SDK roots; lastly fall back to `adb` on PATH.
if ([string]::IsNullOrWhiteSpace($Adb)) {
    $candidateRoots = @(
        $env:ANDROID_SDK_ROOT
        $env:ANDROID_HOME
        (Join-Path $HOME '.local/android-sdk')
        (Join-Path $HOME 'Library/Android/sdk')
        (Join-Path $env:LOCALAPPDATA 'Android\Sdk')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    foreach ($root in $candidateRoots) {
        $probe = Join-Path $root 'platform-tools/adb'
        if (Test-Path -LiteralPath $probe -PathType Leaf) { $Adb = $probe; break }
        $probeExe = Join-Path $root 'platform-tools/adb.exe'
        if (Test-Path -LiteralPath $probeExe -PathType Leaf) { $Adb = $probeExe; break }
    }
    if ([string]::IsNullOrWhiteSpace($Adb)) {
        $onPath = Get-Command adb -ErrorAction SilentlyContinue
        if ($null -ne $onPath) { $Adb = $onPath.Source }
    }
}
if ([string]::IsNullOrWhiteSpace($Adb)) {
    throw "adb not found. Pass -Adb <path> or set ANDROID_SDK_ROOT/ANDROID_HOME."
}

if (-not (Test-Path -LiteralPath $Apk -PathType Leaf)) {
    throw "Release APK not found: $Apk"
}
if (-not (Test-Path -LiteralPath $Adb -PathType Leaf)) {
    throw "adb not found: $Adb"
}
if ($ExpectedSignerSha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'ExpectedSignerSha256 must be an exact lowercase SHA-256 digest.'
}
if ($Pin -notmatch '^\d{4}$') {
    throw 'Pin must contain exactly four digits.'
}
if ($ExpectedPublicEgressSha256 -and $ExpectedPublicEgressSha256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'ExpectedPublicEgressSha256 must be an exact SHA-256 hex digest.'
}
if ($ExpectedPublicEgressSha256 -and -not $LiveDoubleVpn) {
    throw 'ExpectedPublicEgressSha256 is only valid with -LiveDoubleVpn.'
}
if ($RequireXrayFallback -and -not $LiveDoubleVpn) {
    throw 'RequireXrayFallback is only valid with -LiveDoubleVpn.'
}

if ([string]::IsNullOrWhiteSpace($Serial)) {
    $devices = @(& $Adb devices | Select-String -Pattern '^([^\s]+)\s+device$')
    if ($devices.Count -ne 1) {
        throw "Expected exactly one authorized Android device, found $($devices.Count)."
    }
    $Serial = $devices[0].Matches[0].Groups[1].Value
}
$useWirelessMonitor = $LiveDoubleVpn -and $Serial -match ':'
if ($useWirelessMonitor) {
    if ([string]::IsNullOrWhiteSpace($WirelessMonitorScript)) {
        $WirelessMonitorScript = Join-Path $PSScriptRoot 'android_wireless_live_monitor.sh'
    }
    if (-not (Test-Path -LiteralPath $WirelessMonitorScript -PathType Leaf)) {
        throw "Wireless Android live monitor not found: $WirelessMonitorScript"
    }
}

$displaySizeLine = (& $Adb -s $Serial shell wm size |
        Select-String -Pattern '^(?:Override|Physical) size:\s*(\d+)x(\d+)\s*$' |
        Select-Object -Last 1).Line
$displaySizeMatch = [regex]::Match(
    [string]$displaySizeLine,
    '^(?:Override|Physical) size:\s*(\d+)x(\d+)\s*$'
)
if (-not $displaySizeMatch.Success) {
    throw "Unable to determine the Android display size: $displaySizeLine"
}
$DisplayWidth = [int]$displaySizeMatch.Groups[1].Value
$DisplayHeight = [int]$displaySizeMatch.Groups[2].Value
if ($DisplayWidth -lt 320 -or $DisplayHeight -lt 480) {
    throw "Android reported an implausible display size: ${DisplayWidth}x${DisplayHeight}"
}

function Invoke-Adb {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $commandText = $Arguments -join ' '
    $safeToRetry = $Serial -match ':' -and $commandText -match '^(?:exec-out uiautomator|logcat -d|shell (?:cat |dumpsys |ip |pm path|ps |uiautomator ))'
    $attempts = if ($safeToRetry) { 10 } else { 1 }
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
                # Do not kill the host-wide daemon while a wireless device is
                # changing routes into or out of the full tunnel.  The existing
                # authenticated TCP transport can survive that transition;
                # destroying it guarantees a false disconnect until the VPN is
                # already down.  A bounded connect refresh is sufficient for a
                # genuinely stale transport.
                & $Adb connect $Serial 2>&1 | Out-Null
                Start-Sleep -Seconds 1
            }
        } finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
    }
    throw "adb failed ($adbExitCode): $commandText"
}

function Resolve-ApkSigner {
    if (-not [string]::IsNullOrWhiteSpace($ApkSigner)) {
        if (-not (Test-Path -LiteralPath $ApkSigner -PathType Leaf)) {
            throw "apksigner not found: $ApkSigner"
        }
        return (Resolve-Path -LiteralPath $ApkSigner).Path
    }
    $sdkRoots = @(
        $env:ANDROID_SDK_ROOT
        $env:ANDROID_HOME
        (Join-Path $HOME '.local/android-sdk')
        (Join-Path $HOME 'Library/Android/sdk')
        (Join-Path $env:LOCALAPPDATA 'Android\Sdk')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_ -PathType Container) } |
        Select-Object -Unique
    $candidates = @($sdkRoots | ForEach-Object {
        $btRoot = Join-Path $_ 'build-tools'
        if (-not (Test-Path -LiteralPath $btRoot -PathType Container)) { return }
        Get-ChildItem -LiteralPath $btRoot -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'apksigner' -or $_.Name -eq 'apksigner.bat' -or $_.Name -eq 'apksigner.jar' } |
            Where-Object { -not $_.PSIsContainer }
    } | Sort-Object { [version]$_.Directory.Name } -Descending)
    if ($candidates.Count -eq 0) {
        throw 'Android SDK apksigner is required to bind the installed base APK to the pinned signer.'
    }
    return $candidates[0].FullName
}

function Get-ApkSignerDigest {
    param([Parameter(Mandatory = $true)][string]$Path)
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $script:ResolvedApkSigner verify --verbose --print-certs $Path 2>&1 |
            ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($exitCode -ne 0) {
        throw "apksigner verification failed for $([IO.Path]::GetFileName($Path)): $($output -join ' ')"
    }
    # apksigner 36 and earlier label this line as "Signer #1", while
    # apksigner 37 labels it by the verified scheme (for example "V2 Signer").
    # Collapse identical scheme reports but fail closed if distinct signer
    # certificates are ever reported for the same APK.
    $matches = @($output | Select-String -Pattern '(?:Signer #\d+|V\d+(?:\.\d+)? Signer):?\s*certificate SHA-256 digest:\s*([0-9a-fA-F]{64})')
    $digests = @($matches | ForEach-Object {
        $_.Matches[0].Groups[1].Value.ToLowerInvariant()
    } | Sort-Object -Unique)
    if ($digests.Count -ne 1) {
        throw "Expected exactly one distinct APK signer certificate digest, found $($digests.Count)."
    }
    return $digests[0]
}

function Get-UiNodes {
    $lastError = $null
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try {
            $raw = ((Invoke-Adb exec-out uiautomator dump /dev/tty) -join '')
            $start = $raw.IndexOf('<?xml', [StringComparison]::Ordinal)
            $finish = $raw.LastIndexOf('</hierarchy>', [StringComparison]::Ordinal)
            if ($start -ge 0 -and $finish -ge $start) {
                [xml]$document = $raw.Substring($start, $finish + 12 - $start)
                return @($document.SelectNodes('//node'))
            }
            $lastError = 'uiautomator returned no complete XML hierarchy'
        } catch {
            $lastError = $_.Exception.Message
        }
        Start-Sleep -Milliseconds (250 * $attempt)
    }
    throw "Unable to parse the Android UI hierarchy after 5 attempts: $lastError"
}

function Find-UiNode {
    param(
        [Parameter(Mandatory = $true)][string]$Attribute,
        [Parameter(Mandatory = $true)][string]$Prefix
    )
    return Get-UiNodes |
        Where-Object { $_.GetAttribute($Attribute).StartsWith($Prefix, [StringComparison]::Ordinal) } |
        Select-Object -First 1
}

function Get-NodeCenter {
    param([Parameter(Mandatory = $true)]$Node)
    $match = [regex]::Match($Node.GetAttribute('bounds'), '^\[(\d+),(\d+)\]\[(\d+),(\d+)\]$')
    if (-not $match.Success) {
        throw "Invalid UI bounds: $($Node.GetAttribute('bounds'))"
    }
    return @(
        [int](([int]$match.Groups[1].Value + [int]$match.Groups[3].Value) / 2),
        [int](([int]$match.Groups[2].Value + [int]$match.Groups[4].Value) / 2)
    )
}

function Tap-UiNode {
    param([Parameter(Mandatory = $true)]$Node)
    $center = Get-NodeCenter $Node
    Invoke-Adb shell input tap $center[0] $center[1] | Out-Null
}

function Tap-UiPrefix {
    param(
        [Parameter(Mandatory = $true)][string]$Attribute,
        [Parameter(Mandatory = $true)][string]$Prefix
    )
    $node = Find-UiNode -Attribute $Attribute -Prefix $Prefix
    if ($null -eq $node) {
        throw "UI node not found: $Attribute starts with '$Prefix'"
    }
    Tap-UiNode $node
}

function Swipe-OuterUp {
    $x = [int]($DisplayWidth * 0.50)
    $startY = [int]($DisplayHeight * 0.77)
    $endY = [int]($DisplayHeight * 0.29)
    Invoke-Adb shell input touchscreen swipe $x $startY $x $endY 450 | Out-Null
}

function Swipe-OuterDown {
    $x = [int]($DisplayWidth * 0.50)
    $startY = [int]($DisplayHeight * 0.29)
    $endY = [int]($DisplayHeight * 0.77)
    Invoke-Adb shell input touchscreen swipe $x $startY $x $endY 450 | Out-Null
}

function Find-AfterScroll {
    param(
        [Parameter(Mandatory = $true)][string]$Attribute,
        [Parameter(Mandatory = $true)][string]$Prefix,
        [Parameter(Mandatory = $true)][ValidateSet('Up', 'Down')][string]$Direction,
        [int]$Attempts = 8
    )
    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        $node = Find-UiNode -Attribute $Attribute -Prefix $Prefix
        if ($null -ne $node) {
            return $node
        }
        if ($Direction -eq 'Up') { Swipe-OuterUp } else { Swipe-OuterDown }
        Start-Sleep -Milliseconds 250
    }
    throw "UI node not found after scrolling $Direction`: $Prefix"
}

function Get-TopActivity {
    $line = Invoke-Adb shell dumpsys activity activities |
        Select-String -Pattern 'topResumedActivity=' |
        Select-Object -First 1
    if ($null -eq $line) { return '' }
    return $line.Line.Trim()
}

function Assert-DeviceUnlocked {
    $trustState = (Invoke-Adb shell dumpsys trust) -join "`n"
    if ($trustState -match '(?m)^\s*User .*\(current\):.*\bdeviceLocked=1\b') {
        throw 'Android device is locked. Unlock it before the clean-install test; the harness will not bypass a PIN or biometric lock.'
    }
    $windowState = (Invoke-Adb shell dumpsys window) -join "`n"
    if ($windowState -match '(?m)\bmDreamingLockscreen=true\b|\bmShowingLockscreen=true\b|\bmKeyguardShowing=true\b|\bisStatusBarKeyguard=true\b') {
        throw 'Android keyguard is visible. Unlock it before the clean-install test; the harness will not bypass a PIN or biometric lock.'
    }
    Write-Output 'DEVICE_UNLOCK_PRECHECK=PASS'
}

function Assert-WinsVpnIsTop {
    param([Parameter(Mandatory = $true)][string]$Phase)
    $top = Get-TopActivity
    if ($top -notmatch [regex]::Escape($PackageName)) {
        throw "$Phase exposed another application instead of Win's VPN: $top"
    }
    Write-Output "$Phase=$top"
}

function Resolve-PostTunnelBatteryExemption {
    param([ValidateRange(10, 90)][int]$TimeoutSeconds = 45)

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $securedObservedAt = $null
    do {
        $top = Get-TopActivity
        if ($top -match 'RequestIgnoreBatteryOptimizations') {
            $allow = Get-UiNodes | Where-Object {
                $_.GetAttribute('text') -eq 'Allow' -or
                $_.GetAttribute('resource-id') -eq 'android:id/button1'
            } | Select-Object -First 1
            if ($null -eq $allow) {
                throw "Post-tunnel battery-optimization sheet has no Allow action: $top"
            }
            Tap-UiNode $allow
            Start-Sleep -Seconds 5
            if ((Get-TopActivity) -match 'RequestIgnoreBatteryOptimizations') {
                throw 'Android rejected the post-tunnel battery-optimization Allow action.'
            }
            Write-Output 'BATTERY_BACKGROUND_ACTION=allowed_after_secured_tunnel'
            Write-Output 'BATTERY_PROMPT_TIMING=post_tunnel_only'
            return
        }

        if ($top -match [regex]::Escape($PackageName)) {
            $nodes = Get-UiNodes
            $disconnect = $nodes | Where-Object {
                $_.GetAttribute('content-desc').StartsWith('Disconnect VPN', [StringComparison]::Ordinal)
            } | Select-Object -First 1
            $secured = $nodes | Where-Object {
                $_.GetAttribute('content-desc').StartsWith('SECURED', [StringComparison]::Ordinal)
            } | Select-Object -First 1
            if ($null -ne $disconnect -and $null -ne $secured) {
                if ($null -eq $securedObservedAt) {
                    $securedObservedAt = [DateTime]::UtcNow
                } elseif ([DateTime]::UtcNow.Subtract($securedObservedAt).TotalSeconds -ge 5) {
                    Write-Output 'BATTERY_BACKGROUND_ACTION=already_exempt_or_cooldown'
                    Write-Output 'BATTERY_PROMPT_TIMING=post_tunnel_gate_evaluated'
                    return
                }
            }
        } else {
            # Some Samsung/One UI versions show a vendor explanation before
            # Android's standard direct-exemption sheet. Acknowledge it only
            # in this bounded post-tunnel phase, never during initialization.
            $vendorOk = Find-UiNode -Attribute text -Prefix 'OK'
            if ($null -ne $vendorOk) {
                Tap-UiNode $vendorOk
                Start-Sleep -Seconds 4
                Write-Output 'BATTERY_BACKGROUND_ACTION=post_tunnel_vendor_sheet_acknowledged'
            }
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)

    throw 'The post-tunnel battery gate never reached a secured app state or exemption sheet.'
}

function Get-Sha256Text {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
        return (($digest | ForEach-Object { $_.ToString('x2') }) -join '').ToUpperInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Test-TunnelRuntimePresent {
    # Android 16 can deny the adb shell identity's rtnetlink request used by
    # `ip link show` even though /proc/net/dev remains readable.  Use the same
    # kernel counter source as the connected-state proof so cleanup cannot mask
    # the original tunnel result with a diagnostic permission error.
    $netDevices = (Invoke-Adb shell cat /proc/net/dev) -join "`n"
    $services = (Invoke-Adb shell dumpsys activity services $PackageName) -join "`n"
    $processes = (Invoke-Adb -Arguments @('shell', 'ps', '-A')) -join "`n"
    return [pscustomobject]@{
        Tun = $netDevices -match '(?m)^\s*tun0:'
        Service = $services -match (
            '(?:' + [regex]::Escape($PackageName) + '/\.?|' +
            [regex]::Escape("$PackageName.") + ')VpnTunnelService'
        )
        Xray = $processes -match 'libxray|/xray(?:\s|$)'
    }
}

function Stop-LiveVpn {
    param([switch]$RequireUiDisconnect)

    # Launcher routing is intentional: the real Flutter activity is not exported.
    Invoke-Adb -Arguments @(
        'shell', 'monkey', '-p', $PackageName,
        '-c', 'android.intent.category.LAUNCHER', '1'
    ) | Out-Null
    Start-Sleep -Seconds 2
    $disconnectButton = Find-UiNode -Attribute 'content-desc' -Prefix 'Disconnect VPN'
    $usedUi = $null -ne $disconnectButton
    if ($usedUi) {
        Tap-UiNode $disconnectButton
    } elseif ($RequireUiDisconnect) {
        throw 'The secured tunnel could not be disconnected through the app UI.'
    } else {
        Invoke-Adb shell am force-stop $PackageName | Out-Null
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Seconds 1
        $runtime = Test-TunnelRuntimePresent
        if (-not $runtime.Tun -and -not $runtime.Service -and -not $runtime.Xray) {
            if ($usedUi) {
                Write-Output 'ANDROID_LIVE_DISCONNECT=PASS'
                $nodes = Get-UiNodes
                $camouflage = $nodes | Where-Object {
                    $_.GetAttribute('content-desc').StartsWith('Calculator ', [StringComparison]::Ordinal)
                } | Select-Object -First 1
                if ($null -ne $camouflage) {
                    Write-Output 'POST_DISCONNECT_CAMOUFLAGE=PASS'
                }
            } else {
                Write-Output 'ANDROID_FAILED_LIVE_TEST_CLEANUP=PASS'
            }
            return
        }
    } while ([DateTime]::UtcNow -lt $deadline)

    throw "Android VPN runtime did not tear down: tun=$($runtime.Tun) service=$($runtime.Service) xray=$($runtime.Xray)"
}

function Assert-PublicEgress {
    if (-not $ExpectedPublicEgressSha256) { return }

    $browserInstalled = (Invoke-Adb shell pm path $BrowserPackage) -join ''
    if (-not $browserInstalled) {
        throw "Public-egress browser is not installed: $BrowserPackage"
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
    if ($ipCandidates.Count -eq 0) {
        throw 'Public-egress canary did not expose a valid IPv4 result in the browser UI.'
    }
    $expected = $ExpectedPublicEgressSha256.ToUpperInvariant()
    $matched = @($ipCandidates | Where-Object { (Get-Sha256Text $_) -eq $expected })
    if ($matched.Count -ne 1) {
        $observedDigests = @($ipCandidates | ForEach-Object { Get-Sha256Text $_ })
        throw "Public egress did not match the expected exit digest; observed=$($observedDigests -join ',')"
    }
    Write-Output "PUBLIC_EGRESS_SHA256=$expected"
    Write-Output 'ANDROID_BROWSER_DOUBLE_VPN_EGRESS=PASS'
    Invoke-Adb -Arguments @(
        'shell', 'monkey', '-p', $PackageName,
        '-c', 'android.intent.category.LAUNCHER', '1'
    ) | Out-Null
    Start-Sleep -Seconds 2
}

function Start-WirelessLiveMonitor {
    $remoteScript = '/data/local/tmp/winsvpn-wireless-live-monitor.sh'
    Invoke-Adb push $WirelessMonitorScript $remoteScript | Out-Null
    Invoke-Adb shell chmod 700 $remoteScript | Out-Null
    Invoke-Adb shell rm -rf /data/local/tmp/winsvpn-wireless-live | Out-Null
    Invoke-Adb shell sh $remoteScript --background `
        $PackageName $BrowserPackage $PublicEgressCanaryUrl | Out-Null
    $ready = $false
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        Start-Sleep -Milliseconds 250
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & $Adb -s $Serial shell test -d /data/local/tmp/winsvpn-wireless-live 2>$null | Out-Null
            $ready = $LASTEXITCODE -eq 0
        } finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        if ($ready) { break }
    }
    if (-not $ready) {
        throw 'Wireless Android live monitor did not start on the device.'
    }
    Write-Output 'WIRELESS_LIVE_MONITOR=started_before_route_change'
}

function Read-KeyValueFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^([^=]+)=(.*)$') {
            $values[$Matches[1]] = $Matches[2]
        }
    }
    return $values
}

function Wait-WirelessLiveMonitor {
    $remoteRoot = '/data/local/tmp/winsvpn-wireless-live'
    $localParent = Join-Path ([IO.Path]::GetTempPath()) (
        'winsvpn-wireless-live-' + [Guid]::NewGuid().ToString('N')
    )
    New-Item -ItemType Directory -Force -Path $localParent | Out-Null
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds($ConnectTimeoutSeconds + 120)
        $monitorReady = $false
        do {
            Start-Sleep -Seconds 3
            $previousErrorActionPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                & $Adb connect $Serial 2>&1 | Out-Null
                & $Adb -s $Serial shell test -f "$remoteRoot/post-state.txt" 2>&1 | Out-Null
                $monitorReady = $LASTEXITCODE -eq 0
            } finally {
                $ErrorActionPreference = $previousErrorActionPreference
            }
            if ($monitorReady) { break }
        } while ([DateTime]::UtcNow -lt $deadline)
        if (-not $monitorReady) {
            throw 'Wireless Android live monitor did not return after its bounded UI-disconnect window.'
        }

        $pullOutput = Invoke-Adb pull $remoteRoot $localParent
        if (($pullOutput -join "`n") -notmatch 'pulled') {
            throw 'Wireless Android live monitor evidence could not be pulled.'
        }
        $localRoot = Join-Path $localParent 'winsvpn-wireless-live'
        $connectedStatePath = Join-Path $localRoot 'connected-state.txt'
        $postStatePath = Join-Path $localRoot 'post-state.txt'
        $egressPath = Join-Path $localRoot 'egress.xml'
        $connectedUiPath = Join-Path $localRoot 'connected-ui.xml'
        foreach ($path in @($connectedStatePath, $postStatePath, $egressPath, $connectedUiPath)) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw "Wireless Android live monitor evidence is incomplete: $([IO.Path]::GetFileName($path))"
            }
        }

        $connectedState = Read-KeyValueFile $connectedStatePath
        $postState = Read-KeyValueFile $postStatePath
        if ($connectedState['tun_present'] -ne '1' -or
            $connectedState['vpn_service_present'] -ne '1') {
            throw 'Wireless Android monitor did not prove an active TUN and VpnService.'
        }
        $counterMatch = [regex]::Match(
            [string]$connectedState['tun_counters'],
            '^(\d+),(\d+)$'
        )
        if (-not $counterMatch.Success) {
            throw 'Wireless Android monitor did not record valid TUN counters.'
        }
        $rxBytes = [long]$counterMatch.Groups[1].Value
        $txBytes = [long]$counterMatch.Groups[2].Value
        if ($rxBytes -lt 96 -or $txBytes -lt 96) {
            throw "Wireless Android TUN counters are not bidirectional: rx=$rxBytes tx=$txBytes"
        }

        $connectedUi = Get-Content -LiteralPath $connectedUiPath -Raw
        if ($connectedUi -notmatch 'content-desc="[^"]*SECURED' -or
            $connectedUi -notmatch 'content-desc="[^"]*Disconnect VPN') {
            throw 'Wireless Android monitor did not capture the app in its SECURED disconnect state.'
        }

        $egressXml = Get-Content -LiteralPath $egressPath -Raw
        $ipCandidates = @([regex]::Matches(
            $egressXml,
            '(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)'
        ) | ForEach-Object { $_.Value } | Where-Object {
            $octets = $_ -split '\.'
            $octets.Count -eq 4 -and
                @($octets | Where-Object { [int]$_ -gt 255 }).Count -eq 0
        } | Select-Object -Unique)
        if ($ipCandidates.Count -eq 0) {
            throw 'Wireless Android browser canary did not expose a valid IPv4 result.'
        }
        $observedDigests = @($ipCandidates | ForEach-Object { Get-Sha256Text $_ })
        if ($ExpectedPublicEgressSha256 -and
            $ExpectedPublicEgressSha256.ToUpperInvariant() -notin $observedDigests) {
            throw "Wireless Android public egress did not match the expected exit digest; observed=$($observedDigests -join ',')"
        }

        if ($postState['completed'] -ne '1' -or
            $postState['disconnect_control_found'] -ne '1' -or
            $postState['cleanup_fallback'] -ne '0' -or
            $postState['tun_present'] -ne '0' -or
            $postState['vpn_service_present'] -ne '0' -or
            $postState['xray_present'] -ne '0') {
            throw 'Wireless Android UI disconnect did not restore a clean tunnel state.'
        }
        Invoke-Adb shell rm -rf $remoteRoot /data/local/tmp/winsvpn-wireless-live-monitor.sh | Out-Null
        return [pscustomobject]@{
            RxBytes = $rxBytes
            TxBytes = $txBytes
            Xray = $connectedState['xray_present'] -eq '1'
            EgressDigest = if ($ExpectedPublicEgressSha256) {
                $ExpectedPublicEgressSha256.ToUpperInvariant()
            } else {
                $observedDigests[0]
            }
        }
    } finally {
        Remove-Item -LiteralPath $localParent -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Assert-DeviceUnlocked
$originalScreenTimeout = ((Invoke-Adb shell settings get system screen_off_timeout) -join '').Trim()
if ($originalScreenTimeout -notmatch '^\d+$') {
    throw "Android screen timeout could not be read safely: $originalScreenTimeout"
}
$originalStayAwake = ((Invoke-Adb shell settings get global stay_on_while_plugged_in) -join '').Trim()
if ($originalStayAwake -notmatch '^\d+$') {
    throw "Android plugged-in stay-awake policy could not be read safely: $originalStayAwake"
}

try {
Invoke-Adb shell settings put system screen_off_timeout 900000 | Out-Null
Invoke-Adb shell settings put global stay_on_while_plugged_in 7 | Out-Null
# Reset the current inactivity countdown after changing the timeout. Merely
# writing the setting does not reset an already-near-expiry display timer on
# every Android build.
Invoke-Adb shell input keyevent 224 | Out-Null
Invoke-Adb shell input tap 1 1 | Out-Null
Write-Output 'TEMPORARY_SCREEN_TIMEOUT_MS=900000'
Write-Output 'TEMPORARY_PLUGGED_IN_STAY_AWAKE=7'

$script:ResolvedApkSigner = Resolve-ApkSigner
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$evidenceRunId = [Guid]::NewGuid().ToString()
$startupEvidenceRoot = Join-Path (Join-Path (Join-Path $repoRoot '.artifacts') 'android-release-machine') $evidenceRunId
New-Item -ItemType Directory -Force -Path $startupEvidenceRoot | Out-Null
Write-Output "ANDROID_MACHINE_EVIDENCE_RUN_ID=$evidenceRunId"
Write-Output "ANDROID_MACHINE_EVIDENCE_ROOT=$startupEvidenceRoot"

$apkHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Apk).Hash
Write-Output "APK_SHA256=$apkHash"
Write-Output "DEVICE_SERIAL=$Serial"
Write-Output "DISPLAY_SIZE=${DisplayWidth}x${DisplayHeight}"

# Always issue the required clean-uninstall command. ADB returns exit code 1
# with DELETE_FAILED_INTERNAL_ERROR when the package is already absent, so
# verify that state with package manager instead of treating the exit code by
# itself as a failed clean-install precondition.
$previousErrorActionPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = 'Continue'
    $uninstallOutput = @(
        & $Adb -s $Serial uninstall $PackageName 2>&1 |
            ForEach-Object { [string]$_ }
    )
    $uninstallExitCode = $LASTEXITCODE
    $remainingPackagePath = @(
        & $Adb -s $Serial shell pm path $PackageName 2>&1 |
            ForEach-Object { [string]$_ }
    )
    $packagePathExitCode = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $previousErrorActionPreference
}
if ($uninstallExitCode -eq 0) {
    if (($uninstallOutput -join "`n") -notmatch 'Success') {
        throw "Unexpected successful uninstall output: $($uninstallOutput -join ' ')"
    }
} elseif ($packagePathExitCode -eq 0 -or ($remainingPackagePath -join '').Trim()) {
    throw "Existing Android package remains after uninstall failure: $($uninstallOutput -join ' ')"
} else {
    Write-Output 'PREEXISTING_PACKAGE=already_absent_after_required_uninstall'
}
Write-Output 'CLEAN_UNINSTALL=PASS'
$installOutput = Invoke-Adb install --no-streaming $Apk
if (($installOutput -join "`n") -notmatch 'Success') {
    throw "Release APK installation failed: $($installOutput -join ' ')"
}
Write-Output 'EXACT_INSTALL=PASS'
$installedPackagePath = ((Invoke-Adb shell pm path $PackageName) -join '').Trim()
$installedPackageMatch = [regex]::Match($installedPackagePath, '^package:(/.+/base\.apk)$')
if (-not $installedPackageMatch.Success) {
    throw "Installed Android base APK path was unavailable: $installedPackagePath"
}
$installedHashOutput = ((Invoke-Adb shell sha256sum $installedPackageMatch.Groups[1].Value) -join '').Trim()
$installedHashMatch = [regex]::Match($installedHashOutput, '^([0-9a-fA-F]{64})\s+')
if (-not $installedHashMatch.Success) {
    throw 'Android could not hash the newly installed base APK.'
}
$installedApkHash = $installedHashMatch.Groups[1].Value.ToUpperInvariant()
if ($installedApkHash -cne $apkHash.ToUpperInvariant()) {
    throw "Installed Android base APK differs from the staged release artifact: staged=$apkHash installed=$installedApkHash"
}
Write-Output "INSTALLED_BASE_APK_SHA256=$installedApkHash"

$pulledBaseApk = Join-Path $startupEvidenceRoot 'installed-base.apk'
try {
    Invoke-Adb pull $installedPackageMatch.Groups[1].Value $pulledBaseApk | Out-Null
    if (-not (Test-Path -LiteralPath $pulledBaseApk -PathType Leaf)) {
        throw 'adb pull did not create the installed base APK evidence file.'
    }
    $pulledHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $pulledBaseApk).Hash.ToLowerInvariant()
    $artifactHashLower = $apkHash.ToLowerInvariant()
    $artifactSize = (Get-Item -LiteralPath $Apk).Length
    $pulledSize = (Get-Item -LiteralPath $pulledBaseApk).Length
    if ($pulledHash -cne $artifactHashLower -or $pulledSize -ne $artifactSize) {
        throw "Pulled installed APK differs from staged release: staged=$artifactHashLower/$artifactSize installed=$pulledHash/$pulledSize"
    }
    $artifactSigner = Get-ApkSignerDigest -Path $Apk
    $installedSigner = Get-ApkSignerDigest -Path $pulledBaseApk
    if ($artifactSigner -cne $ExpectedSignerSha256 -or $installedSigner -cne $ExpectedSignerSha256) {
        throw "APK signer pin mismatch: staged=$artifactSigner installed=$installedSigner expected=$ExpectedSignerSha256"
    }
    $signatureReceiptPath = Join-Path $startupEvidenceRoot 'apk-signature-receipt.json'
    [ordered]@{
        schema_version = 1
        contract = 'winsvpn-android-apk-signature-receipt-v1'
        artifact_sha256 = $artifactHashLower
        artifact_size_bytes = $artifactSize
        installed_base_apk_sha256 = $pulledHash
        installed_base_apk_size_bytes = $pulledSize
        artifact_signer_sha256 = $artifactSigner
        installed_signer_sha256 = $installedSigner
        apksigner_verified = $true
        captured_at_utc = [DateTime]::UtcNow.ToString('o')
        secret_material_redacted = $true
    } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $signatureReceiptPath -Encoding utf8
    $signatureReceiptHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $signatureReceiptPath).Hash.ToLowerInvariant()
    Write-Output "APK_SIGNATURE_RECEIPT_PATH=$signatureReceiptPath"
    Write-Output "APK_SIGNATURE_RECEIPT_SHA256=$signatureReceiptHash"
    Write-Output "APK_ARTIFACT_SIGNER_SHA256=$artifactSigner"
    Write-Output "APK_INSTALLED_SIGNER_SHA256=$installedSigner"
    Write-Output "APK_SIZE_BYTES=$artifactSize"
    Write-Output "INSTALLED_BASE_APK_SIZE_BYTES=$pulledSize"
} finally {
    Remove-Item -LiteralPath $pulledBaseApk -Force -ErrorAction SilentlyContinue
}

Invoke-Adb logcat -c | Out-Null
Invoke-Adb shell am start -n "$PackageName/$PackageName.LauncherReal" | Out-Null
Start-Sleep -Seconds 8

$startupPid = ((Invoke-Adb shell pidof $PackageName) -join '').Trim()
if ($startupPid -notmatch '^\d+$') {
    throw 'Win''s VPN did not remain alive after the exact clean-install launch.'
}
Write-Output "STARTUP_PID=$startupPid"
$startupLogPath = Join-Path $startupEvidenceRoot (
    'fresh-startup-logcat-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' +
    [Guid]::NewGuid().ToString('N') + '.txt'
)
$startupLog = @(Invoke-Adb logcat "--pid=$startupPid" -d -t 4000 -v threadtime)
$startupLog | Set-Content -LiteralPath $startupLogPath -Encoding utf8
$startupFatalLines = @($startupLog | Select-String -Pattern (
    'FATAL EXCEPTION|AndroidRuntime.*FATAL|E/flutter.*Unhandled Exception|' +
    'WinsVpnService.*(error|failed|crashed)|AmneziaWG.*(error|failed|crashed)|' +
    'Xray.*(error|failed|crashed)|SIGSEGV|SIGABRT'
) -CaseSensitive:$false)
if ($startupFatalLines.Count -gt 0) {
    throw "Exact clean-install startup logcat contains fatal VPN/application errors: $($startupFatalLines.Line -join ' | ')"
}
$startupLogSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $startupLogPath).Hash
Write-Output "STARTUP_LOGCAT_PATH=$startupLogPath"
Write-Output "STARTUP_LOGCAT_SHA256=$startupLogSha256"
Write-Output 'STARTUP_LOGCAT_FATAL_SCAN=PASS'

$securityTop = Get-TopActivity
if ($securityTop -match 'com\.symantec\.mobilesecurity/.+MalwareFoundActivity') {
    if (-not $AcknowledgeThirdPartySecuritySheet) {
        throw 'Norton suspicious-app sheet requires the explicit -AcknowledgeThirdPartySecuritySheet test switch.'
    }
    $cancelUninstall = Get-UiNodes | Where-Object {
        $_.GetAttribute('text') -eq 'Cancel' -and
        $_.GetAttribute('class') -eq 'android.widget.Button'
    } | Select-Object -First 1
    if ($null -eq $cancelUninstall) {
        throw 'Norton suspicious-app sheet has no Cancel action.'
    }
    Tap-UiNode $cancelUninstall
    Start-Sleep -Seconds 4
    if (-not ((Invoke-Adb shell pm path $PackageName) -join '')) {
        throw 'Win''s VPN was removed while dismissing the Norton suspicious-app sheet.'
    }
    Invoke-Adb shell am start -n "$PackageName/$PackageName.LauncherReal" | Out-Null
    Start-Sleep -Seconds 8
    Write-Output 'THIRD_PARTY_SECURITY_SHEET=norton_suspicious_app_cancelled'
}

if ((Get-TopActivity) -match 'RequestIgnoreBatteryOptimizations') {
    throw 'Battery exemption appeared during initialization before privacy consent or VPN use.'
}
Write-Output 'BATTERY_PRE_TUNNEL_PROMPT=absent_during_initialization'

$privacyConsent = Find-AfterScroll -Attribute 'content-desc' `
    -Prefix 'I have read and agree to the Privacy Policy' -Direction Up -Attempts 12
Tap-UiNode $privacyConsent
Start-Sleep -Milliseconds 500
Tap-UiPrefix -Attribute 'content-desc' -Prefix 'Accept Privacy Policy'
Start-Sleep -Seconds 6
if ((Get-TopActivity) -match 'RequestIgnoreBatteryOptimizations') {
    throw 'Battery exemption appeared after privacy consent but before a VPN tunnel was requested.'
}
Write-Output 'PRIVACY_CONSENT_ACTION=accepted_without_battery_prompt'

$editFields = @(Get-UiNodes | Where-Object { $_.GetAttribute('class') -eq 'android.widget.EditText' })
if ($editFields.Count -lt 2) {
    throw 'Fresh-install PIN field was not found.'
}
Tap-UiNode $editFields[-1]
Invoke-Adb shell input text $Pin | Out-Null
Invoke-Adb shell input keyevent 4 | Out-Null
$activationSwipeX = [int]($DisplayWidth * 0.50)
$activationSwipeStartY = [int]($DisplayHeight * 0.70)
$activationSwipeEndY = [int]($DisplayHeight * 0.18)
Invoke-Adb shell input swipe $activationSwipeX $activationSwipeStartY `
    $activationSwipeX $activationSwipeEndY 650 | Out-Null
Start-Sleep -Seconds 2
Tap-UiPrefix -Attribute 'content-desc' -Prefix 'Try Free Server'
Start-Sleep -Seconds 6

$vpnConsent = Find-AfterScroll -Attribute 'content-desc' `
    -Prefix 'I understand and agree to the Android VpnService disclosure.' -Direction Up
Tap-UiNode $vpnConsent
Start-Sleep -Milliseconds 500
$legalConsent = Find-AfterScroll -Attribute 'content-desc' `
    -Prefix 'I agree to the Terms of Service' -Direction Down
Tap-UiNode $legalConsent
Start-Sleep -Milliseconds 800
Tap-UiPrefix -Attribute 'content-desc' -Prefix 'Agree'
Start-Sleep -Seconds 18

Assert-WinsVpnIsTop -Phase 'ONBOARDING_TOP'
$welcome = Find-UiNode -Attribute 'content-desc' -Prefix "Welcome to Win's VPN"
if ($null -eq $welcome) {
    throw 'Fresh free activation did not reach the Win''s VPN dashboard.'
}

$doubleSwitch = Find-AfterScroll -Attribute 'content-desc' -Prefix 'Double VPN' -Direction Up -Attempts 10
Tap-UiNode $doubleSwitch
Start-Sleep -Seconds 3
$doubleSwitch = Find-UiNode -Attribute 'content-desc' -Prefix 'Double VPN'
if ($null -eq $doubleSwitch -or $doubleSwitch.GetAttribute('checked') -ne 'true') {
    throw 'Double VPN did not become checked before restart.'
}
Write-Output 'DOUBLE_BEFORE_RESTART=true'

Invoke-Adb shell am force-stop $PackageName | Out-Null
Start-Sleep -Seconds 2
Invoke-Adb shell am start -n "$PackageName/$PackageName.LauncherReal" | Out-Null
Start-Sleep -Seconds 12
Assert-WinsVpnIsTop -Phase 'REAL_TO_DECOY_TOP'

$calculatorKeys = @(Get-UiNodes | Where-Object {
    $_.GetAttribute('class') -eq 'android.widget.Button' -and
    $_.GetAttribute('content-desc').StartsWith('Calculator ', [StringComparison]::Ordinal)
})
if ($calculatorKeys.Count -ne 20) {
    throw "Expected 20 visible calculator keys after restart, found $($calculatorKeys.Count)."
}
Write-Output 'CALCULATOR_KEYS_VISIBLE=20'

foreach ($digit in $Pin.ToCharArray()) {
    Tap-UiPrefix -Attribute 'content-desc' -Prefix "Calculator $digit"
    Start-Sleep -Milliseconds 250
}
Start-Sleep -Seconds 10
Assert-WinsVpnIsTop -Phase 'DECOY_TO_REAL_TOP'

$doubleSwitch = Find-AfterScroll -Attribute 'content-desc' -Prefix 'Double VPN' -Direction Up -Attempts 12
if ($doubleSwitch.GetAttribute('checked') -ne 'true') {
    throw 'Double VPN selection was lost across the camouflage restart.'
}
Write-Output 'DOUBLE_AFTER_RESTART=true'

if ($LiveDoubleVpn) {
    $tunnelWasSecured = $false
    $connectWasRequested = $false
    $wirelessMonitorCompleted = $false
    try {
        Invoke-Adb logcat -c | Out-Null
        $connectButton = Find-AfterScroll -Attribute 'content-desc' `
            -Prefix 'Connect VPN' -Direction Down -Attempts 12
        if ($useWirelessMonitor) {
            Start-WirelessLiveMonitor
        }
        Tap-UiNode $connectButton
        $connectWasRequested = $true
        Write-Output 'CONNECT_TAP_COUNT=1'

    $permissionHandled = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        $top = Get-TopActivity
        if ($top -match 'com\.android\.vpndialogs') {
            $positiveButton = Get-UiNodes | Where-Object {
                $_.GetAttribute('resource-id') -eq 'android:id/button1' -or
                $_.GetAttribute('text') -match '^(OK|Allow)$'
            } | Select-Object -First 1
            if ($null -eq $positiveButton) {
                throw 'Android VPN permission dialog has no positive action.'
            }
            Tap-UiNode $positiveButton
            Start-Sleep -Seconds 2
            $topAfterTap = Get-TopActivity
            if ($topAfterTap -match 'com\.android\.vpndialogs') {
                throw 'Android rejected the automated VPN-consent action. Tap OK once on the connected phone, then rerun the live test; the harness will not bypass a protected OS consent sheet.'
            }
            $permissionHandled = $true
            Write-Output 'VPN_PERMISSION_ACTION=granted_once'
            break
        }
        if ($top -match [regex]::Escape($PackageName)) {
            $disconnectButton = Find-UiNode -Attribute 'content-desc' -Prefix 'Disconnect VPN'
            if ($null -ne $disconnectButton) { break }
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $permissionHandled) {
        Write-Output 'VPN_PERMISSION_ACTION=already_granted'
    }

    Resolve-PostTunnelBatteryExemption -TimeoutSeconds 45

    if ($useWirelessMonitor) {
        $wirelessResult = Wait-WirelessLiveMonitor
        $tunnelWasSecured = $true
        $wirelessMonitorCompleted = $true
        if ($RequireXrayFallback -and -not $wirelessResult.Xray) {
            throw 'Live Double VPN secured without the required Xray fallback process.'
        }
        Write-Output "DOUBLE_VPN_TUN_RX=$($wirelessResult.RxBytes)"
        Write-Output "DOUBLE_VPN_TUN_TX=$($wirelessResult.TxBytes)"
        if ($wirelessResult.Xray) {
            Write-Output 'DOUBLE_VPN_TRANSPORT=xray_fallback'
        } else {
            Write-Output 'DOUBLE_VPN_TRANSPORT=direct_awg'
        }
        Write-Output "PUBLIC_EGRESS_SHA256=$($wirelessResult.EgressDigest)"
        Write-Output 'ANDROID_BROWSER_DOUBLE_VPN_EGRESS=PASS'
        Write-Output 'ANDROID_LIVE_DISCONNECT=PASS'
        Write-Output 'ANDROID_DOUBLE_VPN_LIVE=PASS'
    } else {
    $deadline = [DateTime]::UtcNow.AddSeconds($ConnectTimeoutSeconds)
    $secured = $false
    do {
        Start-Sleep -Seconds 2
        $nodes = Get-UiNodes
        $disconnectButton = $nodes | Where-Object {
            $_.GetAttribute('content-desc').StartsWith('Disconnect VPN', [StringComparison]::Ordinal)
        } | Select-Object -First 1
        $securedLabel = $nodes | Where-Object {
            $_.GetAttribute('content-desc').StartsWith('SECURED', [StringComparison]::Ordinal)
        } | Select-Object -First 1
        if ($null -ne $disconnectButton -and $null -ne $securedLabel) {
            $secured = $true
            break
        }
    } while ([DateTime]::UtcNow -lt $deadline)

    if (-not $secured) {
        $diagnostic = Invoke-Adb logcat -d -t 2500 -v brief |
            Select-String -Pattern 'WinsVpnService|WinsFallback|WinsVpnMain|FATAL EXCEPTION.*org\.winsvpn\.app|Process: org\.winsvpn\.app' |
            Select-Object -Last 80
        $diagnosticText = @($diagnostic | ForEach-Object {
            if ($_ -is [Microsoft.PowerShell.Commands.MatchInfo]) { $_.Line } else { [string]$_ }
        }) -join ' | '
        throw "Live Double VPN did not reach a proven secured state: $diagnosticText"
    }
    $tunnelWasSecured = $true

    # Android 16 blocks the adb shell identity from reading the per-interface
    # sysfs statistics files even though /proc/net/dev remains readable. Parse
    # the kernel's aggregate line so the physical-device gate does not mistake
    # that SELinux restriction for a tunnel failure.
    $tunCounterLine = Invoke-Adb shell cat /proc/net/dev |
        Where-Object { $_ -match '^\s*tun0:' } |
        Select-Object -First 1
    $tunCounterMatch = [regex]::Match(
        [string]$tunCounterLine,
        '^\s*tun0:\s*(\d+)(?:\s+\d+){7}\s+(\d+)(?:\s+\d+){7}\s*$'
    )
    if (-not $tunCounterMatch.Success) {
        throw "Live Double VPN TUN counters are unavailable: $tunCounterLine"
    }
    $rxBytes = [long]$tunCounterMatch.Groups[1].Value
    $txBytes = [long]$tunCounterMatch.Groups[2].Value
    if ($rxBytes -lt 96 -or $txBytes -lt 96) {
        throw "Live Double VPN TUN counters are not bidirectional: rx=$rxBytes tx=$txBytes"
    }
    $xrayProcess = Invoke-Adb -Arguments @('shell', 'ps', '-A') |
        Select-String -Pattern 'libxray|/xray(?:\s|$)' |
        Select-Object -First 1
    if ($RequireXrayFallback -and $null -eq $xrayProcess) {
        throw 'Live Double VPN secured without the required Xray fallback process.'
    }
    Write-Output "DOUBLE_VPN_TUN_RX=$rxBytes"
    Write-Output "DOUBLE_VPN_TUN_TX=$txBytes"
    if ($null -ne $xrayProcess) {
        Write-Output 'DOUBLE_VPN_TRANSPORT=xray_fallback'
    } else {
        Write-Output 'DOUBLE_VPN_TRANSPORT=direct_awg'
    }
    Assert-PublicEgress
    Write-Output 'ANDROID_DOUBLE_VPN_LIVE=PASS'
    }
    } finally {
        if ($connectWasRequested -and -not $wirelessMonitorCompleted) {
            Stop-LiveVpn -RequireUiDisconnect:$tunnelWasSecured
        }
    }
}

$fatalLines = @(Invoke-Adb logcat -d -t 4000 -v brief |
    Select-String -Pattern 'FATAL EXCEPTION|AndroidRuntime.*FATAL|Process: org\.winsvpn\.app.*has died')
if ($fatalLines.Count -gt 0) {
    throw "Fatal Android startup errors were logged: $($fatalLines.Line -join ' | ')"
}

Write-Output 'ANDROID_FRESH_RELEASE_REGRESSION=PASS'
} finally {
    Invoke-Adb shell settings put system screen_off_timeout $originalScreenTimeout | Out-Null
    Invoke-Adb shell settings put global stay_on_while_plugged_in $originalStayAwake | Out-Null
    Write-Output "SCREEN_TIMEOUT_RESTORED_MS=$originalScreenTimeout"
    Write-Output "PLUGGED_IN_STAY_AWAKE_RESTORED=$originalStayAwake"
}
