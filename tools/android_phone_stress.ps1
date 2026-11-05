param(
    [string]$Package = "org.winsvpn.app.debug",
    [string]$Apk = "build\app\outputs\flutter-apk\app-debug.apk",
    [int]$WarmupSeconds = 8,
    [int]$InstallTimeoutSeconds = 300,
    [int]$LogcatLines = 1200,
    [int]$ConnectReconnectCycles = 3,
    [int]$CycleSettleSeconds = 6,
    [switch]$ToggleWifi,
    [switch]$ToggleCellular
)

$ErrorActionPreference = "Stop"
$AdbSerial = "ZY22GTV6Z3"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$OutDir = Join-Path $RepoRoot ".artifacts\phone-stress"
$DeviceModel = ""
$OverallPassed = $false
$FailReason = $null

function Get-AdbExe {
    $cmd = Get-Command adb -ErrorAction SilentlyContinue
    if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace($cmd.Source)) {
        return $cmd.Source
    }
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'),
        (Join-Path $env:USERPROFILE '.local\android-sdk\platform-tools\adb'),
        "/Users/$env:USER/.local/android-sdk/platform-tools/adb"
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }
    throw "adb not found on PATH or any known location."
}

function Invoke-Adb {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & $script:AdbExe -s $AdbSerial @Arguments
    return $LASTEXITCODE
}

function Get-AppPid {
    $out = (& $script:AdbExe -s $AdbSerial shell pidof $Package) -join ""
    return ($out.Trim())
}

function Test-ForegroundIsApp {
    $focus = (& $script:AdbExe -s $AdbSerial shell dumpsys window 2>$null) -join "`n"
    return ($focus -match ('(?m)^\s*mCurrentFocus=.*' + [regex]::Escape($Package)))
}

function Write-RunLog {
    param([string]$Path, [string[]]$Lines)
    $Lines | Set-Content -LiteralPath $Path -Encoding utf8
}

function Install-ApkWithPromptAwareness {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $script:AdbExe
    $startInfo.Arguments = "-s $AdbSerial install `"$Path`""
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $install = [System.Diagnostics.Process]::Start($startInfo)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $promptReported = $false
    try {
        while (-not $install.HasExited -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 750
            $windowState = (& $script:AdbExe -s $AdbSerial shell dumpsys window 2>$null) -join "`n"
            if (-not $promptReported -and $windowState -match 'PlayProtectDialogsActivity') {
                $promptReported = $true
                Write-Warning "Google Play Protect is waiting on the phone. The owner must choose Send this time or Don't send; this script will not make that privacy/security choice."
            }
        }
        if (-not $install.HasExited) {
            $install.Kill()
            $install.WaitForExit()
            $reason = if ($promptReported) { "the owner did not answer the Play Protect prompt" } else { "Android package installation did not finish" }
            throw "adb install timed out after $TimeoutSeconds seconds because $reason."
        }
        $stdout = $install.StandardOutput.ReadToEnd().Trim()
        $stderr = $install.StandardError.ReadToEnd().Trim()
        if ($stdout) { Write-Host $stdout }
        if ($stderr) { Write-Host $stderr }
        if ($install.ExitCode -ne 0 -or $stdout -notmatch '(?m)^Success\s*$') {
            throw "adb install failed with exit code $($install.ExitCode)."
        }
    } finally {
        $install.Dispose()
    }
}

try {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $script:AdbExe = Get-AdbExe
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"

    # ---------- device preflight ----------
    Write-Host "[PHONE] Connected devices"
    $deviceOutput = & $script:AdbExe devices -l
    if ($LASTEXITCODE -ne 0) { throw "adb devices failed with exit code $LASTEXITCODE" }
    $deviceOutput | Write-Host
    $connectedDevices = @($deviceOutput | Where-Object { $_ -match '^\S+\s+device(?:\s|$)' })
    if (-not ($connectedDevices | Where-Object { $_ -match ('^' + [regex]::Escape($AdbSerial) + '\s') })) {
        throw "Pinned target device $AdbSerial is not attached/authorized."
    }
    $modelLine = @($deviceOutput | Where-Object { $_ -match ('^' + [regex]::Escape($AdbSerial) + '\s') }) | Select-Object -First 1
    $deviceModel = if ($modelLine -match 'model:(\S+)') { $Matches[1] } else { "unknown" }

    # ---------- exact artifact ----------
    $normalizedApk = $Apk -replace '\\', [IO.Path]::DirectorySeparatorChar
    $ApkPath = Resolve-Path -LiteralPath (Join-Path $RepoRoot $normalizedApk)
    if (-not (Test-Path -LiteralPath $ApkPath -PathType Leaf)) { throw "APK does not exist: $ApkPath" }
    $artifactSha256 = (Get-FileHash -LiteralPath $ApkPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "[PHONE] Artifact: $ApkPath sha256=$artifactSha256"

    # ---------- stay awake ----------
    Write-Host "[PHONE] Keeping screen awake while plugged in"
    Invoke-Adb -Arguments @('shell','settings','put','global','stay_on_while_plugged_in','3') | Out-Null
    Invoke-Adb -Arguments @('shell','input','keyevent','WAKEUP') | Out-Null

    # ---------- clean install ----------
    Write-Host "[PHONE] Uninstalling old package first"
    Invoke-Adb -Arguments @('uninstall', $Package) | Out-Host
    Write-Host "[PHONE] Installing debug APK: $ApkPath"
    Install-ApkWithPromptAwareness -Path $ApkPath -TimeoutSeconds $InstallTimeoutSeconds

    # ---------- verify the installed artifact ----------
    $pubspec = Get-Content -LiteralPath (Join-Path $RepoRoot "pubspec.yaml") -Raw
    if ($pubspec -notmatch '(?m)^version:\s*([^+\s]+)\+(\d+)\s*$') {
        throw "Could not read version/build from pubspec.yaml."
    }
    $expectedVersion = $Matches[1]
    $expectedBuild = $Matches[2]
    $packageDump = (& $script:AdbExe -s $AdbSerial shell dumpsys package $Package) -join "`n"
    $versionMatch = [regex]::Match($packageDump, '(?m)^\s*versionName=([^\s]+)')
    if (-not $versionMatch.Success -or $versionMatch.Groups[1].Value -ne $expectedVersion) {
        throw "Installed Android version does not match pubspec version $expectedVersion."
    }
    $buildMatch = [regex]::Match($packageDump, '(?m)^\s*versionCode=(\d+)')
    if (-not $buildMatch.Success -or $buildMatch.Groups[1].Value -ne $expectedBuild) {
        throw "Installed Android build does not match pubspec build $expectedBuild."
    }
    Write-Host "[PHONE] Installed exact artifact: version=$expectedVersion build=$expectedBuild sha256=$artifactSha256"

    # ---------- first launch ----------
    Write-Host "[PHONE] Clearing logcat and launching"
    Invoke-Adb -Arguments @('logcat','-c') | Out-Null
    $launchOut = Invoke-Adb -Arguments @('shell','monkey','-p',$Package,'-c','android.intent.category.LAUNCHER','1')
    if ($LASTEXITCODE -ne 0) { throw "adb monkey launch failed with exit code $LASTEXITCODE" }
    Start-Sleep -Seconds $WarmupSeconds

    $appPid = Get-AppPid
    if ($appPid -notmatch '^\d+$') { throw "Win's VPN did not remain alive after launch." }
    if (-not (Test-ForegroundIsApp)) {
        $focus = (& $script:AdbExe -s $AdbSerial shell dumpsys window 2>$null) -join "`n"
        throw "Win's VPN is alive but is not the focused foreground app after launch."
    }
    Write-Host "[PHONE] First launch foreground, pid=$appPid"
    $firstLaunchPid = $appPid
    $observedPids = @($firstLaunchPid)

    $screenshot = Join-Path $OutDir "screen-$stamp.png"
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $script:AdbExe
    $psi.Arguments = "-s $AdbSerial exec-out screencap -p"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $cap = [System.Diagnostics.Process]::Start($psi)
    $fileStream = [System.IO.File]::Open($screenshot, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    try {
        $cap.StandardOutput.BaseStream.CopyTo($fileStream)
        $cap.WaitForExit()
    } finally {
        $fileStream.Dispose()
    }
    if ($cap.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $screenshot) -or (Get-Item -LiteralPath $screenshot).Length -lt 1024) {
        throw "adb screenshot capture failed"
    }

    # ---------- connect/reconnect cycle ----------
    $runTranscript = @()
    $runTranscript += "[PHONE] Connect/reconnect cycles: $ConnectReconnectCycles"
    $cyclePassed = @()
    if ($ConnectReconnectCycles -ge 1) {
        Invoke-Adb -Arguments @('logcat','-c') | Out-Null
        for ($i = 1; $i -le $ConnectReconnectCycles; $i++) {
            Write-Host "[PHONE] Connect/reconnect cycle $i of $ConnectReconnectCycles"
            Invoke-Adb -Arguments @('shell','am','force-stop',$Package) | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "adb force-stop failed on cycle $i" }
            Start-Sleep -Seconds 2
            $relaunchOut = Invoke-Adb -Arguments @('shell','monkey','-p',$Package,'-c','android.intent.category.LAUNCHER','1')
            if ($LASTEXITCODE -ne 0) { throw "adb relaunch failed on cycle $i" }
            Start-Sleep -Seconds $CycleSettleSeconds

            $cyclePid = Get-AppPid
            $observedPids += $cyclePid
            $cycleForeground = Test-ForegroundIsApp
            if ($cyclePid -notmatch '^\d+$') {
                $runTranscript += "cycle_$i=FAIL pid_missing"
                $cyclePassed += $false
                throw "App did not return to a live process on connect/reconnect cycle $i."
            }
            if (-not $cycleForeground) {
                $runTranscript += "cycle_$i=FAIL not_foreground"
                $cyclePassed += $false
                throw "App process is alive on cycle $i but not foreground."
            }

            $cycleLog = (& $script:AdbExe -s $AdbSerial logcat "--pid=$cyclePid" -d -t $LogcatLines 2>$null)
            $cycleErrors = @($cycleLog | Where-Object {
                $_ -match "FATAL EXCEPTION|AndroidRuntime.*FATAL|SIGSEGV|SIGABRT|E/flutter.*Unhandled Exception|WinsVpnService.*(error|failed|crashed)|AmneziaWG.*(error|failed|crashed)|Xray.*(error|failed|crashed)"
            })
            if ($cycleErrors.Count -gt 0) {
                $cycleErrors | Select-Object -First 40 | ForEach-Object { Write-Host $_ }
                $runTranscript += "cycle_$i=FAIL suspicious_log"
                $cyclePassed += $false
                throw "Suspicious Android/VPN log lines on connect/reconnect cycle $i."
            }

            $runTranscript += "cycle_$i=PASS pid=$cyclePid foreground=$cycleForeground"
            $cyclePassed += $true
            Write-Host "[PHONE] Cycle $i passed (pid=$cyclePid)"
        }
    }

    # ---------- optional network handoff smoke ----------
    if ($ToggleWifi) {
        Write-Host "[PHONE] Toggling Wi-Fi off/on for handoff smoke"
        Invoke-Adb -Arguments @('shell','svc','wifi','disable') | Out-Null
        Start-Sleep -Seconds 8
        Invoke-Adb -Arguments @('shell','svc','wifi','enable') | Out-Null
        Start-Sleep -Seconds 12
        $handoffPid = Get-AppPid
        if ($handoffPid -notmatch '^\d+$') { throw "App died during Wi-Fi handoff smoke." }
        $runTranscript += "wifi_handoff=PASS pid=$handoffPid"
    }
    if ($ToggleCellular) {
        Write-Host "[PHONE] Toggling cellular data off/on for handoff smoke"
        Invoke-Adb -Arguments @('shell','svc','data','disable') | Out-Null
        Start-Sleep -Seconds 8
        Invoke-Adb -Arguments @('shell','svc','data','enable') | Out-Null
        Start-Sleep -Seconds 12
        $handoffPid = Get-AppPid
        if ($handoffPid -notmatch '^\d+$') { throw "App died during cellular handoff smoke." }
        $runTranscript += "cellular_handoff=PASS pid=$handoffPid"
    }

    # ---------- final log artifact ----------
    $observedPids = @($observedPids | Sort-Object -Unique)
    $logPath = Join-Path $OutDir "logcat-$stamp.txt"
    $finalLog = (& $script:AdbExe -s $AdbSerial logcat -d 2>$null)
    if ($LASTEXITCODE -ne 0) { throw "App-scoped adb logcat capture failed." }
    Write-RunLog -Path $logPath -Lines $finalLog

    $appLogLines = @($finalLog | Where-Object {
        $pm = [regex]::Match($_, '^\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}\s+(\d+)')
        if (-not $pm.Success) { return $false }
        $observedPids -contains $pm.Groups[1].Value
    })
    if ($appLogLines.Count -eq 0) {
        throw "Final app-scoped log scan found no lines for observed pids ($($observedPids -join ', ')); cannot verify a clean startup."
    }
    $startupErrors = @($appLogLines | Where-Object {
        $_ -match "FATAL EXCEPTION|AndroidRuntime.*FATAL|SIGSEGV|SIGABRT|E/flutter.*Unhandled Exception|WinsVpnService.*(error|failed|crashed)|AmneziaWG.*(error|failed|crashed)|Xray.*(error|failed|crashed)"
    })

    $runTranscriptPath = Join-Path $OutDir "run-$stamp.log"
    Write-RunLog -Path $runTranscriptPath -Lines $runTranscript

    $passedCount = @($cyclePassed | Where-Object { $_ }).Count
    $allCyclesPassed = ($cyclePassed.Count -gt 0) -and ($passedCount -eq $ConnectReconnectCycles)

    if ($startupErrors.Count -gt 0) {
        $startupErrors | Select-Object -First 40 | ForEach-Object { Write-Host "[PHONE] suspicious: $_" }
        throw "Phone stress run found suspicious Android/VPN log lines. See $logPath"
    }

    $evidencePath = Join-Path $OutDir "startup-evidence-$stamp.json"
    [ordered]@{
        schema_version = 1
        platform = "android"
        package = $Package
        device_serial = $AdbSerial
        device_model = $deviceModel
        app_version = $expectedVersion
        build_number = $expectedBuild
        artifact_sha256 = $artifactSha256
        connect_reconnect_cycles = $ConnectReconnectCycles
        cycles_passed = $allCyclesPassed
        tested_at_utc = [DateTime]::UtcNow.ToString("o")
        clean_install_passed = $true
        foreground_launch_passed = $true
        startup_log_scan_passed = $true
        tunnel_tested = $false
        logcat_artifact = $logPath
        overall_passed = $true
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $evidencePath -Encoding UTF8

    $OverallPassed = $true
    Write-Host "[PHONE] PASS"
    Write-Host "[PHONE] Device: $AdbSerial ($deviceModel)"
    Write-Host "[PHONE] Screenshot: $screenshot"
    Write-Host "[PHONE] Run transcript: $runTranscriptPath"
    Write-Host "[PHONE] Logcat: $logPath"
    Write-Host "[PHONE] Evidence: $evidencePath"
}
catch {
    $OverallPassed = $false
    $FailReason = $_.Exception.Message
    $failureStamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $failureLog = Join-Path $OutDir "logcat-failed-$failureStamp.txt"
    $evidencePath = Join-Path $OutDir "startup-evidence-failed-$failureStamp.json"
    try {
        $errLog = (& $script:AdbExe -s $AdbSerial logcat -d 2>$null)
        Write-RunLog -Path $failureLog -Lines $errLog
    } catch { }
    try {
        [ordered]@{
            schema_version = 1
            platform = "android"
            package = $Package
            device_serial = $AdbSerial
            tested_at_utc = [DateTime]::UtcNow.ToString("o")
            overall_passed = $false
            failure_reason = $FailReason
            logcat_artifact = $failureLog
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $evidencePath -Encoding UTF8
    } catch { }
    Write-Host "[PHONE] FAIL: $FailReason"
    Write-Host "[PHONE] Dated failure log artifact: $failureLog"
    Write-Host "[PHONE] Evidence: $evidencePath"
}
finally {
}
exit $(if ($OverallPassed) { 0 } else { 1 })