param(
    [string]$Package = "org.winsvpn.app",
    [string]$Apk = "build\app\outputs\flutter-apk\app-release.apk",
    [int]$WarmupSeconds = 12,
    [int]$LogcatLines = 1600
)

$ErrorActionPreference = "Stop"
$AdbSerial = "ZY22GTV6Z3"
$Adb = "adb -s $AdbSerial"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$ApkPath = Resolve-Path (Join-Path $RepoRoot $Apk)
$OutDir = Join-Path $RepoRoot ".artifacts\phone-stress"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$deviceOutput = & $Adb devices -l
if ($LASTEXITCODE -ne 0) { throw "adb devices failed with exit code $LASTEXITCODE" }
$connectedDevices = @($deviceOutput | Where-Object { $_ -match '^\S+\s+device(?:\s|$)' })
if ($connectedDevices.Count -lt 1) {
    throw "No authorized USB-debugging device attached."
}
if (-not ($connectedDevices | Where-Object { $_ -match ('^' + [regex]::Escape($AdbSerial) + '\s') })) {
    throw "Pinned target device $AdbSerial is not attached/authorized."
}

$priorPromptEvidence = Get-ChildItem -LiteralPath $OutDir -Filter "focus-*.txt" -File |
    Where-Object { $_.Name -notmatch '^focus-resumed-' } |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
if (-not $priorPromptEvidence) {
    throw "No prior post-tunnel battery-prompt focus evidence exists for this continuation."
}
$priorFocus = Get-Content -LiteralPath $priorPromptEvidence.FullName -Raw
if ($priorFocus -notmatch 'org\.winsvpn\.app' -or $priorFocus -notmatch 'RequestIgnoreBatteryOptimizations') {
    throw "The prior run did not stop at the expected post-tunnel owner battery-optimization dialog."
}

$artifactSha256 = (Get-FileHash -LiteralPath $ApkPath -Algorithm SHA256).Hash.ToLowerInvariant()
$packagePathLine = ((& $Adb shell pm path $Package) -join "").Trim()
if ($LASTEXITCODE -ne 0 -or $packagePathLine -notmatch '^package:(.+)$') {
    throw "The package from the interrupted clean-install run is no longer installed."
}
$installedBaseApkPath = $Matches[1]
$installedShaOutput = ((& $Adb shell sha256sum $installedBaseApkPath) -join "").Trim()
if ($LASTEXITCODE -ne 0 -or $installedShaOutput -notmatch '^([0-9a-fA-F]{64})\s') {
    throw "Android could not hash the installed base APK."
}
$installedSha256 = $Matches[1].ToLowerInvariant()
if ($installedSha256 -cne $artifactSha256) {
    throw "Installed base APK does not match the exact staged clean-install artifact."
}

$pubspec = Get-Content -LiteralPath (Join-Path $RepoRoot "pubspec.yaml") -Raw
if ($pubspec -notmatch '(?m)^version:\s*([^+\s]+)\+(\d+)\s*$') {
    throw "Could not read version/build from pubspec.yaml."
}
$expectedVersion = $Matches[1]
$expectedBuild = $Matches[2]
$packageDump = (& $Adb shell dumpsys package $Package) -join "`n"
$versionMatch = [regex]::Match($packageDump, '(?m)^\s*versionName=([^\s]+)')
$buildMatch = [regex]::Match($packageDump, '(?m)^\s*versionCode=(\d+)')
if (-not $versionMatch.Success -or $versionMatch.Groups[1].Value -ne $expectedVersion) {
    throw "Installed Android version does not match $expectedVersion."
}
if (-not $buildMatch.Success -or $buildMatch.Groups[1].Value -ne $expectedBuild) {
    throw "Installed Android build does not match $expectedBuild."
}

& $Adb logcat -c | Out-Null
& $Adb shell monkey -p $Package -c android.intent.category.LAUNCHER 1 | Out-Host
if ($LASTEXITCODE -ne 0) { throw "adb launch failed with exit code $LASTEXITCODE" }
Start-Sleep -Seconds $WarmupSeconds

$appPid = ((& $Adb shell pidof $Package) -join "").Trim()
if ($LASTEXITCODE -ne 0 -or $appPid -notmatch '^\d+$') {
    throw "Win's VPN did not remain alive after the resumed launch."
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logPath = Join-Path $OutDir "logcat-resumed-$stamp.txt"
$focusPath = Join-Path $OutDir "focus-resumed-$stamp.txt"
$screenPath = Join-Path $OutDir "screen-resumed-$stamp.png"
$evidencePath = Join-Path $OutDir "startup-evidence-resumed-$stamp.json"

& $Adb logcat "--pid=$appPid" -d -t $LogcatLines > $logPath
if ($LASTEXITCODE -ne 0) { throw "App-scoped adb logcat capture failed." }
& $Adb shell dumpsys window > $focusPath
$focusText = Get-Content -LiteralPath $focusPath -Raw
if ($focusText -notmatch ('(?m)^\s*mCurrentFocus=.*' + [regex]::Escape($Package))) {
    throw "Win's VPN is alive but is not focused after the post-tunnel owner dialog was resolved."
}

$startInfo = [Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = (Get-Command adb -ErrorAction Stop).Source
$startInfo.Arguments = "-s $AdbSerial exec-out screencap -p"
$startInfo.UseShellExecute = $false
$startInfo.RedirectStandardOutput = $true
$capture = [Diagnostics.Process]::Start($startInfo)
$fileStream = [IO.File]::Open($screenPath, [IO.FileMode]::Create, [IO.FileAccess]::Write)
try {
    $capture.StandardOutput.BaseStream.CopyTo($fileStream)
    $capture.WaitForExit()
} finally {
    $fileStream.Dispose()
    $capture.Dispose()
}
if (-not (Test-Path -LiteralPath $screenPath) -or (Get-Item -LiteralPath $screenPath).Length -lt 1024) {
    throw "adb screenshot capture failed."
}

$errorPattern = "FATAL EXCEPTION|AndroidRuntime.*FATAL|E/flutter.*Unhandled Exception|WinsVpnService.*(error|failed|crashed)|AmneziaWG.*(error|failed|crashed)|Xray.*(error|failed|crashed)|SIGSEGV|SIGABRT"
$suspicious = @(Select-String -LiteralPath $logPath -Pattern $errorPattern -CaseSensitive:$false)
if ($suspicious.Count -gt 0) {
    $suspicious | Select-Object -First 40 | ForEach-Object { Write-Host $_.Line }
    throw "Resumed phone run found suspicious Android/VPN log lines."
}

[ordered]@{
    schema_version = 1
    platform = "android"
    package = $Package
    app_version = $expectedVersion
    build_number = $expectedBuild
    artifact_sha256 = $artifactSha256
    installed_base_apk_sha256 = $installedSha256
    prior_owner_prompt_evidence = $priorPromptEvidence.Name
    tested_at_utc = [DateTime]::UtcNow.ToString("o")
    clean_install_continuation_passed = $true
    owner_battery_prompt_resolved = $true
    battery_prompt_phase = "post_tunnel"
    tunnel_was_required_before_prompt = $true
    tunnel_revalidated_after_resume = $false
    foreground_launch_passed = $true
    startup_log_scan_passed = $true
    tunnel_tested = $false
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $evidencePath -Encoding UTF8

Write-Host "[PHONE-RESUME] PASS"
Write-Host "[PHONE-RESUME] Exact installed APK: $artifactSha256"
Write-Host "[PHONE-RESUME] Screenshot: $screenPath"
Write-Host "[PHONE-RESUME] Logcat: $logPath"
Write-Host "[PHONE-RESUME] Evidence: $evidencePath"
