param(
    [ValidateSet("AWG", "SmartBoost")]
    [string]$Mode = "AWG",
    [ValidateSet("FrontierLA", "SonicLA", "SpectrumLA", "OoklaLA", "Cachefly", "Custom")]
    [string]$Target = "SonicLA",
    [string]$Url = "",
    [ValidateRange(1, 16)]
    [int]$ParallelConnections = 4,
    [ValidateRange(1, 8)]
    [int]$RepeatsPerConnection = 2,
    [int]$Runs = 3,
    [int]$MaxTimeSeconds = 90,
    [ValidateRange(1048576, 104857600)]
    [int]$BytesPerRequest = 16777216,
    [string]$OutDir = ".artifacts\smart-boost-benchmark"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$OutputDir = Join-Path $RepoRoot $OutDir
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

function Invoke-AdbText {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $previousErrorActionPreference = $ErrorActionPreference
    $previousNativeErrorPreference = $PSNativeCommandUseErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $PSNativeCommandUseErrorActionPreference = $false
        $output = & adb @Args 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "adb $($Args -join ' ') failed with exit code $LASTEXITCODE`n$output"
        }
        return ($output -join "`n")
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
        $PSNativeCommandUseErrorActionPreference = $previousNativeErrorPreference
    }
}

function Write-AndroidShellScript {
    param(
        [string]$Path,
        [string]$Content
    )
    [System.IO.File]::WriteAllText(
        $Path,
        $Content.Replace("`r`n", "`n"),
        [System.Text.Encoding]::ASCII
    )
}

function Assert-PhoneCurl {
    $curlPath = Invoke-AdbText shell which curl
    if ([string]::IsNullOrWhiteSpace($curlPath)) {
        throw "The connected phone does not expose curl through adb shell. Install a test curl binary or run the benchmark with a browser-based speed harness."
    }
}

function Resolve-BenchmarkUrls {
    param(
        [string]$Target,
        [string]$Url
    )

    if (-not [string]::IsNullOrWhiteSpace($Url)) {
        return @($Url)
    }

    switch ($Target) {
        "FrontierLA" {
            return @(
                "http://losangeles.ca.speedtest.frontier.com:8080/speedtest/random4000x4000.jpg",
                "http://losangeles.ca.speedtest.frontier.com:8080/speedtest/random3500x3500.jpg",
                "http://losangeles.ca.speedtest.frontier.com:8080/speedtest/random3000x3000.jpg",
                "https://losangeles.ca.speedtest.frontier.com:8080/speedtest/random4000x4000.jpg",
                "https://losangeles.ca.speedtest.frontier.com:8080/speedtest/random3500x3500.jpg",
                "https://losangeles.ca.speedtest.frontier.com:8080/speedtest/random3000x3000.jpg"
            )
        }
        "SonicLA" {
            return @(
                "http://speedtest.lax2.sonic.net:8080/speedtest/random4000x4000.jpg",
                "http://speedtest.lax2.sonic.net:8080/speedtest/random3500x3500.jpg",
                "http://speedtest.lax2.sonic.net:8080/speedtest/random3000x3000.jpg",
                "https://speedtest.lax2.sonic.net:8080/speedtest/random4000x4000.jpg",
                "https://speedtest.lax2.sonic.net:8080/speedtest/random3500x3500.jpg",
                "https://speedtest.lax2.sonic.net:8080/speedtest/random3000x3000.jpg"
            )
        }
        "SpectrumLA" {
            return @(
                "http://lsanca-speedtest-ookla-02.st.charter.com:8080/speedtest/random4000x4000.jpg",
                "http://lsanca-speedtest-ookla-02.st.charter.com:8080/speedtest/random3500x3500.jpg",
                "http://lsanca-speedtest-ookla-02.st.charter.com:8080/speedtest/random3000x3000.jpg",
                "https://lsanca-speedtest-ookla-02.st.charter.com:8080/speedtest/random4000x4000.jpg",
                "https://lsanca-speedtest-ookla-02.st.charter.com:8080/speedtest/random3500x3500.jpg",
                "https://lsanca-speedtest-ookla-02.st.charter.com:8080/speedtest/random3000x3000.jpg"
            )
        }
        "OoklaLA" {
            return @(
                "http://speedtestla.gethotwired.com:8080/speedtest/random4000x4000.jpg",
                "http://ookla.la.ca.sharktech.net:8080/speedtest/random4000x4000.jpg",
                "http://speedapi.race.com:8080/speedtest/random4000x4000.jpg",
                "http://la.speedtest.clouvider.net:8080/speedtest/random4000x4000.jpg",
                "http://speedtest-lax.melbicom.net:8080/speedtest/random4000x4000.jpg",
                "http://speedtest.uia.net:8080/speedtest/random4000x4000.jpg"
            )
        }
        "Cachefly" {
            return @("https://cachefly.cachefly.net/100mb.test")
        }
        default {
            throw "Custom benchmark target requires -Url."
        }
    }
}

function Test-PhoneBenchmarkUrl {
    param([string]$Url)

    $scriptId = [guid]::NewGuid().ToString("N")
    $localScript = Join-Path $env:TEMP ("wins-vpn-url-probe-{0}.sh" -f $scriptId)
    $remoteScript = "/data/local/tmp/wins_vpn_url_probe_$scriptId.sh"
    $remoteOut = "/data/local/tmp/wins_vpn_url_probe_$scriptId.bin"
    $escapedUrl = $Url.Replace("'", "'\''")
    try {
        $probeScript = @"
#!/system/bin/sh
out='$remoteOut'
url='$escapedUrl'
rm -f "`$out" 2>/dev/null
code=`$(curl -L -m 20 -r 0-4095 -sS -o "`$out" -w '%{http_code}' "`$url" 2>/dev/null)
rc=`$?
if [ -f "`$out" ]; then
  bytes=`$(wc -c "`$out" 2>/dev/null | awk '{print `$1 + 0}')
else
  bytes=0
fi
rm -f "`$out" 2>/dev/null
if [ "`$rc" -ne 0 ] || [ "`$code" -ge 400 ] || [ "`$bytes" -le 0 ]; then
  head_code=`$(curl -L -m 20 -I -sS -o /dev/null -w '%{http_code}' "`$url" 2>/dev/null)
  head_rc=`$?
  if [ "`$head_rc" -eq 0 ] && [ "`$head_code" -ge 200 ] && [ "`$head_code" -lt 400 ]; then
    echo "rc=0 code=`$head_code bytes=1 probe=head"
    exit 0
  fi
fi
echo "rc=`$rc code=`$code bytes=`$bytes"
"@
        Write-AndroidShellScript -Path $localScript -Content $probeScript
        Invoke-AdbText push $localScript $remoteScript | Out-Null
        $raw = Invoke-AdbText shell sh $remoteScript
        $line = (@($raw -split "`n" | Where-Object { $_.Trim() })[-1]).Trim()
        if ($line -notmatch "rc=(\d+)\s+code=(\d+)\s+bytes=(\d+)") {
            Write-Warning "Benchmark URL probe had unexpected output for $Url`: $raw"
            return $false
        }
        $rc = [int]$Matches[1]
        $code = [int]$Matches[2]
        $bytes = [int64]$Matches[3]
        if ($rc -ne 0) {
            Write-Warning "Benchmark URL not usable: $Url curl_rc=$rc code=$code bytes=$bytes"
            return $false
        }
        if ($code -ge 200 -and $code -lt 400) {
            if ($bytes -le 0) {
                Write-Warning "Benchmark URL not usable: $Url returned code=$code but no bytes"
                return $false
            }
            return $true
        }
        Write-Warning "Benchmark URL not usable: $Url returned code=$code bytes=$bytes"
        return $false
    } finally {
        Remove-Item -Force -ErrorAction SilentlyContinue $localScript
        & adb shell rm -f $remoteScript $remoteOut 2>$null | Out-Null
    }
}

function Select-WorkingBenchmarkUrls {
    param([string[]]$Urls)

    $working = @()
    $workingHttp = @()
    foreach ($candidate in $Urls) {
        if (Test-PhoneBenchmarkUrl -Url $candidate) {
            $working += $candidate
            if ($candidate.StartsWith("http://", [System.StringComparison]::OrdinalIgnoreCase)) {
                $workingHttp += $candidate
            }
        }
    }
    if ($workingHttp.Count -gt 0) {
        return $workingHttp
    }
    return $working
}

function New-PhoneBenchmarkScript {
    param(
        [string[]]$Urls,
        [int]$ParallelConnections,
        [int]$RepeatsPerConnection,
        [int]$MaxTimeSeconds,
        [int]$BytesPerRequest
    )

    $caseLines = @()
    for ($index = 0; $index -lt $Urls.Count; $index++) {
        $escaped = $Urls[$index].Replace("'", "'\''")
        $caseLines += "    $index) url='$escaped' ;;"
    }
    $cases = $caseLines -join "`n"
    $urlCount = $Urls.Count
    $rangeEnd = [Math]::Max(0, $BytesPerRequest - 1)

    return @"
#!/system/bin/sh
OUTDIR="/data/local/tmp/wins_vpn_bench_`$`$"
mkdir -p "`$OUTDIR" || exit 90
rm -f "`$OUTDIR"/*.out 2>/dev/null

url_for_index() {
  idx=`$((`$1 % $urlCount))
  case "`$idx" in
$cases
  esac
  echo "`$url"
}

worker=0
while [ "`$worker" -lt "$ParallelConnections" ]; do
  (
    total=0
    rc=0
    repeat=0
    while [ "`$repeat" -lt "$RepeatsPerConnection" ]; do
      url=`$(url_for_index `$((worker + repeat)))
      whole_bytes=`$(curl -L -m "$MaxTimeSeconds" -r "0-$rangeEnd" -sS -o /dev/null -w '%{size_download}' "`$url" 2>/dev/null)
      one_rc=`$?
      case "`$whole_bytes" in
        ''|*[!0-9]*) whole_bytes=0 ;;
      esac
      total=`$((total + whole_bytes))
      if [ "`$one_rc" -ne 0 ] || [ "`$whole_bytes" -le 0 ]; then
        rc=`$one_rc
        break
      fi
      repeat=`$((repeat + 1))
    done
    echo "rc=`$rc bytes=`$total" > "`$OUTDIR/`$worker.out"
  ) &
  worker=`$((worker + 1))
done
wait

total=0
rc=0
count=0
for f in "`$OUTDIR"/*.out; do
  [ -f "`$f" ] || continue
  line=`$(cat "`$f")
  worker_rc=`$(echo "`$line" | sed -n 's/.*rc=\([0-9][0-9]*\).*/\1/p')
  worker_bytes=`$(echo "`$line" | sed -n 's/.*bytes=\([0-9][0-9]*\).*/\1/p')
  [ -z "`$worker_rc" ] && worker_rc=1
  [ -z "`$worker_bytes" ] && worker_bytes=0
  [ "`$worker_rc" -ne 0 ] && rc=`$worker_rc
  total=`$((total + worker_bytes))
  count=`$((count + 1))
done
rm -rf "`$OUTDIR" 2>/dev/null
echo "rc=`$rc bytes=`$total workers=`$count"
"@
}

function Invoke-PhoneDownloadSample {
    param(
        [string[]]$Urls,
        [int]$ParallelConnections,
        [int]$RepeatsPerConnection,
        [int]$MaxTimeSeconds,
        [int]$BytesPerRequest
    )
    $scriptId = [guid]::NewGuid().ToString("N")
    $localScript = Join-Path $env:TEMP ("wins-vpn-phone-bench-{0}.sh" -f $scriptId)
    $localRunner = Join-Path $env:TEMP ("wins-vpn-phone-bench-runner-{0}.sh" -f $scriptId)
    $remoteScript = "/data/local/tmp/wins_vpn_phone_bench_$scriptId.sh"
    $remoteRunner = "/data/local/tmp/wins_vpn_phone_bench_runner_$scriptId.sh"
    $remoteResult = "/data/local/tmp/wins_vpn_phone_bench_$scriptId.out"
    $remoteExit = "/data/local/tmp/wins_vpn_phone_bench_$scriptId.exit"
    $benchScript = New-PhoneBenchmarkScript -Urls $Urls -ParallelConnections $ParallelConnections -RepeatsPerConnection $RepeatsPerConnection -MaxTimeSeconds $MaxTimeSeconds -BytesPerRequest $BytesPerRequest
    Write-AndroidShellScript -Path $localScript -Content $benchScript
    $runnerScript = @"
#!/system/bin/sh
rm -f '$remoteResult' '$remoteExit'
(sh '$remoteScript' > '$remoteResult' 2>&1; echo `$? > '$remoteExit') < /dev/null >/dev/null 2>&1 &
"@
    Write-AndroidShellScript -Path $localRunner -Content $runnerScript
    Invoke-AdbText push $localScript $remoteScript | Out-Null
    Invoke-AdbText push $localRunner $remoteRunner | Out-Null
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $previousNativeErrorPreference = $PSNativeCommandUseErrorActionPreference
    try {
        $PSNativeCommandUseErrorActionPreference = $false
        & adb shell sh $remoteRunner 2>&1 | Out-Null
    } finally {
        $PSNativeCommandUseErrorActionPreference = $previousNativeErrorPreference
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($MaxTimeSeconds + 45)
    $exitCodeText = ""
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds 1
        $previousNativeErrorPreference = $PSNativeCommandUseErrorActionPreference
        try {
            $PSNativeCommandUseErrorActionPreference = $false
            $exitProbe = & adb shell cat $remoteExit 2>$null
            if ($LASTEXITCODE -eq 0) {
                $exitCodeText = (($exitProbe -join "`n") -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1)
                if (-not [string]::IsNullOrWhiteSpace($exitCodeText)) {
                    break
                }
            }
        } finally {
            $PSNativeCommandUseErrorActionPreference = $previousNativeErrorPreference
        }
    }
    if ([string]::IsNullOrWhiteSpace($exitCodeText)) {
        & adb shell sh -c "pkill curl 2>/dev/null || true; rm -f $remoteScript $remoteRunner $remoteResult $remoteExit" 2>$null | Out-Null
        throw "Phone benchmark timed out waiting for detached workload after $($MaxTimeSeconds + 45) seconds."
    }
    $raw = Invoke-AdbText shell cat $remoteResult
    $timer.Stop()
    Remove-Item -Force -ErrorAction SilentlyContinue $localScript
    Remove-Item -Force -ErrorAction SilentlyContinue $localRunner
    & adb shell rm -f $remoteScript $remoteRunner $remoteResult $remoteExit 2>$null | Out-Null
    $lines = @($raw -split "`n" | Where-Object { $_.Trim() })
    $line = $lines[-1].Trim()
    if ($line -notmatch "rc=(\d+)\s+bytes=(\d+)(?:\s+workers=(\d+))?") {
        throw "Unexpected phone benchmark output: $raw"
    }
    $rc = [int]$Matches[1]
    $bytes = [double]$Matches[2]
    $workers = if ($Matches.Count -gt 3 -and $Matches[3]) { [int]$Matches[3] } else { $ParallelConnections }
    $seconds = [Math]::Max(0.001, $timer.Elapsed.TotalSeconds)
    if ($bytes -le 0) {
        throw "Phone download failed: $raw"
    }
    if ($rc -ne 0) {
        Write-Warning "Phone download had a non-zero curl exit after receiving bytes; keeping sample: $raw"
    }
    return [pscustomobject]@{
        http_code = 200
        bytes = [Math]::Round($bytes, 0)
        bytes_per_second = [Math]::Round($bytes / $seconds, 3)
        mbps = [Math]::Round((($bytes * 8.0) / $seconds) / 1000000.0, 3)
        time_seconds = [Math]::Round($seconds, 3)
        workers = $workers
        remote_ip = ""
    }
}

Write-Host "[BOOST-BENCH] Connected devices"
Invoke-AdbText devices | Write-Host

Write-Host "[BOOST-BENCH] Keeping phone awake while plugged in"
& adb shell settings put global stay_on_while_plugged_in 3 | Out-Null
& adb shell input keyevent WAKEUP | Out-Null

Assert-PhoneCurl
$urls = Resolve-BenchmarkUrls -Target $Target -Url $Url
$urls = Select-WorkingBenchmarkUrls -Urls $urls
if ($urls.Count -eq 0) {
    throw "No working benchmark URLs are available for $Target from the connected phone. Try SonicLA, Cachefly, or pass -Target Custom -Url with a verified endpoint."
}
Write-Host "[BOOST-BENCH] Target=$Target URLs=$($urls.Count) parallel=$ParallelConnections repeats=$RepeatsPerConnection bytesPerRequest=$BytesPerRequest"

$samples = @()
for ($i = 1; $i -le $Runs; $i++) {
    Write-Host "[BOOST-BENCH] $Mode run $i/$Runs"
    $sample = Invoke-PhoneDownloadSample -Urls $urls -ParallelConnections $ParallelConnections -RepeatsPerConnection $RepeatsPerConnection -MaxTimeSeconds $MaxTimeSeconds -BytesPerRequest $BytesPerRequest
    $samples += [pscustomobject]@{
        run = $i
        http_code = $sample.http_code
        bytes = $sample.bytes
        bytes_per_second = $sample.bytes_per_second
        mbps = $sample.mbps
        time_seconds = $sample.time_seconds
        workers = $sample.workers
        remote_ip = $sample.remote_ip
    }
    Start-Sleep -Seconds 2
}

$good = @($samples | Where-Object { $_.http_code -ge 200 -and $_.http_code -lt 400 -and $_.mbps -gt 0 })
if ($good.Count -eq 0) {
    throw "No successful benchmark samples were captured for $Mode"
}

$sorted = @($good | Sort-Object mbps)
$median = $sorted[[int][Math]::Floor(($sorted.Count - 1) / 2)].mbps
$average = [Math]::Round((($good | Measure-Object -Property mbps -Average).Average), 3)
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$result = [pscustomobject]@{
    timestamp = (Get-Date).ToString("o")
    mode = $Mode
    target = $Target
    urls = $urls
    parallel_connections = $ParallelConnections
    repeats_per_connection = $RepeatsPerConnection
    bytes_per_request = $BytesPerRequest
    runs = $Runs
    median_mbps = $median
    average_mbps = $average
    samples = $samples
}

$path = Join-Path $OutputDir "$stamp-$($Mode.ToLowerInvariant()).json"
$result | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -Path $path
Write-Host "[BOOST-BENCH] $Mode median=$median Mbps average=$average Mbps"
Write-Host "[BOOST-BENCH] Result: $path"
