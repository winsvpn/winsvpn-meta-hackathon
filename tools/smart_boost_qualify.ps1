param(
    [Parameter(Mandatory = $true)]
    [string]$AwgJson,
    [Parameter(Mandatory = $true)]
    [string]$SmartBoostJson,
    [double]$MinRatio = 1.15,
    [double]$MinAbsoluteGainMbps = 25.0
)

$ErrorActionPreference = "Stop"

function Read-Benchmark {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Benchmark file not found: $Path"
    }
    return Get-Content -Raw -Path $Path | ConvertFrom-Json
}

$awg = Read-Benchmark $AwgJson
$boost = Read-Benchmark $SmartBoostJson

if ($awg.median_mbps -le 0 -or $boost.median_mbps -le 0) {
    throw "Both benchmarks must have positive median Mbps values."
}

$ratio = [Math]::Round([double]$boost.median_mbps / [double]$awg.median_mbps, 3)
$gain = [Math]::Round([double]$boost.median_mbps - [double]$awg.median_mbps, 3)
$qualified = $ratio -ge $MinRatio -and $gain -ge $MinAbsoluteGainMbps

$summary = [pscustomobject]@{
    timestamp = (Get-Date).ToString("o")
    awg_median_mbps = [double]$awg.median_mbps
    smart_boost_median_mbps = [double]$boost.median_mbps
    ratio = $ratio
    gain_mbps = $gain
    min_ratio = $MinRatio
    min_absolute_gain_mbps = $MinAbsoluteGainMbps
    qualified = $qualified
}

$summary | ConvertTo-Json -Depth 4
if (-not $qualified) {
    throw "Smart Boost is not qualified yet. It must beat AWG by at least ${MinRatio}x and ${MinAbsoluteGainMbps} Mbps."
}
