param(
    # The extracted ARM64 payload directory to verify. Required: the previous
    # hardcoded path carried a personal user profile, which must not live in
    # the repository.
    [Parameter(Mandatory = $true)][string]$PayloadDir
)
$ErrorActionPreference = 'Stop'
$Marker = 'winsvpn.local/winnprotocol/winn3'
$ExpectedWintunSha256 = 'f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80'
function Get-PeMachine([string]$Path) {
    $fs = [IO.File]::OpenRead($Path)
    try {
        if ($fs.Length -lt 64) { return 'NOT_PE' }
        $br = New-Object IO.BinaryReader($fs)
        $mz = $br.ReadUInt16()
        $fs.Position = 0x3C
        $offset = $br.ReadUInt32()
        if ($offset -gt ($fs.Length - 6)) { return 'NOT_PE' }
        $fs.Position = $offset
        $sig = $br.ReadUInt32()
        $mach = $br.ReadUInt16()
        if ($mz -ne 0x5A4D -or $sig -ne 0x00004550) { return 'NOT_PE' }
        return ('0x{0:X4}' -f $mach)
    } finally { $fs.Dispose() }
}
function Get-Sha256([string]$Path) {
    (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}
$payloadDir = $PayloadDir
$problems = @()
foreach ($n in 'winn-datapath.exe','winsvpn_winn3_engine.exe','wintun.dll') {
    $p = Join-Path $payloadDir $n
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
        $problems += "$n is missing from the ARM64 payload"
        continue
    }
    $bytes = [IO.File]::ReadAllBytes($p)
    $txt = [Text.Encoding]::ASCII.GetString($bytes)
    $hasMarker = $txt.IndexOf($Marker, [StringComparison]::Ordinal) -ge 0
    $coff = Get-PeMachine $p
    '{0} : COFF={1}  v3marker={2}  bytes={3}' -f $n,$coff,$hasMarker,$bytes.Length
    if ($coff -cne '0xAA64') {
        $problems += "$n is not PE32+ AArch64 (COFF $coff)"
    }
    if ($n -ceq 'winn-datapath.exe' -and -not $hasMarker) {
        $problems += "$n is missing the required Winn Protocol v3 marker"
    }
    if ($n -cne 'winn-datapath.exe' -and $hasMarker) {
        $problems += "$n unexpectedly contains the Winn v3 marker; only winn-datapath.exe is the carrier"
    }
    if ($n -ceq 'wintun.dll') {
        if ($hasMarker) {
            $problems += 'wintun.dll unexpectedly contains the Winn v3 marker; Wintun is not a v3 carrier'
        }
        $actual = Get-Sha256 $p
        if ($actual -cne $ExpectedWintunSha256) {
            $problems += "wintun.dll SHA-256 $actual does not match reviewed ARM64 pin $ExpectedWintunSha256"
        }
    }
}
$manifest = Join-Path $payloadDir 'payload-manifest.json'
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
    $problems += 'payload-manifest.json is missing from the extracted ARM64 payload'
} else {
    '--- payload-manifest.json ---'
    Get-Content -LiteralPath $manifest
    try {
        $document = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
        if ($document.architecture -cne 'arm64') {
            $problems += "payload manifest architecture '$($document.architecture)' is not arm64"
        }
        $manifestFiles = @($document.files)
        $expectedNames = @('winn-datapath.exe','winsvpn_winn3_engine.exe','wintun.dll')
        $actualNames = @($manifestFiles | ForEach-Object { [string]$_.name } | Sort-Object)
        if (($actualNames -join "`n") -cne (($expectedNames | Sort-Object) -join "`n")) {
            $problems += "payload manifest inventory is not exact: $($actualNames -join ', ')"
        }
        foreach ($entry in $manifestFiles) {
            $entryName = [string]$entry.name
            if ($expectedNames -notcontains $entryName) { continue }
            $entryPath = Join-Path $payloadDir $entryName
            if (-not (Test-Path -LiteralPath $entryPath -PathType Leaf)) { continue }
            $actualBytes = [long](Get-Item -LiteralPath $entryPath).Length
            $actualSha256 = Get-Sha256 $entryPath
            if ([long]$entry.bytes -ne $actualBytes) {
                $problems += "$entryName byte length does not match payload manifest"
            }
            if ([string]$entry.sha256 -cne $actualSha256) {
                $problems += "$entryName SHA-256 does not match payload manifest"
            }
        }
    } catch {
        $problems += "payload-manifest.json is not valid or complete JSON: $($_.Exception.Message)"
    }
}
if ($problems.Count -gt 0) {
    throw ("ARM64 Winn v3 MSI payload verification failed:`n - " + ($problems -join "`n - "))
}
