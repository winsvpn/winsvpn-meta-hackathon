#Requires -Version 5.1
<#
install_winsvpn_zip.ps1 — the privileged side of the zip + PowerShell install
route. Run it AFTER expanding the distribution zip, from ANY directory, with
elevation:

This privileged route is disabled. An unsigned ZIP cannot authenticate this
script before PowerShell executes it. The commands below describe the old
route only; -VerifyManifestOnly remains for trusted local fixtures and does
not authenticate a downloaded ZIP.

    powershell -ExecutionPolicy Bypass -File install_winsvpn_zip.ps1

or, to check the contents of a package WITHOUT changing the machine (archived
by this lane as its verification mode):

    powershell -ExecutionPolicy Bypass -File install_winsvpn_zip.ps1 -VerifyManifestOnly

WHAT THIS IS: a faithful, step-for-step PowerShell port of the fail-closed
machinery in winsvpn.iss's [Code] section, so the product keeps every guard it
built into the Inno route even though Inno Setup is not on the build host.
Each numbered step maps to the Inno function that defines it:

  1. elevation + host architecture match     [Setup] PrivilegesRequired=admin,
                                             ArchitecturesAllowed/InstallIn64BitMode matches the payload
  2. exact SHA-256 gate on EVERY staged file GetSHA256OfFile stage (anti-tamper;
     payload-manifest.json is the pin set)
  3. refuse while the packet engine is up   WinsVpnPacketEngineIsRunning (WMI, fails closed)
  4. VC++ runtime install if required       VcRuntimeInstalledAtLeastRequired +
                                             PrepareToInstall VC_redist step
  5. AmneziaWG MSI install + verify         PrepareToInstall AmneziaWG step +
                                             AmneziaWgRuntimeInstalled
  6. tunnel-manager self test               ValidateStagedTunnelManager
                                             (--protocol-self-test)
  7. upgrade-safe service swap              RemovePreviousTunnelManagerForUpgrade /
                                             RestorePreviousTunnelManager (exact-hash backup)
  8. payload copy with post-install verify CurStepChanged ssPostInstall hash checks
  9. licence verification                   VerifyInstalledLicences (pinned texts)
 10. service registration + rollback        CurStepChanged ssPostInstall --install step

It never modifies the machine in -VerifyManifestOnly mode, and all failures
exit 1603 (the same FatalPostInstallExitCode automation reads from Inno), or
abort before the first privileged call when a gate trips.

Authenticode signing of the first-party engines and product happens in
build_zip_installer.ps1 when a signing identity is configured; this script
does not sign. The zip archive itself is never signed: payload-manifest.json
binds every byte, and the zip's .sha256 binds the manifest out-of-band.
#>
[CmdletBinding()]
param(
    # $PSScriptRoot is EMPTY while a param() default is being bound under
    # PowerShell 5.1, so it cannot be the default here: a user running the
    # documented `powershell -File install_winsvpn_zip.ps1` (no -StageDir,
    # from an extracted package) would get $StageDir="" and the very first
    # Join-Path would throw. Resolve $PSScriptRoot in the body instead.
    [string]$StageDir = '',
    [switch]$VerifyManifestOnly,
    [string]$VerificationInstallRoot = '',
    [switch]$NoLaunch
)

$ErrorActionPreference = 'Stop'
if (-not $VerifyManifestOnly) {
    throw 'Privileged installation from an unsigned ZIP is disabled. Use the Authenticode-signed Inno installer.'
}
if ([string]::IsNullOrWhiteSpace($StageDir)) { $StageDir = $PSScriptRoot }
$ExitFatal = 1603
$Marker = 'winsvpn.local/winnprotocol/winn3'
$runningOnWindows = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)
if ($VerifyManifestOnly -and -not [string]::IsNullOrWhiteSpace($VerificationInstallRoot)) {
    $InstallDir = [IO.Path]::GetFullPath($VerificationInstallRoot)
} elseif (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
    $InstallDir = Join-Path $env:ProgramFiles 'WinsVPN'
} elseif ($VerifyManifestOnly) {
    $InstallDir = Join-Path ([IO.Path]::GetTempPath()) 'WinsVPN-VerifyManifestOnly'
} else {
    $InstallDir = ''
}
$ManifestName = 'payload-manifest.json'
$ServiceExeName = 'wins_vpn_tunnel_service.exe'
$VcRequired = @{ Major = 14; Minor = 44; Build = 35211; Revision = 0 }
$ZipX86PeMachine = [uint16]0x014c
$ZipX64PeMachine = [uint16]0x8664
$ZipArm64PeMachine = [uint16]0xAA64
$ZipPeMachine = $ZipX64PeMachine
$script:ZipArchitecture = 'x64'
$script:ZipVcRedistLeaf = 'VC_redist.x64.exe'
$script:ZipMsiLeaf = 'amneziawg-amd64.msi'
$ExpectedDependencyPins = [ordered]@{
    'dependencies/VC_redist.x64.exe' = [ordered]@{ sha256 = 'cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b'; dest = 'temp' }
    'dependencies/amneziawg-amd64.msi' = [ordered]@{ sha256 = 'a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b'; dest = 'temp' }
    'dependencies/amneziawg.exe' = [ordered]@{ sha256 = '12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41'; dest = 'app' }
    'dependencies/awg.exe' = [ordered]@{ sha256 = '272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12'; dest = 'app' }
    'dependencies/wintun.dll' = [ordered]@{ sha256 = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'; dest = 'app' }
    'dependencies/xray.exe' = [ordered]@{ sha256 = 'fffbe5dd92fe13cfc6ab72dead66ddd92c09b2bb27a85592e8e6f4ec27ee1224'; dest = 'app' }
}
$ExpectedDependencyContract = [ordered]@{
    amneziawg_client_version = '3.1.0'
    amneziawg_msi_sha256 = 'a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b'
    amneziawg_msi_runtime_amneziawg_sha256 = 'ba446f6e1a4093e43a65d6ff45f4b8c7b6485dc419327eedaa1a218549740e3a'
    amneziawg_maintenance_helper_sha256 = '12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41'
    amneziawg_source_commit = 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968'
    amneziawg_engine_version = 'v3.1.20260828'
    amneziawg_engine_commit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'
    awg_exe_sha256 = '272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12'
    wintun_version = '0.14.1'
    wintun_dll_sha256 = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
    xray_version = 'v26.9.30'
    xray_source_commit = 'b26a91de4f3294e26a0ad0a970b81a386a41f789'
    xray_exe_sha256 = 'fffbe5dd92fe13cfc6ab72dead66ddd92c09b2bb27a85592e8e6f4ec27ee1224'
    xray_go_version = '1.27.1'
    vc_redist_version = '14.44.35211.0'
    vc_redist_sha256 = 'cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b'
}
$ForbiddenZipPayloadLeafNames = @(
    'mullvad-split-tunnel.sys',
    'mullvad-split-tunnel.cat',
    'mullvad-split-tunnel.inf',
    'mullvad-split-tunnel-MPL-2.0.txt'
)
$ForbiddenZipPayloadLeafPrefixes = @('mullvad-split-tunnel')
$ForbiddenZipPayloadExtensions = @('.sys', '.cat', '.inf')
$ForbiddenZipPayloadPaths = @('licenses/README.txt')
$ForbiddenZipPayloadSha256 = @(
    '10cf25bbcfe51fd663a1fec88a98e9b858f3a579589bb2ec496b66e4fdd1b201',
    'c599926a0327d7ae06b534f4cd039db30392e1897bb9d03e4fec3631744a4e6d',
    '3dd5905e5fb98d61a942a33e8c9a5ba07c3a2de1e4f319e1fec3e54df6591608',
    '6af8b3bfe5aa095d5276187558c7c7d3a3e0c174b34406cd6c4b3f8e6ffa6534',
    'c3d27636739ebaa7dde369d113347de83e3e2173b8a512bb8863d11b148de7ce',
    '0bfdb044e40535dabbeb3620b655c1563714b3a6f3231d3492c972c6e8dea6f1',
    'faeba3cc7a3fb890ec25497b192d860683915e46061bf6588268fd2ddcdc6342',
    '56ab6a25ca2f4dcd0303567815a64f6d09835e2cceb3958020185772c4871c1e'
)
$ForbiddenZipPayloadFingerprints = @(
    @{
        sha256 = '10cf25bbcfe51fd663a1fec88a98e9b858f3a579589bb2ec496b66e4fdd1b201'
        length = 98400
        offset = 102
        marker = '756e20696e20444f53206d6f64652e0d0d0a2400000000000000504500006486'
    }
    @{
        sha256 = 'c599926a0327d7ae06b534f4cd039db30392e1897bb9d03e4fec3631744a4e6d'
        length = 12350
        offset = 64
        marker = '07d2300c060a2b0601040182370c01010410d41414c82cf2934592eb09d9eb5e'
    }
    @{
        sha256 = '3dd5905e5fb98d61a942a33e8c9a5ba07c3a2de1e4f319e1fec3e54df6591608'
        length = 1796
        offset = 690
        marker = '0a254d616e7566616374757265724e616d65253d5374616e646172642c4e5461'
    }
    @{
        sha256 = '6af8b3bfe5aa095d5276187558c7c7d3a3e0c174b34406cd6c4b3f8e6ffa6534'
        length = 101984
        offset = 102
        marker = '756e20696e20444f53206d6f64652e0d0d0a24000000000000005045000064aa'
    }
    @{
        sha256 = 'c3d27636739ebaa7dde369d113347de83e3e2173b8a512bb8863d11b148de7ce'
        length = 12158
        offset = 64
        marker = '0716300c060a2b0601040182370c010104107031a5612275734e8f257e09ec3d'
    }
    @{
        sha256 = '0bfdb044e40535dabbeb3620b655c1563714b3a6f3231d3492c972c6e8dea6f1'
        length = 1796
        offset = 690
        marker = '0a254d616e7566616374757265724e616d65253d5374616e646172642c4e5441'
    }
)
$ExpectedArm64DependencyPins = [ordered]@{
    'dependencies/VC_redist.arm64.exe' = [ordered]@{ sha256 = '5139e1440c3a20b92153a4db561c069a0175aaf76c276c3e5b6f56099edcf4b0'; dest = 'temp' }
    'dependencies/amneziawg-arm64.msi' = [ordered]@{ sha256 = '3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa'; dest = 'temp' }
    'dependencies/awg.exe' = [ordered]@{ sha256 = '3106950ce9f0b93eb4c3f7975cbf44af41623ffeed630f19909730cd16d36e43'; dest = 'app' }
    'dependencies/wintun.dll' = [ordered]@{ sha256 = 'f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80'; dest = 'app' }
    'dependencies/xray.exe' = [ordered]@{ sha256 = 'c6edaa0e535b81d8c4c4a25378e6717b4406a8a0d72b751f4d0a1f171817e7af'; dest = 'app' }
}
$ExpectedArm64DependencyContract = [ordered]@{
    amneziawg_client_version = '3.1.0'
    amneziawg_msi_sha256 = '3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa'
    amneziawg_msi_runtime_amneziawg_sha256 = '25fa81103152699bf416f394059b40d447001c3d0dea5ef889a9426f315e4c0a'
    amneziawg_source_commit = 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968'
    amneziawg_engine_version = 'v3.1.20260828'
    amneziawg_engine_commit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'
    awg_exe_sha256 = '3106950ce9f0b93eb4c3f7975cbf44af41623ffeed630f19909730cd16d36e43'
    wintun_version = '0.14.1'
    wintun_dll_sha256 = 'f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80'
    xray_version = 'v26.9.30'
    xray_source_commit = 'b26a91de4f3294e26a0ad0a970b81a386a41f789'
    xray_exe_sha256 = 'c6edaa0e535b81d8c4c4a25378e6717b4406a8a0d72b751f4d0a1f171817e7af'
    xray_go_version = '1.27.1'
    vc_redist_version = '14.44.35211.0'
    vc_redist_sha256 = '5139e1440c3a20b92153a4db561c069a0175aaf76c276c3e5b6f56099edcf4b0'
}
$RequiredPayloadPaths = @(
    'wins_vpn.exe',
    'wins_vpn_tunnel_service.exe',
    'winsvpn_awg_engine.exe',
    'winn-datapath.exe',
    'winsvpn_winn3_engine.exe',
    'install_winsvpn_zip.ps1',
    'remove_winsvpn_zip.ps1',
    'licenses/Wintun-Prebuilt-Binaries-License.txt',
    'licenses/Xray-core-MPL-2.0.txt',
    'licenses/amneziawg-MIT.txt',
    'licenses/amneziawg-tools-GPL-2.0.txt',
    'licenses/THIRD_PARTY_NOTICES.md'
) + @($ExpectedDependencyPins.Keys)

function Initialize-ZipInstallArchitecture {
    param([Parameter(Mandatory = $true)][ValidateSet('x64', 'arm64')][string]$Architecture)
    $script:ZipArchitecture = $Architecture
    if ($Architecture -ceq 'arm64') {
        $script:ZipPeMachine = $ZipArm64PeMachine
        $script:ExpectedDependencyPins = $ExpectedArm64DependencyPins
        $script:ExpectedDependencyContract = $ExpectedArm64DependencyContract
        $script:ZipVcRedistLeaf = 'VC_redist.arm64.exe'
        $script:ZipMsiLeaf = 'amneziawg-arm64.msi'
    } else {
        $script:ZipPeMachine = $ZipX64PeMachine
        $script:ZipVcRedistLeaf = 'VC_redist.x64.exe'
        $script:ZipMsiLeaf = 'amneziawg-amd64.msi'
    }
    $script:RequiredPayloadPaths = @(
        'wins_vpn.exe',
        'wins_vpn_tunnel_service.exe',
        'winsvpn_awg_engine.exe',
        'winn-datapath.exe',
        'winsvpn_winn3_engine.exe',
        'install_winsvpn_zip.ps1',
        'remove_winsvpn_zip.ps1',
        'licenses/Wintun-Prebuilt-Binaries-License.txt',
        'licenses/Xray-core-MPL-2.0.txt',
        'licenses/amneziawg-MIT.txt',
        'licenses/amneziawg-tools-GPL-2.0.txt',
        'licenses/THIRD_PARTY_NOTICES.md'
    ) + @($ExpectedDependencyPins.Keys)
}

function Out-Step { param([string]$Message) Write-Host "[install_winsvpn_zip] $Message" }

function Fail-Fatal {
    param([string]$Message)
    Write-Host "[install_winsvpn_zip] FATAL: $Message" -ForegroundColor Red
    exit $ExitFatal
}

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail-Fatal "Elevation required. Rerun this script from an elevated (Administrator) PowerShell console. Script path: $PSCommandPath"
    }
}

function Test-PacketEngineRunning {
    # Inno fails CLOSED: a WMI query error is treated as 'engine running',
    # because refusing to proceed is safer than upgrading under an active tunnel.
    try {
        $locator = New-Object -ComObject WbemScripting.SWbemLocator
        $svc = $locator.ConnectServer('.', 'root\cimv2')
        $procs = $svc.ExecQuery("SELECT ProcessId FROM Win32_Process WHERE Name = 'winsvpn_awg_engine.exe'")
        return ($procs.Count -gt 0)
    } catch {
        return $true
    }
}

function Sha256-Of {
    param([string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-PeCoffMachine {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    try {
        if ($stream.Length -lt 64) { return [uint16]0 }
        $reader = New-Object IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { return [uint16]0 }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -gt ($stream.Length - 26)) { return [uint16]0 }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { return [uint16]0 }
        $machine = $reader.ReadUInt16()
        $sectionCount = $reader.ReadUInt16()
        $stream.Position = $peOffset + 20
        $optionalHeaderSize = $reader.ReadUInt16()
        if ($sectionCount -eq 0 -or $optionalHeaderSize -lt 2 -or
            ($peOffset + 24 + $optionalHeaderSize) -gt $stream.Length) { return [uint16]0 }
        $stream.Position = $peOffset + 24
        $optionalMagic = $reader.ReadUInt16()
        $pe32Plus = [uint16]0x020b
        $pe32 = [uint16]0x010b
        if (($machine -eq $ZipX64PeMachine -and $optionalMagic -ne $pe32Plus) -or
            ($machine -eq $ZipArm64PeMachine -and $optionalMagic -ne $pe32Plus) -or
            ($machine -eq $ZipX86PeMachine -and $optionalMagic -ne $pe32)) { return [uint16]0 }
        return $machine
    } finally {
        $stream.Dispose()
    }
}

function ConvertTo-CanonicalPayloadPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -cne $Path.Trim()) {
        throw 'Payload paths must be non-empty and have no surrounding whitespace.'
    }
    if ($Path -cne $Path.Normalize([Text.NormalizationForm]::FormC)) {
        throw "Payload path is not Unicode NFC-normalized: $Path"
    }
    if ($Path.Contains('\') -or $Path -match '^[A-Za-z]:' -or
        $Path.StartsWith('/') -or $Path.Contains(':')) {
        throw "Payload path must be relative and use forward slashes only: $Path"
    }
    $segments = @($Path -split '/')
    if ($segments.Count -eq 0) { throw "Payload path has no segments: $Path" }
    foreach ($segment in $segments) {
        if ([string]::IsNullOrWhiteSpace($segment) -or $segment -in @('.', '..')) {
            throw "Payload path contains an empty or dot segment: $Path"
        }
        if ($segment.EndsWith(' ') -or $segment.EndsWith('.') -or
            $segment.IndexOfAny([char[]]'<>"|?*:') -ge 0) {
            throw "Payload path contains a Windows-ambiguous segment: $Path"
        }
        foreach ($character in $segment.ToCharArray()) {
            if ([int]$character -lt 32) { throw "Payload path contains a control character: $Path" }
        }
        if ($segment -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') {
            throw "Payload path uses a reserved Windows device name: $Path"
        }
    }
    return ($segments -join '/')
}

function Assert-CanonicalReservedPayloadPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $canonical = ConvertTo-CanonicalPayloadPath -Path $Path
    $firstSegment = @($canonical -split '/')[0]
    foreach ($reserved in @('dependencies', 'licenses')) {
        if ($firstSegment.Equals($reserved, [StringComparison]::OrdinalIgnoreCase) -and
            -not $firstSegment.Equals($reserved, [StringComparison]::Ordinal)) {
            throw "Reserved payload prefix '$reserved' must use canonical lowercase spelling: $canonical"
        }
    }
    return $canonical
}

function Assert-ZipPayloadAllowed {
    param([Parameter(Mandatory = $true)][string]$Path)
    $canonical = Assert-CanonicalReservedPayloadPath -Path $Path
    $lastSlash = $canonical.LastIndexOf('/')
    $leaf = if ($lastSlash -ge 0) { $canonical.Substring($lastSlash + 1) } else { $canonical }
    foreach ($forbiddenPrefix in $ForbiddenZipPayloadLeafPrefixes) {
        if ($leaf.StartsWith($forbiddenPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Windows ZIP payload forbids the withdrawn kernel split-tunnel artifact: $canonical"
        }
    }
    foreach ($forbiddenLeaf in $ForbiddenZipPayloadLeafNames) {
        if ($leaf.Equals($forbiddenLeaf, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Windows ZIP payload forbids the withdrawn kernel split-tunnel artifact: $canonical"
        }
    }
    $extension = [IO.Path]::GetExtension($leaf).ToLowerInvariant()
    if ($extension -in $ForbiddenZipPayloadExtensions) {
        throw "Windows ZIP payload forbids kernel driver package files: $canonical"
    }
    foreach ($forbiddenPath in $ForbiddenZipPayloadPaths) {
        if ($canonical.Equals($forbiddenPath, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Windows ZIP payload forbids the obsolete kernel split-tunnel notice: $canonical"
        }
    }
    return $canonical
}

function Assert-ZipPayloadHashAllowed {
    param(
        [Parameter(Mandatory = $true)][string]$Sha256,
        [Parameter(Mandatory = $true)][string]$Path
    )
    foreach ($forbiddenHash in $ForbiddenZipPayloadSha256) {
        if ($Sha256.Equals($forbiddenHash, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Windows ZIP payload forbids withdrawn kernel split-tunnel bytes, including when renamed: $Path"
        }
    }
}

function Assert-ZipPayloadBytesAllowed {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Path
    )
    if ($null -eq $Bytes) { $Bytes = [byte[]]::new(0) }
    if (-not ('WinsZipForbiddenPayloadScan' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Security.Cryptography;
using System.Text;
public static class WinsZipForbiddenPayloadScan {
    public static string Sha256Hex(byte[] data) {
        using (var sha = SHA256.Create()) {
            return Hex(sha.ComputeHash(data ?? Array.Empty<byte>()));
        }
    }
    public static bool Contains(byte[] haystack, string markerHex, int markerOffset, int payloadLength, string sha256Hex) {
        if (haystack == null || payloadLength <= 0 || haystack.Length < payloadLength) return false;
        byte[] marker = HexToBytes(markerHex);
        if (marker.Length == 0 || haystack.Length < marker.Length) return false;
        int start = 0;
        while (true) {
            int idx = IndexOf(haystack, marker, start);
            if (idx < 0) return false;
            int payloadStart = idx - markerOffset;
            if (payloadStart >= 0 && payloadStart <= haystack.Length - payloadLength) {
                using (var sha = SHA256.Create()) {
                    if (Hex(sha.ComputeHash(haystack, payloadStart, payloadLength)).Equals(sha256Hex, StringComparison.OrdinalIgnoreCase)) {
                        return true;
                    }
                }
            }
            start = idx + 1;
        }
    }
    static int IndexOf(byte[] haystack, byte[] needle, int start) {
        if (start < 0) start = 0;
        int last = haystack.Length - needle.Length;
        for (int i = start; i <= last; i++) {
            int j = 0;
            for (; j < needle.Length; j++) {
                if (haystack[i + j] != needle[j]) break;
            }
            if (j == needle.Length) return i;
        }
        return -1;
    }
    static byte[] HexToBytes(string hex) {
        if (string.IsNullOrEmpty(hex) || (hex.Length & 1) != 0) throw new ArgumentException("hex");
        byte[] data = new byte[hex.Length / 2];
        for (int i = 0; i < data.Length; i++) data[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return data;
    }
    static string Hex(byte[] hash) {
        var sb = new StringBuilder(hash.Length * 2);
        for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
        return sb.ToString();
    }
}
'@
    }
    $sha256 = [WinsZipForbiddenPayloadScan]::Sha256Hex($Bytes)
    Assert-ZipPayloadHashAllowed -Sha256 $sha256 -Path $Path
    foreach ($fingerprint in $ForbiddenZipPayloadFingerprints) {
        if ([WinsZipForbiddenPayloadScan]::Contains(
                $Bytes,
                [string]$fingerprint.marker,
                [int]$fingerprint.offset,
                [int]$fingerprint.length,
                [string]$fingerprint.sha256
            )) {
            throw "Windows ZIP payload forbids withdrawn kernel split-tunnel bytes, including when renamed: $Path"
        }
    }
}

function Get-ValidatedContainerRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    if ([string]::IsNullOrWhiteSpace($Root)) { throw "$Purpose root is empty." }
    $rootFull = [IO.Path]::GetFullPath($Root)
    $pathRoot = [IO.Path]::GetPathRoot($rootFull)
    $rootTrimmed = $rootFull.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $pathRootTrimmed = $pathRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    if ([string]::IsNullOrEmpty($rootTrimmed) -or
        [string]::Equals($rootTrimmed, $pathRootTrimmed, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing a filesystem-root container for ${Purpose}: $rootFull"
    }
    return $rootTrimmed
}

function Get-ContainedPath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    $canonical = ConvertTo-CanonicalPayloadPath -Path $RelativePath
    $rootFull = Get-ValidatedContainerRoot -Root $Root -Purpose $Purpose
    $nativeRelative = $canonical.Replace('/', [IO.Path]::DirectorySeparatorChar)
    $full = [IO.Path]::GetFullPath((Join-Path $rootFull $nativeRelative))
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Purpose escapes its approved root: $RelativePath"
    }
    Assert-NoReparsePointChain -Root $rootFull -FullPath $full -Purpose $Purpose
    return $full
}

function Assert-NoReparsePointChain {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$FullPath,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    $rootFull = Get-ValidatedContainerRoot -Root $Root -Purpose $Purpose
    $targetFull = [IO.Path]::GetFullPath($FullPath)
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    if (-not $targetFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Purpose is outside its approved root."
    }
    if (Test-Path -LiteralPath $rootFull) {
        $rootItem = Get-Item -LiteralPath $rootFull -Force
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Purpose root is a reparse point: $rootFull"
        }
    }
    $current = $rootFull
    $parts = @($targetFull.Substring($prefix.Length) -split '[\\/]')
    foreach ($part in $parts) {
        if ([string]::IsNullOrEmpty($part)) { continue }
        $current = Join-Path $current $part
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Purpose crosses a reparse point: $current"
            }
        }
    }
}

function Get-ContainedFileItems {
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$Purpose)
    $rootFull = Get-ValidatedContainerRoot -Root $Root -Purpose $Purpose
    if (-not (Test-Path -LiteralPath $rootFull -PathType Container)) { throw "$Purpose root is missing: $rootFull" }
    $rootItem = Get-Item -LiteralPath $rootFull -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Purpose root is a reparse point: $rootFull"
    }
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($rootFull)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            $full = [IO.Path]::GetFullPath($item.FullName)
            if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "$Purpose item escaped its root: $full"
            }
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Purpose contains a reparse point: $full"
            }
            if ($item.PSIsContainer) { $pending.Push($full) } else { $item }
        }
    }
}

function Assert-ExactPropertySet {
    param([object]$Object, [string[]]$Expected, [string]$Purpose)
    if ($null -eq $Object) { throw "$Purpose is missing." }
    $actual = @($Object.PSObject.Properties | ForEach-Object { $_.Name })
    $missing = @($Expected | Where-Object { $actual -cnotcontains $_ })
    $extra = @($actual | Where-Object { $Expected -cnotcontains $_ })
    if ($missing.Count -gt 0 -or $extra.Count -gt 0) {
        throw "$Purpose has an invalid property set. Missing=[$($missing -join ', ')]; extra=[$($extra -join ', ')]."
    }
}

function Get-InstallRelativePath {
    param([object]$Entry)
    $path = Assert-ZipPayloadAllowed -Path ([string]$Entry.path)
    if ([string]$Entry.dest -ceq 'app-license') {
        if (-not $path.StartsWith('licenses/', [StringComparison]::OrdinalIgnoreCase)) {
            throw "app-license payload is outside licenses/: $path"
        }
        return $path
    }
    if ([string]$Entry.dest -cne 'app') { return $null }
    if ($path.StartsWith('dependencies/', [StringComparison]::OrdinalIgnoreCase)) {
        if (-not $ExpectedDependencyPins.Contains($path) -or [string]$ExpectedDependencyPins[$path].dest -cne 'app') {
            throw "Dependency is not approved for installation: $path"
        }
        return $path.Substring('dependencies/'.Length)
    }
    return $path
}

function Get-InstallDestinationPath {
    param([object]$Entry)
    $relative = Get-InstallRelativePath -Entry $Entry
    if ($null -eq $relative) { return $null }
    return Get-ContainedPath -Root $InstallDir -RelativePath $relative -Purpose 'Install destination'
}

function Test-FileContainsMarker {
    # Raw-byte substring scan (the installer gate's copy, so the INSTALLED
    # datapath is verified by the same rule the build gate used).
    param([string]$Path, [string]$Needle)
    try {
        $text = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($Path))
        return $text.IndexOf($Needle, [StringComparison]::Ordinal) -ge 0
    } catch {
        return $false
    }
}

function Test-PayloadManifest {
    # THE anti-tamper gate. Reads payload-manifest.json beside the package and
    # verifies every entry (path, byte count, sha256) against disk. Any
    # mismatch aborts NAMING the file. Inno's equivalent is the pinned hashes
    # baked into Setup; here the manifest is the pin and the zip's .sha256 is
    # the out-of-band pin for the manifest itself.
    param([string]$Stage)
    $stageFull = [IO.Path]::GetFullPath($Stage)
    $manifestPath = Get-ContainedPath -Root $stageFull -RelativePath $ManifestName -Purpose 'Manifest path'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        Fail-Fatal "Payload manifest '$ManifestName' not found beside the package in $Stage. Refusing to install an unmanifested package."
    }
    $problems = @()
    try {
        Assert-NoReparsePointChain -Root $stageFull -FullPath $manifestPath -Purpose 'Manifest source'
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        Assert-ExactPropertySet -Object $manifest -Expected @('schema_version', 'route', 'app', 'app_version', 'architecture', 'built_at_utc', 'file_count', 'dependency_contract', 'files') -Purpose 'Payload manifest'
        if ([int]$manifest.schema_version -ne 2 -or [string]$manifest.route -cne 'zip-plus-powershell' -or
            [string]$manifest.app -cne 'Win''s VPN') {
            throw 'Payload manifest header is not the exact ZIP schema v2 contract.'
        }
        $architecture = [string]$manifest.architecture
        if ($architecture -cnotin @('x64', 'arm64')) {
            throw 'Payload manifest architecture is not a reviewed ZIP target.'
        }
        Initialize-ZipInstallArchitecture -Architecture $architecture
        if (-not $ExpectedDependencyPins.Contains('dependencies/amneziawg.exe')) {
            throw ("Missing pin: this $architecture ZIP installer requires its app-owned amneziawg.exe maintenance helper. " +
                "Measure the reproducibly built ARM64 helper with Get-FileHash -Algorithm SHA256 " +
                "and record its digest in the producer and both ZIP dependency tables before installation.")
        }
        $timestampIsUtc = if ($manifest.built_at_utc -is [DateTime]) {
            $manifest.built_at_utc.Kind -eq [DateTimeKind]::Utc
        } else {
            [string]$manifest.built_at_utc -match '^\d{4}-\d{2}-\d{2}T.*Z$'
        }
        if ([string]$manifest.app_version -notmatch '^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$' -or -not $timestampIsUtc) {
            throw 'Payload manifest version or UTC build timestamp is malformed.'
        }
        if ((($manifest.file_count -isnot [int]) -and ($manifest.file_count -isnot [long])) -or
            [long]$manifest.file_count -le 0 -or [long]$manifest.file_count -ne @($manifest.files).Count) {
            throw 'Payload manifest file_count is malformed or does not match files.'
        }
        Assert-ExactPropertySet -Object $manifest.dependency_contract -Expected @($ExpectedDependencyContract.Keys) -Purpose 'Dependency contract'
        foreach ($name in $ExpectedDependencyContract.Keys) {
            if ([string]$manifest.dependency_contract.$name -cne [string]$ExpectedDependencyContract[$name]) {
                throw "Dependency contract $name does not match the reviewed release identity."
            }
        }
    } catch {
        Fail-Fatal "Payload manifest schema validation failed: $($_.Exception.Message)"
    }

    $entries = @($manifest.files)
    $seenPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $seenDestinations = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $entries) {
        try {
            Assert-ExactPropertySet -Object $entry -Expected @('path', 'bytes', 'sha256', 'dest') -Purpose 'Manifest file entry'
            $canonical = Assert-ZipPayloadAllowed -Path ([string]$entry.path)
            if (-not $seenPaths.Add($canonical)) { throw "Duplicate manifest path: $canonical" }
            if ([string]$entry.dest -notin @('app', 'app-license', 'temp', 'tooling')) {
                throw "Unsupported manifest destination '$($entry.dest)' for $canonical"
            }
            if ((($entry.bytes -isnot [int]) -and ($entry.bytes -isnot [long])) -or [long]$entry.bytes -le 0) {
                throw "Malformed byte count for $canonical"
            }
            if ([string]$entry.sha256 -cnotmatch '^[0-9a-f]{64}$') {
                throw "Malformed lowercase SHA-256 for $canonical"
            }
            Assert-ZipPayloadHashAllowed -Sha256 ([string]$entry.sha256) -Path $canonical
            if ($canonical.StartsWith('dependencies/', [StringComparison]::OrdinalIgnoreCase)) {
                if (-not $ExpectedDependencyPins.Contains($canonical)) { throw "Unapproved dependency payload: $canonical" }
                $pin = $ExpectedDependencyPins[$canonical]
                if ([string]$entry.dest -cne [string]$pin.dest -or [string]$entry.sha256 -cne [string]$pin.sha256) {
                    throw "Dependency $canonical does not match its exact reviewed hash and destination."
                }
            } elseif ($canonical.StartsWith('licenses/', [StringComparison]::OrdinalIgnoreCase)) {
                if ([string]$entry.dest -cne 'app-license') { throw "License has an invalid destination: $canonical" }
            } elseif ($canonical -in @('install_winsvpn_zip.ps1', 'remove_winsvpn_zip.ps1')) {
                if ([string]$entry.dest -cne 'tooling') { throw "Installer tooling has an invalid destination: $canonical" }
            } elseif ([string]$entry.dest -cne 'app') {
                throw "Application payload has an invalid destination: $canonical"
            }

            $full = Get-ContainedPath -Root $stageFull -RelativePath $canonical -Purpose 'Manifest source'
            Assert-NoReparsePointChain -Root $stageFull -FullPath $full -Purpose 'Manifest source'
            $destination = Get-InstallDestinationPath -Entry $entry
            if ($null -ne $destination) {
                Assert-NoReparsePointChain -Root $InstallDir -FullPath $destination -Purpose 'Install destination'
                if (-not $seenDestinations.Add($destination)) { throw "Duplicate install destination for $canonical" }
            }
        } catch {
            $problems += $_.Exception.Message
            continue
        }
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
            $problems += "$canonical is MISSING"
            continue
        }
        $size = (Get-Item -LiteralPath $full).Length
        if ($size -ne $entry.bytes) {
            $problems += "$canonical is $size bytes, manifest says $($entry.bytes)"
        }
        $sha = Sha256-Of -Path $full
        if ($sha -ne $entry.sha256) {
            $problems += "$canonical sha256 $sha does not match the manifest $($entry.sha256)"
        }
        try {
            Assert-ZipPayloadBytesAllowed -Bytes ([IO.File]::ReadAllBytes($full)) -Path $canonical
        } catch {
            $problems += $_.Exception.Message
        }
        $extension = [IO.Path]::GetExtension($canonical).ToLowerInvariant()
        if ($extension -in @('.exe', '.dll', '.sys')) {
            $expectedMachine = if ([IO.Path]::GetFileName($canonical) -ceq $script:ZipVcRedistLeaf) { $ZipX86PeMachine } else { $script:ZipPeMachine }
            $actualMachine = Get-PeCoffMachine -Path $full
            if ($actualMachine -ne $expectedMachine) {
                $problems += ("$canonical has PE/COFF machine 0x{0:x4}; expected 0x{1:x4}" -f $actualMachine, $expectedMachine)
            }
        }
    }

    $physicalPaths = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    try { $physicalFiles = @(Get-ContainedFileItems -Root $stageFull -Purpose 'Physical payload') }
    catch { $problems += $_.Exception.Message; $physicalFiles = @() }
    foreach ($file in $physicalFiles) {
        $relative = $file.FullName.Substring($stageFull.TrimEnd('\', '/').Length + 1).Replace('\', '/')
        if ($relative -ceq $ManifestName) { continue }
        try {
            $relative = Assert-ZipPayloadAllowed -Path $relative
            Assert-NoReparsePointChain -Root $stageFull -FullPath $file.FullName -Purpose 'Physical payload source'
        } catch {
            $problems += $_.Exception.Message
            continue
        }
        [void]$physicalPaths.Add($relative)
        if (-not $seenPaths.Contains($relative)) { $problems += "$relative is present but unlisted by the manifest" }
        try {
            Assert-ZipPayloadBytesAllowed -Bytes ([IO.File]::ReadAllBytes($file.FullName)) -Path $relative
        } catch {
            $problems += $_.Exception.Message
        }
        if ([IO.Path]::GetExtension($relative).ToLowerInvariant() -in @('.pdb', '.ilk', '.iobj', '.ipdb')) {
            $problems += "Package contains debug symbol files that must not be installed: $relative"
        }
    }
    foreach ($listed in $seenPaths) {
        if (-not $physicalPaths.Contains($listed)) { $problems += "$listed is listed but absent from the package" }
    }
    foreach ($required in $RequiredPayloadPaths) {
        if (-not $seenPaths.Contains($required)) { $problems += "$required is required but unlisted" }
    }
    $datapath = Get-ContainedPath -Root $stageFull -RelativePath 'winn-datapath.exe' -Purpose 'Winn v3 datapath source'
    $relay = Get-ContainedPath -Root $stageFull -RelativePath 'winsvpn_winn3_engine.exe' -Purpose 'Winn v3 relay source'
    if (-not (Test-Path -LiteralPath $datapath -PathType Leaf) -or -not (Test-FileContainsMarker -Path $datapath -Needle $Marker)) {
        $problems += 'winn-datapath.exe does not carry the required Winn Protocol v3 marker'
    }
    if (-not (Test-Path -LiteralPath $relay -PathType Leaf)) {
        $problems += 'winsvpn_winn3_engine.exe is missing from the package'
    }
    if ($problems.Count -gt 0) {
        $detail = ($problems | Select-Object -First 20 | ForEach-Object { "  - $_" }) -join "`n"
        Fail-Fatal "Payload verification FAILED for the following files: `n$detail`n`nThe package is not the exact artifact the builder staged. Obtain the matching distribution and never install a package that fails this check."
    }
    Out-Step ("Payload manifest verified: {0} entries match exact bytes and SHA-256." -f $manifest.files.Count)
    return $manifest
}

function Test-VcRuntimeInstalledAtLeastRequired {
    # Mirrors VcRuntimeRegistryVersionAtLeast / VcRuntimeInstalledAtLeastRequired.
    $vcArch = $script:ZipArchitecture
    $roots = @(
        "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\$vcArch",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\$vcArch"
    )
    foreach ($root in $roots) {
        if (Test-Path -LiteralPath $root) {
            $k = Get-ItemProperty -LiteralPath $root -ErrorAction SilentlyContinue
            if ($k -and $k.Installed -eq 1) {
                $need = '0x{0:x}' -f $VcRequired.Build
                $atLeast = ($k.Major -gt $VcRequired.Major) -or
                    (($k.Major -eq $VcRequired.Major) -and ($k.Minor -gt $VcRequired.Minor)) -or
                    (($k.Major -eq $VcRequired.Major) -and ($k.Minor -eq $VcRequired.Minor) -and ($k.Bld -gt $VcRequired.Build)) -or
                    (($k.Major -eq $VcRequired.Major) -and ($k.Minor -eq $VcRequired.Minor) -and ($k.Bld -eq $VcRequired.Build) -and ($k.Rbld -ge $VcRequired.Revision))
                if ($atLeast) { return $true }
            }
        }
    }
    return $false
}

function Invoke-Checked {
    # Run a program with a working directory and capture stdout/stderr to files
    # (Start-Process + redirection; pipe-deadlock-free). The single
    # -ArgumentList element is passed verbatim as the process command line, so
    # this caller controls exact quoting. Returns the exit code only; getAllowed
    # exit codes decide success.
    param(
        [string]$File,
        [string[]]$Arguments,
        [string]$WorkingDirectory,
        [string]$Purpose,
        [int[]]$Allowed = @(0)
    )
    $tokens = @()
    foreach ($arg in $Arguments) { $tokens += '"' + $arg.Replace('"', '\"') + '"' }
    $cmdLine = $tokens -join ' '
    $stamp = [guid]::NewGuid().ToString('N')
    $outFile = Join-Path $env:TEMP "winsvpn-inst-$stamp.out.txt"
    $errFile = Join-Path $env:TEMP "winsvpn-inst-$stamp.err.txt"
    $psi = Start-Process -FilePath $File -ArgumentList $cmdLine -WorkingDirectory $WorkingDirectory -NoNewWindow -Wait -PassThru -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    $code = $psi.ExitCode
    $outText = ''
    if (Test-Path -LiteralPath $outFile) { $rawOut = Get-Content -LiteralPath $outFile -Raw; if ($null -ne $rawOut) { $outText = $rawOut.Trim() } }
    $errText = ''
    if (Test-Path -LiteralPath $errFile) { $rawErr = Get-Content -LiteralPath $errFile -Raw; if ($null -ne $rawErr) { $errText = $rawErr.Trim() } }
    foreach ($f in @($outFile, $errFile)) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
    Out-Step "$Purpose -> exit $code"
    if ($outText.Length -gt 0) { Out-Step ("    stdout: " + ($outText -replace "\s+", ' ')) }
    if ($errText.Length -gt 0) { Out-Step ("    stderr: " + ($errText -replace "\s+", ' ')) }
    if ($Allowed -notcontains $code) { return $code }
    return 0
}

function Test-AmneziaWgRuntimeInstalled {
    # Mirrors AmneziaWgRuntimeInstalled ({autopf}\AmneziaWG) using the
    # manifest-pinned hashes for the three runtime files.
    param([object]$Manifest)
    $runtimeRoot = Join-Path $env:ProgramFiles 'AmneziaWG'
    foreach ($name in @('amneziawg.exe', 'awg.exe', 'wintun.dll')) {
        $full = Join-Path $runtimeRoot $name
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
            Out-Step "AmneziaWG runtime missing: $full"
            return $false
        }
    }
    $pins = @{
        (Join-Path $runtimeRoot 'amneziawg.exe') = [string]$ExpectedDependencyContract.amneziawg_msi_runtime_amneziawg_sha256
        (Join-Path $runtimeRoot 'awg.exe') = [string]$ExpectedDependencyContract.awg_exe_sha256
        (Join-Path $runtimeRoot 'wintun.dll') = [string]$ExpectedDependencyContract.wintun_dll_sha256
    }
    foreach ($full in $pins.Keys) {
        if ($pins[$full].Length -ne 64) {
            Out-Step "Manifest lacks a pinned hash for AmneziaWG runtime file $full"
            return $false
        }
        if ((Sha256-Of -Path $full) -ne $pins[$full]) {
            Out-Step "AmneziaWG runtime file hash mismatch: $full"
            return $false
        }
    }
    return $true
}

function Copy-ManifestFile {
    # Copy one manifest entry to its install destination. dest app -> installDir
    # root (dependencies\* flattened to root, matching winsvpn.iss); dest
    # app-license -> installDir\licenses\<name>; dest temp/tooling -> never
    # installed. Verifies the copied bytes exactly.
    param([object]$Entry, [string]$Stage)
    if ($Entry.dest -notin @('app', 'app-license')) { return }
    $src = Get-ContainedPath -Root $Stage -RelativePath ([string]$Entry.path) -Purpose 'Manifest source'
    Assert-NoReparsePointChain -Root $Stage -FullPath $src -Purpose 'Manifest source'
    $destFull = Get-InstallDestinationPath -Entry $Entry
    Assert-NoReparsePointChain -Root $InstallDir -FullPath $destFull -Purpose 'Install destination'
    $destDir = Split-Path -Parent $destFull
    if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
    Assert-NoReparsePointChain -Root $InstallDir -FullPath $destFull -Purpose 'Install destination'
    Copy-Item -LiteralPath $src -Destination $destFull -Force
    $size = (Get-Item -LiteralPath $destFull).Length
    $sha = Sha256-Of -Path $destFull
    if ($size -ne $Entry.bytes -or $sha -ne $Entry.sha256) {
        throw "Installed copy of $($Entry.path) failed exact verification ($sha != $($Entry.sha256))."
    }
    return $destFull
}

function Restore-PreviousTunnelManager {
    # Mirrors RestorePreviousTunnelManager: exact-hash backup recovery + --install.
    param([object]$State, [object]$Manifest)
    if (-not $State.needsRestore) { return $true }
    try {
        $backup = $State.backup
        if (-not (Test-Path -LiteralPath $backup -PathType Leaf)) {
            Out-Step 'Previous tunnel-manager restoration failed: backup missing.'
            return $false
        }
        if ((Sha256-Of -Path $backup) -ne $State.sha256) {
            Out-Step 'Previous tunnel-manager restoration failed: backup hash invalid.'
            return $false
        }
        $existing = Join-Path $InstallDir $ServiceExeName
        if (Test-Path -LiteralPath $existing) { Remove-Item -LiteralPath $existing -Force }
        Copy-Item -LiteralPath $backup -Destination $existing -Force
        if ((Sha256-Of -Path $existing) -ne $State.sha256) {
            Out-Step 'Previous tunnel-manager restoration failed: recovered copy hash mismatch.'
            return $false
        }
        $code = Invoke-Checked -File $existing -Arguments @('--install') -WorkingDirectory $InstallDir -Purpose 'restore previous tunnel manager --install'
        if ($code -ne 0) {
            Out-Step 'Previous tunnel-manager restoration failed: --install returned non-zero.'
            return $false
        }
        $State.needsRestore = $false
        Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        Out-Step ('Previous tunnel-manager restoration threw: ' + $_.Exception.Message)
        return $false
    }
}

function Fail-AfterPreviousManagerStopped {
    param([object]$State, [object]$Manifest, [string]$Message)
    if ($State.needsRestore) {
        if (Restore-PreviousTunnelManager -State $State -Manifest $Manifest) {
            Fail-Fatal "$Message The previous tunnel manager was restored."
        }
        Fail-Fatal "$Message The previous tunnel manager could not be restored automatically."
    }
    Fail-Fatal $Message
}

# ---------------------------------------------------------------------------
# Gate 1: exact package identity, containment, dependency pins, PE architecture,
# and Winn v3 completeness. This entire gate runs before elevation or writes.
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath (Join-Path $StageDir $ManifestName) -PathType Leaf)) {
    Fail-Fatal "Run this from (or with -StageDir pointing at) the folder that contains $ManifestName. None found at $StageDir."
}
$manifest = Test-PayloadManifest -Stage $StageDir
if ($VerifyManifestOnly) {
    Out-Step "Verification-only mode: manifest OK, no machine modifications performed. Package version '$($manifest.app_version)'."
    exit 0
}

# ---------------------------------------------------------------------------
# Gate 2: environment. Only a fully validated package reaches elevation.
# ---------------------------------------------------------------------------
if (-not $runningOnWindows) {
    Fail-Fatal 'The privileged ZIP installer can run only on Windows. Use -VerifyManifestOnly for portable package verification.'
}
Assert-Elevated
if (-not [Environment]::Is64BitOperatingSystem) {
    Fail-Fatal 'This host is not 64-bit Windows; the Win''s VPN Windows build is 64-bit only.'
}
$osArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$normalizedHost = switch -Regex ($osArch) {
    '^(?i:X64|Amd64)$' { 'x64' }
    '^(?i:Arm64)$' { 'arm64' }
    default { Fail-Fatal "Unsupported Windows host architecture '$osArch'." }
}
if ($normalizedHost -cne [string]$manifest.architecture) {
    Fail-Fatal ("This zip installer is the $([string]$manifest.architecture) package (host architecture '$osArch'). " +
        'Refusing to mix installer architecture with the host.')
}

if (Test-PacketEngineRunning) {
    Fail-Fatal 'An active Win''s VPN tunnel is still using the packet engine (winsvpn_awg_engine.exe). Disconnect the VPN and rerun; no privileged payload was changed.'
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
$logPath = Join-Path $InstallDir 'winsvpn_zip_install.log'
Start-Transcript -Path $logPath -Force | Out-Null

# ---------------------------------------------------------------------------
# Gate 4: VC++ runtime
# ---------------------------------------------------------------------------
if (-not (Test-VcRuntimeInstalledAtLeastRequired)) {
    $vcRedistRelative = "dependencies/$($script:ZipVcRedistLeaf)"
    $vcRedist = Get-ContainedPath -Root $StageDir -RelativePath $vcRedistRelative -Purpose 'VC runtime source'
    if (-not (Test-Path -LiteralPath $vcRedist -PathType Leaf)) {
        Fail-Fatal "Required $($script:ZipVcRedistLeaf) is not in the package."
    }
    Out-Step 'Installing Microsoft Visual C++ Runtime...'
    $code = Invoke-Checked -File $vcRedist -Arguments @('/install', '/quiet', '/norestart') -WorkingDirectory $StageDir -Purpose $script:ZipVcRedistLeaf -Allowed @(0, 3010, 1638)
    if ($code -ne 0) { Fail-Fatal "Microsoft Visual C++ Runtime installation failed with exit code $code." }
    if (-not (Test-VcRuntimeInstalledAtLeastRequired)) {
        Fail-Fatal "Microsoft Visual C++ Runtime did not register the required $($script:ZipArchitecture) version after install."
    }
}

# ---------------------------------------------------------------------------
# Gate 5: AmneziaWG MSI
# ---------------------------------------------------------------------------
$cwMsi = Get-ContainedPath -Root $StageDir -RelativePath "dependencies/$($script:ZipMsiLeaf)" -Purpose 'AmneziaWG MSI source'
if (-not (Test-Path -LiteralPath $cwMsi -PathType Leaf)) { Fail-Fatal "$($script:ZipMsiLeaf) is not in the package." }
# The AmneziaWG runtime is a shared machine prerequisite (same retain-semantics
# as the VC runtime above and as winsvpn.iss's CurUninstallStepChanged). If it
# is ALREADY the exact pinned version, do NOT rerun its MSI: on an upgrade
# machine where AmneziaWG is installed with its service running, msiexec
# blocks indefinitely on the in-use files (with /qn it cannot prompt), which
# hangs setup for minutes with ~0 CPU. Skipping a satisfied prerequisite is the
# same decision winsvpn.iss makes for the VC runtime, and it cannot weaken the
# fail-closed contract -- when the runtime is absent or mis-pinned, the MSI
# still runs and the exact-hash verify below still gates.
if (-not (Test-AmneziaWgRuntimeInstalled -Manifest $manifest)) {
    Out-Step 'Installing AmneziaWG Windows tunnel engine...'
    $msiCode = Invoke-Checked -File (Join-Path $env:SystemRoot 'System32\msiexec.exe') -Arguments @('/i', $cwMsi, '/qn', '/norestart', 'DO_NOT_LAUNCH=1') -WorkingDirectory $StageDir -Purpose 'AmneziaWG MSI' -Allowed @(0, 3010)
    if ($msiCode -ne 0) { Fail-Fatal "AmneziaWG tunnel-engine installation failed with exit code $msiCode." }
    if (-not (Test-AmneziaWgRuntimeInstalled -Manifest $manifest)) {
        Fail-Fatal "AmneziaWG setup completed without registering the exact pinned $($script:ZipArchitecture) runtime files."
    }
} else {
    Out-Step 'AmneziaWG runtime already at the exact pinned version; skipping MSI reinstall (shared prerequisite retained).'
}

# The protected tunnel manager uses the dynamic MSVC runtime. Run its executable
# self-test only after the exact VC runtime is present, but still before the
# previous service is stopped or any application payload is replaced.
$stagedService = Get-ContainedPath -Root $StageDir -RelativePath $ServiceExeName -Purpose 'Staged tunnel manager source'
$code = Invoke-Checked -File $stagedService -Arguments @('--protocol-self-test') -WorkingDirectory $StageDir -Purpose 'staged tunnel manager --protocol-self-test'
if ($code -ne 0) {
    Fail-Fatal "The new tunnel-manager payload failed its readiness test (--protocol-self-test exit $code)."
}

# ---------------------------------------------------------------------------
# Gate 7: upgrade-safe swap of the previous tunnel manager (exact-hash backup)
# ---------------------------------------------------------------------------
$state = [ordered]@{ needsRestore = $false; backup = $null; sha256 = $null }
$existingService = Join-Path $InstallDir $ServiceExeName
if (Test-Path -LiteralPath $existingService -PathType Leaf) {
    Out-Step 'Previous tunnel manager present; backing it up before the upgrade...'
    $backup = Join-Path $env:TEMP 'winsvpn-previous-tunnel-manager.exe'
    if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
    $prevSha = Sha256-Of -Path $existingService
    Copy-Item -LiteralPath $existingService -Destination $backup -Force
    if ((Sha256-Of -Path $backup) -ne $prevSha) {
        Fail-Fatal 'Could not create an exact rollback copy of the previous tunnel manager.'
    }
    $state.needsRestore = $true; $state.backup = $backup; $state.sha256 = $prevSha
    $code = Invoke-Checked -File $existingService -Arguments @('--uninstall') -WorkingDirectory $InstallDir -Purpose 'previous tunnel manager --uninstall'
    if ($code -ne 0) {
        if (Restore-PreviousTunnelManager -State $state -Manifest $manifest) {
            Fail-Fatal 'The previous tunnel manager could not be stopped safely; it was restored. Setup aborted before replacing privileged files.'
        } else {
            Fail-Fatal 'The previous tunnel manager could not be stopped or restored safely. Setup will not replace privileged files.'
        }
    }
}

# ---------------------------------------------------------------------------
# Gate 8: copy payloads, verifying each installed copy against the manifest
# ---------------------------------------------------------------------------
try {
    foreach ($entry in @($manifest.files)) {
        Copy-ManifestFile -Entry $entry -Stage $StageDir
    }
} catch {
    Fail-AfterPreviousManagerStopped -State $state -Manifest $manifest -Message ("Payload copy failed: " + $_.Exception.Message)
}

# ---------------------------------------------------------------------------
# Gate 9: licences. Pinned texts must hash to the manifest; the component
# inventory is presence-only (it changes legitimately, same as winsvpn.iss).
# ---------------------------------------------------------------------------
foreach ($entry in @($manifest.files | Where-Object { $_.dest -eq 'app-license' })) {
    $licPath = Get-InstallDestinationPath -Entry $entry
    if (-not (Test-Path -LiteralPath $licPath -PathType Leaf)) {
        Fail-AfterPreviousManagerStopped -State $state -Manifest $manifest -Message "A third-party licence this release must convey is missing from the installation: $($entry.path)"
    }
    if ((Sha256-Of -Path $licPath) -ne $entry.sha256) {
        Fail-AfterPreviousManagerStopped -State $state -Manifest $manifest -Message "A third-party licence in this installation does not match the exact text this release was built to convey: $($entry.path)"
    }
}
$tnp = Join-Path (Join-Path $InstallDir 'licenses') 'THIRD_PARTY_NOTICES.md'
if (-not (Test-Path -LiteralPath $tnp -PathType Leaf)) {
    Fail-AfterPreviousManagerStopped -State $state -Manifest $manifest -Message 'The third-party component inventory is missing from the installation: licenses\THIRD_PARTY_NOTICES.md.'
}

# ---------------------------------------------------------------------------
# Gate 10: register + start the tunnel manager, with rollback on failure
# ---------------------------------------------------------------------------
$installedDatapath = Get-ContainedPath -Root $InstallDir -RelativePath 'winn-datapath.exe' -Purpose 'Installed Winn v3 datapath'
$installedRelay = Get-ContainedPath -Root $InstallDir -RelativePath 'winsvpn_winn3_engine.exe' -Purpose 'Installed Winn v3 relay'
if (-not (Test-Path -LiteralPath $installedDatapath -PathType Leaf) -or -not (Test-FileContainsMarker -Path $installedDatapath -Needle $Marker)) {
    Fail-AfterPreviousManagerStopped -State $state -Manifest $manifest -Message 'The installed winn-datapath.exe does not carry Winn Protocol v3. Refusing service registration.'
}
if (-not (Test-Path -LiteralPath $installedRelay -PathType Leaf)) {
    Fail-AfterPreviousManagerStopped -State $state -Manifest $manifest -Message 'The installed winsvpn_winn3_engine.exe is missing. Refusing service registration.'
}

$installedService = Join-Path $InstallDir $ServiceExeName
$servicePin = @($manifest.files | Where-Object { $_.path -eq $ServiceExeName })
if (-not (Test-Path -LiteralPath $installedService -PathType Leaf) -or
    ('app' -ne $servicePin[0].dest) -or
    ((Sha256-Of -Path $installedService) -ne $servicePin[0].sha256)) {
    Fail-AfterPreviousManagerStopped -State $state -Manifest $manifest -Message 'The installed tunnel-manager payload differs from the exact tested staged payload.'
}
$code = Invoke-Checked -File $installedService -Arguments @('--install') -WorkingDirectory $InstallDir -Purpose 'new tunnel manager --install'
if ($code -ne 0) {
    $null = Invoke-Checked -File $installedService -Arguments @('--uninstall') -WorkingDirectory $InstallDir -Purpose 'rollback --uninstall' -Allowed @(0, 1, 2)
    Fail-AfterPreviousManagerStopped -State $state -Manifest $manifest -Message "The new protected tunnel manager failed to install or start (--install exit $code)."
}

if ($state.needsRestore -and $state.backup -and (Test-Path -LiteralPath $state.backup -PathType Leaf)) {
    Remove-Item -LiteralPath $state.backup -Force -ErrorAction SilentlyContinue
    $state.needsRestore = $false
}

Stop-Transcript -ErrorAction SilentlyContinue
Out-Step "Win's VPN installed to $InstallDir. Install log: $logPath"
if (-not $NoLaunch) {
    $app = Join-Path $InstallDir 'wins_vpn.exe'
    if (Test-Path -LiteralPath $app -PathType Leaf) {
        Out-Step "Launching $app (use -NoLaunch to suppress)."
        Start-Process -FilePath $app
    }
}
exit 0
