param(
    [switch]$SkipPubGet,
    [switch]$SelfTestBuildLock,
    [switch]$SelfTestSigningStore,
    [switch]$SelfTestNeutralStaging,
    [switch]$InNeutralStage,
    [string]$ReleaseInputIndex = '',
    [string]$BuildReceiptDirectory = '',
    [string]$SigningStorePath = '',
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ReleaseDependencyArguments = @()
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ReleaseDependencyBuildAttemptSwitch = '--wins-release-dependency-build-attempt-v2'
$script:ReleaseDependencyWitnessMode = @($ReleaseDependencyArguments) -contains $ReleaseDependencyBuildAttemptSwitch
$script:ReleaseDependencyWitnessOutput = $null
$script:ReleaseDependencyWitnessIdentity = $null

# WINS_RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_V1
# WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2
# WINS_RELEASE_DEPENDENCY_NATIVE_HOST=windows
# WINS_RELEASE_DEPENDENCY_NATIVE_RUNTIME=powershell-file
$ReleaseDependencyBuildAttemptContract = 'winsvpn-witnessed-build-attempt-v2'
$ReleaseDependencyBuildAttemptPlatform = 'android'
$ReleaseDependencyBuildAttemptOutputs = @(
    'app-release.apk',
    'app-release.aab',
    'app-tv-release.apk',
    'app-tv-release.aab'
)
$ReleaseDependencyBuildAttemptEnvironment = @(
    'WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT',
    'WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE',
    'WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT',
    'WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM'
)

trap {
    if ($script:ReleaseDependencyWitnessMode) {
        if ($null -ne $script:ReleaseDependencyWitnessOutput) {
            $script:ReleaseDependencyWitnessOutput.Dispose()
            $script:ReleaseDependencyWitnessOutput = $null
        }
        exit 86
    }
    throw $_
}

function Get-WinsReleaseDependencyEnvironmentEntries {
    $isWindowsHost = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    )
    if (-not $isWindowsHost) {
        return @([Environment]::GetEnvironmentVariables('Process').GetEnumerator() |
            ForEach-Object { "$($_.Key)=$($_.Value)" })
    }
    if (-not ('WinsVpn.ReleaseDependencyEnvironment' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace WinsVpn {
    public static class ReleaseDependencyEnvironment {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetEnvironmentStringsW();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool FreeEnvironmentStringsW(IntPtr environmentBlock);

        public static string[] ReadRawEntries() {
            IntPtr block = GetEnvironmentStringsW();
            if (block == IntPtr.Zero) {
                throw new InvalidOperationException("process environment is unavailable");
            }
            var entries = new List<string>();
            try {
                IntPtr cursor = block;
                while (true) {
                    string entry = Marshal.PtrToStringUni(cursor);
                    if (String.IsNullOrEmpty(entry)) {
                        break;
                    }
                    entries.Add(entry);
                    cursor = IntPtr.Add(cursor, checked((entry.Length + 1) * 2));
                }
            } finally {
                if (!FreeEnvironmentStringsW(block)) {
                    throw new InvalidOperationException("process environment release failed");
                }
            }
            return entries.ToArray();
        }
    }
}
'@
    }
    return @([WinsVpn.ReleaseDependencyEnvironment]::ReadRawEntries())
}

function Read-WinsReleaseDependencyWitnessInputs {
    param([Parameter(Mandatory)][string[]]$Entries)

    $required = @{}
    foreach ($name in $ReleaseDependencyBuildAttemptEnvironment) {
        $required[$name] = $true
    }
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $values = @{}
    foreach ($entry in $Entries) {
        $separator = $entry.IndexOf('=')
        if ($separator -le 0) { continue }
        $name = $entry.Substring(0, $separator)
        if (-not $name.StartsWith(
            'WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_',
            [StringComparison]::OrdinalIgnoreCase
        )) { continue }
        if (-not $seen.Add($name) -or -not $required.ContainsKey($name)) {
            throw 'invalid witnessed build environment'
        }
        if ([Array]::IndexOf(
            [string[]]$ReleaseDependencyBuildAttemptEnvironment,
            [string]$name
        ) -lt 0) {
            throw 'invalid witnessed build environment'
        }
        $values[$name] = $entry.Substring($separator + 1)
    }
    if ($seen.Count -ne $ReleaseDependencyBuildAttemptEnvironment.Count) {
        throw 'invalid witnessed build environment'
    }
    if ($values.WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT -cne
        $ReleaseDependencyBuildAttemptContract -or
        $values.WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM -cne
        $ReleaseDependencyBuildAttemptPlatform -or
        $values.WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE -cnotmatch
        '^[0-9a-f]{64}$') {
        throw 'invalid witnessed build environment'
    }
    return $values
}

function Test-WinsReleaseDependencyOutputName {
    param([Parameter(Mandatory)][string]$Name)

    if ([string]::IsNullOrEmpty($Name) -or $Name.Length -gt 192 -or
        [IO.Path]::IsPathRooted($Name) -or
        [IO.Path]::GetFileName($Name) -cne $Name -or
        $Name.IndexOfAny(@([char]'/', [char]'\\', [char]':')) -ge 0 -or
        $Name.EndsWith(' ', [StringComparison]::Ordinal) -or
        $Name.EndsWith('.', [StringComparison]::Ordinal) -or
        $Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+ -]{0,191}$') {
        throw 'invalid witnessed build output'
    }
    if ($Name.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
        throw 'invalid witnessed build output'
    }
    $stem = $Name.Split('.')[0]
    if ($stem -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
        throw 'invalid witnessed build output'
    }
    if ([Array]::IndexOf(
        [string[]]$ReleaseDependencyBuildAttemptOutputs,
        [string]$Name
    ) -lt 0) {
        throw 'invalid witnessed build output'
    }
}

function Open-WinsReleaseDependencyWitnessOutput {
    param([Parameter(Mandatory)][string]$Name)

    Test-WinsReleaseDependencyOutputName -Name $Name
    $workingDirectory = [IO.Path]::GetFullPath((Get-Location).ProviderPath)
    $workingItem = Get-Item -LiteralPath $workingDirectory -Force -ErrorAction Stop
    if (-not $workingItem.PSIsContainer -or
        ($workingItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'invalid witnessed build output'
    }
    $outputPath = [IO.Path]::GetFullPath((Join-Path $workingDirectory $Name))
    if ([IO.Path]::GetDirectoryName($outputPath).TrimEnd('\\', '/') -cne
        $workingDirectory.TrimEnd('\\', '/')) {
        throw 'invalid witnessed build output'
    }
    $item = Get-Item -LiteralPath $outputPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -ne 0) {
        throw 'invalid witnessed build output'
    }
    if (-not ('WinsVpn.ReleaseDependencyOutput' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WinsVpn {
    public static class ReleaseDependencyOutput {
        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME { public uint Low; public uint High; }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION {
            public uint FileAttributes;
            public FILETIME CreationTime;
            public FILETIME LastAccessTime;
            public FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle,
            out BY_HANDLE_FILE_INFORMATION information
        );

        public static ulong[] Inspect(SafeFileHandle handle) {
            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(handle, out information)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return new ulong[] {
                information.VolumeSerialNumber,
                information.FileIndexHigh,
                information.FileIndexLow,
                information.NumberOfLinks,
                ((ulong)information.FileSizeHigh << 32) | information.FileSizeLow
            };
        }
    }
}
'@
    }
    $stream = [IO.FileStream]::new(
        $outputPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Write,
        [IO.FileShare]::ReadWrite,
        4096,
        [IO.FileOptions]::WriteThrough
    )
    try {
        $identity = [WinsVpn.ReleaseDependencyOutput]::Inspect($stream.SafeFileHandle)
        if ($identity[3] -ne 1 -or $identity[4] -ne 0) {
            throw 'invalid witnessed build output'
        }
        return [pscustomobject]@{
            Path = $outputPath
            Stream = $stream
            Identity = @($identity[0], $identity[1], $identity[2])
        }
    } catch {
        $stream.Dispose()
        throw
    }
}

if ($script:ReleaseDependencyWitnessMode) {
    if (@($ReleaseDependencyArguments).Count -ne 1 -or
        $ReleaseDependencyArguments[0] -cne $ReleaseDependencyBuildAttemptSwitch -or
        $SkipPubGet -or $SelfTestBuildLock -or $SelfTestSigningStore -or
        $SelfTestNeutralStaging -or $InNeutralStage -or
        -not [string]::IsNullOrEmpty($ReleaseInputIndex) -or
        -not [string]::IsNullOrEmpty($BuildReceiptDirectory) -or
        -not [string]::IsNullOrEmpty($SigningStorePath)) {
        exit 86
    }
    $witnessInputs = Read-WinsReleaseDependencyWitnessInputs `
        -Entries @(Get-WinsReleaseDependencyEnvironmentEntries)
    Test-WinsReleaseDependencyOutputName `
        -Name ([string]$witnessInputs.WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT)
    $isWindowsHost = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    )
    if (-not $isWindowsHost) { exit 86 }
    $openedWitnessOutput = Open-WinsReleaseDependencyWitnessOutput `
        -Name ([string]$witnessInputs.WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT)
    $script:ReleaseDependencyWitnessOutput = $openedWitnessOutput.Stream
    $script:ReleaseDependencyWitnessOutputPath = $openedWitnessOutput.Path
    $script:ReleaseDependencyWitnessIdentity = $openedWitnessOutput.Identity
} elseif (@($ReleaseDependencyArguments).Count -ne 0) {
    throw "Unknown Android release producer argument: $($ReleaseDependencyArguments[0])"
}
# TOOLCHAIN PIN: this producer reads the reviewed latest-stable freeze from
# tools/toolchain-pins.json and rejects any installed Flutter version or
# revision that differs. The current release freeze is asserted exactly by
# the dedicated Android producer tests without creating a second runtime pin.
$ExpectedUploadCertificateSha256 = '4ebbff15a1274e7b072767fa37f00e8ffbeafab80cb61b51a5ab598af6dbe6ee'
$ExpectedPhoneApplicationId = 'org.winsvpn.app'
$ExpectedTvApplicationId = 'org.winsvpn.app'
$BundletoolVersion = '1.18.3'
$BundletoolAllSha256 = 'a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29'

$RepoRoot = if ($script:ReleaseDependencyWitnessMode -and
    (Split-Path -Leaf $PSCommandPath) -ceq '.producer' -and
    (Split-Path -Leaf (Split-Path -Parent $PSScriptRoot)) -ceq '.artifacts' -and
    (Split-Path -Leaf $PSScriptRoot) -cmatch '^\.build-attempt-[0-9a-f]{64}$') {
    [IO.Path]::GetFullPath((Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path)
} else {
    [IO.Path]::GetFullPath((Resolve-Path (Join-Path $PSScriptRoot '..')).Path)
}
Set-Location $RepoRoot

if ($script:ReleaseDependencyWitnessMode) {
    $productionProducer = Join-Path $RepoRoot 'tools\build_android_release.ps1'
    $productionHashFirst = (Get-FileHash -Algorithm SHA256 -LiteralPath $productionProducer).Hash
    $productionHashSecond = (Get-FileHash -Algorithm SHA256 -LiteralPath $productionProducer).Hash
    $snapshotHashFirst = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash
    $snapshotHashSecond = (Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash
    if ($productionHashFirst -cne $productionHashSecond -or
        $snapshotHashFirst -cne $snapshotHashSecond -or
        $productionHashSecond -cne $snapshotHashSecond) {
        exit 86
    }
    $script:ReleaseDependencyWitnessProducerPath = $productionProducer
    $script:ReleaseDependencyWitnessProducerSha256 = $snapshotHashSecond
}

function Assert-WinsReleaseDependencyProducerUnchanged {
    if (-not $script:ReleaseDependencyWitnessMode) { return }
    $first = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $script:ReleaseDependencyWitnessProducerPath).Hash
    $second = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $script:ReleaseDependencyWitnessProducerPath).Hash
    if ($first -cne $second -or
        $second -cne $script:ReleaseDependencyWitnessProducerSha256) {
        throw 'witnessed Android producer changed during execution'
    }
}

# SINGLE SOURCE OF TRUTH: read every toolchain pin from
# tools/toolchain-pins.json at run time instead of a literal. A literal that
# happens to agree today is still a defect -- the next pin bump silently
# desynchronises this producer from every other build. Fail loudly so a
# missing pin file or parser never selects an unreviewed toolchain silently.
function Read-WinsToolchainPin {
    param(
        [Parameter(Mandatory = $true)][string]$PinPath,
        [Parameter(Mandatory = $true)][string]$Key
    )
    $pin = Get-Content -Raw -LiteralPath $PinPath | ConvertFrom-Json -ErrorAction Stop
    $pointer = $pin
    foreach ($part in $Key.Split('.')) {
        $pointer = $pointer.$part
    }
    return [string]$pointer
}
$RequiredFlutterVersion = Read-WinsToolchainPin -PinPath (Join-Path $RepoRoot 'tools\toolchain-pins.json') -Key 'tools.flutter.version'
$RequiredFlutterRevision = Read-WinsToolchainPin -PinPath (Join-Path $RepoRoot 'tools\toolchain-pins.json') -Key 'tools.flutter.revision'
$RequiredPythonVersion = Read-WinsToolchainPin -PinPath (Join-Path $RepoRoot 'tools\toolchain-pins.json') -Key 'tools.python.version'
$RequiredPythonImplementation = Read-WinsToolchainPin -PinPath (Join-Path $RepoRoot 'tools\toolchain-pins.json') -Key 'tools.python.implementation'
function Get-Winn3DescriptorPubkeyDefines {
    $defines = @()
    foreach ($slot in @('G1','G2','G3')) {
        $var = "WINS_WINN3_DESCRIPTOR_PUBKEY_$slot"; $fileVar = "${var}_FILE"
        $filePath = [Environment]::GetEnvironmentVariable($fileVar); $envValue = [Environment]::GetEnvironmentVariable($var)
        $raw = $null; $value = $null
        if ($filePath -and $filePath.Trim()) {
            $filePath = $filePath.Trim()
            if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) { throw "Winn3 pubkey file missing: $fileVar=$filePath" }
            $raw = (Get-Content -LiteralPath $filePath -Raw -ErrorAction Stop).Trim() -replace '\r','' -replace '\n',''
            $raw = $raw.Trim()
            if ($raw.StartsWith('--dart-define=') -or $raw.StartsWith('WINS_WINN3_DESCRIPTOR_PUBKEY_') -or $raw.StartsWith('WINN3_DESCRIPTOR_PUBKEY_')) { throw "Refusing $fileVar that looks like a dart-define or hub key: $($raw.Substring(0,[Math]::Min(60,$raw.Length)))" }
            $value = $raw
        } elseif ($envValue -and $envValue.Trim()) {
            $raw = $envValue
            if ($raw.StartsWith('--dart-define=')) { throw "Refusing $var that already contains --dart-define" }
            if ($raw.StartsWith('WINN3_DESCRIPTOR_PUBKEY_')) { throw "Refusing $var that looks like hub key name: $($raw.Substring(0,[Math]::Min(60,$raw.Length)))" }
            $value = $raw.Trim()
        } else { continue }
        if (-not $value) { continue }
        try { $d=[Convert]::FromBase64String($value); if($d.Length -ne 32){throw "bad"} } catch { throw "Winn3 pubkey $var not valid base64 of 32 bytes: $($value.Substring(0,[Math]::Min(20,$value.Length)))..." }
        $defines += "--dart-define=$var=$value"
    }
    return $defines
}
function Write-Winn3DescriptorPubkeyStatus { param([string[]]$Defines) $c=if($Defines){$Defines.Count}else{0}; if($c -gt 0){ Write-Host "ANDROID WINDOWS RELEASE: Winn3 descriptor verification ring PRESENT ($c slot(s))" } else { throw "Standalone v3 Android release requires WINS_WINN3_DESCRIPTOR_PUBKEY_G1, G2, or G3" } }

$RunningOnMacOS = $PSVersionTable.PSEdition -eq 'Core' -and
    [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::OSX
    )
if ($RunningOnMacOS) {
    if ($SkipPubGet -or $SelfTestBuildLock -or $SelfTestSigningStore -or
        $SelfTestNeutralStaging -or $InNeutralStage -or
        -not [string]::IsNullOrWhiteSpace($SigningStorePath)) {
        throw 'Windows-only Android producer switches and the DPAPI signing store are unavailable on macOS.'
    }
    if ([string]::IsNullOrWhiteSpace($ReleaseInputIndex)) {
        throw 'ReleaseInputIndex is required for every Android release build.'
    }
    $macProducer = Join-Path $RepoRoot 'tools/build_android_release_macos.sh'
    if (-not (Test-Path -LiteralPath $macProducer -PathType Leaf)) {
        throw "The macOS Android release producer is missing: $macProducer"
    }
    $arguments = @('-p', $macProducer, '--release-input-index', $ReleaseInputIndex)
    if (-not [string]::IsNullOrWhiteSpace($BuildReceiptDirectory)) {
        $arguments += @('--build-receipt-directory', $BuildReceiptDirectory)
    }
    $env:WINS_ANDROID_MACOS_PS_ENTRYPOINT = '1'
    try {
        & /bin/bash @arguments
        if ($LASTEXITCODE -ne 0) {
            throw "The macOS Android release producer failed with exit code $LASTEXITCODE."
        }
    } finally {
        Remove-Item Env:WINS_ANDROID_MACOS_PS_ENTRYPOINT -ErrorAction SilentlyContinue
    }
    exit 0
}

if ([string]::IsNullOrWhiteSpace($SigningStorePath)) {
    $SigningStorePath = Join-Path $env:LOCALAPPDATA 'WinsVPN\Signing\android-signing.dpapi'
}

$VersionLine = Select-String -LiteralPath (Join-Path $RepoRoot 'pubspec.yaml') -Pattern '^version:\s*([^+\s]+)\+(\d+)\s*$' | Select-Object -First 1
if (-not $VersionLine) {
    throw 'Unable to read version: <semver>+<build> from pubspec.yaml.'
}
$AppVersion = $VersionLine.Matches[0].Groups[1].Value
$BuildNumber = $VersionLine.Matches[0].Groups[2].Value
$VersionIdentity = "$AppVersion+$BuildNumber"

$BuildLockDir = Join-Path $RepoRoot '.dart_tool\winsvpn-release-build.lock'
$BuildLockOwnerFile = Join-Path $BuildLockDir 'owner.txt'
$script:BuildLockAcquired = $false

$SymbolsRoot = Join-Path $RepoRoot '.artifacts\private-release-symbols'
$ApkSymbols = Join-Path $SymbolsRoot "android-apk\$VersionIdentity"
$AabSymbols = Join-Path $SymbolsRoot "android-aab\$VersionIdentity"
$TvApkSymbols = Join-Path $SymbolsRoot "android-tv-apk\$VersionIdentity"
$TvAabSymbols = Join-Path $SymbolsRoot "android-tv-aab\$VersionIdentity"
$ApkManifest = Join-Path $ApkSymbols 'manifest.json'
$AabManifest = Join-Path $AabSymbols 'manifest.json'
$TvApkManifest = Join-Path $TvApkSymbols 'manifest.json'
$TvAabManifest = Join-Path $TvAabSymbols 'manifest.json'
$ApkPath = Join-Path $RepoRoot 'build\app\outputs\flutter-apk\app-phone-release.apk'
$AabPath = Join-Path $RepoRoot 'build\app\outputs\bundle\phoneRelease\app-phone-release.aab'
$TvApkPath = Join-Path $RepoRoot 'build\app\outputs\flutter-apk\app-tv-release.apk'
$TvAabPath = Join-Path $RepoRoot 'build\app\outputs\bundle\tvRelease\app-tv-release.aab'
$PublishedApkPath = Join-Path $RepoRoot 'build\app\outputs\flutter-apk\app-release.apk'
$PublishedAabPath = Join-Path $RepoRoot 'build\app\outputs\bundle\release\app-release.aab'
$PublishedTvApkPath = Join-Path $RepoRoot 'build\app\outputs\flutter-apk\app-tv-release.apk'
$ObfuscationContract = Join-Path $RepoRoot 'tools\release_obfuscation_contract.py'
$PrivacyValidator = Join-Path $RepoRoot 'tools\validate_release_artifact_privacy.py'
$PlayRedemptionGate = Join-Path $RepoRoot 'tools\android_play_redemption_gate.py'
$CustodyTool = Join-Path $RepoRoot 'tools\private_release_symbol_custody.py'
$CustodyAclTool = Join-Path $RepoRoot 'tools\private_symbol_custody.ps1'
$DependencyFreezeTool = Join-Path $RepoRoot 'tools\release_dependency_freeze.py'
$PublicationTool = Join-Path $RepoRoot 'tools\android_release_publication.py'
$ToolchainCustodyManifest = Join-Path $RepoRoot 'tools\android-toolchain-custody.json'
$ToolchainCustodyHelper = Join-Path $RepoRoot 'tools\android_toolchain_custody.ps1'
$PublicationState = Join-Path $RepoRoot '.artifacts\android-release-publication.state.json'
$R8MappingPath = Join-Path $RepoRoot 'build\app\outputs\mapping\phoneRelease\mapping.txt'
$NativeDebugSymbolsPath = Join-Path $RepoRoot 'build\app\outputs\native-debug-symbols\phoneRelease\native-debug-symbols.zip'
$TvR8MappingPath = Join-Path $RepoRoot 'build\app\outputs\mapping\tvRelease\mapping.txt'
$TvNativeDebugSymbolsPath = Join-Path $RepoRoot 'build\app\outputs\native-debug-symbols\tvRelease\native-debug-symbols.zip'
$script:LoadedSigningEnvironment = $false
$NeutralStageBase = Join-Path $env:SystemDrive 'WVPAndroidRelease'
$NeutralInputDirectories = @('lib', 'assets', 'android')
$NeutralInputFiles = @(
    '.metadata',
    'analysis_options.yaml',
    'pubspec.yaml',
    'pubspec.lock',
    'tools/build_android_release.ps1',
    'tools/android_release_publication.py',
    'tools/release_obfuscation_contract.py',
    'tools/validate_release_artifact_privacy.py',
    'tools/android_play_redemption_gate.py',
    # Imported at module level by the obfuscation and privacy tools.
    'tools/release_secret_scan_policy.py',
    'tools/release_secret_inventory.py',
    'tools/verify_android_aab_page_alignment.py',
    'tools/verify_android_aab_signers.py',
    'tools/verify_standalone_v3_artifact.py',
    'tools/verify_winn3_ring_artifact.py',
    'tools/winn3_descriptor_ring_identity.py',
    'tools/private_release_symbol_custody.py',
    'tools/private_symbol_custody.ps1',
    'tools/android-toolchain-custody.json',
    'tools/android_toolchain_custody.ps1',
    # The Gradle stamp check verifyWinnReleaseStamp reads ../tools/winn_release_authority.json.
    'tools/winn_release_authority.json',
    # Isolated child re-reads this file at startup via Read-WinsToolchainPin.
    'tools/toolchain-pins.json'
)

. $CustodyAclTool

if (-not ('WinsVpn.ReleaseFileIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WinsVpn {
    public static class ReleaseFileIdentity {
        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME {
            public uint Low;
            public uint High;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION {
            public uint FileAttributes;
            public FILETIME CreationTime;
            public FILETIME LastAccessTime;
            public FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        public sealed class Result {
            public uint VolumeSerialNumber { get; internal set; }
            public uint NumberOfLinks { get; internal set; }
            public uint FileIndexHigh { get; internal set; }
            public uint FileIndexLow { get; internal set; }
            public ulong FileSize { get; internal set; }
            public ulong LastWriteFileTime { get; internal set; }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle,
            out BY_HANDLE_FILE_INFORMATION information
        );

        public static Result Inspect(SafeFileHandle handle) {
            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(handle, out information)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return new Result {
                VolumeSerialNumber = information.VolumeSerialNumber,
                NumberOfLinks = information.NumberOfLinks,
                FileIndexHigh = information.FileIndexHigh,
                FileIndexLow = information.FileIndexLow,
                FileSize = ((ulong)information.FileSizeHigh << 32) | information.FileSizeLow,
                LastWriteFileTime = ((ulong)information.LastWriteTime.High << 32) | information.LastWriteTime.Low
            };
        }
    }
}
'@
}

function Assert-NoReparsePath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    $resolved = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($resolved)
    $current = $root
    foreach ($part in $resolved.Substring($root.Length) -split '[\\/]') {
        if ([string]::IsNullOrWhiteSpace($part)) { continue }
        $current = Join-Path $current $part
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "$Description must not traverse a reparse point: $current"
        }
    }
}

function Get-WinsFileIdentityFromStream {
    param([Parameter(Mandatory)][IO.FileStream]$Stream)
    return [WinsVpn.ReleaseFileIdentity]::Inspect($Stream.SafeFileHandle)
}

function Assert-SingleLinkFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    Assert-NoReparsePath -Path $Path -Description $Description
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Description must be one regular non-reparse file: $Path"
    }
    $stream = [IO.FileStream]::new(
        $item.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $before = Get-WinsFileIdentityFromStream -Stream $stream
        if ($before.NumberOfLinks -ne 1) {
            throw "$Description must be a single-link file: $Path"
        }
    } finally {
        $stream.Dispose()
    }
}

if (-not (Test-Path -LiteralPath $ToolchainCustodyHelper -PathType Leaf)) {
    throw "Android toolchain custody helper is missing: $ToolchainCustodyHelper"
}
. $ToolchainCustodyHelper

function Assert-OwnerOnlyFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Description = 'Android signing state'
    )

    Assert-NoReparsePath -Path $Path -Description $Description
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Description must be a regular non-reparse file: $Path"
    }
    Assert-SingleLinkFile -Path $item.FullName -Description $Description
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.Owner -ne $currentSid.Value -and $acl.Owner -ne $currentSid.Translate([Security.Principal.NTAccount]).Value) {
        throw "$Description is not owned by the current Windows user: $Path"
    }
    $unsafeRule = @($acl.Access | Where-Object {
        $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        $_.IdentityReference.Value -ne $currentSid.Value -and
        $_.IdentityReference.Value -ne $currentSid.Translate([Security.Principal.NTAccount]).Value
    })
    if (-not $acl.AreAccessRulesProtected -or $unsafeRule.Count -gt 0) {
        throw "$Description ACL is not owner-only: $Path"
    }
}

function Resolve-ExternalSigningFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    $resolved = [IO.Path]::GetFullPath($Path)
    $repository = [IO.Path]::GetFullPath([string]$RepoRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    if ($resolved.Equals($repository, [StringComparison]::OrdinalIgnoreCase) -or
        $resolved.StartsWith(($repository + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Description must be outside the repository release-input tree."
    }
    return $resolved
}

function Resolve-TrustedApplication {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$CandidatePath = ''
    )

    if ([string]::IsNullOrWhiteSpace($CandidatePath)) {
        $command = Get-Command $Name -ErrorAction SilentlyContinue
        if (-not $command) {
            throw "$Name is required but was not found on PATH."
        }
        if ($command.CommandType -ne 'Application') {
            throw "$Name must resolve to a real executable, not a $($command.CommandType)."
        }
        $source = $command.Source
    } else {
        $source = [IO.Path]::GetFullPath($CandidatePath)
    }
    # Get-Command can resolve a function or alias, not just a real executable
    # file, and PATH itself is attacker-influenceable; requiring CommandType
    # Application plus rejecting a symlinked .Source means every downstream
    # invocation binds to one concrete file on disk, not to whatever a
    # compromised or substituted command reports (the same reasoning already
    # applied to flutter below).
    $item = Get-Item -LiteralPath $source -ErrorAction SilentlyContinue
    if (-not $item -or $item.PSIsContainer -or $item.LinkType -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Name must resolve to one real regular executable file, not a symlink: $source"
    }
    return $item.FullName
}

function Resolve-ReviewedPython {
    $candidates = [Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($env:WINS_RELEASE_PYTHON)) {
        $candidates.Add($env:WINS_RELEASE_PYTHON)
    } else {
        $minor = ($RequiredPythonVersion -split '\.')[0..1] -join '.'
        $compact = $minor.Replace('.', '')
        if (-not [string]::IsNullOrWhiteSpace($HOME)) {
            $candidates.Add((Join-Path $HOME ".local\toolchains\python$RequiredPythonVersion\python.exe"))
            $candidates.Add((Join-Path $HOME ".local\toolchains\python$RequiredPythonVersion\bin\python.exe"))
        }
        if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
            $candidates.Add((Join-Path $env:LOCALAPPDATA "Programs\Python\Python$compact\python.exe"))
        }
        foreach ($name in @("python$minor", 'python')) {
            $command = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue
            if ($command) { $candidates.Add($command.Source) }
        }
    }
    foreach ($candidate in @($candidates | Select-Object -Unique)) {
        try {
            return Resolve-TrustedApplication -Name 'Python' -CandidatePath $candidate
        } catch {
            if (-not [string]::IsNullOrWhiteSpace($env:WINS_RELEASE_PYTHON)) { throw }
        }
    }
    throw "Android releases require exact $RequiredPythonImplementation $RequiredPythonVersion. Set WINS_RELEASE_PYTHON to its regular executable."
}

function Resolve-ReviewedFlutter {
    $candidates = [Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($env:FLUTTER_BIN)) {
        $candidates.Add($env:FLUTTER_BIN)
    } else {
        if (-not [string]::IsNullOrWhiteSpace($HOME)) {
            $candidates.Add((Join-Path $HOME ".local\toolchains\flutter-$RequiredFlutterVersion\bin\flutter.bat"))
            $candidates.Add((Join-Path $HOME '.local\flutter\bin\flutter.bat'))
        }
        if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
            $candidates.Add((Join-Path $env:LOCALAPPDATA "WinsVPN\toolchains\flutter-$RequiredFlutterVersion\bin\flutter.bat"))
        }
        $command = Get-Command flutter -CommandType Application -ErrorAction SilentlyContinue
        if ($command) { $candidates.Add($command.Source) }
    }
    foreach ($candidate in @($candidates | Select-Object -Unique)) {
        try {
            return Resolve-TrustedApplication -Name 'Flutter' -CandidatePath $candidate
        } catch {
            if (-not [string]::IsNullOrWhiteSpace($env:FLUTTER_BIN)) { throw }
        }
    }
    throw "Flutter $RequiredFlutterVersion is required. Set FLUTTER_BIN to its regular executable."
}

function Resolve-ReviewedJdk17 {
    $homes = [Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($env:JAVA_HOME)) {
        $homes.Add($env:JAVA_HOME)
    } else {
        foreach ($root in @(
            $(if ($HOME) { Join-Path $HOME '.local\jdk17' }),
            $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Programs\Eclipse Adoptium' }),
            $(if ($env:ProgramFiles) { Join-Path $env:ProgramFiles 'Eclipse Adoptium' })
        )) {
            if (-not [string]::IsNullOrWhiteSpace($root)) {
                Get-ChildItem -LiteralPath $root -Directory -Filter 'jdk-17*' -ErrorAction SilentlyContinue |
                    Sort-Object Name -Descending |
                    ForEach-Object { $homes.Add($_.FullName) }
            }
        }
        $javaCommand = Get-Command java -CommandType Application -ErrorAction SilentlyContinue
        if ($javaCommand) {
            $homes.Add((Split-Path -Parent (Split-Path -Parent $javaCommand.Source)))
        }
    }
    foreach ($home in @($homes | Select-Object -Unique)) {
        try {
            $java = Resolve-TrustedApplication -Name 'java' -CandidatePath (Join-Path $home 'bin\java.exe')
            $keytool = Resolve-TrustedApplication -Name 'keytool' -CandidatePath (Join-Path $home 'bin\keytool.exe')
            $jarsigner = Resolve-TrustedApplication -Name 'jarsigner' -CandidatePath (Join-Path $home 'bin\jarsigner.exe')
            return [pscustomobject]@{
                Home = [IO.Path]::GetFullPath($home)
                Java = $java
                Keytool = $keytool
                Jarsigner = $jarsigner
            }
        } catch {
            if (-not [string]::IsNullOrWhiteSpace($env:JAVA_HOME)) { throw }
        }
    }
    throw 'Android releases require JDK 17. Set JAVA_HOME to its regular installation.'
}

function Get-AndroidToolchainRootFromExecutable {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string]$Description
    )

    Assert-NoReparsePath -Path $Executable -Description $Description
    $item = Get-Item -LiteralPath $Executable -Force -ErrorAction Stop
    $parent = $item.Directory
    if (-not $parent) {
        throw "$Description has no installation parent: $Executable"
    }
    if ($parent.Name -ieq 'bin' -and $parent.Parent) {
        return $parent.Parent.FullName
    }
    return $parent.FullName
}

function Assert-ReviewedAndroidToolchainCustodyPreflight {
    # ANDROID_WINDOWS_CUSTODY_PREFLIGHT_BEGIN
    Assert-WinsAndroidToolchainCustodyManifestPreflight `
        -ManifestPath $ToolchainCustodyManifest -Platform 'windows_amd64'
    # ANDROID_WINDOWS_CUSTODY_PREFLIGHT_END
}

function Get-JavaPropertyValue {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Name
    )

    $match = [regex]::Match($Text, "(?m)^\s*$([regex]::Escape($Name))\s*=\s*(.+?)\s*$")
    if (-not $match.Success) {
        throw "JDK did not report the $Name property."
    }
    return $match.Groups[1].Value.Trim()
}

function Get-ReviewedPythonRuntimeIdentity {
    param([Parameter(Mandatory)][string]$PythonPath)

    $raw = (& $PythonPath -c 'import platform,sys; print("|".join([f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}", platform.python_revision(), platform.python_implementation(), platform.machine()]))' | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) {
        throw "Android release Python executable did not report a complete runtime identity: $PythonPath"
    }
    $parts = $raw.Split('|')
    if ($parts.Count -ne 4) {
        throw "Android release Python runtime identity is malformed: $raw"
    }
    return [pscustomobject]@{
        Version = $parts[0]
        Revision = $parts[1]
        Vendor = $parts[2]
        Architecture = $parts[3]
    }
}

function Get-RequiredPsObjectProperty {
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Description
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        throw "$Description is missing required field '$Name'."
    }
    $value = [string]$property.Value
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "$Description field '$Name' is empty."
    }
    return $value
}

function ConvertFrom-FlutterMachineIdentity {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Raw)

    $start = $Raw.IndexOf('{')
    $end = $Raw.LastIndexOf('}')
    if ($start -lt 0 -or $end -le $start) {
        throw 'Android release Flutter executable did not report machine-readable version identity JSON.'
    }
    $document = $Raw.Substring($start, ($end - $start + 1)) | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $document -or $document -is [object[]]) {
        throw 'Android release Flutter machine identity must be one JSON object.'
    }
    return [pscustomobject]@{
        Version = Get-RequiredPsObjectProperty -InputObject $document -Name 'frameworkVersion' `
            -Description 'Flutter --version --machine'
        Revision = Get-RequiredPsObjectProperty -InputObject $document -Name 'frameworkRevision' `
            -Description 'Flutter --version --machine'
        Vendor = Get-RequiredPsObjectProperty -InputObject $document -Name 'repositoryUrl' `
            -Description 'Flutter --version --machine'
    }
}

function Get-ReviewedFlutterRuntimeIdentity {
    param([Parameter(Mandatory)]$flutterItem)

    $raw = (& $flutterItem.FullName --version --machine | Out-String)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) {
        throw 'Android release Flutter executable did not report machine-readable version identity.'
    }
    return ConvertFrom-FlutterMachineIdentity -Raw $raw
}

function Get-ReviewedJdkRuntimeIdentity {
    param([Parameter(Mandatory)]$Jdk)

    # java -XshowSettings:properties writes the properties to STDERR even on
    # success. Under $ErrorActionPreference='Stop', PS 5.1 turns that STDERR
    # into a terminating NativeCommandError when it is merged with 2>&1.
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $reported = (& $Jdk.Java -XshowSettings:properties -version 2>&1 | Out-String)
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($reported)) {
        throw "Android release JDK did not report complete runtime properties: $($Jdk.Java)"
    }
    return [pscustomobject]@{
        Version = Get-JavaPropertyValue -Text $reported -Name 'java.version'
        Revision = Get-JavaPropertyValue -Text $reported -Name 'java.runtime.version'
        Vendor = Get-JavaPropertyValue -Text $reported -Name 'java.vendor'
        Architecture = Get-JavaPropertyValue -Text $reported -Name 'os.arch'
    }
}

function Assert-ReviewedAndroidToolchainCustody {
    param(
        [Parameter(Mandatory)][string]$PythonPath,
        [Parameter(Mandatory)][string]$FlutterPath,
        [Parameter(Mandatory)]$Jdk
    )

    $pythonRoot = Get-AndroidToolchainRootFromExecutable `
        -Executable $PythonPath -Description 'Android release Python executable'
    $flutterRoot = Get-AndroidToolchainRootFromExecutable `
        -Executable $FlutterPath -Description 'Android release Flutter executable'
    $records = @(
        Assert-WinsAndroidToolchainCustody `
            -ManifestPath $ToolchainCustodyManifest -RepoRoot $RepoRoot `
            -Platform 'windows_amd64' -Tool 'python' -Root $pythonRoot
        Assert-WinsAndroidToolchainCustody `
            -ManifestPath $ToolchainCustodyManifest -RepoRoot $RepoRoot `
            -Platform 'windows_amd64' -Tool 'flutter' -Root $flutterRoot
        Assert-WinsAndroidToolchainCustody `
            -ManifestPath $ToolchainCustodyManifest -RepoRoot $RepoRoot `
            -Platform 'windows_amd64' -Tool 'jdk' -Root $Jdk.Home
    )
    if ($records.Count -ne 3) {
        throw 'Android release toolchain custody did not bind Python, Flutter, and JDK exactly once.'
    }
    return $records
}

function Confirm-ReviewedAndroidToolchainRuntimePins {
    param(
        [Parameter(Mandatory)][string]$PythonPath,
        [Parameter(Mandatory)]$FlutterItem,
        [Parameter(Mandatory)]$Jdk,
        [Parameter(Mandatory)]$Records
    )

    $byTool = @{}
    foreach ($record in @($Records)) {
        $byTool[[string]$record.Tool] = $record
    }
    foreach ($tool in @('python', 'flutter', 'jdk')) {
        if (-not $byTool.ContainsKey($tool)) {
            throw "Authenticated Android toolchain custody is missing the $tool record."
        }
    }
    $pythonRuntime = Get-ReviewedPythonRuntimeIdentity -PythonPath $PythonPath
    $flutterRuntime = Get-ReviewedFlutterRuntimeIdentity -flutterItem $FlutterItem
    $jdkRuntime = Get-ReviewedJdkRuntimeIdentity -Jdk $Jdk
    Assert-WinsAndroidToolchainRuntimePins -Record $byTool['python'].Record -Tool 'python' `
        -RuntimeVersion $pythonRuntime.Version -RuntimeRevision $pythonRuntime.Revision `
        -RuntimeVendor $pythonRuntime.Vendor -RuntimeArchitecture $pythonRuntime.Architecture
    # FLUTTER_ARCHITECTURE_BINDING_RULE:
    # Flutter 3.47.6 `flutter --version --machine` emits frameworkVersion,
    # frameworkRevision, and repositoryUrl. It does not emit architecture.
    # Windows Flutter architecture is bound by the already-authenticated
    # windows_amd64 archive_sha256 plus install_tree_sha256 for this platform
    # record, not by a nonexistent --machine field.
    Assert-WinsAndroidToolchainRuntimePins -Record $byTool['flutter'].Record -Tool 'flutter' `
        -RuntimeVersion $flutterRuntime.Version -RuntimeRevision $flutterRuntime.Revision `
        -RuntimeVendor $flutterRuntime.Vendor `
        -RuntimeArchitecture ([string]$byTool['flutter'].PinArchitecture)
    Assert-WinsAndroidToolchainRuntimePins -Record $byTool['jdk'].Record -Tool 'jdk' `
        -RuntimeVersion $jdkRuntime.Version -RuntimeRevision $jdkRuntime.Revision `
        -RuntimeVendor $jdkRuntime.Vendor -RuntimeArchitecture $jdkRuntime.Architecture
    if ($pythonRuntime.Version -cne $RequiredPythonVersion -or
        $pythonRuntime.Vendor.ToLowerInvariant() -cne $RequiredPythonImplementation) {
        throw "Android release Python identity does not match the reviewed toolchain pin: $($pythonRuntime.Vendor) $($pythonRuntime.Version)."
    }
    if ($flutterRuntime.Version -cne $RequiredFlutterVersion -or
        $flutterRuntime.Revision -cne $RequiredFlutterRevision) {
        throw "Android release builds require reviewed Flutter $RequiredFlutterVersion ($RequiredFlutterRevision); found $($flutterRuntime.Version) ($($flutterRuntime.Revision)). Update the toolchain deliberately, then rerun."
    }
    return [pscustomobject]@{
        Python = $pythonRuntime
        Flutter = $flutterRuntime
        Jdk = $jdkRuntime
    }
}

function Assert-ExpectedAndroidSigner {
    if ([string]::IsNullOrWhiteSpace($script:KeytoolPath)) {
        $jdk = Resolve-ReviewedJdk17
        $env:JAVA_HOME = $jdk.Home
        $script:KeytoolPath = $jdk.Keytool
        $script:JarsignerPath = $jdk.Jarsigner
        $script:JavaPath = $jdk.Java
    }
    $keytoolPath = $script:KeytoolPath
    # keytool writes the cert to STDOUT but a trailing notice to STDERR even
    # on success. Under $ErrorActionPreference='Stop', PS 5.1 turns that STDERR
    # into a terminating NativeCommandError the moment it is merged with 2>&1,
    # so this assertion could never complete (it fails on a VALID keystore).
    # Redact STDERR from the success stream by lowering EAP around the call;
    # the digest is read from STDOUT and $LASTEXITCODE still reflects keytool's
    # real status below. Verified on 2026-08-10: the keystore is valid, the
    # cert digest matches, and the assertion passes.
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $certificate = (& $keytoolPath -list -v `
            -keystore $env:WINS_ANDROID_KEYSTORE `
            -alias $env:WINS_ANDROID_KEY_ALIAS `
            '-storepass:env' WINS_ANDROID_STORE_PASSWORD 2>&1 | Out-String)
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($LASTEXITCODE -ne 0) {
        throw 'OWNER-BLOCKED: The configured Android upload certificate could not be read.'
    }
    $match = [regex]::Match($certificate, '(?im)^\s*SHA256:\s*([0-9A-F:]+)\s*$')
    $certificate = $null
    if (-not $match.Success) {
        throw 'The configured Android upload certificate SHA-256 digest was not reported.'
    }
    $digest = $match.Groups[1].Value.Replace(':', '').ToLowerInvariant()
    if ($digest -cne $ExpectedUploadCertificateSha256) {
        throw "Unexpected Android upload signer: sha256=$digest"
    }
}

function Import-AndroidSigningEnvironment {
    $names = @(
        'WINS_ANDROID_KEYSTORE',
        'WINS_ANDROID_KEY_ALIAS',
        'WINS_ANDROID_KEY_PASSWORD',
        'WINS_ANDROID_STORE_PASSWORD'
    )
    $present = @($names | Where-Object { -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_, 'Process')) })
    if ($present.Count -gt 0) {
        if ($present.Count -ne $names.Count) {
            $missing = @($names | Where-Object { [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_, 'Process')) })
            throw "OWNER-BLOCKED: $($missing[0]) is required; missing owner keystore remains blocked."
        }
        $keystore = Resolve-ExternalSigningFile `
            -Path ([Environment]::GetEnvironmentVariable('WINS_ANDROID_KEYSTORE', 'Process')) `
            -Description 'The Android signing keystore'
        if (-not (Test-Path -LiteralPath $keystore -PathType Leaf) -or
            (Get-Item -LiteralPath $keystore -Force).Length -le 0) {
            throw 'OWNER-BLOCKED: missing Android upload keystore'
        }
        Assert-OwnerOnlyFile -Path $keystore
        $env:WINS_ANDROID_KEYSTORE = $keystore
        return
    }
    $externalSigningStore = Resolve-ExternalSigningFile `
        -Path $SigningStorePath `
        -Description 'The Android signing DPAPI store'
    if (-not (Test-Path -LiteralPath $externalSigningStore -PathType Leaf)) {
        throw 'OWNER-BLOCKED: missing Android upload keystore'
    }

    Assert-OwnerOnlyFile -Path $externalSigningStore
    Add-Type -AssemblyName System.Security
    $secure = (Get-Content -LiteralPath $externalSigningStore -Raw).Trim() | ConvertTo-SecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $json = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $signing = $json | ConvertFrom-Json
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        $json = $null
    }
    foreach ($property in @('storeFile', 'keyAlias', 'keyPassword', 'storePassword')) {
        if ([string]::IsNullOrWhiteSpace([string]$signing.$property)) {
            throw "Android signing DPAPI state is missing $property."
        }
    }
    $keystore = Resolve-ExternalSigningFile `
        -Path ([string]$signing.storeFile) `
        -Description 'The Android signing keystore'
    if (-not (Test-Path -LiteralPath $keystore -PathType Leaf) -or
        (Get-Item -LiteralPath $keystore -Force).Length -le 0) {
        throw 'OWNER-BLOCKED: missing Android upload keystore'
    }
    Assert-OwnerOnlyFile -Path $keystore

    $env:WINS_ANDROID_KEYSTORE = $keystore
    $env:WINS_ANDROID_KEY_ALIAS = [string]$signing.keyAlias
    $env:WINS_ANDROID_KEY_PASSWORD = [string]$signing.keyPassword
    $env:WINS_ANDROID_STORE_PASSWORD = [string]$signing.storePassword
    $signing = $null
    $script:LoadedSigningEnvironment = $true
}

function Clear-AndroidSigningEnvironment {
    if (-not $script:LoadedSigningEnvironment) { return }
    foreach ($name in @(
        'WINS_ANDROID_KEYSTORE',
        'WINS_ANDROID_KEY_ALIAS',
        'WINS_ANDROID_KEY_PASSWORD',
        'WINS_ANDROID_STORE_PASSWORD'
    )) {
        [Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }
    $script:LoadedSigningEnvironment = $false
}

function Enter-ReleaseBuildLock {
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $BuildLockDir))
    try {
        New-Item -ItemType Directory -Path $BuildLockDir -ErrorAction Stop | Out-Null
    } catch {
        $owner = 'owner metadata is not available'
        if (Test-Path -LiteralPath $BuildLockOwnerFile -PathType Leaf) {
            $owner = ((Get-Content -LiteralPath $BuildLockOwnerFile -Raw -ErrorAction SilentlyContinue) + '').Trim()
            if ([string]::IsNullOrWhiteSpace($owner)) { $owner = 'owner metadata is not available' }
        }
        throw "Another Windows/WSL release build owns $BuildLockDir. $owner. Wait for it to finish; never delete an active lock."
    }
    $script:BuildLockAcquired = $true
    $ownerText = @(
        'platform=android'
        "pid=$PID"
        "started_utc=$([DateTime]::UtcNow.ToString('o'))"
    ) -join "`n"
    [IO.File]::WriteAllText($BuildLockOwnerFile, $ownerText + "`n", [Text.UTF8Encoding]::new($false))
}

function Exit-ReleaseBuildLock {
    if (-not $script:BuildLockAcquired) { return }
    $releasedLockDir = "$BuildLockDir.released.$PID.$([guid]::NewGuid().ToString('N'))"
    # Rename the complete lock before cleanup. This never exposes an ownerless
    # canonical lock directory if deletion is interrupted or antivirus delays it.
    Move-Item -LiteralPath $BuildLockDir -Destination $releasedLockDir -ErrorAction Stop
    $script:BuildLockAcquired = $false
    Remove-Item -LiteralPath $releasedLockDir -Recurse -Force -ErrorAction SilentlyContinue
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$FailureMessage
    )
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) { throw $FailureMessage }
}

function Resolve-PrivateArtifactPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Label,
        [switch]$RequireExistingFile,
        [switch]$RequireNewDirectory
    )

    $candidate = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    } else {
        [IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
    }
    $repoPrefix = $RepoRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $artifactsRoot = [IO.Path]::GetFullPath((Join-Path $RepoRoot '.artifacts')).TrimEnd('\', '/')
    $artifactsPrefix = $artifactsRoot + [IO.Path]::DirectorySeparatorChar
    if (-not $candidate.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not $candidate.StartsWith($artifactsPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must stay under the repository .artifacts directory."
    }
    $relative = $candidate.Substring($RepoRoot.TrimEnd('\', '/').Length).TrimStart('\', '/')
    $current = $RepoRoot
    $parts = $relative -split '[\\/]'
    for ($index = 0; $index -lt $parts.Count; $index++) {
        $current = Join-Path $current $parts[$index]
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "$Label must not traverse a reparse point: $current"
            }
        }
    }
    if ($RequireExistingFile -and -not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "$Label does not exist: $candidate"
    }
    if ($RequireNewDirectory -and (Test-Path -LiteralPath $candidate)) {
        throw "$Label must be a new immutable directory: $candidate"
    }
    return $candidate
}

function Initialize-FormalBuildReceipts {
    param(
        [Parameter(Mandatory)][string]$IndexPath,
        [Parameter(Mandatory)][string]$ReceiptDirectory
    )

    if ([IO.Path]::GetFileName($IndexPath) -cne 'RELEASE_INPUT_INDEX.json') {
        throw 'ReleaseInputIndex must name RELEASE_INPUT_INDEX.json.'
    }
    $paths = [ordered]@{
        ApkBegin = Join-Path $ReceiptDirectory 'ANDROID_APK_BUILD_BEGIN.json'
        AabBegin = Join-Path $ReceiptDirectory 'ANDROID_AAB_BUILD_BEGIN.json'
        TvApkBegin = Join-Path $ReceiptDirectory 'ANDROID_TV_APK_BUILD_BEGIN.json'
        TvAabBegin = Join-Path $ReceiptDirectory 'ANDROID_TV_AAB_BUILD_BEGIN.json'
        ApkReceipt = Join-Path $ReceiptDirectory 'ANDROID_APK_BUILD_RECEIPT.json'
        AabReceipt = Join-Path $ReceiptDirectory 'ANDROID_AAB_BUILD_RECEIPT.json'
        TvApkReceipt = Join-Path $ReceiptDirectory 'ANDROID_TV_APK_BUILD_RECEIPT.json'
        TvAabReceipt = Join-Path $ReceiptDirectory 'ANDROID_TV_AAB_BUILD_RECEIPT.json'
    }
    # M-1: fail before any Android APK/AAB is accepted if a committed
    # Xray/AmneziaWG binary embeds a Go runtime with known-fixed stdlib CVEs.
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        (Join-Path $RepoRoot 'tools\verify_embedded_engine_runtime_versions.py')
    ) -FailureMessage 'Embedded engine (Xray/AmneziaWG) Go runtime freshness check failed before build.' | Out-Host
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $DependencyFreezeTool, 'verify-index', '--repo', $RepoRoot, '--index', $IndexPath,
        '--platform', 'android'
    ) -FailureMessage 'Android release input index verification failed before build.' | Out-Host
    $bash = Get-Command bash -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $bash) {
        throw 'bash is required for the Android release engine source gate.'
    }
    Invoke-Checked -FilePath $bash.Source -ArgumentList @(
        (Join-Path $RepoRoot 'android/tools/prepare_android_winn_assets.sh'),
        '--verify'
    ) -FailureMessage 'Android release engine source gate failed before build.' | Out-Host
    New-Item -ItemType Directory -Path $ReceiptDirectory -ErrorAction Stop | Out-Null
    foreach ($begin in @($paths.ApkBegin, $paths.AabBegin, $paths.TvApkBegin, $paths.TvAabBegin)) {
        Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
            $DependencyFreezeTool, 'begin-build', '--repo', $RepoRoot,
            '--index', $IndexPath, '--platform', 'android', '--output', $begin
        ) -FailureMessage "Android formal build-begin receipt creation failed: $begin" | Out-Host
    }
    return [pscustomobject]$paths
}

function Complete-FormalBuildReceipt {
    param(
        [Parameter(Mandatory)][string]$IndexPath,
        [Parameter(Mandatory)][string]$BeginPath,
        [Parameter(Mandatory)][string]$ArtifactPath,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string]$FlutterVersion,
        [Parameter(Mandatory)][string]$FlutterRevision
    )

    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $DependencyFreezeTool, 'finish-build', '--repo', $RepoRoot,
        '--index', $IndexPath, '--platform', 'android', '--begin', $BeginPath,
        '--artifact', $ArtifactPath, '--producer', 'tools/build_android_release.ps1',
        '--toolchain-name', 'Flutter', '--toolchain-version', $FlutterVersion,
        '--toolchain-revision', $FlutterRevision, '--target', $Target, '--output', $OutputPath
    ) -FailureMessage "Android formal exact-artifact receipt creation failed: $OutputPath"
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $DependencyFreezeTool, 'verify-receipt', '--repo', $RepoRoot,
        '--index', $IndexPath, '--platform', 'android', '--receipt', $OutputPath,
        '--artifact', $ArtifactPath
    ) -FailureMessage "Android formal exact-artifact receipt verification failed: $OutputPath"
}

function Get-NeutralInputSnapshot {
    param([Parameter(Mandatory)][string]$Root)

    $resolvedRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $selected = [Collections.Generic.List[IO.FileInfo]]::new()
    foreach ($relative in $NeutralInputFiles) {
        $path = Join-Path $resolvedRoot ($relative -replace '/', [IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required Android release input is missing: $relative"
        }
        $item = Get-Item -LiteralPath $path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Android release inputs cannot contain a reparse file: $relative"
        }
        $selected.Add($item)
    }
    foreach ($relative in $NeutralInputDirectories) {
        $path = Join-Path $resolvedRoot $relative
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            throw "Required Android release input directory is missing: $relative"
        }
        if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Android release inputs cannot contain a reparse directory: $relative"
        }
        foreach ($item in Get-ChildItem -LiteralPath $path -File -Recurse -Force) {
            $childRelative = $item.FullName.Substring($resolvedRoot.Length).TrimStart('\', '/')
            $parts = $childRelative -split '[\\/]'
            if ($parts -contains '.gradle' -or $parts -contains 'build' -or
                $item.Name -eq 'local.properties') {
                continue
            }
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Android release inputs cannot contain a reparse file: $childRelative"
            }
            $selected.Add($item)
        }
        foreach ($link in Get-ChildItem -LiteralPath $path -Directory -Recurse -Force | Where-Object {
            $_.Attributes -band [IO.FileAttributes]::ReparsePoint
        }) {
            $childRelative = $link.FullName.Substring($resolvedRoot.Length).TrimStart('\', '/')
            throw "Android release inputs cannot contain a reparse directory: $childRelative"
        }
    }
    return @($selected | Sort-Object FullName -Unique | ForEach-Object {
        [pscustomobject]@{
            RelativePath = $_.FullName.Substring($resolvedRoot.Length).TrimStart('\', '/').Replace('\', '/')
            Sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
            Bytes = $_.Length
        }
    })
}

function Assert-IdenticalInputSnapshots {
    param(
        [Parameter(Mandatory)][object[]]$Expected,
        [Parameter(Mandatory)][object[]]$Actual,
        [Parameter(Mandatory)][string]$Context
    )

    $expectedJson = $Expected | ConvertTo-Json -Depth 3 -Compress
    $actualJson = $Actual | ConvertTo-Json -Depth 3 -Compress
    if ($expectedJson -cne $actualJson) {
        throw "Android release input snapshot changed during $Context. Restart from a stable source tree."
    }
}

function Initialize-NeutralStage {
    $systemRoot = [IO.Path]::GetPathRoot([Environment]::SystemDirectory)
    $base = [IO.Path]::GetFullPath($NeutralStageBase)
    if (-not $base.StartsWith($systemRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $base -match '(?i)\\Users\\|\\Documents and Settings\\') {
        throw "Android neutral staging root must be a non-profile path on the system drive: $base"
    }
    if (Test-Path -LiteralPath $base) {
        $baseItem = Get-Item -LiteralPath $base -Force
        if (-not $baseItem.PSIsContainer -or
            ($baseItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Android neutral staging base is not a regular directory: $base"
        }
    } else {
        [void][IO.Directory]::CreateDirectory($base)
    }
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    & icacls.exe $base '/inheritance:r' '/grant:r' `
        "*$($currentSid.Value):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not harden the Android neutral staging base ACL: $base"
    }
    $stageContainer = Join-Path $base ([guid]::NewGuid().ToString('N'))
    $stageRepo = Join-Path $stageContainer 'source'
    [void][IO.Directory]::CreateDirectory($stageContainer)
    try {
        # The common base may inherit a system-drive DACL. The unique stage itself
        # is the security boundary and is hardened before any release input enters it.
        & icacls.exe $stageContainer '/inheritance:r' '/grant:r' `
            "*$($currentSid.Value):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Could not harden the Android neutral staging ACL: $stageContainer"
        }
        [void][IO.Directory]::CreateDirectory($stageRepo)
        & icacls.exe $stageRepo '/inheritance:r' '/grant:r' `
            "*$($currentSid.Value):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Could not harden the Android neutral source ACL: $stageRepo"
        }
        Assert-NeutralStageRuntime -StageRepo $stageRepo
        return [pscustomobject]@{
            Base = $base
            Container = $stageContainer
            Repo = $stageRepo
        }
    } catch {
        if (Test-Path -LiteralPath $stageContainer) {
            [IO.Directory]::Delete($stageContainer, $true)
        }
        throw
    }
}

function Assert-NeutralStageRuntime {
    param([Parameter(Mandatory)][string]$StageRepo)

    $repo = [IO.Path]::GetFullPath($StageRepo).TrimEnd('\', '/')
    $container = [IO.Path]::GetFullPath((Split-Path -Parent $repo)).TrimEnd('\', '/')
    $base = [IO.Path]::GetFullPath((Split-Path -Parent $container)).TrimEnd('\', '/')
    if ($base -cne [IO.Path]::GetFullPath($NeutralStageBase).TrimEnd('\', '/') -or
        (Split-Path -Leaf $repo) -cne 'source' -or
        (Split-Path -Leaf $container) -notmatch '^[0-9a-f]{32}$') {
        throw "Android staged-build mode requires the producer-owned neutral path: $repo"
    }
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    foreach ($path in @($base, $container, $repo)) {
        $item = Get-Item -LiteralPath $path -Force
        if (-not $item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Android neutral staging path is not a regular directory: $path"
        }
        $acl = Get-Acl -LiteralPath $path
        $rules = @($acl.Access | Where-Object {
            $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow
        })
        $allowed = @($currentSid.Value, $systemSid.Value)
        $unsafe = @($rules | Where-Object {
            $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed
        })
        if ($unsafe.Count -gt 0 -or -not $acl.AreAccessRulesProtected -or
            ($acl.Owner -ne $currentSid.Value -and
             $acl.Owner -ne $currentSid.Translate([Security.Principal.NTAccount]).Value)) {
            throw "Android neutral staging ACL verification failed: $path"
        }
    }
}

function Copy-NeutralInputs {
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$DestinationRoot,
        [Parameter(Mandatory)][object[]]$Snapshot
    )

    foreach ($entry in $Snapshot) {
        $source = Join-Path $SourceRoot ($entry.RelativePath -replace '/', [IO.Path]::DirectorySeparatorChar)
        $destination = Join-Path $DestinationRoot ($entry.RelativePath -replace '/', [IO.Path]::DirectorySeparatorChar)
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $destination))
        Copy-Item -LiteralPath $source -Destination $destination -Force
    }
}

function New-PreparedReleaseFile {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Leaf) -or
        (Get-Item -LiteralPath $Source).Length -le 0) {
        throw "OWNER-BLOCKED: produced Android AAB/APK bytes are absent: $Source"
    }
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $Destination))
    $temporary = Join-Path (Split-Path -Parent $Destination) (
        '.winsvpn-android-publication-prepared-' + [guid]::NewGuid().ToString('N') +
        [IO.Path]::GetExtension($Destination)
    )
    try {
        Copy-Item -LiteralPath $Source -Destination $temporary -ErrorAction Stop
        $sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Source).Hash
        $copyHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $temporary).Hash
        if ($sourceHash -cne $copyHash) {
            throw "Staged Android release output changed while copying: $Source"
        }
        return $temporary
    } catch {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        throw
    }
}

function New-PreparedSymbolDirectory {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$PrivateRoot
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Container) -or
        ((Get-Item -LiteralPath $Source -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Staged Android private-symbol directory is unsafe or missing: $Source"
    }
    foreach ($item in Get-ChildItem -LiteralPath $Source -Recurse -Force) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Staged Android private symbols contain a reparse point: $($item.FullName)"
        }
    }
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $Destination))
    $temporary = Join-Path (Split-Path -Parent $Destination) (
        '.winsvpn-android-publication-prepared-' + [guid]::NewGuid().ToString('N')
    )
    try {
        Initialize-PrivateSymbolDirectory -PrivateRoot $PrivateRoot -Path $temporary
        foreach ($item in Get-ChildItem -LiteralPath $source -Force) {
            Copy-Item -LiteralPath $item.FullName -Destination $temporary -Recurse -Force -ErrorAction Stop
        }
        return $temporary
    } catch {
        Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Publish-NeutralStageOutputs {
    param(
        [Parameter(Mandatory)][string]$StageRepo,
        [Parameter(Mandatory)][string]$DestinationRepo,
        [Parameter(Mandatory)][string]$ReleaseInputIndex
    )

    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $PublicationState))
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $PublicationTool, 'recover', '--state', $PublicationState
    ) -FailureMessage 'A prior Android release publication transaction could not be recovered.' | Out-Host

    $stageSymbolsRoot = Join-Path $StageRepo '.artifacts\private-release-symbols'
    $stagedApkSymbols = Join-Path $stageSymbolsRoot "android-apk\$VersionIdentity"
    $stagedAabSymbols = Join-Path $stageSymbolsRoot "android-aab\$VersionIdentity"
    $stagedTvApkSymbols = Join-Path $stageSymbolsRoot "android-tv-apk\$VersionIdentity"
    $stagedTvAabSymbols = Join-Path $stageSymbolsRoot "android-tv-aab\$VersionIdentity"
    $stagedApk = Join-Path $StageRepo 'build\app\outputs\flutter-apk\app-phone-release.apk'
    $stagedAab = Join-Path $StageRepo 'build\app\outputs\bundle\phoneRelease\app-phone-release.aab'
    $stagedTvApk = Join-Path $StageRepo 'build\app\outputs\flutter-apk\app-tv-release.apk'
    $stagedTvAab = Join-Path $StageRepo 'build\app\outputs\bundle\tvRelease\app-tv-release.aab'
    $destinationSymbolsRoot = Join-Path $DestinationRepo '.artifacts\private-release-symbols'
    $destinationApkSymbols = Join-Path $destinationSymbolsRoot "android-apk\$VersionIdentity"
    $destinationAabSymbols = Join-Path $destinationSymbolsRoot "android-aab\$VersionIdentity"
    $destinationTvApkSymbols = Join-Path $destinationSymbolsRoot "android-tv-apk\$VersionIdentity"
    $destinationTvAabSymbols = Join-Path $destinationSymbolsRoot "android-tv-aab\$VersionIdentity"
    $destinationApk = Join-Path $DestinationRepo 'build\app\outputs\flutter-apk\app-release.apk'
    $destinationAab = Join-Path $DestinationRepo 'build\app\outputs\bundle\release\app-release.aab'
    $destinationTvApk = Join-Path $DestinationRepo 'build\app\outputs\flutter-apk\app-tv-release.apk'
    $destinationTvAab = Join-Path $DestinationRepo 'build\app\outputs\bundle\tvRelease\app-tv-release.aab'
    $prepared = [Collections.Generic.List[string]]::new()
    try {
        $preparedApkSymbols = New-PreparedSymbolDirectory `
            -Source $stagedApkSymbols -Destination $destinationApkSymbols `
            -PrivateRoot $destinationSymbolsRoot
        $prepared.Add($preparedApkSymbols)
        $preparedAabSymbols = New-PreparedSymbolDirectory `
            -Source $stagedAabSymbols -Destination $destinationAabSymbols `
            -PrivateRoot $destinationSymbolsRoot
        $prepared.Add($preparedAabSymbols)
        $preparedTvApkSymbols = New-PreparedSymbolDirectory `
            -Source $stagedTvApkSymbols -Destination $destinationTvApkSymbols `
            -PrivateRoot $destinationSymbolsRoot
        $prepared.Add($preparedTvApkSymbols)
        $preparedTvAabSymbols = New-PreparedSymbolDirectory `
            -Source $stagedTvAabSymbols -Destination $destinationTvAabSymbols `
            -PrivateRoot $destinationSymbolsRoot
        $prepared.Add($preparedTvAabSymbols)
        $preparedApk = New-PreparedReleaseFile -Source $stagedApk -Destination $destinationApk
        $prepared.Add($preparedApk)
        $preparedAab = New-PreparedReleaseFile -Source $stagedAab -Destination $destinationAab
        $prepared.Add($preparedAab)
        $preparedTvApk = New-PreparedReleaseFile -Source $stagedTvApk -Destination $destinationTvApk
        $prepared.Add($preparedTvApk)
        $preparedTvAab = New-PreparedReleaseFile -Source $stagedTvAab -Destination $destinationTvAab
        $prepared.Add($preparedTvAab)
        foreach ($pair in @(
            @($stagedApk, $preparedApk),
            @($stagedAab, $preparedAab),
            @($stagedTvApk, $preparedTvApk),
            @($stagedTvAab, $preparedTvAab)
        )) {
            $sourceDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $pair[0]).Hash
            $preparedDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $pair[1]).Hash
            if ($sourceDigest -cne $preparedDigest) {
                throw 'Prepared Android artifact bytes differ from the fully verified staged artifact.'
            }
        }

        # Verify the complete prepared set before the first canonical path is
        # renamed. Post-commit checks remain inside the open transaction so a
        # failure restores the complete prior set.
        foreach ($specification in @(
            @{ Platform = 'android-apk'; Symbols = $preparedApkSymbols; Artifact = $preparedApk },
            @{ Platform = 'android-aab'; Symbols = $preparedAabSymbols; Artifact = $preparedAab },
            @{ Platform = 'android-apk'; Symbols = $preparedTvApkSymbols; Artifact = $preparedTvApk },
            @{ Platform = 'android-aab'; Symbols = $preparedTvAabSymbols; Artifact = $preparedTvAab }
        )) {
            Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
                $ObfuscationContract, 'verify', '--platform', $specification.Platform,
                '--symbols-dir', $specification.Symbols,
                '--manifest', (Join-Path $specification.Symbols 'manifest.json'),
                '--artifact', $specification.Artifact
            ) -FailureMessage "Prepared Android $($specification.Platform) obfuscation verification failed."
            Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
                $CustodyTool, 'verify', '--platform', $specification.Platform,
                '--symbols-dir', $specification.Symbols, '--artifact', $specification.Artifact
            ) -FailureMessage "Prepared Android $($specification.Platform) private-symbol custody verification failed."
        }
        # Prepared copies have temporary filenames, so exact-target privacy
        # checks run on the canonical staged paths and again after publication.
        # Digest equality above binds each prepared copy to its staged scan.
        $commitArguments = @($PublicationTool, 'commit', '--state', $PublicationState)
        foreach ($pair in @(
            @($preparedApkSymbols, $destinationApkSymbols),
            @($preparedAabSymbols, $destinationAabSymbols),
            @($preparedTvApkSymbols, $destinationTvApkSymbols),
            @($preparedTvAabSymbols, $destinationTvAabSymbols),
            @($preparedApk, $destinationApk),
            @($preparedAab, $destinationAab),
            @($preparedTvApk, $destinationTvApk),
            @($preparedTvAab, $destinationTvAab)
        )) {
            $commitArguments += @('--pair', $pair[0], $pair[1])
        }
        Invoke-Checked -FilePath $script:PythonPath -ArgumentList $commitArguments `
            -FailureMessage 'Android APK/AAB/symbol publication transaction failed.' | Out-Host

        foreach ($specification in @(
            @{ Platform = 'android-apk'; Symbols = $destinationApkSymbols; Artifact = $destinationApk },
            @{ Platform = 'android-aab'; Symbols = $destinationAabSymbols; Artifact = $destinationAab },
            @{ Platform = 'android-apk'; Symbols = $destinationTvApkSymbols; Artifact = $destinationTvApk },
            @{ Platform = 'android-aab'; Symbols = $destinationTvAabSymbols; Artifact = $destinationTvAab }
        )) {
            Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
                $ObfuscationContract, 'verify', '--platform', $specification.Platform,
                '--symbols-dir', $specification.Symbols,
                '--manifest', (Join-Path $specification.Symbols 'manifest.json'),
                '--artifact', $specification.Artifact
            ) -FailureMessage "Published Android $($specification.Platform) obfuscation verification failed."
            Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
                $CustodyTool, 'verify', '--platform', $specification.Platform,
                '--symbols-dir', $specification.Symbols, '--artifact', $specification.Artifact
            ) -FailureMessage "Published Android $($specification.Platform) private-symbol custody verification failed."
        }
        foreach ($privacySpecification in @(
            @{ Target = 'android-phone-tablet-apk'; Artifact = $destinationApk },
            @{ Target = 'android-phone-tablet-aab'; Artifact = $destinationAab },
            @{ Target = 'android-tv-apk'; Artifact = $destinationTvApk },
            @{ Target = 'android-tv-aab'; Artifact = $destinationTvAab }
        )) {
            Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
                $PrivacyValidator, '--artifacts', '--target', $privacySpecification.Target,
                '--artifact', $privacySpecification.Artifact
            ) -FailureMessage 'Published Android release artifact privacy verification failed.'
        }
        foreach ($pair in @(
            @($stagedApk, $destinationApk),
            @($stagedAab, $destinationAab),
            @($stagedTvApk, $destinationTvApk),
            @($stagedTvAab, $destinationTvAab)
        )) {
            $sourceDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $pair[0]).Hash
            $publishedDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $pair[1]).Hash
            if ($sourceDigest -cne $publishedDigest) {
                throw 'Canonical Android artifact bytes differ from the fully verified staged artifact.'
            }
        }
        Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
            $DependencyFreezeTool, 'verify-index', '--repo', $DestinationRepo,
            '--index', $ReleaseInputIndex, '--platform', 'android'
        ) -FailureMessage 'Android release inputs changed before publication finalization.'
        Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
            $PublicationTool, 'finalize', '--state', $PublicationState
        ) -FailureMessage 'Android publication transaction finalization failed.' | Out-Host
    } catch {
        $publicationError = $_
        if (Test-Path -LiteralPath $PublicationState -PathType Leaf) {
            try {
                Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
                    $PublicationTool, 'rollback', '--state', $PublicationState
                ) -FailureMessage 'Android publication rollback failed.' | Out-Host
            } catch {
                throw "Android publication failed ($($publicationError.Exception.Message)) and rollback failed ($($_.Exception.Message)). Preserve $PublicationState for recovery."
            }
        }
        throw $publicationError
    } finally {
        if (-not (Test-Path -LiteralPath $PublicationState)) {
            foreach ($path in $prepared) {
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Get-ApkSigner {
    $sdkRoot = if ($env:ANDROID_SDK_ROOT) {
        $env:ANDROID_SDK_ROOT
    } elseif ($env:ANDROID_HOME) {
        $env:ANDROID_HOME
    } else {
        Join-Path $env:LOCALAPPDATA 'Android\Sdk'
    }
    $buildToolsRoot = Join-Path $sdkRoot 'build-tools'
    $candidates = @(Get-ChildItem -LiteralPath $buildToolsRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $candidate = Join-Path $_.FullName 'apksigner.bat'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            [pscustomobject]@{ Version = [version]$_.Name; Path = $candidate }
        }
    } | Sort-Object Version -Descending)
    if ($candidates.Count -eq 0) {
        throw "No Android SDK apksigner was found under $buildToolsRoot."
    }
    return $candidates[0].Path
}

function Get-ZipAlign {
    $apkSigner = Get-ApkSigner
    $candidate = Join-Path (Split-Path -Parent $apkSigner) 'zipalign.exe'
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "No Android SDK zipalign was found beside $apkSigner."
    }
    return $candidate
}

if ($SelfTestBuildLock) {
    try {
        Enter-ReleaseBuildLock
        try {
            New-Item -ItemType Directory -Path $BuildLockDir -ErrorAction Stop | Out-Null
            throw 'Android release build-lock self-test acquired the same lock twice.'
        } catch [System.IO.IOException] {
            # Expected: the first acquisition owns the directory.
        }
    } finally {
        Exit-ReleaseBuildLock
    }
    if (Test-Path -LiteralPath $BuildLockDir) {
        throw 'Android release build-lock self-test left a stale lock directory.'
    }
    Write-Output 'ANDROID RELEASE BUILD LOCK SELF-TEST: PASS'
    exit 0
}

if ($SelfTestSigningStore) {
    # ANDROID_WINDOWS_CUSTODY_PREFLIGHT_BEGIN
    Assert-ReviewedAndroidToolchainCustodyPreflight
    # ANDROID_WINDOWS_CUSTODY_PREFLIGHT_END
    try {
        $jdk = Resolve-ReviewedJdk17
        $jdkRecord = Assert-WinsAndroidToolchainCustody `
            -ManifestPath $ToolchainCustodyManifest -RepoRoot $RepoRoot `
            -Platform 'windows_amd64' -Tool 'jdk' -Root $jdk.Home
        $jdkRuntime = Get-ReviewedJdkRuntimeIdentity -Jdk $jdk
        Assert-WinsAndroidToolchainRuntimePins -Record $jdkRecord.Record -Tool 'jdk' `
            -RuntimeVersion $jdkRuntime.Version -RuntimeRevision $jdkRuntime.Revision `
            -RuntimeVendor $jdkRuntime.Vendor -RuntimeArchitecture $jdkRuntime.Architecture
        $env:JAVA_HOME = $jdk.Home
        $script:JarsignerPath = $jdk.Jarsigner
        $script:KeytoolPath = $jdk.Keytool
        $script:JavaPath = $jdk.Java
        Import-AndroidSigningEnvironment
        foreach ($name in @(
            'WINS_ANDROID_KEYSTORE',
            'WINS_ANDROID_KEY_ALIAS',
            'WINS_ANDROID_KEY_PASSWORD',
            'WINS_ANDROID_STORE_PASSWORD'
        )) {
            if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name, 'Process'))) {
                throw "Android signing-store self-test did not materialize $name."
            }
        }
        Assert-ExpectedAndroidSigner
        $gradleOutput = (& (Join-Path $RepoRoot 'android\gradlew.bat') -p android `
            :app:validateSigningRelease --no-daemon --console=plain 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw 'Android signing-store self-test could not validate the release keystore, alias, or credentials.'
        }
        $gradleOutput = $null
    } finally {
        Clear-AndroidSigningEnvironment
    }
    Write-Output 'ANDROID RELEASE SIGNING STORE SELF-TEST: PASS'
    exit 0
}

if ($SelfTestNeutralStaging) {
    $stage = $null
    try {
        $before = @(Get-NeutralInputSnapshot -Root $RepoRoot)
        $stage = Initialize-NeutralStage
        Copy-NeutralInputs -SourceRoot $RepoRoot -DestinationRoot $stage.Repo -Snapshot $before
        $copied = @(Get-NeutralInputSnapshot -Root $stage.Repo)
        Assert-IdenticalInputSnapshots -Expected $before -Actual $copied -Context 'neutral-staging self-test copy'
        $after = @(Get-NeutralInputSnapshot -Root $RepoRoot)
        Assert-IdenticalInputSnapshots -Expected $before -Actual $after -Context 'neutral-staging self-test source verification'
        Write-Output 'ANDROID NEUTRAL STAGING SELF-TEST: PASS'
    } finally {
        if ($stage -and (Test-Path -LiteralPath $stage.Container)) {
            Remove-Item -LiteralPath $stage.Container -Recurse -Force
        }
    }
    exit 0
}

# ANDROID_WINDOWS_CUSTODY_PREFLIGHT_BEGIN
Assert-ReviewedAndroidToolchainCustodyPreflight
# ANDROID_WINDOWS_CUSTODY_PREFLIGHT_END
$script:PythonPath = Resolve-ReviewedPython
$flutterPath = Resolve-ReviewedFlutter
$flutterItem = Get-Item -LiteralPath $flutterPath -ErrorAction Stop
$jdk = Resolve-ReviewedJdk17
$env:JAVA_HOME = $jdk.Home
$script:JarsignerPath = $jdk.Jarsigner
$script:KeytoolPath = $jdk.Keytool
$script:JavaPath = $jdk.Java
$jarsignerPath = $script:JarsignerPath
$keytoolPath = $script:KeytoolPath
$javaPath = $script:JavaPath
# ANDROID_WINDOWS_CUSTODY_TREES_AUTHENTICATED
$script:AndroidToolchainCustody = @(Assert-ReviewedAndroidToolchainCustody `
    -PythonPath $script:PythonPath -FlutterPath $flutterPath -Jdk $jdk)
# ANDROID_WINDOWS_CUSTODY_RUNTIME_IDENTITY_AFTER_TREES
$script:AndroidToolchainRuntime = Confirm-ReviewedAndroidToolchainRuntimePins `
    -PythonPath $script:PythonPath -FlutterItem $flutterItem -Jdk $jdk `
    -Records $script:AndroidToolchainCustody
$flutterVersion = [string]$script:AndroidToolchainRuntime.Flutter.Version
$flutterRevision = [string]$script:AndroidToolchainRuntime.Flutter.Revision
if ($flutterVersion -cne $RequiredFlutterVersion -or
    $flutterRevision -cne $RequiredFlutterRevision) {
    throw "Android release builds require reviewed Flutter $RequiredFlutterVersion ($RequiredFlutterRevision); found $flutterVersion ($flutterRevision). Update the toolchain deliberately, then rerun."
}

if ($script:ReleaseDependencyWitnessMode) {
    $stage = $null
    try {
        Enter-ReleaseBuildLock
        Assert-WinsReleaseDependencyProducerUnchanged
        $sourceBefore = @(Get-NeutralInputSnapshot -Root $RepoRoot)
        $stage = Initialize-NeutralStage
        Copy-NeutralInputs -SourceRoot $RepoRoot -DestinationRoot $stage.Repo `
            -Snapshot $sourceBefore
        $stageSnapshot = @(Get-NeutralInputSnapshot -Root $stage.Repo)
        Assert-IdenticalInputSnapshots -Expected $sourceBefore -Actual $stageSnapshot `
            -Context 'witnessed neutral-stage creation'
        $sourceAfterCopy = @(Get-NeutralInputSnapshot -Root $RepoRoot)
        Assert-IdenticalInputSnapshots -Expected $sourceBefore -Actual $sourceAfterCopy `
            -Context 'witnessed neutral-stage creation'

        $childScript = Join-Path $stage.Repo 'tools\build_android_release.ps1'
        $resolvedSigningStore = [IO.Path]::GetFullPath($SigningStorePath)
        $script:AndroidToolchainCustody = @(Assert-ReviewedAndroidToolchainCustody `
            -PythonPath $script:PythonPath -FlutterPath $flutterPath -Jdk $jdk)
        $null = Confirm-ReviewedAndroidToolchainRuntimePins `
            -PythonPath $script:PythonPath -FlutterItem $flutterItem -Jdk $jdk `
            -Records $script:AndroidToolchainCustody
        $escapedChildScript = $childScript.Replace("'", "''")
        $escapedSigningStore = $resolvedSigningStore.Replace("'", "''")
        $childCommand = "& '$escapedChildScript' -InNeutralStage " +
            "-SigningStorePath '$escapedSigningStore'; exit `$LASTEXITCODE"
        $encodedChildCommand = [Convert]::ToBase64String(
            [Text.Encoding]::Unicode.GetBytes($childCommand)
        )
        $childStandardOutput = Join-Path $stage.Container '.witness-stdout.log'
        $childStandardError = Join-Path $stage.Container '.witness-stderr.log'
        $childProcess = Start-Process -FilePath (Get-Process -Id $PID).Path `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedChildCommand) `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $childStandardOutput `
            -RedirectStandardError $childStandardError
        if ($childProcess.ExitCode -ne 0) {
            throw 'witnessed Android child build failed'
        }
        $script:AndroidToolchainCustody = @(Assert-ReviewedAndroidToolchainCustody `
            -PythonPath $script:PythonPath -FlutterPath $flutterPath -Jdk $jdk)
        $null = Confirm-ReviewedAndroidToolchainRuntimePins `
            -PythonPath $script:PythonPath -FlutterItem $flutterItem -Jdk $jdk `
            -Records $script:AndroidToolchainCustody
        $sourceAfterBuild = @(Get-NeutralInputSnapshot -Root $RepoRoot)
        Assert-IdenticalInputSnapshots -Expected $sourceBefore -Actual $sourceAfterBuild `
            -Context 'witnessed isolated Android release build'
        Assert-WinsReleaseDependencyProducerUnchanged

        $witnessOutputName = [IO.Path]::GetFileName(
            $script:ReleaseDependencyWitnessOutputPath
        )
        $witnessArtifacts = @{
            'app-release.apk' = 'build\app\outputs\flutter-apk\app-phone-release.apk'
            'app-release.aab' = 'build\app\outputs\bundle\phoneRelease\app-phone-release.aab'
            'app-tv-release.apk' = 'build\app\outputs\flutter-apk\app-tv-release.apk'
            'app-tv-release.aab' = 'build\app\outputs\bundle\tvRelease\app-tv-release.aab'
        }
        if (-not $witnessArtifacts.ContainsKey($witnessOutputName)) {
            throw 'unsupported witnessed Android artifact name'
        }
        $witnessArtifact = Join-Path $stage.Repo $witnessArtifacts[$witnessOutputName]
        $artifactItem = Get-Item -LiteralPath $witnessArtifact -Force -ErrorAction Stop
        if ($artifactItem.PSIsContainer -or
            ($artifactItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $artifactItem.Length -le 0) {
            throw 'witnessed Android artifact is invalid'
        }
        $artifactStream = [IO.FileStream]::new(
            $artifactItem.FullName,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        try {
            $artifactStream.CopyTo($script:ReleaseDependencyWitnessOutput)
            $script:ReleaseDependencyWitnessOutput.Flush($true)
        } finally {
            $artifactStream.Dispose()
        }
        $finalIdentity = [WinsVpn.ReleaseDependencyOutput]::Inspect(
            $script:ReleaseDependencyWitnessOutput.SafeFileHandle
        )
        if ($finalIdentity[0] -ne $script:ReleaseDependencyWitnessIdentity[0] -or
            $finalIdentity[1] -ne $script:ReleaseDependencyWitnessIdentity[1] -or
            $finalIdentity[2] -ne $script:ReleaseDependencyWitnessIdentity[2] -or
            $finalIdentity[3] -ne 1 -or
            $finalIdentity[4] -ne [uint64]$artifactItem.Length -or
            $script:ReleaseDependencyWitnessOutput.Length -ne $artifactItem.Length) {
            throw 'witnessed Android output identity changed'
        }
    } finally {
        if ($stage -and (Test-Path -LiteralPath $stage.Container)) {
            Remove-Item -LiteralPath $stage.Container -Recurse -Force
        }
        Exit-ReleaseBuildLock
        if ($null -ne $script:ReleaseDependencyWitnessOutput) {
            $script:ReleaseDependencyWitnessOutput.Dispose()
            $script:ReleaseDependencyWitnessOutput = $null
        }
    }
    exit 0
}

if ($InNeutralStage) {
    if (-not [string]::IsNullOrWhiteSpace($ReleaseInputIndex) -or
        -not [string]::IsNullOrWhiteSpace($BuildReceiptDirectory)) {
        throw 'The neutral child build cannot create formal receipts; only the serialized outer producer owns them.'
    }
} elseif ([string]::IsNullOrWhiteSpace($ReleaseInputIndex)) {
    throw 'ReleaseInputIndex is required for every Android release build. Create and verify the immutable five-platform index first.'
}

if (-not $InNeutralStage) {
    if ($SkipPubGet) {
        throw 'SkipPubGet is incompatible with the clean neutral Android release stage. The producer always resolves the locked dependencies in its isolated stage.'
    }
    $stage = $null
    $formalReceipts = $null
    try {
        Enter-ReleaseBuildLock
        $resolvedReleaseInputIndex = Resolve-PrivateArtifactPath `
            -Path $ReleaseInputIndex -Label 'Android release input index' -RequireExistingFile
        if ([string]::IsNullOrWhiteSpace($BuildReceiptDirectory)) {
            $indexParent = Split-Path -Parent $resolvedReleaseInputIndex
            $BuildReceiptDirectory = Join-Path $indexParent (
                'android-build-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' +
                [Guid]::NewGuid().ToString('N')
            )
        }
        $resolvedBuildReceiptDirectory = Resolve-PrivateArtifactPath `
            -Path $BuildReceiptDirectory -Label 'Android build receipt directory' -RequireNewDirectory
        $formalReceipts = Initialize-FormalBuildReceipts `
            -IndexPath $resolvedReleaseInputIndex -ReceiptDirectory $resolvedBuildReceiptDirectory

        $sourceBefore = @(Get-NeutralInputSnapshot -Root $RepoRoot)
        $stage = Initialize-NeutralStage
        Write-Output "ANDROID RELEASE NEUTRAL STAGE: $($stage.Repo)"
        Copy-NeutralInputs -SourceRoot $RepoRoot -DestinationRoot $stage.Repo -Snapshot $sourceBefore
        $stageSnapshot = @(Get-NeutralInputSnapshot -Root $stage.Repo)
        Assert-IdenticalInputSnapshots -Expected $sourceBefore -Actual $stageSnapshot -Context 'neutral-stage creation'
        $sourceAfterCopy = @(Get-NeutralInputSnapshot -Root $RepoRoot)
        Assert-IdenticalInputSnapshots -Expected $sourceBefore -Actual $sourceAfterCopy -Context 'neutral-stage creation'

        $childScript = Join-Path $stage.Repo 'tools\build_android_release.ps1'
        $resolvedSigningStore = [IO.Path]::GetFullPath($SigningStorePath)
        $script:AndroidToolchainCustody = @(Assert-ReviewedAndroidToolchainCustody `
            -PythonPath $script:PythonPath -FlutterPath $flutterPath -Jdk $jdk)
        $null = Confirm-ReviewedAndroidToolchainRuntimePins `
            -PythonPath $script:PythonPath -FlutterItem $flutterItem -Jdk $jdk `
            -Records $script:AndroidToolchainCustody
        & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -File $childScript `
            -InNeutralStage -SigningStorePath $resolvedSigningStore
        if ($LASTEXITCODE -ne 0) {
            throw 'The isolated neutral Android release build failed.'
        }
        $script:AndroidToolchainCustody = @(Assert-ReviewedAndroidToolchainCustody `
            -PythonPath $script:PythonPath -FlutterPath $flutterPath -Jdk $jdk)
        $null = Confirm-ReviewedAndroidToolchainRuntimePins `
            -PythonPath $script:PythonPath -FlutterItem $flutterItem -Jdk $jdk `
            -Records $script:AndroidToolchainCustody

        $sourceAfterBuild = @(Get-NeutralInputSnapshot -Root $RepoRoot)
        Assert-IdenticalInputSnapshots -Expected $sourceBefore -Actual $sourceAfterBuild -Context 'isolated Android release build'
        Publish-NeutralStageOutputs -StageRepo $stage.Repo `
            -DestinationRepo $RepoRoot -ReleaseInputIndex $resolvedReleaseInputIndex

        Complete-FormalBuildReceipt `
            -IndexPath $resolvedReleaseInputIndex `
            -BeginPath $formalReceipts.ApkBegin `
            -ArtifactPath $PublishedApkPath `
            -Target 'android-release-apk' `
            -OutputPath $formalReceipts.ApkReceipt `
            -FlutterVersion $flutterVersion `
            -FlutterRevision $flutterRevision
        Complete-FormalBuildReceipt `
            -IndexPath $resolvedReleaseInputIndex `
            -BeginPath $formalReceipts.AabBegin `
            -ArtifactPath $PublishedAabPath `
            -Target 'android-release-aab' `
            -OutputPath $formalReceipts.AabReceipt `
            -FlutterVersion $flutterVersion `
            -FlutterRevision $flutterRevision
        Complete-FormalBuildReceipt `
            -IndexPath $resolvedReleaseInputIndex `
            -BeginPath $formalReceipts.TvApkBegin `
            -ArtifactPath $PublishedTvApkPath `
            -Target 'android-tv-release-apk' `
            -OutputPath $formalReceipts.TvApkReceipt `
            -FlutterVersion $flutterVersion `
            -FlutterRevision $flutterRevision
        Complete-FormalBuildReceipt `
            -IndexPath $resolvedReleaseInputIndex `
            -BeginPath $formalReceipts.TvAabBegin `
            -ArtifactPath $TvAabPath `
            -Target 'android-tv-release-aab' `
            -OutputPath $formalReceipts.TvAabReceipt `
            -FlutterVersion $flutterVersion `
            -FlutterRevision $flutterRevision

        [pscustomobject]@{
            Version = $VersionIdentity
            NeutralStage = 'cleaned'
            InputFiles = $sourceBefore.Count
            Apk = $PublishedApkPath
            ApkBytes = (Get-Item -LiteralPath $PublishedApkPath).Length
            ApkSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PublishedApkPath).Hash
            Aab = $PublishedAabPath
            AabBytes = (Get-Item -LiteralPath $PublishedAabPath).Length
            AabSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PublishedAabPath).Hash
            TvApk = $PublishedTvApkPath
            TvApkBytes = (Get-Item -LiteralPath $PublishedTvApkPath).Length
            TvApkSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $PublishedTvApkPath).Hash
            TvAab = $TvAabPath
            TvAabBytes = (Get-Item -LiteralPath $TvAabPath).Length
            TvAabSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $TvAabPath).Hash
            ApkSymbols = $ApkSymbols
            AabSymbols = $AabSymbols
            TvApkSymbols = $TvApkSymbols
            TvAabSymbols = $TvAabSymbols
            ReleaseInputIndex = $resolvedReleaseInputIndex
            ApkBuildReceipt = $formalReceipts.ApkReceipt
            ApkBuildReceiptSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $formalReceipts.ApkReceipt).Hash
            AabBuildReceipt = $formalReceipts.AabReceipt
            AabBuildReceiptSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $formalReceipts.AabReceipt).Hash
            TvApkBuildReceipt = $formalReceipts.TvApkReceipt
            TvApkBuildReceiptSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $formalReceipts.TvApkReceipt).Hash
            TvAabBuildReceipt = $formalReceipts.TvAabReceipt
            TvAabBuildReceiptSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $formalReceipts.TvAabReceipt).Hash
        }
    } finally {
        if ($stage -and (Test-Path -LiteralPath $stage.Container)) {
            Remove-Item -LiteralPath $stage.Container -Recurse -Force
        }
        Exit-ReleaseBuildLock
    }
    exit 0
}

Assert-NeutralStageRuntime -StageRepo $RepoRoot

try {
    Enter-ReleaseBuildLock
    Import-AndroidSigningEnvironment
    Assert-ExpectedAndroidSigner
    foreach ($directory in @($ApkSymbols, $AabSymbols, $TvApkSymbols, $TvAabSymbols)) {
        if (Test-Path -LiteralPath $directory) {
            Remove-Item -LiteralPath $directory -Recurse -Force
        }
        Initialize-PrivateSymbolDirectory -PrivateRoot $SymbolsRoot -Path $directory
    }

    if (-not $SkipPubGet) {
        Invoke-Checked -FilePath $flutterItem.FullName -ArgumentList @(
            'pub', 'get', '--enforce-lockfile'
        ) -FailureMessage 'flutter pub get --enforce-lockfile failed.'
    }

    $winn3PubkeyDefines = Get-Winn3DescriptorPubkeyDefines
    Write-Winn3DescriptorPubkeyStatus -Defines $winn3PubkeyDefines
    $winn3RingSha256 = (& $script:PythonPath (Join-Path $RepoRoot 'tools/winn3_descriptor_ring_identity.py') @winn3PubkeyDefines).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Winn3 descriptor ring identity calculation failed.' }
    $expectedWinn3RingSha256 = [string]$env:WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256
    if ($expectedWinn3RingSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
        $expectedWinn3RingSha256.ToLowerInvariant() -cne $winn3RingSha256) {
        throw "Reviewed Winn3 descriptor ring identity mismatch. Computed=$winn3RingSha256"
    }
    $winn3PubkeyDefines += "--dart-define=WINS_WINN3_DESCRIPTOR_RING_SHA256=$winn3RingSha256"
    Invoke-Checked -FilePath $flutterItem.FullName -ArgumentList @(
        'build', 'apk', '--release', '--flavor', 'phone', '--obfuscate',
        "--split-debug-info=$ApkSymbols",
        '--dart-define=WINS_GOOGLE_PLAY_BUILD=true',
        '--dart-define=WINS_WINN3_ENABLED_PLATFORMS=android',
        '--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=android'
    ) + $winn3PubkeyDefines -FailureMessage 'Android release APK build failed.'

    Invoke-Checked -FilePath $flutterItem.FullName -ArgumentList @(
        'build', 'appbundle', '--release', '--flavor', 'phone', '--obfuscate',
        "--split-debug-info=$AabSymbols",
        '--dart-define=WINS_GOOGLE_PLAY_BUILD=true',
        '--dart-define=WINS_WINN3_ENABLED_PLATFORMS=android',
        '--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=android'
    ) + $winn3PubkeyDefines -FailureMessage 'Android release AAB build failed.'

    Invoke-Checked -FilePath $flutterItem.FullName -ArgumentList @(
        'build', 'apk', '--release', '--flavor', 'tv', '--obfuscate',
        "--split-debug-info=$TvApkSymbols",
        '--dart-define=WINS_GOOGLE_PLAY_BUILD=true',
        '--dart-define=WINS_WINN3_ENABLED_PLATFORMS=android'
    ) + $winn3PubkeyDefines -FailureMessage 'Android TV release APK build failed.'

    Invoke-Checked -FilePath $flutterItem.FullName -ArgumentList @(
        'build', 'appbundle', '--release', '--flavor', 'tv', '--obfuscate',
        "--split-debug-info=$TvAabSymbols",
        '--dart-define=WINS_GOOGLE_PLAY_BUILD=true',
        '--dart-define=WINS_WINN3_ENABLED_PLATFORMS=android'
    ) + $winn3PubkeyDefines -FailureMessage 'Android TV release AAB build failed.'

    $script:AndroidToolchainCustody = @(Assert-ReviewedAndroidToolchainCustody `
        -PythonPath $script:PythonPath -FlutterPath $flutterPath -Jdk $jdk)
    $null = Confirm-ReviewedAndroidToolchainRuntimePins `
        -PythonPath $script:PythonPath -FlutterItem $flutterItem -Jdk $jdk `
        -Records $script:AndroidToolchainCustody

    foreach ($artifact in @($ApkPath, $AabPath, $TvApkPath, $TvAabPath)) {
        if (-not (Test-Path -LiteralPath $artifact -PathType Leaf) -or
            (Get-Item -LiteralPath $artifact -Force).Length -le 0) {
            throw "OWNER-BLOCKED: produced Android AAB/APK bytes are absent: $artifact"
        }
    }
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        (Join-Path $RepoRoot 'tools/verify_standalone_v3_artifact.py'),
        $ApkPath,
        $AabPath,
        $TvApkPath,
        $TvAabPath
    ) -FailureMessage 'Android v3-primary plus v1-fallback artifact-content gate failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        (Join-Path $RepoRoot 'tools/verify_winn3_ring_artifact.py'),
        $winn3RingSha256,
        $ApkPath,
        $AabPath,
        $TvApkPath,
        $TvAabPath
    ) -FailureMessage 'Android release artifacts lack the reviewed Winn3 ring identity.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $PlayRedemptionGate, '--repo', $RepoRoot,
        $ApkPath, $AabPath, $TvApkPath, $TvAabPath
    ) -FailureMessage 'Android Google Play redemption-content gate failed.'
    foreach ($privateBuildOutput in @(
        $R8MappingPath,
        $NativeDebugSymbolsPath,
        $TvR8MappingPath,
        $TvNativeDebugSymbolsPath
    )) {
        if (-not (Test-Path -LiteralPath $privateBuildOutput -PathType Leaf) -or
            (Get-Item -LiteralPath $privateBuildOutput).Length -le 0) {
            throw "Android private release symbol output is missing or empty: $privateBuildOutput"
        }
    }
    Copy-Item -LiteralPath $R8MappingPath -Destination (Join-Path $ApkSymbols 'proguard-mapping.txt') -Force
    Copy-Item -LiteralPath $R8MappingPath -Destination (Join-Path $AabSymbols 'proguard-mapping.txt') -Force
    Copy-Item -LiteralPath $NativeDebugSymbolsPath -Destination (Join-Path $AabSymbols 'native-debug-symbols.zip') -Force
    Copy-Item -LiteralPath $TvR8MappingPath -Destination (Join-Path $TvApkSymbols 'proguard-mapping.txt') -Force
    Copy-Item -LiteralPath $TvR8MappingPath -Destination (Join-Path $TvAabSymbols 'proguard-mapping.txt') -Force
    Copy-Item -LiteralPath $TvNativeDebugSymbolsPath -Destination (Join-Path $TvAabSymbols 'native-debug-symbols.zip') -Force

    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $ObfuscationContract, 'record', '--platform', 'android-apk',
        '--symbols-dir', $ApkSymbols, '--manifest', $ApkManifest, '--artifact', $ApkPath
    ) -FailureMessage 'Android APK obfuscation evidence creation failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $ObfuscationContract, 'verify', '--platform', 'android-apk',
        '--symbols-dir', $ApkSymbols, '--manifest', $ApkManifest, '--artifact', $ApkPath
    ) -FailureMessage 'Android APK obfuscation verification failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $ObfuscationContract, 'record', '--platform', 'android-aab',
        '--symbols-dir', $AabSymbols, '--manifest', $AabManifest, '--artifact', $AabPath
    ) -FailureMessage 'Android AAB obfuscation evidence creation failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $ObfuscationContract, 'verify', '--platform', 'android-aab',
        '--symbols-dir', $AabSymbols, '--manifest', $AabManifest, '--artifact', $AabPath
    ) -FailureMessage 'Android AAB obfuscation verification failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $ObfuscationContract, 'record', '--platform', 'android-apk',
        '--symbols-dir', $TvApkSymbols, '--manifest', $TvApkManifest, '--artifact', $TvApkPath
    ) -FailureMessage 'Android TV APK obfuscation evidence creation failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $ObfuscationContract, 'verify', '--platform', 'android-apk',
        '--symbols-dir', $TvApkSymbols, '--manifest', $TvApkManifest, '--artifact', $TvApkPath
    ) -FailureMessage 'Android TV APK obfuscation verification failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $ObfuscationContract, 'record', '--platform', 'android-aab',
        '--symbols-dir', $TvAabSymbols, '--manifest', $TvAabManifest, '--artifact', $TvAabPath
    ) -FailureMessage 'Android TV AAB obfuscation evidence creation failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $ObfuscationContract, 'verify', '--platform', 'android-aab',
        '--symbols-dir', $TvAabSymbols, '--manifest', $TvAabManifest, '--artifact', $TvAabPath
    ) -FailureMessage 'Android TV AAB obfuscation verification failed.'
    foreach ($privacySpecification in @(
        @{ Target = 'android-phone-tablet-apk'; Artifact = $ApkPath },
        @{ Target = 'android-phone-tablet-aab'; Artifact = $AabPath },
        @{ Target = 'android-tv-apk'; Artifact = $TvApkPath },
        @{ Target = 'android-tv-aab'; Artifact = $TvAabPath }
    )) {
        Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
            $PrivacyValidator, '--artifacts', '--target', $privacySpecification.Target,
            '--artifact', $privacySpecification.Artifact,
            '--secret-env', 'WINS_ANDROID_KEY_PASSWORD',
            '--secret-env', 'WINS_ANDROID_STORE_PASSWORD'
        ) -FailureMessage "Android $($privacySpecification.Target) privacy verification failed."
    }

    if ([string]::IsNullOrWhiteSpace($env:WINS_BUNDLETOOL_JAR)) {
        $env:WINS_BUNDLETOOL_JAR = Join-Path $RepoRoot (
            ".artifacts\tool-cache\bundletool\bundletool-all-$BundletoolVersion.jar"
        )
    }
    if (-not (Test-Path -LiteralPath $env:WINS_BUNDLETOOL_JAR -PathType Leaf)) {
        throw "missing pinned bundletool-all-$BundletoolVersion.jar; set WINS_BUNDLETOOL_JAR"
    }
    $bundletoolItem = Get-Item -LiteralPath $env:WINS_BUNDLETOOL_JAR -Force
    if ($bundletoolItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "missing pinned bundletool-all-$BundletoolVersion.jar; set WINS_BUNDLETOOL_JAR"
    }
    $bundletoolHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $bundletoolItem.FullName).Hash.ToLowerInvariant()
    if ($bundletoolHash -cne $BundletoolAllSha256) {
        throw "bundletool-all-$BundletoolVersion.jar SHA-256 does not match the reviewed pin"
    }
    $phoneApkBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $ApkPath).Hash
    $phoneAabBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $AabPath).Hash
    $tvApkBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $TvApkPath).Hash
    $tvAabBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $TvAabPath).Hash
    if ($phoneAabBefore -ceq $tvAabBefore) {
        throw 'Android TV AAB exactly reuses the phone/tablet AAB bytes.'
    }
    if ($phoneApkBefore -ceq $tvApkBefore) {
        throw 'Android TV APK exactly reuses the phone/tablet APK bytes.'
    }
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        (Join-Path $RepoRoot 'tools/verify_android_aab_signers.py'),
        '--verify', 'android-phone-tablet-aab',
        'build/app/outputs/bundle/phoneRelease/app-phone-release.aab',
        '--java', $javaPath,
        '--jarsigner', $jarsignerPath,
        '--keytool', $keytoolPath
    ) -FailureMessage 'Android phone/tablet AAB identity inspection failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        (Join-Path $RepoRoot 'tools/verify_android_aab_signers.py'),
        '--verify', 'android-tv-aab',
        'build/app/outputs/bundle/tvRelease/app-tv-release.aab',
        '--java', $javaPath,
        '--jarsigner', $jarsignerPath,
        '--keytool', $keytoolPath
    ) -FailureMessage 'Android TV AAB identity inspection failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        (Join-Path $RepoRoot 'tools/verify_android_aab_signers.py'),
        '--verify-apk', 'android-phone-tablet-apk',
        'build/app/outputs/flutter-apk/app-phone-release.apk',
        '--java', $javaPath,
        '--jarsigner', $jarsignerPath,
        '--keytool', $keytoolPath
    ) -FailureMessage 'Android phone/tablet APK identity inspection failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        (Join-Path $RepoRoot 'tools/verify_android_aab_signers.py'),
        '--verify-apk', 'android-tv-apk',
        'build/app/outputs/flutter-apk/app-tv-release.apk',
        '--java', $javaPath,
        '--jarsigner', $jarsignerPath,
        '--keytool', $keytoolPath
    ) -FailureMessage 'Android TV APK identity inspection failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        (Join-Path $RepoRoot 'tools/verify_android_aab_signers.py'),
        '--bind-r8', 'android-phone-tablet-aab',
        $AabPath,
        (Join-Path $AabSymbols 'proguard-mapping.txt')
    ) -FailureMessage 'Android phone/tablet AAB R8 bind failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        (Join-Path $RepoRoot 'tools/verify_android_aab_signers.py'),
        '--bind-r8', 'android-phone-tablet-apk',
        $ApkPath,
        (Join-Path $ApkSymbols 'proguard-mapping.txt')
    ) -FailureMessage 'Android phone/tablet APK R8 bind failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        (Join-Path $RepoRoot 'tools/verify_android_aab_signers.py'),
        '--bind-r8', 'android-tv-aab',
        $TvAabPath,
        (Join-Path $TvAabSymbols 'proguard-mapping.txt')
    ) -FailureMessage 'Android TV AAB R8 bind failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        (Join-Path $RepoRoot 'tools/verify_android_aab_signers.py'),
        '--bind-r8', 'android-tv-apk',
        $TvApkPath,
        (Join-Path $TvApkSymbols 'proguard-mapping.txt')
    ) -FailureMessage 'Android TV APK R8 bind failed.'
    $phoneApkAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $ApkPath).Hash
    $phoneAabAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $AabPath).Hash
    $tvApkAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $TvApkPath).Hash
    $tvAabAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $TvAabPath).Hash
    if ($phoneApkBefore -cne $phoneApkAfter) {
        throw 'Android phone APK current bytes changed during identity inspection.'
    }
    if ($phoneAabBefore -cne $phoneAabAfter) {
        throw 'Android phone/tablet AAB current bytes changed during identity inspection.'
    }
    if ($tvApkBefore -cne $tvApkAfter) {
        throw 'Android TV APK current bytes changed during identity inspection.'
    }
    if ($tvAabBefore -cne $tvAabAfter) {
        throw 'Android TV AAB current bytes changed during identity inspection.'
    }
    $apkSigner = Get-ApkSigner
    $zipAlign = Get-ZipAlign
    & $zipAlign -c -P 16 -v 4 $ApkPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Android APK is not 16 KiB ZIP-aligned.' }
    & $zipAlign -c -P 16 -v 4 $TvApkPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Android TV APK is not 16 KiB ZIP-aligned.' }
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        (Join-Path $RepoRoot 'tools/verify_android_aab_page_alignment.py'), $AabPath
    ) -FailureMessage 'Android AAB does not request 16 KiB page alignment.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        (Join-Path $RepoRoot 'tools/verify_android_aab_page_alignment.py'), $TvAabPath
    ) -FailureMessage 'Android TV AAB does not request 16 KiB page alignment.'
    $apkSignature = (& $apkSigner verify -Werr --verbose --print-certs $ApkPath 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'Android APK signature verification failed.' }
    $apkCertDigests = @([regex]::Matches($apkSignature, 'certificate SHA-256 digest:\s*([0-9a-f:]+)', 'IgnoreCase') | ForEach-Object {
        $_.Groups[1].Value.Replace(':', '').ToLowerInvariant()
    } | Sort-Object -Unique)
    if ($apkCertDigests.Count -ne 1) { throw 'Android APK must report exactly one signer certificate.' }
    $tvApkSignature = (& $apkSigner verify -Werr --verbose --print-certs $TvApkPath 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'Android TV APK signature verification failed.' }
    $tvApkCertDigests = @([regex]::Matches($tvApkSignature, 'certificate SHA-256 digest:\s*([0-9a-f:]+)', 'IgnoreCase') | ForEach-Object {
        $_.Groups[1].Value.Replace(':', '').ToLowerInvariant()
    } | Sort-Object -Unique)
    if ($tvApkCertDigests.Count -ne 1) { throw 'Android TV APK must report exactly one signer certificate.' }

    $aabVerification = (& $jarsignerPath -verify $AabPath 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or
        $aabVerification -notmatch '(?i)jar\s+verified' -or
        $aabVerification -match '(?i)jar\s+is\s+unsigned') {
        throw 'Android AAB cryptographic signature verification failed.'
    }
    $aabCertificate = (& $keytoolPath -printcert -jarfile $AabPath 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'Android AAB signer certificate could not be read.' }
    $aabCertMatches = @([regex]::Matches($aabCertificate, '(?im)^\s*SHA256:\s*([0-9A-F:]+)\s*$'))
    if ($aabCertMatches.Count -ne 1) { throw 'Android AAB must report exactly one signer certificate fingerprint.' }
    $tvAabVerification = (& $jarsignerPath -verify $TvAabPath 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or
        $tvAabVerification -notmatch '(?i)jar\s+verified' -or
        $tvAabVerification -match '(?i)jar\s+is\s+unsigned') {
        throw 'Android TV AAB cryptographic signature verification failed.'
    }
    $tvAabCertificate = (& $keytoolPath -printcert -jarfile $TvAabPath 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'Android TV AAB signer certificate could not be read.' }
    $tvAabCertMatches = @([regex]::Matches($tvAabCertificate, '(?im)^\s*SHA256:\s*([0-9A-F:]+)\s*$'))
    if ($tvAabCertMatches.Count -ne 1) { throw 'Android TV AAB must report exactly one signer certificate fingerprint.' }
    $apkCertDigest = $apkCertDigests[0]
    $tvApkCertDigest = $tvApkCertDigests[0]
    $aabCertDigest = $aabCertMatches[0].Groups[1].Value.Replace(':', '').ToLowerInvariant()
    $tvAabCertDigest = $tvAabCertMatches[0].Groups[1].Value.Replace(':', '').ToLowerInvariant()
    if ($apkCertDigest -cne $aabCertDigest) {
        throw 'Android APK and AAB are signed by different certificates.'
    }
    if ($apkCertDigest -cne $tvApkCertDigest) {
        throw 'Android phone APK and TV APK are signed by different certificates.'
    }
    if ($apkCertDigest -cne $tvAabCertDigest) {
        throw 'Android phone APK and TV AAB are signed by different certificates.'
    }
    if ($apkCertDigest -cne $ExpectedUploadCertificateSha256) {
        throw "Android release artifacts use an unexpected upload signer: sha256=$apkCertDigest"
    }
    Write-Output "ANDROID RELEASE SIGNER: PASS sha256=$apkCertDigest"

    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $CustodyTool, 'record', '--platform', 'android-apk',
        '--symbols-dir', $ApkSymbols, '--artifact', $ApkPath
    ) -FailureMessage 'Android APK private-symbol custody creation failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $CustodyTool, 'verify', '--platform', 'android-apk',
        '--symbols-dir', $ApkSymbols, '--artifact', $ApkPath
    ) -FailureMessage 'Android APK private-symbol custody verification failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $CustodyTool, 'record', '--platform', 'android-aab',
        '--symbols-dir', $AabSymbols, '--artifact', $AabPath
    ) -FailureMessage 'Android AAB private-symbol custody creation failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $CustodyTool, 'verify', '--platform', 'android-aab',
        '--symbols-dir', $AabSymbols, '--artifact', $AabPath
    ) -FailureMessage 'Android AAB private-symbol custody verification failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $CustodyTool, 'record', '--platform', 'android-apk',
        '--symbols-dir', $TvApkSymbols, '--artifact', $TvApkPath
    ) -FailureMessage 'Android TV APK private-symbol custody creation failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $CustodyTool, 'verify', '--platform', 'android-apk',
        '--symbols-dir', $TvApkSymbols, '--artifact', $TvApkPath
    ) -FailureMessage 'Android TV APK private-symbol custody verification failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $CustodyTool, 'record', '--platform', 'android-aab',
        '--symbols-dir', $TvAabSymbols, '--artifact', $TvAabPath
    ) -FailureMessage 'Android TV AAB private-symbol custody creation failed.'
    Invoke-Checked -FilePath $script:PythonPath -ArgumentList @(
        $CustodyTool, 'verify', '--platform', 'android-aab',
        '--symbols-dir', $TvAabSymbols, '--artifact', $TvAabPath
    ) -FailureMessage 'Android TV AAB private-symbol custody verification failed.'

    [pscustomobject]@{
        Version = $VersionIdentity
        Apk = $ApkPath
        ApkBytes = (Get-Item -LiteralPath $ApkPath).Length
        ApkSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $ApkPath).Hash
        Aab = $AabPath
        AabBytes = (Get-Item -LiteralPath $AabPath).Length
        AabSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $AabPath).Hash
        TvApk = $TvApkPath
        TvApkBytes = (Get-Item -LiteralPath $TvApkPath).Length
        TvApkSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $TvApkPath).Hash
        TvAab = $TvAabPath
        TvAabBytes = (Get-Item -LiteralPath $TvAabPath).Length
        TvAabSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $TvAabPath).Hash
        ApkSymbols = $ApkSymbols
        AabSymbols = $AabSymbols
        TvApkSymbols = $TvApkSymbols
        TvAabSymbols = $TvAabSymbols
    }
} finally {
    Clear-AndroidSigningEnvironment
    Exit-ReleaseBuildLock
}
