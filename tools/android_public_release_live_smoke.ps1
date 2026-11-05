[CmdletBinding()]
param(
    [string]$Artifact = 'build\app\outputs\flutter-apk\app-release.apk',
    [string]$ReleaseInputIndex = '',
    [string]$BuildReceipt = '',
    [string]$FormFactorEvidenceManifest = '',
    [string]$ExpectedFormFactorEvidenceManifestSha256 = '',
    [string]$FormFactorOwnerAuthorization = '',
    [string]$ExpectedFormFactorOwnerAuthorizationSha256 = '',
    [string]$DeviceAttestationReceipt = '',
    [string]$DeviceCheckBuildReceipt = 'android\devicecheck\app\build\outputs\devicecheck-receipts\release\DEVICECHECK_BUILD_RECEIPT.json',
    [string]$ExpectedDeviceCheckBuildReceiptSha256 = '',
    [string]$ExpectedDeviceCheckTargetApkSha256 = '',
    [string]$ExpectedDeviceCheckTargetApkBytes = '',
    [string]$ExpectedDeviceCheckAndroidTestApkSha256 = '',
    [string]$ExpectedDeviceCheckAndroidTestApkBytes = '',
    [string]$ExpectedDeviceCheckSourceInventorySha256 = '',
    [string]$RouteInventory = '',
    [string]$SshConfig = '',
    [string]$SshIdentity = '',
    [string]$SshKnownHosts = '',
    [string]$Serial = '',
    [string]$Adb = '',
    [string]$Tesseract = '',
    [string[]]$ExpectedMapCity = @(),
    [string]$Pin = '1357',
    [switch]$AcknowledgeThirdPartySecuritySheet,
    [string]$OutputRoot = '.artifacts\release-evidence',
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ToolchainCustodyManifest = Join-Path $RepoRoot 'tools\android-toolchain-custody.json'
$ToolchainCustodyHelper = Join-Path $RepoRoot 'tools\android_toolchain_custody.ps1'
$ToolchainPinManifest = Join-Path $RepoRoot 'tools\toolchain-pins.json'
# Root trust for the support-file closure below. A reviewed custody reissuance
# must update this anchor in the already source-frozen wrapper; a replacement
# manifest cannot authorize its own helper, pin manifest, or interpreter.
$ExpectedToolchainCustodyManifestSha256 = '7517705b3fd340dde17eb493267999a89fea23e6aa8f88f6f21cc49155203d08'
# OWNER-BLOCKED until the final public authority is provisioned and reviewed.
# The release-input graph cannot select its own root key.
$ExpectedFormFactorOwnerAuthoritySha256 = '0000000000000000000000000000000000000000000000000000000000000000'
$ExpectedEvidenceCodeSha256 = [ordered]@{
    'tools/android_final_evidence_collector.py' = 'e79070d6e8fb3c7d4127122739acdad43d94e269d8510e64db763f698c06bacb'
    'tools/android_release_matrix_evidence.py' = 'c0f76952404a6d8abf3e0d8eb2eff1f3bab49ff83be49aaee3d06b1a7e162913'
    'tools/android_release_ui_driver.py' = '36446da900c290f3fb271bec63b977b1377c946275ecb84fa6677f04a7c28b3d'
    'tools/android_remote_route_control.py' = 'b1beb16f478a70d278d7d2848e0aa4661b2b686f7951438122749609c7d49073'
    'tools/android_remote_route_guard.sh' = 'cb50ef4af7251cbd811642b42d2fb44fafdf83d39e3f489898e0a40b0a63ca69'
    'tools/android_fresh_release_regression.ps1' = 'f69ba191c8226f254a4eec2faf28f05677f3d708e211e47f63077e28d7fd4e82'
    'tools/android_exact_installed_live_cycle.ps1' = '990508e558b2a313435445d9923d65ada8e243714f563d09d19e40fb3400cfd1'
    'tools/public_release_live_smoke_common.py' = 'd2f8a156c04715151dccd6d88d444e354a559e2558bf9a53cb8c29953c9cbace'
    'tools/validate_release_artifact_privacy.py' = '5aa96f955256eed8349f72010aee0637607589f568b0a3e11c8506d6a8bc55ce'
    'tools/release_obfuscation_contract.py' = '002a2ba41e54d5d719279bd0021ecf6fceac509dc8234dbc9c94241c82a66ad7'
    'tools/release_dependency_freeze.py' = 'b70e87144c7f30c7eac7b6ffeb6a4c7e5bc017c62d114e2d78f58c6c5427f609'
    'tools/release_secret_scan_policy.py' = '8c5e7732b589b4a459b7e7bca22109ac5c234aeca1f7f52deb96f72a4a0c1180'
    'tools/release_secret_inventory.py' = 'c0ffc1f731b0d82eaf95c594e651a2a55933d3db434f3c2f462b5ba934321ae1'
}
$script:CustodyManifestStream = $null
$script:CustodyHelperStream = $null
$script:ToolchainPinStream = $null
$script:CustodyHelperDigest = ''
$script:ToolchainPinDigest = ''
$script:EvidenceCodeStreams = [Collections.Generic.List[object]]::new()
$script:NativeToolStreams = [Collections.Generic.List[object]]::new()
$script:RouteAuthorityStreams = [Collections.Generic.List[object]]::new()
$script:EvidenceBundleStreams = [Collections.Generic.List[object]]::new()
$script:DedicatedAdbServer = $null
$script:DedicatedAdbServerPort = 0
$script:PythonCustodyStream = $null
$script:PythonCustodyIdentity = $null
$script:PythonCustodyDigest = ''
$script:IsolatedPythonBootstrap = 'import base64,json,sys,types;sys.dont_write_bytecode=True;raw=sys.stdin.buffer.read(16777217);assert len(raw)<=16777216;b=json.loads(raw.decode("utf-8"),parse_constant=lambda x:(_ for _ in ()).throw(ValueError(x)));e=b["entrypoint"];a=b["arguments"];f=b["files"];allowed={"tools/android_final_evidence_collector.py","tools/android_release_matrix_evidence.py","tools/android_release_ui_driver.py","tools/android_remote_route_control.py","tools/public_release_live_smoke_common.py"};mods=(("release_secret_scan_policy","tools/release_secret_scan_policy.py"),("release_secret_inventory","tools/release_secret_inventory.py"),("release_obfuscation_contract","tools/release_obfuscation_contract.py"),("validate_release_artifact_privacy","tools/validate_release_artifact_privacy.py"),("release_dependency_freeze","tools/release_dependency_freeze.py"),("public_release_live_smoke_common","tools/public_release_live_smoke_common.py"),("android_release_ui_driver","tools/android_release_ui_driver.py"),("android_remote_route_control","tools/android_remote_route_control.py"));assert e in allowed and set(f)==set(b["digests"]);exec("for n,q in mods:\n m=types.ModuleType(n)\n m.__file__=q\n m.__package__=\"\"\n m.__spec__=None\n m.__cached__=None\n sys.modules[n]=m\n raw=base64.b64decode(f[q],validate=True)\n assert __import__(\"hashlib\").sha256(raw).hexdigest()==b[\"digests\"][q]\n exec(compile(raw,q,\"exec\"),m.__dict__)");raw=base64.b64decode(f[e],validate=True);assert __import__("hashlib").sha256(raw).hexdigest()==b["digests"][e];sys.argv=[e]+a;g={"__name__":"__main__","__file__":e,"__package__":None,"__spec__":None,"__cached__":None};exec(compile(raw,e,"exec"),g)'

function Assert-NoReparsePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
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
    param([Parameter(Mandatory = $true)][IO.FileStream]$Stream)
    return [WinsVpn.ReleaseFileIdentity]::Inspect($Stream.SafeFileHandle)
}

function Test-ReleaseFileIdentityEqual {
    param(
        [Parameter(Mandatory = $true)]$First,
        [Parameter(Mandatory = $true)]$Second
    )

    return $First.VolumeSerialNumber -eq $Second.VolumeSerialNumber -and
        $First.FileIndexHigh -eq $Second.FileIndexHigh -and
        $First.FileIndexLow -eq $Second.FileIndexLow -and
        $First.NumberOfLinks -eq $Second.NumberOfLinks -and
        $First.FileSize -eq $Second.FileSize -and
        $First.LastWriteFileTime -eq $Second.LastWriteFileTime
}

function Get-HeldReleaseFileDigest {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)]$ExpectedIdentity,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $before = Get-WinsFileIdentityFromStream -Stream $Stream
    if (-not (Test-ReleaseFileIdentityEqual -First $ExpectedIdentity -Second $before)) {
        throw "$Description changed before hashing."
    }
    $null = $Stream.Seek(0, [IO.SeekOrigin]::Begin)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
    $after = Get-WinsFileIdentityFromStream -Stream $Stream
    if (-not (Test-ReleaseFileIdentityEqual -First $before -Second $after)) {
        throw "$Description changed while hashing."
    }
    return $digest
}

function Get-HeldStreamSha256 {
    param([Parameter(Mandatory = $true)][IO.FileStream]$Stream)

    $null = $Stream.Seek(0, [IO.SeekOrigin]::Begin)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Read-HeldUtf8Text {
    param([Parameter(Mandatory = $true)][IO.FileStream]$Stream)

    $null = $Stream.Seek(0, [IO.SeekOrigin]::Begin)
    $reader = [IO.StreamReader]::new(
        $Stream,
        [Text.UTF8Encoding]::new($false, $true),
        $false,
        4096,
        $true
    )
    try {
        return $reader.ReadToEnd()
    } finally {
        $reader.Dispose()
    }
}

function Get-HeldBytesBase64 {
    param([Parameter(Mandatory = $true)][IO.FileStream]$Stream)

    $null = $Stream.Seek(0, [IO.SeekOrigin]::Begin)
    $memory = [IO.MemoryStream]::new()
    try {
        $Stream.CopyTo($memory)
        return [Convert]::ToBase64String($memory.ToArray())
    } finally {
        $memory.Dispose()
    }
}

function New-HeldPythonArguments {
    param(
        [Parameter(Mandatory = $true)][string]$EntryPoint,
        [Parameter(Mandatory = $true)][string[]]$ScriptArguments
    )

    $allowed = @(
        'tools/android_final_evidence_collector.py',
        'tools/android_release_matrix_evidence.py',
        'tools/android_release_ui_driver.py',
        'tools/android_remote_route_control.py',
        'tools/public_release_live_smoke_common.py'
    )
    if ($EntryPoint -cnotin $allowed) {
        throw 'OWNER-BLOCKED: Android held Python entrypoint is not reviewed.'
    }
    $files = [ordered]@{}
    $digests = [ordered]@{}
    foreach ($record in $script:EvidenceCodeStreams) {
        if (-not $record.Path.EndsWith('.py', [StringComparison]::Ordinal)) { continue }
        $files[$record.Path] = Get-HeldBytesBase64 -Stream $record.Stream
        $digests[$record.Path] = $record.Digest
    }
    if (-not $files.Contains($EntryPoint)) {
        throw 'OWNER-BLOCKED: Android held Python entrypoint bytes are absent.'
    }
    $payload = [ordered]@{
        schema_version = 1
        entrypoint = $EntryPoint
        arguments = @($ScriptArguments)
        files = $files
        digests = $digests
    }
    $json = $payload | ConvertTo-Json -Compress -Depth 6
    $stdinBytes = [Text.Encoding]::UTF8.GetBytes($json)
    if ($stdinBytes.Length -gt 16777216) {
        throw 'OWNER-BLOCKED: held Python source closure exceeds the bounded stdin contract.'
    }
    return [PSCustomObject]@{
        Arguments = @('-I', '-S', '-c', $script:IsolatedPythonBootstrap)
        StandardInput = $stdinBytes
    }
}

function Add-HeldAndroidEvidenceFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Role,
        [string]$ExpectedSha256 = '',
        [long]$ExpectedSize = -1
    )

    if (-not [string]::IsNullOrEmpty($ExpectedSha256) -and
        $ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "Android held evidence digest is malformed: $Role"
    }
    Assert-NoReparsePath -Path $Path -Description "Android held evidence $Role"
    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $identity = Get-WinsFileIdentityFromStream -Stream $stream
        if ($identity.NumberOfLinks -ne 1 -or $identity.FileSize -le 0 -or
            ($ExpectedSize -ge 0 -and $identity.FileSize -ne $ExpectedSize)) {
            throw "Android held evidence is empty, hardlinked, or the wrong size: $Role"
        }
        $digest = Get-HeldStreamSha256 -Stream $stream
        if (-not [string]::IsNullOrEmpty($ExpectedSha256) -and
            $digest -cne $ExpectedSha256) {
            throw "Android held evidence does not match its exact digest: $Role"
        }
        $record = [pscustomobject]@{
            Role = $Role
            Path = [IO.Path]::GetFullPath($Path)
            Digest = $digest
            Identity = $identity
            Stream = $stream
        }
        $script:EvidenceBundleStreams.Add($record)
        return $record
    } catch {
        $stream.Dispose()
        throw
    }
}

function Get-AndroidToolchainRootFromExecutable {
    param([Parameter(Mandatory = $true)][string]$Executable)

    $item = Get-Item -LiteralPath $Executable -Force -ErrorAction Stop
    $parent = $item.Directory
    if (-not $parent) {
        throw "Android release Python has no installation parent: $Executable"
    }
    if ($parent.Name -ieq 'bin' -and $parent.Parent) {
        return $parent.Parent.FullName
    }
    return $parent.FullName
}

function Assert-OwnerIndependentReadOnlyTree {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$TrustedBase,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $dangerousPrivileges = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in @(
        'SeAssignPrimaryTokenPrivilege',
        'SeCreateTokenPrivilege',
        'SeDebugPrivilege',
        'SeImpersonatePrivilege',
        'SeLoadDriverPrivilege',
        'SeManageVolumePrivilege',
        'SeRestorePrivilege',
        'SeTakeOwnershipPrivilege',
        'SeTcbPrivilege'
    )) {
        $null = $dangerousPrivileges.Add($name)
    }
    foreach ($name in [WinsVpn.ReleaseSecurity]::CurrentTokenPrivileges()) {
        if ($dangerousPrivileges.Contains($name)) {
            throw "OWNER-BLOCKED: Android evidence release token carries dangerous privilege $name."
        }
    }
    $currentSids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $null = $currentSids.Add($identity.User.Value)
    foreach ($group in @($identity.Groups)) {
        $null = $currentSids.Add($group.Value)
    }
    $administratorsSid = 'S-1-5-32-544'
    if ($currentSids.Contains($administratorsSid)) {
        throw 'OWNER-BLOCKED: Android evidence production must use a non-administrator Windows release account.'
    }

    $trustedBase = [IO.Path]::GetFullPath($TrustedBase).TrimEnd('\', '/')
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    if (-not $rootPath.StartsWith(
        $trustedBase + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "OWNER-BLOCKED: reviewed $Description must be installed below $trustedBase."
    }

    $safeOwners = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($sid in @(
        'S-1-5-18',
        'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    )) {
        $null = $safeOwners.Add($sid)
    }
    $writeMask = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Modify -bor
        [Security.AccessControl.FileSystemRights]::FullControl -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership

    $paths = [Collections.Generic.List[string]]::new()
    $cursor = $rootPath
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        $paths.Add($cursor)
        $parent = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) { break }
        $cursor = $parent.FullName.TrimEnd('\', '/')
    }
    foreach ($entry in @(Get-ChildItem -LiteralPath $rootPath -Force -Recurse -ErrorAction Stop)) {
        $paths.Add($entry.FullName)
    }
    foreach ($path in $paths) {
        Assert-NoReparsePath -Path $path -Description "$Description custody path"
        $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if (-not $safeOwners.Contains($owner) -or $currentSids.Contains($owner)) {
            throw "OWNER-BLOCKED: $Description custody path has an unsafe owner: $path"
        }
        $rules = $acl.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        )
        foreach ($rule in $rules) {
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $currentSids.Contains($rule.IdentityReference.Value) -and
                (($rule.FileSystemRights -band $writeMask) -ne 0)) {
                throw "OWNER-BLOCKED: current release account can modify $Description custody path: $path"
            }
        }
    }
}

function Get-WinsProgramFiles64 {
    $programFiles64 = [Environment]::GetEnvironmentVariable('ProgramW6432', 'Process')
    if ([string]::IsNullOrWhiteSpace($programFiles64)) {
        $programFiles64 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    }
    return [IO.Path]::GetFullPath($programFiles64)
}

function Assert-OwnerIndependentReadOnlyPythonTree {
    param([Parameter(Mandatory = $true)][string]$Root)

    $trustedBase = Join-Path (Get-WinsProgramFiles64) 'WinsVPN\ReleasePython'
    Assert-OwnerIndependentReadOnlyTree -Root $Root -TrustedBase $trustedBase `
        -Description 'Android release Python'
}

function Assert-OwnerIndependentReadOnlyAdbTree {
    param([Parameter(Mandatory = $true)][string]$Root)

    $trustedBase = Join-Path (Get-WinsProgramFiles64) 'WinsVPN\ReleaseTools\AndroidPlatformTools'
    Assert-OwnerIndependentReadOnlyTree -Root $Root -TrustedBase $trustedBase `
        -Description 'Android Platform-Tools'
}

function Assert-OwnerIndependentReadOnlyTesseractTree {
    param([Parameter(Mandatory = $true)][string]$Root)

    $trustedBase = Join-Path (Get-WinsProgramFiles64) 'WinsVPN\ReleaseTools\Tesseract'
    Assert-OwnerIndependentReadOnlyTree -Root $Root -TrustedBase $trustedBase `
        -Description 'Android Tesseract OCR runtime'
}

function Get-ReviewedPythonRuntimeIdentity {
    param([Parameter(Mandatory = $true)][string]$PythonPath)

    $raw = (& $PythonPath -I -S -c 'import platform,sys; print("|".join([f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}", platform.python_revision(), platform.python_implementation(), platform.machine()]))' | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) {
        throw "Android release Python did not report a complete runtime identity: $PythonPath"
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

function Assert-AuthenticatedReleasePythonStillBound {
    if ($null -eq $script:PythonCustodyStream -or $null -eq $script:PythonCustodyIdentity) {
        throw 'Android release Python custody stream is not held.'
    }
    $current = Get-WinsFileIdentityFromStream -Stream $script:PythonCustodyStream
    if (-not (Test-ReleaseFileIdentityEqual `
        -First $script:PythonCustodyIdentity -Second $current)) {
        throw 'Android release Python changed during evidence production.'
    }
    $digest = Get-HeldReleaseFileDigest `
        -Stream $script:PythonCustodyStream `
        -ExpectedIdentity $script:PythonCustodyIdentity `
        -Description 'Android release Python executable'
    if ($digest -cne $script:PythonCustodyDigest) {
        throw 'Android release Python digest changed during evidence production.'
    }
}

function Assert-AuthenticatedSupportFilesStillBound {
    if ($null -eq $script:CustodyManifestStream -or
        $null -eq $script:CustodyHelperStream -or
        $null -eq $script:ToolchainPinStream) {
        throw 'Android support-file custody streams are not held.'
    }
    if ((Get-HeldStreamSha256 -Stream $script:CustodyManifestStream) -cne
        $ExpectedToolchainCustodyManifestSha256 -or
        (Get-HeldStreamSha256 -Stream $script:CustodyHelperStream) -cne
        $script:CustodyHelperDigest -or
        (Get-HeldStreamSha256 -Stream $script:ToolchainPinStream) -cne
        $script:ToolchainPinDigest) {
        throw 'Android toolchain custody support bytes changed during evidence production.'
    }
    foreach ($record in $script:EvidenceCodeStreams) {
        if ((Get-HeldStreamSha256 -Stream $record.Stream) -cne $record.Digest) {
            throw "Android evidence code changed during production: $($record.Path)"
        }
    }
    foreach ($record in $script:NativeToolStreams) {
        if ((Get-HeldStreamSha256 -Stream $record.Stream) -cne $record.Digest) {
            throw "Android native tool changed during production: $($record.Role)"
        }
    }
    foreach ($record in $script:RouteAuthorityStreams) {
        if ((Get-HeldStreamSha256 -Stream $record.Stream) -cne $record.Digest) {
            throw "Android remote-route authority changed during production: $($record.Role)"
        }
    }
    foreach ($record in $script:EvidenceBundleStreams) {
        $identity = Get-WinsFileIdentityFromStream -Stream $record.Stream
        if (-not (Test-ReleaseFileIdentityEqual -First $record.Identity -Second $identity) -or
            (Get-HeldStreamSha256 -Stream $record.Stream) -cne $record.Digest) {
            throw "Android held evidence changed during downstream production: $($record.Role)"
        }
    }
}

function Resolve-AuthenticatedReleasePython {
    $isWindowsHost = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    )
    if (-not $isWindowsHost) {
        throw 'OWNER-BLOCKED: Android public-release live-smoke requires authenticated Windows toolchain custody.'
    }
    if ([string]::IsNullOrWhiteSpace($env:WINS_RELEASE_PYTHON)) {
        throw 'OWNER-BLOCKED: set WINS_RELEASE_PYTHON to the reviewed absolute Python executable.'
    }
    if (-not [IO.Path]::IsPathRooted($env:WINS_RELEASE_PYTHON)) {
        throw 'OWNER-BLOCKED: WINS_RELEASE_PYTHON must be an absolute path.'
    }

    foreach ($required in @($ToolchainCustodyManifest, $ToolchainCustodyHelper, $ToolchainPinManifest)) {
        Assert-NoReparsePath -Path $required -Description 'Android toolchain custody input'
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "OWNER-BLOCKED: Android toolchain custody input is missing: $required"
        }
    }
    $script:CustodyManifestStream = [IO.FileStream]::new(
        $ToolchainCustodyManifest,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $manifestDigest = Get-HeldStreamSha256 -Stream $script:CustodyManifestStream
    if ($manifestDigest -cne $ExpectedToolchainCustodyManifestSha256) {
        throw 'OWNER-BLOCKED: Android toolchain custody manifest does not match the wrapper trust anchor.'
    }
    $custodyText = Read-HeldUtf8Text -Stream $script:CustodyManifestStream
    $custody = $custodyText | ConvertFrom-Json -ErrorAction Stop
    if ([string]$custody.windows_helper -cne 'tools/android_toolchain_custody.ps1' -or
        [string]$custody.manifest -cne 'tools/toolchain-pins.json') {
        throw 'OWNER-BLOCKED: Android toolchain custody paths are not canonical.'
    }
    $expectedHelperSha = ([string]$custody.windows_helper_sha256).ToLowerInvariant()
    $expectedPinSha = ([string]$custody.manifest_sha256).ToLowerInvariant()
    if ($expectedHelperSha -cnotmatch '^[0-9a-f]{64}$' -or
        $expectedPinSha -cnotmatch '^[0-9a-f]{64}$') {
        throw 'OWNER-BLOCKED: Android toolchain custody hashes are malformed.'
    }
    $script:CustodyHelperStream = [IO.FileStream]::new(
        $ToolchainCustodyHelper,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $script:CustodyHelperDigest = Get-HeldStreamSha256 -Stream $script:CustodyHelperStream
    if ($script:CustodyHelperDigest -cne $expectedHelperSha) {
        throw 'OWNER-BLOCKED: Android Windows custody helper does not match its reviewed hash.'
    }
    $script:ToolchainPinStream = [IO.FileStream]::new(
        $ToolchainPinManifest,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $script:ToolchainPinDigest = Get-HeldStreamSha256 -Stream $script:ToolchainPinStream
    if ($script:ToolchainPinDigest -cne $expectedPinSha) {
        throw 'OWNER-BLOCKED: Android toolchain pin manifest requires reviewed custody reissuance.'
    }
    foreach ($relative in $ExpectedEvidenceCodeSha256.Keys) {
        $path = [IO.Path]::GetFullPath((Join-Path $RepoRoot $relative))
        Assert-NoReparsePath -Path $path -Description 'Android evidence code'
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "OWNER-BLOCKED: Android evidence code is missing: $relative"
        }
        $stream = [IO.FileStream]::new(
            $path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $digest = Get-HeldStreamSha256 -Stream $stream
        if ($digest -cne [string]$ExpectedEvidenceCodeSha256[$relative]) {
            $stream.Dispose()
            throw "OWNER-BLOCKED: Android evidence code does not match its wrapper trust anchor: $relative"
        }
        $script:EvidenceCodeStreams.Add([pscustomobject]@{
            Path = $relative
            Digest = $digest
            Stream = $stream
        })
    }

    if (-not ('WinsVpn.ReleaseFileIdentity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace WinsVpn {
    public static class ReleaseFileIdentity {
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
            SafeFileHandle handle, out BY_HANDLE_FILE_INFORMATION information
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

    public static class ReleaseSecurity {
        private const uint TOKEN_QUERY = 0x0008;
        private const int TokenPrivileges = 3;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES {
            public LUID Luid;
            public uint Attributes;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(
            IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(
            IntPtr tokenHandle,
            int tokenInformationClass,
            IntPtr tokenInformation,
            int tokenInformationLength,
            out int returnLength
        );

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LookupPrivilegeName(
            string systemName, ref LUID luid, StringBuilder name, ref int nameLength
        );

        public static string[] CurrentTokenPrivileges() {
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out token)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            try {
                int length;
                GetTokenInformation(token, TokenPrivileges, IntPtr.Zero, 0, out length);
                if (Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER || length <= 0) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                IntPtr buffer = Marshal.AllocHGlobal(length);
                try {
                    if (!GetTokenInformation(
                        token, TokenPrivileges, buffer, length, out length
                    )) {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    uint count = unchecked((uint)Marshal.ReadInt32(buffer));
                    int stride = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
                    IntPtr entry = IntPtr.Add(buffer, sizeof(uint));
                    List<string> names = new List<string>();
                    for (uint i = 0; i < count; i++) {
                        LUID_AND_ATTRIBUTES value =
                            (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                                entry, typeof(LUID_AND_ATTRIBUTES)
                            );
                        int nameLength = 0;
                        LookupPrivilegeName(null, ref value.Luid, null, ref nameLength);
                        if (nameLength <= 0) {
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        }
                        StringBuilder name = new StringBuilder(nameLength + 1);
                        int capacity = name.Capacity;
                        if (!LookupPrivilegeName(
                            null, ref value.Luid, name, ref capacity
                        )) {
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        }
                        names.Add(name.ToString());
                        entry = IntPtr.Add(entry, stride);
                    }
                    return names.ToArray();
                } finally {
                    Marshal.FreeHGlobal(buffer);
                }
            } finally {
                CloseHandle(token);
            }
        }
    }

    public static class ReleaseTcpListener {
        private const int AF_INET = 2;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const int TCP_TABLE_OWNER_PID_LISTENER = 3;

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID {
            public uint State;
            public uint LocalAddress;
            public uint LocalPort;
            public uint RemoteAddress;
            public uint RemotePort;
            public uint OwningProcessId;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr table,
            ref int size,
            bool order,
            int addressFamily,
            int tableClass,
            uint reserved
        );

        [DllImport("ws2_32.dll")]
        private static extern ushort ntohs(ushort value);

        public static int[] LoopbackOwnerProcessIds(int port) {
            if (port < 1 || port > 65535) {
                throw new ArgumentOutOfRangeException("port");
            }
            int size = 0;
            uint first = GetExtendedTcpTable(
                IntPtr.Zero, ref size, true, AF_INET,
                TCP_TABLE_OWNER_PID_LISTENER, 0
            );
            if (first != ERROR_INSUFFICIENT_BUFFER || size <= sizeof(uint)) {
                throw new Win32Exception(unchecked((int)first));
            }
            IntPtr table = Marshal.AllocHGlobal(size);
            try {
                uint result = GetExtendedTcpTable(
                    table, ref size, true, AF_INET,
                    TCP_TABLE_OWNER_PID_LISTENER, 0
                );
                if (result != 0) {
                    throw new Win32Exception(unchecked((int)result));
                }
                uint count = unchecked((uint)Marshal.ReadInt32(table));
                int stride = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));
                IntPtr rowPointer = IntPtr.Add(table, sizeof(uint));
                List<int> owners = new List<int>();
                for (uint index = 0; index < count; index++) {
                    MIB_TCPROW_OWNER_PID row =
                        (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(
                            rowPointer, typeof(MIB_TCPROW_OWNER_PID)
                        );
                    if (
                        ntohs(unchecked((ushort)row.LocalPort)) == port &&
                        row.LocalAddress == 0x0100007F
                    ) {
                        owners.Add(unchecked((int)row.OwningProcessId));
                    }
                    rowPointer = IntPtr.Add(rowPointer, stride);
                }
                return owners.ToArray();
            } finally {
                Marshal.FreeHGlobal(table);
            }
        }
    }

    public static class ReleaseBoundedProcess {
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint STARTF_USESTDHANDLES = 0x00000100;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const int JobObjectExtendedLimitInformation = 9;
        private static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST =
            new IntPtr(0x00020002);

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO {
            public uint cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFOEX {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr attributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            IntPtr job,
            int informationClass,
            ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information,
            uint informationLength
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr attributeList,
            int attributeCount,
            int flags,
            ref UIntPtr size
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr attributeList,
            uint flags,
            IntPtr attribute,
            IntPtr value,
            UIntPtr size,
            IntPtr previousValue,
            IntPtr returnSize
        );

        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessW(
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref STARTUPINFOEX startupInfo,
            out PROCESS_INFORMATION processInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public sealed class Result {
            public int ExitCode { get; internal set; }
            public string Stdout { get; internal set; }
            public string Stderr { get; internal set; }
        }

        private sealed class ChildProcess : IDisposable {
            public Process Process { get; private set; }
            public Stream StandardInput { get; private set; }
            public Stream StandardOutput { get; private set; }
            public Stream StandardError { get; private set; }
            private SafeFileHandle job;
            private bool disposed;

            public ChildProcess(
                Process process,
                Stream standardInput,
                Stream standardOutput,
                Stream standardError,
                SafeFileHandle jobHandle
            ) {
                Process = process;
                StandardInput = standardInput;
                StandardOutput = standardOutput;
                StandardError = standardError;
                job = jobHandle;
            }

            public void TerminateTree() {
                if (job != null && !job.IsInvalid && !job.IsClosed) {
                    TerminateJobObject(job.DangerousGetHandle(), 1);
                    return;
                }
                try {
                    if (!Process.HasExited) {
                        Process.Kill();
                    }
                } catch { }
            }

            public void Dispose() {
                if (disposed) {
                    return;
                }
                disposed = true;
                foreach (Stream stream in new[] {
                    StandardInput, StandardOutput, StandardError
                }) {
                    if (stream != null && !Object.ReferenceEquals(stream, Stream.Null)) {
                        try { stream.Dispose(); } catch { }
                    }
                }
                if (Process != null) {
                    Process.Dispose();
                }
                if (job != null) {
                    job.Dispose();
                }
            }
        }

        private static byte[] ReadBounded(
            Stream stream, int maximumBytes, ChildProcess child, string label
        ) {
            byte[] buffer = new byte[65536];
            using (MemoryStream collected = new MemoryStream()) {
                while (true) {
                    int count = stream.Read(buffer, 0, buffer.Length);
                    if (count == 0) {
                        return collected.ToArray();
                    }
                    if (collected.Length + count > maximumBytes) {
                        child.TerminateTree();
                        throw new InvalidOperationException(
                            "Android child " + label + " exceeded its byte limit."
                        );
                    }
                    collected.Write(buffer, 0, count);
                }
            }
        }

        private static string QuoteArgument(string argument) {
            if (argument.Length == 0) {
                return "\"\"";
            }
            if (argument.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) < 0) {
                return argument;
            }
            StringBuilder quoted = new StringBuilder();
            quoted.Append('"');
            int backslashes = 0;
            foreach (char value in argument) {
                if (value == '\\') {
                    backslashes++;
                } else if (value == '"') {
                    quoted.Append('\\', backslashes * 2 + 1);
                    quoted.Append('"');
                    backslashes = 0;
                } else {
                    quoted.Append('\\', backslashes);
                    quoted.Append(value);
                    backslashes = 0;
                }
            }
            quoted.Append('\\', backslashes * 2);
            quoted.Append('"');
            return quoted.ToString();
        }

        private static string CommandLine(string fileName, string[] arguments) {
            StringBuilder line = new StringBuilder(QuoteArgument(fileName));
            foreach (string argument in arguments) {
                line.Append(' ');
                line.Append(QuoteArgument(argument));
            }
            return line.ToString();
        }

        private static ChildProcess StartPortable(
            string fileName, string[] arguments, bool redirectInput
        ) {
            ProcessStartInfo start = new ProcessStartInfo {
                FileName = fileName,
                Arguments = String.Join(" ", Array.ConvertAll(arguments, QuoteArgument)),
                UseShellExecute = false,
                RedirectStandardInput = redirectInput,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = Environment.CurrentDirectory
            };
            Process process = new Process { StartInfo = start };
            if (!process.Start()) {
                process.Dispose();
                throw new InvalidOperationException("Android child process did not start.");
            }
            return new ChildProcess(
                process,
                redirectInput ? process.StandardInput.BaseStream : Stream.Null,
                process.StandardOutput.BaseStream,
                process.StandardError.BaseStream,
                null
            );
        }

        private static ChildProcess StartWindows(
            string fileName, string[] arguments
        ) {
            if (!Path.IsPathRooted(fileName)) {
                throw new ArgumentException("Windows bounded process path is not absolute.");
            }
            SafeFileHandle job = null;
            AnonymousPipeServerStream stdinPipe = null;
            AnonymousPipeServerStream stdoutPipe = null;
            AnonymousPipeServerStream stderrPipe = null;
            IntPtr attributeList = IntPtr.Zero;
            IntPtr inheritedHandles = IntPtr.Zero;
            PROCESS_INFORMATION information = new PROCESS_INFORMATION();
            bool processCreated = false;
            bool assignedToJob = false;
            bool success = false;
            try {
                job = new SafeFileHandle(CreateJobObject(IntPtr.Zero, null), true);
                if (job.IsInvalid) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits =
                    new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                limits.BasicLimitInformation.LimitFlags =
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if (!SetInformationJobObject(
                    job.DangerousGetHandle(),
                    JobObjectExtendedLimitInformation,
                    ref limits,
                    unchecked((uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)))
                )) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                stdinPipe = new AnonymousPipeServerStream(
                    PipeDirection.Out, HandleInheritability.Inheritable
                );
                stdoutPipe = new AnonymousPipeServerStream(
                    PipeDirection.In, HandleInheritability.Inheritable
                );
                stderrPipe = new AnonymousPipeServerStream(
                    PipeDirection.In, HandleInheritability.Inheritable
                );
                IntPtr stdinClient = new IntPtr(Int64.Parse(
                    stdinPipe.GetClientHandleAsString(), CultureInfo.InvariantCulture
                ));
                IntPtr stdoutClient = new IntPtr(Int64.Parse(
                    stdoutPipe.GetClientHandleAsString(), CultureInfo.InvariantCulture
                ));
                IntPtr stderrClient = new IntPtr(Int64.Parse(
                    stderrPipe.GetClientHandleAsString(), CultureInfo.InvariantCulture
                ));

                UIntPtr attributeBytes = UIntPtr.Zero;
                InitializeProcThreadAttributeList(
                    IntPtr.Zero, 1, 0, ref attributeBytes
                );
                if (attributeBytes == UIntPtr.Zero) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                attributeList = Marshal.AllocHGlobal(
                    checked((int)attributeBytes.ToUInt64())
                );
                if (!InitializeProcThreadAttributeList(
                    attributeList, 1, 0, ref attributeBytes
                )) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                inheritedHandles = Marshal.AllocHGlobal(IntPtr.Size * 3);
                Marshal.WriteIntPtr(inheritedHandles, 0, stdinClient);
                Marshal.WriteIntPtr(inheritedHandles, IntPtr.Size, stdoutClient);
                Marshal.WriteIntPtr(inheritedHandles, IntPtr.Size * 2, stderrClient);
                if (!UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    inheritedHandles,
                    new UIntPtr(unchecked((uint)(IntPtr.Size * 3))),
                    IntPtr.Zero,
                    IntPtr.Zero
                )) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                STARTUPINFOEX startup = new STARTUPINFOEX();
                startup.StartupInfo.cb = unchecked((uint)Marshal.SizeOf(typeof(STARTUPINFOEX)));
                startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                startup.StartupInfo.hStdInput = stdinClient;
                startup.StartupInfo.hStdOutput = stdoutClient;
                startup.StartupInfo.hStdError = stderrClient;
                startup.lpAttributeList = attributeList;
                StringBuilder commandLine = new StringBuilder(
                    CommandLine(fileName, arguments)
                );
                processCreated = CreateProcessW(
                    fileName,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    true,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                    IntPtr.Zero,
                    Environment.CurrentDirectory,
                    ref startup,
                    out information
                );
                if (!processCreated) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                stdinPipe.DisposeLocalCopyOfClientHandle();
                stdoutPipe.DisposeLocalCopyOfClientHandle();
                stderrPipe.DisposeLocalCopyOfClientHandle();
                if (!AssignProcessToJobObject(
                    job.DangerousGetHandle(), information.hProcess
                )) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                assignedToJob = true;
                Process process = Process.GetProcessById(
                    unchecked((int)information.dwProcessId)
                );
                if (ResumeThread(information.hThread) == UInt32.MaxValue) {
                    process.Dispose();
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                ChildProcess child = new ChildProcess(
                    process, stdinPipe, stdoutPipe, stderrPipe, job
                );
                success = true;
                return child;
            } finally {
                if (information.hThread != IntPtr.Zero) {
                    CloseHandle(information.hThread);
                }
                if (information.hProcess != IntPtr.Zero) {
                    if (processCreated && !success) {
                        if (assignedToJob && job != null && !job.IsInvalid) {
                            TerminateJobObject(job.DangerousGetHandle(), 1);
                        } else {
                            TerminateProcess(information.hProcess, 1);
                        }
                    }
                    CloseHandle(information.hProcess);
                }
                if (attributeList != IntPtr.Zero) {
                    DeleteProcThreadAttributeList(attributeList);
                    Marshal.FreeHGlobal(attributeList);
                }
                if (inheritedHandles != IntPtr.Zero) {
                    Marshal.FreeHGlobal(inheritedHandles);
                }
                if (!success) {
                    if (stdinPipe != null) { stdinPipe.Dispose(); }
                    if (stdoutPipe != null) { stdoutPipe.Dispose(); }
                    if (stderrPipe != null) { stderrPipe.Dispose(); }
                    if (job != null) { job.Dispose(); }
                }
            }
        }

        private static int RemainingMilliseconds(Stopwatch timer, int maximum) {
            long remaining = maximum - timer.ElapsedMilliseconds;
            if (remaining <= 0) {
                return 0;
            }
            return remaining > Int32.MaxValue ? Int32.MaxValue : unchecked((int)remaining);
        }

        public static Result Run(
            string fileName,
            string[] arguments,
            byte[] standardInput,
            int maximumStdoutBytes,
            int maximumStderrBytes,
            int timeoutMilliseconds
        ) {
            if (
                String.IsNullOrWhiteSpace(fileName) || arguments == null ||
                (standardInput != null && standardInput.Length > 16777216) ||
                maximumStdoutBytes <= 0 || maximumStderrBytes <= 0 ||
                timeoutMilliseconds <= 0
            ) {
                throw new ArgumentException("Bounded process parameters are invalid.");
            }
            foreach (string argument in arguments) {
                if (argument == null) {
                    throw new ArgumentException("Bounded process argument is null.");
                }
            }
            Stopwatch timer = Stopwatch.StartNew();
            ChildProcess started = Environment.OSVersion.Platform == PlatformID.Win32NT
                ? StartWindows(fileName, arguments)
                : StartPortable(fileName, arguments, standardInput != null);
            using (ChildProcess child = started) {
                Task<byte[]> stdout = Task.Run(
                    () => ReadBounded(
                        child.StandardOutput,
                        maximumStdoutBytes,
                        child,
                        "stdout"
                    )
                );
                Task<byte[]> stderr = Task.Run(
                    () => ReadBounded(
                        child.StandardError,
                        maximumStderrBytes,
                        child,
                        "stderr"
                    )
                );
                Task stdin = Task.FromResult(0);
                if (standardInput != null) {
                    stdin = Task.Run(() => {
                        try {
                            child.StandardInput.Write(
                                standardInput, 0, standardInput.Length
                            );
                            child.StandardInput.Flush();
                        } finally {
                            child.StandardInput.Close();
                        }
                    });
                } else if (!Object.ReferenceEquals(child.StandardInput, Stream.Null)) {
                    child.StandardInput.Close();
                }
                int remaining = RemainingMilliseconds(timer, timeoutMilliseconds);
                if (remaining == 0 || !child.Process.WaitForExit(remaining)) {
                    child.TerminateTree();
                    child.Process.WaitForExit(5000);
                    throw new TimeoutException("Android child process timed out.");
                }
                try {
                    remaining = RemainingMilliseconds(timer, timeoutMilliseconds);
                    if (
                        remaining == 0 ||
                        !Task.WaitAll(new Task[] { stdin, stdout, stderr }, remaining)
                    ) {
                        child.TerminateTree();
                        Task.WaitAll(new Task[] { stdin, stdout, stderr }, 5000);
                        throw new TimeoutException(
                            "Android child process tree did not close its bounded streams."
                        );
                    }
                } catch {
                    child.TerminateTree();
                    throw;
                }
                child.TerminateTree();
                UTF8Encoding strictUtf8 = new UTF8Encoding(false, true);
                return new Result {
                    ExitCode = child.Process.ExitCode,
                    Stdout = strictUtf8.GetString(stdout.Result),
                    Stderr = strictUtf8.GetString(stderr.Result)
                };
            }
        }
    }
}
'@
    }

    $heldHelperText = Read-HeldUtf8Text -Stream $script:CustodyHelperStream
    $heldHelperModule = New-Module -ScriptBlock ([ScriptBlock]::Create($heldHelperText))
    & $heldHelperModule {
        param($ManifestPath)
        Assert-WinsAndroidToolchainCustodyManifestPreflight `
            -ManifestPath $ManifestPath -Platform 'windows_amd64'
    } $ToolchainCustodyManifest

    $pythonPath = [IO.Path]::GetFullPath($env:WINS_RELEASE_PYTHON)
    Assert-NoReparsePath -Path $pythonPath -Description 'Android release Python executable'
    $pythonItem = Get-Item -LiteralPath $pythonPath -Force -ErrorAction Stop
    if ($pythonItem.PSIsContainer -or
        ($pythonItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'OWNER-BLOCKED: WINS_RELEASE_PYTHON must be one regular non-reparse file.'
    }
    $pythonRoot = Get-AndroidToolchainRootFromExecutable -Executable $pythonPath
    $script:PythonCustodyStream = [IO.FileStream]::new(
        $pythonPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $script:PythonCustodyIdentity = Get-WinsFileIdentityFromStream `
        -Stream $script:PythonCustodyStream
    if ($script:PythonCustodyIdentity.NumberOfLinks -ne 1) {
        throw 'OWNER-BLOCKED: Android release Python executable must have exactly one link.'
    }
    Assert-OwnerIndependentReadOnlyPythonTree -Root $pythonRoot
    $record = & $heldHelperModule {
        param($ManifestPath, $RepositoryRoot, $RuntimeRoot)
        Assert-WinsAndroidToolchainCustody `
            -ManifestPath $ManifestPath -RepoRoot $RepositoryRoot `
            -Platform 'windows_amd64' -Tool 'python' -Root $RuntimeRoot
    } $ToolchainCustodyManifest $RepoRoot $pythonRoot
    $script:PythonCustodyDigest = Get-HeldReleaseFileDigest `
        -Stream $script:PythonCustodyStream `
        -ExpectedIdentity $script:PythonCustodyIdentity `
        -Description 'Android release Python executable'
    Assert-AuthenticatedReleasePythonStillBound
    Assert-AuthenticatedSupportFilesStillBound
    throw (
        'OWNER-BLOCKED: Windows process creation cannot prove execution from the held ' +
        'ReleasePython handle; pathname execution and parent/junction substitution are refused.'
    )
}

function Invoke-BoundedAndroidChild {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds,
        [byte[]]$StandardInput = $null,
        [int]$MaximumStdoutBytes = 4194304,
        [int]$MaximumStderrBytes = 1048576
    )

    $result = [WinsVpn.ReleaseBoundedProcess]::Run(
        $FilePath,
        $Arguments,
        $StandardInput,
        $MaximumStdoutBytes,
        $MaximumStderrBytes,
        $TimeoutMilliseconds
    )
    $lines = [Collections.Generic.List[string]]::new()
    foreach ($text in @($result.Stdout, $result.Stderr)) {
        if ([string]::IsNullOrEmpty($text)) { continue }
        foreach ($line in ($text -split '\r?\n')) {
            if (-not [string]::IsNullOrEmpty($line)) {
                $lines.Add($line)
            }
        }
    }
    return [pscustomobject]@{
        ExitCode = $result.ExitCode
        Lines = @($lines)
    }
}

$Python = Resolve-AuthenticatedReleasePython

function Start-DedicatedAdbServer {
    param([Parameter(Mandatory = $true)][string]$AdbPath)

    $reservation = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $reservation.Start()
    try {
        $port = ([Net.IPEndPoint]$reservation.LocalEndpoint).Port
    } finally {
        $reservation.Stop()
    }
    $socket = "tcp:127.0.0.1:$port"
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $AdbPath
    $start.Arguments = "-L $socket server nodaemon"
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $process = [Diagnostics.Process]::Start($start)
    if ($null -eq $process) {
        throw 'Android evidence could not start the dedicated ADB server.'
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    try {
        while ([DateTime]::UtcNow -lt $deadline) {
            $process.Refresh()
            if ($process.HasExited) {
                throw "Dedicated ADB server exited before binding loopback port $port."
            }
            $owners = @([WinsVpn.ReleaseTcpListener]::LoopbackOwnerProcessIds($port))
            if ($owners.Count -eq 1 -and $owners[0] -eq $process.Id) {
                $script:DedicatedAdbServer = $process
                $script:DedicatedAdbServerPort = $port
                return $socket
            }
            Start-Sleep -Milliseconds 100
        }
        throw "Dedicated ADB server did not exclusively bind loopback port $port."
    } catch {
        if (-not $process.HasExited) {
            $process.Kill()
            $process.WaitForExit(5000) | Out-Null
        }
        $process.Dispose()
        throw
    }
}

function Assert-DedicatedAdbServerStillBound {
    if ($null -eq $script:DedicatedAdbServer -or $script:DedicatedAdbServerPort -lt 1) {
        throw 'Dedicated ADB server custody is absent.'
    }
    $script:DedicatedAdbServer.Refresh()
    if ($script:DedicatedAdbServer.HasExited) {
        throw 'Dedicated ADB server exited during physical evidence collection.'
    }
    $owners = @(
        [WinsVpn.ReleaseTcpListener]::LoopbackOwnerProcessIds(
            $script:DedicatedAdbServerPort
        )
    )
    if ($owners.Count -ne 1 -or $owners[0] -ne $script:DedicatedAdbServer.Id) {
        throw 'Dedicated ADB server listener ownership changed during collection.'
    }
}

function Stop-DedicatedAdbServer {
    if ($null -ne $script:DedicatedAdbServer) {
        $script:DedicatedAdbServer.Refresh()
        if (-not $script:DedicatedAdbServer.HasExited) {
            $script:DedicatedAdbServer.Kill()
            $script:DedicatedAdbServer.WaitForExit(5000) | Out-Null
        }
        $script:DedicatedAdbServer.Dispose()
        $script:DedicatedAdbServer = $null
        $script:DedicatedAdbServerPort = 0
    }
}

function Get-UniqueMarker {
    param(
        [Parameter(Mandatory = $true)][string[]]$Lines,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ValuePattern
    )
    $matches = @($Lines | Where-Object { $_ -match ('^' + [regex]::Escape($Name) + '=') })
    if ($matches.Count -ne 1) {
        throw "Android physical collector/compiler returned $($matches.Count) $Name markers; exactly one is required."
    }
    $value = $matches[0].Substring($Name.Length + 1)
    if ($value -cnotmatch $ValuePattern) {
        throw "Android physical collector/compiler returned an invalid $Name marker."
    }
    return $value
}

$arguments = @(
    (Join-Path $PSScriptRoot 'public_release_live_smoke_common.py'),
    '--platform', 'android',
    '--producer', 'tools/android_public_release_live_smoke.ps1'
)
if ($SelfTest) {
    $selfTestMarkers = @{
        'android_release_matrix_evidence.py' = 'ANDROID RELEASE MATRIX EVIDENCE COMPILER SELF-TEST: PASS'
        'android_release_ui_driver.py' = 'ANDROID RELEASE UI DRIVER SELF-TEST: PASS'
        'android_remote_route_control.py' = 'ANDROID REMOTE ROUTE CONTROL SELF-TEST: PASS'
        'android_final_evidence_collector.py' = 'ANDROID FINAL EVIDENCE COLLECTOR SELF-TEST: PASS'
    }
    foreach ($selfTestScript in @(
        'android_release_matrix_evidence.py',
        'android_release_ui_driver.py',
        'android_remote_route_control.py',
        'android_final_evidence_collector.py'
    )) {
        $selfTestArgs = @((Join-Path $PSScriptRoot $selfTestScript))
        if ($selfTestScript -in @('android_remote_route_control.py', 'android_release_ui_driver.py')) {
            $selfTestArgs += 'self-test'
        } else {
            $selfTestArgs += '--self-test'
        }
        $isolatedSelfTestInvocation = New-HeldPythonArguments `
            -EntryPoint "tools/$selfTestScript" `
            -ScriptArguments @($selfTestArgs | Select-Object -Skip 1)
        $selfTestResult = Invoke-BoundedAndroidChild `
            -FilePath $Python -Arguments $isolatedSelfTestInvocation.Arguments `
            -StandardInput $isolatedSelfTestInvocation.StandardInput `
            -TimeoutMilliseconds 120000
        $selfTestOutput = @($selfTestResult.Lines)
        $selfTestExitCode = $selfTestResult.ExitCode
        $selfTestOutput | Write-Output
        if ($selfTestExitCode -ne 0) {
            throw "Android evidence helper self-test failed for $selfTestScript with exit code $selfTestExitCode."
        }
        $expectedSelfTestMarker = $selfTestMarkers[$selfTestScript]
        $selfTestMarkerCount = @(
            $selfTestOutput | Where-Object { $_ -ceq $expectedSelfTestMarker }
        ).Count
        if ($selfTestMarkerCount -ne 1) {
            throw "Android evidence helper self-test returned $selfTestMarkerCount exact PASS markers for $selfTestScript; exactly one is required."
        }
        Assert-AuthenticatedReleasePythonStillBound
        Assert-AuthenticatedSupportFilesStillBound
    }
    $arguments += '--self-test'
} else {
    if ($ExpectedFormFactorOwnerAuthoritySha256 -ceq ('0' * 64)) {
        throw 'OWNER-BLOCKED: reviewed Android owner authority is not provisioned in the source-frozen wrapper.'
    }
    if ([string]::IsNullOrWhiteSpace($ReleaseInputIndex) -or
        [string]::IsNullOrWhiteSpace($BuildReceipt) -or
        [string]::IsNullOrWhiteSpace($FormFactorEvidenceManifest) -or
        [string]::IsNullOrWhiteSpace($ExpectedFormFactorEvidenceManifestSha256) -or
        [string]::IsNullOrWhiteSpace($FormFactorOwnerAuthorization) -or
        [string]::IsNullOrWhiteSpace($ExpectedFormFactorOwnerAuthorizationSha256) -or
        [string]::IsNullOrWhiteSpace($DeviceAttestationReceipt) -or
        [string]::IsNullOrWhiteSpace($DeviceCheckBuildReceipt) -or
        [string]::IsNullOrWhiteSpace($ExpectedDeviceCheckBuildReceiptSha256) -or
        [string]::IsNullOrWhiteSpace($ExpectedDeviceCheckTargetApkSha256) -or
        [string]::IsNullOrWhiteSpace($ExpectedDeviceCheckTargetApkBytes) -or
        [string]::IsNullOrWhiteSpace($ExpectedDeviceCheckAndroidTestApkSha256) -or
        [string]::IsNullOrWhiteSpace($ExpectedDeviceCheckAndroidTestApkBytes) -or
        [string]::IsNullOrWhiteSpace($ExpectedDeviceCheckSourceInventorySha256)) {
        throw 'ReleaseInputIndex, BuildReceipt, DeviceCheck build receipt, form-factor manifest, owner authorization, and physical-device attestation are required for the exact frozen Android candidate.'
    }
    if ($ExpectedFormFactorEvidenceManifestSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedFormFactorOwnerAuthorizationSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedDeviceCheckBuildReceiptSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedDeviceCheckTargetApkSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedDeviceCheckAndroidTestApkSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedDeviceCheckSourceInventorySha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Form-factor manifest, owner authorization, DeviceCheck receipt, APK, and source-inventory expected hashes must be lowercase SHA-256 values.'
    }
    if ($ExpectedDeviceCheckTargetApkBytes -cnotmatch '^[1-9][0-9]{0,9}$' -or
        $ExpectedDeviceCheckAndroidTestApkBytes -cnotmatch '^[1-9][0-9]{0,9}$' -or
        [uint64]$ExpectedDeviceCheckTargetApkBytes -gt 536870912 -or
        [uint64]$ExpectedDeviceCheckAndroidTestApkBytes -gt 536870912) {
        throw 'DeviceCheck target and androidTest APK owner-pinned byte counts are invalid.'
    }
    if ([string]::IsNullOrWhiteSpace($RouteInventory) -or
        [string]::IsNullOrWhiteSpace($SshConfig) -or
        [string]::IsNullOrWhiteSpace($SshIdentity) -or
        [string]::IsNullOrWhiteSpace($SshKnownHosts) -or
        [string]::IsNullOrWhiteSpace($Serial) -or
        [string]::IsNullOrWhiteSpace($Tesseract) -or
        $ExpectedMapCity.Count -lt 2) {
        throw 'Every qualifying Android run requires owner-authorized route inventory, SSH config/identity/known-hosts, USB Serial, Tesseract, and map labels.'
    }
    if ([string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        throw 'OWNER-BLOCKED: Windows SystemRoot is required for native evidence-tool custody.'
    }
    if ([string]::IsNullOrWhiteSpace($Adb) -or -not [IO.Path]::IsPathRooted($Adb)) {
        throw 'OWNER-BLOCKED: Adb must name the reviewed absolute Platform-Tools adb.exe.'
    }
    $PowerShellExecutable = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $SshExecutable = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    $WhoAmIExecutable = Join-Path $env:SystemRoot 'System32\whoami.exe'
    $IcaclsExecutable = Join-Path $env:SystemRoot 'System32\icacls.exe'
    $TaskkillExecutable = Join-Path $env:SystemRoot 'System32\taskkill.exe'

    $artifactPath = [IO.Path]::GetFullPath(
        $(if ([IO.Path]::IsPathRooted($Artifact)) { $Artifact } else { Join-Path $RepoRoot $Artifact })
    )
    $routeInventoryPath = [IO.Path]::GetFullPath(
        $(if ([IO.Path]::IsPathRooted($RouteInventory)) { $RouteInventory } else { Join-Path $RepoRoot $RouteInventory })
    )
    $sshConfigPath = [IO.Path]::GetFullPath(
        $(if ([IO.Path]::IsPathRooted($SshConfig)) { $SshConfig } else { Join-Path $RepoRoot $SshConfig })
    )
    $sshIdentityPath = [IO.Path]::GetFullPath(
        $(if ([IO.Path]::IsPathRooted($SshIdentity)) { $SshIdentity } else { Join-Path $RepoRoot $SshIdentity })
    )
    $sshKnownHostsPath = [IO.Path]::GetFullPath(
        $(if ([IO.Path]::IsPathRooted($SshKnownHosts)) { $SshKnownHosts } else { Join-Path $RepoRoot $SshKnownHosts })
    )
    $tesseractPath = [IO.Path]::GetFullPath(
        $(if ([IO.Path]::IsPathRooted($Tesseract)) { $Tesseract } else { Join-Path $RepoRoot $Tesseract })
    )
    $indexPath = [IO.Path]::GetFullPath(
        $(if ([IO.Path]::IsPathRooted($ReleaseInputIndex)) { $ReleaseInputIndex } else { Join-Path $RepoRoot $ReleaseInputIndex })
    )
    $receiptPath = [IO.Path]::GetFullPath(
        $(if ([IO.Path]::IsPathRooted($BuildReceipt)) { $BuildReceipt } else { Join-Path $RepoRoot $BuildReceipt })
    )
    $formFactorManifestPath = [IO.Path]::GetFullPath(
        $(if ([IO.Path]::IsPathRooted($FormFactorEvidenceManifest)) { $FormFactorEvidenceManifest } else { Join-Path $RepoRoot $FormFactorEvidenceManifest })
    )
    $ownerAuthorizationPath = [IO.Path]::GetFullPath(
        $(if ([IO.Path]::IsPathRooted($FormFactorOwnerAuthorization)) { $FormFactorOwnerAuthorization } else { Join-Path $RepoRoot $FormFactorOwnerAuthorization })
    )
    $deviceAttestationPath = [IO.Path]::GetFullPath(
        $(if ([IO.Path]::IsPathRooted($DeviceAttestationReceipt)) { $DeviceAttestationReceipt } else { Join-Path $RepoRoot $DeviceAttestationReceipt })
    )
    $deviceCheckBuildReceiptPath = [IO.Path]::GetFullPath(
        $(if ([IO.Path]::IsPathRooted($DeviceCheckBuildReceipt)) { $DeviceCheckBuildReceipt } else { Join-Path $RepoRoot $DeviceCheckBuildReceipt })
    )
    $expectedDeviceCheckBuildReceiptPath = [IO.Path]::GetFullPath(
        (Join-Path $RepoRoot 'android\devicecheck\app\build\outputs\devicecheck-receipts\release\DEVICECHECK_BUILD_RECEIPT.json')
    )
    if ($deviceCheckBuildReceiptPath -cne $expectedDeviceCheckBuildReceiptPath) {
        throw 'DeviceCheck build receipt must use the exact release producer-custody path.'
    }
    $deviceCheckBuildReceiptSidecarPath = "$deviceCheckBuildReceiptPath.sha256"
    $deviceCheckTargetApkPath = [IO.Path]::GetFullPath(
        (Join-Path $RepoRoot 'android\devicecheck\app\build\outputs\apk\release\app-release.apk')
    )
    $deviceCheckAndroidTestApkPath = [IO.Path]::GetFullPath(
        (Join-Path $RepoRoot 'android\devicecheck\app\build\outputs\apk\androidTest\release\app-release-androidTest.apk')
    )
    foreach ($requiredFile in @(
        $artifactPath,
        $routeInventoryPath,
        $sshConfigPath,
        $sshIdentityPath,
        $sshKnownHostsPath,
        $tesseractPath,
        $indexPath,
        $receiptPath,
        $formFactorManifestPath,
        $ownerAuthorizationPath,
        $deviceAttestationPath,
        $deviceCheckBuildReceiptPath,
        $deviceCheckBuildReceiptSidecarPath,
        $deviceCheckTargetApkPath,
        $deviceCheckAndroidTestApkPath,
        $Adb,
        $PowerShellExecutable,
        $SshExecutable,
        $WhoAmIExecutable,
        $IcaclsExecutable,
        $TaskkillExecutable
    )) {
        if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
            throw "Required Android physical-run input does not exist: $requiredFile"
        }
    }
    $nativeTools = [ordered]@{
        adb = [IO.Path]::GetFullPath($Adb)
        tesseract = $tesseractPath
        powershell = [IO.Path]::GetFullPath($PowerShellExecutable)
        ssh = [IO.Path]::GetFullPath($SshExecutable)
        whoami = [IO.Path]::GetFullPath($WhoAmIExecutable)
        icacls = [IO.Path]::GetFullPath($IcaclsExecutable)
        taskkill = [IO.Path]::GetFullPath($TaskkillExecutable)
    }
    $adbSupportRoot = [IO.Path]::GetDirectoryName([string]$nativeTools.adb)
    if ([string]::IsNullOrWhiteSpace($adbSupportRoot)) {
        throw 'OWNER-BLOCKED: reviewed ADB executable has no support-tree root.'
    }
    Assert-OwnerIndependentReadOnlyAdbTree -Root $adbSupportRoot
    foreach ($role in $nativeTools.Keys) {
        $path = [string]$nativeTools[$role]
        Assert-NoReparsePath -Path $path -Description "Android $role executable"
        $stream = [IO.FileStream]::new(
            $path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $script:NativeToolStreams.Add([pscustomobject]@{
            Role = $role
            Path = $path
            Digest = Get-HeldStreamSha256 -Stream $stream
            Stream = $stream
        })
    }
    $adbSupportFiles = @(
        Get-ChildItem -LiteralPath $adbSupportRoot -File -Force -Recurse -ErrorAction Stop |
            Sort-Object -Property FullName
    )
    $requiredAdbRuntime = @('adb.exe', 'AdbWinApi.dll', 'AdbWinUsbApi.dll')
    foreach ($requiredName in $requiredAdbRuntime) {
        if (@($adbSupportFiles | Where-Object { $_.Name -ceq $requiredName }).Count -ne 1) {
            throw "OWNER-BLOCKED: reviewed ADB support tree requires one $requiredName."
        }
    }
    foreach ($item in $adbSupportFiles) {
        Assert-NoReparsePath -Path $item.FullName -Description 'Android ADB support file'
        $stream = [IO.FileStream]::new(
            $item.FullName,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $identity = Get-WinsFileIdentityFromStream -Stream $stream
        if ($identity.NumberOfLinks -ne 1 -or $identity.FileSize -eq 0) {
            $stream.Dispose()
            throw "OWNER-BLOCKED: ADB support file is empty or hardlinked: $($item.FullName)"
        }
        $script:NativeToolStreams.Add([pscustomobject]@{
            Role = "adb-support:$($item.FullName.Substring($adbSupportRoot.Length).TrimStart('\'))"
            Path = $item.FullName
            Digest = Get-HeldStreamSha256 -Stream $stream
            Stream = $stream
        })
    }
    $tesseractSupportRoot = [IO.Path]::GetDirectoryName([string]$nativeTools.tesseract)
    if ([string]::IsNullOrWhiteSpace($tesseractSupportRoot) -or
        [IO.Path]::GetFileName([string]$nativeTools.tesseract) -cne 'tesseract.exe') {
        throw 'OWNER-BLOCKED: reviewed Tesseract executable must be the canonical tesseract.exe.'
    }
    Assert-OwnerIndependentReadOnlyTesseractTree -Root $tesseractSupportRoot
    $tesseractSupportFiles = @(
        Get-ChildItem -LiteralPath $tesseractSupportRoot -File -Force -Recurse -ErrorAction Stop |
            Sort-Object -Property FullName
    )
    $requiredTessdata = Join-Path $tesseractSupportRoot 'tessdata\eng.traineddata'
    if (@($tesseractSupportFiles | Where-Object {
        $_.FullName -ceq $requiredTessdata
    }).Count -ne 1) {
        throw 'OWNER-BLOCKED: reviewed Tesseract runtime requires exact English tessdata.'
    }
    foreach ($item in $tesseractSupportFiles) {
        Assert-NoReparsePath -Path $item.FullName -Description 'Android Tesseract support file'
        $stream = [IO.FileStream]::new(
            $item.FullName,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $identity = Get-WinsFileIdentityFromStream -Stream $stream
        if ($identity.NumberOfLinks -ne 1 -or $identity.FileSize -eq 0) {
            $stream.Dispose()
            throw "OWNER-BLOCKED: Tesseract support file is empty or hardlinked: $($item.FullName)"
        }
        $script:NativeToolStreams.Add([pscustomobject]@{
            Role = "tesseract-support:$($item.FullName.Substring($tesseractSupportRoot.Length).TrimStart('\'))"
            Path = $item.FullName
            Digest = Get-HeldStreamSha256 -Stream $stream
            Stream = $stream
        })
    }
    $routeAuthority = [ordered]@{
        route_inventory = $routeInventoryPath
        ssh_config = $sshConfigPath
        ssh_identity = $sshIdentityPath
        ssh_known_hosts = $sshKnownHostsPath
        device_attestation = $deviceAttestationPath
        devicecheck_build_receipt = $deviceCheckBuildReceiptPath
        devicecheck_build_receipt_sidecar = $deviceCheckBuildReceiptSidecarPath
        devicecheck_target_apk = $deviceCheckTargetApkPath
        devicecheck_android_test_apk = $deviceCheckAndroidTestApkPath
    }
    foreach ($role in $routeAuthority.Keys) {
        $path = [string]$routeAuthority[$role]
        Assert-NoReparsePath -Path $path -Description "Android $role"
        $stream = [IO.FileStream]::new(
            $path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $identity = Get-WinsFileIdentityFromStream -Stream $stream
        if ($identity.NumberOfLinks -ne 1 -or $identity.FileSize -eq 0) {
            $stream.Dispose()
            throw "OWNER-BLOCKED: Android $role is empty or hardlinked."
        }
        $script:RouteAuthorityStreams.Add([pscustomobject]@{
            Role = $role
            Path = $path
            Digest = Get-HeldStreamSha256 -Stream $stream
            Stream = $stream
        })
    }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $formFactorManifestPath).Hash.ToLowerInvariant() -cne
        $ExpectedFormFactorEvidenceManifestSha256) {
        throw 'Android form-factor evidence manifest changed before physical collection.'
    }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $ownerAuthorizationPath).Hash.ToLowerInvariant() -cne
        $ExpectedFormFactorOwnerAuthorizationSha256) {
        throw 'Android form-factor owner authorization changed before physical collection.'
    }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $deviceCheckBuildReceiptPath).Hash.ToLowerInvariant() -cne
        $ExpectedDeviceCheckBuildReceiptSha256) {
        throw 'Android DeviceCheck build receipt changed before physical collection.'
    }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $deviceCheckTargetApkPath).Hash.ToLowerInvariant() -cne
        $ExpectedDeviceCheckTargetApkSha256 -or
        (Get-Item -LiteralPath $deviceCheckTargetApkPath).Length -ne
        [uint64]$ExpectedDeviceCheckTargetApkBytes) {
        throw 'Android DeviceCheck target APK contradicts owner-pinned custody.'
    }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $deviceCheckAndroidTestApkPath).Hash.ToLowerInvariant() -cne
        $ExpectedDeviceCheckAndroidTestApkSha256 -or
        (Get-Item -LiteralPath $deviceCheckAndroidTestApkPath).Length -ne
        [uint64]$ExpectedDeviceCheckAndroidTestApkBytes) {
        throw 'Android DeviceCheck androidTest APK contradicts owner-pinned custody.'
    }

    # There is intentionally no caller-supplied evidence/resume path. Every
    # non-self-test invocation creates one fresh physical bundle.
    $bundleParent = Join-Path $RepoRoot '.artifacts\android-final-bundles'
    $preexistingBundlePaths = if (Test-Path -LiteralPath $bundleParent -PathType Container) {
        @(Get-ChildItem -LiteralPath $bundleParent -Directory -Force | ForEach-Object { $_.FullName })
    } else {
        @()
    }
    $adbEnvironmentNames = @(
        'ADB_SERVER_SOCKET',
        'ADB_LIBUSB',
        'ANDROID_ADB_SERVER_ADDRESS',
        'ANDROID_ADB_SERVER_PORT'
    )
    $adbEnvironmentNames += @(
        Get-ChildItem Env: | Where-Object {
            $_.Name -like 'TESSDATA*' -or $_.Name -like 'TESSERACT*'
        } | ForEach-Object { $_.Name }
    )
    $adbEnvironmentNames = @($adbEnvironmentNames | Sort-Object -Unique)
    $priorAdbEnvironment = @{}
    foreach ($name in $adbEnvironmentNames) {
        $priorAdbEnvironment[$name] = [Environment]::GetEnvironmentVariable(
            $name, [EnvironmentVariableTarget]::Process
        )
        [Environment]::SetEnvironmentVariable(
            $name, $null, [EnvironmentVariableTarget]::Process
        )
    }
    try {
        [Environment]::SetEnvironmentVariable(
            'ADB_LIBUSB', '1', [EnvironmentVariableTarget]::Process
        )
        $dedicatedAdbSocket = Start-DedicatedAdbServer -AdbPath ([string]$nativeTools.adb)
        [Environment]::SetEnvironmentVariable(
            'ADB_SERVER_SOCKET', $dedicatedAdbSocket,
            [EnvironmentVariableTarget]::Process
        )
    } catch {
        foreach ($name in $adbEnvironmentNames) {
            [Environment]::SetEnvironmentVariable(
                $name, $priorAdbEnvironment[$name],
                [EnvironmentVariableTarget]::Process
            )
        }
        throw
    }
    $collectorArgs = @(
        (Join-Path $PSScriptRoot 'android_final_evidence_collector.py'),
        '--apk', $artifactPath,
        '--adb', ([string]$nativeTools.adb),
        '--adb-support-root', $adbSupportRoot,
        '--expected-adb-server-socket', $dedicatedAdbSocket,
        '--serial', $Serial,
        '--pin', $Pin,
        '--route-inventory', $routeInventoryPath,
        '--ssh-config', $sshConfigPath,
        '--ssh-identity', $sshIdentityPath,
        '--ssh-known-hosts', $sshKnownHostsPath,
        '--release-input-index', $indexPath,
        '--build-receipt', $receiptPath,
        '--form-factor-evidence-manifest', $formFactorManifestPath,
        '--expected-form-factor-evidence-manifest-sha256', $ExpectedFormFactorEvidenceManifestSha256,
        '--form-factor-owner-authorization', $ownerAuthorizationPath,
        '--expected-form-factor-owner-authorization-sha256', $ExpectedFormFactorOwnerAuthorizationSha256,
        '--device-attestation-receipt', $deviceAttestationPath,
        '--devicecheck-build-receipt', $deviceCheckBuildReceiptPath,
        '--expected-devicecheck-build-receipt-sha256', $ExpectedDeviceCheckBuildReceiptSha256,
        '--expected-devicecheck-target-apk-sha256', $ExpectedDeviceCheckTargetApkSha256,
        '--expected-devicecheck-target-apk-bytes', $ExpectedDeviceCheckTargetApkBytes,
        '--expected-devicecheck-android-test-apk-sha256', $ExpectedDeviceCheckAndroidTestApkSha256,
        '--expected-devicecheck-android-test-apk-bytes', $ExpectedDeviceCheckAndroidTestApkBytes,
        '--expected-devicecheck-source-inventory-sha256', $ExpectedDeviceCheckSourceInventorySha256,
        '--tesseract', $tesseractPath,
        '--tesseract-support-root', $tesseractSupportRoot,
        '--powershell', $PowerShellExecutable,
        '--ssh', $SshExecutable,
        '--whoami', $WhoAmIExecutable,
        '--icacls', $IcaclsExecutable,
        '--taskkill', $TaskkillExecutable,
        '--output-root', $bundleParent
    )
    foreach ($city in $ExpectedMapCity) { $collectorArgs += @('--expected-map-city', $city) }
    if ($AcknowledgeThirdPartySecuritySheet) {
        $collectorArgs += '--acknowledge-third-party-security-sheet'
    }
    $isolatedCollectorInvocation = New-HeldPythonArguments `
        -EntryPoint 'tools/android_final_evidence_collector.py' `
        -ScriptArguments @($collectorArgs | Select-Object -Skip 1)
    try {
        Assert-DedicatedAdbServerStillBound
        $collectorResult = Invoke-BoundedAndroidChild `
            -FilePath $Python -Arguments $isolatedCollectorInvocation.Arguments `
            -StandardInput $isolatedCollectorInvocation.StandardInput `
            -TimeoutMilliseconds 3600000
        $collectorOutput = @($collectorResult.Lines)
        $collectorExitCode = $collectorResult.ExitCode
        Assert-DedicatedAdbServerStillBound
    } finally {
        Stop-DedicatedAdbServer
        foreach ($name in $adbEnvironmentNames) {
            [Environment]::SetEnvironmentVariable(
                $name, $priorAdbEnvironment[$name],
                [EnvironmentVariableTarget]::Process
            )
        }
    }
    $collectorOutput | Write-Output
    if ($collectorExitCode -ne 0) {
        throw "Android physical evidence collection failed with exit code $collectorExitCode."
    }
    Assert-AuthenticatedReleasePythonStillBound
    Assert-AuthenticatedSupportFilesStillBound
    $runId = Get-UniqueMarker -Lines $collectorOutput -Name 'EVIDENCE_RUN_ID' `
        -ValuePattern '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    $bundleIndexExpectedSha = Get-UniqueMarker -Lines $collectorOutput -Name 'EVIDENCE_INDEX_SHA256' `
        -ValuePattern '^[0-9a-f]{64}$'
    $bundleIndexPath = Get-UniqueMarker -Lines $collectorOutput -Name 'EVIDENCE_INDEX_PATH' `
        -ValuePattern '^.+EVIDENCE_INDEX\.json$'
    $bundleIndexPath = (Resolve-Path -LiteralPath $bundleIndexPath).Path
    $bundlePath = [IO.Path]::GetDirectoryName($bundleIndexPath)
    $requiredBundlePrefix = [IO.Path]::GetFullPath($bundleParent) + [IO.Path]::DirectorySeparatorChar
    if (-not ($bundlePath + [IO.Path]::DirectorySeparatorChar).StartsWith(
        $requiredBundlePrefix, [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'Android collector returned an evidence index outside the private bundle root.'
    }
    if ($preexistingBundlePaths -contains $bundlePath) {
        throw 'Android collector attempted to reuse a preexisting evidence bundle.'
    }
    if ([IO.Path]::GetFileName($bundlePath) -cne $runId) {
        throw 'Android collector returned a bundle directory that does not match its fresh run ID.'
    }
    $indexRecord = Add-HeldAndroidEvidenceFile `
        -Path $bundleIndexPath -Role 'evidence-index' `
        -ExpectedSha256 $bundleIndexExpectedSha
    $bundleIndexText = Read-HeldUtf8Text -Stream $indexRecord.Stream
    $bundleIndex = $bundleIndexText | ConvertFrom-Json -ErrorAction Stop
    $indexedFiles = @($bundleIndex.files)
    if ($indexedFiles.Count -lt 1) {
        throw 'Android evidence index contains no held member inventory.'
    }
    $heldNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $indexedFiles) {
        $name = [string]$entry.path
        $digest = ([string]$entry.sha256).ToLowerInvariant()
        $size = [long]$entry.size_bytes
        if ([string]::IsNullOrWhiteSpace($name) -or
            [IO.Path]::GetFileName($name) -cne $name -or
            -not $heldNames.Add($name)) {
            throw 'Android evidence index contains an unsafe or duplicate member path.'
        }
        $memberPath = [IO.Path]::GetFullPath((Join-Path $bundlePath $name))
        if (-not ($memberPath + [IO.Path]::DirectorySeparatorChar).StartsWith(
            $bundlePath + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw 'Android evidence index member escaped the exact bundle.'
        }
        Add-HeldAndroidEvidenceFile `
            -Path $memberPath -Role "evidence-member:$name" `
            -ExpectedSha256 $digest -ExpectedSize $size | Out-Null
    }
    Assert-AuthenticatedSupportFilesStillBound

    $transcriptRoot = Join-Path $RepoRoot '.artifacts\android-native-transcripts'
    New-Item -ItemType Directory -Force -Path $transcriptRoot | Out-Null
    $transcriptPath = Join-Path $transcriptRoot "$runId.json"
    if (Test-Path -LiteralPath $transcriptPath) {
        throw "Refusing to reuse an Android native transcript: $transcriptPath"
    }
    $compilerArgs = @(
        (Join-Path $PSScriptRoot 'android_release_matrix_evidence.py'),
        '--evidence-index', $bundleIndexPath,
        '--expected-evidence-index-sha256', $bundleIndexExpectedSha,
        '--expected-run-id', $runId,
        '--artifact', $artifactPath,
        '--release-input-index', $indexPath,
        '--build-receipt', $receiptPath,
        '--output', $transcriptPath
    )
    $isolatedCompilerInvocation = New-HeldPythonArguments `
        -EntryPoint 'tools/android_release_matrix_evidence.py' `
        -ScriptArguments @($compilerArgs | Select-Object -Skip 1)
    $compilerResult = Invoke-BoundedAndroidChild `
        -FilePath $Python -Arguments $isolatedCompilerInvocation.Arguments `
        -StandardInput $isolatedCompilerInvocation.StandardInput `
        -TimeoutMilliseconds 600000
    $compilerOutput = @($compilerResult.Lines)
    $compilerExitCode = $compilerResult.ExitCode
    $compilerOutput | Write-Output
    if ($compilerExitCode -ne 0) {
        throw "Android indexed evidence compilation failed with exit code $compilerExitCode. Rerun the complete physical collection."
    }
    Assert-AuthenticatedReleasePythonStillBound
    Assert-AuthenticatedSupportFilesStillBound
    $compiledRunId = Get-UniqueMarker -Lines $compilerOutput -Name 'EVIDENCE_RUN_ID' `
        -ValuePattern '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    $compiledIndexSha = Get-UniqueMarker -Lines $compilerOutput -Name 'EVIDENCE_INDEX_SHA256' `
        -ValuePattern '^[0-9a-f]{64}$'
    $mapScreenshotPath = Get-UniqueMarker -Lines $compilerOutput -Name 'EVIDENCE_MAP_SCREENSHOT_PATH' `
        -ValuePattern '^.+\.(png|jpg|jpeg)$'
    if ($compiledRunId -cne $runId -or $compiledIndexSha -cne $bundleIndexExpectedSha) {
        throw 'Android compiler did not preserve the fresh collector run/index identity.'
    }
    $mapScreenshotPath = (Resolve-Path -LiteralPath $mapScreenshotPath).Path
    if (-not ($mapScreenshotPath + [IO.Path]::DirectorySeparatorChar).StartsWith(
        $bundlePath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'Android compiler returned a map screenshot outside the indexed evidence bundle.'
    }
    $transcriptRecord = Add-HeldAndroidEvidenceFile `
        -Path $transcriptPath -Role 'native-transcript'
    $heldMapRecords = @(
        $script:EvidenceBundleStreams | Where-Object {
            $_.Path -ceq [IO.Path]::GetFullPath($mapScreenshotPath)
        }
    )
    if ($heldMapRecords.Count -ne 1) {
        throw 'Android compiler map screenshot is not the exact held indexed member.'
    }
    Assert-AuthenticatedSupportFilesStillBound
    $arguments += @(
        '--artifact', $artifactPath,
        '--native-transcript', $transcriptPath,
        '--map-screenshot', $mapScreenshotPath,
        '--release-input-index', $indexPath,
        '--build-receipt', $receiptPath,
        '--output-root', $OutputRoot
    )
}

$isolatedProducerInvocation = New-HeldPythonArguments `
    -EntryPoint 'tools/public_release_live_smoke_common.py' `
    -ScriptArguments @($arguments | Select-Object -Skip 1)
$producerResult = Invoke-BoundedAndroidChild `
    -FilePath $Python -Arguments $isolatedProducerInvocation.Arguments `
    -StandardInput $isolatedProducerInvocation.StandardInput `
    -TimeoutMilliseconds 600000
$producerOutput = @($producerResult.Lines)
$producerExitCode = $producerResult.ExitCode
$producerOutput | Write-Output
if ($producerExitCode -ne 0) {
    throw "Android public-release live-smoke producer failed with exit code $producerExitCode."
}
Assert-AuthenticatedReleasePythonStillBound
Assert-AuthenticatedSupportFilesStillBound
if ($SelfTest) {
    $producerMarker = 'PUBLIC RELEASE LIVE-SMOKE PRODUCER SELF-TEST: PASS'
    $producerMarkerCount = @(
        $producerOutput | Where-Object { $_ -ceq $producerMarker }
    ).Count
    if ($producerMarkerCount -ne 1) {
        throw "Android public-release live-smoke producer returned $producerMarkerCount exact PASS markers; exactly one is required."
    }
}
$script:PythonCustodyStream.Dispose()
$script:PythonCustodyStream = $null
foreach ($record in $script:EvidenceCodeStreams) {
    $record.Stream.Dispose()
}
$script:EvidenceCodeStreams.Clear()
foreach ($record in $script:NativeToolStreams) {
    $record.Stream.Dispose()
}
$script:NativeToolStreams.Clear()
foreach ($record in $script:RouteAuthorityStreams) {
    $record.Stream.Dispose()
}
$script:RouteAuthorityStreams.Clear()
foreach ($record in $script:EvidenceBundleStreams) {
    $record.Stream.Dispose()
}
$script:EvidenceBundleStreams.Clear()
$script:ToolchainPinStream.Dispose()
$script:ToolchainPinStream = $null
$script:CustodyHelperStream.Dispose()
$script:CustodyHelperStream = $null
$script:CustodyManifestStream.Dispose()
$script:CustodyManifestStream = $null
