[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CandidateInstaller,
    [Parameter(Mandatory)][string]$CandidatePayloadManifest,
    [Parameter(Mandatory)][string]$PreviousInstaller,
    [Parameter(Mandatory)][string]$PreviousPayloadManifest,
    [Parameter(Mandatory)][string]$ReleaseInputIndex,
    [Parameter(Mandatory)][string]$BuildReceipt,
    [Parameter(Mandatory)][ValidatePattern('^https://[A-Za-z0-9.-]+/verify$')]
    [string]$VerifyUri,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9.:-]{1,253}$')]
    [string]$ManagementProbeHost,
    [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$ManagementProbePort,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9.-]{1,253}$')]
    [string]$HubHost,
    [Parameter(Mandatory)][ValidatePattern('^[a-z_][a-z0-9_-]{0,31}$')]
    [string]$HubUser,
    [Parameter(Mandatory)][string]$HubPrivateKey,
    [Parameter(Mandatory)][string]$HubKnownHostsFile,
    [Parameter(Mandatory)][string]$OutputRoot,
    [Security.SecureString]$AccountNumberOverride,
    [string]$AppDataRoot = (Join-Path $env:APPDATA 'wins_vpn'),
    [string]$TargetCity = 'Tampa',
    [string[]]$SurroundingCities = @('Clearwater', 'Saint Petersburg', 'Plant City')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

$secureStateHelper = Join-Path $PSScriptRoot 'windows_secure_state_helpers.ps1'
if (-not (Test-Path -LiteralPath $secureStateHelper -PathType Leaf)) {
    throw "Win's VPN secure-state helper is missing: $secureStateHelper"
}
. $secureStateHelper

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Read-Json {
    param([Parameter(Mandatory)][string]$Path)
    Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Write-Utf8Json {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Value)
    $json = $Value | ConvertTo-Json -Depth 32
    [IO.File]::WriteAllText($Path, $json + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
}

function Set-OwnerOnlyAcl {
    param([Parameter(Mandatory)][string]$Path)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner($identity)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $identity,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    ))
    # A fresh descriptor marks only owner/access as modified. Directly applying
    # it avoids Set-Acl attempting to rewrite an existing SACL on an idempotent
    # rerun, which would incorrectly require SeSecurityPrivilege.
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSObject.Methods.Name -contains 'SetAccessControl') {
        $item.SetAccessControl($acl)
    } else {
        # PowerShell 7 exposes these ACL APIs as .NET extension methods rather
        # than FileInfo instance methods. Keep the same owner/DACL-only write.
        [IO.FileSystemAclExtensions]::SetAccessControl($item, $acl)
    }
    $sections = [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Access
    $verified = if ($item.PSObject.Methods.Name -contains 'GetAccessControl') {
        $item.GetAccessControl($sections)
    } else {
        [IO.FileSystemAclExtensions]::GetAccessControl($item, $sections)
    }
    $rules = @($verified.GetAccessRules($true, $true,
            [Security.Principal.SecurityIdentifier]))
    if ($verified.GetOwner([Security.Principal.SecurityIdentifier]) -ne $identity -or
        -not $verified.AreAccessRulesProtected -or $rules.Count -ne 1 -or
        $rules[0].IdentityReference -ne $identity -or
        $rules[0].AccessControlType -ne
            [Security.AccessControl.AccessControlType]::Allow -or
        ($rules[0].FileSystemRights -band
            [Security.AccessControl.FileSystemRights]::FullControl) -ne
            [Security.AccessControl.FileSystemRights]::FullControl -or
        $rules[0].IsInherited) {
        throw "Owner-only ACL verification failed: $Path"
    }
}

function Assert-ExactUnsignedInstaller {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Manifest)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'NotSigned' -or $signature.SignerCertificate -or
        $signature.TimeStamperCertificate -or
        [string]$Manifest.installer.sha256 -cne (Get-Sha256 $Path) -or
        [long]$Manifest.installer.size -ne (Get-Item -LiteralPath $Path).Length -or
        $Manifest.signing.production_signed -ne $false -or
        $Manifest.signing.every_loose_pe_verified -ne $false) {
        throw 'Lab installer is not the exact manifest-bound unsigned artifact.'
    }
}

foreach ($path in @(
    $CandidateInstaller, $CandidatePayloadManifest, $PreviousInstaller,
    $PreviousPayloadManifest, $ReleaseInputIndex, $BuildReceipt,
    $HubPrivateKey, $HubKnownHostsFile, $AppDataRoot
)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required lab input is missing: $path" }
}

$candidatePayload = Read-Json $CandidatePayloadManifest
$previousPayload = Read-Json $PreviousPayloadManifest
Assert-ExactUnsignedInstaller $CandidateInstaller $candidatePayload
Assert-ExactUnsignedInstaller $PreviousInstaller $previousPayload

$releaseIndex = Read-Json $ReleaseInputIndex
$windowsRef = $releaseIndex.platform_manifests.windows
$manifestDirectory = Split-Path -Parent (Resolve-Path $ReleaseInputIndex)
$windowsInputsPath = Join-Path $manifestDirectory ([string]$windowsRef.path)
$sharedInputsPath = Join-Path $manifestDirectory ([string]$releaseIndex.shared_manifest.path)
$windowsInputs = Read-Json $windowsInputsPath
$sharedInputs = Read-Json $sharedInputsPath
if ((Get-Sha256 $windowsInputsPath) -cne [string]$windowsRef.sha256 -or
    (Get-Sha256 $sharedInputsPath) -cne [string]$releaseIndex.shared_manifest.sha256) {
    throw 'Provisional lab input index has a stale shared or Windows manifest.'
}

$payloadRoot = $RepoRoot.TrimEnd('\') + '\'
foreach ($entry in @($candidatePayload.payload)) {
    $relative = ([string]$entry.path).Replace('/', '\')
    $path = [IO.Path]::GetFullPath((Join-Path $RepoRoot $relative))
    if (-not $path.StartsWith($payloadRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $path -PathType Leaf) -or
        (Get-Sha256 $path) -cne [string]$entry.sha256 -or
        (Get-Item -LiteralPath $path).Length -ne [long]$entry.size) {
        throw "Candidate payload input is missing or stale: $relative"
    }
}

$gui = @($candidatePayload.payload | Where-Object {
    ([string]$_.path).Replace('\', '/').EndsWith('/wins_vpn.exe')
})
$service = @($candidatePayload.payload | Where-Object {
    ([string]$_.path).Replace('\', '/').EndsWith('/wins_vpn_tunnel_service.exe')
})
$awgEngine = @($candidatePayload.payload | Where-Object {
    ([string]$_.path).Replace('\', '/').EndsWith('/winsvpn_awg_engine.exe')
})
if ($gui.Count -ne 1 -or $service.Count -ne 1 -or $awgEngine.Count -ne 1) {
    throw 'Candidate payload lacks exactly one GUI, tunnel service, and AWG engine.'
}

if (-not (Test-Path -LiteralPath $OutputRoot)) {
    New-Item -ItemType Directory -Path $OutputRoot | Out-Null
}
$OutputRoot = (Resolve-Path $OutputRoot).Path

$candidateManifestPath = Join-Path $OutputRoot 'candidate-manifest.json'
$candidateManifest = [ordered]@{
    schema_version = 1
    evidence_class = 'nonpublishable_lab'
    lab_only = $true
    publication_authorized = $false
    public_release_gate_eligible = $false
    unsigned_local_candidate = $true
    created_utc = [DateTime]::UtcNow.ToString('o')
    release_identity = [string]$releaseIndex.release
    internal_candidate = $true
    stage = 'nonpublishable_lab'
    shared_revision = [string]$releaseIndex.shared_revision
    shared_fingerprint_sha256 = [string]$sharedInputs.inputs.fingerprint_sha256
    native_fingerprint_sha256 = [string]$windowsInputs.native_inputs.fingerprint_sha256
    producer_fingerprint_sha256 = [string]$windowsInputs.producer_inputs.fingerprint_sha256
    artifact_input_fingerprint_sha256 = [string]$windowsInputs.artifact_input_fingerprint_sha256
    source_archive_sha256 = Get-Sha256 $windowsInputsPath
    artifacts = @(
        [ordered]@{ name = 'WinsVPN-Setup.exe'; sha256 = Get-Sha256 $CandidateInstaller; size = (Get-Item $CandidateInstaller).Length },
        [ordered]@{ name = 'WinsVPN-Setup.exe.payload-manifest.json'; sha256 = Get-Sha256 $CandidatePayloadManifest; size = (Get-Item $CandidatePayloadManifest).Length },
        [ordered]@{ name = 'wins_vpn.exe'; sha256 = [string]$gui[0].sha256; size = [long]$gui[0].size },
        [ordered]@{ name = 'wins_vpn_tunnel_service.exe'; sha256 = [string]$service[0].sha256; size = [long]$service[0].size },
        [ordered]@{ name = 'winsvpn_awg_engine.exe'; sha256 = [string]$awgEngine[0].sha256; size = [long]$awgEngine[0].size }
    )
    payload_entry_count = @($candidatePayload.payload).Count
    payload_all_present_and_matching = $true
    authenticode_status = 'NotSigned'
}
Write-Utf8Json $candidateManifestPath $candidateManifest

$previousRecordPath = Join-Path $OutputRoot 'previous-release-record.json'
Write-Utf8Json $previousRecordPath ([ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-lab-previous-release-record-v1'
    evidence_class = 'nonpublishable_lab'
    lab_only = $true
    publication_authorized = $false
    public_release_gate_eligible = $false
    unsigned_local_candidate = $true
    release_identity = '1.0.14+29-pre-acceleration'
    artifact_sha256 = Get-Sha256 $PreviousInstaller
    artifact_size_bytes = (Get-Item -LiteralPath $PreviousInstaller).Length
    payload_manifest_sha256 = Get-Sha256 $PreviousPayloadManifest
})

$settings = Read-WinsVpnSecureJson -Name 'vpn_settings.txt'
$config = Read-WinsVpnSecureJson -Name 'vpn_config.txt'
$keypair = Read-WinsVpnSecureJson -Name 'client_keypair.json'
$nodeCache = Read-Json (Join-Path $AppDataRoot 'node_cache.json')
$pinCredential = (Read-WinsVpnSecureText -Name 'user_pin.txt').Trim()
$null = $pinCredential | ConvertFrom-Json
$installId = [IO.File]::ReadAllText((Join-Path $AppDataRoot 'install_id.txt'),
    [Text.UTF8Encoding]::new($false)).Trim()
$deviceIdentity = 'INSTALL-' + $installId.ToUpperInvariant()
$resolvedAccountNumber = [string]$settings.account_number
$accountBstr = [IntPtr]::Zero
if ($AccountNumberOverride) {
    try {
        $accountBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
            $AccountNumberOverride
        )
        $resolvedAccountNumber = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
            $accountBstr
        )
    } finally {
        if ($accountBstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($accountBstr)
            $accountBstr = [IntPtr]::Zero
        }
    }
}
if ($resolvedAccountNumber -notmatch '^[0-9]{4}-[0-9]{4}-[0-9]{4}$') {
    throw 'Windows lab account number is invalid.'
}

$knownMatch = & ssh-keygen.exe -F $HubHost -f $HubKnownHostsFile 2>$null
if ($LASTEXITCODE -ne 0 -or -not $knownMatch) {
    throw 'Hub host is not present in the pinned known-hosts file.'
}
$knownLine = @($knownMatch | Where-Object { $_ -and -not $_.StartsWith('#') } |
    Select-Object -First 1)
$knownParts = @(([string]$knownLine[0]) -split '\s+')
if ($knownParts.Count -lt 3) { throw 'Pinned hub known-hosts record is invalid.' }
$literalKnownHost = "$HubHost $($knownParts[1]) $($knownParts[2])"

$baseRequest = [ordered]@{
    account_number = $resolvedAccountNumber
    device_id = $deviceIdentity
    device_fingerprint = $deviceIdentity
    device_model = 'AICORE PHYSICAL WINDOWS LAB'
    platform = 'windows'
    app_version = ([string]$releaseIndex.release).Split('+')[0]
    locale = 'en_US'
    location = [string]$config.node_slug
    stealth_mode = $false
    double_vpn = $false
    double_vpn_enabled = $false
    client_public_key = [string]$keypair.public_key
    supports_awg = $true
    supports_xray = $true
    supports_split_tunnel = $true
    supports_per_app_split_tunnel = $true
    supports_double_vpn = $true
    legal_version = [string]$settings.legal_accepted_version
    legal_hash = [string]$settings.legal_accepted_hash
    accepted_terms = $true
    accepted_hold_harmless = $true
    accepted_limitation_liability = $true
    accepted_electronic_records = $true
    acceptance_method = 'clickwrap'
}
$coreRequest = [ordered]@{}
foreach ($property in $baseRequest.GetEnumerator()) { $coreRequest[$property.Key] = $property.Value }
$coreRequest.double_vpn = $true
$coreRequest.double_vpn_enabled = $true

$privateKeyBytes = [IO.File]::ReadAllBytes((Resolve-Path $HubPrivateKey))
$credential = [ordered]@{
    contract = 'winsvpn-windows-lab-credentials-v1'
    evidence_class = 'nonpublishable_lab'
    lab_only = $true
    publication_authorized = $false
    public_release_gate_eligible = $false
    unsigned_local_candidate = $true
    verify_uri = $VerifyUri
    management_probe_host = $ManagementProbeHost
    management_probe_port = $ManagementProbePort
    selected_location_index = [int]$settings.selected_index
    node_request = $baseRequest
    core_request = $coreRequest
    user_pin_credential = $pinCredential
    client_keypair = $keypair
    node_cache = $nodeCache
    hub_host = $HubHost
    hub_user = $HubUser
    hub_private_key_base64 = [Convert]::ToBase64String($privateKeyBytes)
    hub_known_hosts = $literalKnownHost
}
try {
    $plain = $credential | ConvertTo-Json -Depth 32 -Compress
    $secure = ConvertTo-SecureString -String $plain -AsPlainText -Force
    $cipher = ConvertFrom-SecureString -SecureString $secure
    $credentialPath = Join-Path $OutputRoot 'credentials.dat'
    [IO.File]::WriteAllText($credentialPath, $cipher + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
} finally {
    if ($privateKeyBytes) { [Array]::Clear($privateKeyBytes, 0, $privateKeyBytes.Length) }
    $plain = $null
    $secure = $null
    $resolvedAccountNumber = $null
    $cipher = $null
    $credential = $null
}

$gazetteerPath = Join-Path $OutputRoot 'gazetteer.json'
Write-Utf8Json $gazetteerPath ([ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-lab-map-gazetteer-v1'
    evidence_class = 'nonpublishable_lab'
    lab_only = $true
    publication_authorized = $false
    public_release_gate_eligible = $false
    unsigned_local_candidate = $true
    target_city = $TargetCity
    surrounding_cities = @($SurroundingCities)
})

foreach ($path in @($candidateManifestPath, $previousRecordPath, $credentialPath, $gazetteerPath)) {
    Set-OwnerOnlyAcl $path
}

Write-Output "WINDOWS_LAB_PREPARED=PASS output=$OutputRoot"
Write-Output "WINDOWS_LAB_CANDIDATE_SHA256=$(Get-Sha256 $CandidateInstaller)"
Write-Output "WINDOWS_LAB_PREVIOUS_SHA256=$(Get-Sha256 $PreviousInstaller)"
Write-Output "WINDOWS_LAB_CREDENTIALS=DPAPI_CURRENT_USER_REDACTED"
