[CmdletBinding()]
param(
    [string]$TargetFile,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ArtifactSigningTimestampUrl = 'http://timestamp.acs.microsoft.com'
$ApprovedTimestampUrls = @(
    'http://timestamp.acs.microsoft.com',
    'http://timestamp.digicert.com',
    'https://timestamp.digicert.com'
)
$AllowedInnoTargetNames = @(
    'WinsVPN-Setup.exe',
    'WinsVPN-Setup-arm64.exe',
    'WinsVPN-PartnerCenter.exe',
    'WinsVPN-PartnerCenter-arm64.exe',
    'uninst.e32.tmp'
)
$ForbiddenInnoTargetNames = @(
    'amneziawg.exe',
    'awg.exe',
    'xray.exe',
    'wins_vpn.exe',
    'wins_vpn_tunnel_service.exe',
    'winn.exe',
    'winn3.exe'
)

# Optional Authenticode leaf pin, the same key build_installer.ps1 reads:
# tools.windows_authenticode.leaf_sha256 in tools/toolchain-pins.json. Absent
# or null means no leaf pin; the subject regex, chain, timestamp and signtool
# checks still apply. A present value must be 64 lowercase hex characters.
function Get-WinsAuthenticodeLeafPin {
    param([Parameter(Mandatory=$true)][string]$PinPath)
    $pointer = Get-Content -Raw -LiteralPath $PinPath | ConvertFrom-Json -ErrorAction Stop
    foreach ($part in @('tools', 'windows_authenticode', 'leaf_sha256')) {
        if ($null -eq $pointer) { return $null }
        $property = $pointer.PSObject.Properties[$part]
        if ($null -eq $property) { return $null }
        $pointer = $property.Value
    }
    if ($null -eq $pointer) { return $null }
    $value = [string]$pointer
    if ([string]::IsNullOrEmpty($value)) { return $null }
    if ($value -cnotmatch '^[0-9a-f]{64}$') {
        throw 'tools.windows_authenticode.leaf_sha256 in tools/toolchain-pins.json must be 64 lowercase hex characters.'
    }
    return $value
}

# Binds the post-sign signer to the configured identity: in certificate-store
# mode the signer must be the WINS_WINDOWS_SIGN_CERT_SHA1 certificate, and when
# a leaf pin is recorded the signer leaf SHA-256 must equal it.
function Assert-InnoSignerBinding {
    param(
        [Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [AllowNull()][AllowEmptyString()][string]$ExpectedThumbprint,
        [AllowNull()][AllowEmptyString()][string]$ExpectedLeafSha256
    )
    if (-not [string]::IsNullOrEmpty($ExpectedThumbprint) -and
        ([string]$Certificate.Thumbprint).ToUpperInvariant() -cne $ExpectedThumbprint) {
        throw 'Inno payload signer is not the WINS_WINDOWS_SIGN_CERT_SHA1 certificate.'
    }
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $leafSha = ([BitConverter]::ToString($sha256.ComputeHash($Certificate.RawData))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
    if (-not [string]::IsNullOrEmpty($ExpectedLeafSha256) -and $leafSha -cne $ExpectedLeafSha256) {
        throw 'Inno payload signer leaf does not match tools.windows_authenticode.leaf_sha256.'
    }
    return $leafSha
}

if ($SelfTest -and -not [string]::IsNullOrWhiteSpace($TargetFile)) {
    throw 'SelfTest cannot be combined with -TargetFile.'
}
if (-not $SelfTest -and [string]::IsNullOrWhiteSpace($TargetFile)) {
    throw 'TargetFile is required unless -SelfTest is set.'
}

function Get-ApprovedSignToolRoots {
    # H-4: this wrapper is invoked only by Inno Setup's SignTool= hook,
    # which is wired up in installer/windows/build_installer.ps1 only when
    # the release signing ($mustSign) path is active. Every invocation is
    # therefore a release-signing invocation, so resolution here is
    # unconditionally restricted to the fixed Windows SDK root: no PATH
    # search, no WINDOWS_SIGNTOOL override. Build the list defensively so a
    # host missing this environment variable fails closed with an empty
    # root set instead of a null-argument crash.
    $roots = [System.Collections.Generic.List[string]]::new()
    if (${env:ProgramFiles(x86)}) {
        $roots.Add((Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'))
    }
    return @($roots)
}

function Get-ApprovedArtifactSigningDlibRoots {
    # H-4: same rationale as Get-ApprovedSignToolRoots. LocalAppData is
    # deliberately excluded: it is user-writable and must never be trusted
    # for release signing.
    $roots = [System.Collections.Generic.List[string]]::new()
    if (${env:ProgramFiles(x86)}) {
        $roots.Add((Join-Path ${env:ProgramFiles(x86)} 'Microsoft\ArtifactSigningClientTools\bin\x64'))
    }
    if ($env:ProgramFiles) {
        $roots.Add((Join-Path $env:ProgramFiles 'Microsoft\ArtifactSigningClientTools\bin\x64'))
    }
    return @($roots)
}

function Assert-SafeSigningToken {
    param(
        [Parameter(Mandatory=$true)][string]$Value,
        [Parameter(Mandatory=$true)][string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "$Label is empty." }
    if ($Value -match '[\x00-\x1f\x7f"`|*?<>]') {
        throw "$Label contains a forbidden path or argument character."
    }
}

function Test-PathIsInsideRoot {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Root
    )
    $fullPath = [IO.Path]::GetFullPath($Path)
    $rootFull = [IO.Path]::GetFullPath($Root)
    foreach ($separator in @([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar, '\', '/')) {
        $prefix = $rootFull.TrimEnd('\', '/') + [string]$separator
        if ($fullPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Assert-NoReparsePointChain {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Label
    )
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    $cursor = $full
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            $linkType = [string]$item.LinkType
            $isReparse = (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
                ($linkType -in @('SymbolicLink', 'Junction'))
            if ($isReparse) {
                $parent = [IO.Path]::GetDirectoryName($cursor)
                $isRootChild = -not [string]::IsNullOrWhiteSpace($root) -and -not [string]::IsNullOrWhiteSpace($parent) -and
                    [string]::Equals(
                        $parent.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar),
                        $root.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar),
                        [StringComparison]::OrdinalIgnoreCase
                    )
                if ([string]::Equals($cursor, $full, [StringComparison]::OrdinalIgnoreCase) -or -not $isRootChild) {
                    throw "$Label path crosses a reparse point: $cursor"
                }
            }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Assert-MicrosoftReleaseTool {
    # H-4: trustworthy only if the resolved path is inside one of the fixed
    # roots the caller supplies AND carries a currently valid Microsoft
    # Authenticode signature. Both conditions are required.
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string[]]$AllowedRoots
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Release signing tool does not exist: $Path"
    }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $separator = [IO.Path]::DirectorySeparatorChar
    $withinApprovedRoot = @($AllowedRoots | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_) -and
        $resolved.StartsWith(($_.TrimEnd('\', '/') + $separator), [StringComparison]::OrdinalIgnoreCase)
    }).Count -gt 0
    if (-not $withinApprovedRoot) {
        throw "Release signing tool is outside every approved root: $resolved"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $resolved
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
        throw "Release signing tool lacks the required valid Microsoft signature: $resolved"
    }
    return $resolved
}

function Find-SignTool {
    $approvedRoots = Get-ApprovedSignToolRoots
    $candidate = $null
    foreach ($kitRoot in $approvedRoots) {
        if (-not (Test-Path -LiteralPath $kitRoot)) { continue }
        $candidate = Get-ChildItem -LiteralPath $kitRoot -Directory -ErrorAction SilentlyContinue |
            Sort-Object { try { [version]$_.Name } catch { [version]'0.0' } } -Descending |
            ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Select-Object -First 1
        if ($candidate) { break }
    }
    if (-not $candidate) {
        throw 'SignTool was not found under an approved Windows SDK root.'
    }
    return Assert-MicrosoftReleaseTool -Path $candidate -AllowedRoots $approvedRoots
}

function Find-ArtifactSigningDlib {
    $approvedRoots = Get-ApprovedArtifactSigningDlibRoots
    foreach ($root in $approvedRoots) {
        $candidate = Join-Path $root 'Azure.CodeSigning.Dlib.dll'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return Assert-MicrosoftReleaseTool -Path $candidate -AllowedRoots $approvedRoots
        }
    }
    throw 'Microsoft Artifact Signing Client Tools were not found under an approved Program Files root.'
}

function Resolve-OutsideRepoFile {
    param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)][string]$Label)
    Assert-SafeSigningToken -Value $Path -Label $Label
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Label does not point to a file." }
    $resolved = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path).Path)
    Assert-NoReparsePointChain -Path $resolved -Label $Label
    if (Test-PathIsInsideRoot -Path $resolved -Root $RepoRoot) {
        throw "$Label must be stored outside the repository tree."
    }
    return $resolved
}

function Assert-ArtifactSigningEndpoint {
    param([Parameter(Mandatory=$true)][string]$Value)
    $endpoint = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$endpoint) -or
        $endpoint.Scheme -ne 'https' -or
        $endpoint.Host -notmatch '^[a-z0-9-]+\.codesigning\.azure\.net$' -or
        -not [string]::IsNullOrEmpty($endpoint.UserInfo) -or
        -not [string]::IsNullOrEmpty($endpoint.Query) -or
        -not [string]::IsNullOrEmpty($endpoint.Fragment) -or
        ($endpoint.AbsolutePath -ne '/' -and $endpoint.AbsolutePath -ne '')) {
        throw 'Artifact Signing endpoint is invalid.'
    }
}

function Assert-ArtifactSigningName {
    param([Parameter(Mandatory=$true)][string]$Value, [Parameter(Mandatory=$true)][string]$Label)
    if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{2,99}$') {
        throw "Artifact Signing $Label is not an exact Azure identity token."
    }
}

function Resolve-ArtifactMetadata {
    param([Parameter(Mandatory=$true)][string]$Path)
    $resolved = Resolve-OutsideRepoFile -Path $Path -Label 'Artifact Signing metadata'
    if ((Get-Item -LiteralPath $resolved).Length -gt 16384) { throw 'Artifact Signing metadata is unexpectedly large.' }
    $metadata = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    $allowed = @('Endpoint','CodeSigningAccountName','CertificateProfileName')
    foreach ($property in $metadata.PSObject.Properties.Name) {
        if ($property -notin $allowed) { throw "Artifact Signing metadata field is forbidden: $property" }
    }
    foreach ($field in $allowed) {
        if ([string]::IsNullOrWhiteSpace(($metadata.$field + ''))) { throw "Artifact Signing metadata requires $field." }
    }
    Assert-ArtifactSigningEndpoint -Value ($metadata.Endpoint + '')
    Assert-ArtifactSigningName -Value ($metadata.CodeSigningAccountName + '') -Label 'account'
    Assert-ArtifactSigningName -Value ($metadata.CertificateProfileName + '') -Label 'certificate-profile'
    return $resolved
}

function Assert-ApprovedTimestampUrl {
    param([Parameter(Mandatory=$true)][string]$Value)
    Assert-SafeSigningToken -Value $Value -Label 'timestamp URL'
    if ($Value -notin $ApprovedTimestampUrls) {
        throw 'The signing timestamp URL must be an exact approved Microsoft/DigiCert RFC 3161 endpoint.'
    }
}

function Assert-SignerSubjectRegex {
    param([Parameter(Mandatory=$true)][string]$Pattern)
    if ($Pattern.Length -gt 256) { throw 'WINS_WINDOWS_SIGNER_SUBJECT_REGEX is too long.' }
    if ($Pattern -match '[\x00-\x1f]') { throw 'WINS_WINDOWS_SIGNER_SUBJECT_REGEX contains a control character.' }
    if ($Pattern -in @('.', '.*', '.+', '^', '$', '^.*$', '^.+$')) {
        throw 'WINS_WINDOWS_SIGNER_SUBJECT_REGEX is too broad.'
    }
    try {
        [void][regex]::new($Pattern)
    } catch {
        throw 'WINS_WINDOWS_SIGNER_SUBJECT_REGEX is not a valid regular expression.'
    }
}

function Assert-SignToolArgumentList {
    param([Parameter(Mandatory=$true)][string[]]$Arguments)
    if ($Arguments.Count -lt 2) { throw 'SignTool argument list is incomplete.' }
    foreach ($argument in $Arguments) {
        if ([string]::IsNullOrWhiteSpace($argument)) { throw 'Empty SignTool argument is forbidden.' }
        if ($argument -match '[\x00-\x1f\x7f]') { throw 'SignTool argument contains a control character.' }
    }
    foreach ($forbidden in @('/as', '/f', '/p', '/ac', '/a')) {
        if ($Arguments -contains $forbidden) {
            throw "SignTool argument $forbidden is forbidden for release signing."
        }
    }
}

function New-InnoSignArgumentList {
    param(
        [Parameter(Mandatory=$true)][string]$Timestamp,
        [Parameter(Mandatory=$true)][string[]]$SignerArguments,
        [Parameter(Mandatory=$true)][string]$Target
    )
    Assert-ApprovedTimestampUrl -Value $Timestamp
    $signArgs = [System.Collections.Generic.List[string]]::new()
    foreach ($part in @('sign', '/v', '/fd', 'SHA256', '/tr', $Timestamp, '/td', 'SHA256', '/d', "Win's VPN")) {
        $signArgs.Add($part)
    }
    foreach ($part in @($SignerArguments)) { $signArgs.Add([string]$part) }
    $signArgs.Add($Target)
    $list = @($signArgs)
    Assert-SignToolArgumentList -Arguments $list
    if ($list[$list.Count - 1] -cne $Target) {
        throw 'SignTool target must be the final argument.'
    }
    return $list
}

function New-InnoVerifyArgumentList {
    param([Parameter(Mandatory=$true)][string]$Target)
    $verifyArgs = @('verify', '/pa', '/all', '/v', '/tw', $Target)
    Assert-SignToolArgumentList -Arguments $verifyArgs
    if ($verifyArgs[$verifyArgs.Count - 1] -cne $Target) {
        throw 'SignTool verify target must be the final argument.'
    }
    return $verifyArgs
}

function Get-SigningConfiguration {
    # M-3: PFX-file-plus-command-line-password signing is disabled
    # unconditionally. This wrapper only ever runs on the release-signing
    # path (see Get-ApprovedSignToolRoots above), so there is no
    # non-publishing caller to preserve; fail loud immediately rather than
    # silently falling back to a weaker signer. Certificate-store selection
    # by thumbprint (below) never places a secret on the command line.
    if (-not [string]::IsNullOrWhiteSpace(($env:WINS_WINDOWS_SIGN_PFX + '')) -or
        -not [string]::IsNullOrWhiteSpace(($env:WINS_WINDOWS_SIGN_PFX_PASSWORD + ''))) {
        throw 'PFX command-line signing (WINS_WINDOWS_SIGN_PFX/WINS_WINDOWS_SIGN_PFX_PASSWORD) is disabled for release. Configure WINS_WINDOWS_ARTIFACT_SIGNING_METADATA or WINS_WINDOWS_SIGN_CERT_SHA1 instead.'
    }
    $artifactMetadata = ($env:WINS_WINDOWS_ARTIFACT_SIGNING_METADATA + '').Trim()
    $thumbprint = (($env:WINS_WINDOWS_SIGN_CERT_SHA1 + '') -replace '\s','').ToUpperInvariant()
    $configured = @(@($artifactMetadata, $thumbprint) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($configured.Count -ne 1) { throw 'Configure exactly one Windows public-trust signing source.' }
    if ($artifactMetadata) {
        Assert-SafeSigningToken -Value $artifactMetadata -Label 'Artifact Signing metadata'
        $timestamp = $ArtifactSigningTimestampUrl
        Assert-ApprovedTimestampUrl -Value $timestamp
        return [pscustomobject]@{
            Arguments = @('/dlib', (Find-ArtifactSigningDlib), '/dmdf', (Resolve-ArtifactMetadata $artifactMetadata))
            Timestamp = $timestamp
            Thumbprint = $null
        }
    }
    if ($thumbprint -notmatch '^[A-F0-9]{40}$') { throw 'WINS_WINDOWS_SIGN_CERT_SHA1 must be a 40-character thumbprint.' }
    $scope = if ($env:WINS_WINDOWS_SIGN_CERT_STORE) { $env:WINS_WINDOWS_SIGN_CERT_STORE } else { 'CurrentUser' }
    if ($scope -notin @('CurrentUser','LocalMachine')) { throw 'WINS_WINDOWS_SIGN_CERT_STORE must be CurrentUser or LocalMachine.' }
    $selector = @('/s','My','/sha1',$thumbprint)
    if ($scope -eq 'LocalMachine') { $selector = @('/sm') + $selector }
    $timestamp = if ($env:WINS_WINDOWS_TIMESTAMP_URL) { ($env:WINS_WINDOWS_TIMESTAMP_URL + '').Trim() } else { 'http://timestamp.digicert.com' }
    Assert-ApprovedTimestampUrl -Value $timestamp
    return [pscustomobject]@{
        Arguments = $selector
        Timestamp = $timestamp
        Thumbprint = $thumbprint
    }
}

function Assert-Target {
    param([Parameter(Mandatory=$true)][string]$Path)
    Assert-SafeSigningToken -Value $Path -Label 'Inno signing target'
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'Inno signing target does not exist.' }
    $resolved = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path).Path)
    Assert-NoReparsePointChain -Path $resolved -Label 'Inno signing target'
    $item = Get-Item -LiteralPath $resolved -Force
    $linkType = [string]$item.LinkType
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        ($linkType -in @('SymbolicLink', 'Junction'))) {
        throw 'Inno signing target must be a regular non-reparse file.'
    }
    $name = [IO.Path]::GetFileName($resolved)
    foreach ($forbidden in $ForbiddenInnoTargetNames) {
        if ($name -ieq $forbidden) {
            throw "Inno signing target refuses engine/product payload $name."
        }
    }
    $allowed = $false
    foreach ($expected in $AllowedInnoTargetNames) {
        if ($name -ieq $expected) { $allowed = $true; break }
    }
    if (-not $allowed) {
        throw 'Inno signing target must be Setup EXE or the exact uninst.e32.tmp staging file.'
    }
    $stream = [IO.File]::Open($resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $magic = [byte[]]::new(2)
        if ($stream.Read($magic, 0, 2) -ne 2 -or $magic[0] -ne 0x4D -or $magic[1] -ne 0x5A) {
            throw 'Inno signing target is not a PE MZ image.'
        }
    } finally {
        $stream.Dispose()
    }
    return $resolved
}

function Assert-TargetNotAlreadySigned {
    param([Parameter(Mandatory=$true)][string]$Path)
    $command = Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue
    if (-not $command) {
        throw 'Get-AuthenticodeSignature is required before release signing.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::NotSigned -or
        $signature.SignerCertificate) {
        throw 'Refusing to sign an already-signed or partially signed Inno target.'
    }
}

function Assert-MicrosoftTrustedRootProgramChain {
    param([Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreNotTimeValid
        [void]$chain.Build($Certificate)
        if ($chain.ChainElements.Count -lt 2) { throw 'The signing certificate does not have a public CA chain.' }
        $rootThumbprint = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Thumbprint
        $trusted = $false
        $installedRoot = $false
        foreach ($location in @(
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        )) {
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('AuthRoot', $location)
            try {
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                if (@($store.Certificates | Where-Object { $_.Thumbprint -eq $rootThumbprint }).Count -gt 0) {
                    $trusted = $true
                }
            } finally { $store.Close() }
            $rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', $location)
            try {
                $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                if (@($rootStore.Certificates | Where-Object { $_.Thumbprint -eq $rootThumbprint }).Count -gt 0) {
                    $installedRoot = $true
                }
            } finally { $rootStore.Close() }
        }
        $pinnedMicrosoftRoots = @(
            '3B1EFD3A66EA28B16697394703A72CA340A05BD5',
            '8F43288AD272F3103B6FB1428485EA3014C0BCFE'
        )
        if (-not $trusted -and -not ($installedRoot -and $rootThumbprint -in $pinnedMicrosoftRoots)) {
            throw 'The signer chain does not terminate in AuthRoot or an explicitly pinned Microsoft system root.'
        }
    } finally { $chain.Dispose() }
}

# Committed publisher identity, the same CN and O that
# tools/windows_cross_store_artifact_gate.py enforces at upload
# (AUTHENTICODE_LEAF_CN/AUTHENTICODE_LEAF_O). The environment subject regex
# and thumbprint still apply; this is an extra pin, not a replacement.
$WindowsAuthenticodePublisherName = "WIN'S VPN INC."
function Assert-WinsAuthenticodePublisherIdentity {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $flags = [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseNewLines -bor
        [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::DoNotUseQuotes
    $rdns = @($Certificate.SubjectName.Decode($flags) -split "`r?`n" | Where-Object { $_ -ne '' })
    $cn = @($rdns | Where-Object { $_.StartsWith('CN=', [StringComparison]::Ordinal) } | ForEach-Object { $_.Substring(3) })
    $org = @($rdns | Where-Object { $_.StartsWith('O=', [StringComparison]::Ordinal) } | ForEach-Object { $_.Substring(2) })
    # A control character inside an attribute value (for example a CN holding
    # a line break and a fake O=) would forge an extra decoded line. -cne is a
    # culture-aware compare that ignores zero-width, soft-hyphen and BOM
    # characters, so the names are compared ordinally.
    if ($Certificate.Subject -match '[\x00-\x1f\x7f]' -or
        $cn.Count -ne 1 -or -not [string]::Equals($cn[0], $WindowsAuthenticodePublisherName, [StringComparison]::Ordinal) -or
        $org.Count -ne 1 -or -not [string]::Equals($org[0], $WindowsAuthenticodePublisherName, [StringComparison]::Ordinal)) {
        throw "Authenticode signer of $Path is not the reviewed $WindowsAuthenticodePublisherName publisher: $($Certificate.Subject)"
    }
}

function Assert-SignedTargetPolicy {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$SignerPattern,
        [AllowNull()][AllowEmptyString()][string]$ExpectedThumbprint,
        [AllowNull()][AllowEmptyString()][string]$ExpectedLeafSha256
    )
    $command = Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue
    if (-not $command) {
        throw 'Get-AuthenticodeSignature is required for post-sign verification.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        -not $signature.SignerCertificate) {
        throw "Inno payload Authenticode signature is not valid. Status=$($signature.Status)"
    }
    if (-not $signature.TimeStamperCertificate) {
        throw 'The Authenticode signature is missing a trusted timestamp.'
    }
    $signer = $signature.SignerCertificate
    if ($signer.Subject -notmatch $SignerPattern) {
        throw "Inno payload signer does not match the pinned publisher identity: $($signer.Subject)"
    }
    if ($signer.Subject -eq $signer.Issuer) {
        throw 'A self-signed certificate is forbidden for production distribution.'
    }
    Assert-MicrosoftTrustedRootProgramChain -Certificate $signer
    Assert-WinsAuthenticodePublisherIdentity -Certificate $signer -Path $Path
    [void](Assert-InnoSignerBinding -Certificate $signer `
        -ExpectedThumbprint $ExpectedThumbprint -ExpectedLeafSha256 $ExpectedLeafSha256)
}

if ($SelfTest) {
    $scriptText = Get-Content -LiteralPath $PSCommandPath -Raw
    foreach ($required in @(
        'Configure exactly one Windows public-trust signing source.',
        '/dlib',
        '/dmdf',
        'WINS_WINDOWS_SIGN_PFX_PASSWORD',
        '/sha1',
        'Timestamp Verified by',
        'explicitly pinned Microsoft system root',
        'Private test roots are forbidden',
        'Inno payload signer is not the WINS_WINDOWS_SIGN_CERT_SHA1 certificate.',
        'Inno payload signer leaf does not match tools.windows_authenticode.leaf_sha256.',
        'verify /pa /all /v /tw',
        'SelfTest cannot be combined with -TargetFile.',
        'Refusing to sign an already-signed or partially signed Inno target.',
        'partially signed artifact is not shippable',
        'TimeStamperCertificate',
        'Get-AuthenticodeSignature',
        'amneziawg.exe',
        'xray.exe',
        'UserInfo'
    )) {
        if (-not $scriptText.Contains($required)) { throw "Inno signing self-test contract missing: $required" }
    }

    # H-4: a release tool must be rejected if it is outside every approved
    # root, or if it lacks a valid Microsoft signature, and a planted
    # WINDOWS_SIGNTOOL/WINS_WINDOWS_ARTIFACT_SIGNING_DLIB value must never
    # surface as the resolved release tool.
    $releaseToolTestRoot = Join-Path ([IO.Path]::GetTempPath()) ("winsvpn-inno-sign-selftest-" + [guid]::NewGuid().ToString('N'))
    $approvedToolTestDir = Join-Path $releaseToolTestRoot 'approved-root'
    $rogueToolTestDir = Join-Path $releaseToolTestRoot 'rogue-root'
    New-Item -ItemType Directory -Path $approvedToolTestDir -Force | Out-Null
    New-Item -ItemType Directory -Path $rogueToolTestDir -Force | Out-Null
    try {
        $unsignedInApprovedRoot = Join-Path $approvedToolTestDir 'signtool.exe'
        $unsignedOutsideApprovedRoot = Join-Path $rogueToolTestDir 'signtool.exe'
        [IO.File]::WriteAllText($unsignedInApprovedRoot, 'not a real signed binary')
        [IO.File]::WriteAllText($unsignedOutsideApprovedRoot, 'not a real signed binary')

        $rejected = $true
        try {
            [void](Assert-MicrosoftReleaseTool -Path $unsignedOutsideApprovedRoot -AllowedRoots @($approvedToolTestDir))
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) { throw 'Inno signing self-test accepted a release tool outside its approved root.' }

        $rejected = $true
        try {
            [void](Assert-MicrosoftReleaseTool -Path $unsignedInApprovedRoot -AllowedRoots @($approvedToolTestDir))
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) { throw 'Inno signing self-test accepted a release tool without a valid Microsoft signature.' }

        $savedWindowsSignTool = $env:WINDOWS_SIGNTOOL
        $savedArtifactDlib = $env:WINS_WINDOWS_ARTIFACT_SIGNING_DLIB
        try {
            $env:WINDOWS_SIGNTOOL = $unsignedOutsideApprovedRoot
            $env:WINS_WINDOWS_ARTIFACT_SIGNING_DLIB = $unsignedOutsideApprovedRoot
            $plantedResolved = (Resolve-Path -LiteralPath $unsignedOutsideApprovedRoot).Path

            $plantedSignToolAccepted = $true
            try {
                $strictSignTool = Find-SignTool
                $plantedSignToolAccepted = ($strictSignTool -eq $plantedResolved)
            } catch { $plantedSignToolAccepted = $false }
            if ($plantedSignToolAccepted) { throw 'Inno signing self-test: SignTool resolution trusted a planted WINDOWS_SIGNTOOL path.' }

            $plantedDlibAccepted = $true
            try {
                $dlibResult = Find-ArtifactSigningDlib
                $plantedDlibAccepted = ($dlibResult -eq $plantedResolved)
            } catch { $plantedDlibAccepted = $false }
            if ($plantedDlibAccepted) { throw 'Inno signing self-test: Artifact Signing DLIB resolution trusted a planted WINS_WINDOWS_ARTIFACT_SIGNING_DLIB path.' }
        } finally {
            $env:WINDOWS_SIGNTOOL = $savedWindowsSignTool
            $env:WINS_WINDOWS_ARTIFACT_SIGNING_DLIB = $savedArtifactDlib
        }

        $mz = [byte[]](0x4D, 0x5A) + [byte[]]::new(64)
        foreach ($name in $ForbiddenInnoTargetNames) {
            $engine = Join-Path $releaseToolTestRoot $name
            [IO.File]::WriteAllBytes($engine, $mz)
            $rejected = $true
            try {
                [void](Assert-Target -Path $engine)
                $rejected = $false
            } catch { $rejected = $true }
            if (-not $rejected) { throw "Inno signing self-test accepted engine payload $name." }
        }
        $setup = Join-Path $releaseToolTestRoot 'WinsVPN-Setup.exe'
        [IO.File]::WriteAllBytes($setup, $mz)
        $resolvedSetup = Assert-Target -Path $setup
        if (-not $resolvedSetup.EndsWith('WinsVPN-Setup.exe', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Inno signing self-test rejected the exact Setup EXE identity.'
        }
        $uninst = Join-Path $releaseToolTestRoot 'uninst.e32.tmp'
        [IO.File]::WriteAllBytes($uninst, $mz)
        [void](Assert-Target -Path $uninst)
        $unsignedLocal = Join-Path $releaseToolTestRoot 'WinsVPN-UNSIGNED-LOCAL-Setup.exe'
        [IO.File]::WriteAllBytes($unsignedLocal, $mz)
        $rejected = $true
        try {
            [void](Assert-Target -Path $unsignedLocal)
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) { throw 'Inno signing self-test accepted an unsigned-local Setup name.' }
        $nonPe = Join-Path $releaseToolTestRoot 'WinsVPN-PartnerCenter.exe'
        [IO.File]::WriteAllText($nonPe, 'not a pe')
        $rejected = $true
        try {
            [void](Assert-Target -Path $nonPe)
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) { throw 'Inno signing self-test accepted a non-PE Setup EXE name.' }

        foreach ($url in @(
            'https://evil.example/ts',
            'https://evil.example/ts /f C:\pwn.pfx',
            'https://timestamp.digicert.com extra',
            'http://timestamp.digicert.com/evil',
            'http://evil.example'
        )) {
            $rejected = $true
            try {
                Assert-ApprovedTimestampUrl -Value $url
                $rejected = $false
            } catch { $rejected = $true }
            if (-not $rejected) { throw "Inno signing self-test accepted hostile timestamp $url" }
        }
        foreach ($url in $ApprovedTimestampUrls) {
            Assert-ApprovedTimestampUrl -Value $url
        }

        $signArgs = New-InnoSignArgumentList -Timestamp 'http://timestamp.digicert.com' -SignerArguments @('/s','My','/sha1','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA') -Target $resolvedSetup
        if ($signArgs -contains '/as' -or $signArgs[$signArgs.Count - 1] -cne $resolvedSetup) {
            throw 'Inno signing self-test produced a non-exact SignTool sign argv.'
        }
        $verifyArgs = New-InnoVerifyArgumentList -Target $resolvedSetup
        if (($verifyArgs -join ' ') -cne ("verify /pa /all /v /tw $resolvedSetup")) {
            throw 'Inno signing self-test produced a non-exact SignTool verify argv.'
        }
        $rejected = $true
        try {
            [void](New-InnoSignArgumentList -Timestamp 'https://evil.example/ts' -SignerArguments @('/s','My') -Target $resolvedSetup)
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) { throw 'Inno signing self-test accepted a hostile timestamp in argv construction.' }
        $rejected = $true
        try {
            Assert-SignToolArgumentList -Arguments @('sign', '/as', $resolvedSetup)
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) { throw 'Inno signing self-test accepted appending an additional Authenticode signature.' }

        $savedThumb = $env:WINS_WINDOWS_SIGN_CERT_SHA1
        $savedTs = $env:WINS_WINDOWS_TIMESTAMP_URL
        $savedMeta = $env:WINS_WINDOWS_ARTIFACT_SIGNING_METADATA
        $savedPfx = $env:WINS_WINDOWS_SIGN_PFX
        $savedPfxPassword = $env:WINS_WINDOWS_SIGN_PFX_PASSWORD
        try {
            $env:WINS_WINDOWS_SIGN_PFX = ''
            $env:WINS_WINDOWS_SIGN_PFX_PASSWORD = ''
            $env:WINS_WINDOWS_ARTIFACT_SIGNING_METADATA = ''
            $env:WINS_WINDOWS_SIGN_CERT_SHA1 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            $env:WINS_WINDOWS_TIMESTAMP_URL = 'https://evil.example/ts /f C:\pwn.pfx'
            $rejected = $true
            try {
                [void](Get-SigningConfiguration)
                $rejected = $false
            } catch { $rejected = $true }
            if (-not $rejected) { throw 'Inno signing self-test accepted a hostile HTTPS timestamp override.' }
            $env:WINS_WINDOWS_TIMESTAMP_URL = 'http://timestamp.digicert.com'
            $configuration = Get-SigningConfiguration
            if ($configuration.Timestamp -cne 'http://timestamp.digicert.com') {
                throw 'Inno signing self-test did not bind the exact DigiCert timestamp.'
            }
        } finally {
            $env:WINS_WINDOWS_SIGN_CERT_SHA1 = $savedThumb
            $env:WINS_WINDOWS_TIMESTAMP_URL = $savedTs
            $env:WINS_WINDOWS_ARTIFACT_SIGNING_METADATA = $savedMeta
            $env:WINS_WINDOWS_SIGN_PFX = $savedPfx
            $env:WINS_WINDOWS_SIGN_PFX_PASSWORD = $savedPfxPassword
        }
    } finally {
        Remove-Item -LiteralPath $releaseToolTestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    # M-3: PFX-file-plus-command-line-password signing must be rejected
    # however it is configured, and must not silently fall through to an
    # empty/absent signer selection.
    $savedSignPfx = $env:WINS_WINDOWS_SIGN_PFX
    $savedSignPfxPassword = $env:WINS_WINDOWS_SIGN_PFX_PASSWORD
    try {
        $env:WINS_WINDOWS_SIGN_PFX = Join-Path ([IO.Path]::GetTempPath()) 'winsvpn-selftest-does-not-exist.pfx'
        $env:WINS_WINDOWS_SIGN_PFX_PASSWORD = 'winsvpn-selftest-password'
        $rejected = $true
        try {
            [void](Get-SigningConfiguration)
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) { throw 'Inno signing self-test accepted PFX command-line signing.' }
    } finally {
        $env:WINS_WINDOWS_SIGN_PFX = $savedSignPfx
        $env:WINS_WINDOWS_SIGN_PFX_PASSWORD = $savedSignPfxPassword
    }

    # Signer binding: the store thumbprint and the optional leaf pin each
    # refuse a different certificate, and absent pins add no requirement.
    $bindingRsa = [System.Security.Cryptography.RSA]::Create(2048)
    $bindingCertificate = $null
    $bindingRoot = Join-Path ([IO.Path]::GetTempPath()) ("winsvpn-inno-binding-selftest-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $bindingRoot -Force | Out-Null
    try {
        $bindingRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=Win's VPN Inno Binding Test",
            $bindingRsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $bindingCertificate = $bindingRequest.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddMinutes(-5),
            [DateTimeOffset]::UtcNow.AddDays(1)
        )
        $bindingLeaf = Assert-InnoSignerBinding -Certificate $bindingCertificate -ExpectedThumbprint $null -ExpectedLeafSha256 $null
        if ($bindingLeaf -cnotmatch '^[0-9a-f]{64}$') { throw 'Inno signing self-test computed a malformed leaf SHA-256.' }
        [void](Assert-InnoSignerBinding -Certificate $bindingCertificate `
            -ExpectedThumbprint $bindingCertificate.Thumbprint.ToUpperInvariant() -ExpectedLeafSha256 $bindingLeaf)
        foreach ($case in @(
            @{ Thumbprint = ('A' * 40); Leaf = $null; Label = 'a different store thumbprint' },
            @{ Thumbprint = $null; Leaf = ('0' * 64); Label = 'a different pinned leaf' }
        )) {
            $rejected = $true
            try {
                [void](Assert-InnoSignerBinding -Certificate $bindingCertificate `
                    -ExpectedThumbprint $case.Thumbprint -ExpectedLeafSha256 $case.Leaf)
                $rejected = $false
            } catch { $rejected = $true }
            if (-not $rejected) { throw "Inno signing self-test accepted $($case.Label)." }
        }
        $absentPin = Join-Path $bindingRoot 'absent.json'
        [IO.File]::WriteAllText($absentPin, '{"tools":{"go":{"version":"1.27.1"}}}')
        if ($null -ne (Get-WinsAuthenticodeLeafPin -PinPath $absentPin)) {
            throw 'Inno signing self-test invented a leaf pin from a pin file without one.'
        }
        $presentPin = Join-Path $bindingRoot 'present.json'
        [IO.File]::WriteAllText($presentPin, ('{"tools":{"windows_authenticode":{"leaf_sha256":"' + $bindingLeaf + '"}}}'))
        if ((Get-WinsAuthenticodeLeafPin -PinPath $presentPin) -cne $bindingLeaf) {
            throw 'Inno signing self-test did not read tools.windows_authenticode.leaf_sha256.'
        }
        $malformedPin = Join-Path $bindingRoot 'malformed.json'
        [IO.File]::WriteAllText($malformedPin, '{"tools":{"windows_authenticode":{"leaf_sha256":"not-a-digest"}}}')
        $rejected = $true
        try {
            [void](Get-WinsAuthenticodeLeafPin -PinPath $malformedPin)
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) { throw 'Inno signing self-test accepted a malformed leaf pin.' }
    } finally {
        if ($bindingCertificate) { $bindingCertificate.Dispose() }
        $bindingRsa.Dispose()
        Remove-Item -LiteralPath $bindingRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host 'WINDOWS INNO SIGNING WRAPPER SELF-TEST: PASS'
    exit 0
}

$target = Assert-Target -Path $TargetFile
$preSignPath = $target
$preSignSha256 = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not [string]::IsNullOrWhiteSpace(($env:WINS_WINDOWS_ALLOW_PRIVATE_TEST_ROOT + ''))) {
    throw 'Private test roots are forbidden for Inno SignTool release signing.'
}
Assert-TargetNotAlreadySigned -Path $target
$signerPattern = ($env:WINS_WINDOWS_SIGNER_SUBJECT_REGEX + '').Trim()
if ([string]::IsNullOrWhiteSpace($signerPattern)) { throw 'WINS_WINDOWS_SIGNER_SUBJECT_REGEX is required.' }
Assert-SignerSubjectRegex -Pattern $signerPattern
$configuration = Get-SigningConfiguration
$leafPin = Get-WinsAuthenticodeLeafPin -PinPath (Join-Path $RepoRoot 'tools\toolchain-pins.json')
$signTool = Find-SignTool
$signArgs = New-InnoSignArgumentList -Timestamp $configuration.Timestamp -SignerArguments @($configuration.Arguments) -Target $target
$verifyArgs = New-InnoVerifyArgumentList -Target $target

& $signTool @signArgs
if ($LASTEXITCODE -ne 0) { throw 'Inno payload Authenticode signing failed; partially signed artifact is not shippable.' }

try {
    $postSignPath = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $target).Path)
    if (-not $postSignPath.Equals($preSignPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Inno signing target path identity changed during Authenticode signing.'
    }
    Assert-NoReparsePointChain -Path $postSignPath -Label 'post-sign Inno target'
    $postSignSha256 = (Get-FileHash -LiteralPath $postSignPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($postSignSha256 -ceq $preSignSha256) {
        throw 'Inno signing did not change the target bytes.'
    }
    Assert-SignedTargetPolicy -Path $postSignPath -SignerPattern $signerPattern `
        -ExpectedThumbprint $configuration.Thumbprint -ExpectedLeafSha256 $leafPin
    $verifyOutput = & $signTool @verifyArgs 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or
        $verifyOutput -notmatch 'Successfully verified' -or
        $verifyOutput -notmatch '(Timestamp Verified by:|The signature is timestamped|Signing time:)') {
        throw "Inno payload signature/timestamp policy verification failed. $verifyOutput"
    }
} catch {
    throw ('partially signed artifact is not shippable. ' + $_.Exception.Message)
}
