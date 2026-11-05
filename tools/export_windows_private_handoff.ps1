[CmdletBinding()]
param(
    [string]$ProjectRoot,
    [string]$OutputPath,
    [string]$PasswordFile = (Join-Path $env:LOCALAPPDATA 'WinsVPN\PrivateHandoff\WINSVPN_NEW_MAC_SECRET_BUNDLE_PASSWORD_20260721.txt'),
    [string]$PythonCommand = 'python'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
}
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ProjectRoot '.private-handoff\winsvpn-private-handoff-20260721.wvenc'
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$PasswordFile = [IO.Path]::GetFullPath($PasswordFile)
if ($OutputPath -ieq $PasswordFile) {
    throw 'Encrypted bundle and password file must be different paths.'
}
# A bundle and its password are one immutable generation. Never replace either
# half: doing so could leave an older ciphertext paired with a newly generated
# password after a later encryption or verification failure.
if (Test-Path -LiteralPath $OutputPath) {
    throw "Refusing to overwrite an existing private handoff bundle: $OutputPath"
}
if (Test-Path -LiteralPath $PasswordFile) {
    throw "Refusing to overwrite an existing private handoff password: $PasswordFile"
}

function Set-OwnerOnlyAcl {
    param([Parameter(Mandatory)][string]$Path)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $account = $identity.Translate([Security.Principal.NTAccount]).Value
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $Path '/setowner' $account | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to set owner on $Path" }
    & $icacls $Path '/inheritance:r' '/grant:r' "*$($identity.Value):F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to restrict ACL on $Path" }
}

function Read-DeploymentPreseed {
    param([Parameter(Mandatory)][string]$Path)
    Add-Type -AssemblyName System.Security
    $entropy = [Text.Encoding]::UTF8.GetBytes('WinsVPN.DeploymentPreseed.v1')
    $cipher = $null
    $plain = $null
    try {
        $cipher = [IO.File]::ReadAllBytes($Path)
        $plain = [Security.Cryptography.ProtectedData]::Unprotect(
            $cipher, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        return [Text.Encoding]::UTF8.GetString($plain)
    }
    finally {
        if ($null -ne $plain) { [Array]::Clear($plain, 0, $plain.Length) }
        if ($null -ne $cipher) { [Array]::Clear($cipher, 0, $cipher.Length) }
        [Array]::Clear($entropy, 0, $entropy.Length)
    }
}

function Read-AndroidSigningState {
    param([Parameter(Mandatory)][string]$Path)
    $secure = (Get-Content -LiteralPath $Path -Raw).Trim() | ConvertTo-SecureString
    $bstr = [IntPtr]::Zero
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        if ($null -ne $secure) { $secure.Dispose() }
    }
}

function Copy-PrivatePath {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$Inventory,
        [switch]$Optional
    )
    if (-not (Test-Path -LiteralPath $Source)) {
        $Inventory.Add([pscustomobject]@{ source = $Source; destination = $Destination; status = 'missing' })
        if (-not $Optional) { throw "Required private state is missing: $Source" }
        return
    }
    $parent = Split-Path -Parent $Destination
    [void][IO.Directory]::CreateDirectory($parent)
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force
    $Inventory.Add([pscustomobject]@{ source = $Source; destination = $Destination; status = 'included' })
}

$deploymentStore = Join-Path $env:LOCALAPPDATA 'WinsVPN\Deployment\preseed.dpapi'
$androidStore = Join-Path $env:LOCALAPPDATA 'WinsVPN\Signing\android-signing.dpapi'
$androidKeystore = Join-Path $env:LOCALAPPDATA 'WinsVPN\Signing\winsvpn-release.keystore'
$cryptoTool = Join-Path $PSScriptRoot 'private_handoff_crypto.py'
foreach ($required in @($deploymentStore, $androidStore, $androidKeystore, $cryptoTool)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Required input is missing: $required" }
}

$temporaryRoot = Join-Path $env:TEMP ('winsvpn-private-handoff-' + [Guid]::NewGuid().ToString('N'))
$staging = Join-Path $temporaryRoot 'private-handoff'
$inventory = [System.Collections.Generic.List[object]]::new()
$deploymentJson = $null
$androidJson = $null
$passwordCreatedByThisRun = $false
$bundlePublishedByThisRun = $false
$stagedOutputPath = $null
try {
    [void][IO.Directory]::CreateDirectory($staging)
    $deploymentJson = Read-DeploymentPreseed -Path $deploymentStore
    $deploymentDestination = Join-Path $staging 'winsvpn-state\deployment-preseed.json'
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $deploymentDestination))
    [IO.File]::WriteAllText($deploymentDestination, $deploymentJson, [Text.UTF8Encoding]::new($false))
    $inventory.Add([pscustomobject]@{ source = $deploymentStore; destination = 'winsvpn-state/deployment-preseed.json'; status = 'decrypted-and-included' })
    $deploymentJson = $null

    $androidJson = Read-AndroidSigningState -Path $androidStore
    $androidDestination = Join-Path $staging 'winsvpn-state\android-signing.json'
    [IO.File]::WriteAllText($androidDestination, $androidJson, [Text.UTF8Encoding]::new($false))
    $inventory.Add([pscustomobject]@{ source = $androidStore; destination = 'winsvpn-state/android-signing.json'; status = 'decrypted-and-included' })
    $androidJson = $null
    Copy-PrivatePath -Source $androidKeystore -Destination (Join-Path $staging 'winsvpn-state\winsvpn-release.keystore') -Inventory $inventory

    Copy-PrivatePath -Source (Join-Path $HOME '.ssh') -Destination (Join-Path $staging 'user-state\.ssh') -Inventory $inventory -Optional
    Copy-PrivatePath -Source (Join-Path $HOME '.cloudflared') -Destination (Join-Path $staging 'user-state\.cloudflared') -Inventory $inventory -Optional
    Copy-PrivatePath -Source (Join-Path $HOME '.azure') -Destination (Join-Path $staging 'user-state\.azure') -Inventory $inventory -Optional
    Copy-PrivatePath -Source (Join-Path $env:LOCALAPPDATA 'GitHub CLI') -Destination (Join-Path $staging 'user-state\github-cli') -Inventory $inventory -Optional
    Copy-PrivatePath -Source (Join-Path $ProjectRoot '.artifacts\private-release-route-control') -Destination (Join-Path $staging 'winsvpn-state\private-release-route-control') -Inventory $inventory -Optional

    $legacy = @('RSA key.txt', 'GitHub Gist.txt', 'upcloud_vps_key', 'upcloud_vps_key.pub')
    foreach ($name in $legacy) {
        Copy-PrivatePath -Source (Join-Path $ProjectRoot $name) -Destination (Join-Path $staging ('legacy-project-private\' + $name)) -Inventory $inventory -Optional
    }

    $hashes = [System.Collections.Generic.List[object]]::new()
    foreach ($file in Get-ChildItem -LiteralPath $staging -Recurse -File -Force) {
        if ($file.Name -eq 'PRIVATE_HANDOFF_MANIFEST.json') { continue }
        $hashes.Add([pscustomobject]@{
            path = $file.FullName.Substring($staging.Length + 1).Replace('\', '/')
            bytes = $file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        })
    }
    $manifest = [ordered]@{
        schema = 1
        created_utc = [DateTime]::UtcNow.ToString('o')
        source_machine = $env:COMPUTERNAME
        source_user = [Environment]::UserName
        warning = 'Contains live private material. Keep encrypted at rest, never commit it, and rotate provider credentials after migration.'
        inventory = $inventory
        files = $hashes
        deliberately_not_exported = @(
            'Browser cookies and browser password stores',
            'Windows Credential Manager secrets',
            'Apple Keychain private keys and App Store Connect p8 material held on the retired Mac',
            'A genuine Windows public-trust signing identity, because none exists on this machine'
        )
    }
    $manifestPath = Join-Path $staging 'PRIVATE_HANDOFF_MANIFEST.json'
    [IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))

    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $PasswordFile))
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $password = [Convert]::ToBase64String($bytes)
    [Array]::Clear($bytes, 0, $bytes.Length)
    $passwordBytes = [Text.UTF8Encoding]::new($false).GetBytes(
        $password + [Environment]::NewLine
    )
    $password = $null
    $passwordStream = [IO.File]::Open(
        $PasswordFile,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $passwordStream.Write($passwordBytes, 0, $passwordBytes.Length)
        $passwordStream.Flush($true)
    } finally {
        $passwordStream.Dispose()
        [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
    }
    $passwordCreatedByThisRun = $true
    Set-OwnerOnlyAcl -Path $PasswordFile

    $outputParent = Split-Path -Parent $OutputPath
    [void][IO.Directory]::CreateDirectory($outputParent)
    $stagedOutputPath = Join-Path $outputParent (
        '.' + [IO.Path]::GetFileName($OutputPath) + '.publish.' +
        [Guid]::NewGuid().ToString('N') + '.wvenc'
    )
    & $PythonCommand $cryptoTool encrypt --source-dir $staging `
        --output $stagedOutputPath --password-file $PasswordFile
    if ($LASTEXITCODE -ne 0 -or
        -not (Test-Path -LiteralPath $stagedOutputPath -PathType Leaf)) {
        throw 'Private handoff encryption failed.'
    }
    & $PythonCommand $cryptoTool verify --input $stagedOutputPath `
        --password-file $PasswordFile
    if ($LASTEXITCODE -ne 0) {
        throw 'Private handoff verification failed before publication.'
    }
    # File.Move without overwrite is the atomic same-volume publication
    # boundary. A concurrent generation can never replace an existing pair.
    [IO.File]::Move($stagedOutputPath, $OutputPath)
    $bundlePublishedByThisRun = $true
    [pscustomobject]@{
        EncryptedBundle = $OutputPath
        BundleSha256 = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash
        BundleBytes = (Get-Item -LiteralPath $OutputPath).Length
        PasswordFile = $PasswordFile
        PasswordFileOwnerOnly = $true
        IncludedItems = @($inventory | Where-Object status -ne 'missing').Count
        MissingOptionalItems = @($inventory | Where-Object status -eq 'missing').Count
    }
}
finally {
    $deploymentJson = $null
    $androidJson = $null
    if (-not $bundlePublishedByThisRun) {
        if ($stagedOutputPath) {
            Remove-Item -LiteralPath $stagedOutputPath, "$stagedOutputPath.tmp" `
                -Force -ErrorAction SilentlyContinue
        }
        if ($passwordCreatedByThisRun) {
            Remove-Item -LiteralPath $PasswordFile -Force `
                -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}
