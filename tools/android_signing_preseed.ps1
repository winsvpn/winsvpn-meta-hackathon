[CmdletBinding()]
param(
    [ValidateSet('MigrateLegacy', 'Status', 'SelfTest')]
    [string]$Action = 'Status',
    [string]$ProjectRoot,
    [string]$LegacyPropertiesPath,
    [string]$StorePath = (Join-Path $env:LOCALAPPDATA 'WinsVPN\Signing\android-signing.dpapi'),
    [string]$ExternalKeystorePath,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
}
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
if ([string]::IsNullOrWhiteSpace($LegacyPropertiesPath)) {
    $LegacyPropertiesPath = Join-Path $ProjectRoot 'android\key.properties'
}
if ([string]::IsNullOrWhiteSpace($ExternalKeystorePath)) {
    $ExternalKeystorePath = Join-Path (Split-Path -Parent $StorePath) 'winsvpn-release.keystore'
}

function Resolve-OutsideRepositoryPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Description
    )

    $resolved = [IO.Path]::GetFullPath($Path)
    $repository = $ProjectRoot.TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    if ($resolved.Equals($repository, [StringComparison]::OrdinalIgnoreCase) -or
        $resolved.StartsWith(($repository + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Description must be outside the repository."
    }
    return $resolved
}

$StorePath = Resolve-OutsideRepositoryPath -Path $StorePath -Description 'The Android signing DPAPI store'
$ExternalKeystorePath = Resolve-OutsideRepositoryPath -Path $ExternalKeystorePath -Description 'The external Android keystore'

function Set-OwnerOnlyAcl {
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer) {
        throw "Set-OwnerOnlyAcl expects a file, not a directory: $Path"
    }
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $identity = $current.User
    $account = $identity.Translate([Security.Principal.NTAccount]).Value
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $Path '/setowner' $account | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to assign ownership of the Android signing state: $Path"
    }
    & $icacls $Path '/inheritance:r' '/grant:r' "*$($identity.Value):F" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to restrict the Android signing-state ACL: $Path"
    }
    Assert-OwnerOnlyFile -Path $Path
}

function Assert-OwnerOnlyFile {
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Signing state must be a regular non-reparse file: $Path"
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $account = $identity.Translate([Security.Principal.NTAccount]).Value
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.Owner -ne $identity.Value -and $acl.Owner -ne $account) {
        throw "Signing state is not owned by the current user: $Path"
    }
    $unsafe = @($acl.Access | Where-Object {
        $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        $_.IdentityReference.Value -ne $identity.Value -and
        $_.IdentityReference.Value -ne $account
    })
    if (-not $acl.AreAccessRulesProtected -or $unsafe.Count -gt 0) {
        throw "Signing state ACL is not owner-only: $Path"
    }
}

function Read-LegacyProperties {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Legacy Android signing properties were not found: $Path"
    }
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('#') -or $line.TrimStart().StartsWith('!')) {
            continue
        }
        $separator = $line.IndexOf('=')
        if ($separator -le 0) {
            throw 'Legacy Android signing properties contain an unsupported line.'
        }
        $key = $line.Substring(0, $separator).Trim()
        $value = $line.Substring($separator + 1).Trim()
        if ($value.Contains('\')) {
            throw 'Legacy Android signing values contain escape syntax; migrate them through an explicit WINS_ANDROID_* environment instead.'
        }
        if ($values.ContainsKey($key)) {
            throw "Legacy Android signing properties repeat $key."
        }
        $values[$key] = $value
    }
    foreach ($key in @('storeFile', 'keyAlias', 'keyPassword', 'storePassword')) {
        if (-not $values.ContainsKey($key) -or [string]::IsNullOrWhiteSpace([string]$values[$key])) {
            throw "Legacy Android signing properties are missing $key."
        }
    }
    return $values
}

function Protect-SigningJson {
    param([Parameter(Mandatory)][hashtable]$Values, [Parameter(Mandatory)][string]$Destination)

    Add-Type -AssemblyName System.Security
    $json = [pscustomobject]@{
        storeFile = [string]$Values.storeFile
        keyAlias = [string]$Values.keyAlias
        keyPassword = [string]$Values.keyPassword
        storePassword = [string]$Values.storePassword
    } | ConvertTo-Json -Compress
    $secure = ConvertTo-SecureString $json -AsPlainText -Force
    $ciphertext = ConvertFrom-SecureString $secure
    $json = $null
    $directory = Split-Path -Parent $Destination
    [void][IO.Directory]::CreateDirectory($directory)
    $temporary = Join-Path $directory ('.android-signing-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllText($temporary, $ciphertext + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        Set-OwnerOnlyAcl -Path $temporary
        Move-Item -LiteralPath $temporary -Destination $Destination -Force
        Set-OwnerOnlyAcl -Path $Destination
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        $ciphertext = $null
    }
}

function Read-SigningStore {
    param([Parameter(Mandatory)][string]$Path)

    Assert-OwnerOnlyFile -Path $Path
    $secure = (Get-Content -LiteralPath $Path -Raw).Trim() | ConvertTo-SecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $json = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        return $json | ConvertFrom-Json
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        $json = $null
    }
}

function Invoke-MigrateLegacy {
    $values = Read-LegacyProperties -Path $LegacyPropertiesPath
    $legacyDirectory = Split-Path -Parent ([IO.Path]::GetFullPath($LegacyPropertiesPath))
    $legacyKeystore = if ([IO.Path]::IsPathRooted([string]$values.storeFile)) {
        [IO.Path]::GetFullPath([string]$values.storeFile)
    } else {
        [IO.Path]::GetFullPath((Join-Path $legacyDirectory ([string]$values.storeFile)))
    }
    if (-not (Test-Path -LiteralPath $legacyKeystore -PathType Leaf)) {
        throw 'The legacy Android signing keystore is missing.'
    }
    $externalKeystore = $ExternalKeystorePath
    $stateDirectory = Split-Path -Parent $externalKeystore
    [void][IO.Directory]::CreateDirectory($stateDirectory)
    if (Test-Path -LiteralPath $externalKeystore -PathType Leaf) {
        if ((Get-FileHash -LiteralPath $externalKeystore -Algorithm SHA256).Hash -cne
            (Get-FileHash -LiteralPath $legacyKeystore -Algorithm SHA256).Hash) {
            if (-not $Force) {
                throw 'An unrelated external Android keystore already exists. Use a different destination or explicitly use -Force to replace it.'
            }
            Copy-Item -LiteralPath $legacyKeystore -Destination $externalKeystore -Force
        }
    } else {
        Copy-Item -LiteralPath $legacyKeystore -Destination $externalKeystore
    }
    Set-OwnerOnlyAcl -Path $externalKeystore
    if ((Get-FileHash -LiteralPath $externalKeystore -Algorithm SHA256).Hash -cne
        (Get-FileHash -LiteralPath $legacyKeystore -Algorithm SHA256).Hash) {
        throw 'External Android keystore verification failed.'
    }

    $protected = @{
        storeFile = $externalKeystore
        keyAlias = [string]$values.keyAlias
        keyPassword = [string]$values.keyPassword
        storePassword = [string]$values.storePassword
    }
    Protect-SigningJson -Values $protected -Destination $StorePath
    $roundTrip = Read-SigningStore -Path $StorePath
    foreach ($property in @('storeFile', 'keyAlias', 'keyPassword', 'storePassword')) {
        if ([string]$roundTrip.$property -cne [string]$protected[$property]) {
            throw "Android signing DPAPI round-trip failed for $property."
        }
    }

    $legacyInsideRepo = $legacyKeystore.StartsWith(($ProjectRoot + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)
    Remove-Item -LiteralPath $LegacyPropertiesPath -Force
    if ($legacyInsideRepo -and $legacyKeystore -cne $externalKeystore) {
        Remove-Item -LiteralPath $legacyKeystore -Force
    }
    if ((Test-Path -LiteralPath $LegacyPropertiesPath) -or
        ($legacyInsideRepo -and (Test-Path -LiteralPath $legacyKeystore))) {
        throw 'Legacy repository-local Android signing material could not be removed.'
    }
    Write-Output 'Android signing material migrated to current-user DPAPI state; repository-local secrets removed.'
}

switch ($Action) {
    'MigrateLegacy' {
        Invoke-MigrateLegacy
    }
    'Status' {
        $ready = $false
        $keystoreReady = $false
        if (Test-Path -LiteralPath $StorePath -PathType Leaf) {
            try {
                $record = Read-SigningStore -Path $StorePath
                $keystoreReady = -not [string]::IsNullOrWhiteSpace([string]$record.storeFile) -and
                    (Test-Path -LiteralPath ([string]$record.storeFile) -PathType Leaf)
                if ($keystoreReady) { Assert-OwnerOnlyFile -Path ([string]$record.storeFile) }
                $ready = $keystoreReady -and @('keyAlias', 'keyPassword', 'storePassword').Where({
                    [string]::IsNullOrWhiteSpace([string]$record.$_)
                }).Count -eq 0
            } catch {
                $ready = $false
            }
        }
        [pscustomobject]@{
            DpapiStoreReady = $ready
            ExternalKeystoreReady = $keystoreReady
            LegacyPropertiesPresent = Test-Path -LiteralPath $LegacyPropertiesPath
        }
    }
    'SelfTest' {
        $temporaryRoot = Join-Path $env:TEMP ('wins-android-signing-' + [Guid]::NewGuid().ToString('N'))
        try {
            [void][IO.Directory]::CreateDirectory($temporaryRoot)
            $testStore = Join-Path $temporaryRoot 'test.dpapi'
            $expected = @{
                storeFile = (Join-Path $temporaryRoot 'test.keystore')
                keyAlias = 'test-alias'
                keyPassword = 'test-key-password'
                storePassword = 'test-store-password'
            }
            Protect-SigningJson -Values $expected -Destination $testStore
            $actual = Read-SigningStore -Path $testStore
            foreach ($property in $expected.Keys) {
                if ([string]$actual.$property -cne [string]$expected[$property]) {
                    throw "Android signing self-test failed for $property."
                }
            }
            Write-Output 'ANDROID SIGNING DPAPI SELF-TEST: PASS'
        } finally {
            Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
