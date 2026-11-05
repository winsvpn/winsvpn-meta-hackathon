$script:WinsVpnSecurityModuleManifest = Join-Path $PSHOME `
    'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'
if (-not (Test-Path -LiteralPath $script:WinsVpnSecurityModuleManifest `
        -PathType Leaf -ErrorAction Stop)) {
    throw 'The active PowerShell engine is missing its Security module.'
}
# PowerShell 7 can prepend its module tree to PSModulePath. A Windows
# PowerShell 5.1 child must import the Security module belonging to its own
# engine explicitly or Get-Acl/Set-Acl autoload can select an incompatible
# assembly. Secure-state ACL enforcement must not depend on parent launch
# order.
Import-Module -Name $script:WinsVpnSecurityModuleManifest -ErrorAction Stop

$script:WinsVpnSecureTextNames = @(
    'client_keypair.json',
    'install_id.txt',
    'pending_logout.json',
    'user_pin.txt',
    'vpn_config.txt',
    'vpn_settings.txt',
    'wins_vpn_restart_config.conf'
)
$script:WinsVpnSecureJsonNames = @(
    'client_keypair.json',
    'pending_logout.json',
    'vpn_config.txt',
    'vpn_settings.txt'
)

function Assert-WinsVpnSecureTextName {
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -cnotin $script:WinsVpnSecureTextNames) {
        throw 'Win''s VPN secure-text name is not allowed.'
    }
}

function Assert-WinsVpnSecureJsonName {
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -cnotin $script:WinsVpnSecureJsonNames) {
        throw 'Win''s VPN secure JSON name is not allowed.'
    }
}

function Assert-WinsVpnSecureStatePath {
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    $current = $root
    foreach ($part in @($full.Substring($root.Length) -split '[\\/]' |
            Where-Object { $_ })) {
        if ($part -eq '..') { throw 'Protected app-state parent traversal is forbidden.' }
        $current = Join-Path $current $part
        if (Test-Path -LiteralPath $current -ErrorAction Stop) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Protected app state traverses a reparse point.'
            }
        }
    }
}

function Get-WinsVpnSecureStatePaths {
    param([Parameter(Mandatory)][string]$Name)
    Assert-WinsVpnSecureTextName $Name
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA) -or
        [string]::IsNullOrWhiteSpace($env:APPDATA)) {
        throw 'Windows app-state roots are unavailable.'
    }
    $secureParent = Join-Path $env:LOCALAPPDATA 'WinsVPN'
    $secureRoot = Join-Path $secureParent 'SecureState'
    $securePath = Join-Path $secureRoot ($Name + '.wvdp')
    $legacyPath = Join-Path (Join-Path $env:APPDATA 'wins_vpn') $Name
    foreach ($path in @($secureParent, $secureRoot, $securePath, $legacyPath)) {
        Assert-WinsVpnSecureStatePath $path
    }
    [pscustomobject]@{
        Parent = $secureParent
        Root = $secureRoot
        Secure = $securePath
        Legacy = $legacyPath
    }
}

function Assert-WinsVpnNoLegacySecureText {
    param([Parameter(Mandatory)]$Paths, [Parameter(Mandatory)][string]$Name)
    if (Test-Path -LiteralPath $Paths.Legacy -ErrorAction Stop) {
        throw "Win's VPN legacy plaintext $Name state is forbidden."
    }
}

function New-WinsVpnSecureStateAcl {
    param([switch]$Directory)
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $acl = if ($Directory) {
        [Security.AccessControl.DirectorySecurity]::new()
    } else {
        [Security.AccessControl.FileSecurity]::new()
    }
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($currentSid, $systemSid)) {
        [void]$acl.AddAccessRule(
            [Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow
            )
        )
    }
    $acl.SetOwner($currentSid)
    $acl
}

function Set-WinsVpnSecureStateAcl {
    param([Parameter(Mandatory)][string]$Path, [switch]$Directory)
    Assert-WinsVpnSecureStatePath $Path
    Set-Acl -LiteralPath $Path -AclObject (
        New-WinsVpnSecureStateAcl -Directory:$Directory
    ) -ErrorAction Stop
}

function Assert-WinsVpnSecureStateAcl {
    param([Parameter(Mandatory)][string]$Path)
    Assert-WinsVpnSecureStatePath $Path
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $ownerSid = $acl.GetOwner(
        [Security.Principal.SecurityIdentifier]
    ).Value
    $entries = @($acl.Access)
    $actualSids = @($entries | ForEach-Object {
        $_.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    } | Sort-Object -Unique)
    $expectedSids = @('S-1-5-18', $currentSid) | Sort-Object
    if (-not $acl.AreAccessRulesProtected -or
        $ownerSid -cne $currentSid -or
        $entries.Count -ne 2 -or
        ($actualSids -join '|') -cne ($expectedSids -join '|') -or
        @($entries | Where-Object {
            $_.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            $_.FileSystemRights -ne
                [Security.AccessControl.FileSystemRights]::FullControl -or
            $_.IsInherited
        }).Count -ne 0) {
        throw 'Protected app state has an invalid access-control policy.'
    }
}

function Initialize-WinsVpnSecureStateRoot {
    param([Parameter(Mandatory)]$Paths)
    if (-not (Test-Path -LiteralPath $Paths.Parent -ErrorAction Stop)) {
        [void][IO.Directory]::CreateDirectory($Paths.Parent)
    }
    Assert-WinsVpnSecureStatePath $Paths.Parent
    if (-not (Test-Path -LiteralPath $Paths.Parent -PathType Container `
            -ErrorAction Stop)) {
        throw 'Win''s VPN secure-state parent is not a regular directory.'
    }
    if (-not (Test-Path -LiteralPath $Paths.Root -ErrorAction Stop)) {
        [void][IO.Directory]::CreateDirectory($Paths.Root)
        Set-WinsVpnSecureStateAcl -Path $Paths.Root -Directory
    }
    if (-not (Test-Path -LiteralPath $Paths.Root -PathType Container `
            -ErrorAction Stop)) {
        throw 'Win''s VPN secure-state root is not a regular directory.'
    }
    Assert-WinsVpnSecureStatePath $Paths.Root
    Assert-WinsVpnSecureStateAcl $Paths.Root
}

function Read-WinsVpnSecureText {
    param([Parameter(Mandatory)][string]$Name)
    $paths = Get-WinsVpnSecureStatePaths -Name $Name
    Assert-WinsVpnNoLegacySecureText -Paths $paths -Name $Name
    if (-not (Test-Path -LiteralPath $paths.Root -PathType Container `
            -ErrorAction Stop) -or
        -not (Test-Path -LiteralPath $paths.Secure -PathType Leaf `
            -ErrorAction Stop)) {
        throw "Win's VPN protected $Name state is missing."
    }
    Assert-WinsVpnSecureStateAcl $paths.Root
    Assert-WinsVpnSecureStateAcl $paths.Secure
    $length = (Get-Item -LiteralPath $paths.Secure -Force `
        -ErrorAction Stop).Length
    if ($length -le 8 -or $length -gt 5MB) {
        throw "Win's VPN protected $Name state has an invalid size."
    }

    [byte[]]$encoded = [IO.File]::ReadAllBytes($paths.Secure)
    [byte[]]$magic = [byte[]](0x57, 0x56, 0x44, 0x50, 1, 0, 0, 0)
    [byte[]]$ciphertext = $null
    [byte[]]$entropy = $null
    [byte[]]$plaintext = $null
    try {
        if ($encoded.Length -ne $length) {
            throw "Win's VPN protected $Name state changed while reading."
        }
        for ($index = 0; $index -lt $magic.Length; ++$index) {
            if ($encoded[$index] -ne $magic[$index]) {
                throw "Win's VPN protected $Name state has invalid framing."
            }
        }
        $ciphertext = [byte[]]::new($encoded.Length - $magic.Length)
        [Array]::Copy($encoded, $magic.Length, $ciphertext, 0, $ciphertext.Length)
        $entropy = [Text.Encoding]::UTF8.GetBytes(
            'WinsVPN:WindowsSecureText:v1:' + $Name
        )
        try {
            Add-Type -AssemblyName System.Security
            $plaintext = [Security.Cryptography.ProtectedData]::Unprotect(
                $ciphertext,
                $entropy,
                [Security.Cryptography.DataProtectionScope]::CurrentUser
            )
        } catch {
            $failureType = $_.Exception.GetType().FullName
            $failureCode = ('0x{0:X8}' -f ($_.Exception.HResult -band 0xffffffffL))
            throw ("Win's VPN protected $Name state failed current-user " +
                "DPAPI validation ($failureType, $failureCode).")
        }
        if ($plaintext.Length -gt 4MB) {
            throw "Win's VPN protected $Name plaintext exceeds its bound."
        }
        try {
            $result = [Text.UTF8Encoding]::new($false, $true).
                GetString($plaintext)
        } catch {
            throw "Win's VPN protected $Name state is not valid UTF-8."
        }
        Assert-WinsVpnSecureStateAcl $paths.Secure
        return $result
    } finally {
        if ($null -ne $plaintext) { [Array]::Clear($plaintext, 0, $plaintext.Length) }
        if ($null -ne $entropy) { [Array]::Clear($entropy, 0, $entropy.Length) }
        if ($null -ne $ciphertext) { [Array]::Clear($ciphertext, 0, $ciphertext.Length) }
        [Array]::Clear($encoded, 0, $encoded.Length)
    }
}

function Read-WinsVpnSecureJson {
    param([Parameter(Mandatory)][string]$Name)
    Assert-WinsVpnSecureJsonName $Name
    $text = $null
    try {
        $text = Read-WinsVpnSecureText -Name $Name
        try {
            $value = $text | ConvertFrom-Json -ErrorAction Stop
        } catch {
            throw "Win's VPN protected $Name state is not valid JSON."
        }
        if ($null -eq $value) {
            throw "Win's VPN protected $Name state contains no JSON value."
        }
        $value
    } finally {
        $text = $null
    }
}

function Write-WinsVpnSecureText {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value
    )
    $paths = Get-WinsVpnSecureStatePaths -Name $Name
    Assert-WinsVpnNoLegacySecureText -Paths $paths -Name $Name
    Initialize-WinsVpnSecureStateRoot -Paths $paths
    if (Test-Path -LiteralPath $paths.Secure -ErrorAction Stop) {
        if (-not (Test-Path -LiteralPath $paths.Secure -PathType Leaf `
                -ErrorAction Stop)) {
            throw "Win's VPN protected $Name destination is not a regular file."
        }
        Assert-WinsVpnSecureStateAcl $paths.Secure
    }

    $temporary = Join-Path $paths.Root (
        $Name + '.wvdp.tmp-' + [Guid]::NewGuid().ToString('N')
    )
    $replacementBackup = ''
    Assert-WinsVpnSecureStatePath $temporary
    [byte[]]$plaintext = $null
    [byte[]]$entropy = $null
    [byte[]]$ciphertext = $null
    [byte[]]$magic = [byte[]](0x57, 0x56, 0x44, 0x50, 1, 0, 0, 0)
    [byte[]]$framed = $null
    try {
        try {
            $plaintext = [Text.UTF8Encoding]::new($false, $true).GetBytes($Value)
        } catch {
            throw "Win's VPN protected $Name value is not valid UTF-8 text."
        }
        if ($plaintext.Length -gt 4MB) {
            throw "Win's VPN protected $Name plaintext exceeds its bound."
        }
        $entropy = [Text.Encoding]::UTF8.GetBytes(
            'WinsVPN:WindowsSecureText:v1:' + $Name
        )
        try {
            Add-Type -AssemblyName System.Security
            $ciphertext = [Security.Cryptography.ProtectedData]::Protect(
                $plaintext,
                $entropy,
                [Security.Cryptography.DataProtectionScope]::CurrentUser
            )
        } catch {
            $failureType = $_.Exception.GetType().FullName
            $failureCode = ('0x{0:X8}' -f ($_.Exception.HResult -band 0xffffffffL))
            throw ("Win's VPN protected $Name write failed current-user " +
                "DPAPI validation ($failureType, $failureCode).")
        }
        if ($null -eq $ciphertext -or $ciphertext.Length -eq 0 -or
            $ciphertext.Length + $magic.Length -gt 5MB) {
            throw "Win's VPN protected $Name ciphertext has an invalid size."
        }
        $framed = [byte[]]::new($magic.Length + $ciphertext.Length)
        [Array]::Copy($magic, 0, $framed, 0, $magic.Length)
        [Array]::Copy($ciphertext, 0, $framed, $magic.Length, $ciphertext.Length)
        $stream = [IO.File]::Open(
            $temporary,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $stream.Write($framed, 0, $framed.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        Set-WinsVpnSecureStateAcl -Path $temporary
        Assert-WinsVpnSecureStateAcl $temporary
        Assert-WinsVpnNoLegacySecureText -Paths $paths -Name $Name
        if (Test-Path -LiteralPath $paths.Secure -PathType Leaf `
                -ErrorAction Stop) {
            # Windows PowerShell 5.1 converts a null backup argument into an
            # illegal empty path for File.Replace. Use a same-directory,
            # DPAPI-encrypted backup so replacement remains atomic on every
            # supported Windows PowerShell runtime.
            $replacementBackup = Join-Path $paths.Root (
                $Name + '.wvdp.backup-' + [Guid]::NewGuid().ToString('N')
            )
            Assert-WinsVpnSecureStatePath $replacementBackup
            [IO.File]::Replace(
                $temporary, $paths.Secure, $replacementBackup, $true
            )
            $temporary = ''
            Set-WinsVpnSecureStateAcl -Path $replacementBackup
            Remove-Item -LiteralPath $replacementBackup -Force `
                -ErrorAction Stop
            $replacementBackup = ''
        } else {
            [IO.File]::Move($temporary, $paths.Secure)
            $temporary = ''
        }
        Assert-WinsVpnSecureStatePath $paths.Secure
        Assert-WinsVpnSecureStateAcl $paths.Root
        Assert-WinsVpnSecureStateAcl $paths.Secure
        Assert-WinsVpnNoLegacySecureText -Paths $paths -Name $Name
    } finally {
        if (-not [string]::IsNullOrWhiteSpace($temporary) -and
            (Test-Path -LiteralPath $temporary -PathType Leaf `
                -ErrorAction SilentlyContinue)) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
        if (-not [string]::IsNullOrWhiteSpace($replacementBackup) -and
            (Test-Path -LiteralPath $replacementBackup -PathType Leaf `
                -ErrorAction SilentlyContinue)) {
            Set-WinsVpnSecureStateAcl -Path $replacementBackup
            Remove-Item -LiteralPath $replacementBackup -Force `
                -ErrorAction SilentlyContinue
        }
        if ($null -ne $framed) { [Array]::Clear($framed, 0, $framed.Length) }
        if ($null -ne $ciphertext) { [Array]::Clear($ciphertext, 0, $ciphertext.Length) }
        if ($null -ne $entropy) { [Array]::Clear($entropy, 0, $entropy.Length) }
        if ($null -ne $plaintext) { [Array]::Clear($plaintext, 0, $plaintext.Length) }
    }
}

function Write-WinsVpnSecureJson {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value
    )
    Assert-WinsVpnSecureJsonName $Name
    $json = $null
    try {
        try {
            $json = $Value | ConvertTo-Json -Depth 32 -Compress `
                -ErrorAction Stop
        } catch {
            throw "Win's VPN protected $Name value could not be serialized as JSON."
        }
        Write-WinsVpnSecureText -Name $Name -Value $json
    } catch {
        throw
    } finally {
        $json = $null
    }
}
