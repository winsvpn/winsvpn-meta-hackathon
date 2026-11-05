[CmdletBinding()]
param(
    [ValidateSet('ImportLegacy', 'Status', 'RotateAdminToken', 'RotateEdgeAdminToken', 'RefreshAdminCidr', 'RefreshSshPublicKey', 'SetCloudflareAppCloudToken', 'RepairCloudflareAppCloudFallback', 'SetCloudflareTunnelToken', 'SetCloudflareAccessToken', 'RefreshPayPalProducts', 'EnsurePayPalWebhook', 'SelfTest', 'TestProviders', 'TestArtifacts', 'AuditWorktree', 'AuditGitHistory', 'Deploy')]
    [string]$Action = 'Status',

    [string]$ProjectRoot,
    [string]$StorePath = (Join-Path $env:LOCALAPPDATA 'WinsVPN\Deployment\preseed.dpapi'),
    [string]$LegacyControlScript,
    [string]$SshPublicKey,
    [string]$SshPublicKeyFile,
    [switch]$SecretFromStdin,
    [switch]$SecretFromClipboard,
    [switch]$Force,

    [ValidateSet('control', 'data', 'core')]
    [string]$Role,
    [string]$Target,
    [string]$IdentityFile,
    [string]$RoleDefaultsFile,
    # L41: owner-only fragment from tools/wins_operator_prepare_subject.sh with
    # this one target's bootstrap grant and tunnel connector (data/core only).
    [string]$SubjectSecretFragment,
    # L54 (L51 C7): local file of PUBLIC age/SSH recipients for the data plane's
    # /etc/winsvpn/backup-recipients.age (gateway backup encryption, data only).
    [string]$BackupRecipientsFile,
    [switch]$NoAutomaticReboot,
    [string]$WslDistro = 'WinsVPN-Fresh-Control-Noble'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Windows PowerShell 5.1 evaluates parameter defaults before $PSScriptRoot is
# populated. Resolve the repository only after parameter binding so the same
# one-touch command works in both powershell.exe and pwsh.
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
}

$script:Entropy = [Text.Encoding]::UTF8.GetBytes('WinsVPN.DeploymentPreseed.v1')
$script:RequiredControlFields = @(
    'ADMIN_TOKEN',
    'SMTP_USER', 'SMTP_PASS',
    'PAYPAL_PUBLIC_CLIENT_ID', 'PAYPAL_CLIENT_ID', 'PAYPAL_CLIENT_SECRET',
    'PAYPAL_WEBHOOK_ID', 'PAYPAL_PLAN_1M', 'PAYPAL_PLAN_1Y',
    'PAYPAL_PLAN_PERSONAL', 'PAYPAL_LIFETIME_SUPPORT_URL',
    'PAYPAL_LIFETIME_NO_SUPPORT_URL', 'PAYPAL_LIFETIME_SUPPORT_AMOUNT',
    'PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT', 'PAYPAL_LIFETIME_CURRENCY',
    'CLOUDFLARE_APPCLOUD_ACCOUNT_ID', 'CLOUDFLARE_APPCLOUD_API_TOKEN',
    'CLOUDFLARE_APPCLOUD_ZONE_ID', 'CLOUDFLARE_WINS_ACCOUNT_ID',
    'CLOUDFLARE_WINS_API_TOKEN', 'CLOUDFLARE_WINSVPN_ORG_ZONE_ID',
    'CLOUDFLARE_WINSVPN_COM_ZONE_ID', 'CLOUDFLARE_TUNNEL_ACCOUNT_ID',
    'CLOUDFLARE_TUNNEL_API_TOKEN', 'CLOUDFLARE_ACCESS_API_TOKEN',
    'NODE_MANAGEMENT_TUNNEL_ZONE_ID',
    'RCLONE_CONFIG_B64', 'HUB_ADMIN_SSH_CIDRS', 'HUB_SSH_PUBLIC_KEY'
)

function Assert-WindowsDpapi {
    $runningOnWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    if (-not $runningOnWindows) {
        throw 'This preseed store uses Windows DPAPI and must run on Windows.'
    }
    Add-Type -AssemblyName System.Security
}

function Clear-ClipboardSecret {
    # Windows PowerShell 5.1 throws for `Set-Clipboard -Value ''`. Overwrite
    # the clipboard with harmless whitespace first, then verify that no
    # non-whitespace credential material remains. Use the native clipboard
    # implementation as a best-effort final clear without depending on it.
    Set-Clipboard -Value ' '
    $remaining = [string](Get-Clipboard -Raw)
    if (-not [string]::IsNullOrWhiteSpace($remaining)) {
        throw 'Unable to remove secret material from the clipboard.'
    }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        [Windows.Forms.Clipboard]::Clear()
    }
    catch {
        # A single space contains no secret and is an acceptable fail-closed
        # fallback for hosts where the calling thread cannot clear Clipboard.
    }
}

function Read-DeploymentSecret {
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Z][A-Z0-9_]+$')][string]$EnvironmentVariable,
        [Parameter(Mandatory)][string]$Prompt
    )

    if ($SecretFromStdin -and $SecretFromClipboard) {
        throw 'Use only one explicit secret input mode: -SecretFromStdin or -SecretFromClipboard.'
    }
    if ($SecretFromStdin) {
        return ([Console]::In.ReadToEnd()).Trim()
    }

    # An action-specific process environment variable is the unattended
    # one-touch path. Remove our process copy immediately after reading it so
    # later child processes cannot inherit the credential accidentally.
    $environmentValue = [Environment]::GetEnvironmentVariable(
        $EnvironmentVariable,
        [EnvironmentVariableTarget]::Process
    )
    if (-not [string]::IsNullOrWhiteSpace($environmentValue)) {
        try {
            return ([string]$environmentValue).Trim()
        }
        finally {
            [Environment]::SetEnvironmentVariable(
                $EnvironmentVariable,
                $null,
                [EnvironmentVariableTarget]::Process
            )
            $environmentValue = ''
        }
    }

    # Clipboard ingestion remains available only as an explicit compatibility
    # mode. It is never the default because clipboard history and synchronizers
    # can retain credentials beyond this process.
    if ($SecretFromClipboard) {
        try {
            return ([string](Get-Clipboard -Raw)).Trim()
        }
        finally {
            Clear-ClipboardSecret
        }
    }

    $inputRedirected = $true
    try { $inputRedirected = [Console]::IsInputRedirected } catch { }
    if ($inputRedirected -or -not [Environment]::UserInteractive) {
        throw "No protected interactive input is available. Set process environment variable $EnvironmentVariable or pipe the secret with -SecretFromStdin. Clipboard input requires explicit -SecretFromClipboard."
    }

    $secureValue = Read-Host -Prompt $Prompt -AsSecureString
    $bstr = [IntPtr]::Zero
    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        if ($null -ne $secureValue) { $secureValue.Dispose() }
    }
}

function New-CryptographicHexSecret {
    param([ValidateRange(32, 128)][int]$ByteCount = 32)

    $bytes = New-Object byte[] $ByteCount
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
        return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        $rng.Dispose()
    }
}

function Set-OwnerOnlyAcl {
    param([Parameter(Mandatory)][string]$Path)

    # A PowerShell 7 parent can prepend its own WindowsApps module directory to
    # PSModulePath. A Windows PowerShell 5.1 child then discovers the incompatible
    # PowerShell 7 Security module first and cannot autoload Get-Acl/Set-Acl.
    # Import the module that belongs to the current engine by absolute path.
    $securityManifest = Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'
    if (-not (Test-Path -LiteralPath $securityManifest -PathType Leaf)) {
        throw "The current PowerShell installation is missing its Security module: $securityManifest"
    }
    Import-Module -Name $securityManifest -ErrorAction Stop

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = Get-Acl -LiteralPath $Path
    $rules = @($acl.Access)
    $alreadyRestricted = $acl.AreAccessRulesProtected -and $rules.Count -eq 1 -and
        $rules[0].AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        (($rules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
            [Security.AccessControl.FileSystemRights]::FullControl) -and
        ($rules[0].IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $identity.Value)
    if ($alreadyRestricted) { return }
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) {
        [void]$acl.RemoveAccessRuleAll($rule)
    }
    $acl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $identity,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    ))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function ConvertTo-StringDictionary {
    param([Parameter(Mandatory)]$Object)

    $dictionary = [ordered]@{}
    foreach ($property in $Object.PSObject.Properties) {
        $dictionary[$property.Name] = [string]$property.Value
    }
    return $dictionary
}

function Save-PreseedStore {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values)

    Assert-WindowsDpapi
    $directory = Split-Path -Parent $StorePath
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $jsonBytes = $null
    $protectedBytes = $null
    try {
        $payload = [ordered]@{
            schema = 1
            updated_utc = [DateTime]::UtcNow.ToString('o')
            values = $Values
        }
        $jsonBytes = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress -Depth 5))
        $protectedBytes = [Security.Cryptography.ProtectedData]::Protect(
            $jsonBytes,
            $script:Entropy,
            [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        [IO.File]::WriteAllBytes($StorePath, $protectedBytes)
        Set-OwnerOnlyAcl -Path $StorePath
    }
    finally {
        if ($null -ne $jsonBytes) { [Array]::Clear($jsonBytes, 0, $jsonBytes.Length) }
        if ($null -ne $protectedBytes) { [Array]::Clear($protectedBytes, 0, $protectedBytes.Length) }
    }
}

function Read-PreseedStore {
    Assert-WindowsDpapi
    if (-not (Test-Path -LiteralPath $StorePath -PathType Leaf)) {
        throw "Encrypted preseed store not found: $StorePath"
    }
    $cipherBytes = $null
    $plainBytes = $null
    try {
        $cipherBytes = [IO.File]::ReadAllBytes($StorePath)
        $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect(
            $cipherBytes,
            $script:Entropy,
            [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        $payload = [Text.Encoding]::UTF8.GetString($plainBytes) | ConvertFrom-Json
        if ([int]$payload.schema -ne 1) {
            throw 'Unsupported deployment preseed schema.'
        }
        return ConvertTo-StringDictionary -Object $payload.values
    }
    finally {
        if ($null -ne $plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
        if ($null -ne $cipherBytes) { [Array]::Clear($cipherBytes, 0, $cipherBytes.Length) }
    }
}

function Get-BashLiteralAssignment {
    param(
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)][string]$Name,
        [switch]$AllowMissing
    )

    $pattern = '(?m)^' + [regex]::Escape($Name) + '=(?:''([^'']*)''|"([^"]*)"|([^#\r\n]*))'
    $match = [regex]::Match($Content, $pattern)
    if (-not $match.Success) {
        if ($AllowMissing) { return '' }
        throw "Legacy source does not define $Name."
    }
    if ($match.Groups[1].Success) { $value = $match.Groups[1].Value }
    elseif ($match.Groups[2].Success) { $value = $match.Groups[2].Value }
    else { $value = $match.Groups[3].Value.Trim() }
    if ([string]::IsNullOrWhiteSpace($value) -or $value -match '^\$\{') {
        if ($AllowMissing) { return '' }
        throw "Legacy source does not contain a literal value for $Name."
    }
    return $value
}

function Get-EmbeddedRcloneConfig {
    param([Parameter(Mandatory)][string]$Content)

    $output = [Collections.Generic.List[string]]::new()
    $started = $false
    $secured = $false
    foreach ($line in ($Content -split "\r?\n")) {
        if (-not $started) {
            if ($line.Trim() -eq '[GoogleDrive_base]') {
                $started = $true
                $output.Add('[GoogleDrive_base]')
            }
            continue
        }
        if ($line.Trim() -eq '[GoogleDrive_secured]') {
            $secured = $true
            $output.Add('[GoogleDrive_secured]')
            continue
        }
        if ($line -match '^\s*[A-Za-z0-9_]+\s*=.*$' -or
            $line -match '^\s*[#;].*$' -or [string]::IsNullOrWhiteSpace($line)) {
            $output.Add($line.TrimEnd())
            continue
        }
        if ($secured) { break }
    }
    $value = (($output -join [char]10).Trim() + [char]10)
    if ($value -match '(?m)^\[GoogleDrive_base\]$' -and
        $value -match '(?m)^\[GoogleDrive_secured\]$' -and
        $value -match '(?m)^token\s*=') {
        return $value
    }
    return ''
}

function Test-PublicIpv4 {
    param([Parameter(Mandatory)][string]$Address)

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed) -or
        $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }
    $octets = $parsed.GetAddressBytes()
    if ($octets[0] -in 0, 10, 127 -or $octets[0] -ge 224) { return $false }
    if ($octets[0] -eq 169 -and $octets[1] -eq 254) { return $false }
    if ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) { return $false }
    if ($octets[0] -eq 192 -and $octets[1] -eq 168) { return $false }
    if ($octets[0] -eq 100 -and $octets[1] -ge 64 -and $octets[1] -le 127) { return $false }
    return $true
}

function Get-CurrentAdminCidr {
    $trace = Invoke-RestMethod -UseBasicParsing `
        -Uri 'https://1.1.1.1/cdn-cgi/trace' -TimeoutSec 20
    $line = ($trace -split "`n" | Where-Object { $_ -like 'ip=*' } | Select-Object -First 1)
    $address = ($line -replace '^ip=', '').Trim()
    if (-not (Test-PublicIpv4 -Address $address)) {
        throw 'Unable to determine a safe public IPv4 administration CIDR.'
    }
    return "$address/32"
}

function Get-PayPalHostedProductContract {
    param([Parameter(Mandatory)][string]$Url)

    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -ne 'https' -or $uri.Host -notmatch '(^|\.)paypal\.com$') {
        throw 'PayPal hosted product URL must use HTTPS on paypal.com.'
    }
    $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -MaximumRedirection 8 -TimeoutSec 30
    $finalUri = $response.BaseResponse.RequestMessage.RequestUri
    if ($null -eq $finalUri -or $finalUri.Scheme -ne 'https' -or $finalUri.Host -notmatch '(^|\.)paypal\.com$') {
        throw 'PayPal hosted product redirected outside HTTPS paypal.com.'
    }
    $pattern = '"name"\s*:\s*"item_name"\s*,\s*"value"\s*:\s*"(?<item>[^"]+)"\s*\}\s*,\s*\{\s*"name"\s*:\s*"currency_code"\s*,\s*"value"\s*:\s*"(?<currency>[A-Z]{3})"\s*\}\s*,\s*\{\s*"name"\s*:\s*"amount"\s*,\s*"value"\s*:\s*"(?<amount>[0-9]+(?:\.[0-9]{1,2})?)"'
    $match = [regex]::Match([string]$response.Content, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $match.Success) {
        throw 'Unable to read the PayPal hosted product amount/currency contract.'
    }
    $amount = [decimal]::Zero
    if (-not [decimal]::TryParse($match.Groups['amount'].Value, [Globalization.NumberStyles]::Number, [Globalization.CultureInfo]::InvariantCulture, [ref]$amount) -or $amount -le 0) {
        throw 'PayPal hosted product amount is invalid.'
    }
    return [pscustomobject]@{
        Item = [Net.WebUtility]::HtmlDecode($match.Groups['item'].Value)
        Currency = $match.Groups['currency'].Value.ToUpperInvariant()
        Amount = $amount.ToString('0.00', [Globalization.CultureInfo]::InvariantCulture)
    }
}

function Update-PayPalHostedProductContracts {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values)

    $supportProduct = Get-PayPalHostedProductContract -Url ([string]$Values.PAYPAL_LIFETIME_SUPPORT_URL)
    $noSupportProduct = Get-PayPalHostedProductContract -Url ([string]$Values.PAYPAL_LIFETIME_NO_SUPPORT_URL)
    if ($supportProduct.Item -notmatch '(?i)lifetime' -or $supportProduct.Item -notmatch '(?i)(?<!out)\s+tech support' -or
        $noSupportProduct.Item -notmatch '(?i)lifetime' -or $noSupportProduct.Item -notmatch '(?i)(without|no)\s+tech support' -or
        $supportProduct.Currency -ne $noSupportProduct.Currency) {
        throw 'The two PayPal hosted lifetime products do not match the expected support/no-support contracts.'
    }
    $Values.PAYPAL_LIFETIME_SUPPORT_AMOUNT = $supportProduct.Amount
    $Values.PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT = $noSupportProduct.Amount
    $Values.PAYPAL_LIFETIME_CURRENCY = $supportProduct.Currency
}

function Test-SshPublicKey {
    param([Parameter(Mandatory)][string]$Value)
    return $Value.Trim() -match '^(ssh-ed25519|ssh-rsa|ecdsa-[^\s]+)\s+[A-Za-z0-9+/=]+(?:\s+[^\r\n]+)?$'
}

function Get-LocalSshPublicKey {
    foreach ($candidate in @(
        (Join-Path $env:USERPROFILE '.ssh\id_ed25519.pub'),
        (Join-Path $env:USERPROFILE '.ssh\id_rsa.pub')
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $value = (Get-Content -LiteralPath $candidate -Raw).Trim()
            if (Test-SshPublicKey -Value $value) { return $value }
        }
    }
    return ''
}

function Resolve-SshPublicKey {
    if (-not [string]::IsNullOrWhiteSpace($SshPublicKey) -and
        -not [string]::IsNullOrWhiteSpace($SshPublicKeyFile)) {
        throw 'Use either -SshPublicKey or -SshPublicKeyFile, not both.'
    }
    $value = ''
    if (-not [string]::IsNullOrWhiteSpace($SshPublicKeyFile)) {
        if (-not (Test-Path -LiteralPath $SshPublicKeyFile -PathType Leaf)) {
            throw "SSH public key file not found: $SshPublicKeyFile"
        }
        $value = (Get-Content -LiteralPath $SshPublicKeyFile -Raw).Trim()
    }
    elseif (-not [string]::IsNullOrWhiteSpace($SshPublicKey)) {
        $value = $SshPublicKey.Trim()
    }
    else {
        $value = Get-LocalSshPublicKey
    }
    if (-not (Test-SshPublicKey -Value $value)) {
        throw 'No valid SSH public key was supplied or found locally.'
    }
    return $value
}

function Assert-PreseedComplete {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values)

    $missing = @($script:RequiredControlFields | Where-Object {
        -not $Values.Contains($_) -or [string]::IsNullOrWhiteSpace([string]$Values[$_])
    })
    if ($missing.Count -gt 0) {
        throw ('Encrypted preseed is incomplete: ' + ($missing -join ', '))
    }
    if ([string]$Values.ADMIN_TOKEN -notmatch '^\S{32,}$') {
        throw 'ADMIN_TOKEN fails the minimum length/whitespace contract.'
    }
    if (-not (Test-SshPublicKey -Value ([string]$Values.HUB_SSH_PUBLIC_KEY))) {
        throw 'HUB_SSH_PUBLIC_KEY is invalid.'
    }
    foreach ($name in 'PAYPAL_LIFETIME_SUPPORT_AMOUNT', 'PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT') {
        $amount = [decimal]::Zero
        if (-not [decimal]::TryParse([string]$Values[$name], [Globalization.NumberStyles]::Number, [Globalization.CultureInfo]::InvariantCulture, [ref]$amount) -or $amount -le 0) {
            throw "$name must be a positive invariant-decimal amount."
        }
    }
    if ([string]$Values.PAYPAL_LIFETIME_CURRENCY -notmatch '^[A-Z]{3}$') {
        throw 'PAYPAL_LIFETIME_CURRENCY must be a three-letter uppercase currency code.'
    }
    $rcloneText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$Values.RCLONE_CONFIG_B64))
    if ($rcloneText -notmatch '(?m)^\[GoogleDrive_secured\]\r?$') {
        throw 'The encrypted rclone configuration lacks [GoogleDrive_secured].'
    }
}

function Import-LegacyPreseed {
    if ((Test-Path -LiteralPath $StorePath) -and -not $Force) {
        throw "Encrypted store already exists. Use -Force only for an intentional refresh: $StorePath"
    }
    if ([string]::IsNullOrWhiteSpace($LegacyControlScript)) {
        $LegacyControlScript = Join-Path $ProjectRoot '.artifacts\private_backup_sync_export\server\wins_control_plane_setup_ONETOUCH.sh'
    }
    if (-not (Test-Path -LiteralPath $LegacyControlScript -PathType Leaf)) {
        throw "Legacy control source not found: $LegacyControlScript"
    }

    $legacy = Get-Content -LiteralPath $LegacyControlScript -Raw
    $map = [ordered]@{
        ADMIN_TOKEN = 'ADMIN_TOKEN_DEFAULT'
        SMTP_USER = 'SMTP_USER_DEFAULT'
        SMTP_PASS = 'SMTP_PASS_DEFAULT'
        PAYPAL_PUBLIC_CLIENT_ID = 'PAYPAL_PUBLIC_CLIENT_ID_DEFAULT'
        PAYPAL_CLIENT_SECRET = 'PAYPAL_CLIENT_SECRET_DEFAULT'
        PAYPAL_WEBHOOK_ID = 'PAYPAL_WEBHOOK_ID_DEFAULT'
        PAYPAL_PLAN_1M = 'PAYPAL_PLAN_1M_DEFAULT'
        PAYPAL_PLAN_1Y = 'PAYPAL_PLAN_1Y_DEFAULT'
        PAYPAL_PLAN_PERSONAL = 'PAYPAL_PLAN_PERSONAL_DEFAULT'
        PAYPAL_LIFETIME_SUPPORT_URL = 'PAYPAL_LIFETIME_SUPPORT_URL_DEFAULT'
        PAYPAL_LIFETIME_NO_SUPPORT_URL = 'PAYPAL_LIFETIME_NO_SUPPORT_URL_DEFAULT'
        PAYPAL_DONATION_URL = 'PAYPAL_DONATION_URL_DEFAULT'
        CLOUDFLARE_APPCLOUD_ACCOUNT_ID = 'CLOUDFLARE_APPCLOUD_ACCOUNT_ID_DEFAULT'
        CLOUDFLARE_APPCLOUD_API_TOKEN = 'CLOUDFLARE_APPCLOUD_API_TOKEN_DEFAULT'
        CLOUDFLARE_APPCLOUD_ZONE_ID = 'CLOUDFLARE_APPCLOUD_ZONE_ID_DEFAULT'
        CLOUDFLARE_WINS_ACCOUNT_ID = 'CLOUDFLARE_WINS_ACCOUNT_ID_DEFAULT'
        CLOUDFLARE_WINS_API_TOKEN = 'CLOUDFLARE_WINS_API_TOKEN_DEFAULT'
        CLOUDFLARE_WINSVPN_ORG_ZONE_ID = 'CLOUDFLARE_WINSVPN_ORG_ZONE_ID_DEFAULT'
    }
    $values = [ordered]@{}
    foreach ($entry in $map.GetEnumerator()) {
        $values[$entry.Key] = Get-BashLiteralAssignment -Content $legacy -Name $entry.Value
    }

    $controlSource = Get-Content -LiteralPath (Join-Path $ProjectRoot 'server\wins_control_plane_setup_ONETOUCH.sh') -Raw
    $values.PAYPAL_CLIENT_ID = $values.PAYPAL_PUBLIC_CLIENT_ID
    Update-PayPalHostedProductContracts -Values $values
    $values.CLOUDFLARE_WINSVPN_COM_ZONE_ID = Get-BashLiteralAssignment -Content $controlSource -Name 'CLOUDFLARE_WINSVPN_COM_ZONE_ID_DEFAULT'
    $values.CLOUDFLARE_TUNNEL_ACCOUNT_ID = $values.CLOUDFLARE_WINS_ACCOUNT_ID
    $values.CLOUDFLARE_TUNNEL_API_TOKEN = $values.CLOUDFLARE_WINS_API_TOKEN
    $values.CLOUDFLARE_ACCESS_API_TOKEN = Get-BashLiteralAssignment `
        -Content $controlSource -Name 'CLOUDFLARE_ACCESS_API_TOKEN_DEFAULT' -AllowMissing
    $values.NODE_MANAGEMENT_TUNNEL_ZONE_ID = $values.CLOUDFLARE_WINSVPN_COM_ZONE_ID
    $values.REQUIRE_ACTIVE_GATEWAY_AUTOMATION = '0'
    $values.HIDE_CONTROL_ORIGIN = '1'
    $values.STRICT_ONE_TOUCH_SECRETS = '1'
    $values.PREFLIGHT_VERIFY_EXTERNAL_CREDENTIALS = '1'
    $values.REQUIRE_REMOTE_BACKUP = '1'

    $rcloneText = Get-EmbeddedRcloneConfig -Content $legacy
    if ([string]::IsNullOrWhiteSpace($rcloneText)) {
        throw 'The explicitly selected legacy source does not embed the authorized rclone configuration. Recovery from deleted files or Git history is forbidden; import freshly rotated rclone material through the secure DPAPI preseed instead.'
    }
    if ($rcloneText -notmatch '(?m)^\[GoogleDrive_secured\]\r?$') {
        throw 'Legacy rclone source lacks [GoogleDrive_secured].'
    }
    $values.RCLONE_CONFIG_B64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($rcloneText))

    $values.HUB_SSH_PUBLIC_KEY = Resolve-SshPublicKey
    $values.HUB_ADMIN_SSH_CIDRS = Get-CurrentAdminCidr

    Save-PreseedStore -Values $values
    if ([string]::IsNullOrWhiteSpace([string]$values.CLOUDFLARE_ACCESS_API_TOKEN)) {
        Write-Warning 'Imported the authorized legacy values into a partial DPAPI store. Complete it with SetCloudflareAccessToken; an unrelated Cloudflare token is not a safe substitute.'
        return
    }
    Assert-PreseedComplete -Values $values
    Write-Host 'Imported the authorized legacy values into a current-user DPAPI store.'
    Write-Warning 'These reused credentials remain compromised until rotated at their providers.'
}

function ConvertTo-BashAssignment {
    param(
        [Parameter(Mandatory)][string]$Name,
        [AllowEmptyString()][string]$Value
    )
    if ($Name -notmatch '^[A-Z][A-Z0-9_]*$' -or $Value -match "[\r\n]") {
        throw "Unsafe environment assignment for $Name."
    }
    $quoted = $Value.Replace("'", "'`"'`"'")
    return "$Name='$quoted'"
}

function Write-RoleSecretFile {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Values,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$SelectedRole
    )

    $selected = if ($SelectedRole -eq 'control') {
        @($script:RequiredControlFields + @(
            'PAYPAL_DONATION_URL', 'REQUIRE_ACTIVE_GATEWAY_AUTOMATION',
            'HIDE_CONTROL_ORIGIN', 'STRICT_ONE_TOUCH_SECRETS',
            'PREFLIGHT_VERIFY_EXTERNAL_CREDENTIALS', 'REQUIRE_REMOTE_BACKUP',
            'EDGE_ADMIN_TOKEN'
        ))
    }
    elseif ($SelectedRole -eq 'data') {
        # L41: no ADMIN_TOKEN and no Cloudflare credential on a data plane.
        @(
            'RCLONE_CONFIG_B64', 'REQUIRE_REMOTE_BACKUP',
            'DNS4EU_COMMERCIAL_DOH_URL'
        )
    }
    else {
        # L41: a Core role file carries no fleet credential at all.
        @()
    }

    $lines = [Collections.Generic.List[string]]::new()
    foreach ($name in $selected | Select-Object -Unique) {
        if ($Values.Contains($name) -and -not [string]::IsNullOrWhiteSpace([string]$Values[$name])) {
            $lines.Add((ConvertTo-BashAssignment -Name $name -Value ([string]$Values[$name])))
        }
    }
    # L41: data planes and Cores receive NO Cloudflare credential and NO
    # ADMIN_TOKEN. The app-cloud-sync.net token is zone-wide (Cloudflare cannot
    # scope a token to one record), so it goes to the control role only; the
    # hub edge broker performs every node DNS, Origin CA, ACME and redirect
    # operation. Admin-only steps (hostname assignment, tunnel minting, the
    # bootstrap grant) run operator-side in tools/wins_operator_prepare_subject.sh;
    # its fragment carries only that target's one-time material.
    if ($SelectedRole -ne 'control' -and -not [string]::IsNullOrWhiteSpace($SubjectSecretFragment)) {
        foreach ($line in Read-SubjectSecretFragment -Path $SubjectSecretFragment -SelectedRole $SelectedRole) {
            $lines.Add($line)
        }
    }
    [IO.File]::WriteAllText($Path, (($lines -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
    Set-OwnerOnlyAcl -Path $Path
}

function Read-SubjectSecretFragment {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$SelectedRole
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Subject secret fragment not found: $Path"
    }
    $prefix = if ($SelectedRole -eq 'data') { 'NODE' } else { 'CORE' }
    $idName = if ($SelectedRole -eq 'data') { 'NODE_SLUG' } else { 'CORE_ID' }
    $allowed = @($idName, "${prefix}_BOOTSTRAP_TOKEN", "${prefix}_MGMT_TUNNEL_TOKEN", "${prefix}_MGMT_SSH_HOST", "${prefix}_MGMT_TUNNEL_ID")
    $accepted = [Collections.Generic.List[string]]::new()
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
        if ($line -notmatch "^([A-Z][A-Z0-9_]*)='([A-Za-z0-9+/=_.:-]*)'$") {
            throw 'Subject secret fragment contains a malformed line.'
        }
        if ($Matches[1] -notin $allowed) {
            throw "Subject secret fragment may only carry $($allowed -join ', ') for a $SelectedRole target."
        }
        $accepted.Add($line)
    }
    return $accepted
}

function Assert-PublicRoleDefaults {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Role defaults file not found: $Path"
    }
    $forbidden = 'ADMIN_TOKEN|SMTP_PASS|PAYPAL_CLIENT_SECRET|API_TOKEN|GITHUB_GIST_TOKEN|RCLONE_CONFIG|PRIVATE_KEY|PRESHARED_KEY'
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^\s*(' + $forbidden + ')[A-Z0-9_]*\s*=\s*\S+') {
            throw 'RoleDefaultsFile contains a secret-like populated assignment; put it in the DPAPI store instead.'
        }
    }
}

function Read-BackupRecipients {
    # Public recipients only, exactly the data-plane installer's rules: every
    # non-comment line is "age1..." or "ssh-ed25519|ssh-rsa <blob> [comment]".
    # A private identity is refused before anything leaves this machine.
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Backup recipients file not found: $Path"
    }
    $accepted = [Collections.Generic.List[string]]::new()
    foreach ($raw in Get-Content -LiteralPath $Path) {
        $line = $raw.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
        if ($line -match 'AGE-SECRET-KEY' -or $line -match 'PRIVATE KEY') {
            throw 'BackupRecipientsFile contains a PRIVATE identity. Keep only public recipients; the identity stays off every host.'
        }
        if ($line -cmatch '^age1[0-9a-z]{10,}$' -or
            $line -cmatch '^(ssh-ed25519|ssh-rsa)\s+[A-Za-z0-9+/]+={0,2}(\s+[A-Za-z0-9@._:+-]+)?$') {
            $accepted.Add(($line -replace '\s+', ' '))
            continue
        }
        throw 'BackupRecipientsFile has a line that is not an age or SSH public recipient.'
    }
    if ($accepted.Count -lt 1) {
        throw 'BackupRecipientsFile holds no recipient.'
    }
    if ($accepted.Count -lt 2) {
        Write-Warning 'One backup recipient only: losing that identity makes every gateway backup unreadable.'
    }
    return "BACKUP_AGE_RECIPIENTS='" + ($accepted -join ';') + "'"
}

function Invoke-ExternalChecked {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE."
    }
}

function Get-Sha256Hex {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [IO.File]::OpenRead($Path)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

function Invoke-RemoteDeployment {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values)

    if ([string]::IsNullOrWhiteSpace($Role) -or [string]::IsNullOrWhiteSpace($Target)) {
        throw 'Deploy requires -Role and -Target (for example ubuntu@203.0.113.10).'
    }
    if ($Target -notmatch '^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$') {
        throw 'Target must be a simple user@hostname or user@IPv4 value.'
    }
    if (-not [string]::IsNullOrWhiteSpace($IdentityFile) -and -not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) {
        throw "SSH identity file not found: $IdentityFile"
    }
    if ($Role -eq 'control') {
        $Values.HUB_ADMIN_SSH_CIDRS = Get-CurrentAdminCidr
        Save-PreseedStore -Values $Values
    }
    Assert-PreseedComplete -Values $Values

    $roleScriptName = switch ($Role) {
        'control' { 'wins_control_plane_setup_ONETOUCH.sh' }
        'data' { 'wins_data_plane_setup_ONETOUCH.sh' }
        'core' { 'wins_core_server_setup_ONETOUCH.sh' }
    }
    $roleScriptPath = Join-Path $ProjectRoot "server\$roleScriptName"
    if (-not (Test-Path -LiteralPath $roleScriptPath -PathType Leaf)) {
        throw "Role installer not found: $roleScriptPath"
    }
    if (-not [string]::IsNullOrWhiteSpace($RoleDefaultsFile)) {
        Assert-PublicRoleDefaults -Path $RoleDefaultsFile
    }
    $backupRecipientsLine = $null
    if (-not [string]::IsNullOrWhiteSpace($BackupRecipientsFile)) {
        if ($Role -ne 'data') {
            throw '-BackupRecipientsFile applies to -Role data only.'
        }
        $backupRecipientsLine = Read-BackupRecipients -Path $BackupRecipientsFile
    }

    $id = [Guid]::NewGuid().ToString('N')
    $localStage = Join-Path ([IO.Path]::GetTempPath()) "winsvpn-deploy-$id"
    $remoteStage = "/tmp/winsvpn-deploy-$id"
    $remoteInitialized = $false
    $remotePrepareBytes = $null
    $remoteCommandBytes = $null
    $remoteResumeCommandBytes = $null
    $sshBase = @(
        '-o', 'BatchMode=yes',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', 'ConnectTimeout=15'
    )
    if (-not [string]::IsNullOrWhiteSpace($IdentityFile)) { $sshBase += @('-i', $IdentityFile) }
    try {
        New-Item -ItemType Directory -Path $localStage | Out-Null
        $secretFile = Join-Path $localStage 'winsvpn-secrets.env'
        $defaultsFile = Join-Path $localStage 'winsvpn-defaults.env'
        $scriptFile = Join-Path $localStage $roleScriptName
        Write-RoleSecretFile -Values $Values -Path $secretFile -SelectedRole $Role
        $defaultsText = (Get-Content -LiteralPath (Join-Path $ProjectRoot '.env.example') -Raw).Replace("`r`n", "`n")
        if (-not [string]::IsNullOrWhiteSpace($RoleDefaultsFile)) {
            $defaultsText += "`n" + (Get-Content -LiteralPath $RoleDefaultsFile -Raw).Replace("`r`n", "`n")
        }
        if ($null -ne $backupRecipientsLine) {
            $defaultsText += "`n" + $backupRecipientsLine + "`n"
        }
        [IO.File]::WriteAllText($defaultsFile, $defaultsText, [Text.UTF8Encoding]::new($false))
        $scriptText = (Get-Content -LiteralPath $roleScriptPath -Raw).Replace("`r`n", "`n")
        [IO.File]::WriteAllText($scriptFile, $scriptText, [Text.UTF8Encoding]::new($false))
        Set-OwnerOnlyAcl -Path $defaultsFile
        Set-OwnerOnlyAcl -Path $scriptFile
        $secretFileSha256 = Get-Sha256Hex -Path $secretFile
        $defaultsFileSha256 = Get-Sha256Hex -Path $defaultsFile
        $scriptFileSha256 = Get-Sha256Hex -Path $scriptFile

        # Disable every active swap source before SCP transfers the role-scoped
        # secret file.  The role installer later recreates only its reviewed
        # encrypted swap policy.  If the host cannot free enough RAM, stop here
        # before sshd/scp can page credential-bearing memory to disk.
        $remotePrepare = @'
set -eu
if [ "$(id -u)" -eq 0 ]; then SUDO=''; else sudo -n true; SUDO='sudo'; fi
if awk 'NR > 1 { found=1 } END { exit found ? 0 : 1 }' /proc/swaps; then
  $SUDO swapoff -a
fi
if awk 'NR > 1 { found=1 } END { exit found ? 0 : 1 }' /proc/swaps; then
  echo '[ERR] Active swap remains; refusing to transfer deployment credentials.' >&2
  exit 1
fi
umask 077
mkdir '__REMOTE_STAGE__'
'@.Replace('__REMOTE_STAGE__', $remoteStage)
        $remotePrepareBytes = [Text.Encoding]::UTF8.GetBytes($remotePrepare)
        $remotePrepareEncoded = [Convert]::ToBase64String($remotePrepareBytes)
        $remotePrepareWrapper = "printf '%s' '$remotePrepareEncoded' | base64 -d | bash"
        Invoke-ExternalChecked -FilePath 'ssh' -Arguments ($sshBase + @($Target, $remotePrepareWrapper))
        $remoteInitialized = $true
        Invoke-ExternalChecked -FilePath 'scp' -Arguments ($sshBase + @($secretFile, $defaultsFile, $scriptFile, "${Target}:$remoteStage/"))

        $remoteCommand = @"
set -eu
if [ "`$(id -u)" -eq 0 ]; then SUDO=''; else sudo -n true; SUDO='sudo'; fi
`$SUDO install -o root -g root -m 600 '$remoteStage/winsvpn-secrets.env' /root/winsvpn-secrets.env
`$SUDO install -o root -g root -m 600 '$remoteStage/winsvpn-defaults.env' /root/winsvpn-defaults.env
`$SUDO install -o root -g root -m 700 '$remoteStage/$roleScriptName' '/root/$roleScriptName'
rm -rf '$remoteStage'
`$SUDO bash '/root/$roleScriptName' --preflight
`$SUDO bash '/root/$roleScriptName' --deploy
"@
        $remoteCommandBytes = [Text.Encoding]::UTF8.GetBytes($remoteCommand)
        $remoteCommandEncoded = [Convert]::ToBase64String($remoteCommandBytes)
        $remoteWrapper = "printf '%s' '$remoteCommandEncoded' | base64 -d | bash"
        # The initial command deliberately removes the secret-bearing /tmp
        # stage before package work.  A reboot resume therefore must execute
        # from the installed root-only copies, not replay the now-missing
        # staging command.  Bind those copies to the exact local inputs so a
        # stale or altered installer cannot be resumed accidentally.
        $remoteResumeCommand = @"
set -eu
if [ "`$(id -u)" -eq 0 ]; then SUDO=''; else sudo -n true; SUDO='sudo'; fi
printf '%s  %s\n' '$secretFileSha256' /root/winsvpn-secrets.env | `$SUDO sha256sum -c -
printf '%s  %s\n' '$defaultsFileSha256' /root/winsvpn-defaults.env | `$SUDO sha256sum -c -
printf '%s  %s\n' '$scriptFileSha256' '/root/$roleScriptName' | `$SUDO sha256sum -c -
`$SUDO bash '/root/$roleScriptName' --preflight
`$SUDO bash '/root/$roleScriptName' --deploy
"@
        $remoteResumeCommandBytes = [Text.Encoding]::UTF8.GetBytes($remoteResumeCommand)
        $remoteResumeCommandEncoded = [Convert]::ToBase64String($remoteResumeCommandBytes)
        $remoteResumeWrapper = "printf '%s' '$remoteResumeCommandEncoded' | base64 -d | bash"
        & ssh @sshBase $Target $remoteWrapper
        $deployExitCode = $LASTEXITCODE
        if ($deployExitCode -eq 75) {
            if ($NoAutomaticReboot) {
                throw "Package installation requires a controlled reboot. Reboot $Target, then rerun the identical Deploy command."
            }

            $bootBeforeLines = @(& ssh @sshBase $Target 'cat /proc/sys/kernel/random/boot_id' 2>$null)
            if ($LASTEXITCODE -ne 0 -or $bootBeforeLines.Count -eq 0) {
                throw 'Deployment paused for a required reboot, but the remote kernel boot ID could not be read. No reboot was issued.'
            }
            $bootBefore = ([string]$bootBeforeLines[-1]).Trim()
            if ($bootBefore -notmatch '^[0-9A-Fa-f-]{8,64}$') {
                throw 'Deployment paused for a required reboot, but the remote kernel boot ID was malformed. No reboot was issued.'
            }

            Write-Host "Package phase requires a reboot; restarting $Target and waiting for a different kernel boot ID."
            $rebootCommand = 'if [ "$(id -u)" -eq 0 ]; then systemctl reboot; else sudo -n systemctl reboot; fi'
            & ssh @sshBase $Target $rebootCommand 2>$null | Out-Null
            $rebootRequestExit = $LASTEXITCODE
            if ($rebootRequestExit -notin @(0, 255)) {
                throw "Remote reboot request failed with exit code $rebootRequestExit."
            }

            $deadline = [DateTime]::UtcNow.AddMinutes(10)
            $bootAfter = ''
            do {
                Start-Sleep -Seconds 5
                $bootAfterLines = @(& ssh @sshBase $Target 'cat /proc/sys/kernel/random/boot_id' 2>$null)
                $probeExit = $LASTEXITCODE
                if ($probeExit -eq 0 -and $bootAfterLines.Count -gt 0) {
                    $candidateBootId = ([string]$bootAfterLines[-1]).Trim()
                    if ($candidateBootId -match '^[0-9A-Fa-f-]{8,64}$' -and $candidateBootId -ne $bootBefore) {
                        $bootAfter = $candidateBootId
                        break
                    }
                }
            } while ([DateTime]::UtcNow -lt $deadline)

            if ([string]::IsNullOrWhiteSpace($bootAfter)) {
                throw 'The required reboot was requested, but SSH did not return with a different kernel boot ID within ten minutes.'
            }

            Write-Host 'SSH recovered after the required reboot; repeating validation and resuming the idempotent deployment.'
            & ssh @sshBase $Target $remoteResumeWrapper
            $deployExitCode = $LASTEXITCODE
            if ($deployExitCode -eq 75) {
                throw 'The host requested a second package reboot in the same deployment. Automatic reboot is bounded to one; inspect /var/run/reboot-required.pkgs before continuing.'
            }
        }
        if ($deployExitCode -ne 0) {
            throw "ssh deployment failed with exit code $deployExitCode."
        }
        Write-Host "Completed validated $Role deployment without placing credentials on the command line."
    }
    finally {
        if ($remoteInitialized) {
            try {
                & ssh @sshBase $Target "rm -rf '$remoteStage'" 2>$null | Out-Null
            }
            catch { }
        }
        if ($null -ne $remotePrepareBytes) { [Array]::Clear($remotePrepareBytes, 0, $remotePrepareBytes.Length) }
        if ($null -ne $remoteCommandBytes) { [Array]::Clear($remoteCommandBytes, 0, $remoteCommandBytes.Length) }
        if ($null -ne $remoteResumeCommandBytes) { [Array]::Clear($remoteResumeCommandBytes, 0, $remoteResumeCommandBytes.Length) }
        if (Test-Path -LiteralPath $localStage) {
            Remove-Item -LiteralPath $localStage -Recurse -Force
        }
    }
}

function ConvertTo-WslPath {
    param([Parameter(Mandatory)][string]$Path)

    $absolute = [IO.Path]::GetFullPath($Path)
    if ($absolute -notmatch '^([A-Za-z]):\\(.*)$') {
        throw 'Only local Windows drive paths can be mapped into WSL.'
    }
    $drive = $Matches[1].ToLowerInvariant()
    $tail = $Matches[2].Replace('\', '/')
    $value = "/mnt/$drive/$tail"
    if ([string]::IsNullOrWhiteSpace($value) -or $value.Contains("'")) {
        throw 'WSL path conversion returned an unsafe path.'
    }
    return $value
}

function Test-ProviderCredentials {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values)

    Assert-PreseedComplete -Values $Values
    $id = [Guid]::NewGuid().ToString('N')
    $localStage = Join-Path ([IO.Path]::GetTempPath()) "winsvpn-provider-test-$id"
    $rcloneBytes = $null
    $bashBytes = $null
    $originToken = ''
    $originHeaders = $null
    try {
        $originToken = [string]$Values.CLOUDFLARE_APPCLOUD_API_TOKEN
        $originZone = [string]$Values.CLOUDFLARE_APPCLOUD_ZONE_ID
        if ($originZone -notmatch '^[A-Fa-f0-9]{32}$') {
            throw 'Cloudflare app-zone ID is invalid for the Origin CA permission check.'
        }
        $originHeaders = @{ Authorization = "Bearer $originToken" }
        $originResponse = Invoke-RestMethod -UseBasicParsing `
            -Uri "https://api.cloudflare.com/client/v4/certificates?zone_id=$originZone&per_page=1" `
            -Headers $originHeaders -TimeoutSec 30
        if (-not [bool]$originResponse.success) {
            throw 'Cloudflare Origin CA read check failed; the app-zone token needs Zone SSL and Certificates Edit.'
        }
        Write-Host 'Cloudflare Origin CA read access passed; deployment will prove issuance and use automated ACME DNS-01 if issuance is denied.'

        New-Item -ItemType Directory -Path $localStage | Out-Null
        $secretFile = Join-Path $localStage 'winsvpn-secrets.env'
        $defaultsFile = Join-Path $localStage 'winsvpn-defaults.env'
        $rcloneFile = Join-Path $localStage 'rclone.conf'
        Write-RoleSecretFile -Values $Values -Path $secretFile -SelectedRole 'control'
        [IO.File]::AppendAllText($secretFile, "PAYPAL_WEBHOOK_AUTO_ENSURE='0'`n", [Text.UTF8Encoding]::new($false))
        $defaultsText = (Get-Content -LiteralPath (Join-Path $ProjectRoot '.env.example') -Raw).Replace("`r`n", "`n")
        [IO.File]::WriteAllText($defaultsFile, $defaultsText, [Text.UTF8Encoding]::new($false))
        Set-OwnerOnlyAcl -Path $defaultsFile
        $rcloneBytes = [Convert]::FromBase64String([string]$Values.RCLONE_CONFIG_B64)
        [IO.File]::WriteAllBytes($rcloneFile, $rcloneBytes)
        Set-OwnerOnlyAcl -Path $rcloneFile

        $controlScriptWsl = ConvertTo-WslPath -Path (Join-Path $ProjectRoot 'server\wins_control_plane_setup_ONETOUCH.sh')
        $defaultsFileWsl = ConvertTo-WslPath -Path $defaultsFile
        $secretFileWsl = ConvertTo-WslPath -Path $secretFile
        $rcloneFileWsl = ConvertTo-WslPath -Path $rcloneFile
        $bash = @"
set -Eeuo pipefail
source <(sed '/^main "\`$@"`$/d' '$controlScriptWsl')
set -a
source '$defaultsFileWsl'
source '$secretFileWsl'
set +a
for required_name in PAYPAL_LIFETIME_SUPPORT_AMOUNT PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT PAYPAL_LIFETIME_CURRENCY; do
  if [[ -z "\`${!required_name:-}" ]]; then
    echo "[ERR] Generated provider-test preseed is missing \`${required_name}" >&2
    exit 1
  fi
done
validate_external_secret_contract
verify_preflight_external_credentials
if rclone lsd --config '$rcloneFileWsl' --max-depth 1 'GoogleDrive_secured:' >/dev/null 2>&1; then
  echo '[INFO] Read-only rclone remote preflight passed'
else
  echo '[ERR] Read-only rclone remote preflight failed' >&2
  exit 1
fi
"@
        # Windows PowerShell 5.1 can split a multiline native argument and turn
        # later words into bash's positional parameters. Base64 keeps the exact
        # command order and content identical under powershell.exe and pwsh.
        $bashBytes = [Text.Encoding]::UTF8.GetBytes($bash)
        $bashEncoded = [Convert]::ToBase64String($bashBytes)
        $bashWrapper = "printf '%s' '$bashEncoded' | base64 -d | bash"
        Invoke-ExternalChecked -FilePath 'wsl.exe' -Arguments @('-d', $WslDistro, '--', 'bash', '-lc', $bashWrapper)
        Write-Host 'All required provider credentials passed read-only validation.'
    }
    finally {
        if ($null -ne $originHeaders) { $originHeaders.Clear() }
        $originToken = ''
        if ($null -ne $bashBytes) { [Array]::Clear($bashBytes, 0, $bashBytes.Length) }
        if ($null -ne $rcloneBytes) { [Array]::Clear($rcloneBytes, 0, $rcloneBytes.Length) }
        if (Test-Path -LiteralPath $localStage) {
            Remove-Item -LiteralPath $localStage -Recurse -Force
        }
    }
}

function Set-CloudflareTunnelToken {
    Add-Type -AssemblyName System.Net.Http
    $values = Read-PreseedStore
    $token = ''
    $client = $null
    $listResponse = $null
    $probeResponse = $null
    try {
        $token = Read-DeploymentSecret `
            -EnvironmentVariable 'WINS_CLOUDFLARE_TUNNEL_API_TOKEN' `
            -Prompt 'Cloudflare Tunnel API token'
        if ($token -notmatch '^[A-Za-z0-9_-]{40,}$') {
            throw 'Cloudflare Tunnel token format is invalid.'
        }
        $account = [string]$values.CLOUDFLARE_TUNNEL_ACCOUNT_ID
        if ($account -notmatch '^[A-Fa-f0-9]{32}$') {
            throw 'Stored Cloudflare Tunnel account ID is invalid.'
        }

        $client = [Net.Http.HttpClient]::new()
        $client.Timeout = [TimeSpan]::FromSeconds(30)
        $client.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)
        $api = "https://api.cloudflare.com/client/v4/accounts/$account/cfd_tunnel"
        $listResponse = $client.GetAsync("${api}?per_page=1&is_deleted=false").GetAwaiter().GetResult()
        $listJson = $listResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
        if (-not $listResponse.IsSuccessStatusCode -or -not [bool]$listJson.success) {
            throw 'Cloudflare rejected the Tunnel Read check for the supplied token/account.'
        }

        # A deliberately incomplete request proves Edit authorization while
        # remaining incapable of creating a tunnel. Read-only tokens return
        # 403; an Edit token reaches Cloudflare's payload validation instead.
        $probeBody = [Net.Http.StringContent]::new('{"config_src":"cloudflare"}', [Text.Encoding]::UTF8, 'application/json')
        $probeResponse = $client.PostAsync($api, $probeBody).GetAwaiter().GetResult()
        $probeText = $probeResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $probeJson = $null
        try { $probeJson = $probeText | ConvertFrom-Json -ErrorAction Stop } catch { }
        $probeStatus = [int]$probeResponse.StatusCode
        $probeResultId = ''
        if ($null -ne $probeJson) {
            $resultProperty = $probeJson.PSObject.Properties['result']
            if ($null -ne $resultProperty -and $null -ne $resultProperty.Value) {
                $idProperty = $resultProperty.Value.PSObject.Properties['id']
                if ($null -ne $idProperty) {
                    $probeResultId = [string]$idProperty.Value
                }
            }
        }
        if ($probeResponse.IsSuccessStatusCode -or
            ($null -ne $probeJson -and [bool]$probeJson.success) -or
            -not [string]::IsNullOrWhiteSpace($probeResultId)) {
            throw 'Cloudflare Tunnel Edit validation failed or returned an unsafe result.'
        }
        if ($probeStatus -in 401, 403) {
            throw 'Cloudflare rejected the Tunnel Edit permission.'
        }
        if ($probeStatus -notin 400, 422) {
            throw "Cloudflare Tunnel Edit validation returned unexpected HTTP $probeStatus."
        }

        $values.CLOUDFLARE_TUNNEL_API_TOKEN = $token
        Assert-PreseedComplete -Values $values
        Save-PreseedStore -Values $values
        Write-Host 'Stored a verified Cloudflare Tunnel Edit token in the DPAPI preseed without printing it.'
    }
    finally {
        $token = ''
        if ($null -ne $listResponse) { $listResponse.Dispose() }
        if ($null -ne $probeResponse) { $probeResponse.Dispose() }
        if ($null -ne $client) { $client.Dispose() }
    }
}

function Set-CloudflareAccessToken {
    Add-Type -AssemblyName System.Net.Http
    $values = Read-PreseedStore
    $token = ''
    $client = $null
    $responses = [Collections.Generic.List[Net.Http.HttpResponseMessage]]::new()
    $contents = [Collections.Generic.List[Net.Http.HttpContent]]::new()
    try {
        $token = Read-DeploymentSecret `
            -EnvironmentVariable 'WINS_CLOUDFLARE_ACCESS_API_TOKEN' `
            -Prompt 'Cloudflare Access API token'
        if ($token -notmatch '^[A-Za-z0-9_-]{40,}$') {
            throw 'The supplied value is not a valid Cloudflare API token.'
        }

        $account = [string]$values.CLOUDFLARE_TUNNEL_ACCOUNT_ID
        if ($account -notmatch '^[A-Fa-f0-9]{32}$') {
            throw 'Stored Cloudflare Access account ID is invalid.'
        }
        $api = "https://api.cloudflare.com/client/v4/accounts/$account/access"
        $client = [Net.Http.HttpClient]::new()
        $client.Timeout = [TimeSpan]::FromSeconds(30)
        $client.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)

        foreach ($check in @(
            @{ Name = 'Apps and Policies'; Uri = "$api/apps?per_page=1" },
            @{ Name = 'Service Tokens'; Uri = "$api/service_tokens?per_page=1" }
        )) {
            $response = $client.GetAsync([string]$check.Uri).GetAwaiter().GetResult()
            $responses.Add($response)
            $json = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
            if (-not $response.IsSuccessStatusCode -or -not [bool]$json.success) {
                throw "Cloudflare rejected the Access: $($check.Name) read validation."
            }
        }

        # Prove the two write permissions against an all-zero UUID that can
        # never identify a real Access object. An authorized token reaches
        # object/payload validation (400/404/422); a read-only token returns
        # 401/403. These calls cannot create, update, rotate, or delete data.
        $nonexistentId = '00000000-0000-0000-0000-000000000000'
        $appBody = [Net.Http.StringContent]::new('{}', [Text.Encoding]::UTF8, 'application/json')
        $contents.Add($appBody)
        $appProbe = $client.PutAsync("$api/apps/$nonexistentId", $appBody).GetAwaiter().GetResult()
        $responses.Add($appProbe)
        $serviceBody = [Net.Http.StringContent]::new('{}', [Text.Encoding]::UTF8, 'application/json')
        $contents.Add($serviceBody)
        $serviceProbe = $client.PutAsync("$api/service_tokens/$nonexistentId", $serviceBody).GetAwaiter().GetResult()
        $responses.Add($serviceProbe)

        foreach ($probe in @(
            @{ Name = 'Apps and Policies Write'; Response = $appProbe },
            @{ Name = 'Service Tokens Write'; Response = $serviceProbe }
        )) {
            $response = [Net.Http.HttpResponseMessage]$probe.Response
            $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $json = $null
            try { $json = $text | ConvertFrom-Json -ErrorAction Stop } catch { }
            $status = [int]$response.StatusCode
            $resultId = ''
            if ($null -ne $json) {
                $resultProperty = $json.PSObject.Properties['result']
                if ($null -ne $resultProperty -and $null -ne $resultProperty.Value) {
                    $idProperty = $resultProperty.Value.PSObject.Properties['id']
                    if ($null -ne $idProperty) {
                        $resultId = [string]$idProperty.Value
                    }
                }
            }
            if ($response.IsSuccessStatusCode -or
                ($null -ne $json -and [bool]$json.success) -or
                -not [string]::IsNullOrWhiteSpace($resultId)) {
                throw "Cloudflare Access $($probe.Name) validation returned an unsafe result."
            }
            if ($status -in 401, 403) {
                throw "Cloudflare rejected the Access: $($probe.Name) permission."
            }
            if ($status -notin 400, 404, 422) {
                throw "Cloudflare Access $($probe.Name) returned an unexpected validation status."
            }
        }

        $values.CLOUDFLARE_ACCESS_API_TOKEN = $token
        Assert-PreseedComplete -Values $values
        Save-PreseedStore -Values $values
        Write-Host 'Stored a verified least-privilege Cloudflare Access automation token in the DPAPI preseed without printing it.'
    }
    finally {
        $token = ''
        foreach ($response in $responses) { $response.Dispose() }
        foreach ($content in $contents) { $content.Dispose() }
        if ($null -ne $client) { $client.Dispose() }
    }
}

function Set-CloudflareAppCloudToken {
    Add-Type -AssemblyName System.Net.Http
    $values = Read-PreseedStore
    $token = ''
    $client = $null
    $responses = [Collections.Generic.List[Net.Http.HttpResponseMessage]]::new()
    try {
        $token = Read-DeploymentSecret `
            -EnvironmentVariable 'WINS_CLOUDFLARE_APPCLOUD_API_TOKEN' `
            -Prompt 'Cloudflare app-cloud-sync.net API token'
        if ($token -notmatch '^[A-Za-z0-9_-]{40,}$') {
            throw 'The supplied value is not a valid Cloudflare API token.'
        }

        $client = [Net.Http.HttpClient]::new()
        $client.Timeout = [TimeSpan]::FromSeconds(30)
        $client.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)

        $zoneLookup = $client.GetAsync(
            'https://api.cloudflare.com/client/v4/zones?name=app-cloud-sync.net&status=active&per_page=50'
        ).GetAwaiter().GetResult()
        $responses.Add($zoneLookup)
        $zoneLookupJson = $zoneLookup.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
        if (-not $zoneLookup.IsSuccessStatusCode -or -not [bool]$zoneLookupJson.success -or
            @($zoneLookupJson.result).Count -ne 1) {
            throw 'Cloudflare rejected the app-cloud-sync.net Zone Read validation.'
        }
        $zone = @($zoneLookupJson.result)[0]
        $zoneId = [string]$zone.id
        $accountId = [string]$zone.account.id
        if ($zoneId -notmatch '^[A-Fa-f0-9]{32}$' -or $accountId -notmatch '^[A-Fa-f0-9]{32}$') {
            throw 'Cloudflare returned an invalid app-cloud-sync.net zone or account identifier.'
        }

        $readChecks = @(
            @{ Name = 'DNS'; Uri = "https://api.cloudflare.com/client/v4/zones/$zoneId/dns_records?per_page=1" },
            @{ Name = 'Zone Settings'; Uri = "https://api.cloudflare.com/client/v4/zones/$zoneId/settings/always_use_https" },
            @{ Name = 'Dynamic URL Redirects'; Uri = "https://api.cloudflare.com/client/v4/zones/$zoneId/rulesets?per_page=1" },
            @{ Name = 'SSL and Certificates'; Uri = "https://api.cloudflare.com/client/v4/certificates?zone_id=$zoneId&per_page=1" }
        )
        foreach ($check in $readChecks) {
            $response = $client.GetAsync([string]$check.Uri).GetAwaiter().GetResult()
            $responses.Add($response)
            $responseJson = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
            if (-not $response.IsSuccessStatusCode -or -not [bool]$responseJson.success) {
                throw "Cloudflare rejected the $($check.Name) permission validation."
            }
        }

        $values.CLOUDFLARE_APPCLOUD_ACCOUNT_ID = $accountId
        $values.CLOUDFLARE_APPCLOUD_ZONE_ID = $zoneId
        $values.CLOUDFLARE_APPCLOUD_API_TOKEN = $token
        Assert-PreseedComplete -Values $values
        Save-PreseedStore -Values $values
        Write-Host 'Stored the verified app-cloud-sync.net automation token and discovered IDs in the DPAPI preseed without printing them.'
    }
    finally {
        $token = ''
        foreach ($response in $responses) { $response.Dispose() }
        if ($null -ne $client) { $client.Dispose() }
    }
}

function Repair-CloudflareAppCloudFallback {
    Add-Type -AssemblyName System.Net.Http
    $values = Read-PreseedStore
    $token = [string]$values.CLOUDFLARE_APPCLOUD_API_TOKEN
    $zoneId = [string]$values.CLOUDFLARE_APPCLOUD_ZONE_ID
    if ($token -notmatch '^[A-Za-z0-9_-]{40,}$' -or $zoneId -notmatch '^[A-Fa-f0-9]{32}$') {
        throw 'The encrypted app-cloud-sync.net Cloudflare credential is incomplete.'
    }

    $client = [Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromSeconds(30)
    $client.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)
    $client.DefaultRequestHeaders.Accept.ParseAdd('application/json')
    $api = "https://api.cloudflare.com/client/v4/zones/$zoneId"
    $phaseUri = "$api/rulesets/phases/http_request_dynamic_redirect/entrypoint"

    function Invoke-CloudflareJsonRequest {
        param(
            [Parameter(Mandatory)][Net.Http.HttpMethod]$Method,
            [Parameter(Mandatory)][string]$Uri,
            [AllowNull()][string]$Body,
            [switch]$AllowNotFound
        )
        $request = [Net.Http.HttpRequestMessage]::new($Method, $Uri)
        $response = $null
        try {
            if ($null -ne $Body) {
                $request.Content = [Net.Http.StringContent]::new($Body, [Text.Encoding]::UTF8, 'application/json')
            }
            $response = $client.SendAsync($request).GetAwaiter().GetResult()
            $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $json = $null
            try { $json = $text | ConvertFrom-Json -ErrorAction Stop } catch { }
            if ($AllowNotFound -and [int]$response.StatusCode -eq 404) {
                return [pscustomobject]@{ Found = $false; Json = $json }
            }
            if (-not $response.IsSuccessStatusCode -or $null -eq $json -or -not [bool]$json.success) {
                $errorSummary = if ($null -ne $json) {
                    (@($json.errors | ForEach-Object { [string]$_.message }) | Where-Object { $_ }) -join '; '
                }
                else { '' }
                throw "Cloudflare API request failed for $Uri. $errorSummary"
            }
            return [pscustomobject]@{ Found = $true; Json = $json }
        }
        finally {
            if ($null -ne $response) { $response.Dispose() }
            $request.Dispose()
        }
    }

    try {
        $phase = Invoke-CloudflareJsonRequest -Method ([Net.Http.HttpMethod]::Get) -Uri $phaseUri -Body $null -AllowNotFound
        $rulesetId = if ($phase.Found) { [string]$phase.Json.result.id } else { '' }
        $existingRule = if ($phase.Found) {
            @($phase.Json.result.rules | Where-Object { [string]$_.ref -eq 'winsvpn_preserve_plaintext_websocket_paths' }) |
                Select-Object -First 1
        }
        else { $null }

        $paths = [Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
        $hosts = [Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        if ($null -ne $existingRule) {
            foreach ($match in [regex]::Matches([string]$existingRule.expression, '"(/[^"}]*)"')) {
                if ($match.Groups[1].Value -match '^/[A-Za-z0-9._~!$&()*+,;=:@%+/\-]+$') {
                    [void]$paths.Add($match.Groups[1].Value)
                }
            }
            foreach ($match in [regex]::Matches([string]$existingRule.expression, '"([A-Za-z0-9.-]+)"')) {
                $hostName = $match.Groups[1].Value.ToLowerInvariant()
                if ($hostName -match '^(?=.{1,253}$)(?=.*[A-Za-z])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$') {
                    [void]$hosts.Add($hostName)
                }
            }
        }
        if ($hosts.Count -eq 0) {
            throw 'No exact plaintext-stealth host set exists yet. Run the current data-plane deployment first; refusing to create a zone-wide path-only exception.'
        }
        [void]$paths.Add('/wins-stealth-tunnel')
        $pathSet = (($paths | ForEach-Object { '"' + $_ + '"' }) -join ' ')
        $hostSet = (($hosts | ForEach-Object { '"' + $_ + '"' }) -join ' ')
        $rule = [ordered]@{
            ref = 'winsvpn_preserve_plaintext_websocket_paths'
            expression = "(not ssl and not ((http.host in {$hostSet}) and (http.request.uri.path in {$pathSet})))"
            description = "Redirect HTTP to HTTPS except exact Win s VPN plaintext WebSocket fallback hosts and paths"
            action = 'redirect'
            action_parameters = [ordered]@{
                from_value = [ordered]@{
                    target_url = [ordered]@{ expression = 'concat("https://", http.host, http.request.uri.path)' }
                    status_code = 301
                    preserve_query_string = $true
                }
            }
            enabled = $true
        }
        if ([string]::IsNullOrWhiteSpace($rulesetId)) {
            $body = [ordered]@{
                name = "Win s VPN selective HTTPS redirects"
                kind = 'zone'
                phase = 'http_request_dynamic_redirect'
                rules = @($rule)
            } | ConvertTo-Json -Compress -Depth 10
            [void](Invoke-CloudflareJsonRequest -Method ([Net.Http.HttpMethod]::Post) -Uri "$api/rulesets" -Body $body)
        }
        elseif ($null -ne $existingRule) {
            $body = $rule | ConvertTo-Json -Compress -Depth 10
            [void](Invoke-CloudflareJsonRequest -Method ([Net.Http.HttpMethod]::Patch) -Uri "$api/rulesets/$rulesetId/rules/$($existingRule.id)" -Body $body)
        }
        else {
            $body = $rule | ConvertTo-Json -Compress -Depth 10
            [void](Invoke-CloudflareJsonRequest -Method ([Net.Http.HttpMethod]::Post) -Uri "$api/rulesets/$rulesetId/rules" -Body $body)
        }

        $settingUri = "$api/settings/always_use_https"
        $setting = Invoke-CloudflareJsonRequest -Method ([Net.Http.HttpMethod]::Get) -Uri $settingUri -Body $null
        if ([string]$setting.Json.result.value -eq 'on') {
            [void](Invoke-CloudflareJsonRequest -Method ([Net.Http.HttpMethod]::Patch) -Uri $settingUri -Body '{"value":"off"}')
        }
        $setting = Invoke-CloudflareJsonRequest -Method ([Net.Http.HttpMethod]::Get) -Uri $settingUri -Body $null
        if ([string]$setting.Json.result.value -ne 'off') {
            throw 'Cloudflare Always Use HTTPS remained enabled.'
        }

        $phase = Invoke-CloudflareJsonRequest -Method ([Net.Http.HttpMethod]::Get) -Uri $phaseUri -Body $null
        $verifiedRule = @($phase.Json.result.rules | Where-Object { [string]$_.ref -eq 'winsvpn_preserve_plaintext_websocket_paths' }) |
            Select-Object -First 1
        if ($null -eq $verifiedRule -or -not [bool]$verifiedRule.enabled -or
            [string]$verifiedRule.action -ne 'redirect' -or
            [string]$verifiedRule.expression -notmatch 'not ssl' -or
            [string]$verifiedRule.expression -notmatch 'http\.host in' -or
            [string]$verifiedRule.expression -notmatch '"/wins-stealth-tunnel"') {
            throw 'Cloudflare selective redirect verification failed after the API update.'
        }
        Write-Host 'Verified selective HTTPS redirects with exact cumulative plaintext-stealth hosts and paths; Always Use HTTPS is off.'
    }
    finally {
        $token = ''
        $client.Dispose()
    }
}

function Test-LocalPreseedMaterialization {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values)

    Assert-PreseedComplete -Values $Values
    $localStage = Join-Path ([IO.Path]::GetTempPath()) ('winsvpn-preseed-selftest-' + [Guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path $localStage | Out-Null
        foreach ($selectedRole in @('control', 'data', 'core')) {
            $path = Join-Path $localStage "$selectedRole.env"
            Write-RoleSecretFile -Values $Values -Path $path -SelectedRole $selectedRole
            $bytes = [IO.File]::ReadAllBytes($path)
            try {
                if ($bytes -contains 13) { throw "$selectedRole secret material contains CRLF." }
            }
            finally { [Array]::Clear($bytes, 0, $bytes.Length) }
            $names = @(Get-Content -LiteralPath $path | ForEach-Object {
                if ($_ -match '^([A-Z][A-Z0-9_]*)=') { $Matches[1] }
            })
            if ($selectedRole -eq 'control' -and 'ADMIN_TOKEN' -notin $names) { throw 'control preseed lacks ADMIN_TOKEN.' }
            if ($selectedRole -ne 'control' -and 'ADMIN_TOKEN' -in $names) { throw "$selectedRole preseed must not carry ADMIN_TOKEN." }
            if ($selectedRole -eq 'core') {
                if ($names.Count -gt 0) {
                    throw 'Core preseed must carry no fleet credential.'
                }
            }
            if ($selectedRole -eq 'data') {
                $expected = @(
                    'RCLONE_CONFIG_B64', 'REQUIRE_REMOTE_BACKUP'
                )
                if ($Values.Contains('DNS4EU_COMMERCIAL_DOH_URL') -and
                    -not [string]::IsNullOrWhiteSpace([string]$Values.DNS4EU_COMMERCIAL_DOH_URL)) {
                    $expected += 'DNS4EU_COMMERCIAL_DOH_URL'
                }
                if (@($names | Where-Object { $_ -notin $expected }).Count -gt 0 -or
                    @($expected | Where-Object { $_ -notin $names }).Count -gt 0) {
                    throw 'Data preseed is not limited to the required backup credentials.'
                }
            }
            if ($selectedRole -eq 'control') {
                foreach ($required in @('SMTP_PASS', 'PAYPAL_CLIENT_SECRET', 'RCLONE_CONFIG_B64', 'CLOUDFLARE_TUNNEL_API_TOKEN', 'CLOUDFLARE_ACCESS_API_TOKEN')) {
                    if ($required -notin $names) { throw "Control preseed lacks $required." }
                }
            }
        }
        Write-Host 'Role-scoped LF-only preseed materialization passed.'
    }
    finally {
        if (Test-Path -LiteralPath $localStage) { Remove-Item -LiteralPath $localStage -Recurse -Force }
    }
}

function Test-ReleaseArtifactsForPreseedValues {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values)

    Assert-PreseedComplete -Values $Values
    $scanner = Join-Path $ProjectRoot 'tools\validate_release_artifact_privacy.py'
    if (-not (Test-Path -LiteralPath $scanner -PathType Leaf)) {
        throw "Release artifact privacy scanner not found: $scanner"
    }
    $python = Get-Command python -ErrorAction Stop
    $payload = [ordered]@{}
    $rcloneBytes = $null
    $rcloneText = ''
    $json = ''
    $jsonBytes = $null
    $process = $null
    try {
        foreach ($name in $script:RequiredControlFields) {
            $value = [string]$Values[$name]
            if ($value.Length -ge 12) {
                $payload[$name] = $value
            }
        }
        $rcloneBytes = [Convert]::FromBase64String([string]$Values.RCLONE_CONFIG_B64)
        $rcloneText = [Text.Encoding]::UTF8.GetString($rcloneBytes)
        $index = 0
        foreach ($line in ($rcloneText -split "\r?\n")) {
            if ($line -match '^\s*[^#;][^=]*=(.*)$') {
                $value = [string]$Matches[1].Trim()
                if ($value.Length -ge 12) {
                    $index++
                    $payload[('RCLONE_VALUE_{0:D2}' -f $index)] = $value
                }
            }
        }
        if ($payload.Count -lt 8) {
            throw 'Too few DPAPI fields were selected for a meaningful artifact scan.'
        }
        $json = [string](ConvertTo-Json -InputObject $payload -Compress)
        if (-not $json.StartsWith('{') -or -not $json.EndsWith('}')) {
            throw 'DPAPI artifact-scan payload did not serialize as one JSON object.'
        }
        try { $null = ConvertFrom-Json -InputObject $json -ErrorAction Stop }
        catch { throw 'DPAPI artifact-scan payload failed local JSON validation.' }
        $jsonBytes = [Text.Encoding]::UTF8.GetBytes($json)
        $start = New-Object System.Diagnostics.ProcessStartInfo
        $start.FileName = $python.Source
        $start.Arguments = '"' + $scanner.Replace('"', '\"') + '" --secrets-stdin'
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardInput = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $start
        if (-not $process.Start()) { throw 'Could not start release artifact privacy scanner.' }
        $stdin = $process.StandardInput.BaseStream
        $stdin.Write($jsonBytes, 0, $jsonBytes.Length)
        $stdin.Flush()
        $stdin.Close()
        $stdout = $process.StandardOutput.ReadToEnd().Trim()
        $stderr = $process.StandardError.ReadToEnd().Trim()
        $process.WaitForExit()
        if ($stdout) { Write-Host $stdout }
        if ($process.ExitCode -ne 0) {
            if ($stderr) { Write-Warning $stderr }
            throw 'Release artifacts contain a DPAPI preseed value or failed privacy validation.'
        }
        Write-Host 'Current Android, Windows, and Linux artifacts contain none of the DPAPI preseed values.'
    }
    finally {
        foreach ($key in @($payload.Keys)) { $payload[$key] = '' }
        $json = ''
        $rcloneText = ''
        if ($null -ne $jsonBytes) { [Array]::Clear($jsonBytes, 0, $jsonBytes.Length) }
        if ($null -ne $rcloneBytes) { [Array]::Clear($rcloneBytes, 0, $rcloneBytes.Length) }
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Test-GitHistoryForPreseedValues {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Values,
        [switch]$WorktreeOnly
    )

    Assert-PreseedComplete -Values $Values
    $scanner = Join-Path $ProjectRoot 'tools\audit_git_history_for_secrets.py'
    if (-not (Test-Path -LiteralPath $scanner -PathType Leaf)) {
        throw "Git history secret scanner not found: $scanner"
    }
    $python = Get-Command python -ErrorAction Stop
    # E-02 (Sol audit, 2026-08-28): the inventory used to enumerate only the
    # admin/SMTP/PayPal/Cloudflare/rclone values by exact name, so a live
    # fleet static key could coexist with a passing exact-value gate. The
    # named list now includes the Winn v3 identity material and the provider
    # keys, AND a pattern sweep catches any *KEY/*SECRET/*TOKEN/*PASSWORD
    # value that later joins the env -- the gate fails closed on unknown
    # labels instead of silently ignoring them.
    $sensitiveFields = @(
        'ADMIN_TOKEN', 'SMTP_USER', 'SMTP_PASS', 'PAYPAL_CLIENT_SECRET',
        'CLOUDFLARE_APPCLOUD_API_TOKEN', 'CLOUDFLARE_WINS_API_TOKEN',
        'CLOUDFLARE_TUNNEL_API_TOKEN', 'CLOUDFLARE_ACCESS_API_TOKEN',
        'WINN3_ADMISSION_KEY', 'WINN3_STATIC_KEY', 'WINN3_STATIC_PRIVATE',
        'WINN3_AUTH_ED25519_KEY', 'WINN3_AUTH_MLDSA65_KEY',
        'WINN_CLIENT_PRIVATE_KEY', 'GEMINI_API_KEY', 'ACCUWEATHER_API_KEY'
    )
    $payload = [ordered]@{}
    $rcloneBytes = $null
    $rcloneText = ''
    $json = ''
    $jsonBytes = $null
    $process = $null
    try {
        foreach ($name in $sensitiveFields) {
            $value = [string]$Values[$name]
            if ($value.Length -ge 12) {
                $payload[$name] = $value
            }
        }
        $rcloneBytes = [Convert]::FromBase64String([string]$Values.RCLONE_CONFIG_B64)
        $rcloneText = [Text.Encoding]::UTF8.GetString($rcloneBytes)
        $index = 0
        foreach ($line in ($rcloneText -split "\r?\n")) {
            if ($line -match '^\s*[^#;][^=]*=(.*)$') {
                $value = [string]$Matches[1].Trim()
                if ($value.Length -ge 12) {
                    $index++
                    $payload[('RCLONE_VALUE_{0:D2}' -f $index)] = $value
                }
            }
        }
        # E-02: pattern sweep -- every value whose env name looks like a
        # credential joins the inventory regardless of the named list, so a
        # NEW secret class cannot ship beneath a passing gate.
        foreach ($key in @($Values.Keys)) {
            if ($key -notmatch '(KEY|SECRET|TOKEN|PASSWORD|PASS)$' -and
                $key -notmatch '(_KEY_|_SECRET_|_TOKEN_|_PASSWORD_|_PASS_)') {
                continue
            }
            if ($payload.Contains($key)) { continue }
            $value = [string]$Values[$key]
            if ($value.Length -ge 20) {
                $payload[$key] = $value
            }
        }
        if ($payload.Count -lt 8) {
            throw 'Too few DPAPI fields were selected for a meaningful Git history audit.'
        }
        $json = [string](ConvertTo-Json -InputObject $payload -Compress)
        if (-not $json.StartsWith('{') -or -not $json.EndsWith('}')) {
            throw 'Git history audit payload did not serialize as one JSON object.'
        }
        try { $null = ConvertFrom-Json -InputObject $json -ErrorAction Stop }
        catch { throw 'Git history audit payload failed local JSON validation.' }
        $jsonBytes = [Text.Encoding]::UTF8.GetBytes($json)
        $start = New-Object System.Diagnostics.ProcessStartInfo
        $start.FileName = $python.Source
        # This action answers one narrow question: whether any currently active
        # DPAPI-preseed value exists in source/history. Generic assignment
        # heuristics are intentionally a separate lint because configuration
        # parsers and placeholder examples otherwise create false positives.
        $scannerArguments = '"' + $scanner.Replace('"', '\"') + '" --repo "' + $ProjectRoot.Replace('"', '\"') + '" --secrets-stdin --exact-only --include-worktree --fail-on-findings'
        if ($WorktreeOnly) { $scannerArguments += ' --worktree-only' }
        $start.Arguments = $scannerArguments
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardInput = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $start
        if (-not $process.Start()) { throw 'Could not start the Git history secret scanner.' }
        $stdin = $process.StandardInput.BaseStream
        $stdin.Write($jsonBytes, 0, $jsonBytes.Length)
        $stdin.Flush()
        $stdin.Close()
        $stdout = $process.StandardOutput.ReadToEnd().Trim()
        $stderr = $process.StandardError.ReadToEnd().Trim()
        $process.WaitForExit()
        if ($stdout) { Write-Host $stdout }
        if ($process.ExitCode -eq 2) {
            if ($WorktreeOnly) {
                throw 'Active deployment credentials occur in current tracked or untracked source files. Remove them before release.'
            }
            throw 'Active deployment credentials remain recoverable from Git history. Rotate/revoke them and carefully purge the matched objects before release.'
        }
        if ($process.ExitCode -ne 0) {
            if ($stderr) { Write-Warning $stderr }
            throw 'Git history secret audit failed.'
        }
    }
    finally {
        foreach ($key in @($payload.Keys)) { $payload[$key] = '' }
        $json = ''
        $rcloneText = ''
        if ($null -ne $jsonBytes) { [Array]::Clear($jsonBytes, 0, $jsonBytes.Length) }
        if ($null -ne $rcloneBytes) { [Array]::Clear($rcloneBytes, 0, $rcloneBytes.Length) }
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Ensure-PayPalWebhook {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values)

    Assert-PreseedComplete -Values $Values
    $basicBytes = $null
    $basic = ''
    $accessToken = ''
    try {
        $basicBytes = [Text.Encoding]::ASCII.GetBytes(([string]$Values.PAYPAL_CLIENT_ID + ':' + [string]$Values.PAYPAL_CLIENT_SECRET))
        $basic = [Convert]::ToBase64String($basicBytes)
        $oauth = Invoke-RestMethod -UseBasicParsing -Method Post -Uri 'https://api-m.paypal.com/v1/oauth2/token' `
            -Headers @{ Authorization = "Basic $basic"; Accept = 'application/json'; 'Accept-Language' = 'en_US' } `
            -ContentType 'application/x-www-form-urlencoded' -Body 'grant_type=client_credentials' -TimeoutSec 30
        $accessToken = [string]$oauth.access_token
        if ([string]::IsNullOrWhiteSpace($accessToken)) { throw 'PayPal OAuth returned no access token.' }
        $headers = @{ Authorization = "Bearer $accessToken"; Accept = 'application/json' }
        $targetUrl = 'https://sync.winsvpn.org/webhook/paypal'
        $requiredNames = @(
            'BILLING.SUBSCRIPTION.ACTIVATED',
            'BILLING.SUBSCRIPTION.UPDATED',
            'BILLING.SUBSCRIPTION.RE-ACTIVATED',
            'BILLING.SUBSCRIPTION.CANCELLED',
            'BILLING.SUBSCRIPTION.SUSPENDED',
            'BILLING.SUBSCRIPTION.EXPIRED',
            'BILLING.SUBSCRIPTION.PAYMENT.FAILED',
            'PAYMENT.SALE.COMPLETED',
            'PAYMENT.SALE.REFUNDED',
            'PAYMENT.SALE.REVERSED',
            'PAYMENT.CAPTURE.COMPLETED',
            'PAYMENT.CAPTURE.REFUNDED',
            'PAYMENT.CAPTURE.REVERSED'
        )
        $eventTypes = @($requiredNames | ForEach-Object { @{ name = $_ } })
        $list = Invoke-RestMethod -UseBasicParsing -Uri 'https://api-m.paypal.com/v1/notifications/webhooks' -Headers $headers -TimeoutSec 30
        $webhook = @($list.webhooks | Where-Object { [string]$_.url -eq $targetUrl } | Select-Object -First 1)
        if ($webhook.Count -eq 0) {
            $body = @{ url = $targetUrl; event_types = $eventTypes } | ConvertTo-Json -Compress -Depth 5
            $webhook = @(Invoke-RestMethod -UseBasicParsing -Method Post -Uri 'https://api-m.paypal.com/v1/notifications/webhooks' `
                -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec 30)
            Write-Host 'Created the missing live PayPal provisioning webhook.'
        }
        $webhookId = [string]$webhook[0].id
        if ([string]::IsNullOrWhiteSpace($webhookId)) { throw 'PayPal webhook response contained no ID.' }
        $details = Invoke-RestMethod -UseBasicParsing -Uri "https://api-m.paypal.com/v1/notifications/webhooks/$webhookId" -Headers $headers -TimeoutSec 30
        $actual = @($details.event_types | ForEach-Object { [string]$_.name })
        $missing = @($requiredNames | Where-Object { $_ -notin $actual })
        if ($missing.Count -gt 0) {
            $patch = ConvertTo-Json -InputObject @(@{ op = 'replace'; path = '/event_types'; value = $eventTypes }) -Compress -Depth 6
            if (-not $patch.TrimStart().StartsWith('[')) { throw 'PayPal JSON Patch payload must be an array.' }
            Invoke-RestMethod -UseBasicParsing -Method Patch -Uri "https://api-m.paypal.com/v1/notifications/webhooks/$webhookId" `
                -Headers $headers -ContentType 'application/json' -Body $patch -TimeoutSec 30 | Out-Null
            Write-Host 'Repaired the live PayPal provisioning event subscriptions.'
            $details = Invoke-RestMethod -UseBasicParsing -Uri "https://api-m.paypal.com/v1/notifications/webhooks/$webhookId" -Headers $headers -TimeoutSec 30
            $actual = @($details.event_types | ForEach-Object { [string]$_.name })
            $missing = @($requiredNames | Where-Object { $_ -notin $actual })
        }
        if ([string]$details.url -ne $targetUrl -or $missing.Count -gt 0) {
            throw 'PayPal webhook verification failed after create/repair.'
        }
        $Values.PAYPAL_WEBHOOK_ID = $webhookId
        Save-PreseedStore -Values $Values
        Write-Host 'Stored the verified PayPal webhook ID inside the DPAPI deployment preseed.'
    }
    finally {
        $accessToken = ''
        $basic = ''
        if ($null -ne $basicBytes) { [Array]::Clear($basicBytes, 0, $basicBytes.Length) }
    }
}

switch ($Action) {
    'ImportLegacy' {
        Import-LegacyPreseed
    }
    'Status' {
        $values = Read-PreseedStore
        Assert-PreseedComplete -Values $values
        Write-Host "DPAPI preseed is complete for control/data/core deployment: $StorePath"
        Write-Host 'GitHub Gist write credential: intentionally not required (stable hidden-origin hostname).'
    }
    'RotateAdminToken' {
        $values = Read-PreseedStore
        $newToken = ''
        try {
            $newToken = New-CryptographicHexSecret -ByteCount 32
            $values.ADMIN_TOKEN = $newToken
            Assert-PreseedComplete -Values $values
            Save-PreseedStore -Values $values
            Write-Host 'Rotated the future control/data/core admin token inside the DPAPI preseed without printing it.'
            Write-Host 'The live hub was not modified; use the rotated token only with the coordinated fresh installation.'
        }
        finally {
            $newToken = ''
        }
    }
    'RotateEdgeAdminToken' {
        $values = Read-PreseedStore
        $newToken = ''
        try {
            $newToken = New-CryptographicHexSecret -ByteCount 32
            $values.EDGE_ADMIN_TOKEN = $newToken
            Assert-PreseedComplete -Values $values
            Save-PreseedStore -Values $values
            Write-Host 'Stored a new hub-only edge admin credential in the DPAPI preseed without printing it.'
            Write-Host 'It reaches the hub only through the control role; no data or core role file ever carries it.'
        }
        finally {
            $newToken = ''
        }
    }
    'RefreshAdminCidr' {
        $values = Read-PreseedStore
        $values.HUB_ADMIN_SSH_CIDRS = Get-CurrentAdminCidr
        Save-PreseedStore -Values $values
        Write-Host 'Refreshed the encrypted trusted administration /32 without printing it.'
    }
    'RefreshSshPublicKey' {
        $values = Read-PreseedStore
        $values.HUB_SSH_PUBLIC_KEY = Resolve-SshPublicKey
        Assert-PreseedComplete -Values $values
        Save-PreseedStore -Values $values
        Write-Host 'Refreshed the encrypted hub SSH public key without changing other preseed values.'
    }
    'SetCloudflareTunnelToken' {
        Set-CloudflareTunnelToken
    }
    'SetCloudflareAccessToken' {
        Set-CloudflareAccessToken
    }
    'SetCloudflareAppCloudToken' {
        Set-CloudflareAppCloudToken
    }
    'RepairCloudflareAppCloudFallback' {
        Repair-CloudflareAppCloudFallback
    }
    'RefreshPayPalProducts' {
        $values = Read-PreseedStore
        Update-PayPalHostedProductContracts -Values $values
        Assert-PreseedComplete -Values $values
        Save-PreseedStore -Values $values
        Write-Host 'Refreshed the encrypted PayPal hosted-product amount/currency contracts without printing them.'
    }
    'EnsurePayPalWebhook' {
        $values = Read-PreseedStore
        Ensure-PayPalWebhook -Values $values
    }
    'SelfTest' {
        $values = Read-PreseedStore
        Test-LocalPreseedMaterialization -Values $values
    }
    'TestProviders' {
        $values = Read-PreseedStore
        Test-ProviderCredentials -Values $values
    }
    'TestArtifacts' {
        $values = Read-PreseedStore
        Test-ReleaseArtifactsForPreseedValues -Values $values
    }
    'AuditWorktree' {
        $values = Read-PreseedStore
        Test-GitHistoryForPreseedValues -Values $values -WorktreeOnly
    }
    'AuditGitHistory' {
        $values = Read-PreseedStore
        Test-GitHistoryForPreseedValues -Values $values
    }
    'Deploy' {
        $values = Read-PreseedStore
        Invoke-RemoteDeployment -Values $values
    }
}
