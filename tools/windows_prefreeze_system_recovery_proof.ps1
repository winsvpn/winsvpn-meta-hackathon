[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunRoot,
    [Parameter(Mandatory)][string]$TargetProfile,
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-21-(\d+-){3}\d+$')]
    [string]$TargetUserSid,
    [Parameter(Mandatory)][ValidateRange(1, 255)][int]$TargetSessionId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedGuiSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedServiceSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedSecureClosureSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedLegacyClosureSha256,
    [Parameter(Mandatory)][ValidateSet('present', 'absent')]
    [string]$ExpectedLegacyTopology,
    [Parameter(Mandatory)][string]$ProofTaskName,
    [Parameter(Mandatory)][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RunRoot = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
$TargetProfile = [IO.Path]::GetFullPath($TargetProfile).TrimEnd('\')
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$runLeaf = Split-Path -Leaf $RunRoot
$allowedRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramData 'WinsVPN\PreFreezeMatrix')
).TrimEnd('\') + '\'
$secureRoot = Join-Path $TargetProfile 'AppData\Local\WinsVPN\SecureState'
$legacyRoot = Join-Path $TargetProfile 'AppData\Roaming\wins_vpn'
$guiPath = Join-Path $env:ProgramFiles 'WinsVPN\wins_vpn.exe'
$servicePath = Join-Path $env:ProgramFiles `
    'WinsVPN\wins_vpn_tunnel_service.exe'
$firewallGroup = "WinsVPN-PreFreeze-$runLeaf"
$ExpectedGuiSha256 = $ExpectedGuiSha256.ToLowerInvariant()
$ExpectedServiceSha256 = $ExpectedServiceSha256.ToLowerInvariant()
$ExpectedSecureClosureSha256 = `
    $ExpectedSecureClosureSha256.ToLowerInvariant()
$ExpectedLegacyClosureSha256 = `
    $ExpectedLegacyClosureSha256.ToLowerInvariant()

if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne
        'S-1-5-18' -or
    -not ($RunRoot + '\').StartsWith(
        $allowedRoot, [StringComparison]::OrdinalIgnoreCase
    ) -or $runLeaf -notmatch '^[0-9a-f]{32}$' -or
    -not $OutputPath.StartsWith(
        ($RunRoot + '\'), [StringComparison]::OrdinalIgnoreCase
    ) -or [IO.Path]::GetExtension($OutputPath) -cne '.json' -or
    [bool]((Get-Item -LiteralPath $RunRoot).Attributes -band
        [IO.FileAttributes]::ReparsePoint)) {
    throw 'The SYSTEM recovery proof boundary is invalid.'
}

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class WinsVpnPreFreezeSystemProofNativeV1 {
 const uint QueryLimited=0x1000,TokenQuery=8; const int TokenElevation=20;
 [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint a,bool i,uint p);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool GetTokenInformation(IntPtr t,int c,out int v,int l,out int r);
 public static bool Elevated(uint id){IntPtr p=OpenProcess(QueryLimited,false,id);if(p==IntPtr.Zero)throw new Win32Exception();try{IntPtr t;if(!OpenProcessToken(p,TokenQuery,out t))throw new Win32Exception();try{int v,r;if(!GetTokenInformation(t,TokenElevation,out v,4,out r))throw new Win32Exception();return v!=0;}finally{CloseHandle(t);}}finally{CloseHandle(p);}}
}
'@

function Get-StringSha256([AllowEmptyString()][string]$Value) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($algorithm.ComputeHash(
            [Text.UTF8Encoding]::new($false).GetBytes($Value)
        ))).Replace('-', '').ToLowerInvariant()
    } finally { $algorithm.Dispose() }
}

function Get-StateClosure([string]$Root) {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        return Get-StringSha256 ''
    }
    $parts = @(Get-ChildItem -LiteralPath $Root -File -Force |
        Sort-Object Name | ForEach-Object {
            $_.Name + ':' + (
                Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
            ).Hash.ToLowerInvariant()
        })
    Get-StringSha256 ($parts -join '|')
}

function Get-AclRecord([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    $entries = @($acl.Access | ForEach-Object {
        $sid = $_.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
        [ordered]@{
            sid = $sid
            type = [string]$_.AccessControlType
            rights = [string]$_.FileSystemRights
            inherited = [bool]$_.IsInherited
            inheritance_flags = [string]$_.InheritanceFlags
            propagation_flags = [string]$_.PropagationFlags
        }
    })
    $ownerSid = $acl.Owner
    try {
        $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    } catch {}
    $strictSids = @($entries | Where-Object {
        $_.type -ceq 'Allow' -and $_.rights -match 'FullControl' -and
        -not $_.inherited
    } | ForEach-Object sid | Sort-Object -Unique)
    $expectedSids = @('S-1-5-18', $TargetUserSid) | Sort-Object
    [ordered]@{
        path = $Path
        owner_sid = $ownerSid
        protected = [bool]$acl.AreAccessRulesProtected
        sddl = $acl.Sddl
        entries = $entries
        strict_current_user_system = (
            $acl.AreAccessRulesProtected -and $entries.Count -eq 2 -and
            ($strictSids -join '|') -ceq ($expectedSids -join '|')
        )
    }
}

$secureClosure = Get-StateClosure $secureRoot
$legacyClosure = Get-StateClosure $legacyRoot
$legacyTopology = if (Test-Path -LiteralPath $legacyRoot -PathType Container) {
    'present'
} else { 'absent' }
$secureAcl = Get-AclRecord $secureRoot
$secureFileAcls = @(Get-ChildItem -LiteralPath $secureRoot -File -Force |
    Sort-Object Name | ForEach-Object { Get-AclRecord $_.FullName })
$guiProcesses = @(Get-Process wins_vpn -ErrorAction SilentlyContinue |
    Where-Object {
        if ($_.SessionId -ne $TargetSessionId) { return $false }
        try {
            ([string](Get-FileHash -LiteralPath $_.Path `
                -Algorithm SHA256).Hash).ToLowerInvariant() -ceq
                $ExpectedGuiSha256
        } catch { $false }
    })
$guiNormal = $guiProcesses.Count -eq 1 -and $guiProcesses[0].Responding -and
    -not [WinsVpnPreFreezeSystemProofNativeV1]::Elevated(
        [uint32]$guiProcesses[0].Id
    )
$activeServices = @(Get-Service -ErrorAction SilentlyContinue | Where-Object {
    ($_.Name -eq 'WinsVPNSplitTunnel' -or
     $_.Name -like 'AmneziaWGTunnel$winsvpn*') -and
    $_.Status -ne 'Stopped'
})
$adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq 'winsvpn' -and $_.Status -ne 'Disabled' })
$routes = @(Get-NetRoute -InterfaceAlias 'winsvpn' -ErrorAction SilentlyContinue)
$xray = @(Get-Process xray -ErrorAction SilentlyContinue)
$awgEngine = @(Get-Process winsvpn_awg_engine -ErrorAction SilentlyContinue)
$rules = @(Get-NetFirewallRule -Group $firewallGroup `
    -ErrorAction SilentlyContinue)
$otherTasks = @(Get-ScheduledTask -TaskName 'WinsVPN-PreFreeze-*' `
    -ErrorAction SilentlyContinue | Where-Object TaskName -ne $ProofTaskName |
    Select-Object TaskName, State)
$zeroResidue = $activeServices.Count -eq 0 -and $adapters.Count -eq 0 -and
    $routes.Count -eq 0 -and $xray.Count -eq 0 -and
    $awgEngine.Count -eq 0
$strictSecureAcls = $secureAcl.strict_current_user_system -and
    @($secureFileAcls | Where-Object {
        -not $_.strict_current_user_system
    }).Count -eq 0
$pass = $secureClosure -ceq $ExpectedSecureClosureSha256 -and
    $legacyClosure -ceq $ExpectedLegacyClosureSha256 -and
    $legacyTopology -ceq $ExpectedLegacyTopology -and
    $strictSecureAcls -and $zeroResidue -and $rules.Count -eq 0 -and
    $otherTasks.Count -eq 0 -and $guiNormal -and
    (Get-FileHash -LiteralPath $guiPath -Algorithm SHA256).Hash.ToLowerInvariant() `
        -ceq $ExpectedGuiSha256 -and
    (Get-FileHash -LiteralPath $servicePath -Algorithm SHA256).Hash.ToLowerInvariant() `
        -ceq $ExpectedServiceSha256

$receipt = [ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-prefreeze-system-recovery-proof-v1'
    pass = $pass
    secure_closure_sha256 = $secureClosure
    secure_closure_matches = $secureClosure -ceq $ExpectedSecureClosureSha256
    legacy_closure_sha256 = $legacyClosure
    legacy_closure_matches = $legacyClosure -ceq $ExpectedLegacyClosureSha256
    legacy_topology = $legacyTopology
    legacy_topology_matches = $legacyTopology -ceq $ExpectedLegacyTopology
    secure_root_acl = $secureAcl
    secure_file_acls = $secureFileAcls
    strict_secure_acl_contract = $strictSecureAcls
    scoped_firewall_rule_count = $rules.Count
    other_matrix_tasks = $otherTasks
    active_tunnel_service_count = $activeServices.Count
    winsvpn_adapter_count = $adapters.Count
    winsvpn_route_count = $routes.Count
    xray_process_count = $xray.Count
    awg_engine_process_count = $awgEngine.Count
    final_zero_residue = $zeroResidue
    manager = Get-Service WinsVpnTunnelManager |
        Select-Object Name, Status, StartType
    exact_gui_process_count = $guiProcesses.Count
    exact_gui_pid = if ($guiProcesses.Count -eq 1) {
        [int]$guiProcesses[0].Id
    } else { 0 }
    exact_gui_session_id = if ($guiProcesses.Count -eq 1) {
        [int]$guiProcesses[0].SessionId
    } else { -1 }
    exact_gui_normal_token_and_responsive = $guiNormal
    exact_gui_sha256 = (
        Get-FileHash -LiteralPath $guiPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    exact_service_sha256 = (
        Get-FileHash -LiteralPath $servicePath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    observed_at_utc = [DateTime]::UtcNow.ToString('o')
    secret_material_redacted = $true
} | ConvertTo-Json -Depth 12 -Compress
[IO.File]::WriteAllText(
    $OutputPath,
    $receipt,
    [Text.UTF8Encoding]::new($false)
)
