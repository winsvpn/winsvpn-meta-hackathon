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
    [string]$ExpectedSecureClosureSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedLegacyClosureSha256,
    [Parameter(Mandatory)][string]$RepairTaskName,
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
$backupRoot = Join-Path $RunRoot 'private\state-backup'
$secureBackup = Join-Path $backupRoot 'secure'
$legacyBackup = Join-Path $backupRoot 'legacy'
$guiPath = Join-Path $env:ProgramFiles 'WinsVPN\wins_vpn.exe'
$guiTask = "WinsVPN-Recovery-GUI-$runLeaf"
$ExpectedGuiSha256 = $ExpectedGuiSha256.ToLowerInvariant()
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
        [IO.FileAttributes]::ReparsePoint) -or
    (Get-FileHash -LiteralPath $guiPath -Algorithm SHA256).Hash.ToLowerInvariant() `
        -cne $ExpectedGuiSha256) {
    throw 'The recovery repair boundary or exact GUI changed.'
}
if (-not (Get-ScheduledTask -TaskName $RepairTaskName `
        -ErrorAction SilentlyContinue)) {
    throw 'The declared one-use repair task does not exist.'
}

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class WinsVpnPreFreezeRepairNativeV1 {
 const uint QueryLimited=0x1000,TokenQuery=8; const int TokenElevation=20;
 const uint DaclSecurity=0x4,ProtectedDacl=0x80000000;
 [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint a,bool i,uint p);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool GetTokenInformation(IntPtr t,int c,out int v,int l,out int r);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string s,uint r,out IntPtr d,IntPtr n);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool SetFileSecurity(string p,uint i,IntPtr d);
 public static bool Elevated(uint id){IntPtr p=OpenProcess(QueryLimited,false,id);if(p==IntPtr.Zero)throw new Win32Exception();try{IntPtr t;if(!OpenProcessToken(p,TokenQuery,out t))throw new Win32Exception();try{int v,r;if(!GetTokenInformation(t,TokenElevation,out v,4,out r))throw new Win32Exception();return v!=0;}finally{CloseHandle(t);}}finally{CloseHandle(p);}}
 public static void ApplyStrict(string path,string sddl){IntPtr d;if(!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl,1,out d,IntPtr.Zero))throw new Win32Exception();try{if(!SetFileSecurity(path,DaclSecurity|ProtectedDacl,d))throw new Win32Exception();}finally{LocalFree(d);}}
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

function Set-StrictSecureFileAcl([string]$Path) {
    [WinsVpnPreFreezeRepairNativeV1]::ApplyStrict(
        $Path,
        "D:P(A;;FA;;;SY)(A;;FA;;;$TargetUserSid)"
    )
}

function Test-StrictSecureFileAcl([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path
    $owner = ([Security.Principal.NTAccount]$acl.Owner).Translate(
        [Security.Principal.SecurityIdentifier]
    ).Value
    $records = @($acl.Access | ForEach-Object {
        [ordered]@{
            sid = $_.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]
            ).Value
            type = [string]$_.AccessControlType
            rights = [string]$_.FileSystemRights
            inherited = [bool]$_.IsInherited
        }
    })
    $sids = @($records | Where-Object {
        $_.type -ceq 'Allow' -and $_.rights -match 'FullControl' -and
        -not $_.inherited
    } | ForEach-Object sid | Sort-Object -Unique)
    $expected = @('S-1-5-18', $TargetUserSid) | Sort-Object
    [ordered]@{
        path = $Path
        valid = $acl.AreAccessRulesProtected -and $records.Count -eq 2 -and
            ($sids -join '|') -ceq ($expected -join '|')
        owner_sid = $owner
        protected = [bool]$acl.AreAccessRulesProtected
        sddl = $acl.Sddl
        entries = $records
    }
}

function Get-ExactGuiProcesses {
    @(Get-Process wins_vpn -ErrorAction SilentlyContinue | Where-Object {
        try {
            ([string](Get-FileHash -LiteralPath $_.Path `
                -Algorithm SHA256).Hash).ToLowerInvariant() -ceq
                $ExpectedGuiSha256
        } catch { $false }
    })
}

if ((Get-StateClosure $secureBackup) -cne $ExpectedSecureClosureSha256 -or
    (Get-StateClosure $legacyBackup) -cne $ExpectedLegacyClosureSha256) {
    throw 'The recovery backup bytes are not the armed baseline.'
}
$exactGui = @(Get-ExactGuiProcesses)
$allGui = @(Get-Process wins_vpn -ErrorAction SilentlyContinue)
if ($allGui.Count -ne $exactGui.Count -or $exactGui.Count -gt 1) {
    throw 'An unexpected GUI process exists before repair.'
}
$exactGui | Stop-Process -Force -ErrorAction Stop
$limit = [DateTime]::UtcNow.AddSeconds(10)
do { Start-Sleep -Milliseconds 250; $exactGui = @(Get-ExactGuiProcesses) }
while ($exactGui.Count -ne 0 -and [DateTime]::UtcNow -lt $limit)
if ($exactGui.Count -ne 0) { throw 'The old exact GUI did not stop.' }

$secureFiles = @(Get-ChildItem -LiteralPath $secureRoot -File -Force |
    Sort-Object Name)
$secureBackupFiles = @(Get-ChildItem -LiteralPath $secureBackup -File -Force |
    Sort-Object Name)
if (($secureFiles.Name -join '|') -cne ($secureBackupFiles.Name -join '|')) {
    throw 'The secure-state file topology is not the armed baseline.'
}
foreach ($source in $secureBackupFiles) {
    [IO.File]::WriteAllBytes(
        (Join-Path $secureRoot $source.Name),
        [IO.File]::ReadAllBytes($source.FullName)
    )
}
foreach ($file in $secureFiles) { Set-StrictSecureFileAcl $file.FullName }
$secureAclProof = @($secureFiles | ForEach-Object {
    Test-StrictSecureFileAcl $_.FullName
})
if (@($secureAclProof | Where-Object { -not $_.valid }).Count -ne 0 -or
    (Get-StateClosure $secureRoot) -cne $ExpectedSecureClosureSha256) {
    throw 'Secure-state bytes or strict ACL repair did not converge.'
}

$sid = [Security.SecurityElement]::Escape($TargetUserSid)
$gui = [Security.SecurityElement]::Escape($guiPath)
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
 <Principals><Principal id="A"><UserId>$sid</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
 <Settings><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
 <Triggers/><Actions Context="A"><Exec><Command>$gui</Command></Exec></Actions>
</Task>
"@
if (Get-ScheduledTask -TaskName $guiTask -ErrorAction SilentlyContinue) {
    throw 'The recovery GUI task already exists.'
}
try {
    Register-ScheduledTask -TaskName $guiTask -Xml $taskXml | Out-Null
    $registered = Get-ScheduledTask -TaskName $guiTask
    $registeredXml = Export-ScheduledTask -TaskName $guiTask
    if ([string]$registered.Principal.LogonType -cne 'Interactive' -or
        [string]$registered.Principal.RunLevel -cne 'Limited' -or
        [string]$registered.Actions[0].Execute -cne $guiPath -or
        $registeredXml -notmatch '<LogonType>InteractiveToken</LogonType>' -or
        $registeredXml -notmatch (
            '<UserId>' + [regex]::Escape($TargetUserSid) + '</UserId>'
        )) {
        throw 'The normal GUI recovery task semantic contract is invalid.'
    }
    Start-ScheduledTask -TaskName $guiTask
    $limit = [DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 250
        $exactGui = @(Get-ExactGuiProcesses | Where-Object {
            $_.SessionId -eq $TargetSessionId
        })
    } while ($exactGui.Count -ne 1 -and [DateTime]::UtcNow -lt $limit)
    if ($exactGui.Count -ne 1 -or -not $exactGui[0].Responding -or
        [WinsVpnPreFreezeRepairNativeV1]::Elevated(
            [uint32]$exactGui[0].Id
        )) {
        throw 'The repaired exact GUI is not one responsive normal process.'
    }
} finally {
    Unregister-ScheduledTask -TaskName $guiTask -Confirm:$false `
        -ErrorAction SilentlyContinue
}

# Let startup cache writes settle, then restore only the baseline legacy bytes
# and secure DPAPI bytes into the existing files. Reapply the source-defined
# secure DACL after startup so the live GUI cannot leave regenerated
# ciphertext or a relaxed access policy at the recovery handoff. Ownership is
# evidence only and is deliberately not changed.
Start-Sleep -Seconds 8
$secureFiles = @(Get-ChildItem -LiteralPath $secureRoot -File -Force |
    Sort-Object Name)
if (($secureFiles.Name -join '|') -cne ($secureBackupFiles.Name -join '|')) {
    throw 'The secure-state topology changed during GUI startup.'
}
foreach ($source in $secureBackupFiles) {
    [IO.File]::WriteAllBytes(
        (Join-Path $secureRoot $source.Name),
        [IO.File]::ReadAllBytes($source.FullName)
    )
}
foreach ($file in $secureFiles) { Set-StrictSecureFileAcl $file.FullName }
$legacyFiles = @(Get-ChildItem -LiteralPath $legacyRoot -File -Force |
    Sort-Object Name)
$backupFiles = @(Get-ChildItem -LiteralPath $legacyBackup -File -Force |
    Sort-Object Name)
if (($legacyFiles.Name -join '|') -cne ($backupFiles.Name -join '|')) {
    throw 'The legacy file topology changed during recovery.'
}
$legacyAclsBefore = [ordered]@{}
foreach ($file in $legacyFiles) {
    $legacyAclsBefore[$file.Name] = (Get-Acl -LiteralPath $file.FullName).Sddl
}
foreach ($source in $backupFiles) {
    $target = Join-Path $legacyRoot $source.Name
    [IO.File]::WriteAllBytes(
        $target,
        [IO.File]::ReadAllBytes($source.FullName)
    )
    if ((Get-Acl -LiteralPath $target).Sddl -cne
        $legacyAclsBefore[$source.Name]) {
        throw 'Legacy byte restore changed the existing file ACL.'
    }
}
if ((Get-StateClosure $legacyRoot) -cne $ExpectedLegacyClosureSha256 -or
    (Get-StateClosure $secureRoot) -cne $ExpectedSecureClosureSha256) {
    throw 'Final recovery closures did not converge.'
}
$exactGui = @(Get-ExactGuiProcesses | Where-Object {
    $_.SessionId -eq $TargetSessionId
})
$secureAclProof = @($secureFiles | ForEach-Object {
    Test-StrictSecureFileAcl $_.FullName
})
if ($exactGui.Count -ne 1 -or -not $exactGui[0].Responding -or
    [WinsVpnPreFreezeRepairNativeV1]::Elevated([uint32]$exactGui[0].Id) -or
    @($secureAclProof | Where-Object { -not $_.valid }).Count -ne 0) {
    throw 'Final normal GUI or secure ACL proof did not converge.'
}

[ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-prefreeze-recovery-repair-v1'
    repaired = $true
    exact_gui_sha256 = $ExpectedGuiSha256
    exact_gui_pid = [int]$exactGui[0].Id
    exact_gui_session_id = [int]$exactGui[0].SessionId
    exact_gui_normal_token_and_responsive = $true
    secure_closure_sha256 = Get-StateClosure $secureRoot
    secure_acl_proof = $secureAclProof
    legacy_closure_sha256 = Get-StateClosure $legacyRoot
    legacy_topology = 'present'
    legacy_existing_acl_preserved = $true
    gui_task_removed = $null -eq (
        Get-ScheduledTask -TaskName $guiTask -ErrorAction SilentlyContinue
    )
    repair_task_name = $RepairTaskName
    observed_at_utc = [DateTime]::UtcNow.ToString('o')
    secret_material_redacted = $true
} | ConvertTo-Json -Depth 12 -Compress | ForEach-Object {
    [IO.File]::WriteAllText(
        $OutputPath,
        $_,
        [Text.UTF8Encoding]::new($false)
    )
}
