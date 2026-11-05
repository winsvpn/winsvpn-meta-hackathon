[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class WinsVpnPrefreezeAclRuntimeTestV1 {
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint ProtectedDaclSecurityInformation = 0x80000000;

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr handle);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string sddl, uint revision, out IntPtr descriptor, IntPtr size);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool SetFileSecurityW(
        string path, uint securityInformation, IntPtr descriptor);

    public static void ApplyProtectedDacl(string path, string sddl) {
        IntPtr descriptor;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, out descriptor, IntPtr.Zero)) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        try {
            if (!SetFileSecurityW(
                    path,
                    DaclSecurityInformation | ProtectedDaclSecurityInformation,
                    descriptor)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        } finally {
            LocalFree(descriptor);
        }
    }
}
'@

function Test-StrictAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$UserSid
    )
    $acl = Get-Acl -LiteralPath $Path
    $entries = @($acl.Access)
    $actualSids = @($entries | ForEach-Object {
        $_.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    } | Sort-Object -Unique)
    $expectedSids = @('S-1-5-18', $UserSid) | Sort-Object
    $acl.AreAccessRulesProtected -and $entries.Count -eq 2 -and
        ($actualSids -join '|') -ceq ($expectedSids -join '|') -and
        @($entries | Where-Object {
            $_.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow -or
            $_.FileSystemRights -ne
                [Security.AccessControl.FileSystemRights]::FullControl -or
            $_.IsInherited
        }).Count -eq 0
}

$userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sddl = "D:P(A;;FA;;;SY)(A;;FA;;;$userSid)"
$root = Join-Path $env:TEMP (
    'winsvpn-prefreeze-acl-regression-' + [Guid]::NewGuid().ToString('N')
)
$target = Join-Path $root 'vpn_settings.txt.wvdp'
$temporary = "$target.prefreeze-write.tmp"
$oldWriteStrict = $true
$patchedTemporaryStrict = $false
$atomicReplacementStrict = $false

try {
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    [WinsVpnPrefreezeAclRuntimeTestV1]::ApplyProtectedDacl($root, $sddl)
    [IO.File]::WriteAllBytes($target, [byte[]](0x57, 0x56, 0x44, 0x50))
    [WinsVpnPrefreezeAclRuntimeTestV1]::ApplyProtectedDacl($target, $sddl)

    # This is the pre-fix behavior: a newly written sibling does not carry the
    # protected two-ACE DACL merely because its directory has that DACL.
    [IO.File]::WriteAllBytes($temporary, [byte[]](1, 2, 3, 4))
    $oldWriteStrict = Test-StrictAcl -Path $temporary -UserSid $userSid

    # This is the fixed flow: secure and verify the same-volume temporary,
    # atomically replace, then reapply and verify the destination.
    [WinsVpnPrefreezeAclRuntimeTestV1]::ApplyProtectedDacl($temporary, $sddl)
    $patchedTemporaryStrict = Test-StrictAcl `
        -Path $temporary -UserSid $userSid
    Move-Item -LiteralPath $temporary -Destination $target -Force
    [WinsVpnPrefreezeAclRuntimeTestV1]::ApplyProtectedDacl($target, $sddl)
    $atomicReplacementStrict = Test-StrictAcl `
        -Path $target -UserSid $userSid
} finally {
    if (Test-Path -LiteralPath $temporary) {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Force -ErrorAction SilentlyContinue
    }
}

$pass = -not $oldWriteStrict -and $patchedTemporaryStrict -and
    $atomicReplacementStrict -and -not (Test-Path -LiteralPath $root)
[ordered]@{
    schema_version = 1
    contract = 'winsvpn-prefreeze-securestate-acl-runtime-regression-v1'
    pass = $pass
    old_write_strict = $oldWriteStrict
    patched_temporary_strict = $patchedTemporaryStrict
    atomic_replacement_strict = $atomicReplacementStrict
    scratch_removed = -not (Test-Path -LiteralPath $root)
    secret_material_used = $false
} | ConvertTo-Json -Compress

if (-not $pass) { exit 1 }
