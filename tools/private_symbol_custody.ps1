param([switch]$SelfTest)

$ErrorActionPreference = 'Stop'

function Initialize-PrivateSymbolDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrivateRoot,
        [Parameter(Mandatory)][string]$Path
    )

    $root = [IO.Path]::GetFullPath($PrivateRoot).TrimEnd('\', '/')
    $target = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    if (-not $target.StartsWith(($root + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Private symbol directory must be beneath $root."
    }
    [void][IO.Directory]::CreateDirectory($target)

    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $directories = [Collections.Generic.List[string]]::new()
    $directories.Add($root)
    $current = $root
    $relativeParts = $target.Substring($root.Length).TrimStart('\', '/') -split '[\\/]'
    foreach ($part in $relativeParts) {
        if ([string]::IsNullOrWhiteSpace($part)) { continue }
        $current = Join-Path $current $part
        $directories.Add($current)
    }
    foreach ($directory in $directories) {
        [void][IO.Directory]::CreateDirectory($directory)
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetOwner($currentSid)
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @($currentSid, $systemSid)) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow
            )
            [void]$acl.AddAccessRule($rule)
        }
        # Apply only the owner and DACL sections. Set-Acl can attempt to carry
        # an existing SACL into the write on an idempotent PowerShell 7 run,
        # which incorrectly requires SeSecurityPrivilege from a normal release
        # builder even though this function never changes audit policy.
        $item = Get-Item -LiteralPath $directory -Force
        if ($item.PSObject.Methods.Name -contains 'SetAccessControl') {
            $item.SetAccessControl($acl)
        } else {
            [IO.FileSystemAclExtensions]::SetAccessControl($item, $acl)
        }
        $sections = [Security.AccessControl.AccessControlSections]::Owner -bor
            [Security.AccessControl.AccessControlSections]::Access
        $verified = if ($item.PSObject.Methods.Name -contains 'GetAccessControl') {
            $item.GetAccessControl($sections)
        } else {
            [IO.FileSystemAclExtensions]::GetAccessControl($item, $sections)
        }
        $allowed = @($currentSid.Value, $systemSid.Value)
        $rules = @($verified.GetAccessRules(
            $true, $true, [Security.Principal.SecurityIdentifier]
        ))
        $unsafe = @($rules | Where-Object {
            $_.IsInherited -or
            $_.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $_.IdentityReference.Value -notin $allowed
        })
        if ($verified.GetOwner([Security.Principal.SecurityIdentifier]) -ne
                $currentSid -or
            -not $verified.AreAccessRulesProtected -or $unsafe.Count -gt 0 -or
            $rules.Count -ne $allowed.Count -or
            @($rules | Where-Object {
                ($_.FileSystemRights -band
                    [Security.AccessControl.FileSystemRights]::FullControl) -ne
                    [Security.AccessControl.FileSystemRights]::FullControl
            }).Count -gt 0) {
            throw "Private symbol directory ACL verification failed: $directory"
        }
    }
}

if ($SelfTest) {
    $base = Join-Path ([IO.Path]::GetTempPath()) ("winsvpn-symbol-acl-" + [guid]::NewGuid().ToString('N'))
    try {
        $root = Join-Path $base 'private-release-symbols'
        $target = Join-Path $root 'windows\1.0.0+1'
        Initialize-PrivateSymbolDirectory -PrivateRoot $root -Path $target
        Write-Output 'PRIVATE SYMBOL ACL SELF-TEST: PASS'
    } finally {
        if (Test-Path -LiteralPath $base) { Remove-Item -LiteralPath $base -Recurse -Force }
    }
}
