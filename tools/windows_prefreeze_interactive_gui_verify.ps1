[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedVerifierSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedGuiSha256,
    [Parameter(Mandatory)][ValidateRange(1, 255)][int]$ExpectedSessionId,
    [Parameter(Mandatory)][ValidateRange(1, 2147483647)][int]$ExpectedPid,
    [Parameter(Mandatory)][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ExpectedGuiSha256 = $ExpectedGuiSha256.ToLowerInvariant()
$ExpectedVerifierSha256 = $ExpectedVerifierSha256.ToLowerInvariant()
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$allowedRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramData 'WinsVPN\PreFreezeMatrix')
).TrimEnd('\') + '\'
if ((Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant() `
        -cne $ExpectedVerifierSha256 -or
    -not [Environment]::UserInteractive -or
    (Get-Process -Id $PID).SessionId -ne $ExpectedSessionId -or
    -not $OutputPath.StartsWith(
        $allowedRoot, [StringComparison]::OrdinalIgnoreCase
    ) -or [IO.Path]::GetExtension($OutputPath) -cne '.json') {
    throw 'The GUI verifier is not in its exact interactive/output boundary.'
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class WinsVpnPreFreezeInteractiveGuiVerifyV1 {
 const uint QueryLimited=0x1000,TokenQuery=8,GwOwner=4;
 const int TokenElevation=20,DwmwaCloaked=14;
 delegate bool EnumWindowsProc(IntPtr w,IntPtr p);
 [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint a,bool i,uint p);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool GetTokenInformation(IntPtr t,int c,out int v,int l,out int r);
 [DllImport("user32.dll")]static extern bool EnumWindows(EnumWindowsProc c,IntPtr p);
 [DllImport("user32.dll")]static extern uint GetWindowThreadProcessId(IntPtr w,out uint p);
 [DllImport("user32.dll")]static extern bool IsWindowVisible(IntPtr w);
 [DllImport("user32.dll")]static extern bool IsIconic(IntPtr w);
 [DllImport("user32.dll")]static extern IntPtr GetParent(IntPtr w);
 [DllImport("user32.dll")]static extern IntPtr GetWindow(IntPtr w,uint c);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)]static extern int GetClassName(IntPtr w,StringBuilder s,int m);
 [DllImport("dwmapi.dll")]static extern int DwmGetWindowAttribute(IntPtr w,int a,out int v,int s);
 public static bool Elevated(uint id){IntPtr p=OpenProcess(QueryLimited,false,id);if(p==IntPtr.Zero)throw new Win32Exception();try{IntPtr t;if(!OpenProcessToken(p,TokenQuery,out t))throw new Win32Exception();try{int v,r;if(!GetTokenInformation(t,TokenElevation,out v,4,out r))throw new Win32Exception();return v!=0;}finally{CloseHandle(t);}}finally{CloseHandle(p);}}
 public static IntPtr Window(uint id){var a=new List<IntPtr>();EnumWindows(delegate(IntPtr w,IntPtr p){uint x;GetWindowThreadProcessId(w,out x);if(x!=id||!IsWindowVisible(w)||IsIconic(w)||GetParent(w)!=IntPtr.Zero||GetWindow(w,GwOwner)!=IntPtr.Zero)return true;var s=new StringBuilder(256);GetClassName(w,s,s.Capacity);if(s.ToString()!="FLUTTER_RUNNER_WIN32_WINDOW")return true;int c=0;if(DwmGetWindowAttribute(w,DwmwaCloaked,out c,4)==0&&c!=0)return true;a.Add(w);return true;},IntPtr.Zero);return a.Count==1?a[0]:IntPtr.Zero;}
}
'@

$matches = @(Get-Process wins_vpn -ErrorAction Stop | Where-Object {
    if ($_.SessionId -ne $ExpectedSessionId) { return $false }
    try {
        (Get-FileHash -LiteralPath $_.Path -Algorithm SHA256).Hash.ToLowerInvariant() `
            -ceq $ExpectedGuiSha256
    } catch { $false }
})
if ($matches.Count -ne 1 -or $matches[0].Id -ne $ExpectedPid -or
    -not $matches[0].Responding) {
    throw 'Exactly one responsive exact GUI process was not found.'
}
$process = $matches[0]
$elevated = [WinsVpnPreFreezeInteractiveGuiVerifyV1]::Elevated(
    [uint32]$process.Id
)
$window = [WinsVpnPreFreezeInteractiveGuiVerifyV1]::Window(
    [uint32]$process.Id
)
if ($elevated -or $window -eq [IntPtr]::Zero) {
    throw 'The exact GUI is not one normal-token visible Flutter window.'
}
$receipt = [ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-prefreeze-interactive-gui-proof-v1'
    verified = $true
    verifier_sha256 = $ExpectedVerifierSha256
    exact_gui_sha256 = $ExpectedGuiSha256
    gui_pid = [int]$process.Id
    session_id = [int]$process.SessionId
    normal_token = $true
    responsive = $true
    exact_visible_flutter_window = $true
    observed_at_utc = [DateTime]::UtcNow.ToString('o')
    secret_material_redacted = $true
} | ConvertTo-Json -Depth 5 -Compress
$temporary = $OutputPath + '.tmp-' + [Guid]::NewGuid().ToString('N')
try {
    [IO.File]::WriteAllText(
        $temporary,
        $receipt,
        [Text.UTF8Encoding]::new($false)
    )
    Move-Item -LiteralPath $temporary -Destination $OutputPath `
        -ErrorAction Stop
} finally {
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
}
