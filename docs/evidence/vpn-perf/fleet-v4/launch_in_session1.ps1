$ErrorActionPreference = 'Stop'
$code = @'
using System;
using System.Runtime.InteropServices;
public static class SessionLauncher {
  [DllImport("wtsapi32.dll", SetLastError=true)] public static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool DuplicateTokenEx(IntPtr tok, uint acc, IntPtr sa, int level, int type, out IntPtr newTok);
  [DllImport("userenv.dll", SetLastError=true)] public static extern bool CreateEnvironmentBlock(out IntPtr env, IntPtr tok, bool inherit);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool CreateProcessAsUser(IntPtr tok, string app, string cmdline, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct STARTUPINFO { public int cb; public string lpReserved; public string lpDesktop; public string lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
  [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }
  public static uint Launch(uint sessionId, string cmdline) {
    IntPtr tok;
    if (!WTSQueryUserToken(sessionId, out tok)) return unchecked((uint)Marshal.GetLastWin32Error());
    IntPtr dup;
    if (!DuplicateTokenEx(tok, 0xF01FF, IntPtr.Zero, 2, 1, out dup)) return unchecked((uint)Marshal.GetLastWin32Error());
    IntPtr env;
    if (!CreateEnvironmentBlock(out env, dup, false)) return unchecked((uint)Marshal.GetLastWin32Error());
    STARTUPINFO si = new STARTUPINFO(); si.cb = Marshal.SizeOf(si); si.lpDesktop = @"winsta0\default";
    PROCESS_INFORMATION pi;
    bool ok = CreateProcessAsUser(dup, null, cmdline, IntPtr.Zero, IntPtr.Zero, false, 0x400, env, @"C:\fleet", ref si, out pi);
    uint err = ok ? 0u : unchecked((uint)Marshal.GetLastWin32Error());
    if (ok) { CloseHandle(pi.hThread); CloseHandle(pi.hProcess); }
    return err;
  }
}
'@
Add-Type -TypeDefinition $code
Set-Content -Path C:\fleet\launcher_result.txt -Value ('START ' + (Get-Date -Format o))
$r = [SessionLauncher]::Launch(1, 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\fleet\fleet_orchestrator.ps1')
Add-Content -Path C:\fleet\launcher_result.txt -Value ('LAUNCH_RESULT=' + $r)
