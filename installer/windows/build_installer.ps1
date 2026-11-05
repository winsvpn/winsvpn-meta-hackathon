param(
    [string]$Configuration = "Release",
    [switch]$SkipFlutterBuild,
    [switch]$SkipRuntimeDownload,
    [switch]$RequireCodeSigning,
    [switch]$AllowUnsigned,
    [string]$ReleaseInputIndex = $env:WINS_RELEASE_INPUT_INDEX,
    [string]$BuildReceiptDirectory = $env:WINS_WINDOWS_BUILD_RECEIPT_DIR,
    # Remote-attested mode (round R11a): REMOTE_INPUT.json written by
    # tools/release_remote_build.py on the macOS release host, which ran
    # begin-build and runs finish-build. Only that orchestrator sets it.
    [string]$RemoteAttestationInput = $env:WINS_REMOTE_ATTESTATION_INPUT,
    [switch]$SelfTestSigningPolicy,
    [switch]$SelfTestBuildLock,
    [switch]$SelfTestWithdrawnMullvadStaging,
    [switch]$SelfTestPrerequisiteCustody,
    [ValidateSet('website', 'partner-center')]
    [string]$DistributionSurface = 'website',
    [switch]$StandaloneWinn3Release,
    # Ship a Windows build with the Winn Protocol v3 carrier missing or inert.
    #
    # WHY THIS IS A SWITCH AND NOT THE DEFAULT. Until 2026-08-09 both v3
    # builders were "best effort": a missing bash, a Go build failure, or a
    # staged image that did not actually contain the v3 packages each produced a
    # Write-Warning and a finished installer. A warning in a several-thousand
    # line build log is not a decision, and the resulting installer is
    # indistinguishable from a good one until a user in Myanmar connects to a
    # v3 server and is refused. The completeness gate below is now FATAL, so an
    # AmneziaWG/Xray-only Windows release has to be asked for by name.
    [switch]$AllowMissingWinn3Carrier,
    # Signed Winn release directory (tools/winn_release.py build + sign). The
    # Winn Protocol v3 datapath engine and tun relay are taken only from this
    # release, after `winn_release.py verify --print-artifact <target>`.
    [string]$WinnReleaseDir = $env:WINS_WINN_RELEASE_DIR,
    # Dev only: accept an UNSIGNED driver build (verify --allow-unsigned).
    # Refused on any build that must be signed.
    [switch]$AllowUnsignedWinnRelease,
    # Flutter 3.47.1 emits the current Windows host architecture. Stable has no
    # x64-host target override, so native ARM64 releases must run on a Windows
    # ARM64 host and use the architecture-specific dependency set below.
    [ValidateSet('x64', 'arm64')]
    [string]$TargetArchitecture = 'x64',
    [switch]$WinsReleaseDependencyIsolatedStage,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ReleaseDependencyArguments = @()
)

$ErrorActionPreference = "Stop"
$ProgressPreference = 'SilentlyContinue'
$ReleaseDependencyBuildAttemptSwitch = '--wins-release-dependency-build-attempt-v2'
$script:ReleaseDependencyWitnessMode = @($ReleaseDependencyArguments) -contains `
    $ReleaseDependencyBuildAttemptSwitch
$script:ReleaseDependencyWitnessOutput = $null
$script:ReleaseDependencyWitnessSource = $null
$script:ReleaseDependencyWitnessIdentity = $null
$script:ReleaseDependencyWitnessStage = $null

# WINS_RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_V1
# WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_V2
# WINS_RELEASE_DEPENDENCY_NATIVE_HOST=windows
# WINS_RELEASE_DEPENDENCY_NATIVE_RUNTIME=powershell-file
$ReleaseDependencyBuildAttemptContract = 'winsvpn-witnessed-build-attempt-v2'
$ReleaseDependencyBuildAttemptPlatform = 'windows'
$ReleaseDependencyBuildAttemptEnvironment = @(
    'WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT',
    'WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE',
    'WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT',
    'WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM'
)
$ReleaseDependencyDescriptorEnvironment = @(
    'WINS_RELEASE_DEPENDENCY_REPOSITORY_FD',
    'WINS_RELEASE_DEPENDENCY_SOURCE_FD',
    'WINS_RELEASE_DEPENDENCY_ATTEMPT_FD',
    'WINS_RELEASE_DEPENDENCY_OUTPUT_FD'
)
$ReleaseDependencyBuildAttemptOutputs = @(
    'WinsVPN-Setup.exe',
    'WinsVPN-PartnerCenter.exe',
    'WinsVPN-Setup-arm64.exe',
    'WinsVPN-PartnerCenter-arm64.exe',
    'WinsVPN-UNSIGNED-LOCAL-Setup.exe',
    'WinsVPN-UNSIGNED-LOCAL-PartnerCenter.exe',
    'WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe',
    'WinsVPN-UNSIGNED-LOCAL-PartnerCenter-arm64.exe'
)

trap {
    if ($script:ReleaseDependencyWitnessMode) {
        if ($null -ne $script:ReleaseDependencyWitnessOutput) {
            $script:ReleaseDependencyWitnessOutput.Dispose()
            $script:ReleaseDependencyWitnessOutput = $null
        }
        if ($null -ne $script:ReleaseDependencyWitnessSource) {
            $script:ReleaseDependencyWitnessSource.Dispose()
            $script:ReleaseDependencyWitnessSource = $null
        }
        if (-not [string]::IsNullOrWhiteSpace($script:ReleaseDependencyWitnessStage) -and
            (Test-Path -LiteralPath $script:ReleaseDependencyWitnessStage)) {
            Remove-Item -LiteralPath $script:ReleaseDependencyWitnessStage `
                -Recurse -Force -ErrorAction SilentlyContinue
        }
        exit 86
    }
    throw $_
}

function Get-WinsReleaseDependencyEnvironmentEntries {
    $isWindowsHost = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    )
    if (-not $isWindowsHost) {
        return @([Environment]::GetEnvironmentVariables('Process').GetEnumerator() |
            ForEach-Object { "$($_.Key)=$($_.Value)" })
    }
    if (-not ('WinsVpn.ReleaseDependencyEnvironment' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace WinsVpn {
    public static class ReleaseDependencyEnvironment {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetEnvironmentStringsW();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool FreeEnvironmentStringsW(IntPtr environmentBlock);

        public static string[] ReadRawEntries() {
            IntPtr block = GetEnvironmentStringsW();
            if (block == IntPtr.Zero) {
                throw new InvalidOperationException("process environment is unavailable");
            }
            var entries = new List<string>();
            try {
                IntPtr cursor = block;
                while (true) {
                    string entry = Marshal.PtrToStringUni(cursor);
                    if (String.IsNullOrEmpty(entry)) {
                        break;
                    }
                    entries.Add(entry);
                    cursor = IntPtr.Add(cursor, checked((entry.Length + 1) * 2));
                }
            } finally {
                if (!FreeEnvironmentStringsW(block)) {
                    throw new InvalidOperationException("process environment release failed");
                }
            }
            return entries.ToArray();
        }
    }
}
'@
    }
    return @([WinsVpn.ReleaseDependencyEnvironment]::ReadRawEntries())
}

function Read-WinsReleaseDependencyWitnessInputs {
    param([Parameter(Mandatory)][string[]]$Entries)

    $required = @{}
    foreach ($name in $ReleaseDependencyBuildAttemptEnvironment) {
        $required[$name] = $true
    }
    foreach ($name in $ReleaseDependencyDescriptorEnvironment) {
        $required[$name] = $true
    }
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $values = @{}
    foreach ($entry in $Entries) {
        $separator = $entry.IndexOf('=')
        if ($separator -le 0) { continue }
        $name = $entry.Substring(0, $separator)
        if (-not $name.StartsWith(
            'WINS_RELEASE_DEPENDENCY_',
            [StringComparison]::OrdinalIgnoreCase
        )) { continue }
        if (-not $seen.Add($name) -or -not $required.ContainsKey($name)) {
            throw 'invalid witnessed build environment'
        }
        if ([Array]::IndexOf(
            [string[]]$ReleaseDependencyBuildAttemptEnvironment,
            [string]$name
        ) -lt 0) {
            throw 'invalid witnessed build environment'
        }
        $values[$name] = $entry.Substring($separator + 1)
    }
    if ($seen.Count -ne (
            $ReleaseDependencyBuildAttemptEnvironment.Count +
            $ReleaseDependencyDescriptorEnvironment.Count
        )) {
        throw 'invalid witnessed build environment'
    }
    if ($values.WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_CONTRACT -cne
        $ReleaseDependencyBuildAttemptContract -or
        $values.WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_PLATFORM -cne
        $ReleaseDependencyBuildAttemptPlatform -or
        $values.WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE -cnotmatch
        '^[0-9a-f]{64}$') {
        throw 'invalid witnessed build environment'
    }
    $descriptors = @(
        $values.WINS_RELEASE_DEPENDENCY_REPOSITORY_FD,
        $values.WINS_RELEASE_DEPENDENCY_SOURCE_FD,
        $values.WINS_RELEASE_DEPENDENCY_ATTEMPT_FD,
        $values.WINS_RELEASE_DEPENDENCY_OUTPUT_FD
    )
    if (@($descriptors | Where-Object {
            [string]$_ -cnotmatch '^[0-9]{1,19}$' -or [uint64]$_ -lt 4 -or
            [uint64]$_ -gt [int64]::MaxValue
        }).Count -ne 0 -or
        @($descriptors | Select-Object -Unique).Count -ne $descriptors.Count) {
        throw 'invalid witnessed build descriptors'
    }
    return $values
}

function Test-WinsReleaseDependencyOutputName {
    param([Parameter(Mandatory)][string]$Name)

    if ([string]::IsNullOrEmpty($Name) -or $Name.Length -gt 192 -or
        [IO.Path]::IsPathRooted($Name) -or
        [IO.Path]::GetFileName($Name) -cne $Name -or
        $Name.IndexOfAny(@([char]'/', [char]'\', [char]':')) -ge 0 -or
        $Name.EndsWith(' ', [StringComparison]::Ordinal) -or
        $Name.EndsWith('.', [StringComparison]::Ordinal) -or
        $Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+ -]{0,191}$' -or
        $Name.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0 -or
        [Array]::IndexOf(
            [string[]]$ReleaseDependencyBuildAttemptOutputs,
            [string]$Name
        ) -lt 0) {
        throw 'invalid witnessed build output'
    }
}

function Initialize-WinsReleaseDependencyNativeTypes {
    if ('WinsVpn.ReleaseDependencyOutput' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace WinsVpn {
    public static class ReleaseDependencyOutput {
        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME { public uint Low; public uint High; }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION {
            public uint FileAttributes;
            public FILETIME CreationTime;
            public FILETIME LastAccessTime;
            public FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle,
            out BY_HANDLE_FILE_INFORMATION information
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(
            IntPtr handle, uint mask, uint flags
        );

        private static SafeFileHandle BorrowDescriptor(long descriptor) {
            IntPtr handle = new IntPtr(descriptor);
            if (handle == new IntPtr(-1) || handle == IntPtr.Zero) {
                throw new InvalidOperationException("invalid inherited handle");
            }
            if (!SetHandleInformation(handle, 1, 0)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return new SafeFileHandle(handle, false);
        }

        public static ulong[] Inspect(SafeFileHandle handle) {
            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(handle, out information)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return new ulong[] {
                information.VolumeSerialNumber,
                information.FileIndexHigh,
                information.FileIndexLow,
                information.NumberOfLinks,
                ((ulong)information.FileSizeHigh << 32) | information.FileSizeLow,
                information.FileAttributes
            };
        }

        public static ulong[] InspectDescriptor(long descriptor) {
            using (SafeFileHandle handle = BorrowDescriptor(descriptor)) {
                return Inspect(handle);
            }
        }

        public static FileStream OpenBorrowedDescriptor(
            long descriptor, FileAccess access
        ) {
            return new FileStream(
                BorrowDescriptor(descriptor), access, 4096, false
            );
        }
    }

    public static class ReleaseDependencyJob {
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint STARTF_USESTDHANDLES = 0x00000100;
        private const uint HANDLE_FLAG_INHERIT = 0x00000001;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const uint WAIT_TIMEOUT = 0x00000102;
        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
            public long TotalUserTime;
            public long TotalKernelTime;
            public long ThisPeriodTotalUserTime;
            public long ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount;
            public uint TotalProcesses;
            public uint ActiveProcesses;
            public uint TotalTerminatedProcesses;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr attributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            IntPtr job, int informationClass, IntPtr information, uint length
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(
            IntPtr job, int informationClass, IntPtr information,
            uint length, IntPtr returnLength
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessW(
            string applicationName, StringBuilder commandLine,
            IntPtr processAttributes, IntPtr threadAttributes,
            bool inheritHandles, uint creationFlags, IntPtr environment,
            string currentDirectory, ref STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(
            IntPtr handle, uint mask, uint flags
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(
            string name, uint access, uint share, IntPtr securityAttributes,
            uint creationDisposition, uint flags, IntPtr template
        );

        private static void ThrowLastError(string operation) {
            throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
        }

        private static uint ActiveProcesses(IntPtr job) {
            int bytes = Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
            IntPtr buffer = Marshal.AllocHGlobal(bytes);
            try {
                if (!QueryInformationJobObject(job, 1, buffer, (uint)bytes, IntPtr.Zero)) {
                    ThrowLastError("QueryInformationJobObject");
                }
                var value = (JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)
                    Marshal.PtrToStructure(
                        buffer, typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)
                    );
                return value.ActiveProcesses;
            } finally {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public static int Run(
            string executable, string arguments, string workingDirectory,
            string standardOutput, string standardError, uint timeoutMilliseconds
        ) {
            IntPtr job = IntPtr.Zero;
            IntPtr nullInput = new IntPtr(-1);
            PROCESS_INFORMATION process = new PROCESS_INFORMATION();
            FileStream stdout = null;
            FileStream stderr = null;
            try {
                stdout = new FileStream(
                    standardOutput, FileMode.CreateNew, FileAccess.Write,
                    FileShare.Read, 4096, FileOptions.WriteThrough
                );
                stderr = new FileStream(
                    standardError, FileMode.CreateNew, FileAccess.Write,
                    FileShare.Read, 4096, FileOptions.WriteThrough
                );
                if (!SetHandleInformation(
                        stdout.SafeFileHandle.DangerousGetHandle(),
                        HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) ||
                    !SetHandleInformation(
                        stderr.SafeFileHandle.DangerousGetHandle(),
                        HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
                    ThrowLastError("SetHandleInformation");
                }
                nullInput = CreateFileW(
                    "NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero
                );
                if (nullInput == new IntPtr(-1) ||
                    !SetHandleInformation(
                        nullInput, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
                    ThrowLastError("CreateFileW NUL");
                }
                job = CreateJobObject(IntPtr.Zero, null);
                if (job == IntPtr.Zero) {
                    ThrowLastError("CreateJobObject");
                }
                var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                limits.BasicLimitInformation.LimitFlags =
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                int limitBytes = Marshal.SizeOf(
                    typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)
                );
                IntPtr limitBuffer = Marshal.AllocHGlobal(limitBytes);
                try {
                    Marshal.StructureToPtr(limits, limitBuffer, false);
                    if (!SetInformationJobObject(
                            job, 9, limitBuffer, (uint)limitBytes)) {
                        ThrowLastError("SetInformationJobObject");
                    }
                } finally {
                    Marshal.FreeHGlobal(limitBuffer);
                }
                var startup = new STARTUPINFO();
                startup.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
                startup.dwFlags = STARTF_USESTDHANDLES;
                startup.hStdInput = nullInput;
                startup.hStdOutput = stdout.SafeFileHandle.DangerousGetHandle();
                startup.hStdError = stderr.SafeFileHandle.DangerousGetHandle();
                var commandLine = new StringBuilder(
                    "\"" + executable + "\" " + arguments
                );
                if (!CreateProcessW(
                        executable, commandLine, IntPtr.Zero, IntPtr.Zero,
                        true, CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        IntPtr.Zero, workingDirectory, ref startup, out process)) {
                    ThrowLastError("CreateProcessW");
                }
                if (!AssignProcessToJobObject(job, process.hProcess)) {
                    ThrowLastError("AssignProcessToJobObject");
                }
                if (ResumeThread(process.hThread) == UInt32.MaxValue) {
                    ThrowLastError("ResumeThread");
                }
                uint wait = WaitForSingleObject(process.hProcess, timeoutMilliseconds);
                if (wait == WAIT_TIMEOUT) {
                    TerminateJobObject(job, 86);
                    throw new TimeoutException("witnessed process exceeded its deadline");
                }
                if (wait != WAIT_OBJECT_0) {
                    ThrowLastError("WaitForSingleObject");
                }
                uint exitCode;
                if (!GetExitCodeProcess(process.hProcess, out exitCode)) {
                    ThrowLastError("GetExitCodeProcess");
                }
                for (int attempt = 0; attempt != 100 && ActiveProcesses(job) != 0; ++attempt) {
                    Thread.Sleep(50);
                }
                if (ActiveProcesses(job) != 0) {
                    TerminateJobObject(job, 86);
                    throw new InvalidOperationException(
                        "witnessed process left descendants alive"
                    );
                }
                stdout.Flush(true);
                stderr.Flush(true);
                return checked((int)exitCode);
            } catch {
                if (process.hProcess != IntPtr.Zero) {
                    TerminateProcess(process.hProcess, 86);
                }
                if (job != IntPtr.Zero) {
                    TerminateJobObject(job, 86);
                }
                throw;
            } finally {
                if (process.hThread != IntPtr.Zero) { CloseHandle(process.hThread); }
                if (process.hProcess != IntPtr.Zero) { CloseHandle(process.hProcess); }
                if (job != IntPtr.Zero) { CloseHandle(job); }
                if (nullInput != new IntPtr(-1)) { CloseHandle(nullInput); }
                if (stdout != null) { stdout.Dispose(); }
                if (stderr != null) { stderr.Dispose(); }
            }
        }
    }
}
'@
}

function Open-WinsReleaseDependencyWitnessOutput {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Inputs
    )

    Test-WinsReleaseDependencyOutputName -Name $Name
    $workingDirectory = [IO.Path]::GetFullPath((Get-Location).ProviderPath)
    $workingItem = Get-Item -LiteralPath $workingDirectory -Force -ErrorAction Stop
    if (-not $workingItem.PSIsContainer -or
        ($workingItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'invalid witnessed build output'
    }
    $outputPath = [IO.Path]::GetFullPath((Join-Path $workingDirectory $Name))
    if ([IO.Path]::GetDirectoryName($outputPath).TrimEnd('\', '/') -cne
        $workingDirectory.TrimEnd('\', '/')) {
        throw 'invalid witnessed build output'
    }
    $item = Get-Item -LiteralPath $outputPath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -ne 0) {
        throw 'invalid witnessed build output'
    }
    Initialize-WinsReleaseDependencyNativeTypes
    $repositoryIdentity = [WinsVpn.ReleaseDependencyOutput]::InspectDescriptor(
        [int64]$Inputs.WINS_RELEASE_DEPENDENCY_REPOSITORY_FD
    )
    $sourceIdentity = [WinsVpn.ReleaseDependencyOutput]::InspectDescriptor(
        [int64]$Inputs.WINS_RELEASE_DEPENDENCY_SOURCE_FD
    )
    $attemptIdentity = [WinsVpn.ReleaseDependencyOutput]::InspectDescriptor(
        [int64]$Inputs.WINS_RELEASE_DEPENDENCY_ATTEMPT_FD
    )
    if (($repositoryIdentity[5] -band 0x10) -eq 0 -or
        ($attemptIdentity[5] -band 0x10) -eq 0 -or
        ($sourceIdentity[5] -band 0x10) -ne 0 -or
        $sourceIdentity[3] -ne 1 -or $sourceIdentity[4] -le 0) {
        throw 'invalid witnessed build descriptor identity'
    }
    $sourceStream = [WinsVpn.ReleaseDependencyOutput]::OpenBorrowedDescriptor(
        [int64]$Inputs.WINS_RELEASE_DEPENDENCY_SOURCE_FD,
        [IO.FileAccess]::Read
    )
    $stream = [WinsVpn.ReleaseDependencyOutput]::OpenBorrowedDescriptor(
        [int64]$Inputs.WINS_RELEASE_DEPENDENCY_OUTPUT_FD,
        [IO.FileAccess]::Write
    )
    try {
        $identity = [WinsVpn.ReleaseDependencyOutput]::Inspect($stream.SafeFileHandle)
        if (($identity[5] -band 0x10) -ne 0 -or
            $identity[3] -ne 1 -or $identity[4] -ne 0) {
            throw 'invalid witnessed build output'
        }
        return [pscustomobject]@{
            Path = $outputPath
            Stream = $stream
            SourceStream = $sourceStream
            Identity = @($identity[0], $identity[1], $identity[2])
        }
    } catch {
        $stream.Dispose()
        $sourceStream.Dispose()
        throw
    }
}

function Get-WinsReleaseDependencyStreamSha256 {
    param([Parameter(Mandatory)][IO.FileStream]$Stream)

    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        throw 'witnessed producer source descriptor is not readable and seekable'
    }
    $Stream.Position = 0
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($Stream)
    } finally {
        $sha256.Dispose()
        $Stream.Position = 0
    }
    return -join @($digest | ForEach-Object { $_.ToString('x2') })
}

function Get-WinsReleaseDependencyVariant {
    param([Parameter(Mandatory)][string]$Name)

    Test-WinsReleaseDependencyOutputName -Name $Name
    return [pscustomobject]@{
        Architecture = if ($Name -cmatch '-arm64\.exe$') { 'arm64' } else { 'x64' }
        DistributionSurface = if ($Name -cmatch 'PartnerCenter') {
            'partner-center'
        } else {
            'website'
        }
        AllowUnsigned = $Name -cmatch '^WinsVPN-UNSIGNED-LOCAL-'
        ArtifactName = $Name
    }
}

function Invoke-WinsReleaseDependencyJob {
    param(
        [Parameter(Mandatory)][string]$EncodedCommand,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [Parameter(Mandatory)][string]$StandardOutput,
        [Parameter(Mandatory)][string]$StandardError
    )

    Initialize-WinsReleaseDependencyNativeTypes
    $powerShell = (Get-Process -Id $PID -ErrorAction Stop).Path
    $savedEnvironment = @{}
    $privateEnvironment = @(
        $ReleaseDependencyBuildAttemptEnvironment +
        $ReleaseDependencyDescriptorEnvironment
    )
    try {
        foreach ($name in $privateEnvironment) {
            $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable(
                $name,
                [EnvironmentVariableTarget]::Process
            )
            [Environment]::SetEnvironmentVariable(
                $name,
                $null,
                [EnvironmentVariableTarget]::Process
            )
        }
        $exitCode = [WinsVpn.ReleaseDependencyJob]::Run(
            $powerShell,
            "-NoLogo -NoProfile -NonInteractive -EncodedCommand $EncodedCommand",
            $WorkingDirectory,
            $StandardOutput,
            $StandardError,
            [uint32](2 * 60 * 60 * 1000)
        )
    } finally {
        foreach ($name in $privateEnvironment) {
            [Environment]::SetEnvironmentVariable(
                $name,
                $savedEnvironment[$name],
                [EnvironmentVariableTarget]::Process
            )
        }
    }
    if ($exitCode -ne 0) {
        throw "witnessed child failed with exit status $exitCode"
    }
}

function Invoke-WinsReleaseDependencyWitnessBuild {
    param(
        [Parameter(Mandatory)]$Inputs,
        [Parameter(Mandatory)]$Variant
    )

    $attemptDirectory = [IO.Path]::GetFullPath((Get-Location).ProviderPath)
    $nonce = [string]$Inputs.WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_NONCE
    $stageContainer = Join-Path $attemptDirectory ".winsvpn-windows-stage-$nonce"
    if (Test-Path -LiteralPath $stageContainer) {
        throw 'witnessed isolated stage already exists'
    }
    [void][IO.Directory]::CreateDirectory($stageContainer)
    $script:ReleaseDependencyWitnessStage = $stageContainer
    $stageRoot = Join-Path $stageContainer 'source'
    $snapshotPath = [IO.Path]::GetFullPath($PSCommandPath)
    $repoRoot = if (
        (Split-Path -Leaf $snapshotPath) -ceq '.producer' -and
        (Split-Path -Leaf $PSScriptRoot) -ceq ".build-attempt-$nonce" -and
        (Split-Path -Leaf (Split-Path -Parent $PSScriptRoot)) -ceq '.artifacts'
    ) {
        [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    } else {
        throw 'witnessed producer snapshot location is invalid'
    }
    $productionProducer = Join-Path $repoRoot `
        'installer\windows\build_installer.ps1'
    $productionHashFirst = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $productionProducer).Hash
    $productionHashSecond = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $productionProducer).Hash
    $snapshotHashFirst = Get-WinsReleaseDependencyStreamSha256 `
        -Stream $script:ReleaseDependencyWitnessSource
    $snapshotHashSecond = Get-WinsReleaseDependencyStreamSha256 `
        -Stream $script:ReleaseDependencyWitnessSource
    if ($productionHashFirst -cne $productionHashSecond -or
        $snapshotHashFirst -cne $snapshotHashSecond -or
        $productionHashSecond -cne $snapshotHashSecond) {
        throw 'witnessed producer mutated before isolated build'
    }

    $git = Get-Command git.exe -CommandType Application -ErrorAction Stop
    $gitItem = Get-Item -LiteralPath $git.Source -Force -ErrorAction Stop
    if ($gitItem.PSIsContainer -or
        ($gitItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'witnessed source export requires a regular Git executable'
    }
    $escapedGit = $gitItem.FullName.Replace("'", "''")
    $escapedRepo = $repoRoot.Replace("'", "''")
    $escapedStage = $stageRoot.Replace("'", "''")
    $cloneCommand = "& '$escapedGit' clone --no-hardlinks --no-tags " +
        "--quiet -- '$escapedRepo' '$escapedStage'; exit `$LASTEXITCODE"
    $cloneEncoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($cloneCommand)
    )
    Invoke-WinsReleaseDependencyJob -EncodedCommand $cloneEncoded `
        -WorkingDirectory $attemptDirectory `
        -StandardOutput (Join-Path $stageContainer '.clone-stdout.log') `
        -StandardError (Join-Path $stageContainer '.clone-stderr.log')

    $stageProducer = Join-Path $stageRoot `
        'installer\windows\build_installer.ps1'
    $stageHashFirst = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $stageProducer).Hash
    $stageHashSecond = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $stageProducer).Hash
    $productionHashThird = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $productionProducer).Hash
    $snapshotHashThird = Get-WinsReleaseDependencyStreamSha256 `
        -Stream $script:ReleaseDependencyWitnessSource
    if ($stageHashFirst -cne $stageHashSecond -or
        $productionHashThird -cne $productionHashSecond -or
        $snapshotHashThird -cne $snapshotHashSecond -or
        $stageHashSecond -cne $snapshotHashSecond) {
        throw 'witnessed producer or isolated snapshot mutated during export'
    }

    $childArguments = @(
        '-WinsReleaseDependencyIsolatedStage',
        '-RequireCodeSigning',
        '-DistributionSurface',
        [string]$Variant.DistributionSurface,
        '-TargetArchitecture',
        [string]$Variant.Architecture
    )
    if ([bool]$Variant.AllowUnsigned) {
        $childArguments = @(
            '-WinsReleaseDependencyIsolatedStage',
            '-AllowUnsigned',
            '-DistributionSurface',
            [string]$Variant.DistributionSurface,
            '-TargetArchitecture',
            [string]$Variant.Architecture
        )
    }
    $escapedStageProducer = $stageProducer.Replace("'", "''")
    $quotedChildArguments = @($childArguments | ForEach-Object {
        "'" + ([string]$_).Replace("'", "''") + "'"
    }) -join ' '
    $childCommand = "& '$escapedStageProducer' $quotedChildArguments; " +
        'exit $LASTEXITCODE'
    $childEncoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($childCommand)
    )
    Invoke-WinsReleaseDependencyJob -EncodedCommand $childEncoded `
        -WorkingDirectory $stageRoot `
        -StandardOutput (Join-Path $stageContainer '.build-stdout.log') `
        -StandardError (Join-Path $stageContainer '.build-stderr.log')

    $escapedStageRoot = $stageRoot.Replace("'", "''")
    $cleanCommand = "& '$escapedGit' -C '$escapedStageRoot' diff " +
        "--quiet --no-ext-diff --; if (`$LASTEXITCODE -ne 0) { exit 87 }; " +
        "& '$escapedGit' -C '$escapedStageRoot' diff --cached " +
        '--quiet --no-ext-diff --; exit $LASTEXITCODE'
    $cleanEncoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($cleanCommand)
    )
    Invoke-WinsReleaseDependencyJob -EncodedCommand $cleanEncoded `
        -WorkingDirectory $stageRoot `
        -StandardOutput (Join-Path $stageContainer '.clean-stdout.log') `
        -StandardError (Join-Path $stageContainer '.clean-stderr.log')

    $productionHashFourth = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $productionProducer).Hash
    $productionHashFifth = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $productionProducer).Hash
    $snapshotHashFourth = Get-WinsReleaseDependencyStreamSha256 `
        -Stream $script:ReleaseDependencyWitnessSource
    $snapshotHashFifth = Get-WinsReleaseDependencyStreamSha256 `
        -Stream $script:ReleaseDependencyWitnessSource
    $stageHashThird = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $stageProducer).Hash
    $stageHashFourth = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $stageProducer).Hash
    if ($productionHashFourth -cne $productionHashSecond -or
        $productionHashFifth -cne $productionHashFourth -or
        $snapshotHashFourth -cne $snapshotHashSecond -or
        $snapshotHashFifth -cne $snapshotHashFourth -or
        $stageHashThird -cne $stageHashSecond -or
        $stageHashFourth -cne $stageHashThird -or
        $stageHashFourth -cne $snapshotHashFifth) {
        throw 'witnessed producer mutated during isolated installer build'
    }

    $isolatedArtifact = Join-Path $stageRoot (
        'build\windows-installer\' + [string]$Variant.ArtifactName
    )
    $artifactItem = Get-Item -LiteralPath $isolatedArtifact -Force -ErrorAction Stop
    if ($artifactItem.PSIsContainer -or
        ($artifactItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $artifactItem.Length -le 0) {
        throw 'witnessed isolated installer artifact is invalid'
    }
    $artifactStream = [IO.FileStream]::new(
        $artifactItem.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $artifactIdentityBefore = [WinsVpn.ReleaseDependencyOutput]::Inspect(
            $artifactStream.SafeFileHandle
        )
        if ($artifactIdentityBefore[3] -ne 1 -or
            $artifactIdentityBefore[4] -le 0) {
            throw 'witnessed isolated installer handle is invalid'
        }
        $artifactStream.CopyTo($script:ReleaseDependencyWitnessOutput)
        $script:ReleaseDependencyWitnessOutput.Flush($true)
        $artifactIdentityAfter = [WinsVpn.ReleaseDependencyOutput]::Inspect(
            $artifactStream.SafeFileHandle
        )
        $finalIdentity = [WinsVpn.ReleaseDependencyOutput]::Inspect(
            $script:ReleaseDependencyWitnessOutput.SafeFileHandle
        )
        if ($artifactIdentityAfter[0] -ne $artifactIdentityBefore[0] -or
            $artifactIdentityAfter[1] -ne $artifactIdentityBefore[1] -or
            $artifactIdentityAfter[2] -ne $artifactIdentityBefore[2] -or
            $artifactIdentityAfter[3] -ne $artifactIdentityBefore[3] -or
            $artifactIdentityAfter[4] -ne $artifactIdentityBefore[4] -or
            $finalIdentity[0] -ne $script:ReleaseDependencyWitnessIdentity[0] -or
            $finalIdentity[1] -ne $script:ReleaseDependencyWitnessIdentity[1] -or
            $finalIdentity[2] -ne $script:ReleaseDependencyWitnessIdentity[2] -or
            $finalIdentity[3] -ne 1 -or
            $finalIdentity[4] -ne $artifactIdentityBefore[4] -or
            $script:ReleaseDependencyWitnessOutput.Length -ne
                [int64]$artifactIdentityBefore[4]) {
            throw 'witnessed installer handle identity changed'
        }
    } finally {
        $artifactStream.Dispose()
    }
}

if ($script:ReleaseDependencyWitnessMode) {
    if (@($ReleaseDependencyArguments).Count -ne 1 -or
        $ReleaseDependencyArguments[0] -cne $ReleaseDependencyBuildAttemptSwitch -or
        $WinsReleaseDependencyIsolatedStage -or
        $Configuration -cne 'Release' -or $SkipFlutterBuild -or
        $SkipRuntimeDownload -or $RequireCodeSigning -or $AllowUnsigned -or
        -not [string]::IsNullOrEmpty($ReleaseInputIndex) -or
        -not [string]::IsNullOrEmpty($BuildReceiptDirectory) -or
        $SelfTestSigningPolicy -or $SelfTestBuildLock -or
        $SelfTestWithdrawnMullvadStaging -or $SelfTestPrerequisiteCustody -or
        $DistributionSurface -cne 'website' -or $StandaloneWinn3Release -or
        $AllowMissingWinn3Carrier -or $TargetArchitecture -cne 'x64') {
        exit 86
    }
    $witnessInputs = Read-WinsReleaseDependencyWitnessInputs `
        -Entries @(Get-WinsReleaseDependencyEnvironmentEntries)
    $witnessOutputName = [string]`
        $witnessInputs.WINS_RELEASE_DEPENDENCY_BUILD_ATTEMPT_OUTPUT
    Test-WinsReleaseDependencyOutputName -Name $witnessOutputName
    $isWindowsHost = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    )
    if (-not $isWindowsHost) { exit 86 }
    $openedWitnessOutput = Open-WinsReleaseDependencyWitnessOutput `
        -Name $witnessOutputName -Inputs $witnessInputs
    $script:ReleaseDependencyWitnessOutput = $openedWitnessOutput.Stream
    $script:ReleaseDependencyWitnessSource = $openedWitnessOutput.SourceStream
    $script:ReleaseDependencyWitnessIdentity = $openedWitnessOutput.Identity
    $variant = Get-WinsReleaseDependencyVariant -Name $witnessOutputName
    Invoke-WinsReleaseDependencyWitnessBuild `
        -Inputs $witnessInputs -Variant $variant
    $script:ReleaseDependencyWitnessSource.Dispose()
    $script:ReleaseDependencyWitnessSource = $null
    $script:ReleaseDependencyWitnessOutput.Dispose()
    $script:ReleaseDependencyWitnessOutput = $null
    Remove-Item -LiteralPath $script:ReleaseDependencyWitnessStage `
        -Recurse -Force -ErrorAction Stop
    $script:ReleaseDependencyWitnessStage = $null
    exit 0
} elseif (@($ReleaseDependencyArguments).Count -ne 0) {
    throw "Unknown Windows installer producer argument: $($ReleaseDependencyArguments[0])"
}

if ($WinsReleaseDependencyIsolatedStage) {
    $stageSource = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $stageContainer = Split-Path -Parent $stageSource
    $stageContainerName = Split-Path -Leaf $stageContainer
    if ((Split-Path -Leaf $stageSource) -cne 'source' -or
        $stageContainerName -cnotmatch
            '^\.winsvpn-windows-stage-[0-9a-f]{64}$' -or
        @($ReleaseDependencyArguments).Count -ne 0 -or
        -not [string]::IsNullOrEmpty($ReleaseInputIndex) -or
        -not [string]::IsNullOrEmpty($BuildReceiptDirectory) -or
        $SkipFlutterBuild -or $SkipRuntimeDownload -or
        $SelfTestSigningPolicy -or $SelfTestBuildLock -or
        $SelfTestWithdrawnMullvadStaging -or $SelfTestPrerequisiteCustody -or
        $StandaloneWinn3Release -or $AllowMissingWinn3Carrier -or
        ($RequireCodeSigning -eq $AllowUnsigned)) {
        throw 'invalid witnessed isolated Windows installer stage'
    }
}
# All release downloads in this script are HTTPS and SHA-256-pinned, so a
# downgraded transport cannot poison a binary; this makes the transport
# itself non-degradable on the Windows PowerShell 5.1 hosts the installer is
# built on, where the .NET Framework default protocol list can exclude
# TLS 1.2 until the OS/.NET opts into SystemDefault. Additive only: it never
# removes whatever newer protocols the host already negotiated.
if ($PSVersionTable.PSVersion.Major -le 5) {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
if ($StandaloneWinn3Release -and $AllowMissingWinn3Carrier) {
    throw '-StandaloneWinn3Release cannot be combined with -AllowMissingWinn3Carrier.'
}

$script:WindowsFlutterArchDirectory = @{
    'x64' = 'x64'
    'arm64' = 'arm64'
}[$TargetArchitecture]
$script:WindowsAwgGoArch = @{
    'x64' = 'amd64'
    'arm64' = 'arm64'
}[$TargetArchitecture]
# COFF Machine in the PE header. First-party and vendored payloads must match
# the installer target: mixing an ARM64 Flutter GUI with x64 Wintun/Xray, or
# the reverse, is refused by Assert-StagedReleasePeMachines rather than shipped.
$script:WindowsPeMachine = @{
    'x64' = [uint16]0x8664
    'arm64' = [uint16]0xAA64
}[$TargetArchitecture]
if (-not $script:WindowsFlutterArchDirectory -or -not $script:WindowsAwgGoArch -or -not $script:WindowsPeMachine) {
    throw "Unsupported Windows TargetArchitecture '$TargetArchitecture'."
}
$WindowsInnoFreezeTargets = @{
    'x64' = @{
        Signed = 'windows-x64-inno-signed'
        Unsigned = 'windows-x64-inno-unsigned'
        Prebuilt = 'windows-x64-inno-unsigned-prebuilt'
    }
    'arm64' = @{
        Signed = 'windows-arm64-inno-signed'
        Unsigned = 'windows-arm64-inno-unsigned'
        Prebuilt = 'windows-arm64-inno-unsigned-prebuilt'
    }
}
if (-not $WindowsInnoFreezeTargets.ContainsKey($TargetArchitecture)) {
    throw "No reviewed Windows Inno freeze target exists for $TargetArchitecture."
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$ReleaseDir = Join-Path $RepoRoot "build\windows\$($script:WindowsFlutterArchDirectory)\runner\$Configuration"
$OutputDir = Join-Path $RepoRoot "build\windows-installer"
$DependenciesDir = Join-Path $PSScriptRoot "dependencies"
$dependencyNames = if ($TargetArchitecture -ceq 'arm64') {
    @{
        VcRedist = 'VC_redist.arm64.exe'
        AmneziaMsi = 'amneziawg-arm64.msi'
        AmneziaHelper = 'amneziawg-arm64.exe'
        AwgTool = 'awg-arm64.exe'
        Wintun = 'wintun-arm64.dll'
        Xray = 'xray-arm64.exe'
    }
} else {
    @{
        VcRedist = 'VC_redist.x64.exe'
        AmneziaMsi = 'amneziawg-amd64.msi'
        AmneziaHelper = 'amneziawg.exe'
        AwgTool = 'awg.exe'
        Wintun = 'wintun.dll'
        Xray = 'xray.exe'
    }
}
$VcRedist = Join-Path $DependenciesDir $dependencyNames.VcRedist
$AmneziaWgMsi = Join-Path $DependenciesDir $dependencyNames.AmneziaMsi
$AmneziaWgExe = Join-Path $DependenciesDir $dependencyNames.AmneziaHelper
$AmneziaWgExeProvenance = "$AmneziaWgExe.provenance.json"
$AwgToolExe = Join-Path $DependenciesDir $dependencyNames.AwgTool
$WintunDll = Join-Path $DependenciesDir $dependencyNames.Wintun
$XrayExe = Join-Path $DependenciesDir $dependencyNames.Xray
$InnoScript = Join-Path $PSScriptRoot "winsvpn.iss"
$InnoSigningWrapper = Join-Path $RepoRoot "tools\windows_inno_sign.ps1"
$InnoCompilerCustodyVerifier = Join-Path $RepoRoot "tools\release_inno_toolchain_custody.py"
$InnoToolchainPin = Join-Path $RepoRoot "tools\inno-toolchain-pins.json"
$WindowsStandaloneVerifier = Join-Path $RepoRoot "tools\verify_windows_standalone_v3_artifact.py"
$StagedDependenciesDir = Join-Path $OutputDir "payload-stage"
$installerArchitectureSuffix = if ($TargetArchitecture -ceq 'arm64') { '-arm64' } else { '' }
$CanonicalInstallerName = if ($DistributionSurface -ceq 'partner-center') {
    "WinsVPN-PartnerCenter$installerArchitectureSuffix.exe"
} else {
    "WinsVPN-Setup$installerArchitectureSuffix.exe"
}
$CanonicalInstaller = Join-Path $OutputDir $CanonicalInstallerName
$CanonicalPayloadManifest = "$CanonicalInstaller.payload-manifest.json"
$script:IsccStageDir = $null
$script:CanonicalInstallerPublishedByThisRun = $false
$script:CanonicalManifestPublishedByThisRun = $false
$TimestampUrl = if ($env:WINS_WINDOWS_TIMESTAMP_URL) { ($env:WINS_WINDOWS_TIMESTAMP_URL + '').Trim() } else { 'http://timestamp.digicert.com' }
$ArtifactSigningTimestampUrl = 'http://timestamp.acs.microsoft.com'
$ApprovedTimestampUrls = @(
    'http://timestamp.acs.microsoft.com',
    'http://timestamp.digicert.com',
    'https://timestamp.digicert.com'
)
$script:AuthenticodeTimestampVerified = $false
$script:AuthenticodeLeafSha256 = $null
$BuildLockDir = Join-Path $RepoRoot ".dart_tool\winsvpn-release-build.lock"
$BuildLockOwnerFile = Join-Path $BuildLockDir "owner.txt"
$script:BuildLockAcquired = $false
# SINGLE SOURCE OF TRUTH: read every toolchain pin from
# tools/toolchain-pins.json at run time instead of a literal. A literal that
# happens to agree today is still a defect -- the next pin bump silently
# desynchronises this installer build from every other build. Fail loudly so a
# missing pin file or parser never selects an unreviewed toolchain silently.
function Read-WinsToolchainPin {
    param(
        [Parameter(Mandatory = $true)][string]$PinPath,
        [Parameter(Mandatory = $true)][string]$Key
    )
    $pin = Get-Content -Raw -LiteralPath $PinPath | ConvertFrom-Json -ErrorAction Stop
    $pointer = $pin
    foreach ($part in $Key.Split('.')) {
        $pointer = $pointer.$part
    }
    return [string]$pointer
}
$RequiredFlutterVersion = Read-WinsToolchainPin -PinPath (Join-Path $RepoRoot 'tools\toolchain-pins.json') -Key 'tools.flutter.version'
$RequiredFlutterRevision = Read-WinsToolchainPin -PinPath (Join-Path $RepoRoot 'tools\toolchain-pins.json') -Key 'tools.flutter.revision'
# Optional Authenticode leaf pin. When tools/toolchain-pins.json carries
# tools.windows_authenticode.leaf_sha256, every product signature verified by
# Assert-ProductSignature must come from exactly that leaf certificate. When
# the key is absent, the signer subject regex, Code Signing EKU, public chain,
# timestamp and signtool policy checks still apply, and the measured leaf is
# recorded in the preservation receipt.
function Get-WinsAuthenticodeLeafPin {
    param([Parameter(Mandatory = $true)][string]$PinPath)
    $value = Read-WinsToolchainPin -PinPath $PinPath -Key 'tools.windows_authenticode.leaf_sha256'
    if ([string]::IsNullOrEmpty($value)) {
        return $null
    }
    if ($value -cnotmatch '^[0-9a-f]{64}$') {
        throw 'tools.windows_authenticode.leaf_sha256 in tools/toolchain-pins.json must be 64 lowercase hex characters.'
    }
    return $value
}
function Get-WinsCertificateSha256 {
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($Certificate.RawData))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}
function Assert-WinsAuthenticodeLeafPin {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [AllowNull()][AllowEmptyString()][string]$ExpectedLeafSha256,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $leaf = Get-WinsCertificateSha256 -Certificate $Certificate
    if (-not [string]::IsNullOrEmpty($ExpectedLeafSha256) -and $leaf -cne $ExpectedLeafSha256) {
        throw "Authenticode leaf certificate of $Path does not match tools.windows_authenticode.leaf_sha256 (expected $ExpectedLeafSha256, actual $leaf)."
    }
    return $leaf
}
$WindowsAuthenticodeLeafPin = Get-WinsAuthenticodeLeafPin -PinPath (Join-Path $RepoRoot 'tools\toolchain-pins.json')
# Committed publisher identity, the same CN and O that
# tools/windows_cross_store_artifact_gate.py enforces at upload
# (AUTHENTICODE_LEAF_CN/AUTHENTICODE_LEAF_O). The environment subject regex
# and thumbprint still apply; this is an extra pin, not a replacement.
$WindowsAuthenticodePublisherName = "WIN'S VPN INC."
function Assert-WinsAuthenticodePublisherIdentity {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $flags = [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseNewLines -bor
        [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::DoNotUseQuotes
    $rdns = @($Certificate.SubjectName.Decode($flags) -split "`r?`n" | Where-Object { $_ -ne '' })
    $cn = @($rdns | Where-Object { $_.StartsWith('CN=', [StringComparison]::Ordinal) } | ForEach-Object { $_.Substring(3) })
    $org = @($rdns | Where-Object { $_.StartsWith('O=', [StringComparison]::Ordinal) } | ForEach-Object { $_.Substring(2) })
    # A control character inside an attribute value (for example a CN holding
    # a line break and a fake O=) would forge an extra decoded line. -cne is a
    # culture-aware compare that ignores zero-width, soft-hyphen and BOM
    # characters, so the names are compared ordinally.
    if ($Certificate.Subject -match '[\x00-\x1f\x7f]' -or
        $cn.Count -ne 1 -or -not [string]::Equals($cn[0], $WindowsAuthenticodePublisherName, [StringComparison]::Ordinal) -or
        $org.Count -ne 1 -or -not [string]::Equals($org[0], $WindowsAuthenticodePublisherName, [StringComparison]::Ordinal)) {
        throw "Authenticode signer of $Path is not the reviewed $WindowsAuthenticodePublisherName publisher: $($Certificate.Subject)"
    }
}
function Get-Winn3DescriptorPubkeyDefines {
    # PUBLIC key only, build-time --dart-define. Client: WINS_ prefix, hub: no prefix (cross is silent no-op).
    # Reads WINS_WINN3_DESCRIPTOR_PUBKEY_G1..G3 and *_FILE. Validates base64 of 32 bytes. Never hardcodes a value.
    $defines = @()
    foreach ($slot in @('G1','G2','G3')) {
        $var = "WINS_WINN3_DESCRIPTOR_PUBKEY_$slot"
        $fileVar = "${var}_FILE"
        $raw = $null
        $value = $null
        $filePath = [Environment]::GetEnvironmentVariable($fileVar)
        $envValue = [Environment]::GetEnvironmentVariable($var)
        if ($filePath -and $filePath.Trim()) {
            $filePath = $filePath.Trim()
            if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) { throw "Winn3 descriptor pubkey file missing: $fileVar=$filePath" }
            if ((Get-Item -LiteralPath $filePath).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Winn3 descriptor pubkey file is symbolic: $filePath" }
            $raw = (Get-Content -LiteralPath $filePath -Raw -ErrorAction Stop).Trim()
            $raw = $raw -replace '\r','' -replace '\n',''
            $raw = $raw.Trim()
            if ($raw.StartsWith('--dart-define=') -or $raw.StartsWith('WINS_WINN3_DESCRIPTOR_PUBKEY_') -or $raw.StartsWith('WINN3_DESCRIPTOR_PUBKEY_')) { throw "Refusing $fileVar that looks like a dart-define or hub key name: $($raw.Substring(0,[Math]::Min(60,$raw.Length)))" }
            $value = $raw
        } elseif ($envValue -and $envValue.Trim()) {
            $raw = $envValue
            if ($raw.StartsWith('--dart-define=')) { throw "Refusing $var that already contains --dart-define (pass just the base64 value)" }
            if ($raw.StartsWith('WINN3_DESCRIPTOR_PUBKEY_')) { throw "Refusing $var that looks like a hub key name (hub is WINN3_ without WINS_ prefix): $($raw.Substring(0,[Math]::Min(60,$raw.Length)))" }
            $value = $raw.Trim()
        } else { continue }
        if (-not $value) { continue }
        try {
            $decoded = [Convert]::FromBase64String($value)
            if ($decoded.Length -ne 32) { throw "bad length $($decoded.Length)" }
        } catch { throw "Winn3 descriptor pubkey $var is not valid base64 of 32 bytes: $($value.Substring(0,[Math]::Min(20,$value.Length)))..." }
        $defines += "--dart-define=$var=$value"
    }
    return $defines
}
function Write-Winn3DescriptorPubkeyStatus {
    param([string[]]$Defines)
    $count = if ($Defines) { $Defines.Count } else { 0 }
    if ($count -gt 0) {
        Write-Host "Winn3 descriptor verification ring: PRESENT ($count slot(s) compiled in; standalone v3 can verify descriptors)"
    } else {
        Write-Warning "Winn3 descriptor verification ring ABSENT - no WINS_WINN3_DESCRIPTOR_PUBKEY_G1..G3 supplied."
        Write-Warning "This build will report descriptor-no-verification-keys-compiled and standalone is unavailable."
        Write-Warning "Set WINS_WINN3_DESCRIPTOR_PUBKEY_G1 to the base64 raw-32-byte pubkey from tools/winn3_sign_descriptor.py pubkey --key <pem> --kid g1 to produce a complete build."
        Write-Warning "The PUBLIC key is safe to pass as --dart-define; never pass a private key."
        throw "Standalone v3 Windows release requires WINS_WINN3_DESCRIPTOR_PUBKEY_G1, G2, or G3."
    }
}
$script:ResolvedReleaseInputIndex = $null
$script:FlutterIdentity = $null
$script:FlutterCommand = $null
$script:WindowsBuildReceiptDirectory = $null
$script:WindowsBuildBeginReceipt = $null
$script:WindowsBuildReceipt = $null
$script:InnoCompilerIdentity = $null
$script:ReviewedIsccPath = $null
$DependencyFreezeTool = Join-Path $RepoRoot 'tools\release_dependency_freeze.py'

$AmneziaWgVersion = "3.1.0"
$AmneziaWgUrl = "https://github.com/amnezia-vpn/amneziawg-windows-client/releases/download/$AmneziaWgVersion/amneziawg-$($script:WindowsAwgGoArch)-$AmneziaWgVersion.msi"
$AmneziaWgSha256 = @{
    'x64' = 'a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b'
    'arm64' = '3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa'
}[$TargetArchitecture]
# M-11: the maintenance helper is rebuilt from the reviewed 3.1.0 source
# commit with the pinned Go 1.27.1 archive by
# tools/build_windows_amneziawg_client.ps1. The upstream MSI still supplies
# awg.exe/wintun.dll, but must never overwrite this rebuilt helper.
$UpstreamAmneziaWgExeSha256 = @{
    'x64' = 'ba446f6e1a4093e43a65d6ff45f4b8c7b6485dc419327eedaa1a218549740e3a'
    'arm64' = '25fa81103152699bf416f394059b40d447001c3d0dea5ef889a9426f315e4c0a'
}[$TargetArchitecture]
# Unsigned product maintenance-helper pin, mirrored from
# tools/build_windows_amneziawg_client.ps1 ($architecturePins.ProductHelperSha256).
# The arm64 value is the two-clean-build digest measured on the Windows 11
# ARM64 build VM (2026-10-15, two producer runs, four builds, byte-identical);
# the helper's own hash is never the expectation.
$AmneziaWgHelperUnsignedSha256 = @{
    'x64' = '12525f397d957659354df03ac1e9568170d8842aa8fa0d16942d8a59d7307d41'
    'arm64' = '0e88c6d049d0905b5aa1e53c63ffa24f2760701be4b28eee5975b381393ef73f'
}[$TargetArchitecture]
$script:AmneziaWgHelperReviewedSha256 = $null
$AmneziaWgSourceCommit = "ca5dd3b983bd19c335ab095ccd21fc2f804ec968"
$AmneziaWgSourceGoModSha256 = "ad578b6a2107ae4c1bab214c8057e89608ac516d6e381675c3d9441ccc4da70a"
$AmneziaWgSourceGoSumSha256 = "268286d6183ec93c39e5295e73e660d9920481c66ecff8331ab64fa082230723"
$AmneziaWgSourceBuildBatSha256 = "c501fd947d08a4bfdb29f65a9f06ced004779be7a90a125f703c1c5a5130350b"
$AmneziaWgPatchedBuildBatSha256 = "79bd946166bc6e87d4ff1602889557590703fc8a64737fbfe7f0b64ebda431d7"
$AmneziaWgBuildPatchSha256 = "a5ad25797aadc29f0e7aa0bf91e6197ce57c48cb845194a18ae7c2dbbebadcbd"
$AmneziaWgWindowsLibraryVersion = "v3.1.20260814"
$AmneziaWgWindowsLibraryCommit = "e90531d15802cb976773f3b63443bc281f738ca3"
$AmneziaWgEngineVersion = "v3.1.20260828"
$AmneziaWgEngineCommit = "b5928efb6ca19f0153958460c3d141f04abc5c2e"
$WindowsAwgEngineGoModSha256 = "e447b49513d1fc452fa7cb2f87b15c40b88ab6f0656e22b4eccdfe238fa623e4"
$WindowsAwgEngineGoSumSha256 = "fbec66bcbe1cf3603eb5b0f6c7c2041aea6749dc8c1d36b91726a7a479df4719"
$AmneziaWgGoVersion = "1.27.1"
$AmneziaWgGoArchiveSha256 = "a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d"
$AwgToolExeSha256 = @{
    'x64' = '272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12'
    'arm64' = '3106950ce9f0b93eb4c3f7975cbf44af41623ffeed630f19909730cd16d36e43'
}[$TargetArchitecture]
$WintunDllSha256 = @{
    'x64' = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
    'arm64' = 'f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80'
}[$TargetArchitecture]
# M-1 remediation: xray.exe is no longer downloaded from the upstream release
# archive at build time. That archive's xray.exe embeds go1.26.1, which
# predates several fixed stdlib CVEs (see docs/RELEASE_ENGINE_BINARY_REFRESH.md).
# The vendored dependencies\xray.exe below is instead a from-source rebuild of
# this exact same reviewed Xray-core commit, produced with the pinned,
# independently-verified Go 1.27.1 toolchain by tools/build_xray_engine.sh
# (run: bash tools/build_xray_engine.sh windows-amd64 <out>, on any macOS or
# Linux host -- CGO is not required for this target). $XrayVersion/
# $XrayArchiveUrl/$XrayArchiveSha256 are kept only as provenance: they record
# exactly which upstream release's source this rebuild is derived from.
$XrayVersion = "26.9.30"
$XrayArchiveUrl = "https://github.com/XTLS/Xray-core/releases/download/v$XrayVersion/Xray-windows-64.zip"
$XrayArchiveSha256 = "b17a619343c11b89d8faf36278298856749b15c52277d875d32051b33dcda617"
$XrayExeSha256 = @{
    'x64' = 'fffbe5dd92fe13cfc6ab72dead66ddd92c09b2bb27a85592e8e6f4ec27ee1224'
    'arm64' = 'c6edaa0e535b81d8c4c4a25378e6717b4406a8a0d72b751f4d0a1f171817e7af'
}[$TargetArchitecture]
$VcRedistVersion = "14.44.35211.0"
$VcRedistSha256 = @{
    'x64' = 'cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b'
    'arm64' = '5139e1440c3a20b92153a4db561c069a0175aaf76c276c3e5b6f56099edcf4b0'
}[$TargetArchitecture]
$VcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.$TargetArchitecture.exe"
# Vendor origin for owner review only. The producer never downloads VC_redist
# or the AmneziaWG MSI; those elevated embedded bytes must already exist as
# regular single-link files bound to the in-script SHA-256 pins.
$script:WinsVcRedistPublisherPattern = 'CN=Microsoft Corporation'
$script:WinsAmneziaWgMsiPublisherPattern = 'O=Privacy Technologies OU'
$script:WinsVcRedistOriginalFileName = $dependencyNames.VcRedist
$script:WinsVcRedistProductName = if ($TargetArchitecture -ceq 'arm64') {
    'Microsoft Visual C++ 2022 Redistributable (Arm64) - 14.44.35211'
} else {
    'Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.44.35211'
}
$script:WinsVcRedistMaxBytes = 104857600
$script:WinsAmneziaWgMsiMaxBytes = 16777216
$script:WinsVcRedistIdentity = $null
$script:WinsAmneziaWgMsiIdentity = $null
# Exclusion identities, not release pins. winsvpn.iss recursively packs SourceDir,
# so renamed or nested withdrawn Mullvad SYS/CAT/INF bytes must be rejected by
# reviewed hash before signed packaging. Cover x64 and arm64 packages present
# under installer/windows/dependencies.
$affectedSplitTunnelDriverNames = @(
    'mullvad-split-tunnel.sys',
    'mullvad-split-tunnel.cat',
    'mullvad-split-tunnel.inf'
)
$ForbiddenInnoMullvadPayloadLeafPrefixes = @('mullvad-split-tunnel')
$ForbiddenInnoMullvadPayloadExtensions = @('.sys', '.cat', '.inf')
$ForbiddenInnoMullvadPayloadSha256 = @(
    '10cf25bbcfe51fd663a1fec88a98e9b858f3a579589bb2ec496b66e4fdd1b201', # x64 .sys
    'c599926a0327d7ae06b534f4cd039db30392e1897bb9d03e4fec3631744a4e6d', # x64 .cat
    '3dd5905e5fb98d61a942a33e8c9a5ba07c3a2de1e4f319e1fec3e54df6591608', # x64 .inf
    '6af8b3bfe5aa095d5276187558c7c7d3a3e0c174b34406cd6c4b3f8e6ffa6534', # arm64 .sys
    'c3d27636739ebaa7dde369d113347de83e3e2173b8a512bb8863d11b148de7ce', # arm64 .cat
    '0bfdb044e40535dabbeb3620b655c1563714b3a6f3231d3492c972c6e8dea6f1'  # arm64 .inf
)
$VersionLine = Select-String -LiteralPath (Join-Path $RepoRoot "pubspec.yaml") -Pattern '^version:\s*([^+\s]+)\+(\d+)\s*$' | Select-Object -First 1
if (-not $VersionLine) {
    throw "Unable to read version: <semver>+<build> from pubspec.yaml."
}
$AppVersion = $VersionLine.Matches[0].Groups[1].Value
$BuildNumber = $VersionLine.Matches[0].Groups[2].Value
$WindowsVersionParts = @($AppVersion.Split('.') + $BuildNumber)
if ($WindowsVersionParts.Count -ne 4 -or @($WindowsVersionParts | Where-Object {
    $_ -notmatch '^\d+$' -or [uint32]$_ -gt 65535
}).Count -ne 0) {
    throw "Windows version resources require pubspec.yaml version major.minor.patch+build with four 0-65535 integer components."
}
$WindowsProductVersion = $AppVersion
$WindowsFileVersion = "$AppVersion.$BuildNumber"
$WindowsObfuscationTargetIds = @{
    'x64/website' = 'windows-x64-installer'
    'x64/partner-center' = 'windows-x64-partner-center'
    'arm64/website' = 'windows-arm64-installer'
    'arm64/partner-center' = 'windows-arm64-partner-center'
}
$WindowsObfuscationTargetId = $WindowsObfuscationTargetIds["$TargetArchitecture/$DistributionSurface"]
if ([string]::IsNullOrEmpty($WindowsObfuscationTargetId)) {
    throw "Unsupported Windows obfuscation target ${TargetArchitecture}/${DistributionSurface}."
}
$WindowsSymbolDir = Join-Path $RepoRoot ".artifacts\private-release-symbols\windows\$TargetArchitecture\$AppVersion+$BuildNumber"
$WindowsObfuscationManifest = Join-Path $WindowsSymbolDir "manifest-$DistributionSurface.json"
$WindowsAotObfuscationManifest = Join-Path $WindowsSymbolDir "aot-manifest.json"
$ObfuscationContract = Join-Path $RepoRoot "tools\release_obfuscation_contract.py"
$CustodyTool = Join-Path $RepoRoot "tools\private_release_symbol_custody.py"
$CustodyAclTool = Join-Path $RepoRoot "tools\private_symbol_custody.ps1"
$PrivateSymbolsRoot = Join-Path $RepoRoot ".artifacts\private-release-symbols"
$WindowsAotArtifact = Join-Path $ReleaseDir "data\app.so"
$TunnelServiceArtifact = Join-Path $ReleaseDir "wins_vpn_tunnel_service.exe"
$AwgEngineArtifact = Join-Path $ReleaseDir "winsvpn_awg_engine.exe"
$AwgEngineProvenance = "$AwgEngineArtifact.provenance.json"
$AwgEngineBuilder = Join-Path $RepoRoot "tools\build_windows_awg_engine.ps1"
$NativeHostStageDir = Join-Path $ReleaseDir "NativeMessagingHost"
$NativeHostArtifact = Join-Path $NativeHostStageDir "wins_bridge_host.exe"
$NativeHostBuilder = Join-Path $RepoRoot "tools\native_messaging\build_native_host.ps1"
$NativeHostManifestRenderer = Join-Path $RepoRoot "tools\native_messaging\render_host_manifest.py"
$NativeHostLayout = Join-Path $RepoRoot "tools\native_messaging\native_host_layout.py"
# Winn Protocol v3 datapath engine. windows/runner/windows_tunnel_backend.cpp
# resolves it at runtime as winn-datapath.exe beside the running module (see
# FindWinnDatapathExecutable() there), built from
# winn_protocol_experimental/cmd/winn-datapath. The Windows installer is an
# artifact consumer only: it takes the engine from a signed Winn release
# (-WinnReleaseDir) after tools\winn_release.py verifies the manifest signature
# and every artifact digest, and stages it as $ReleaseDir\winn-datapath.exe.
# Off Windows, tools/build_windows_winn_engine.sh --release DIR stages the same
# verified bytes into build/windows/winn3/{x64,arm64}/ for the ZIP and MSI
# packagers:
#   build/windows/winn3/x64/winn-datapath.exe
#   build/windows/winn3/arm64/winn-datapath.exe
# There is no in-installer Go or bash fallback.
$WinnEngineArtifact = Join-Path $ReleaseDir "winn-datapath.exe"
$WinnReleaseTool = Join-Path $RepoRoot "tools\winn_release.py"
$Winn3ArtifactProvenanceTool = Join-Path $RepoRoot "tools\windows_winn3_artifact_provenance.py"
# Reviewed source hash of the compiled-role checker above.
$Winn3ArtifactProvenanceToolSha256 = '99c244b84ecd1fadb0d1566e2298c122cf44fb0f2c1e3473c0cb1310719f99ae'
$script:Winn3PairCustody = $null
# Winn Protocol v3 Windows TUN RELAY -- the second half of the v3 carrier, and
# a DIFFERENT BINARY from $WinnEngineArtifact above.
#
# windows/runner/winn3_supervisor.cpp needs BOTH, and resolves each by an exact
# name beside the running module with no fallback search path:
#
#   FindWinn3RelayExecutable()    -> winsvpn_winn3_engine.exe  (this one)
#   FindWinn3DatapathExecutable() -> winn-datapath.exe         ($WinnEngineArtifact)
#
# Until now only the datapath half was ever staged, so every installed Windows
# build reached StartWinn3Tunnel, failed the relay lookup, and returned the
# refusal "This server uses Winn Protocol v3, but the v3 tun relay is not
# installed beside this application" (winn3_supervisor.cpp:963-967). That
# refusal is correct behaviour for a missing relay -- the defect was that the
# relay was missing from every build, which is a packaging gap, not a runtime
# one.
#
# THE NAME IS LOAD-BEARING. windows/awg_engine's winsvpn_awg_engine.exe owns
# the adapter "winsvpn" and emits ALREADY-ENCRYPTED datagrams; this relay owns
# the adapter "winsvpn3" and moves RAW INNER PACKETS with no cryptography at
# all. Staging the wrong image under this name is the one mistake on this
# boundary that puts cleartext on the wire, which is why the supervisor has no
# fallback and why the relay has its own name, combined provenance receipt, and
# role-specific consumer gate.
#
# The relay comes from the SAME signed Winn release as the datapath (targets
# winn3-relay-windows-{amd64,arm64}), staged under the exact unsuffixed name
# the supervisor resolves, and admitted only when its PE machine matches and
# its compiled Go build information names the relay module, so no other image
# can be staged under this name. The off-Windows staging copies are:
#   build/windows/winn3/x64/winsvpn_winn3_engine.exe
#   build/windows/winn3/arm64/winsvpn_winn3_engine.exe
$Winn3RelayArtifact = Join-Path $ReleaseDir "winsvpn_winn3_engine.exe"

. $CustodyAclTool

function Enter-ReleaseBuildLock {
    $lockParent = Split-Path -Parent $BuildLockDir
    [void][IO.Directory]::CreateDirectory($lockParent)
    $directoryCreated = $false
    $temporaryOwnerFile = Join-Path $BuildLockDir `
        ("owner.$PID." + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        New-Item -ItemType Directory -Path $BuildLockDir -ErrorAction Stop | Out-Null
        $directoryCreated = $true
        $ownerText = @(
            "platform=windows"
            "pid=$PID"
            "started_utc=$([DateTime]::UtcNow.ToString('o'))"
        ) -join "`n"
        [IO.File]::WriteAllText(
            $temporaryOwnerFile,
            $ownerText + "`n",
            [Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $temporaryOwnerFile `
            -Destination $BuildLockOwnerFile -ErrorAction Stop
        $script:BuildLockAcquired = $true
    } catch {
        $initializationError = $_.Exception.Message
        if ($directoryCreated) {
            Remove-Item -LiteralPath $BuildLockDir -Recurse -Force `
                -ErrorAction SilentlyContinue
            throw "Unable to initialize the Windows release build lock transactionally: $initializationError"
        }
        $owner = "owner metadata is not available"
        if (Test-Path -LiteralPath $BuildLockOwnerFile -PathType Leaf) {
            $owner = ((Get-Content -LiteralPath $BuildLockOwnerFile -Raw -ErrorAction SilentlyContinue) + "").Trim()
            if ([string]::IsNullOrWhiteSpace($owner)) { $owner = "owner metadata is not available" }
        }
        throw "Another Windows/WSL release build owns $BuildLockDir. $owner. Wait for it to finish; never delete an active lock."
    }
}

function Exit-ReleaseBuildLock {
    if (-not $script:BuildLockAcquired) { return }
    $releasedLockDir = "$BuildLockDir.released.$PID.$([guid]::NewGuid().ToString('N'))"
    Move-Item -LiteralPath $BuildLockDir -Destination $releasedLockDir `
        -ErrorAction Stop
    $script:BuildLockAcquired = $false
    Remove-Item -LiteralPath $releasedLockDir -Recurse -Force `
        -ErrorAction SilentlyContinue
}

function Resolve-ReleaseInputIndex {
    if ([string]::IsNullOrWhiteSpace($ReleaseInputIndex)) {
        throw 'Every Windows installer build requires -ReleaseInputIndex or WINS_RELEASE_INPUT_INDEX.'
    }
    $absolute = [IO.Path]::GetFullPath($ReleaseInputIndex)
    $artifactsRoot = [IO.Path]::GetFullPath((Join-Path $RepoRoot '.artifacts'))
    $artifactsPrefix = $artifactsRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if ([IO.Path]::GetFileName($absolute) -cne 'RELEASE_INPUT_INDEX.json' -or
        -not $absolute.StartsWith($artifactsPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $absolute -PathType Leaf)) {
        throw 'ReleaseInputIndex must name an existing repository .artifacts RELEASE_INPUT_INDEX.json.'
    }
    return $absolute
}

# The dependency-freeze worker runs only on the macOS release host. In
# remote-attested mode every direct controller call becomes
# tools/release_remote_attestation_check.py (verify-inputs: the shipped index,
# manifests and every manifest file against the digests the Mac recorded;
# record-run: REMOTE_RUN.json next to REMOTE_INPUT.json for finish-build on the
# Mac, which validates the copied-back installer bytes against the begin record).
function Test-WindowsRemoteAttested {
    return -not [string]::IsNullOrWhiteSpace($RemoteAttestationInput)
}

function Get-WindowsRemoteAttestationInput {
    $absolute = [IO.Path]::GetFullPath($RemoteAttestationInput)
    if ([IO.Path]::GetFileName($absolute) -cne 'REMOTE_INPUT.json' -or
        -not (Test-Path -LiteralPath $absolute -PathType Leaf) -or
        ((Get-Item -LiteralPath $absolute -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint)) {
        throw 'RemoteAttestationInput must name a regular REMOTE_INPUT.json.'
    }
    if ($WinsReleaseDependencyIsolatedStage) {
        throw 'Remote-attested builds never run as a witnessed isolated stage.'
    }
    return $absolute
}
# The exact secret scan loads the authenticated inventory through descriptor-relative
# open and stat, which Windows does not have. A remote-attested Windows build hands
# the scan to finish-build on the macOS release host (tools/release_remote_build.py),
# which scans the copied-back installer with the real inventory and refuses the receipt
# on any hit or scan failure. Any other Windows build gets no deferral and fails at the
# scan, as before.
function Get-WindowsSecretScanDeferralArguments {
    if (Test-WindowsRemoteAttested) {
        return @('--defer-secret-scan-to-release-host', (Get-WindowsRemoteAttestationInput))
    }
    return @()
}

function Invoke-WindowsRemoteAttestationCheck {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        $pythonCommand = Get-Command python -ErrorAction Stop
    }
    & $pythonCommand.Source -I (Join-Path $RepoRoot 'tools\release_remote_attestation_check.py') `
        @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Remote attestation check $($Arguments[0]) failed."
    }
}

function Assert-ReleaseInputIndexUnchanged {
    if ([string]::IsNullOrWhiteSpace($script:ResolvedReleaseInputIndex)) {
        throw 'The Windows release input index was not resolved.'
    }
    if (Test-WindowsRemoteAttested) {
        Invoke-WindowsRemoteAttestationCheck -Arguments @(
            'verify-inputs', '--repo', $RepoRoot.Path,
            '--input', (Get-WindowsRemoteAttestationInput),
            '--index', $script:ResolvedReleaseInputIndex
        )
        return
    }
    $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        $pythonCommand = Get-Command python -ErrorAction Stop
    }
    & $pythonCommand.Source (Join-Path $RepoRoot 'tools\release_dependency_freeze.py') `
        verify-index --repo $RepoRoot.Path --index $script:ResolvedReleaseInputIndex `
        --platform windows | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'The immutable Windows release input index no longer matches the source tree.'
    }
}

function Assert-EmbeddedEngineRuntimeFreshness {
    if ($StandaloneWinn3Release) {
        return
    }
    # M-1: fail before any Windows installer is accepted if a committed
    # Xray/AmneziaWG binary embeds a Go runtime with known-fixed stdlib CVEs.
    $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        $pythonCommand = Get-Command python -ErrorAction Stop
    }
    & $pythonCommand.Source (Join-Path $RepoRoot 'tools\verify_embedded_engine_runtime_versions.py') | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Embedded engine (Xray/AmneziaWG) Go runtime freshness check failed before build.'
    }
}

function Assert-ReviewedFlutterToolchain {
    $flutterCommand = Get-Command flutter.bat -ErrorAction SilentlyContinue
    if (-not $flutterCommand) {
        $flutterCommand = Get-Command flutter -ErrorAction Stop
    }
    $machineJson = (& $flutterCommand.Source --version --machine 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($machineJson)) {
        throw 'Flutter did not report its machine-readable release identity.'
    }
    try {
        $identity = $machineJson | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw 'Flutter returned invalid machine-readable release identity JSON.'
    }
    if ([string]$identity.frameworkVersion -cne $RequiredFlutterVersion -or
        [string]$identity.frameworkRevision -cne $RequiredFlutterRevision) {
        throw "Windows release builds require reviewed Flutter $RequiredFlutterVersion ($RequiredFlutterRevision)."
    }
    $script:FlutterIdentity = [ordered]@{
        framework_version = [string]$identity.frameworkVersion
        framework_revision = [string]$identity.frameworkRevision
        engine_revision = [string]$identity.engineRevision
        dart_sdk_version = [string]$identity.dartSdkVersion
    }
    # Resolve once, then invoke this exact executable for dependency resolution
    # and compilation. An alias/function named `flutter` must not be able to
    # build different bytes from the toolchain whose identity was reviewed.
    $script:FlutterCommand = $flutterCommand.Source
}

function Resolve-WindowsBuildReceiptDirectory {
    $requested = $BuildReceiptDirectory
    $usingDefault = [string]::IsNullOrWhiteSpace($requested)
    if ($usingDefault) {
        $indexHash = (Get-FileHash -LiteralPath $script:ResolvedReleaseInputIndex `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        # Release-manifest directories are immutable eight-file control sets.
        # Keep per-build receipts in a separate index-hash namespace so a
        # successful build never adds mutable run state to the freeze set.
        $receiptNamespace = Join-Path $RepoRoot (
            '.artifacts\release-build-receipts\windows\' + $indexHash
        )
        $requested = Join-Path $receiptNamespace (
            'windows-build-' +
            [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') + '-' +
            [guid]::NewGuid().ToString('N')
        )
    } elseif (-not [IO.Path]::IsPathRooted($requested)) {
        $requested = Join-Path $RepoRoot $requested
    }

    $absolute = [IO.Path]::GetFullPath($requested)
    $repoRootPath = [IO.Path]::GetFullPath($RepoRoot.Path).TrimEnd('\', '/')
    $artifactsRoot = [IO.Path]::GetFullPath(
        (Join-Path $RepoRoot '.artifacts')
    ).TrimEnd('\', '/')
    $artifactsPrefix = $artifactsRoot + [IO.Path]::DirectorySeparatorChar
    if (-not $absolute.StartsWith(
            $artifactsPrefix,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'Windows build receipts must stay under the repository .artifacts directory.'
    }
    if (Test-Path -LiteralPath $absolute) {
        throw "Windows build receipt directory must be a new immutable path: $absolute"
    }

    $relative = $absolute.Substring($repoRootPath.Length).TrimStart('\', '/')
    $cursor = $repoRootPath
    foreach ($part in ($relative -split '[\\/]')) {
        $cursor = Join-Path $cursor $part
        if (-not (Test-Path -LiteralPath $cursor)) { break }
        if ((Get-Item -LiteralPath $cursor -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint) {
            throw "Windows build receipt directory traverses a reparse point: $cursor"
        }
    }
    $parent = Split-Path -Parent $absolute
    if ($usingDefault -and -not (Test-Path -LiteralPath $parent)) {
        $namespaceRelative = $parent.Substring($repoRootPath.Length).TrimStart('\', '/')
        $namespaceCursor = $repoRootPath
        foreach ($part in ($namespaceRelative -split '[\\/]')) {
            $namespaceCursor = Join-Path $namespaceCursor $part
            if (Test-Path -LiteralPath $namespaceCursor) {
                $namespaceItem = Get-Item -LiteralPath $namespaceCursor -Force
                if (-not $namespaceItem.PSIsContainer -or
                    ($namespaceItem.Attributes -band
                        [IO.FileAttributes]::ReparsePoint)) {
                    throw "Windows build receipt namespace is not a regular directory: $namespaceCursor"
                }
            } else {
                New-Item -ItemType Directory -Path $namespaceCursor `
                    -ErrorAction Stop | Out-Null
            }
        }
    }
    if (-not (Test-Path -LiteralPath $parent -PathType Container) -or
        ((Get-Item -LiteralPath $parent -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint)) {
        throw 'Windows build receipt parent must be an existing regular directory.'
    }
    return $absolute
}

function Initialize-WindowsBuildReceipt {
    $directory = Resolve-WindowsBuildReceiptDirectory
    New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
    $script:WindowsBuildReceiptDirectory = $directory
    $script:WindowsBuildBeginReceipt = Join-Path $directory `
        'WINDOWS_BUILD_BEGIN.json'
    $script:WindowsBuildReceipt = Join-Path $directory `
        'WINDOWS_BUILD_RECEIPT.json'
    if (Test-WindowsRemoteAttested) {
        # The macOS release host already ran begin-build for this remote run.
        Assert-ReleaseInputIndexUnchanged
        return
    }

    $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        $pythonCommand = Get-Command python -ErrorAction Stop
    }
    & $pythonCommand.Source $DependencyFreezeTool begin-build `
        --repo $RepoRoot.Path --index $script:ResolvedReleaseInputIndex `
        --platform windows --output $script:WindowsBuildBeginReceipt | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw 'Windows formal build-begin receipt creation failed.'
    }
}

function Complete-WindowsBuildReceipt {
    if ([string]::IsNullOrWhiteSpace($script:WindowsBuildBeginReceipt) -or
        [string]::IsNullOrWhiteSpace($script:WindowsBuildReceipt)) {
        throw 'Windows formal build receipt state was not initialized.'
    }
    $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        $pythonCommand = Get-Command python -ErrorAction Stop
    }
    $toolchainName = if ($SkipFlutterBuild) {
        'Flutter prebuilt local output'
    } else {
        'Flutter'
    }
    $toolchainVersion = if ($script:FlutterIdentity) {
        [string]$script:FlutterIdentity.framework_version
    } else {
        $RequiredFlutterVersion
    }
    $toolchainRevision = if ($script:FlutterIdentity) {
        [string]$script:FlutterIdentity.framework_revision
    } else {
        $RequiredFlutterRevision
    }
    $innoFreeze = $WindowsInnoFreezeTargets[$TargetArchitecture]
    $target = if ($SkipFlutterBuild) {
        $innoFreeze.Prebuilt
    } elseif ($mustSign) {
        $innoFreeze.Signed
    } else {
        $innoFreeze.Unsigned
    }
    if (Test-WindowsRemoteAttested) {
        $remoteInput = Get-WindowsRemoteAttestationInput
        Invoke-WindowsRemoteAttestationCheck -Arguments @(
            'record-run', '--repo', $RepoRoot.Path, '--input', $remoteInput,
            '--artifact', $CanonicalInstaller,
            '--toolchain-name', $toolchainName,
            '--toolchain-version', $toolchainVersion,
            '--toolchain-revision', $toolchainRevision,
            '--target', $target,
            '--output', (Join-Path (Split-Path -Parent $remoteInput) 'REMOTE_RUN.json'),
            '--signing', $(if ($mustSign) { 'producer' } else { 'unsigned' }),
            '--secret-scan', 'deferred-to-release-host'
        )
        return
    }

    & $pythonCommand.Source $DependencyFreezeTool finish-build `
        --repo $RepoRoot.Path --index $script:ResolvedReleaseInputIndex `
        --platform windows --begin $script:WindowsBuildBeginReceipt `
        --artifact $CanonicalInstaller `
        --producer 'installer/windows/build_installer.ps1' `
        --toolchain-name $toolchainName `
        --toolchain-version $toolchainVersion `
        --toolchain-revision $toolchainRevision `
        --target $target --output $script:WindowsBuildReceipt | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw 'Windows formal exact-installer build receipt creation failed.'
    }
    & $pythonCommand.Source $DependencyFreezeTool verify-receipt `
        --repo $RepoRoot.Path --index $script:ResolvedReleaseInputIndex `
        --platform windows --receipt $script:WindowsBuildReceipt `
        --artifact $CanonicalInstaller | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw 'Windows formal exact-installer build receipt verification failed.'
    }
}

function Invoke-BuildLockSelfTest {
    Enter-ReleaseBuildLock
    try {
        $duplicateCreated = $false
        try {
            New-Item -ItemType Directory -Path $BuildLockDir -ErrorAction Stop | Out-Null
            $duplicateCreated = $true
        } catch {
            $duplicateCreated = $false
        }
        if ($duplicateCreated) {
            throw "Build-lock self-test acquired the same lock twice."
        }
    } finally {
        Exit-ReleaseBuildLock
    }
    if (Test-Path -LiteralPath $BuildLockDir) {
        throw "Build-lock self-test left a stale lock directory."
    }
    Write-Host "WINDOWS RELEASE BUILD LOCK SELF-TEST: PASS" -ForegroundColor Green
}

# BEGIN-WINDOWS-INNO-COMPILER-CUSTODY
# Automatic package-manager installation is forbidden.
# Exact Inno Setup 7.1.0 compiler custody. Release builds bind ISCC.exe from
# the reviewed Program Files\Inno Setup 7 install tree to
# tools/inno-toolchain-pins.json. PATH, INNO_SETUP_ISCC, WinGet, registry, and
# Inno Setup 6 discovery are not accepted. Unmeasured (null) compiler hash,
# VERSIONINFO, Authenticode leaf, or install-tree pins fail closed.
function Get-WinsInnoPythonCommand {
    $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        $pythonCommand = Get-Command python -ErrorAction Stop
    }
    return $pythonCommand
}

function ConvertFrom-WinsInnoCustodyRecords {
    param([Parameter(Mandatory = $true)][object]$Lines)

    $record = [ordered]@{}
    foreach ($line in @($Lines)) {
        $text = [string]$line
        if ($text -notmatch '^(architecture|filename|sha256|size|pe_machine|output_architectures|version|product_version_string|publisher_name|authenticode_leaf_sha256|authenticode_leaf_serial_hex|install_tree_sha256|trusted_root_leaf)\|(.+)$') {
            continue
        }
        $record[$Matches[1]] = $Matches[2]
    }
    return $record
}

function Resolve-ReviewedIsccPath {
    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    if ([string]::IsNullOrWhiteSpace($programFiles)) {
        throw 'Windows Inno Setup compiler custody requires the native Program Files root.'
    }
    $expected = [IO.Path]::GetFullPath((Join-Path $programFiles 'Inno Setup 7\ISCC.exe'))
    if (-not [IO.Path]::IsPathRooted($expected) -or
        [IO.Path]::GetFileName($expected) -cne 'ISCC.exe' -or
        [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($expected)) -cne 'Inno Setup 7') {
        throw 'untrusted installation root'
    }
    if (-not (Test-Path -LiteralPath $expected -PathType Leaf)) {
        throw ('Inno Setup 7.1.0 ISCC.exe was not found at ' +
            $expected +
            '. PATH, INNO_SETUP_ISCC, and package-manager discovery are not accepted.')
    }
    $item = Get-Item -LiteralPath $expected -Force
    if ($item.PSIsContainer) {
        throw 'untrusted installation root'
    }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'untrusted installation root'
    }
    return $expected
}

function Get-WinsInnoCompilerIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$IsccPath,
        [Parameter(Mandatory = $true)][ValidateSet('x64', 'arm64')][string]$Architecture
    )

    if (-not (Test-Path -LiteralPath $InnoToolchainPin -PathType Leaf)) {
        throw 'tools/inno-toolchain-pins.json is absent.'
    }
    $pinItem = Get-Item -LiteralPath $InnoToolchainPin -Force
    if ($pinItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Inno toolchain pin traverses a reparse point.'
    }
    $pinHashBefore = (Get-FileHash -LiteralPath $InnoToolchainPin -Algorithm SHA256).Hash.ToLowerInvariant()
    $pythonCommand = Get-WinsInnoPythonCommand
    $previousErrorActionPreference = $ErrorActionPreference
    $output = $null
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $pythonCommand.Source $InnoCompilerCustodyVerifier `
            verify-compiler --arch $Architecture --path $IsccPath --pin $InnoToolchainPin
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($LASTEXITCODE -ne 0) {
        $detail = (($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine)
        if ([string]::IsNullOrWhiteSpace($detail)) {
            $detail = 'Inno Setup compiler pin verification failed.'
        }
        throw $detail
    }
    $pinHashAfter = (Get-FileHash -LiteralPath $InnoToolchainPin -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($pinHashBefore -cne $pinHashAfter -or $pinHashAfter -cnotmatch '^[0-9a-f]{64}$' -or $pinHashAfter -ceq ('0' * 64)) {
        throw 'Inno toolchain pin mutated while the compiler was verified.'
    }
    $parsed = ConvertFrom-WinsInnoCustodyRecords -Lines $output
    $required = @(
        'architecture', 'filename', 'sha256', 'size', 'pe_machine',
        'output_architectures', 'version', 'product_version_string',
        'publisher_name', 'authenticode_leaf_sha256', 'authenticode_leaf_serial_hex',
        'install_tree_sha256', 'trusted_root_leaf'
    )
    foreach ($key in $required) {
        if (-not ($parsed.Keys -contains $key) -or [string]::IsNullOrWhiteSpace([string]$parsed[$key])) {
            throw "Inno Setup compiler identity omitted $key."
        }
    }
    $sha256 = [string]$parsed['sha256']
    $treeSha256 = [string]$parsed['install_tree_sha256']
    $leafSha256 = [string]$parsed['authenticode_leaf_sha256']
    $serial = [string]$parsed['authenticode_leaf_serial_hex']
    $sizeText = [string]$parsed['size']
    if ($sha256 -cnotmatch '^[0-9a-f]{64}$' -or $sha256 -ceq ('0' * 64)) {
        throw 'compiler SHA-256 mismatch'
    }
    if ($treeSha256 -cnotmatch '^[0-9a-f]{64}$' -or $treeSha256 -ceq ('0' * 64)) {
        throw 'compiler install-tree SHA-256 mismatch'
    }
    if ($sha256 -ceq $treeSha256) {
        throw 'compiler file and install-tree hashes must be independently derived'
    }
    if ($leafSha256 -cnotmatch '^[0-9a-f]{64}$' -or $leafSha256 -ceq ('0' * 64)) {
        throw 'Authenticode publisher mismatch'
    }
    if ($serial -cnotmatch '^[0-9a-f]+$') {
        throw 'Authenticode leaf serial is malformed'
    }
    $size = 0L
    if (-not [int64]::TryParse($sizeText, [ref]$size) -or $size -lt 1) {
        throw 'compiler size mismatch'
    }
    $outputArchitectures = @(@([string]$parsed['output_architectures']).Split(',') | Where-Object { $_ })
    if ($outputArchitectures.Count -ne 1 -or [string]$outputArchitectures[0] -cne $Architecture) {
        throw "compiler output architecture mismatch: $Architecture"
    }
    # The official 7.1.0 ISCC.exe carries VERSIONINFO ProductVersion 0.0.0.0,
    # so the reviewed string is the pinned one. The verifier already compared
    # it; it is re-read here from pin bytes whose hash must equal the hash
    # bound around that verification.
    $pinBytes = [IO.File]::ReadAllBytes($InnoToolchainPin)
    $pinBytesHash = -join ([Security.Cryptography.SHA256]::Create().ComputeHash($pinBytes) |
        ForEach-Object { $_.ToString('x2') })
    if ($pinBytesHash -cne $pinHashAfter) {
        throw 'Inno toolchain pin mutated while the compiler was verified.'
    }
    $pinnedProductVersion = [string](([Text.Encoding]::UTF8.GetString($pinBytes) |
        ConvertFrom-Json).compilers."windows_$Architecture".product_version_string)
    if ([string]::IsNullOrWhiteSpace($pinnedProductVersion)) {
        throw 'Inno Setup compiler product_version_string pin is absent.'
    }
    if ([string]$parsed['architecture'] -cne $Architecture -or
        [string]$parsed['filename'] -cne 'ISCC.exe' -or
        [string]$parsed['pe_machine'] -cne 'x64' -or
        [string]$parsed['version'] -cne '7.1.0' -or
        [string]$parsed['product_version_string'] -cne $pinnedProductVersion -or
        [string]$parsed['publisher_name'] -cne 'Pyrsys B.V.' -or
        $leafSha256 -cne '4efd84e6f1091b19321231743b9aa86482effd6d0bea9f7a44db6211154616f3' -or
        $serial -cne 'b208315c09c02ef1550e0c8d127cf499' -or
        [string]$parsed['trusted_root_leaf'] -cne 'Inno Setup 7') {
        throw 'Inno Setup compiler identity does not match the reviewed 7.1.0 pin.'
    }
    return [ordered]@{
        contract = 'winsvpn-inno-compiler-receipt-v1'
        product = 'Inno Setup'
        vendor = 'JRSoftware'
        version = '7.1.0'
        filename = 'ISCC.exe'
        architecture = $Architecture
        pe_machine = 'x64'
        output_architectures = @(, [string]$Architecture)
        sha256 = $sha256
        size = $size
        product_version_string = $pinnedProductVersion
        publisher_name = 'Pyrsys B.V.'
        authenticode_leaf_sha256 = $leafSha256
        authenticode_leaf_serial_hex = $serial
        install_tree_sha256 = $treeSha256
        trusted_root_leaf = 'Inno Setup 7'
        pin_path = 'tools/inno-toolchain-pins.json'
        pin_sha256 = $pinHashAfter
    }
}

function Assert-WinsInnoCompilerIdentityMatch {
    param(
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)]$Actual
    )

    foreach ($key in @(
        'contract', 'product', 'vendor', 'version', 'filename', 'architecture',
        'pe_machine', 'sha256', 'size', 'product_version_string', 'publisher_name',
        'authenticode_leaf_sha256', 'authenticode_leaf_serial_hex',
        'install_tree_sha256', 'trusted_root_leaf', 'pin_path', 'pin_sha256'
    )) {
        if ([string]$Expected[$key] -cne [string]$Actual[$key]) {
            throw "Inno Setup compiler identity mutated: $key"
        }
    }
    $expectedArch = @($Expected['output_architectures'] | ForEach-Object { [string]$_ })
    $actualArch = @($Actual['output_architectures'] | ForEach-Object { [string]$_ })
    if ($expectedArch.Count -ne $actualArch.Count) {
        throw 'Inno Setup compiler identity mutated: output_architectures'
    }
    for ($index = 0; $index -lt $expectedArch.Count; $index++) {
        if ($expectedArch[$index] -cne $actualArch[$index]) {
            throw 'Inno Setup compiler identity mutated: output_architectures'
        }
    }
}

function Bind-WinsInnoCompilerCustody {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('x64', 'arm64')][string]$Architecture
    )

    $iscc = Resolve-ReviewedIsccPath
    $identity = Get-WinsInnoCompilerIdentity -IsccPath $iscc -Architecture $Architecture
    return [ordered]@{
        Path = $iscc
        Identity = $identity
    }
}

function Write-WinsInnoCompilerReceipt {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Identity
    )

    $json = ConvertTo-Json -InputObject $Identity -Depth 6 -Compress:$false
    Write-AtomicNewUtf8File -Path $Path -Value ($json + "`n")
}

function Find-Iscc {
    return (Bind-WinsInnoCompilerCustody -Architecture $TargetArchitecture).Path
}
# END-WINDOWS-INNO-COMPILER-CUSTODY

function Find-Python {
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python) { return @($python.Source) }

    $pyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($pyLauncher) { return @($pyLauncher.Source, "-3") }

    throw "Python was not found. Install Python 3 so release image metadata can be verified before packaging."
}

function Get-ReleasePython {
    $requirements = Join-Path $RepoRoot "tools\release-python-requirements.txt"
    if (-not (Test-Path -LiteralPath $requirements -PathType Leaf)) {
        throw "Pinned release Python requirements were not found at $requirements."
    }
    $pythonCommand = @(Find-Python)
    $pythonArgs = @()
    if ($pythonCommand.Count -gt 1) {
        $pythonArgs = $pythonCommand[1..($pythonCommand.Count - 1)]
    }
    $venvDir = Join-Path $RepoRoot ".artifacts\release-python"
    $venvPython = Join-Path $venvDir "Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
        & $pythonCommand[0] @pythonArgs -m venv $venvDir
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
            throw "Could not create the isolated release Python environment at $venvDir."
        }
    }
    $previousErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $venvPython -c "import PIL; assert PIL.__version__ == '12.3.0'" *> $null
        $dependencyProbeExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorPreference
    }
    if ($dependencyProbeExit -ne 0) {
        & $venvPython -m pip install --disable-pip-version-check --no-input `
            --only-binary=:all: --require-hashes --requirement $requirements | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Pinned release Python dependencies could not be installed."
        }
    }
    return $venvPython
}

function Add-DartPluginRegistrantVirtualPackage {
    # Flutter otherwise passes the generated registrant to the frontend as an
    # absolute file URI. Dart preserves that URI in app.so even for an
    # obfuscated/stripped AOT build, disclosing the release builder's user-home
    # path. Bind the already-generated .dart_tool location to a package URI in
    # package_config.json, then build with --no-pub so Flutter cannot overwrite
    # the binding between validation and compilation.
    $packageConfigPath = Join-Path $RepoRoot '.dart_tool\package_config.json'
    if (-not (Test-Path -LiteralPath $packageConfigPath -PathType Leaf)) {
        throw 'Flutter package_config.json is missing after dependency resolution.'
    }
    $document = Get-Content -LiteralPath $packageConfigPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    if ([int]$document.configVersion -ne 2 -or $null -eq $document.packages) {
        throw 'Flutter package_config.json has an unsupported schema.'
    }
    $packageName = 'winsvpn_generated_plugin_registrant'
    if (@($document.packages | Where-Object { [string]$_.name -ceq $packageName }).Count -ne 0) {
        throw 'Synthetic Dart plugin-registrant package name already exists.'
    }
    $document.packages += [pscustomobject][ordered]@{
        name = $packageName
        rootUri = 'flutter_build/'
        packageUri = ''
    }
    $json = $document | ConvertTo-Json -Depth 20
    [IO.File]::WriteAllText(
        $packageConfigPath, $json + "`n", [Text.UTF8Encoding]::new($false)
    )
    $verified = Get-Content -LiteralPath $packageConfigPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $matches = @($verified.packages | Where-Object {
        [string]$_.name -ceq $packageName -and
        [string]$_.rootUri -ceq 'flutter_build/' -and
        [string]$_.packageUri -ceq ''
    })
    if ($matches.Count -ne 1) {
        throw 'Synthetic Dart plugin-registrant package binding did not persist.'
    }
}

function Assert-ReleaseImageMetadataClean {
    $stripScript = Join-Path $RepoRoot "tools\strip_image_metadata.py"
    if (-not (Test-Path -LiteralPath $stripScript)) {
        throw "Image metadata stripping script was not found at $stripScript."
    }

    $releasePython = Get-ReleasePython
    & $releasePython $stripScript --check `
        (Join-Path $RepoRoot "assets") `
        (Join-Path $RepoRoot "web")
    if ($LASTEXITCODE -ne 0) {
        throw "Release images contain metadata. Normalize them deliberately before freezing shared inputs; the installer build never mutates release sources."
    }
}

function Save-Download {
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [Parameter(Mandatory=$true)][string]$OutFile
    )
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $OutFile `
        -MaximumRedirection 8 -TimeoutSec 180 -ErrorAction Stop `
        -Headers @{ "User-Agent" = "wins-vpn-installer-build" }
}

function Assert-PinnedVcRedist {
    param(
        [string]$Path = $VcRedist
    )
    if (-not (Test-FileSha256 -Path $Path -ExpectedSha256 $VcRedistSha256)) {
        throw "Pinned VC++ Redistributable $VcRedistVersion is missing or has the wrong SHA-256. The mutable Microsoft download must be reviewed and its identity pin updated deliberately before release."
    }
    Assert-AuthenticodeSigner -Path $Path -SignerPattern "CN=Microsoft Corporation"
    $versionInfo = (Get-Item -LiteralPath $Path).VersionInfo
    $fileVersion = [string]$versionInfo.FileVersion
    $expectedOriginalFilename = $dependencyNames.VcRedist
    $expectedProductName = if ($TargetArchitecture -ceq 'arm64') {
        'Microsoft Visual C++ 2022 Redistributable (Arm64) - 14.44.35211'
    } else {
        'Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.44.35211'
    }
    if ($fileVersion -ne $VcRedistVersion -or
        [string]$versionInfo.ProductVersion -ne $VcRedistVersion -or
        [string]$versionInfo.OriginalFilename -cne $expectedOriginalFilename -or
        [string]$versionInfo.CompanyName -ne 'Microsoft Corporation' -or
        [string]$versionInfo.ProductName -cne $expectedProductName) {
        throw "Pinned VC++ Redistributable metadata does not match the reviewed $VcRedistVersion $TargetArchitecture package."
    }
    return [version]$fileVersion
}

function Get-ApprovedSignToolRoots {
    # H-4: release signing must resolve SignTool only under the fixed
    # Windows SDK install root, never PATH or an arbitrary environment
    # variable. Build the list defensively so a host missing this
    # environment variable (e.g. non-Windows) fails closed with an empty
    # root set instead of a null-argument crash.
    $roots = [System.Collections.Generic.List[string]]::new()
    if (${env:ProgramFiles(x86)}) {
        $roots.Add((Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"))
    }
    return @($roots)
}

function Get-ApprovedArtifactSigningDlibRoots {
    # H-4: same rationale as Get-ApprovedSignToolRoots, for the Azure
    # Artifact Signing client DLIB. LocalAppData is deliberately excluded:
    # it is user-writable and must never be trusted for release signing.
    $roots = [System.Collections.Generic.List[string]]::new()
    foreach ($arch in (Get-WindowsSdkToolArchitectures)) {
        if (${env:ProgramFiles(x86)}) {
            $roots.Add((Join-Path ${env:ProgramFiles(x86)} "Microsoft\ArtifactSigningClientTools\bin\$arch"))
        }
        if ($env:ProgramFiles) {
            $roots.Add((Join-Path $env:ProgramFiles "Microsoft\ArtifactSigningClientTools\bin\$arch"))
        }
    }
    return @($roots)
}

function Assert-MicrosoftReleaseTool {
    # H-4: a release-signing tool is trustworthy only if it resolves inside
    # one of the fixed, admin-writable-only roots the caller supplies AND
    # carries a currently valid Microsoft Authenticode signature. Both
    # conditions are required: an approved root alone does not prove the
    # bytes at that path are genuine, and a valid signature alone does not
    # prove the path was not attacker-influenced (e.g. via PATH ordering).
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string[]]$AllowedRoots
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Release signing tool does not exist: $Path"
    }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $separator = [IO.Path]::DirectorySeparatorChar
    $withinApprovedRoot = @($AllowedRoots | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_) -and
        $resolved.StartsWith(
            ($_.TrimEnd('\', '/') + $separator),
            [System.StringComparison]::OrdinalIgnoreCase
        )
    }).Count -gt 0
    if (-not $withinApprovedRoot) {
        throw "Release signing tool is outside every approved root: $resolved"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $resolved
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
        throw "Release signing tool lacks the required valid Microsoft signature: $resolved"
    }
    return $resolved
}

function Get-WindowsSdkToolArchitectures {
    # Prefer the installer target, then x64. Native ARM64 hosts still have an
    # x64 SDK layout that runs under emulation; x64 hosts must not prefer arm64.
    $arches = [System.Collections.Generic.List[string]]::new()
    if ($script:WindowsFlutterArchDirectory) {
        $arches.Add($script:WindowsFlutterArchDirectory)
    }
    if ($arches -notcontains 'x64') {
        $arches.Add('x64')
    }
    return @($arches)
}

function Find-SignToolUnderApprovedRoots {
    param([string[]]$Roots = (Get-ApprovedSignToolRoots))
    $sdkArches = Get-WindowsSdkToolArchitectures
    foreach ($kitRoot in $Roots) {
        if (-not (Test-Path -LiteralPath $kitRoot)) { continue }
        $versionDirs = @(Get-ChildItem -LiteralPath $kitRoot -Directory -ErrorAction SilentlyContinue |
            Sort-Object { try { [version]$_.Name } catch { [version]"0.0" } } -Descending)
        foreach ($arch in $sdkArches) {
            $candidate = $versionDirs |
                ForEach-Object { Join-Path $_.FullName "$arch\signtool.exe" } |
                Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
                Select-Object -First 1
            if ($candidate) { return $candidate }
        }
    }
    return $null
}

function Find-SignTool {
    # H-4: -RequireApprovedMicrosoftSignature is the release-signing path
    # (the only path that ever executes SignTool with the signer's
    # authority). It ignores WINDOWS_SIGNTOOL and PATH entirely and demands
    # an Authenticode-verified binary under an approved SDK root. The
    # default (no switch) behavior is unchanged for the pre-existing
    # verify-only caller (pinned third-party driver kernel-signature
    # verification), which is not a publishing action and intentionally
    # keeps its wider search so local/dev builds are not broken.
    param([switch]$RequireApprovedMicrosoftSignature)

    if ($RequireApprovedMicrosoftSignature) {
        $approvedRoots = Get-ApprovedSignToolRoots
        $candidate = Find-SignToolUnderApprovedRoots -Roots $approvedRoots
        if (-not $candidate) { return $null }
        return Assert-MicrosoftReleaseTool -Path $candidate -AllowedRoots $approvedRoots
    }

    if ($env:WINDOWS_SIGNTOOL) {
        if (Test-Path -LiteralPath $env:WINDOWS_SIGNTOOL -PathType Leaf) {
            return (Resolve-Path -LiteralPath $env:WINDOWS_SIGNTOOL).Path
        }
        throw "WINDOWS_SIGNTOOL does not exist: $($env:WINDOWS_SIGNTOOL)"
    }

    $fromPath = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }

    $candidate = Find-SignToolUnderApprovedRoots
    if ($candidate) { return $candidate }
    return $null
}

function Find-ArtifactSigningDlib {
    # H-4: every caller of this function is already inside the release
    # ($mustSign) signing path, so resolution is unconditionally strict:
    # only the fixed Program Files roots are trusted, and the resolved DLIB
    # must carry a valid Microsoft signature. WINS_WINDOWS_ARTIFACT_SIGNING_DLIB
    # and the LocalAppData candidate are intentionally no longer honored.
    $approvedRoots = Get-ApprovedArtifactSigningDlibRoots
    foreach ($root in $approvedRoots) {
        $candidate = Join-Path $root "Azure.CodeSigning.Dlib.dll"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return Assert-MicrosoftReleaseTool -Path $candidate -AllowedRoots $approvedRoots
        }
    }
    return $null
}

function Resolve-ArtifactSigningMetadataPath {
    param([Parameter(Mandatory=$true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "WINS_WINDOWS_ARTIFACT_SIGNING_METADATA does not exist: $Path"
    }
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $repoPrefix = $RepoRoot.Path.TrimEnd('\') + '\'
    if ($resolved.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Artifact Signing metadata must be stored outside the repository tree."
    }
    if ((Get-Item -LiteralPath $resolved).Length -gt 16384) {
        throw "Artifact Signing metadata is unexpectedly large."
    }
    try {
        $metadata = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    } catch {
        throw "Artifact Signing metadata is not valid JSON: $($_.Exception.Message)"
    }
    $allowedFields = @('Endpoint', 'CodeSigningAccountName', 'CertificateProfileName', 'CorrelationId', 'ExcludeCredentials')
    foreach ($field in $metadata.PSObject.Properties.Name) {
        if ($field -notin $allowedFields) {
            throw "Artifact Signing metadata field '$field' is forbidden. Authentication tokens and secrets must come from Azure identity providers, not metadata JSON."
        }
    }
    foreach ($field in @('Endpoint', 'CodeSigningAccountName', 'CertificateProfileName')) {
        if ([string]::IsNullOrWhiteSpace(($metadata.$field + ''))) {
            throw "Artifact Signing metadata requires $field."
        }
    }
    $endpoint = $null
    if (-not [Uri]::TryCreate(($metadata.Endpoint + ''), [UriKind]::Absolute, [ref]$endpoint) -or
        $endpoint.Scheme -ne 'https' -or
        $endpoint.Host -notmatch '^[a-z0-9-]+\.codesigning\.azure\.net$' -or
        -not [string]::IsNullOrEmpty($endpoint.Query) -or
        -not [string]::IsNullOrEmpty($endpoint.Fragment)) {
        throw "Artifact Signing Endpoint must be a regional HTTPS *.codesigning.azure.net URI with no query or fragment."
    }
    return $resolved
}

function Assert-CodeSigningCertificate {
    param(
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$true)][string]$SignerPattern,
        [Parameter(Mandatory=$true)][string]$SourceLabel
    )

    if (-not $Certificate.HasPrivateKey) {
        throw "$SourceLabel does not contain an accessible private key."
    }
    $now = [DateTime]::UtcNow
    if ($now -lt $Certificate.NotBefore.ToUniversalTime() -or $now -gt $Certificate.NotAfter.ToUniversalTime()) {
        throw "$SourceLabel is not currently valid."
    }
    if ($Certificate.Subject -eq $Certificate.Issuer) {
        throw "A self-signed certificate is forbidden for production distribution: $SourceLabel"
    }
    if ($Certificate.Subject -notmatch $SignerPattern) {
        throw "$SourceLabel subject does not match WINS_WINDOWS_SIGNER_SUBJECT_REGEX."
    }
    $eku = $Certificate.Extensions |
        Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
        Select-Object -First 1
    $hasCodeSigningEku = $false
    if ($eku -and $eku.EnhancedKeyUsages) {
        $hasCodeSigningEku = @(
            $eku.EnhancedKeyUsages |
                Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.3' }
        ).Count -eq 1
    }
    if (-not $hasCodeSigningEku) {
        throw "$SourceLabel is not an Authenticode Code Signing certificate. TLS/server certificates are forbidden."
    }
}

function Get-CodeSigningSelector {
    # M-3: PFX-file-plus-command-line-password signing is disabled
    # unconditionally in this function. Every caller of
    # Get-CodeSigningSelector is already inside the release ($mustSign)
    # signing path, so there is no legitimate way to reach this code with a
    # non-publishing intent; fail loud and immediately rather than silently
    # falling back to a weaker signer. Certificate-store selection by
    # thumbprint (below) never places a secret on the command line.
    param([Parameter(Mandatory=$true)][string]$SignerPattern)

    if (-not [string]::IsNullOrWhiteSpace(($env:WINS_WINDOWS_SIGN_PFX + '')) -or
        -not [string]::IsNullOrWhiteSpace(($env:WINS_WINDOWS_SIGN_PFX_PASSWORD + ''))) {
        throw "PFX command-line signing (WINS_WINDOWS_SIGN_PFX/WINS_WINDOWS_SIGN_PFX_PASSWORD) is disabled for a signed release. Configure WINS_WINDOWS_ARTIFACT_SIGNING_METADATA or WINS_WINDOWS_SIGN_CERT_SHA1 instead."
    }
    $thumbprint = (($env:WINS_WINDOWS_SIGN_CERT_SHA1 + "") -replace '\s', '').ToUpperInvariant()
    if (-not $thumbprint) {
        return @()
    }
    if ($thumbprint -notmatch '^[A-F0-9]{40}$') {
        throw "WINS_WINDOWS_SIGN_CERT_SHA1 must be a 40-character certificate thumbprint."
    }
    $storeScope = if ($env:WINS_WINDOWS_SIGN_CERT_STORE) { $env:WINS_WINDOWS_SIGN_CERT_STORE } else { "CurrentUser" }
    if ($storeScope -notin @("CurrentUser", "LocalMachine")) {
        throw "WINS_WINDOWS_SIGN_CERT_STORE must be CurrentUser or LocalMachine."
    }
    $location = [System.Security.Cryptography.X509Certificates.StoreLocation]::$storeScope
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new("My", $location)
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $matches = @($store.Certificates | Where-Object { $_.Thumbprint -eq $thumbprint })
        if ($matches.Count -ne 1) {
            throw "WINS_WINDOWS_SIGN_CERT_SHA1 must resolve to exactly one certificate in $storeScope\\My."
        }
        Assert-CodeSigningCertificate -Certificate $matches[0] `
            -SignerPattern $SignerPattern -SourceLabel "WINS_WINDOWS_SIGN_CERT_SHA1"
        Assert-MicrosoftTrustedRootProgramChain -Certificate $matches[0] `
            -Path "WINS_WINDOWS_SIGN_CERT_SHA1"
    } finally {
        $store.Close()
    }
    $selector = @("/s", "My", "/sha1", $thumbprint)
    if ($storeScope -eq "LocalMachine") { $selector = @("/sm") + $selector }
    return $selector
}

function Assert-MicrosoftTrustedRootProgramChain {
    param(
        [Parameter(Mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$true)][string]$Path
    )
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreNotTimeValid
        [void]$chain.Build($Certificate)
        if ($chain.ChainElements.Count -lt 2) { throw "The signer lacks a public CA chain: $Path" }
        $rootThumbprint = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Thumbprint
        $trusted = $false
        $installedRoot = $false
        foreach ($location in @(
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        )) {
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('AuthRoot', $location)
            try {
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                if (@($store.Certificates | Where-Object { $_.Thumbprint -eq $rootThumbprint }).Count -gt 0) { $trusted = $true }
            } finally { $store.Close() }
            $rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', $location)
            try {
                $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                if (@($rootStore.Certificates | Where-Object { $_.Thumbprint -eq $rootThumbprint }).Count -gt 0) { $installedRoot = $true }
            } finally { $rootStore.Close() }
        }
        $pinnedMicrosoftRoots = @(
            '3B1EFD3A66EA28B16697394703A72CA340A05BD5', # Microsoft Root CA 2010
            '8F43288AD272F3103B6FB1428485EA3014C0BCFE'  # Microsoft Root CA 2011
        )
        if (-not $trusted -and -not ($installedRoot -and $rootThumbprint -in $pinnedMicrosoftRoots)) {
            throw "The signer does not terminate in AuthRoot or an explicitly pinned Microsoft system root: $Path"
        }
    } finally { $chain.Dispose() }
}

function Assert-ProductSignature {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$SignerPattern,
        [Parameter(Mandatory=$true)][string]$SignTool
    )
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $subject = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { "" }
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $subject -notmatch $SignerPattern) {
        throw "Product signature verification failed for $Path. Status=$($signature.Status); signer=$subject"
    }
    if ($signature.SignerCertificate.Subject -eq $signature.SignerCertificate.Issuer) {
        throw "A self-signed certificate is forbidden for production distribution: $Path"
    }
    Assert-MicrosoftTrustedRootProgramChain -Certificate $signature.SignerCertificate -Path $Path
    Assert-WinsAuthenticodePublisherIdentity -Certificate $signature.SignerCertificate -Path $Path
    $leafSha256 = Assert-WinsAuthenticodeLeafPin -Certificate $signature.SignerCertificate `
        -ExpectedLeafSha256 $WindowsAuthenticodeLeafPin -Path $Path
    if (-not $signature.TimeStamperCertificate) {
        throw "The Authenticode signature on $Path is missing a trusted timestamp."
    }
    $verifyOutput = & $SignTool verify /pa /all /v /tw $Path 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or
        $verifyOutput -notmatch 'Successfully verified' -or
        $verifyOutput -notmatch '(Timestamp Verified by:|The signature is timestamped|Signing time:)') {
        throw "SignTool policy/timestamp verification failed for $Path. $verifyOutput"
    }
    $script:AuthenticodeTimestampVerified = $true
    $script:AuthenticodeLeafSha256 = $leafSha256
}

function Assert-SafeSigningToken {
    param(
        [Parameter(Mandatory=$true)][string]$Value,
        [Parameter(Mandatory=$true)][string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "$Label is empty." }
    if ($Value -match '[\x00-\x1f\x7f"`|*?<>]') {
        throw "$Label contains a forbidden path or argument character."
    }
}

function Assert-ApprovedTimestampUrl {
    param([Parameter(Mandatory=$true)][string]$Value)
    Assert-SafeSigningToken -Value $Value -Label 'timestamp URL'
    if ($Value -notin $ApprovedTimestampUrls) {
        throw 'The signing timestamp URL must be an exact approved Microsoft/DigiCert RFC 3161 endpoint.'
    }
}

function Assert-SignToolArgumentList {
    param([Parameter(Mandatory=$true)][string[]]$Arguments)
    if ($Arguments.Count -lt 2) { throw 'SignTool argument list is incomplete.' }
    foreach ($argument in $Arguments) {
        if ([string]::IsNullOrWhiteSpace($argument)) { throw 'Empty SignTool argument is forbidden.' }
        if ($argument -match '[\x00-\x1f\x7f]') { throw 'SignTool argument contains a control character.' }
    }
    foreach ($forbidden in @('/as', '/f', '/p', '/ac', '/a')) {
        if ($Arguments -contains $forbidden) {
            throw "SignTool argument $forbidden is forbidden for release signing."
        }
    }
}

function New-ProductSignArgumentList {
    param(
        [Parameter(Mandatory=$true)][string]$Timestamp,
        [Parameter(Mandatory=$true)][string[]]$SignerArguments,
        [Parameter(Mandatory=$true)][string]$Target
    )
    Assert-ApprovedTimestampUrl -Value $Timestamp
    $signArgs = [System.Collections.Generic.List[string]]::new()
    foreach ($part in @('sign', '/v', '/fd', 'SHA256', '/tr', $Timestamp, '/td', 'SHA256', '/d', "Win's VPN")) {
        $signArgs.Add($part)
    }
    foreach ($part in @($SignerArguments)) { $signArgs.Add([string]$part) }
    $signArgs.Add($Target)
    $list = @($signArgs)
    Assert-SignToolArgumentList -Arguments $list
    if ($list[$list.Count - 1] -cne $Target) {
        throw 'SignTool target must be the final argument.'
    }
    return $list
}

function Invoke-ProductSigning {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string[]]$SigningArguments,
        [Parameter(Mandatory=$true)][string]$SigningTimestampUrl,
        [Parameter(Mandatory=$true)][string]$SignerPattern,
        [Parameter(Mandatory=$true)][string]$SignTool
    )
    $signArgs = New-ProductSignArgumentList -Timestamp $SigningTimestampUrl -SignerArguments @($SigningArguments) -Target $Path
    & $SignTool @signArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Authenticode signing failed for $Path."
    }
    Assert-ProductSignature -Path $Path -SignerPattern $SignerPattern -SignTool $SignTool
}

function Test-FileSha256 {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$ExpectedSha256
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.Equals(
        $ExpectedSha256,
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Get-VerifiedDownload {
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [Parameter(Mandatory=$true)][string]$OutFile,
        [Parameter(Mandatory=$true)][string]$ExpectedSha256,
        [scriptblock]$AdditionalValidation,
        [ValidateRange(1, 3)][int]$MaximumAttempts = 2
    )

    $parent = Split-Path -Parent $OutFile
    [void][IO.Directory]::CreateDirectory($parent)
    $cacheValid = Test-FileSha256 -Path $OutFile `
        -ExpectedSha256 $ExpectedSha256
    if ($cacheValid -and $AdditionalValidation) {
        try { & $AdditionalValidation $OutFile }
        catch { $cacheValid = $false }
    }
    if ($cacheValid) { return }
    if (Test-Path -LiteralPath $OutFile) {
        Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $OutFile) {
            throw "Rejected download cache could not be removed safely: $OutFile"
        }
    }

    $lastFailure = $null
    for ($attempt = 1; $attempt -le $MaximumAttempts; $attempt++) {
        $temporary = Join-Path $parent (
            '.' + [IO.Path]::GetFileName($OutFile) + '.download.' + $PID +
            '.' + [guid]::NewGuid().ToString('N') + '.tmp'
        )
        $published = $false
        try {
            Save-Download -Uri $Uri -OutFile $temporary
            if (-not (Test-FileSha256 -Path $temporary `
                    -ExpectedSha256 $ExpectedSha256)) {
                throw "SHA-256 verification failed for download attempt $attempt."
            }
            if ($AdditionalValidation) { & $AdditionalValidation $temporary }
            if (Test-Path -LiteralPath $OutFile) {
                throw "Verified download destination unexpectedly appeared: $OutFile"
            }
            # A same-directory rename is the publication boundary. Consumers
            # can observe either no cache entry or the completely validated
            # file, never a partial Invoke-WebRequest destination.
            [IO.File]::Move($temporary, $OutFile)
            $published = $true
            if (-not (Test-FileSha256 -Path $OutFile `
                    -ExpectedSha256 $ExpectedSha256)) {
                throw 'Published download changed after its atomic rename.'
            }
            if ($AdditionalValidation) { & $AdditionalValidation $OutFile }
            return
        } catch {
            $lastFailure = $_.Exception
            if ($published -and (Test-Path -LiteralPath $OutFile)) {
                Remove-Item -LiteralPath $OutFile -Force `
                    -ErrorAction SilentlyContinue
            }
            if ($attempt -eq $MaximumAttempts) {
                throw "Verified atomic download failed after $MaximumAttempts attempts for $Uri. $($lastFailure.Message)"
            }
        } finally {
            if (Test-Path -LiteralPath $temporary) {
                Remove-Item -LiteralPath $temporary -Force `
                    -ErrorAction SilentlyContinue
            }
        }
    }
}

function Write-AtomicNewUtf8File {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Value
    )
    $parent = Split-Path -Parent $Path
    [void][IO.Directory]::CreateDirectory($parent)
    $temporary = Join-Path $parent (
        '.' + [IO.Path]::GetFileName($Path) + '.publish.' + $PID + '.' +
        [guid]::NewGuid().ToString('N') + '.tmp'
    )
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
        $stream = [IO.File]::Open(
            $temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        if (Test-Path -LiteralPath $Path) {
            throw "Atomic publication target unexpectedly exists: $Path"
        }
        [IO.File]::Move($temporary, $Path)
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Quarantine-CanonicalInstallerOutputs {
    $targets = @($CanonicalInstaller, $CanonicalPayloadManifest)
    $existing = @($targets | Where-Object {
        Test-Path -LiteralPath $_ -PathType Leaf
    })
    if ($existing.Count -eq 0) { return }
    $quarantineParent = Join-Path $RepoRoot `
        '.artifacts\quarantine\windows-installer'
    [void][IO.Directory]::CreateDirectory($quarantineParent)
    $quarantine = Join-Path $quarantineParent (
        '.stale-output-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') +
        '-' + [guid]::NewGuid().ToString('N')
    )
    [void][IO.Directory]::CreateDirectory($quarantine)
    try {
        foreach ($path in $existing) {
            Move-Item -LiteralPath $path -Destination (
                Join-Path $quarantine ([IO.Path]::GetFileName($path))
            ) -ErrorAction Stop
        }
    } finally {
        # If quarantine itself is interrupted, exact canonical names are
        # still removed so a caller cannot mistake an older build for output
        # from this failed producer run.
        foreach ($path in $targets) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
    foreach ($path in $targets) {
        if (Test-Path -LiteralPath $path) {
            throw "Stale canonical Windows output survived quarantine: $path"
        }
    }
}

function Assert-AuthenticodeSigner {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$SignerPattern
    )
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $subject = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { "" }
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $subject -notmatch $SignerPattern) {
        throw "Authenticode verification failed for $Path. Status=$($signature.Status); signer=$subject"
    }
    if ($signature.SignerCertificate.Subject -eq $signature.SignerCertificate.Issuer) {
        throw "A self-signed third-party payload certificate is forbidden: $Path"
    }
    Assert-MicrosoftTrustedRootProgramChain -Certificate $signature.SignerCertificate -Path $Path
}

# BEGIN-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT
function Assert-WindowsAwgSchema2OwnerPublicationContract {
    param(
        [Parameter(Mandatory = $true)][string]$ProvenancePath,
        [Parameter(Mandatory = $true)][string]$HelperPath,
        [Parameter(Mandatory = $true)][string]$ExpectedUnsignedSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedTarget
    )
    if (-not (Test-Path -LiteralPath $ProvenancePath -PathType Leaf)) {
        throw 'The rebuilt AmneziaWG maintenance-helper provenance is missing.'
    }
    if (-not (Test-Path -LiteralPath $HelperPath -PathType Leaf)) {
        throw 'The rebuilt AmneziaWG maintenance helper is missing.'
    }
    if ($ExpectedUnsignedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'The reviewed unsigned AmneziaWG helper digest is not lowercase SHA-256.'
    }
    $raw = Get-Content -LiteralPath $ProvenancePath -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw 'The rebuilt AmneziaWG provenance is empty.'
    }
    # Every field the contract reads must appear once: PowerShell's JSON
    # parser keeps the last duplicate silently, so a repeated key could hide
    # a second value behind the reviewed one.
    foreach ($name in @(
            'schema_version', 'source_repository', 'source_version', 'source_commit',
            'source_go_mod_sha256', 'source_go_sum_sha256', 'source_build_bat_sha256',
            'patched_build_bat_sha256', 'build_patch_sha256', 'windows_library_repository',
            'windows_library_version', 'windows_library_commit', 'engine_module',
            'engine_version', 'engine_commit', 'go_version', 'go_archive', 'go_archive_sha256',
            'go_toolchain_policy', 'go_module_policy', 'go_checksum_database', 'target',
            'unsigned_artifact_sha256', 'expected_unsigned_artifact_sha256',
            'reproducibility_builds', 'reproducibility_status', 'module_build_info'
        )) {
        if ([regex]::Matches($raw, '"' + [regex]::Escape($name) + '"\s*:').Count -gt 1) {
            throw "Windows AWG helper provenance repeats JSON key $name."
        }
    }
    try { $evidence = $raw | ConvertFrom-Json }
    catch { throw "The rebuilt AmneziaWG provenance is invalid JSON: $($_.Exception.Message)" }
    if ($null -eq $evidence) {
        throw 'The rebuilt AmneziaWG provenance is not a JSON object.'
    }

    function Get-RequiredJsonProperty {
        param($Object, [string]$Name)
        $property = $Object.PSObject.Properties[$Name]
        if ($null -eq $property) {
            throw "Windows AWG schema-2 provenance is missing required field '$Name'."
        }
        return $property.Value
    }
    function Assert-JsonIntegerEquals {
        param($Value, [long]$Expected, [string]$Name)
        if ($null -eq $Value -or $Value -is [bool] -or $Value -is [string] -or
            $Value -is [double] -or $Value -is [float] -or $Value -is [decimal] -or
            ($Value -isnot [int] -and $Value -isnot [long])) {
            $actualType = if ($null -eq $Value) { 'null' } else { $Value.GetType().FullName }
            throw "Windows AWG field $Name must be JSON integer $Expected, not $actualType."
        }
        if ([int64]$Value -ne $Expected) {
            throw "Windows AWG field $Name must equal JSON integer $Expected."
        }
    }
    function Assert-JsonStringEquals {
        param($Value, [string]$Expected, [string]$Name)
        if ($Value -isnot [string]) {
            $actualType = if ($null -eq $Value) { 'null' } else { $Value.GetType().FullName }
            throw "Windows AWG field $Name must be a JSON string, not $actualType."
        }
        if ($Value -cne $Expected) {
            throw "Windows AWG field $Name is not the reviewed value."
        }
    }
    function Assert-JsonHexString {
        param($Value, [int]$Length, [string]$Name)
        if ($Value -isnot [string] -or $Value -cnotmatch ("^[0-9a-f]{$Length}$")) {
            throw "Windows AWG field $Name must be a lowercase $Length-hex JSON string."
        }
    }

    Assert-JsonIntegerEquals -Value (Get-RequiredJsonProperty $evidence 'schema_version') -Expected 2 -Name 'schema_version'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'source_repository') -Expected 'https://github.com/amnezia-vpn/amneziawg-windows-client.git' -Name 'source_repository'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'source_version') -Expected '3.1.0' -Name 'source_version'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'source_commit') -Expected 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968' -Name 'source_commit'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'source_go_mod_sha256') -Expected 'ad578b6a2107ae4c1bab214c8057e89608ac516d6e381675c3d9441ccc4da70a' -Name 'source_go_mod_sha256'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'source_go_sum_sha256') -Expected '268286d6183ec93c39e5295e73e660d9920481c66ecff8331ab64fa082230723' -Name 'source_go_sum_sha256'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'source_build_bat_sha256') -Expected 'c501fd947d08a4bfdb29f65a9f06ced004779be7a90a125f703c1c5a5130350b' -Name 'source_build_bat_sha256'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'patched_build_bat_sha256') -Expected '79bd946166bc6e87d4ff1602889557590703fc8a64737fbfe7f0b64ebda431d7' -Name 'patched_build_bat_sha256'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'build_patch_sha256') -Expected 'a5ad25797aadc29f0e7aa0bf91e6197ce57c48cb845194a18ae7c2dbbebadcbd' -Name 'build_patch_sha256'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'windows_library_repository') -Expected 'https://github.com/amnezia-vpn/amneziawg-windows.git' -Name 'windows_library_repository'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'windows_library_version') -Expected 'v3.1.20260814' -Name 'windows_library_version'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'windows_library_commit') -Expected 'e90531d15802cb976773f3b63443bc281f738ca3' -Name 'windows_library_commit'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'engine_module') -Expected 'github.com/amnezia-vpn/amneziawg-go/v3' -Name 'engine_module'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'engine_version') -Expected 'v3.1.20260828' -Name 'engine_version'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'engine_commit') -Expected 'b5928efb6ca19f0153958460c3d141f04abc5c2e' -Name 'engine_commit'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'go_version') -Expected '1.27.1' -Name 'go_version'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'go_archive') -Expected 'go1.27.1.windows-amd64.zip' -Name 'go_archive'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'go_archive_sha256') -Expected 'a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d' -Name 'go_archive_sha256'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'go_toolchain_policy') -Expected 'verified_archive_only' -Name 'go_toolchain_policy'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'go_module_policy') -Expected 'readonly' -Name 'go_module_policy'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'go_checksum_database') -Expected 'sum.golang.org' -Name 'go_checksum_database'
    Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'target') -Expected $ExpectedTarget -Name 'target'
    Assert-JsonHexString -Value (Get-RequiredJsonProperty $evidence 'unsigned_artifact_sha256') -Length 64 -Name 'unsigned_artifact_sha256'
    Assert-JsonHexString -Value (Get-RequiredJsonProperty $evidence 'expected_unsigned_artifact_sha256') -Length 64 -Name 'expected_unsigned_artifact_sha256'
    if ($ExpectedTarget -ceq 'windows-arm64') {
        Assert-JsonIntegerEquals -Value (Get-RequiredJsonProperty $evidence 'reproducibility_builds') -Expected 2 -Name 'reproducibility_builds'
        Assert-JsonStringEquals -Value (Get-RequiredJsonProperty $evidence 'reproducibility_status') -Expected 'two_clean_builds_byte_identical' -Name 'reproducibility_status'
    }
    $unsignedDigest = [string](Get-RequiredJsonProperty $evidence 'unsigned_artifact_sha256')
    $expectedDigest = [string](Get-RequiredJsonProperty $evidence 'expected_unsigned_artifact_sha256')
    $actualHelper = (Get-FileHash -LiteralPath $HelperPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($unsignedDigest -cne $expectedDigest -or $unsignedDigest -cne $ExpectedUnsignedSha256 -or $actualHelper -cne $ExpectedUnsignedSha256) {
        throw 'Windows AWG schema-2 provenance unsigned digest does not agree with the helper bytes and reviewed pin.'
    }
    $moduleBuildInfo = Get-RequiredJsonProperty $evidence 'module_build_info'
    if ($moduleBuildInfo -is [string]) {
        throw 'Windows AWG field module_build_info must be a JSON array of strings, not a string.'
    }
    $moduleLines = @($moduleBuildInfo)
    if ($moduleLines.Count -lt 1) {
        throw 'Windows AWG field module_build_info must be a non-empty JSON array of strings.'
    }
    foreach ($line in $moduleLines) {
        if ($line -isnot [string]) {
            throw 'Windows AWG field module_build_info must contain only JSON strings.'
        }
    }
    $moduleText = [string]::Join("`n", $moduleLines)
    if ($moduleText -notmatch '(?m)^\s*dep\s+github\.com/amnezia-vpn/amneziawg-go/v3\s+v3\.1\.20260828\s+' -or
        $moduleText -notmatch '(?m)^\s*dep\s+github\.com/amnezia-vpn/amneziawg-windows/v3\s+v3\.1\.20260814\s+') {
        throw 'The rebuilt AmneziaWG maintenance-helper provenance lacks the exact AWG 3.1 module identities.'
    }
}
# END-WINDOWS-AWG-SCHEMA2-OWNER-PUBLICATION-CONTRACT

function Assert-RebuiltAmneziaWgHelper {
    if (-not (Test-Path -LiteralPath $AmneziaWgExe -PathType Leaf)) {
        throw ("The rebuilt AmneziaWG maintenance helper is missing. " +
            "Rebuild it on a reviewed Windows x64 or ARM64 host with " +
            "tools\\build_windows_amneziawg_client.ps1; never substitute " +
            "the helper extracted from the upstream MSI.")
    }
    $expectedUnsigned = $AmneziaWgHelperUnsignedSha256
    if ([string]::IsNullOrEmpty($expectedUnsigned)) {
        throw ("No reviewed unsigned AmneziaWG helper SHA-256 pin exists for windows-$($script:WindowsAwgGoArch). " +
            "Measure the two-clean-build helper from tools\\build_windows_amneziawg_client.ps1 on a Windows " +
            "$($script:WindowsAwgGoArch) host and record it in `$AmneziaWgHelperUnsignedSha256 and the producer's ProductHelperSha256.")
    }
    $script:AmneziaWgHelperReviewedSha256 = $expectedUnsigned
    Assert-WindowsAwgSchema2OwnerPublicationContract `
        -ProvenancePath $AmneziaWgExeProvenance `
        -HelperPath $AmneziaWgExe `
        -ExpectedUnsignedSha256 $expectedUnsigned `
        -ExpectedTarget "windows-$($script:WindowsAwgGoArch)"
    $signature = Get-AuthenticodeSignature -LiteralPath $AmneziaWgExe
    if ($signature.Status -ne
        [System.Management.Automation.SignatureStatus]::NotSigned) {
        throw ("The vendored AmneziaWG helper must remain the exact unsigned " +
            "reproducible artifact bound by provenance; the staged release " +
            "copy is signed below. Status=$($signature.Status)")
    }
}

function Assert-AmneziaWgPayloadSignatures {
    $auditDirectory = Join-Path $OutputDir 'amneziawg-signature-audit'
    if (Test-Path -LiteralPath $auditDirectory) {
        Remove-Item -LiteralPath $auditDirectory -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $auditDirectory | Out-Null
    try {
        $arguments = @('/a', ('"' + $AmneziaWgMsi + '"'), '/qn', ('TARGETDIR="' + $auditDirectory + '"'), '/norestart')
        $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
        if ($process.ExitCode -ne 0) { throw "AmneziaWG signature-audit extraction failed: $($process.ExitCode)." }
        $expectations = @{
            'amneziawg.exe' = 'O=Privacy Technologies OU'
            'awg.exe' = 'O=Privacy Technologies OU'
            'wintun.dll' = 'O=WireGuard LLC'
        }
        $hashes = @{
            'amneziawg.exe' = $UpstreamAmneziaWgExeSha256
            'awg.exe' = $AwgToolExeSha256
            'wintun.dll' = $WintunDllSha256
        }
        $destinations = @{
            'awg.exe' = $AwgToolExe
            'wintun.dll' = $WintunDll
        }
        foreach ($name in $expectations.Keys) {
            $matches = @(Get-ChildItem -LiteralPath $auditDirectory -Recurse -File -Filter $name)
            if ($matches.Count -ne 1) { throw "AmneziaWG MSI must contain exactly one signed $name." }
            if (-not (Test-FileSha256 -Path $matches[0].FullName `
                    -ExpectedSha256 $hashes[$name])) {
                throw "Pinned AmneziaWG MSI contains an unexpected $name payload."
            }
            Assert-AuthenticodeSigner -Path $matches[0].FullName -SignerPattern $expectations[$name]
            if ($destinations.ContainsKey($name)) {
                Copy-Item -LiteralPath $matches[0].FullName `
                    -Destination $destinations[$name] -Force
            }
        }
    } finally {
        Remove-Item -LiteralPath $auditDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Ensure-AmneziaWgMsi {
    $script:WinsAmneziaWgMsiIdentity = Assert-WinsEmbeddedPrerequisiteCustody `
        -Kind 'amneziawg_msi' `
        -Path $AmneziaWgMsi `
        -ExpectedSha256 $AmneziaWgSha256 `
        -ExpectedVersion $AmneziaWgVersion `
        -ExpectedArchitecture $TargetArchitecture `
        -ExpectedFileName $dependencyNames.AmneziaMsi `
        -ExpectedPublisherPattern $script:WinsAmneziaWgMsiPublisherPattern `
        -MaximumBytes $script:WinsAmneziaWgMsiMaxBytes
}

# BEGIN-WINDOWS-EMBEDDED-PREREQUISITE-CUSTODY
function Test-WinsPrerequisiteWindowsHost {
    return [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}

function Assert-WinsPrerequisiteInnoDefineSafe {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($Value -match "[\r\n`"'$]") {
        throw "$Name contains characters that cannot be encoded into the installer."
    }
}

function Assert-WinsPrerequisiteNoReparsePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    $resolved = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($resolved)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "$Purpose path is not rooted: $resolved"
    }
    $current = $root
    foreach ($part in @($resolved.Substring($root.Length) -split '[\\/]' | Where-Object { $_ })) {
        if ($part -eq '..' -or $part -eq '.') {
            throw "unsafe path component rejected: $resolved"
        }
        $current = Join-Path $current $part
        if (-not (Test-Path -LiteralPath $current)) { continue }
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        $linkType = [string]$item.LinkType
        $isReparse = (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            ($linkType -in @('SymbolicLink', 'Junction'))
        if ($isReparse) {
            $parent = [IO.Path]::GetDirectoryName($current)
            $isRootChild = [string]::Equals(
                $parent.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar),
                $root.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar),
                [StringComparison]::OrdinalIgnoreCase
            )
            if ([string]::Equals($current, $resolved, [StringComparison]::OrdinalIgnoreCase) -or
                -not $isRootChild) {
                throw "reparse point rejected: $Purpose crosses $current"
            }
        }
    }
}

function Get-WinsPrerequisiteHandleIdentity {
    param(
        [Parameter(Mandatory = $true)][IO.FileStream]$Stream,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    if (Test-WinsPrerequisiteWindowsHost) {
        if (-not ('WinsVpn.PrerequisiteFileIdentity' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WinsVpn {
    public static class PrerequisiteFileIdentity {
        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME { public uint Low; public uint High; }
        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION {
            public uint FileAttributes;
            public FILETIME CreationTime;
            public FILETIME LastAccessTime;
            public FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }
        public sealed class Result {
            public uint VolumeSerialNumber { get; internal set; }
            public uint NumberOfLinks { get; internal set; }
            public uint FileIndexHigh { get; internal set; }
            public uint FileIndexLow { get; internal set; }
            public ulong FileSize { get; internal set; }
            public ulong LastWriteFileTime { get; internal set; }
            public uint FileAttributes { get; internal set; }
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle, out BY_HANDLE_FILE_INFORMATION information);
        public static Result Inspect(SafeFileHandle handle) {
            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(handle, out information)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return new Result {
                VolumeSerialNumber = information.VolumeSerialNumber,
                NumberOfLinks = information.NumberOfLinks,
                FileIndexHigh = information.FileIndexHigh,
                FileIndexLow = information.FileIndexLow,
                FileSize = ((ulong)information.FileSizeHigh << 32) | information.FileSizeLow,
                LastWriteFileTime = ((ulong)information.LastWriteTime.High << 32) | information.LastWriteTime.Low,
                FileAttributes = information.FileAttributes
            };
        }
    }
}
'@
        }
        return [WinsVpn.PrerequisiteFileIdentity]::Inspect($Stream.SafeFileHandle)
    }
    $useDarwinStat = ($PSVersionTable.PSVersion.Major -ge 6 -and $IsMacOS)
    $stat = if ($useDarwinStat) {
        @{
            NumberOfLinks = [uint32](& /usr/bin/stat -f %l $Path)
            FileSize = [uint64](& /usr/bin/stat -f %z $Path)
        }
    } else {
        @{
            NumberOfLinks = [uint32](& /usr/bin/stat -c %h -- $Path)
            FileSize = [uint64](& /usr/bin/stat -c %s -- $Path)
        }
    }
    if ($LASTEXITCODE -ne 0) {
        throw "$Purpose identity tooling failed for $Path"
    }
    return [pscustomobject]@{
        VolumeSerialNumber = [uint32]0
        NumberOfLinks = [uint32]$stat.NumberOfLinks
        FileIndexHigh = [uint32]0
        FileIndexLow = [uint32]0
        FileSize = [uint64]$stat.FileSize
        LastWriteFileTime = [uint64]0
        FileAttributes = [uint32]0
    }
}

function Test-WinsPrerequisiteIdentityEqual {
    param($First, $Second)
    return $First.VolumeSerialNumber -eq $Second.VolumeSerialNumber -and
        $First.FileIndexHigh -eq $Second.FileIndexHigh -and
        $First.FileIndexLow -eq $Second.FileIndexLow -and
        $First.NumberOfLinks -eq $Second.NumberOfLinks -and
        $First.FileSize -eq $Second.FileSize -and
        $First.LastWriteFileTime -eq $Second.LastWriteFileTime -and
        $First.FileAttributes -eq $Second.FileAttributes
}

function Get-WinsBoundedRegularFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Purpose,
        [Parameter(Mandatory = $true)][long]$MaximumBytes
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "$Purpose path is empty." }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.Path]::IsPathRooted($full)) {
        throw "$Purpose path is not absolute: $full"
    }
    Assert-WinsPrerequisiteNoReparsePath -Path $full -Purpose $Purpose
    if (-not (Test-Path -LiteralPath $full)) {
        throw "$Purpose is missing: $full"
    }
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    $linkType = [string]$item.LinkType
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $linkType -in @('SymbolicLink', 'Junction')) {
        throw "reparse point rejected: $Purpose must be one regular non-reparse file: $full"
    }
    $after = $null
    $digest = $null
    $stream = [IO.FileStream]::new(
        $full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
    )
    try {
        $before = Get-WinsPrerequisiteHandleIdentity -Stream $stream -Path $full -Purpose $Purpose
        if ([int64]$before.NumberOfLinks -ne 1) {
            throw "hardlink refused: $Purpose must be a single-link file"
        }
        if ([int64]$before.FileSize -lt 1 -or [int64]$before.FileSize -gt $MaximumBytes) {
            throw "$Purpose size is outside the accepted range: $full"
        }
        if ($stream.Length -ne [int64]$before.FileSize) {
            throw "$Purpose size disagreed between handle and stream: $full"
        }
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        } finally { $sha.Dispose() }
        $after = Get-WinsPrerequisiteHandleIdentity -Stream $stream -Path $full -Purpose $Purpose
        if (-not (Test-WinsPrerequisiteIdentityEqual -First $before -Second $after)) {
            throw "$Purpose mutated while it was hashed: $full"
        }
    } finally { $stream.Dispose() }
    $reopened = [IO.FileStream]::new(
        $full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
    )
    try {
        $latest = Get-WinsPrerequisiteHandleIdentity -Stream $reopened -Path $full -Purpose $Purpose
        if (-not (Test-WinsPrerequisiteIdentityEqual -First $after -Second $latest)) {
            throw "$Purpose mutated after it was hashed: $full"
        }
        if ([int64]$latest.NumberOfLinks -ne 1) {
            throw "hardlink refused: $Purpose must be a single-link file"
        }
    } finally { $reopened.Dispose() }
    return [pscustomobject]@{
        Path = $full
        Sha256 = $digest
        SizeBytes = [int64]$after.FileSize
        Name = $item.Name
        VersionInfo = $item.VersionInfo
    }
}

function Assert-WinsPrerequisitePin {
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$ActualSha256,
        [Parameter(Mandatory = $true)][long]$ActualSizeBytes,
        [Parameter(Mandatory = $true)][long]$MaximumBytes
    )
    # The reviewed pin is the in-script SHA-256 ($VcRedistSha256,
    # $AmneziaWgSha256). The bytes on disk are compared to it directly; no
    # sidecar file can supply or override the expected digest.
    if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "reviewed $Kind SHA-256 pin is not lowercase hex."
    }
    if ($ActualSha256 -cne $ExpectedSha256) {
        throw "stale $Kind prerequisite bytes do not match the pinned SHA-256 $ExpectedSha256 (actual $ActualSha256)."
    }
    if ($ActualSizeBytes -lt 1 -or $ActualSizeBytes -gt $MaximumBytes) {
        throw "$Kind size is outside the accepted range."
    }
}

function Assert-WinsPrerequisiteAuthenticodeSigner {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$PublisherPattern
    )
    if (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
        throw 'Authenticode verification tooling is unavailable; refusing to skip.'
    }
    Assert-AuthenticodeSigner -Path $Path -SignerPattern $PublisherPattern
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $subject = [string]$signature.SignerCertificate.Subject
    if ([string]::IsNullOrWhiteSpace($subject) -or $subject -notmatch $PublisherPattern) {
        throw "wrong Authenticode signer: $Path subject is not the reviewed publisher."
    }
    return $subject
}

function Assert-WinsPrerequisiteVcMetadata {
    param(
        [Parameter(Mandatory = $true)]$File,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$ExpectedArchitecture,
        [Parameter(Mandatory = $true)][string]$ExpectedOriginalFileName,
        [Parameter(Mandatory = $true)][string]$ExpectedProductName
    )
    $versionInfo = $File.VersionInfo
    $fileVersion = [string]$versionInfo.FileVersion
    $original = [string]$versionInfo.OriginalFilename
    $product = [string]$versionInfo.ProductName
    $company = [string]$versionInfo.CompanyName
    if ($fileVersion -cne $ExpectedVersion -or
        [string]$versionInfo.ProductVersion -cne $ExpectedVersion) {
        throw "wrong prerequisite version: VC_redist FILEVERSION is not $ExpectedVersion."
    }
    if ($original -cne $ExpectedOriginalFileName) {
        throw "wrong prerequisite architecture: VC_redist OriginalFilename is not $ExpectedOriginalFileName."
    }
    if ($product -cne $ExpectedProductName -or $company -cne 'Microsoft Corporation') {
        throw "wrong prerequisite architecture: VC_redist product identity is not the reviewed $ExpectedArchitecture package."
    }
}

function Assert-WinsPrerequisiteMsiMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$ExpectedArchitecture
    )
    if (-not (Test-WinsPrerequisiteWindowsHost)) {
        throw 'AmneziaWG MSI version/architecture verification tooling is unavailable; refusing to skip.'
    }
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.GetType().InvokeMember(
            'OpenDatabase', [Reflection.BindingFlags]::InvokeMethod, $null, $installer, @($Path, 0)
        )
        $view = $database.GetType().InvokeMember(
            'OpenView', [Reflection.BindingFlags]::InvokeMethod, $null, $database,
            @('SELECT `Value` FROM `Property` WHERE `Property`=''ProductVersion''')
        )
        [void]$view.GetType().InvokeMember('Execute', [Reflection.BindingFlags]::InvokeMethod, $null, $view, $null)
        $record = $view.GetType().InvokeMember('Fetch', [Reflection.BindingFlags]::InvokeMethod, $null, $view, $null)
        if ($null -eq $record) {
            throw 'wrong prerequisite version: AmneziaWG MSI ProductVersion is missing.'
        }
        $productVersion = [string]$record.GetType().InvokeMember(
            'StringData', [Reflection.BindingFlags]::GetProperty, $null, $record, @(1)
        )
        $summary = $database.GetType().InvokeMember(
            'SummaryInformation', [Reflection.BindingFlags]::GetProperty, $null, $database, $null
        )
        $template = [string]$summary.GetType().InvokeMember(
            'Property', [Reflection.BindingFlags]::GetProperty, $null, $summary, @(7)
        )
    } catch {
        throw "AmneziaWG MSI version/architecture verification tooling failed; refusing to skip. $($_.Exception.Message)"
    }
    if ($productVersion -cne $ExpectedVersion) {
        throw "wrong prerequisite version: AmneziaWG MSI ProductVersion is not $ExpectedVersion."
    }
    $isArm = $template -match '(?i)Arm64'
    $isX64 = $template -match '(?i)(x64|Intel64|AMD64)'
    if ($ExpectedArchitecture -ceq 'arm64') {
        if (-not $isArm -or $isX64) {
            throw 'wrong prerequisite architecture: AmneziaWG MSI is not the reviewed arm64 package.'
        }
    } elseif ($ExpectedArchitecture -ceq 'x64') {
        if (-not $isX64 -or $isArm) {
            throw 'wrong prerequisite architecture: AmneziaWG MSI is not the reviewed x64 package.'
        }
    } else {
        throw "wrong prerequisite architecture: unsupported $ExpectedArchitecture."
    }
}

function Assert-WinsEmbeddedPrerequisiteCustody {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('vc_redist', 'amneziawg_msi')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$ExpectedArchitecture,
        [Parameter(Mandatory = $true)][string]$ExpectedFileName,
        [Parameter(Mandatory = $true)][string]$ExpectedPublisherPattern,
        [Parameter(Mandatory = $true)][long]$MaximumBytes,
        [string]$ExpectedOriginalFileName,
        [string]$ExpectedProductName
    )
    if ($ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "reviewed $Kind SHA-256 pin is not lowercase hex."
    }
    $file = Get-WinsBoundedRegularFile -Path $Path -Purpose $Kind -MaximumBytes $MaximumBytes
    if ($file.Name -cne $ExpectedFileName) {
        throw "$Kind leaf name is not $ExpectedFileName."
    }
    Assert-WinsPrerequisitePin -Kind $Kind -ExpectedSha256 $ExpectedSha256 `
        -ActualSha256 $file.Sha256 -ActualSizeBytes $file.SizeBytes `
        -MaximumBytes $MaximumBytes
    if ($Kind -ceq 'vc_redist') {
        Assert-WinsPrerequisiteVcMetadata -File $file `
            -ExpectedVersion $ExpectedVersion `
            -ExpectedArchitecture $ExpectedArchitecture `
            -ExpectedOriginalFileName $ExpectedOriginalFileName `
            -ExpectedProductName $ExpectedProductName
    }
    $subject = Assert-WinsPrerequisiteAuthenticodeSigner -Path $file.Path `
        -PublisherPattern $ExpectedPublisherPattern
    if ($Kind -ceq 'amneziawg_msi') {
        Assert-WinsPrerequisiteMsiMetadata -Path $file.Path `
            -ExpectedVersion $ExpectedVersion -ExpectedArchitecture $ExpectedArchitecture
    }
    Assert-WinsPrerequisiteInnoDefineSafe -Value $file.Sha256 -Name "$Kind sha256"
    Assert-WinsPrerequisiteInnoDefineSafe -Value ([string]$file.SizeBytes) -Name "$Kind size"
    Assert-WinsPrerequisiteInnoDefineSafe -Value $subject -Name "$Kind publisher"
    Assert-WinsPrerequisiteInnoDefineSafe -Value $ExpectedVersion -Name "$Kind version"
    Assert-WinsPrerequisiteInnoDefineSafe -Value $ExpectedArchitecture -Name "$Kind architecture"
    return [pscustomobject]@{
        Kind = $Kind
        Path = $file.Path
        Sha256 = $file.Sha256
        SizeBytes = $file.SizeBytes
        Publisher = $subject
        FileVersion = $ExpectedVersion
        Architecture = $ExpectedArchitecture
        FileName = $ExpectedFileName
    }
}

function Copy-WinsExactRegularFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$Purpose,
        [Parameter(Mandatory = $true)][long]$MaximumBytes
    )
    $before = Get-WinsBoundedRegularFile -Path $Source -Purpose $Purpose -MaximumBytes $MaximumBytes
    $destFull = [IO.Path]::GetFullPath($Destination)
    Assert-WinsPrerequisiteNoReparsePath -Path $destFull -Purpose "$Purpose destination"
    $parent = Split-Path -Parent $destFull
    [void][IO.Directory]::CreateDirectory($parent)
    [IO.File]::Copy($before.Path, $destFull, $true)
    $after = Get-WinsBoundedRegularFile -Path $destFull -Purpose "$Purpose staged copy" -MaximumBytes $MaximumBytes
    if ($after.Sha256 -cne $before.Sha256 -or $after.SizeBytes -ne $before.SizeBytes) {
        throw "$Purpose changed during copy."
    }
    return $after
}
# END-WINDOWS-EMBEDDED-PREREQUISITE-CUSTODY

function Ensure-XrayRuntime {
    if (Test-FileSha256 -Path $XrayExe -ExpectedSha256 $XrayExeSha256) { return }

    # Deliberately does not fall back to downloading $XrayArchiveUrl anymore.
    # That upstream release archive's xray.exe embeds go1.26.1, which is
    # exactly the outdated-runtime problem M-1 fixed; silently re-fetching it
    # here would undo that fix the moment the vendored copy went missing.
    throw ("dependencies\xray.exe does not match the pinned, from-source " +
        "Go 1.27.1 rebuild ($XrayExeSha256). Refusing to fetch the upstream " +
        "v$XrayVersion release archive as a substitute -- it embeds an " +
        "outdated go1.26.1 runtime with known-fixed stdlib CVEs. Regenerate " +
        "it instead with: bash tools/build_xray_engine.sh windows-$($script:WindowsAwgGoArch) " +
        "installer/windows/dependencies/$($dependencyNames.Xray) -- see " +
        "docs/RELEASE_ENGINE_BINARY_REFRESH.md.")
}

function Get-PeCoffMachine {
    param([Parameter(Mandatory = $true)][string]$Path)
    $fs = [IO.File]::OpenRead($Path)
    try {
        $br = New-Object IO.BinaryReader($fs)
        if ($br.ReadUInt16() -ne 0x5A4D) {
            throw "Not a PE image: $Path"
        }
        $fs.Position = 0x3C
        $peOffset = $br.ReadUInt32()
        $fs.Position = $peOffset
        if ($br.ReadUInt32() -ne 0x00004550) {
            throw "Not a PE image: $Path"
        }
        return $br.ReadUInt16()
    } finally {
        $fs.Dispose()
    }
}

function Assert-PeCoffMachine {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][uint16]$Expected
    )
    $actual = Get-PeCoffMachine -Path $Path
    if ($actual -ne $Expected) {
        throw ("Refusing to package $Path with COFF machine 0x{0:X4}; a $TargetArchitecture release requires 0x{1:X4}." -f $actual, $Expected)
    }
}

function Get-WindowsPayloadDebugSymbolFiles {
    param([Parameter(Mandatory = $true)][string]$Root)
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        return @()
    }
    $blocked = @('.pdb', '.ilk', '.iobj', '.ipdb', '.map', '.sym', '.dbg', '.debug')
    return @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force -ErrorAction Stop |
        Where-Object { $blocked -contains $_.Extension.ToLowerInvariant() })
}

function Move-WindowsPayloadDebugSymbolsToPrivateCustody {
    param([Parameter(Mandatory = $true)][string]$PayloadRoot)
    $files = Get-WindowsPayloadDebugSymbolFiles -Root $PayloadRoot
    if ($files.Count -eq 0) {
        return
    }
    if (-not (Test-Path -LiteralPath $WindowsSymbolDir -PathType Container)) {
        throw "Private Windows symbol custody directory is missing: $WindowsSymbolDir"
    }
    $rootResolved = (Resolve-Path -LiteralPath $PayloadRoot).Path
    foreach ($file in $files) {
        $full = $file.FullName
        if (-not $full.StartsWith($rootResolved, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Debug symbol $full is outside payload root $rootResolved."
        }
        $relative = $full.Substring($rootResolved.Length).TrimStart('\')
        $destination = Join-Path $WindowsSymbolDir $relative
        $destDir = Split-Path -Parent $destination
        if (-not (Test-Path -LiteralPath $destDir -PathType Container)) {
            New-Item -ItemType Directory -Force -Path $destDir | Out-Null
        }
        Move-Item -LiteralPath $full -Destination $destination -Force
        Write-Host "Moved private debug symbol $relative into $WindowsSymbolDir"
    }
}

function Assert-WindowsPayloadContainsNoDebugSymbols {
    param(
        [Parameter(Mandatory = $true)][string]$PayloadRoot,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $files = Get-WindowsPayloadDebugSymbolFiles -Root $PayloadRoot
    if ($files.Count -gt 0) {
        throw ("$Label still contains debug symbol files that must stay in private custody: " +
            ($files.FullName -join ', '))
    }
}

# The runner's CMake project builds its unit-test programs (windows_winn_gate_test.exe,
# winn3_supervisor_test.exe, winsvpn-carrierhost-test.exe and the like) next to the
# application. They are build outputs, not product files, and none of them may ship.
function Get-WindowsPayloadTestExecutableFiles {
    param([Parameter(Mandatory = $true)][string]$Root)
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        return @()
    }
    return @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force -ErrorAction Stop |
        Where-Object { $_.Name -match '(?i)[-_]test\.exe$' })
}

function Remove-WindowsPayloadTestExecutables {
    param([Parameter(Mandatory = $true)][string]$PayloadRoot)
    foreach ($file in (Get-WindowsPayloadTestExecutableFiles -Root $PayloadRoot)) {
        Remove-Item -LiteralPath $file.FullName -Force
    }
}

function Assert-WindowsPayloadContainsNoTestExecutables {
    param(
        [Parameter(Mandatory = $true)][string]$PayloadRoot,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $files = Get-WindowsPayloadTestExecutableFiles -Root $PayloadRoot
    if ($files.Count -gt 0) {
        throw ("$Label still contains test executables that must not ship: " +
            ($files.FullName -join ', '))
    }
}

function Get-ValidatedInnoContainerRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    if ([string]::IsNullOrWhiteSpace($Root)) { throw "$Purpose root is empty." }
    $rootFull = [IO.Path]::GetFullPath($Root)
    $pathRoot = [IO.Path]::GetPathRoot($rootFull)
    $rootTrimmed = $rootFull.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $pathRootTrimmed = $pathRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    if ([string]::IsNullOrEmpty($rootTrimmed) -or
        [string]::Equals($rootTrimmed, $pathRootTrimmed, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing a filesystem-root container for ${Purpose}: $rootFull"
    }
    return $rootTrimmed
}

function Assert-InnoNoReparsePointChain {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$FullPath,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    $rootFull = Get-ValidatedInnoContainerRoot -Root $Root -Purpose $Purpose
    if (Test-Path -LiteralPath $rootFull) {
        $rootItem = Get-Item -LiteralPath $rootFull -Force
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Purpose root is a reparse point: $rootFull"
        }
    }
    $targetFull = [IO.Path]::GetFullPath($FullPath)
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    if (-not $targetFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Purpose is outside its approved root."
    }
    $current = $rootFull
    foreach ($part in @($targetFull.Substring($prefix.Length) -split '[\\/]')) {
        if ([string]::IsNullOrEmpty($part)) { continue }
        $current = Join-Path $current $part
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Purpose crosses a reparse point: $current"
            }
        }
    }
}

function Get-ContainedInnoStagingFiles {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    $rootFull = Get-ValidatedInnoContainerRoot -Root $Root -Purpose $Purpose
    if (-not (Test-Path -LiteralPath $rootFull -PathType Container)) {
        throw "$Purpose root is missing: $rootFull"
    }
    $rootItem = Get-Item -LiteralPath $rootFull -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Purpose root is a reparse point: $rootFull"
    }
    $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($rootFull)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            $full = [IO.Path]::GetFullPath($item.FullName)
            if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "$Purpose item escaped its root: $full"
            }
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Purpose contains a reparse point: $full"
            }
            if ($item.PSIsContainer) { $pending.Push($full) } else { $item }
        }
    }
}

function Assert-InnoStagingPayloadAllowed {
    param([Parameter(Mandatory = $true)][string]$RelativePath)
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or $RelativePath -cne $RelativePath.Trim()) {
        throw 'Inno staging paths must be non-empty and have no surrounding whitespace.'
    }
    $relative = $RelativePath.Replace('\', '/')
    $segments = @($relative -split '/')
    if ($segments.Count -eq 0) { throw "Inno staging path has no segments: $relative" }
    foreach ($segment in $segments) {
        if ([string]::IsNullOrWhiteSpace($segment) -or $segment -in @('.', '..')) {
            throw "Inno staging path contains an empty or dot segment: $relative"
        }
    }
    $lastSlash = $relative.LastIndexOf('/')
    $leaf = if ($lastSlash -ge 0) { $relative.Substring($lastSlash + 1) } else { $relative }
    foreach ($forbiddenPrefix in $ForbiddenInnoMullvadPayloadLeafPrefixes) {
        if ($leaf.StartsWith($forbiddenPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw ("Known-affected Mullvad split-tunnel driver 1.3.0.0 must not " +
                "enter a release payload: withdrawn kernel split-tunnel artifact: $relative")
        }
    }
    foreach ($forbiddenLeaf in $affectedSplitTunnelDriverNames) {
        if ($leaf.Equals($forbiddenLeaf, [StringComparison]::OrdinalIgnoreCase)) {
            throw ("Known-affected Mullvad split-tunnel driver 1.3.0.0 must not " +
                "enter a release payload: withdrawn kernel split-tunnel artifact: $relative")
        }
    }
    $extension = [IO.Path]::GetExtension($leaf).ToLowerInvariant()
    if ($ForbiddenInnoMullvadPayloadExtensions -contains $extension) {
        throw "Windows Inno staging forbids kernel driver package files: $relative"
    }
    return $relative
}

function Assert-InnoStagingPayloadHashAllowed {
    param(
        [Parameter(Mandatory = $true)][string]$Sha256,
        [Parameter(Mandatory = $true)][string]$Path
    )
    foreach ($forbiddenHash in $ForbiddenInnoMullvadPayloadSha256) {
        if ($Sha256.Equals($forbiddenHash, [StringComparison]::OrdinalIgnoreCase)) {
            throw ("Known-affected Mullvad split-tunnel driver 1.3.0.0 must not " +
                "enter a release payload: withdrawn kernel split-tunnel bytes, including when renamed: $Path")
        }
    }
}

function Assert-InnoStagingContainsNoWithdrawnMullvadPayloads {
    param(
        [Parameter(Mandatory = $true)][string[]]$Roots,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ($null -eq $Roots -or $Roots.Count -eq 0) {
        throw "$Label has no Inno staging roots to inspect."
    }
    foreach ($root in $Roots) {
        $rootFull = Get-ValidatedInnoContainerRoot -Root $root -Purpose $Label
        $prefix = $rootFull + [IO.Path]::DirectorySeparatorChar
        foreach ($file in @(Get-ContainedInnoStagingFiles -Root $rootFull -Purpose $Label)) {
            $full = [IO.Path]::GetFullPath($file.FullName)
            Assert-InnoNoReparsePointChain -Root $rootFull -FullPath $full -Purpose $Label
            $relative = $full.Substring($prefix.Length).Replace('\', '/')
            $canonical = Assert-InnoStagingPayloadAllowed -RelativePath $relative
            $sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $full).Hash.ToLowerInvariant()
            Assert-InnoStagingPayloadHashAllowed -Sha256 $sha256 -Path $canonical
        }
    }
}

function Invoke-WithdrawnMullvadStagingSelfTest {
    $testRoot = Join-Path ([IO.Path]::GetTempPath()) (
        'winsvpn-inno-mullvad-selftest-' + [guid]::NewGuid().ToString('N')
    )
    $release = Join-Path $testRoot 'release'
    $deps = Join-Path $testRoot 'deps'
    New-Item -ItemType Directory -Path $release -Force | Out-Null
    New-Item -ItemType Directory -Path $deps -Force | Out-Null
    try {
        [IO.File]::WriteAllText((Join-Path $release 'ordinary.bin'), 'innocent')
        Assert-InnoStagingContainsNoWithdrawnMullvadPayloads `
            -Roots @($release, $deps) -Label 'clean Inno staging self-test'

        $cases = New-Object 'System.Collections.Generic.List[hashtable]'
        $cases.Add(@{
            Name = 'nested-name'
            Relative = 'nested/mullvad-split-tunnel.sys'
            Bytes = [byte[]](1, 2, 3, 4)
            Marker = 'withdrawn kernel split-tunnel artifact'
        })
        $cases.Add(@{
            Name = 'prefix-arm64-cat'
            Relative = 'nested/MULLVAD-SPLIT-TUNNEL-ARM64.CAT'
            Bytes = [byte[]](5, 6, 7, 8)
            Marker = 'withdrawn kernel split-tunnel artifact'
        })
        $cases.Add(@{
            Name = 'renamed-extension'
            Relative = 'nested/renamed-driver.sys'
            Bytes = [byte[]](9, 10, 11, 12)
            Marker = 'kernel driver package files'
        })
        foreach ($identityFile in @(Get-ChildItem -LiteralPath $DependenciesDir -File -Force |
            Where-Object {
                $_.Name.StartsWith('mullvad-split-tunnel', [StringComparison]::OrdinalIgnoreCase) -and
                ($ForbiddenInnoMullvadPayloadExtensions -contains $_.Extension.ToLowerInvariant())
            })) {
            $cases.Add(@{
                Name = "renamed-hash-$($identityFile.Name)"
                Relative = "nested/neutral-$($identityFile.Name).bin"
                Bytes = [IO.File]::ReadAllBytes($identityFile.FullName)
                Marker = 'withdrawn kernel split-tunnel bytes, including when renamed'
            })
        }

        foreach ($case in $cases) {
            $plantedRoot = Join-Path $testRoot $case.Name
            $plantedRelease = Join-Path $plantedRoot 'release'
            $relativeNative = $case.Relative.Replace('/', [IO.Path]::DirectorySeparatorChar)
            $destination = Join-Path $plantedRelease $relativeNative
            $plantedParent = Split-Path -Parent $destination
            New-Item -ItemType Directory -Path $plantedParent -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $plantedRoot 'deps') -Force | Out-Null
            [IO.File]::WriteAllBytes($destination, $case.Bytes)
            $rejected = $true
            try {
                Assert-InnoStagingContainsNoWithdrawnMullvadPayloads `
                    -Roots @($plantedRelease, (Join-Path $plantedRoot 'deps')) `
                    -Label "adversarial Inno staging $($case.Name)"
                $rejected = $false
            } catch {
                if ($_.Exception.Message -notmatch [regex]::Escape($case.Marker)) {
                    throw
                }
            }
            if (-not $rejected) {
                throw "Withdrawn Mullvad Inno staging self-test accepted $($case.Name)."
            }
        }

        $rootRejected = $true
        try {
            Assert-InnoStagingContainsNoWithdrawnMullvadPayloads `
                -Roots @([IO.Path]::GetPathRoot($testRoot)) `
                -Label 'filesystem-root Inno staging self-test'
            $rootRejected = $false
        } catch {
            if ($_.Exception.Message -notmatch 'filesystem-root container') {
                throw
            }
        }
        if (-not $rootRejected) {
            throw 'Withdrawn Mullvad Inno staging self-test accepted a filesystem-root container.'
        }

        $linkDir = Join-Path $testRoot 'release-with-link'
        $outside = Join-Path $testRoot 'outside'
        New-Item -ItemType Directory -Path $linkDir -Force | Out-Null
        New-Item -ItemType Directory -Path $outside -Force | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $outside 'secret.bin'), [byte[]](13, 14, 15, 16))
        $linked = Join-Path $linkDir 'linked'
        $linkCreated = $false
        try {
            New-Item -ItemType SymbolicLink -Path $linked -Target $outside -ErrorAction Stop | Out-Null
            $linkCreated = $true
        } catch {
            $linkCreated = $false
        }
        if ($linkCreated) {
            $linkItem = Get-Item -LiteralPath $linked -Force
            if (($linkItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                $reparseRejected = $true
                try {
                    Assert-InnoStagingContainsNoWithdrawnMullvadPayloads `
                        -Roots @($linkDir) -Label 'reparse Inno staging self-test'
                    $reparseRejected = $false
                } catch {
                    if ($_.Exception.Message -notmatch 'reparse point') {
                        throw
                    }
                }
                if (-not $reparseRejected) {
                    throw 'Withdrawn Mullvad Inno staging self-test followed a reparse point.'
                }
            }
        }
    } finally {
        Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "WINDOWS WITHDRAWN MULLVAD INNO STAGING SELF-TEST: PASS" -ForegroundColor Green
}

# Builds the optional Winn Protocol v3 datapath engine into $ReleaseDir so it
# is picked up by the same "{#SourceDir}\*" Inno Setup rule (winsvpn.iss) and
# the same recursive product-signing loop that already carry
# winsvpn_awg_engine.exe -- no installer or signing change is needed beyond
# the artifact existing in $ReleaseDir before both run. Must be called before
# the product-signing loop and before Assert-ReleaseInputIndexUnchanged.
#
function Get-Winn3VerifierPython {
    param([bool]$RequirePsfSignature = $false)
    $pythonCommand = Get-Command python.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $pythonCommand) {
        $pythonCommand = Get-Command python -CommandType Application -ErrorAction Stop |
            Select-Object -First 1
    }
    $pythonPath = [IO.Path]::GetFullPath([string]$pythonCommand.Source)
    if ($RequirePsfSignature) {
        # The interpreter decides whether the Winn release signature verifies,
        # so a build that will be product-signed runs only a python.org CPython
        # whose Python Software Foundation Authenticode signature is valid. Any
        # version is accepted; the Store alias and unsigned builds are not.
        if ($pythonPath -match '\\WindowsApps\\') {
            throw "Signed builds need a python.org CPython for the Winn release verifier, not the Store alias at $pythonPath."
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $pythonPath
        $subject = [string]$signature.SignerCertificate.Subject
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
            $subject -notmatch '(^|, )(CN|O)=Python Software Foundation(,|$)') {
            throw "The Python that runs the Winn release verifier ($pythonPath) lacks a valid Python Software Foundation signature."
        }
    }
    return $pythonPath
}

# Runs one repository Python tool in isolated mode and separates its stdout
# lines from its stderr lines. Native stderr must not become a terminating
# error here, so this scope runs with ErrorActionPreference Continue and the
# caller decides from the exit code.
function Invoke-Winn3PythonTool {
    param(
        [Parameter(Mandatory = $true)][string]$Python,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $ErrorActionPreference = 'Continue'
    # -I already ignores PYTHON* variables and the user site; scrubbing them
    # and narrowing PATH as well keeps a hostile environment out of the
    # verifier even if a future interpreter changes that default. The
    # interpreter path itself was resolved before PATH is narrowed.
    $environmentNames = @(
        'PATH', 'PYTHONHOME', 'PYTHONPATH', 'PYTHONSTARTUP', 'PYTHONINSPECT',
        'PYTHONUSERBASE', 'PYTHONWARNINGS', 'PYTHONSAFEPATH'
    )
    $savedEnvironment = @{}
    foreach ($name in $environmentNames) {
        $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        [Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }
    [Environment]::SetEnvironmentVariable(
        'PATH', "$env:SystemRoot\System32;$env:SystemRoot", 'Process'
    )
    try {
        $output = @(& $Python -I -B @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        foreach ($name in $savedEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
        }
    }
    $stdout = @()
    $stderr = @()
    foreach ($item in $output) {
        if ($item -is [System.Management.Automation.ErrorRecord]) {
            $stderr += [string]$item
        } else {
            $stdout += [string]$item
        }
    }
    return [pscustomobject]@{ ExitCode = $exitCode; Stdout = $stdout; Stderr = $stderr }
}

function Assert-Winn3CompiledRole {
    param(
        [Parameter(Mandatory = $true)][string]$Python,
        [Parameter(Mandatory = $true)][string]$Tool,
        [Parameter(Mandatory = $true)][ValidateSet('core', 'relay')][string]$Role,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        # Garbled website engines carry no readable build info; their role is
        # proven by the verified signed manifest row written here.
        [string]$SignedEntryPath
    )
    $roleArguments = @(
        $Tool, 'check-role', '--role', $Role, '--architecture', $TargetArchitecture,
        '--expect-sha256', $ExpectedSha256
    )
    if (-not [string]::IsNullOrEmpty($SignedEntryPath)) {
        $roleArguments += @('--signed-entry', $SignedEntryPath)
    }
    $result = Invoke-Winn3PythonTool -Python $Python -Arguments ($roleArguments + @($Path))
    $pattern = "^PASS: windows winn3 $Role $TargetArchitecture sha256=$ExpectedSha256 build_identity=[0-9a-f]{64}$"
    if ($result.ExitCode -ne 0 -or $result.Stdout.Count -ne 1 -or
        ([string]$result.Stdout[0]) -cnotmatch $pattern) {
        $detail = (@($result.Stdout) + @($result.Stderr)) -join "`n"
        throw "Winn v3 $Role compiled-role check failed (exit $($result.ExitCode)): $detail"
    }
}

# Copy one verified image to a stage path that must not exist. FileMode
# CreateNew fails on any existing name (file, directory or link), so a stage
# path that something recreated after Remove-Winn3PairStage is refused rather
# than overwritten, and the copy never writes through a planted link.
function Copy-WinsExclusiveFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    $reader = [IO.FileStream]::new(
        $Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
    )
    try {
        $writer = [IO.FileStream]::new(
            $Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None
        )
        try {
            $reader.CopyTo($writer)
            $writer.Flush($true)
        } finally { $writer.Dispose() }
    } finally { $reader.Dispose() }
}

function Remove-Winn3PairStage {
    if ($null -ne $script:Winn3PairCustody) {
        foreach ($name in @('CoreStream', 'RelayStream')) {
            $stream = $script:Winn3PairCustody.$name
            if ($null -ne $stream) { $stream.Dispose() }
        }
        $script:Winn3PairCustody = $null
    }
    foreach ($path in @($WinnEngineArtifact, $Winn3RelayArtifact)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
    }
}

function Open-Winn3RetainedPayload {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][long]$ExpectedBytes,
        [Parameter(Mandatory = $true)][string]$Role
    )
    $stream = [IO.FileStream]::new(
        $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
    )
    try {
        $identity = Get-WinsPrerequisiteHandleIdentity -Stream $stream `
            -Path $Path -Purpose "retained Winn v3 $Role payload"
        if ([int64]$identity.NumberOfLinks -ne 1 -or
            [int64]$identity.FileSize -ne $ExpectedBytes) {
            throw "Winn v3 $Role retained handle identity is invalid."
        }
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $stream.Position = 0
            $digest = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        } finally { $sha.Dispose() }
        if ($digest -cne $ExpectedSha256) {
            throw "Winn v3 $Role changed before retained custody was established."
        }
        return [pscustomobject]@{
            Stream = $stream
            Identity = $identity
            Sha256 = $digest
            SizeBytes = $ExpectedBytes
        }
    } catch {
        $stream.Dispose()
        throw
    }
}

function Assert-Winn3RetainedPayloadUnchanged {
    param(
        [Parameter(Mandatory = $true)]$Retained,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Role
    )
    $identity = Get-WinsPrerequisiteHandleIdentity -Stream $Retained.Stream `
        -Path $Path -Purpose "retained Winn v3 $Role payload"
    if ([int64]$identity.VolumeSerialNumber -ne [int64]$Retained.Identity.VolumeSerialNumber -or
        [int64]$identity.FileIndexHigh -ne [int64]$Retained.Identity.FileIndexHigh -or
        [int64]$identity.FileIndexLow -ne [int64]$Retained.Identity.FileIndexLow -or
        [int64]$identity.NumberOfLinks -ne 1 -or
        [int64]$identity.FileSize -ne [int64]$Retained.SizeBytes) {
        throw "Winn v3 $Role retained handle changed during installer compilation."
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $Retained.Stream.Position = 0
        $digest = ([BitConverter]::ToString($sha.ComputeHash($Retained.Stream))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
    if ($digest -cne [string]$Retained.Sha256) {
        throw "Winn v3 $Role retained bytes changed during installer compilation."
    }
}

function Assert-Winn3PairCustodyUnchanged {
    if ($null -eq $script:Winn3PairCustody) {
        throw 'Winn v3 pair custody has not been established.'
    }
    foreach ($entry in @(
            @($WinnEngineArtifact, $script:Winn3PairCustody.Core, $script:Winn3PairCustody.CoreRetained, 'core'),
            @($Winn3RelayArtifact, $script:Winn3PairCustody.Relay, $script:Winn3PairCustody.RelayRetained, 'relay')
        )) {
        $current = Get-WinsBoundedRegularFile -Path $entry[0] `
            -Purpose "Winn v3 $($entry[3]) staged artifact" -MaximumBytes 536870912
        if ($current.Sha256 -cne $entry[1].Sha256 -or
            $current.SizeBytes -ne $entry[1].SizeBytes) {
            throw "Winn v3 $($entry[3]) staged artifact changed after pair verification."
        }
        Assert-PeCoffMachine -Path $current.Path -Expected $script:WindowsPeMachine
        Assert-Winn3RetainedPayloadUnchanged -Retained $entry[2] `
            -Path $entry[0] -Role $entry[3]
    }
}

function Invoke-Winn3ArtifactProvenanceVerification {
    if ($null -ne $script:Winn3PairCustody) {
        Assert-Winn3PairCustodyUnchanged
        return $script:Winn3PairCustody
    }
    if ([string]::IsNullOrWhiteSpace($WinnReleaseDir)) {
        throw ('A signed Winn release is required: pass -WinnReleaseDir or set ' +
            'WINS_WINN_RELEASE_DIR to a directory produced by tools\winn_release.py build and sign.')
    }
    if ($AllowUnsignedWinnRelease -and $mustSign) {
        throw '-AllowUnsignedWinnRelease is refused on a build that must be signed.'
    }
    $releaseRoot = [IO.Path]::GetFullPath($WinnReleaseDir)
    if (-not (Test-Path -LiteralPath $releaseRoot -PathType Container)) {
        throw "Winn release directory does not exist: $releaseRoot"
    }
    $releaseTool = Get-WinsBoundedRegularFile -Path $WinnReleaseTool `
        -Purpose 'Winn release driver' -MaximumBytes 4194304
    $roleTool = Get-WinsBoundedRegularFile -Path $Winn3ArtifactProvenanceTool `
        -Purpose 'Winn v3 compiled-role checker' -MaximumBytes 4194304
    if ($Winn3ArtifactProvenanceToolSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $roleTool.Sha256 -cne $Winn3ArtifactProvenanceToolSha256) {
        throw 'Winn v3 compiled-role checker does not match the reviewed source hash.'
    }
    $python = Get-Winn3VerifierPython -RequirePsfSignature $mustSign
    $target = "datapath-windows-$($script:WindowsAwgGoArch)"
    $relayTarget = "winn3-relay-windows-$($script:WindowsAwgGoArch)"
    Remove-Winn3PairStage

    # 1. Signature and digests, verified ONCE. Exit 0 from verify means the
    # manifest signature verified against the pinned release authority and
    # every artifact on disk matched the manifest; stdout is the exact
    # manifest bytes that were verified (one canonical JSON line). Every
    # expected digest below comes from those held bytes; manifest.json is
    # never read again.
    if ($AllowUnsignedWinnRelease) {
        Write-Warning 'Staging Winn v3 from an UNSIGNED release (-AllowUnsignedWinnRelease). Dev use only; do not publish this installer.'
    }
    Write-Host "Verifying Winn release $releaseRoot"
    $verifyArguments = @(
        $releaseTool.Path, 'verify', '--release', $releaseRoot, '--print-manifest'
    )
    if ($AllowUnsignedWinnRelease) {
        $verifyArguments += '--allow-unsigned'
    }
    $verification = Invoke-Winn3PythonTool -Python $python -Arguments $verifyArguments
    if ($verification.ExitCode -ne 0 -or $verification.Stdout.Count -ne 1) {
        $detail = (@($verification.Stdout) + @($verification.Stderr)) -join "`n"
        throw "Winn release verification failed (exit $($verification.ExitCode)): $detail"
    }
    $manifest = ([string]$verification.Stdout[0]) | ConvertFrom-Json -ErrorAction Stop
    $verifiedImages = @{}
    $signedEntries = @{}
    # The outer finally removes every signed-entry file written below, on any
    # refusal between the manifest read and the role checks. The body keeps
    # its existing indentation.
    try {
    foreach ($image in @(
            @{ Role = 'core'; Target = $target; FileName = 'winn-datapath.exe' },
            @{ Role = 'relay'; Target = $relayTarget; FileName = 'winsvpn_winn3_engine.exe' }
        )) {
        $rows = @($manifest.artifacts | Where-Object {
            [string]$_.target -ceq $image.Target
        })
        $relative = "artifacts/$($image.Target)/$($image.FileName)"
        if ($rows.Count -ne 1 -or
            ([string]$rows[0].sha256) -cnotmatch '^[0-9a-f]{64}$' -or
            ([string]$rows[0].path) -cne $relative) {
            throw "Authenticated Winn manifest entry is invalid for $($image.Target)."
        }
        $printed = [IO.Path]::GetFullPath(
            (Join-Path (Join-Path (Join-Path $releaseRoot 'artifacts') $image.Target) $image.FileName))
        $verified = Get-WinsBoundedRegularFile -Path $printed `
            -Purpose "verified Winn v3 $($image.Role)" -MaximumBytes 536870912
        if ($verified.Sha256 -cne [string]$rows[0].sha256) {
            throw "Verified Winn v3 $($image.Role) changed after verification ($($image.Target))."
        }
        $verifiedImages[$image.Role] = $verified
        # Owner ruling 2026-10-27: website engines may be garbled. Their role
        # check reads this copy of the verified row, taken from the manifest
        # bytes the release driver authenticated above.
        if ($null -ne $rows[0].PSObject.Properties['obfuscation']) {
            if ($AllowUnsignedWinnRelease) {
                throw 'Garbled Winn engines take their role from a signed manifest row; an unsigned release is refused.'
            }
            if ($null -eq $manifest.PSObject.Properties['obfuscation']) {
                throw "Winn manifest row $($image.Target) is obfuscated but the manifest carries no obfuscation record."
            }
            $entryPath = Join-Path ([IO.Path]::GetTempPath()) (
                "winn3-signed-entry-$($image.Role)-$([guid]::NewGuid().ToString('N')).json")
            $entryJson = [pscustomobject]@{
                artifact = $rows[0]
                manifest_obfuscation = $manifest.obfuscation
            } | ConvertTo-Json -Depth 20 -Compress
            [IO.File]::WriteAllText($entryPath, $entryJson, [Text.UTF8Encoding]::new($false))
            $signedEntries[$image.Role] = $entryPath
        }
    }
    $manifestSha256 = $verifiedImages['core'].Sha256
    $relayManifestSha256 = $verifiedImages['relay'].Sha256

    # 3. Stage, then require the staged bytes to be exactly what was checked.
    # Each stage path is created exclusively; on a refusal only the copies this
    # call created are removed.
    $createdStage = @()
    try {
        Copy-WinsExclusiveFile -Source $verifiedImages['core'].Path -Destination $WinnEngineArtifact
        $createdStage += $WinnEngineArtifact
        Copy-WinsExclusiveFile -Source $verifiedImages['relay'].Path -Destination $Winn3RelayArtifact
        $createdStage += $Winn3RelayArtifact
    } catch {
        foreach ($createdPath in $createdStage) {
            Remove-Item -LiteralPath $createdPath -Force -ErrorAction SilentlyContinue
        }
        throw
    }
    $core = Get-WinsBoundedRegularFile -Path $WinnEngineArtifact `
        -Purpose 'Winn v3 staged core' -MaximumBytes 536870912
    $relay = Get-WinsBoundedRegularFile -Path $Winn3RelayArtifact `
        -Purpose 'Winn v3 staged relay' -MaximumBytes 536870912
    if ($core.Sha256 -cne $manifestSha256) {
        Remove-Winn3PairStage
        throw "Staged winn-datapath.exe differs from the release manifest ($target)."
    }
    if ($relay.Sha256 -cne $relayManifestSha256) {
        Remove-Winn3PairStage
        throw "Staged winsvpn_winn3_engine.exe differs from the release manifest ($relayTarget)."
    }
    try {
        Assert-PeCoffMachine -Path $core.Path -Expected $script:WindowsPeMachine
        Assert-PeCoffMachine -Path $relay.Path -Expected $script:WindowsPeMachine
        Assert-Winn3CompiledRole -Python $python -Tool $roleTool.Path -Role 'core' `
            -Path $core.Path -ExpectedSha256 $core.Sha256 -SignedEntryPath $signedEntries['core']
        Assert-Winn3CompiledRole -Python $python -Tool $roleTool.Path -Role 'relay' `
            -Path $relay.Path -ExpectedSha256 $relay.Sha256 -SignedEntryPath $signedEntries['relay']
    } catch {
        Remove-Winn3PairStage
        throw
    }
    } finally {
        foreach ($entryPath in $signedEntries.Values) {
            Remove-Item -LiteralPath $entryPath -Force -ErrorAction SilentlyContinue
        }
    }

    # 4. Product-sign both here, because the release loop below excludes them
    # and custody must be taken on the bytes that ship.
    if ($mustSign) {
        foreach ($path in @($WinnEngineArtifact, $Winn3RelayArtifact)) {
            Invoke-ProductSigning -Path $path -SigningArguments $signingArguments `
                -SigningTimestampUrl $signingTimestampUrl -SignerPattern $productSignerPattern `
                -SignTool $signTool
        }
        $core = Get-WinsBoundedRegularFile -Path $WinnEngineArtifact `
            -Purpose 'Winn v3 signed core' -MaximumBytes 536870912
        $relay = Get-WinsBoundedRegularFile -Path $Winn3RelayArtifact `
            -Purpose 'Winn v3 signed relay' -MaximumBytes 536870912
        Assert-PeCoffMachine -Path $core.Path -Expected $script:WindowsPeMachine
        Assert-PeCoffMachine -Path $relay.Path -Expected $script:WindowsPeMachine
    }
    $coreRetained = Open-Winn3RetainedPayload -Path $core.Path `
        -ExpectedSha256 $core.Sha256 -ExpectedBytes $core.SizeBytes -Role 'core'
    try {
        $relayRetained = Open-Winn3RetainedPayload -Path $relay.Path `
            -ExpectedSha256 $relay.Sha256 -ExpectedBytes $relay.SizeBytes -Role 'relay'
    } catch {
        $coreRetained.Stream.Dispose()
        throw
    }
    $script:Winn3PairCustody = [pscustomobject]@{
        ReleaseTarget = $target
        ReleaseManifestSha256 = $manifestSha256
        RelayReleaseTarget = $relayTarget
        RelayReleaseManifestSha256 = $relayManifestSha256
        UnsignedRelease = [bool]$AllowUnsignedWinnRelease
        TargetArchitecture = $TargetArchitecture
        Core = $core
        Relay = $relay
        CoreRetained = $coreRetained
        RelayRetained = $relayRetained
        CoreStream = $coreRetained.Stream
        RelayStream = $relayRetained.Stream
    }
    return $script:Winn3PairCustody
}

function Build-WinnDatapathEngine {
    try {
        [void](Invoke-Winn3ArtifactProvenanceVerification)
        Write-Host "Staged the release-verified, role-checked Winn Protocol v3 datapath and relay for $TargetArchitecture."
    } catch {
        Remove-Winn3PairStage
        if ($AllowMissingWinn3Carrier) {
            Write-Warning "Winn v3 pair was not staged: $($_.Exception.Message)"
            return
        }
        throw
    }
}

function Build-BrowserNativeHost {
    $dart = [string]$env:DART_BIN
    if (-not $dart -and $script:FlutterCommand) {
        $flutterBinDir = Split-Path -Parent $script:FlutterCommand
        $candidate = Join-Path $flutterBinDir 'cache\dart-sdk\bin\dart.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $dart = $candidate }
    }
    if (-not $dart) {
        $resolved = Get-Command dart.exe -ErrorAction SilentlyContinue
        if ($resolved) { $dart = $resolved.Source }
    }
    if (-not $dart -or -not (Test-Path -LiteralPath $dart -PathType Leaf)) {
        throw 'The reviewed Dart SDK needed to compile the browser native host is unavailable.'
    }

    if (-not (Test-Path -LiteralPath $NativeHostManifestRenderer -PathType Leaf) -or
        -not (Test-Path -LiteralPath $NativeHostLayout -PathType Leaf) -or
        -not (Test-Path -LiteralPath $NativeHostBuilder -PathType Leaf)) {
        throw 'Native-host renderer, layout, or host builder is missing from tools/native_messaging.'
    }

    if (Test-Path -LiteralPath $NativeHostStageDir) {
        Remove-Item -LiteralPath $NativeHostStageDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $NativeHostStageDir | Out-Null
    & $NativeHostBuilder -Output $NativeHostArtifact -DartBin $dart
    if ($LASTEXITCODE -ne 0 -or
        -not (Test-Path -LiteralPath $NativeHostArtifact -PathType Leaf)) {
        throw 'The production browser native host did not compile and self-test.'
    }
    Assert-PeCoffMachine -Path $NativeHostArtifact -Expected $script:WindowsPeMachine

    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        $pythonCommand = Get-Command python3 -ErrorAction Stop
    }

    # Final JSON only. The checked-in manifests/ templates are documentation and
    # are never copied into the payload: a PLACEHOLDER origin would register a
    # host the browser accepts and the extension never reaches.
    $firefoxId = & $pythonCommand.Source $NativeHostLayout recorded-id --browser firefox
    if ($LASTEXITCODE -ne 0 -or -not $firefoxId) {
        throw 'Firefox native-host add-on id could not be read from the pinned source.'
    }
    $firefoxId = ([string]$firefoxId).Trim()
    if ($firefoxId -cne 'companion@winsvpn.org') {
        throw 'Firefox native-host add-on id is not the pinned companion@winsvpn.org identity.'
    }
    & $pythonCommand.Source $NativeHostManifestRenderer --browser firefox `
        --extension-id $firefoxId --host-path 'wins_bridge_host.exe' `
        --allow-relative-host-path --output `
        (Join-Path $NativeHostStageDir 'org.winsvpn.bridge.firefox.json')
    if ($LASTEXITCODE -ne 0) { throw 'Firefox native-host manifest rendering failed.' }

    # Chrome and Edge are registered only when the renderer has a pinned store
    # id for that browser (exit 78 means none is recorded). A browser without an
    # id is skipped with a warning: no manifest is staged and winsvpn.iss writes
    # no registry key for it. Firefox is always required.
    $renderedManifests = @('org.winsvpn.bridge.firefox.json')
    foreach ($browser in @('chrome', 'edge')) {
        $browserManifest = Join-Path $NativeHostStageDir "org.winsvpn.bridge.$browser.json"
        & $pythonCommand.Source $NativeHostManifestRenderer --browser $browser `
            --host-path 'wins_bridge_host.exe' `
            --allow-relative-host-path --output $browserManifest
        if ($LASTEXITCODE -eq 78) {
            if (Test-Path -LiteralPath $browserManifest) {
                throw "$browser native-host renderer reported no pinned store id but left a manifest at $browserManifest."
            }
            Write-Warning "$browser native host is not registered: no pinned $browser store id is recorded."
            continue
        }
        if ($LASTEXITCODE -ne 0) {
            throw "$browser native-host manifest rendering failed."
        }
        $renderedManifests += "org.winsvpn.bridge.$browser.json"
    }

    foreach ($name in $renderedManifests) {
        $manifestPath = Join-Path $NativeHostStageDir $name
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            throw "Native-host manifest $name was not rendered."
        }
        $text = Get-Content -LiteralPath $manifestPath -Raw
        if ($text -match 'placeholder') {
            throw "Refusing to stage native-host manifest $name because it still contains a placeholder."
        }
        if ($name -eq 'org.winsvpn.bridge.firefox.json' -and $text -notmatch 'companion@winsvpn.org') {
            throw 'Firefox native-host manifest is not bound to companion@winsvpn.org.'
        }
    }
}

# Builds the Winn Protocol v3 Windows TUN RELAY into $ReleaseDir, under the
# exact unsuffixed name winn3_supervisor.cpp resolves.
#
# Same contract as Build-WinnDatapathEngine above: dropping the artifact into
# $ReleaseDir is the whole integration. The "{#SourceDir}\*" rule in
# winsvpn.iss installs it to {app}, the recursive product-signing loop
# Authenticode-signs it, and the payload manifest hashes it -- none of which
# need a change here. Must run before the signing loop and before
# Assert-ReleaseInputIndexUnchanged, so it is called immediately after
# Build-WinnDatapathEngine.
#
# The pair was already verified and staged by Build-WinnDatapathEngine. This
# second build hook only revalidates those exact retained identities.
function Build-Winn3RelayEngine {
    try {
        Assert-Winn3PairCustodyUnchanged
        Write-Host "Revalidated the already-staged Winn Protocol v3 pair for $TargetArchitecture."
    } catch {
        Remove-Winn3PairStage
        if ($AllowMissingWinn3Carrier) {
            Write-Warning "Winn v3 pair did not survive revalidation: $($_.Exception.Message)"
            return
        }
        throw
    }
}

# The v3 carrier needs BOTH halves installed beside the application, and the
# datapath half has to actually contain winn/3. Either one missing is inert:
# winn3_supervisor.cpp refuses the start and names the missing image.
#
# THIS GATE IS FATAL, and that is a deliberate change from the "best effort"
# contract the two builders above still keep. Their warnings are diagnostics;
# this is the decision. "The installer built without error" must not be
# indistinguishable from "v3 will work on the installed build" -- that
# equivalence is what shipped Jul 14/16 installers with no v3 in them at all.
#
# Role identity is derived from the compiled Go build-info sections by
# tools\windows_winn3_artifact_provenance.py check-role, and the datapath bytes
# are bound to the signed Winn release manifest. Raw marker strings have no
# authority.
function Write-Winn3CarrierCompleteness {
    $haveDatapath = Test-Path -LiteralPath $WinnEngineArtifact -PathType Leaf
    $haveRelay = Test-Path -LiteralPath $Winn3RelayArtifact -PathType Leaf

    $problems = @()
    if (-not $haveDatapath) {
        $problems += "winn-datapath.exe was not staged in $ReleaseDir"
    }
    if (-not $haveRelay) {
        $problems += "winsvpn_winn3_engine.exe was not staged in $ReleaseDir"
    }
    if ($haveDatapath -and $haveRelay) {
        try {
            Assert-Winn3PairCustodyUnchanged
        } catch {
            $problems += $_.Exception.Message
        }
    } elseif ($null -ne $script:Winn3PairCustody) {
        $problems += 'Winn v3 pair custody exists but one staged artifact is missing.'
    }

    if ($problems.Count -eq 0) {
        Write-Host "Winn Protocol v3 carrier: COMPLETE (release-verified, compiled-role-checked pair is staged in $ReleaseDir)."
        return
    }

    $detail = ($problems | ForEach-Object { "  - $_" }) -join "`n"
    if ($AllowMissingWinn3Carrier) {
        Write-Warning ("Winn Protocol v3 carrier: NOT SHIPPABLE, but -AllowMissingWinn3Carrier was passed, so this build continues and will ship the AmneziaWG/Xray carriers only:`n$detail")
        return
    }
    throw ("Winn Protocol v3 carrier is not shippable:`n$detail`n`n" +
        "The installed build would refuse every v3 server rather than start one. " +
        "Pass -WinnReleaseDir with a signed Winn release that carries both the datapath and " +
        "the relay for the target architecture; the Windows installer has no Go or bash build fallback. " +
        "To ship a Windows release without v3 on purpose, re-run with " +
        "-AllowMissingWinn3Carrier.")
}

# Best-effort staging of the arm64 C++ tunnel-manager service and the arm64
# Winn Protocol v3 Go engine. The Windows installer does not cross-compile
# either component; a later reviewed producer must supply any arm64 inputs.
# Neither needs a Windows host to produce a genuine PE32+ arm64 binary with a
# correct import table -- see
# tools\README_WINDOWS_ELEVATED_VERIFY.md and
# docs\handoff\WINN_V3_SHIP_READINESS_MATRIX_20260804.md Sec.5.2 for how that was
# established, and tools\build_windows_tunnel_service_xcompile.sh's own header
# for exactly which four source files and which flags are used.
#
# THIS DOES NOT PRODUCE A SHIPPABLE ARM64 INSTALLER, and does not try to. The
# Flutter UI target (wins_vpn.exe, i.e. ${BINARY_NAME}) cannot be cross-built
# for windows-arm64 from any host: Flutter's own BuildWindowsCommand
# (packages/flutter_tools/lib/src/commands/build_windows.dart in the Flutter
# SDK) refuses to run at all on a non-Windows host, and even on a Windows x64
# host it selects windows-arm64 only from the CURRENT machine's own
# architecture -- there is no -target-platform override on this command,
# unlike `flutter build apk`. Producing a windows-arm64 Flutter build needs
# literally running `flutter build windows` ON a Windows-on-ARM machine or CI
# runner (e.g. GitHub's windows-11-arm hosted runner -- free for public
# repositories only; a private repository needs a paid arm64 larger-runner or
# a self-hosted arm64 Windows box), which this project does not have today.
# Several vendored third-party dependencies this installer also bundles
# ($VcRedist, $AmneziaWgMsi, $WintunDll, $XrayExe) are additionally only
# present here as x64 binaries; a
# real arm64 release would need arm64-specific, owner-reviewed equivalents of
# every one of them, not only an arm64 Flutter build.
#
# Deliberately never throws, exactly like Build-WinnDatapathEngine above: an
# absent cross-compilation toolchain (clang-cl/lld-link/xwin, or bash on a
# Windows box without Git for Windows) degrades this step to "skipped", never
# to a broken x64 release -- the whole function body runs under its own
# try/catch so even an unexpected exception (not just a nonzero exit) cannot
# escape into the real release flow. Writes only under
# build\windows-arm64-staging, never under $ReleaseDir or $OutputDir, so it
# can never be picked up by the x64 Inno Setup wildcard rule
# ("{#SourceDir}\*") or the product-signing loop below: these binaries are
# unsigned staging artifacts, not release inputs.
function Build-Arm64WinnComponentsBestEffort {
    Write-Host "Skipping optional arm64 Winn component production from the Windows installer; macOS-host producer inputs are target-bound and consumed only by the matching release lane."
}

function Assert-WindowsReleaseArchitecture {
    $osArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    $normalizedHost = switch -Regex ($osArch) {
        '^(?i:X64|Amd64)$' { 'x64' }
        '^(?i:Arm64)$' { 'arm64' }
        default {
            throw "Unsupported Windows host architecture '$osArch'."
        }
    }
    if ($TargetArchitecture -cne $normalizedHost) {
        throw ("A Windows $TargetArchitecture release cannot be produced on a $normalizedHost host. " +
            "Flutter build windows has no target-platform override and selects the current host architecture. " +
            "Mixing $normalizedHost Flutter output with $TargetArchitecture dependencies is refused.")
    }
}

function Assert-StagedReleasePeMachines {
    $expected = $script:WindowsPeMachine
    $required = @(
        (Join-Path $ReleaseDir 'wins_vpn.exe'),
        $TunnelServiceArtifact
    )
    foreach ($path in $required) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required $TargetArchitecture PE is missing: $path"
        }
        Assert-PeCoffMachine -Path $path -Expected $expected
    }
    $optional = @(
        $WinnEngineArtifact,
        $Winn3RelayArtifact,
        $AwgEngineArtifact,
        $NativeHostArtifact,
        (Join-Path $ReleaseDir 'flutter_windows.dll'),
        $WintunDll
    )
    if (-not $StandaloneWinn3Release) {
        $optional += @($XrayExe, $AmneziaWgExe, $AwgToolExe)
    }
    foreach ($path in $optional) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Assert-PeCoffMachine -Path $path -Expected $expected
        }
    }
}

function Assert-WindowsReleaseVersionResources {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [string]$ExpectedFileDescription,
        [string]$ExpectedOriginalFilename
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is missing: $Path"
    }
    $versionInfo = (Get-Item -LiteralPath $Path).VersionInfo
    $productVersion = ([string]$versionInfo.ProductVersion).Trim()
    $fileVersion = ([string]$versionInfo.FileVersion).Trim()
    if ($productVersion -cne $WindowsProductVersion -or
        $fileVersion -cne $WindowsFileVersion) {
        throw "$Label version resources are not exact. ProductVersion=$productVersion FileVersion=$fileVersion ExpectedProductVersion=$WindowsProductVersion ExpectedFileVersion=$WindowsFileVersion"
    }
    if ($ExpectedFileDescription) {
        $fileDescription = ([string]$versionInfo.FileDescription).Trim()
        if ($fileDescription -cne $ExpectedFileDescription) {
            throw "$Label FileDescription is not exact. FileDescription=$fileDescription ExpectedFileDescription=$ExpectedFileDescription"
        }
    }
    if ($ExpectedOriginalFilename) {
        $originalFilename = ([string]$versionInfo.OriginalFilename).Trim()
        if ($originalFilename -cne $ExpectedOriginalFilename) {
            throw "$Label OriginalFilename is not exact. OriginalFilename=$originalFilename ExpectedOriginalFilename=$ExpectedOriginalFilename"
        }
    }
}

function Invoke-WinsPrerequisiteCustodySelfTest {
    $parseErrors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile(
        $PSCommandPath, [ref]$null, [ref]$parseErrors
    )
    if ($parseErrors -and $parseErrors.Count -gt 0) {
        throw ("Windows prerequisite custody self-test parser errors: " +
            ($parseErrors | ForEach-Object { $_.ToString() } | Out-String))
    }
    $sourceText = [IO.File]::ReadAllText($PSCommandPath)
    if ($sourceText -match 'Get-VerifiedDownload -Uri \$VcRedistUrl' -or
        $sourceText -match 'Get-VerifiedDownload -Uri \$AmneziaWgUrl') {
        throw 'Windows prerequisite custody self-test found a VC_redist or AmneziaWG MSI network fetch.'
    }

    $root = Join-Path ([IO.Path]::GetTempPath()) (
        'winsvpn-prereq-custody-' + [guid]::NewGuid().ToString('N')
    )
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    try {
        $payload = [Text.Encoding]::UTF8.GetBytes('winsvpn-prereq-fixture-v1')
        $payloadPath = Join-Path $root 'VC_redist.x64.exe'
        [IO.File]::WriteAllBytes($payloadPath, $payload)
        $digest = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $identity = Get-WinsBoundedRegularFile -Path $payloadPath -Purpose 'self-test payload' -MaximumBytes 4096
        if ($identity.Sha256 -cne $digest -or $identity.SizeBytes -ne $payload.Length) {
            throw 'Bounded regular-file identity did not match the fixture bytes.'
        }

        function Assert-WinsPrerequisiteRefusal {
            param([scriptblock]$Action, [string]$Marker, [string]$Name)
            $refused = $true
            try {
                & $Action
                $refused = $false
            } catch {
                if ($_.Exception.Message -notmatch $Marker) { throw }
            }
            if (-not $refused) {
                throw "Windows prerequisite custody self-test silently skipped $Name."
            }
        }

        # The pin is the in-script SHA-256. Matching bytes pass with no
        # provenance sidecar anywhere, and every mismatch refuses.
        if (Test-Path -LiteralPath "$payloadPath.provenance.json") {
            throw 'Windows prerequisite custody self-test fixture unexpectedly has a provenance sidecar.'
        }
        Assert-WinsPrerequisitePin -Kind 'vc_redist' -ExpectedSha256 $digest `
            -ActualSha256 $identity.Sha256 -ActualSizeBytes $identity.SizeBytes `
            -MaximumBytes 4096

        $corrupt = Join-Path $root 'corrupt.bin'
        [IO.File]::WriteAllBytes($corrupt, $payload)
        $bytes = [IO.File]::ReadAllBytes($corrupt)
        $bytes[$bytes.Length - 1] = ($bytes[$bytes.Length - 1] + 1) % 256
        [IO.File]::WriteAllBytes($corrupt, $bytes)
        $corruptIdentity = Get-WinsBoundedRegularFile -Path $corrupt -Purpose 'one-byte corruption' -MaximumBytes 4096
        Assert-WinsPrerequisiteRefusal -Name 'one-byte-corruption' -Marker 'stale vc_redist prerequisite bytes' -Action {
            Assert-WinsPrerequisitePin -Kind 'vc_redist' -ExpectedSha256 $digest `
                -ActualSha256 $corruptIdentity.Sha256 -ActualSizeBytes $corruptIdentity.SizeBytes `
                -MaximumBytes 4096
        }
        Assert-WinsPrerequisiteRefusal -Name 'uppercase-pin' -Marker 'not lowercase hex' -Action {
            Assert-WinsPrerequisitePin -Kind 'vc_redist' -ExpectedSha256 $digest.ToUpperInvariant() `
                -ActualSha256 $digest.ToUpperInvariant() -ActualSizeBytes $payload.Length `
                -MaximumBytes 4096
        }
        Assert-WinsPrerequisiteRefusal -Name 'oversize' -Marker 'outside the accepted range' -Action {
            Assert-WinsPrerequisitePin -Kind 'vc_redist' -ExpectedSha256 $digest `
                -ActualSha256 $digest -ActualSizeBytes 4097 -MaximumBytes 4096
        }
        Assert-WinsPrerequisiteRefusal -Name 'empty-bytes' -Marker 'outside the accepted range' -Action {
            Assert-WinsPrerequisitePin -Kind 'vc_redist' -ExpectedSha256 $digest `
                -ActualSha256 $digest -ActualSizeBytes 0 -MaximumBytes 4096
        }

        # Full custody path without any sidecar: pinned bytes get past the pin
        # and are then refused by the real VERSIONINFO identity check; wrong
        # bytes are refused by the pin before any metadata is read.
        Assert-WinsPrerequisiteRefusal -Name 'no-sidecar-reaches-metadata' -Marker 'wrong prerequisite version' -Action {
            [void](Assert-WinsEmbeddedPrerequisiteCustody -Kind 'vc_redist' -Path $payloadPath `
                -ExpectedSha256 $digest -ExpectedVersion $VcRedistVersion `
                -ExpectedArchitecture 'x64' -ExpectedFileName 'VC_redist.x64.exe' `
                -ExpectedPublisherPattern $script:WinsVcRedistPublisherPattern `
                -ExpectedOriginalFileName 'VC_redist.x64.exe' `
                -ExpectedProductName $script:WinsVcRedistProductName `
                -MaximumBytes 4096)
        }
        Assert-WinsPrerequisiteRefusal -Name 'full-path-wrong-bytes' -Marker 'stale vc_redist prerequisite bytes' -Action {
            [void](Assert-WinsEmbeddedPrerequisiteCustody -Kind 'vc_redist' -Path $payloadPath `
                -ExpectedSha256 ('0' * 64) -ExpectedVersion $VcRedistVersion `
                -ExpectedArchitecture 'x64' -ExpectedFileName 'VC_redist.x64.exe' `
                -ExpectedPublisherPattern $script:WinsVcRedistPublisherPattern `
                -ExpectedOriginalFileName 'VC_redist.x64.exe' `
                -ExpectedProductName $script:WinsVcRedistProductName `
                -MaximumBytes 4096)
        }

        Assert-WinsPrerequisiteRefusal -Name 'unsigned-authenticode' -Marker 'Authenticode verification failed|verification tooling is unavailable' -Action {
            Assert-WinsPrerequisiteAuthenticodeSigner -Path $payloadPath `
                -PublisherPattern $script:WinsVcRedistPublisherPattern
        }

        $wrongMeta = [pscustomobject]@{
            VersionInfo = [pscustomobject]@{
                FileVersion = '1.2.3.4'
                ProductVersion = '1.2.3.4'
                OriginalFilename = 'VC_redist.arm64.exe'
                ProductName = 'not-the-reviewed-product'
                CompanyName = 'Not Microsoft'
            }
        }
        Assert-WinsPrerequisiteRefusal -Name 'wrong-file-version' -Marker 'wrong prerequisite version' -Action {
            Assert-WinsPrerequisiteVcMetadata -File $wrongMeta `
                -ExpectedVersion $VcRedistVersion -ExpectedArchitecture 'x64' `
                -ExpectedOriginalFileName 'VC_redist.x64.exe' `
                -ExpectedProductName $script:WinsVcRedistProductName
        }
        Assert-WinsPrerequisiteRefusal -Name 'wrong-file-architecture' -Marker 'wrong prerequisite architecture' -Action {
            $archMeta = [pscustomobject]@{
                VersionInfo = [pscustomobject]@{
                    FileVersion = $VcRedistVersion
                    ProductVersion = $VcRedistVersion
                    OriginalFilename = 'VC_redist.arm64.exe'
                    ProductName = $script:WinsVcRedistProductName
                    CompanyName = 'Microsoft Corporation'
                }
            }
            Assert-WinsPrerequisiteVcMetadata -File $archMeta `
                -ExpectedVersion $VcRedistVersion -ExpectedArchitecture 'x64' `
                -ExpectedOriginalFileName 'VC_redist.x64.exe' `
                -ExpectedProductName $script:WinsVcRedistProductName
        }

        Assert-WinsPrerequisiteRefusal -Name 'msi-tooling' -Marker 'verification tooling' -Action {
            Assert-WinsPrerequisiteMsiMetadata -Path $payloadPath `
                -ExpectedVersion $AmneziaWgVersion -ExpectedArchitecture 'x64'
        }

        $linkDir = Join-Path $root 'links'
        New-Item -ItemType Directory -Path $linkDir | Out-Null
        $regular = Join-Path $linkDir 'regular.bin'
        [IO.File]::WriteAllBytes($regular, $payload)
        $symlink = Join-Path $linkDir 'symlink.bin'
        New-Item -ItemType SymbolicLink -Path $symlink -Target $regular | Out-Null
        Assert-WinsPrerequisiteRefusal -Name 'symlink-reparse' -Marker 'reparse point rejected' -Action {
            [void](Get-WinsBoundedRegularFile -Path $symlink -Purpose 'symlink' -MaximumBytes 4096)
        }

        $hard = Join-Path $linkDir 'hard.bin'
        try {
            New-Item -ItemType HardLink -Path $hard -Target $regular -ErrorAction Stop | Out-Null
        } catch {
            & /bin/ln $regular $hard
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $hard)) {
                throw "hardlink fixture could not be created: $($_.Exception.Message)"
            }
        }
        Assert-WinsPrerequisiteRefusal -Name 'hardlink' -Marker 'hardlink refused' -Action {
            [void](Get-WinsBoundedRegularFile -Path $regular -Purpose 'hardlink' -MaximumBytes 4096)
        }

        $swap = Join-Path $linkDir 'swap.bin'
        [IO.File]::WriteAllBytes($swap, $payload)
        [void](Get-WinsBoundedRegularFile -Path $swap -Purpose 'pre-swap' -MaximumBytes 4096)
        Remove-Item -LiteralPath $swap -Force
        New-Item -ItemType SymbolicLink -Path $swap -Target $regular | Out-Null
        Assert-WinsPrerequisiteRefusal -Name 'path-swap-reparse' -Marker 'reparse point rejected' -Action {
            [void](Get-WinsBoundedRegularFile -Path $swap -Purpose 'path-swap' -MaximumBytes 4096)
        }
    } finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host 'WINDOWS EMBEDDED PREREQUISITE CUSTODY SELF-TEST: PASS' -ForegroundColor Green
}

function Invoke-SigningPolicySelfTest {
    $scriptText = Get-Content -LiteralPath $PSCommandPath -Raw
    foreach ($required in @(
        'A self-signed certificate is forbidden for production distribution',
        'verify /pa /all /v /tw',
        'authenticode_leaf_sha256 = $script:AuthenticodeLeafSha256',
        '-ExpectedLeafSha256 $WindowsAuthenticodeLeafPin -Path $Path',
        'timestamp_verified = [bool]$script:AuthenticodeTimestampVerified',
        'PFX command-line signing',
        'The signing timestamp URL must be an exact approved Microsoft/DigiCert RFC 3161 endpoint.',
        'https://evil.example/ts /f C:\pwn.pfx',
        'function New-ProductSignArgumentList',
        'Assert-ApprovedTimestampUrl -Value $signingTimestampUrl'
    )) {
        if (-not $scriptText.Contains($required)) {
            throw "Signing policy self-test contract missing: $required"
        }
    }
    $cases = @(
        @{ Name = 'code-signing'; Oid = '1.3.6.1.5.5.7.3.3'; Accepted = $false },
        @{ Name = 'tls-server'; Oid = '1.3.6.1.5.5.7.3.1'; Accepted = $false }
    )
    foreach ($case in $cases) {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $certificate = $null
        try {
            $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                "CN=Win's VPN Signing Policy Test",
                $rsa,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $oids = [System.Security.Cryptography.OidCollection]::new()
            [void]$oids.Add([System.Security.Cryptography.Oid]::new($case.Oid))
            $request.CertificateExtensions.Add(
                [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids, $false)
            )
            $certificate = $request.CreateSelfSigned(
                [DateTimeOffset]::UtcNow.AddMinutes(-5),
                [DateTimeOffset]::UtcNow.AddDays(1)
            )
            $accepted = $true
            try {
                Assert-CodeSigningCertificate -Certificate $certificate `
                    -SignerPattern "Win's VPN Signing Policy Test" -SourceLabel $case.Name
            } catch {
                $accepted = $false
            }
            if ($accepted -ne $case.Accepted) {
                throw "Signing policy self-test result was wrong for $($case.Name)."
            }
        } finally {
            if ($certificate) { $certificate.Dispose() }
            $rsa.Dispose()
        }
    }
    # Optional Authenticode leaf pin: an absent pin accepts the leaf and
    # reports its SHA-256, a present pin accepts only that exact leaf, and a
    # malformed pin value in the pin file refuses.
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $certificate = $null
    $pinTestDir = Join-Path ([IO.Path]::GetTempPath()) ("winsvpn-leaf-pin-selftest-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $pinTestDir | Out-Null
    try {
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=Win's VPN Leaf Pin Test",
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $certificate = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddMinutes(-5),
            [DateTimeOffset]::UtcNow.AddDays(1)
        )
        $leaf = Get-WinsCertificateSha256 -Certificate $certificate
        if ($leaf -cnotmatch '^[0-9a-f]{64}$') { throw 'Signing policy self-test computed a malformed leaf SHA-256.' }
        if ((Assert-WinsAuthenticodeLeafPin -Certificate $certificate -ExpectedLeafSha256 $null -Path 'self-test') -cne $leaf) {
            throw 'Signing policy self-test: an absent leaf pin did not report the measured leaf.'
        }
        if ((Assert-WinsAuthenticodeLeafPin -Certificate $certificate -ExpectedLeafSha256 $leaf -Path 'self-test') -cne $leaf) {
            throw 'Signing policy self-test: the exact pinned leaf was not accepted.'
        }
        $rejected = $true
        try {
            [void](Assert-WinsAuthenticodeLeafPin -Certificate $certificate -ExpectedLeafSha256 ('0' * 64) -Path 'self-test')
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) { throw 'Signing policy self-test accepted a leaf that does not match the pin.' }
        $absentPinPath = Join-Path $pinTestDir 'absent.json'
        [IO.File]::WriteAllText($absentPinPath, '{"tools":{"go":{"version":"1.27.1"}}}')
        if ($null -ne (Get-WinsAuthenticodeLeafPin -PinPath $absentPinPath)) {
            throw 'Signing policy self-test invented a leaf pin from a pin file without one.'
        }
        $presentPinPath = Join-Path $pinTestDir 'present.json'
        [IO.File]::WriteAllText($presentPinPath, ('{"tools":{"windows_authenticode":{"leaf_sha256":"' + $leaf + '"}}}'))
        if ((Get-WinsAuthenticodeLeafPin -PinPath $presentPinPath) -cne $leaf) {
            throw 'Signing policy self-test did not read tools.windows_authenticode.leaf_sha256.'
        }
        $malformedPinPath = Join-Path $pinTestDir 'malformed.json'
        [IO.File]::WriteAllText($malformedPinPath, ('{"tools":{"windows_authenticode":{"leaf_sha256":"' + $leaf.ToUpperInvariant() + '"}}}'))
        $rejected = $true
        try {
            [void](Get-WinsAuthenticodeLeafPin -PinPath $malformedPinPath)
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) { throw 'Signing policy self-test accepted a malformed leaf pin.' }
    } finally {
        if ($certificate) { $certificate.Dispose() }
        $rsa.Dispose()
        Remove-Item -LiteralPath $pinTestDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host 'WINDOWS AUTHENTICODE LEAF PIN SELF-TEST: PASS'
    $metadataTestDir = Join-Path ([IO.Path]::GetTempPath()) ("winsvpn-artifact-signing-selftest-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $metadataTestDir | Out-Null
    try {
        $validPath = Join-Path $metadataTestDir 'valid.json'
        $invalidTokenPath = Join-Path $metadataTestDir 'token.json'
        $invalidEndpointPath = Join-Path $metadataTestDir 'endpoint.json'
        [IO.File]::WriteAllText($validPath, '{"Endpoint":"https://eus.codesigning.azure.net","CodeSigningAccountName":"winsvpn","CertificateProfileName":"public-release"}')
        [IO.File]::WriteAllText($invalidTokenPath, '{"Endpoint":"https://eus.codesigning.azure.net","CodeSigningAccountName":"winsvpn","CertificateProfileName":"public-release","AccessToken":"forbidden"}')
        [IO.File]::WriteAllText($invalidEndpointPath, '{"Endpoint":"https://example.com","CodeSigningAccountName":"winsvpn","CertificateProfileName":"public-release"}')
        [void](Resolve-ArtifactSigningMetadataPath -Path $validPath)
        foreach ($invalidPath in @($invalidTokenPath, $invalidEndpointPath)) {
            $accepted = $true
            try { [void](Resolve-ArtifactSigningMetadataPath -Path $invalidPath) } catch { $accepted = $false }
            if ($accepted) { throw "Signing policy self-test accepted unsafe Artifact Signing metadata." }
        }
    } finally {
        Remove-Item -LiteralPath $metadataTestDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    # H-4: a release tool must be rejected if it is outside every approved
    # root, or if it lacks a valid Microsoft signature, and a planted
    # WINDOWS_SIGNTOOL/WINS_WINDOWS_ARTIFACT_SIGNING_DLIB value must never
    # surface as the resolved release tool.
    $releaseToolTestRoot = Join-Path ([IO.Path]::GetTempPath()) ("winsvpn-release-tool-selftest-" + [guid]::NewGuid().ToString('N'))
    $approvedToolTestDir = Join-Path $releaseToolTestRoot 'approved-root'
    $rogueToolTestDir = Join-Path $releaseToolTestRoot 'rogue-root'
    New-Item -ItemType Directory -Path $approvedToolTestDir -Force | Out-Null
    New-Item -ItemType Directory -Path $rogueToolTestDir -Force | Out-Null
    try {
        $unsignedInApprovedRoot = Join-Path $approvedToolTestDir 'signtool.exe'
        $unsignedOutsideApprovedRoot = Join-Path $rogueToolTestDir 'signtool.exe'
        [IO.File]::WriteAllText($unsignedInApprovedRoot, 'not a real signed binary')
        [IO.File]::WriteAllText($unsignedOutsideApprovedRoot, 'not a real signed binary')

        $rejected = $true
        try {
            [void](Assert-MicrosoftReleaseTool -Path $unsignedOutsideApprovedRoot -AllowedRoots @($approvedToolTestDir))
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) {
            throw "Signing policy self-test accepted a release tool outside its approved root."
        }

        $rejected = $true
        try {
            [void](Assert-MicrosoftReleaseTool -Path $unsignedInApprovedRoot -AllowedRoots @($approvedToolTestDir))
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) {
            throw "Signing policy self-test accepted a release tool without a valid Microsoft signature."
        }

        $savedWindowsSignTool = $env:WINDOWS_SIGNTOOL
        $savedArtifactDlib = $env:WINS_WINDOWS_ARTIFACT_SIGNING_DLIB
        try {
            $env:WINDOWS_SIGNTOOL = $unsignedOutsideApprovedRoot
            $env:WINS_WINDOWS_ARTIFACT_SIGNING_DLIB = $unsignedOutsideApprovedRoot
            $plantedResolved = (Resolve-Path -LiteralPath $unsignedOutsideApprovedRoot).Path

            $strictSignTool = Find-SignTool -RequireApprovedMicrosoftSignature
            if ($strictSignTool -and $strictSignTool -eq $plantedResolved) {
                throw "Signing policy self-test: release SignTool resolution trusted a planted WINDOWS_SIGNTOOL path."
            }

            $plantedDlibAccepted = $true
            try {
                $dlibResult = Find-ArtifactSigningDlib
                $plantedDlibAccepted = ($dlibResult -eq $plantedResolved)
            } catch {
                $plantedDlibAccepted = $false
            }
            if ($plantedDlibAccepted) {
                throw "Signing policy self-test: Artifact Signing DLIB resolution trusted a planted WINS_WINDOWS_ARTIFACT_SIGNING_DLIB path."
            }
        } finally {
            $env:WINDOWS_SIGNTOOL = $savedWindowsSignTool
            $env:WINS_WINDOWS_ARTIFACT_SIGNING_DLIB = $savedArtifactDlib
        }
    } finally {
        Remove-Item -LiteralPath $releaseToolTestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    # M-3: PFX-file-plus-command-line-password signing must be rejected for
    # a signed release however it is configured, and must not silently fall
    # through to an empty/absent signer selection.
    $savedSignPfx = $env:WINS_WINDOWS_SIGN_PFX
    $savedSignPfxPassword = $env:WINS_WINDOWS_SIGN_PFX_PASSWORD
    try {
        $env:WINS_WINDOWS_SIGN_PFX = Join-Path ([IO.Path]::GetTempPath()) 'winsvpn-selftest-does-not-exist.pfx'
        $env:WINS_WINDOWS_SIGN_PFX_PASSWORD = 'winsvpn-selftest-password'
        $rejected = $true
        try {
            [void](Get-CodeSigningSelector -SignerPattern "Win's VPN")
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) {
            throw "Signing policy self-test accepted PFX command-line signing for a release."
        }
    } finally {
        $env:WINS_WINDOWS_SIGN_PFX = $savedSignPfx
        $env:WINS_WINDOWS_SIGN_PFX_PASSWORD = $savedSignPfxPassword
    }

    foreach ($url in @(
        'https://evil.example/ts',
        'https://evil.example/ts /f C:\pwn.pfx',
        'https://timestamp.digicert.com extra',
        'http://timestamp.digicert.com/evil',
        'http://evil.example'
    )) {
        $rejected = $true
        try {
            Assert-ApprovedTimestampUrl -Value $url
            $rejected = $false
        } catch { $rejected = $true }
        if (-not $rejected) { throw "Signing policy self-test accepted hostile timestamp $url" }
    }
    foreach ($url in $ApprovedTimestampUrls) {
        Assert-ApprovedTimestampUrl -Value $url
    }
    $signArgs = New-ProductSignArgumentList -Timestamp 'http://timestamp.digicert.com' -SignerArguments @('/s','My','/sha1','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA') -Target 'WinsVPN-Setup.exe'
    if ($signArgs -contains '/as' -or $signArgs[$signArgs.Count - 1] -cne 'WinsVPN-Setup.exe') {
        throw 'Signing policy self-test produced a non-exact SignTool sign argv.'
    }
    $rejected = $true
    try {
        [void](New-ProductSignArgumentList -Timestamp 'https://evil.example/ts' -SignerArguments @('/s','My') -Target 'WinsVPN-Setup.exe')
        $rejected = $false
    } catch { $rejected = $true }
    if (-not $rejected) { throw 'Signing policy self-test accepted a hostile timestamp in argv construction.' }
    $rejected = $true
    try {
        Assert-SignToolArgumentList -Arguments @('sign', '/as', 'WinsVPN-Setup.exe')
        $rejected = $false
    } catch { $rejected = $true }
    if (-not $rejected) { throw 'Signing policy self-test accepted appending an additional Authenticode signature.' }

    Write-Host "WINDOWS SIGNING POLICY SELF-TEST: PASS" -ForegroundColor Green
}

if ($SelfTestSigningPolicy) {
    Invoke-SigningPolicySelfTest
    exit 0
}

if ($SelfTestBuildLock) {
    Invoke-BuildLockSelfTest
    exit 0
}

if ($SelfTestWithdrawnMullvadStaging) {
    Invoke-WithdrawnMullvadStagingSelfTest
    exit 0
}

if ($SelfTestPrerequisiteCustody) {
    Invoke-WinsPrerequisiteCustodySelfTest
    exit 0
}

if ($RequireCodeSigning -and $AllowUnsigned) {
    throw "-RequireCodeSigning and -AllowUnsigned cannot be used together."
}
$mustSign = $RequireCodeSigning -or -not $AllowUnsigned
if ($mustSign -and $AllowMissingWinn3Carrier) {
    throw 'A signed Windows release cannot omit the Winn Protocol v3 carrier. Do not pass -AllowMissingWinn3Carrier on a signed build; unsigned local builds may omit v3 only with -AllowUnsigned.'
}
if (-not $mustSign) {
    # Keep explicitly unsigned local output physically and visibly separate
    # from the canonical public candidate name.
    $unsignedInstallerName = if ($DistributionSurface -ceq 'partner-center') {
        "WinsVPN-UNSIGNED-LOCAL-PartnerCenter$installerArchitectureSuffix.exe"
    } else {
        "WinsVPN-UNSIGNED-LOCAL-Setup$installerArchitectureSuffix.exe"
    }
    $CanonicalInstaller = Join-Path $OutputDir $unsignedInstallerName
    $CanonicalPayloadManifest = "$CanonicalInstaller.payload-manifest.json"
}
if ($SkipFlutterBuild -and $mustSign) {
    throw 'A signed Windows release cannot use -SkipFlutterBuild; rebuild with the reviewed Flutter toolchain.'
}
$signTool = $null
$signingArguments = @()
$signingTimestampUrl = $TimestampUrl
$productSignerPattern = $env:WINS_WINDOWS_SIGNER_SUBJECT_REGEX
if ($mustSign) {
    # M-3: fail loud, first, and unconditionally if PFX command-line signing
    # is configured for a signed release, before any other resolution runs.
    if (-not [string]::IsNullOrWhiteSpace(($env:WINS_WINDOWS_SIGN_PFX + '')) -or
        -not [string]::IsNullOrWhiteSpace(($env:WINS_WINDOWS_SIGN_PFX_PASSWORD + ''))) {
        throw "PFX command-line signing (WINS_WINDOWS_SIGN_PFX/WINS_WINDOWS_SIGN_PFX_PASSWORD) is disabled for a signed release. Configure WINS_WINDOWS_ARTIFACT_SIGNING_METADATA or WINS_WINDOWS_SIGN_CERT_SHA1 instead."
    }
    if ([string]::IsNullOrWhiteSpace($productSignerPattern)) {
        throw "WINS_WINDOWS_SIGNER_SUBJECT_REGEX is required for a signed release."
    }
    $artifactMetadata = ($env:WINS_WINDOWS_ARTIFACT_SIGNING_METADATA + '').Trim()
    $thumbprintConfigured = -not [string]::IsNullOrWhiteSpace(($env:WINS_WINDOWS_SIGN_CERT_SHA1 + ''))
    if ($artifactMetadata -and $thumbprintConfigured) {
        throw "Configure Artifact Signing metadata or a certificate-store identity, not both."
    }
    if ($artifactMetadata) {
        $artifactMetadata = Resolve-ArtifactSigningMetadataPath -Path $artifactMetadata
        $artifactDlib = Find-ArtifactSigningDlib
        if (-not $artifactDlib) {
            throw "Microsoft Artifact Signing Client Tools were not found under an approved Program Files root. Install Microsoft.Azure.ArtifactSigningClientTools."
        }
        $signingArguments = @('/dlib', $artifactDlib, '/dmdf', $artifactMetadata)
        $signingTimestampUrl = $ArtifactSigningTimestampUrl
    } else {
        $signingArguments = @(Get-CodeSigningSelector -SignerPattern $productSignerPattern)
    }
    Assert-ApprovedTimestampUrl -Value $signingTimestampUrl
    if ($signingArguments.Count -eq 0) {
        throw "Windows release signing is required. Configure WINS_WINDOWS_ARTIFACT_SIGNING_METADATA or WINS_WINDOWS_SIGN_CERT_SHA1. Use -AllowUnsigned only for a local non-release build."
    }
    # H-4: the release SignTool must resolve only under an approved
    # Windows SDK root and carry a valid Microsoft signature; PATH and
    # WINDOWS_SIGNTOOL are not trusted for this signing-authority call site.
    $signTool = Find-SignTool -RequireApprovedMicrosoftSignature
    if (-not $signTool) {
        throw "SignTool was not found under an approved Windows SDK root. Install the Windows SDK."
    }
} else {
    Write-Warning "Building an explicitly unsigned local installer. Do not publish this artifact."
}

Assert-WindowsReleaseArchitecture

Enter-ReleaseBuildLock
try {
Set-Location $RepoRoot

if ($WinsReleaseDependencyIsolatedStage) {
    $witnessStateDirectory = Join-Path $RepoRoot `
        '.artifacts\windows-installer-witness-state'
    New-Item -ItemType Directory -Force -Path $witnessStateDirectory | Out-Null
    $script:ResolvedReleaseInputIndex = Join-Path $witnessStateDirectory `
        'RELEASE_INPUT_INDEX.json'
    [IO.File]::WriteAllText(
        $script:ResolvedReleaseInputIndex,
        "WINS_RELEASE_DEPENDENCY_NATIVE_BUILD_WITNESS_V1`n",
        [Text.UTF8Encoding]::new($false)
    )
    $script:WindowsBuildReceiptDirectory = Join-Path $witnessStateDirectory `
        'receipts'
    New-Item -ItemType Directory -Path `
        $script:WindowsBuildReceiptDirectory -ErrorAction Stop | Out-Null
} else {
    $script:ResolvedReleaseInputIndex = Resolve-ReleaseInputIndex
    Assert-ReleaseInputIndexUnchanged
}
Assert-EmbeddedEngineRuntimeFreshness
if (-not $SkipFlutterBuild) {
    Assert-ReviewedFlutterToolchain
}
if (-not $WinsReleaseDependencyIsolatedStage) {
    Initialize-WindowsBuildReceipt
}

New-Item -ItemType Directory -Force -Path $OutputDir, $DependenciesDir | Out-Null
Quarantine-CanonicalInstallerOutputs

Assert-ReleaseImageMetadataClean

if (-not $SkipFlutterBuild) {
    foreach ($name in @('DART_DEFINES', 'EXTRA_FRONT_END_OPTIONS', 'EXTRA_GEN_SNAPSHOT_OPTIONS', 'FLUTTER_TARGET')) {
        Remove-Item "Env:$name" -ErrorAction SilentlyContinue
    }
    foreach ($target in @(
        (Join-Path $RepoRoot '.dart_tool\flutter_build'),
        (Join-Path $RepoRoot 'build\flutter_assets'),
        (Join-Path $RepoRoot 'build\native_assets'),
        (Join-Path $RepoRoot 'build\.last_build_id'),
        (Join-Path $RepoRoot 'build\windows'),
        # Flutter regenerates these links during `pub get`. A copied or
        # interrupted cross-platform tree can otherwise retain a real
        # directory where Flutter expects to create a link, causing errno 183
        # before the Windows compile even starts.
        (Join-Path $RepoRoot 'windows\flutter\ephemeral\.plugin_symlinks'),
        (Join-Path $RepoRoot 'linux\flutter\ephemeral\.plugin_symlinks'),
        (Join-Path $RepoRoot 'macos\Flutter\ephemeral\.symlinks'),
        (Join-Path $RepoRoot 'ios\.symlinks')
    )) {
        if (Test-Path -LiteralPath $target) {
            Remove-Item -LiteralPath $target -Recurse -Force
        }
    }
    & $script:FlutterCommand pub get
    if ($LASTEXITCODE -ne 0) { throw 'Flutter dependency resolution failed.' }
    Add-DartPluginRegistrantVirtualPackage
    if (Test-Path -LiteralPath $WindowsSymbolDir) {
        Remove-Item -LiteralPath $WindowsSymbolDir -Recurse -Force
    }
    Initialize-PrivateSymbolDirectory -PrivateRoot $PrivateSymbolsRoot -Path $WindowsSymbolDir
    $winn3PubkeyDefines = Get-Winn3DescriptorPubkeyDefines
    Write-Winn3DescriptorPubkeyStatus -Defines $winn3PubkeyDefines
    $winn3RingSha256 = (& python (Join-Path $RepoRoot 'tools/winn3_descriptor_ring_identity.py') @winn3PubkeyDefines).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Winn3 descriptor ring identity calculation failed.' }
    $expectedWinn3RingSha256 = [string]$env:WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256
    if ($expectedWinn3RingSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
        $expectedWinn3RingSha256.ToLowerInvariant() -cne $winn3RingSha256) {
        throw "Reviewed Winn3 descriptor ring identity mismatch. Computed=$winn3RingSha256"
    }
    $winn3PubkeyDefines += "--dart-define=WINS_WINN3_DESCRIPTOR_RING_SHA256=$winn3RingSha256"
    # Owner ruling 2026-10-24: the Double VPN ciphertext relay ships on every
    # platform. This one command builds both the x64 and the Windows-on-ARM
    # release (Flutter has no target-platform override), so one relay define
    # next to the standalone enable covers both. Keep it out of the middle of
    # the backtick continuation: a comment there ends the command.
    & $script:FlutterCommand build windows --release --no-pub --obfuscate `
        "--split-debug-info=$WindowsSymbolDir" `
        '--extra-gen-snapshot-options=--strip' `
        '--dart-define=WINS_WINN3_ENABLED_PLATFORMS=windows' `
        '--dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=windows' `
        @winn3PubkeyDefines
    if ($LASTEXITCODE -ne 0) { throw 'Windows Flutter release build failed.' }
    & python (Join-Path $RepoRoot 'tools/verify_winn3_ring_artifact.py') `
        $winn3RingSha256 $WindowsAotArtifact
    if ($LASTEXITCODE -ne 0) { throw 'Windows release payload lacks the attested Winn3 ring identity.' }
}
Initialize-PrivateSymbolDirectory -PrivateRoot $PrivateSymbolsRoot -Path $WindowsSymbolDir

if (-not $StandaloneWinn3Release) {
    & $AwgEngineBuilder -Output $AwgEngineArtifact -DeferExecutionGuard `
        -TargetArchitecture $script:WindowsAwgGoArch
    if ($LASTEXITCODE -ne 0) {
        throw 'The pinned LocalSystem-only Windows AWG engine build failed.'
    }
}

# Best-effort: never throws. See Build-WinnDatapathEngine for why. Runs before
# the product-signing loop below so a successfully built engine is
# Authenticode-signed exactly like every other binary in $ReleaseDir.
Build-WinnDatapathEngine

# The v3 carrier's OTHER half. winn3_supervisor.cpp resolves BOTH
# winn-datapath.exe (above) and winsvpn_winn3_engine.exe (here) beside the
# running module, with no fallback for either; staging only the first is what
# produced the "the v3 tun relay is not installed beside this application"
# refusal on every installed build. Same best-effort contract, same position in
# the flow, so the relay is Authenticode-signed by the same loop.
Build-Winn3RelayEngine

# Browser-extension native host. Mandatory for every desktop installer: the
# browser launches this signed executable directly, so a release without it is
# not a browser-capable release. Chrome and Edge registration remain conditional
# on their store-issued IDs; Firefox's add-on ID is already stable and pinned.
Build-BrowserNativeHost

# FATAL as of 2026-08-09, unless -AllowMissingWinn3Carrier is passed. The two
# builders above stay best-effort so their diagnostics reach the log; this is
# the line that decides whether a v3-less installer is allowed to exist. It also
# scans the staged winn-datapath.exe for the winn/3 packages, so a build that
# staged a correctly named image carrying nothing fails here rather than on a
# user's machine.
Write-Winn3CarrierCompleteness
Move-WindowsPayloadDebugSymbolsToPrivateCustody -PayloadRoot $ReleaseDir
Assert-WindowsPayloadContainsNoDebugSymbols -PayloadRoot $ReleaseDir -Label 'Windows release directory'
Remove-WindowsPayloadTestExecutables -PayloadRoot $ReleaseDir
Assert-WindowsPayloadContainsNoTestExecutables -PayloadRoot $ReleaseDir -Label 'Windows release directory'

# Best-effort, and entirely separate from the release surface above: stages
# (does not ship) an arm64 C++ tunnel service + arm64 Winn engine under
# build\windows-arm64-staging. See Build-Arm64WinnComponentsBestEffort's own
# header for exactly what this can and cannot close. Runs after
# Build-WinnDatapathEngine and before the mandatory x64 artifact checks below
# so a missing/broken arm64 toolchain is visibly logged in the same place as
# the other optional Winn step, without being able to affect what those
# mandatory checks see in $ReleaseDir. Native arm64 installer builds skip this
# side-channel: first-party arm64 images belong in $ReleaseDir, not staging.
if ($TargetArchitecture -ceq 'x64') {
    Build-Arm64WinnComponentsBestEffort
}

if (-not (Test-Path (Join-Path $ReleaseDir "wins_vpn.exe"))) {
    throw "Windows release output was not found at $ReleaseDir. Install the Visual Studio Desktop development with C++ workload, then rerun this script."
}
if (-not (Test-Path -LiteralPath $TunnelServiceArtifact -PathType Leaf)) {
    throw "The protected Windows tunnel-manager service was not produced at $TunnelServiceArtifact."
}
Assert-StagedReleasePeMachines
Assert-WindowsReleaseVersionResources -Path (Join-Path $ReleaseDir 'wins_vpn.exe') -Label 'Windows application executable'
if (-not $StandaloneWinn3Release) {
    if (-not (Test-Path -LiteralPath $AwgEngineArtifact -PathType Leaf) -or
        -not (Test-Path -LiteralPath $AwgEngineProvenance -PathType Leaf)) {
        throw 'The pinned Windows AWG engine and its provenance were not produced.'
    }
    $awgEngineEvidence = Get-Content -Raw -LiteralPath $AwgEngineProvenance |
        ConvertFrom-Json
    if ([int]$awgEngineEvidence.schema_version -ne 3 -or
        [string]$awgEngineEvidence.engine_module -cne
            'github.com/amnezia-vpn/amneziawg-go/v3' -or
        [string]$awgEngineEvidence.engine_version -cne
            $AmneziaWgEngineVersion -or
        [string]$awgEngineEvidence.engine_commit -cne
            $AmneziaWgEngineCommit -or
        [string]$awgEngineEvidence.go_version -cne $AmneziaWgGoVersion -or
        [string]$awgEngineEvidence.go_archive_sha256 -cne
            $AmneziaWgGoArchiveSha256 -or
        [string]$awgEngineEvidence.go_mod_sha256 -cne
            $WindowsAwgEngineGoModSha256 -or
        [string]$awgEngineEvidence.go_sum_sha256 -cne
            $WindowsAwgEngineGoSumSha256 -or
        [string]$awgEngineEvidence.target_architecture -cne
            $script:WindowsAwgGoArch -or
        [string]$awgEngineEvidence.build_entrypoint_sha256 -notmatch
            '^[0-9a-f]{64}$' -or
        [string]$awgEngineEvidence.entrypoint_module_migration -cne
            'github.com/amnezia-vpn/amneziawg-go=>github.com/amnezia-vpn/amneziawg-go/v3' -or
        [string]$awgEngineEvidence.execution_guard_status -cne
            'pending_authenticode' -or
        [string]$awgEngineEvidence.unsigned_artifact_sha256 -cne
            (Get-FileHash -Algorithm SHA256 `
                -LiteralPath $AwgEngineArtifact).Hash.ToLowerInvariant() -or
        -not [string]::IsNullOrEmpty([string]$awgEngineEvidence.artifact_sha256) -or
        [int]$awgEngineEvidence.non_system_exit_code -ne 2) {
        throw 'The provisional Windows AWG engine provenance contract is invalid.'
    }
}
$privacyScanner = Join-Path $RepoRoot 'tools\validate_release_artifact_privacy.py'
$python = Get-Command python -ErrorAction Stop
$secretScanDeferral = @(Get-WindowsSecretScanDeferralArguments)
if ($SkipFlutterBuild) {
    & $python.Source $ObfuscationContract verify --platform windows `
        --symbols-dir $WindowsSymbolDir --manifest $WindowsAotObfuscationManifest `
        --artifact $WindowsAotArtifact @secretScanDeferral
} else {
    & $python.Source $ObfuscationContract record --platform windows `
        --symbols-dir $WindowsSymbolDir --manifest $WindowsAotObfuscationManifest `
        --artifact $WindowsAotArtifact @secretScanDeferral
}
if ($LASTEXITCODE -ne 0) {
    throw 'Windows release output lacks exact private Flutter obfuscation evidence.'
}
# SkipRuntimeDownload never fetches VC_redist or the AmneziaWG MSI. Those
# elevated embedded bytes are local files bound to the in-script SHA-256 pins.
$script:WinsVcRedistIdentity = Assert-WinsEmbeddedPrerequisiteCustody `
    -Kind 'vc_redist' `
    -Path $VcRedist `
    -ExpectedSha256 $VcRedistSha256 `
    -ExpectedVersion $VcRedistVersion `
    -ExpectedArchitecture $TargetArchitecture `
    -ExpectedFileName $dependencyNames.VcRedist `
    -ExpectedPublisherPattern $script:WinsVcRedistPublisherPattern `
    -ExpectedOriginalFileName $script:WinsVcRedistOriginalFileName `
    -ExpectedProductName $script:WinsVcRedistProductName `
    -MaximumBytes $script:WinsVcRedistMaxBytes

if ($null -ne $script:Winn3PairCustody) {
    Assert-Winn3PairCustodyUnchanged
    if ($mustSign) {
        Assert-AuthenticodeSigner -Path $WinnEngineArtifact -SignerPattern $productSignerPattern
        Assert-AuthenticodeSigner -Path $Winn3RelayArtifact -SignerPattern $productSignerPattern
    }
}
if ($mustSign) {
    $productBinaries = @(Get-ChildItem -LiteralPath $ReleaseDir -Recurse -File |
        Where-Object {
            $_.Extension -in @(".exe", ".dll") -and
            $_.FullName -cne $WinnEngineArtifact -and
            $_.FullName -cne $Winn3RelayArtifact
        })
    if ($productBinaries.Count -eq 0) {
        throw "No Windows application binaries were found to sign in $ReleaseDir."
    }
    foreach ($binary in $productBinaries) {
        Invoke-ProductSigning -Path $binary.FullName -SigningArguments $signingArguments `
            -SigningTimestampUrl $signingTimestampUrl -SignerPattern $productSignerPattern -SignTool $signTool
    }
}
if ($null -ne $script:Winn3PairCustody) {
    Assert-Winn3PairCustodyUnchanged
    if ($mustSign) {
        Assert-AuthenticodeSigner -Path $WinnEngineArtifact -SignerPattern $productSignerPattern
        Assert-AuthenticodeSigner -Path $Winn3RelayArtifact -SignerPattern $productSignerPattern
    }
}
if (-not $StandaloneWinn3Release) {
    # The AWG engine must never be launched while it is still a newly compiled,
    # unsigned executable. Finalization performs the no-argument LocalSystem
    # guard only after product signing and seals provenance to the signed bytes.
    & $AwgEngineBuilder -Output $AwgEngineArtifact -FinalizeExecutionGuard `
        -TargetArchitecture $script:WindowsAwgGoArch `
        -RequireValidAuthenticode:$mustSign
    if ($LASTEXITCODE -ne 0) {
        throw 'The signed Windows AWG engine execution guard finalization failed.'
    }
    $awgEngineEvidence = Get-Content -Raw -LiteralPath $AwgEngineProvenance |
        ConvertFrom-Json
    if ([int]$awgEngineEvidence.schema_version -ne 3 -or
        [string]$awgEngineEvidence.engine_module -cne
            'github.com/amnezia-vpn/amneziawg-go/v3' -or
        [string]$awgEngineEvidence.engine_version -cne
            $AmneziaWgEngineVersion -or
        [string]$awgEngineEvidence.engine_commit -cne
            $AmneziaWgEngineCommit -or
        [string]$awgEngineEvidence.go_version -cne $AmneziaWgGoVersion -or
        [string]$awgEngineEvidence.go_archive_sha256 -cne
            $AmneziaWgGoArchiveSha256 -or
        [string]$awgEngineEvidence.go_mod_sha256 -cne
            $WindowsAwgEngineGoModSha256 -or
        [string]$awgEngineEvidence.go_sum_sha256 -cne
            $WindowsAwgEngineGoSumSha256 -or
        [string]$awgEngineEvidence.target_architecture -cne
            $script:WindowsAwgGoArch -or
        [string]$awgEngineEvidence.build_entrypoint_sha256 -notmatch
            '^[0-9a-f]{64}$' -or
        [string]$awgEngineEvidence.entrypoint_module_migration -cne
            'github.com/amnezia-vpn/amneziawg-go=>github.com/amnezia-vpn/amneziawg-go/v3' -or
        [string]$awgEngineEvidence.execution_guard_status -cne
            'verified_after_authenticode_phase' -or
        [string]$awgEngineEvidence.artifact_sha256 -cne
            (Get-FileHash -Algorithm SHA256 `
                -LiteralPath $AwgEngineArtifact).Hash.ToLowerInvariant() -or
        [bool]$awgEngineEvidence.authenticode_required -ne [bool]$mustSign -or
        ($mustSign -and [string]$awgEngineEvidence.authenticode_status -cne 'Valid') -or
        [int]$awgEngineEvidence.non_system_exit_code -ne 2) {
        throw 'The finalized Windows AWG engine provenance contract is invalid.'
    }
}
# Smart App Control/WDAC correctly refuses to execute a newly compiled unsigned
# service.  Production signing therefore has to complete before the mandatory
# byte-exact protocol self-test; otherwise a correctly configured signed build
# is blocked before it can reach its signing step.  Unsigned local builds still
# execute this test and fail closed on hosts that enforce signed-code policy.
& $TunnelServiceArtifact --protocol-self-test
if ($LASTEXITCODE -ne 0) {
    throw 'The Windows tunnel-manager protocol self-test failed.'
}
$VcRuntimeVersion = Assert-PinnedVcRedist

if (-not $StandaloneWinn3Release) {
    Ensure-AmneziaWgMsi
    Ensure-XrayRuntime
    Assert-AmneziaWgPayloadSignatures
    Assert-RebuiltAmneziaWgHelper
} else {
    if (-not (Test-FileSha256 -Path $WintunDll -ExpectedSha256 $WintunDllSha256)) {
        throw 'The standalone Winn v3 Wintun runtime is missing or has the wrong SHA-256.'
    }
    Assert-AuthenticodeSigner -Path $WintunDll -SignerPattern 'O=WireGuard LLC'
}
Assert-StagedReleasePeMachines
Move-WindowsPayloadDebugSymbolsToPrivateCustody -PayloadRoot $ReleaseDir
Assert-WindowsPayloadContainsNoDebugSymbols -PayloadRoot $ReleaseDir -Label 'Windows release directory'
Assert-WindowsPayloadContainsNoTestExecutables -PayloadRoot $ReleaseDir -Label 'Windows release directory'

if (Test-Path -LiteralPath $StagedDependenciesDir) {
    Remove-Item -LiteralPath $StagedDependenciesDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $StagedDependenciesDir | Out-Null
$stagedDependencyMap = [ordered]@{}
$stagedDependencyMap[$dependencyNames.VcRedist] = $VcRedist
$stagedDependencyMap['wintun.dll'] = $WintunDll
if (-not $StandaloneWinn3Release) {
    $stagedDependencyMap[$dependencyNames.AmneziaMsi] = $AmneziaWgMsi
    $stagedDependencyMap['amneziawg.exe'] = $AmneziaWgExe
    $stagedDependencyMap['amneziawg.exe.provenance.json'] = $AmneziaWgExeProvenance
    $stagedDependencyMap['awg.exe'] = $AwgToolExe
    $stagedDependencyMap['xray.exe'] = $XrayExe
}
foreach ($entry in $stagedDependencyMap.GetEnumerator()) {
    $destination = Join-Path $StagedDependenciesDir $entry.Key
    if ($entry.Key -ceq $dependencyNames.VcRedist) {
        [void](Copy-WinsExactRegularFile -Source $entry.Value -Destination $destination `
            -Purpose 'staged VC_redist' -MaximumBytes $script:WinsVcRedistMaxBytes)
    } elseif (-not $StandaloneWinn3Release -and $entry.Key -ceq $dependencyNames.AmneziaMsi) {
        [void](Copy-WinsExactRegularFile -Source $entry.Value -Destination $destination `
            -Purpose 'staged AmneziaWG MSI' -MaximumBytes $script:WinsAmneziaWgMsiMaxBytes)
    } else {
        Copy-Item -LiteralPath $entry.Value -Destination $destination -Force
    }
}
Write-Host 'Re-verifying staged dependency bytes against reviewed pins after copy...'
$stagedPinMap = [ordered]@{
    $dependencyNames.VcRedist = $VcRedistSha256
    'wintun.dll' = $WintunDllSha256
}
if (-not $StandaloneWinn3Release) {
    $stagedPinMap[$dependencyNames.AmneziaMsi] = $AmneziaWgSha256
    $stagedPinMap['amneziawg.exe'] = $script:AmneziaWgHelperReviewedSha256
    $stagedPinMap['awg.exe'] = $AwgToolExeSha256
    $stagedPinMap['xray.exe'] = $XrayExeSha256
}
foreach ($name in $stagedPinMap.Keys) {
    $stagedPath = Join-Path $StagedDependenciesDir $name
    $actual = (Get-FileHash -LiteralPath $stagedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $expected = ([string]$stagedPinMap[$name]).ToLowerInvariant()
    if ($actual -cne $expected) {
        throw "Staged dependency $name has SHA-256 $actual after copy; expected $expected. Refusing to sign or package bytes that changed after the pre-copy pin check."
    }
}
Write-Host 'Re-verifying embedded prerequisite custody against the pinned SHA-256 after copy...'
$script:WinsVcRedistIdentity = Assert-WinsEmbeddedPrerequisiteCustody `
    -Kind 'vc_redist' `
    -Path (Join-Path $StagedDependenciesDir $dependencyNames.VcRedist) `
    -ExpectedSha256 $VcRedistSha256 `
    -ExpectedVersion $VcRedistVersion `
    -ExpectedArchitecture $TargetArchitecture `
    -ExpectedFileName $dependencyNames.VcRedist `
    -ExpectedPublisherPattern $script:WinsVcRedistPublisherPattern `
    -ExpectedOriginalFileName $script:WinsVcRedistOriginalFileName `
    -ExpectedProductName $script:WinsVcRedistProductName `
    -MaximumBytes $script:WinsVcRedistMaxBytes
if (-not $StandaloneWinn3Release) {
    $script:WinsAmneziaWgMsiIdentity = Assert-WinsEmbeddedPrerequisiteCustody `
        -Kind 'amneziawg_msi' `
        -Path (Join-Path $StagedDependenciesDir $dependencyNames.AmneziaMsi) `
        -ExpectedSha256 $AmneziaWgSha256 `
        -ExpectedVersion $AmneziaWgVersion `
        -ExpectedArchitecture $TargetArchitecture `
        -ExpectedFileName $dependencyNames.AmneziaMsi `
        -ExpectedPublisherPattern $script:WinsAmneziaWgMsiPublisherPattern `
        -MaximumBytes $script:WinsAmneziaWgMsiMaxBytes
}
if (-not $StandaloneWinn3Release) {
    Assert-WindowsAwgSchema2OwnerPublicationContract `
        -ProvenancePath (Join-Path $StagedDependenciesDir 'amneziawg.exe.provenance.json') `
        -HelperPath (Join-Path $StagedDependenciesDir 'amneziawg.exe') `
        -ExpectedUnsignedSha256 $stagedPinMap['amneziawg.exe'] `
        -ExpectedTarget "windows-$($script:WindowsAwgGoArch)"
}
Assert-InnoStagingContainsNoWithdrawnMullvadPayloads `
    -Roots @($ReleaseDir, $StagedDependenciesDir) `
    -Label 'Windows Inno staging after dependency publish'
if ($StandaloneWinn3Release) {
    & $python.Source $WindowsStandaloneVerifier $ReleaseDir $StagedDependenciesDir
    if ($LASTEXITCODE -ne 0) {
        throw 'Windows standalone-v3 source image failed its payload-content gate.'
    }
}
$stagedAmneziaWgSha256 = $null
if (-not $StandaloneWinn3Release) {
    $stagedAmneziaWg = Join-Path $StagedDependenciesDir 'amneziawg.exe'
    $stagedXray = Join-Path $StagedDependenciesDir 'xray.exe'
    if ($mustSign) {
        Invoke-ProductSigning -Path $stagedAmneziaWg `
            -SigningArguments $signingArguments `
            -SigningTimestampUrl $signingTimestampUrl `
            -SignerPattern $productSignerPattern -SignTool $signTool
        Invoke-ProductSigning -Path $stagedXray -SigningArguments $signingArguments `
            -SigningTimestampUrl $signingTimestampUrl -SignerPattern $productSignerPattern -SignTool $signTool
    }
    $stagedAmneziaWgSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $stagedAmneziaWg
    ).Hash.ToLowerInvariant()
}

$compilerCustody = Bind-WinsInnoCompilerCustody -Architecture $TargetArchitecture
$iscc = [string]$compilerCustody.Path
$script:ReviewedIsccPath = $iscc
$script:InnoCompilerIdentity = $compilerCustody.Identity
if ([string]::IsNullOrWhiteSpace($iscc) -or $null -eq $script:InnoCompilerIdentity) {
    throw 'Inno Setup 7.1.0 compiler identity is absent.'
}
$script:IsccStageDir = Join-Path $OutputDir (
    '.iscc-stage-' + $PID + '-' + [guid]::NewGuid().ToString('N')
)
[void][IO.Directory]::CreateDirectory($script:IsccStageDir)

$innoArguments = @(
    "/DSourceDir=$ReleaseDir",
    "/DDependenciesDir=$StagedDependenciesDir",
    "/DOutputDir=$($script:IsccStageDir)",
    "/DAppVersion=$AppVersion",
    "/DReleaseProductVersion=$WindowsProductVersion",
    "/DReleaseFileVersion=$WindowsFileVersion",
    "/DVcRuntimeMajor=$($VcRuntimeVersion.Major)",
    "/DVcRuntimeMinor=$($VcRuntimeVersion.Minor)",
    "/DVcRuntimeBuild=$($VcRuntimeVersion.Build)",
    "/DVcRuntimeRevision=$($VcRuntimeVersion.Revision)",
    "/DWintunDllSha256=$WintunDllSha256"
)
if ($TargetArchitecture -ceq 'arm64') {
    $innoArguments += '/DArm64Build=1'
}
if (Test-Path -LiteralPath (Join-Path $NativeHostStageDir 'org.winsvpn.bridge.chrome.json')) {
    $innoArguments += '/DEnableChromeNativeHost=1'
}
if (Test-Path -LiteralPath (Join-Path $NativeHostStageDir 'org.winsvpn.bridge.edge.json')) {
    $innoArguments += '/DEnableEdgeNativeHost=1'
}
if ($StandaloneWinn3Release) {
    $innoArguments += '/DStandaloneWinn3Release=1'
} else {
    $innoArguments += "/DAmneziaWgExeSha256=$stagedAmneziaWgSha256"
    $innoArguments += "/DUpstreamAmneziaWgExeSha256=$UpstreamAmneziaWgExeSha256"
    $innoArguments += "/DAwgToolExeSha256=$AwgToolExeSha256"
}
if ($mustSign) {
    # Inno's /S parser requires its $q escape for embedded quotes. Literal
    # quote characters are stripped while parsing the compiler command line.
    $innoSignCommand = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $q' + $InnoSigningWrapper + '$q -TargetFile $f'
    $innoArguments += '/DEnableSigning=1'
    if ($DistributionSurface -ceq 'partner-center') {
        $innoArguments += '/DPartnerCenterCandidate=1'
    }
    $innoArguments += "/Swinsvpn=$innoSignCommand"
} else {
    $innoArguments += '/DAllowUnsignedLocal=1'
}
Move-WindowsPayloadDebugSymbolsToPrivateCustody -PayloadRoot $ReleaseDir
Assert-WindowsPayloadContainsNoDebugSymbols -PayloadRoot $ReleaseDir -Label 'Windows Inno source directory'
Assert-WindowsPayloadContainsNoDebugSymbols -PayloadRoot $StagedDependenciesDir -Label 'Windows staged dependencies'
Assert-WindowsPayloadContainsNoTestExecutables -PayloadRoot $ReleaseDir -Label 'Windows Inno source directory'
Assert-WindowsPayloadContainsNoTestExecutables -PayloadRoot $StagedDependenciesDir -Label 'Windows staged dependencies'
Assert-InnoStagingContainsNoWithdrawnMullvadPayloads `
    -Roots @($ReleaseDir, $StagedDependenciesDir) `
    -Label 'Windows Inno source directory'
Write-Host 'Re-verifying embedded prerequisite custody immediately before ISCC...'
$script:WinsVcRedistIdentity = Assert-WinsEmbeddedPrerequisiteCustody `
    -Kind 'vc_redist' `
    -Path (Join-Path $StagedDependenciesDir $dependencyNames.VcRedist) `
    -ExpectedSha256 $VcRedistSha256 `
    -ExpectedVersion $VcRedistVersion `
    -ExpectedArchitecture $TargetArchitecture `
    -ExpectedFileName $dependencyNames.VcRedist `
    -ExpectedPublisherPattern $script:WinsVcRedistPublisherPattern `
    -ExpectedOriginalFileName $script:WinsVcRedistOriginalFileName `
    -ExpectedProductName $script:WinsVcRedistProductName `
    -MaximumBytes $script:WinsVcRedistMaxBytes
$innoArguments += "/DVcRedistExpectedSha256=$($script:WinsVcRedistIdentity.Sha256)"
$innoArguments += "/DVcRedistExpectedBytes=$($script:WinsVcRedistIdentity.SizeBytes)"
$innoArguments += "/DVcRedistExpectedPublisher=$($script:WinsVcRedistIdentity.Publisher)"
$innoArguments += "/DVcRedistExpectedVersion=$($script:WinsVcRedistIdentity.FileVersion)"
$innoArguments += "/DVcRedistExpectedArchitecture=$($script:WinsVcRedistIdentity.Architecture)"
if (-not $StandaloneWinn3Release) {
    $script:WinsAmneziaWgMsiIdentity = Assert-WinsEmbeddedPrerequisiteCustody `
        -Kind 'amneziawg_msi' `
        -Path (Join-Path $StagedDependenciesDir $dependencyNames.AmneziaMsi) `
        -ExpectedSha256 $AmneziaWgSha256 `
        -ExpectedVersion $AmneziaWgVersion `
        -ExpectedArchitecture $TargetArchitecture `
        -ExpectedFileName $dependencyNames.AmneziaMsi `
        -ExpectedPublisherPattern $script:WinsAmneziaWgMsiPublisherPattern `
        -MaximumBytes $script:WinsAmneziaWgMsiMaxBytes
    $innoArguments += "/DAmneziaWgMsiExpectedSha256=$($script:WinsAmneziaWgMsiIdentity.Sha256)"
    $innoArguments += "/DAmneziaWgMsiExpectedBytes=$($script:WinsAmneziaWgMsiIdentity.SizeBytes)"
    $innoArguments += "/DAmneziaWgMsiExpectedPublisher=$($script:WinsAmneziaWgMsiIdentity.Publisher)"
    $innoArguments += "/DAmneziaWgMsiExpectedVersion=$($script:WinsAmneziaWgMsiIdentity.FileVersion)"
    $innoArguments += "/DAmneziaWgMsiExpectedArchitecture=$($script:WinsAmneziaWgMsiIdentity.Architecture)"
}
$innoArguments += $InnoScript
Write-Host 'Re-verifying exact Inno Setup compiler custody immediately before ISCC...'
if ($null -ne $script:Winn3PairCustody) {
    Assert-Winn3PairCustodyUnchanged
}
$compilerCustody = Bind-WinsInnoCompilerCustody -Architecture $TargetArchitecture
if ([string]$compilerCustody.Path -cne $script:ReviewedIsccPath) {
    throw 'Inno Setup compiler path mutated before compilation.'
}
Assert-WinsInnoCompilerIdentityMatch -Expected $script:InnoCompilerIdentity -Actual $compilerCustody.Identity
$script:InnoCompilerIdentity = $compilerCustody.Identity
$iscc = [string]$compilerCustody.Path
& $iscc @innoArguments
if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed with exit code $LASTEXITCODE." }
if ($null -ne $script:Winn3PairCustody) {
    Assert-Winn3PairCustodyUnchanged
}

$stagedInstallerName = if ($mustSign) {
    if ($DistributionSurface -ceq 'partner-center') {
        "WinsVPN-PartnerCenter$installerArchitectureSuffix.exe"
    } else {
        "WinsVPN-Setup$installerArchitectureSuffix.exe"
    }
} else {
    if ($DistributionSurface -ceq 'partner-center') {
        "WinsVPN-UNSIGNED-LOCAL-PartnerCenter$installerArchitectureSuffix.exe"
    } else {
        "WinsVPN-UNSIGNED-LOCAL-Setup$installerArchitectureSuffix.exe"
    }
}
$stagedInstaller = Join-Path $script:IsccStageDir $stagedInstallerName
if (-not (Test-Path -LiteralPath $stagedInstaller -PathType Leaf) -or
    (Get-Item -LiteralPath $stagedInstaller).Length -lt 1024) {
    throw "Inno Setup finished without a plausible staged installer."
}

if ($mustSign) {
    Assert-ProductSignature -Path $stagedInstaller `
        -SignerPattern $productSignerPattern -SignTool $signTool
}
if ($StandaloneWinn3Release) {
    & $python.Source $WindowsStandaloneVerifier $stagedInstaller
    if ($LASTEXITCODE -ne 0) {
        throw 'Windows standalone-v3 installer failed its archive-content gate.'
    }
}

# The staged installer is not publishable if any shared, native, producer, or
# installer-helper byte changed while Flutter, Go, signing, or ISCC ran.
if (-not $WinsReleaseDependencyIsolatedStage) {
    Assert-ReleaseInputIndexUnchanged
}

if (Test-Path -LiteralPath $CanonicalInstaller) {
    throw "Canonical installer unexpectedly appeared before publication: $CanonicalInstaller"
}
[IO.File]::Move($stagedInstaller, $CanonicalInstaller)
$script:CanonicalInstallerPublishedByThisRun = $true
$installer = $CanonicalInstaller
if ($mustSign) {
    Assert-ProductSignature -Path $installer `
        -SignerPattern $productSignerPattern -SignTool $signTool
}
if ($mustSign) {
    $expectedInstallerDescription = if ($DistributionSurface -ceq 'partner-center') {
        "Win's VPN $TargetArchitecture Partner Center Win32 installer"
    } else {
        "Win's VPN $TargetArchitecture website installer"
    }
    Assert-WindowsReleaseVersionResources -Path $installer -Label 'Windows installer' `
        -ExpectedFileDescription $expectedInstallerDescription `
        -ExpectedOriginalFilename $CanonicalInstallerName
} else {
    Assert-WindowsReleaseVersionResources -Path $installer -Label 'Windows installer'
}
& $python.Source $privacyScanner --artifacts `
    --target $WindowsObfuscationTargetId --artifact $installer @secretScanDeferral
if ($LASTEXITCODE -ne 0) {
    throw 'Final Windows installer failed exact-target hidden-origin/secret-literal privacy validation.'
}

$hash = Get-FileHash $installer -Algorithm SHA256
& $python.Source $ObfuscationContract record --platform windows `
    --symbols-dir $WindowsSymbolDir --manifest $WindowsObfuscationManifest `
    --target-id $WindowsObfuscationTargetId `
    --artifact $installer @secretScanDeferral
if ($LASTEXITCODE -ne 0) {
    throw 'Final Windows installer lacks exact private Flutter obfuscation evidence.'
}
& $python.Source $ObfuscationContract verify --platform windows `
    --symbols-dir $WindowsSymbolDir --manifest $WindowsObfuscationManifest `
    --target-id $WindowsObfuscationTargetId `
    --artifact $installer @secretScanDeferral
if ($LASTEXITCODE -ne 0) {
    throw 'Final Windows installer obfuscation evidence does not match the exact target.'
}
& $python.Source $CustodyTool record --platform windows `
    --symbols-dir $WindowsSymbolDir --artifact $installer
if ($LASTEXITCODE -ne 0) {
    throw 'Windows private-symbol custody manifest creation failed.'
}
& $python.Source $CustodyTool verify --platform windows `
    --symbols-dir $WindowsSymbolDir --artifact $installer
if ($LASTEXITCODE -ne 0) {
    throw 'Windows private-symbol custody integrity verification failed.'
}
$manifestPath = $CanonicalPayloadManifest
$payloadFiles = @(
    Get-ChildItem -LiteralPath $ReleaseDir -Recurse -File
    Get-ChildItem -LiteralPath $StagedDependenciesDir -File
)
$payloadEntries = @(
    $payloadFiles | ForEach-Object {
        $file = if ($_ -is [IO.FileInfo]) { $_ } else { Get-Item -LiteralPath $_ }
        $relative = $file.FullName.Substring($RepoRoot.Path.Length).TrimStart([char[]]@('\', '/')).Replace('\', '/')
        [ordered]@{
            path = $relative
            size = [long]$file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    } | Sort-Object { $_.path }
)
if ($null -ne $script:Winn3PairCustody) {
    Assert-Winn3PairCustodyUnchanged
}
$producerPath = Join-Path $RepoRoot 'installer\windows\build_installer.ps1'
$innoScriptPath = Join-Path $RepoRoot 'installer\windows\winsvpn.iss'
$payloadManifest = [ordered]@{
    schema_version = 3
    target_architecture = $TargetArchitecture
    distribution_surface = $DistributionSurface
    standalone_winn3 = [bool]$StandaloneWinn3Release
    standalone_payload_verified = [bool]$StandaloneWinn3Release
    installer = [ordered]@{
        name = [IO.Path]::GetFileName($installer)
        size = [long](Get-Item -LiteralPath $installer).Length
        sha256 = $hash.Hash.ToLowerInvariant()
    }
    producer = [ordered]@{
        path = 'installer/windows/build_installer.ps1'
        sha256 = (Get-FileHash -LiteralPath $producerPath -Algorithm SHA256).Hash.ToLowerInvariant()
        inno_script_path = 'installer/windows/winsvpn.iss'
        inno_script_sha256 = (Get-FileHash -LiteralPath $innoScriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
        inno_signing_wrapper_path = 'tools/windows_inno_sign.ps1'
        inno_signing_wrapper_sha256 = (Get-FileHash -LiteralPath $InnoSigningWrapper -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    signing = [ordered]@{
        production_signed = [bool]$mustSign
        every_loose_pe_verified = [bool]$mustSign
        staged_xray_product_signed = [bool]($mustSign -and -not $StandaloneWinn3Release)
        inno_setup_and_uninstaller_signed = [bool]$mustSign
        self_signed_certificate_forbidden = $true
    }
    release_input = [ordered]@{
        path = $script:ResolvedReleaseInputIndex.Substring($RepoRoot.Path.Length).TrimStart([char[]]@('\', '/')).Replace('\', '/')
        sha256 = (Get-FileHash -LiteralPath $script:ResolvedReleaseInputIndex -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    toolchain = $script:FlutterIdentity
    inno_compiler = $script:InnoCompilerIdentity
    payload = $payloadEntries
}
$manifestJson = ConvertTo-Json -InputObject $payloadManifest -Depth 6
if ($null -eq $script:InnoCompilerIdentity -or
    [string]$script:InnoCompilerIdentity.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
    [string]$script:InnoCompilerIdentity.install_tree_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
    [string]$script:InnoCompilerIdentity.authenticode_leaf_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
    [string]$script:InnoCompilerIdentity.pin_sha256 -cnotmatch '^[0-9a-f]{64}$') {
    throw 'Windows payload manifest is missing exact Inno Setup compiler identity.'
}
Write-AtomicNewUtf8File -Path $manifestPath -Value ($manifestJson + "`n")
$script:CanonicalManifestPublishedByThisRun = $true
if (-not $WinsReleaseDependencyIsolatedStage) {
    Assert-ReleaseInputIndexUnchanged
}
if ([string]::IsNullOrWhiteSpace($script:WindowsBuildReceiptDirectory)) {
    throw 'Windows formal build receipt state was not initialized.'
}
$compilerReceiptPath = Join-Path $script:WindowsBuildReceiptDirectory 'INNO_COMPILER_RECEIPT.json'
Write-WinsInnoCompilerReceipt -Path $compilerReceiptPath -Identity $script:InnoCompilerIdentity

# A build receipt is useful only while the byte-exact artifact still exists.
# Preserve every fully validated installer automatically so later signing,
# clean-install, rollback, and public-evidence runs cannot silently lose the
# candidate that a receipt names.
$artifactHash = $hash.Hash.ToLowerInvariant()
$preservationParent = Join-Path $RepoRoot ".artifacts\rollback\windows"
$preservationDirectory = Join-Path $preservationParent "$AppVersion+$BuildNumber-$artifactHash"
New-Item -ItemType Directory -Force -Path $preservationDirectory | Out-Null
$preservedInstaller = Join-Path $preservationDirectory ([IO.Path]::GetFileName($installer))
$preservedPayloadManifest = Join-Path $preservationDirectory ([IO.Path]::GetFileName($manifestPath))
$preservedCompilerReceipt = Join-Path $preservationDirectory 'INNO_COMPILER_RECEIPT.json'
foreach ($copy in @(
    [pscustomobject]@{ Source = $installer; Destination = $preservedInstaller },
    [pscustomobject]@{ Source = $manifestPath; Destination = $preservedPayloadManifest },
    [pscustomobject]@{ Source = $compilerReceiptPath; Destination = $preservedCompilerReceipt }
)) {
    if (Test-Path -LiteralPath $copy.Destination -PathType Leaf) {
        $sourceHash = (Get-FileHash -LiteralPath $copy.Source -Algorithm SHA256).Hash
        $destinationHash = (Get-FileHash -LiteralPath $copy.Destination -Algorithm SHA256).Hash
        if ($sourceHash -cne $destinationHash) {
            throw "Immutable Windows artifact preservation collision: $($copy.Destination)"
        }
    } else {
        [IO.File]::Copy($copy.Source, $copy.Destination, $false)
    }
}
$preservationReceiptPath = Join-Path $preservationDirectory 'PRESERVED_ARTIFACT.json'
$preservationReceipt = [ordered]@{
    schema_version = 1
    contract = 'winsvpn-preserved-windows-artifact-v1'
    captured_at_utc = [DateTime]::UtcNow.ToString('o')
    release = "$AppVersion+$BuildNumber"
    production_signed = [bool]$mustSign
    timestamp_verified = [bool]$script:AuthenticodeTimestampVerified
    authenticode_leaf_sha256 = $script:AuthenticodeLeafSha256
    artifact = [ordered]@{
        path = [IO.Path]::GetFileName($preservedInstaller)
        size = [long](Get-Item -LiteralPath $preservedInstaller).Length
        sha256 = $artifactHash
    }
    payload_manifest = [ordered]@{
        path = [IO.Path]::GetFileName($preservedPayloadManifest)
        sha256 = (Get-FileHash -LiteralPath $preservedPayloadManifest -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    producer_sha256 = (Get-FileHash -LiteralPath $producerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    inno_compiler = $script:InnoCompilerIdentity
    publication_authorized = $false
}
$preservationReceiptJson = ConvertTo-Json -InputObject $preservationReceipt -Depth 6
if (Test-Path -LiteralPath $preservationReceiptPath -PathType Leaf) {
    $existingPreservation = Get-Content -LiteralPath $preservationReceiptPath -Raw | ConvertFrom-Json
    if ([string]$existingPreservation.artifact.sha256 -cne $artifactHash -or
        [string]$existingPreservation.payload_manifest.sha256 -cne $preservationReceipt.payload_manifest.sha256 -or
        [string]$existingPreservation.inno_compiler.sha256 -cne [string]$script:InnoCompilerIdentity.sha256 -or
        [string]$existingPreservation.inno_compiler.install_tree_sha256 -cne [string]$script:InnoCompilerIdentity.install_tree_sha256 -or
        [bool]$existingPreservation.production_signed -ne [bool]$mustSign) {
        throw "Immutable Windows preservation receipt collision: $preservationReceiptPath"
    }
} else {
    [IO.File]::WriteAllText(
        $preservationReceiptPath,
        $preservationReceiptJson + "`n",
        [Text.UTF8Encoding]::new($false)
    )
}
if (-not $WinsReleaseDependencyIsolatedStage) {
    Complete-WindowsBuildReceipt
    # Receipt finalization re-verifies the frozen Windows scope, but keep an
    # explicit verification as the final fallible success gate. No source-bound
    # operation may follow it, so a producer cannot return success after inputs
    # changed during preservation or receipt sealing.
    Assert-ReleaseInputIndexUnchanged
}
Write-Host "Created installer: $installer"
Write-Host "SHA256: $($hash.Hash)"
Write-Host "Payload manifest: $manifestPath"
Write-Host "Inno compiler receipt: $compilerReceiptPath"
Write-Host "Preserved exact installer: $preservedInstaller"
if (-not $WinsReleaseDependencyIsolatedStage) {
    Write-Host "Formal Windows build receipt: $script:WindowsBuildReceipt"
}
} catch {
    # Canonical names are transactional, while create-new formal receipts are
    # retained as forensic evidence. A failed run can therefore leave only a
    # build-begin record (or a sealed publication_authorized=false receipt),
    # never a canonical installer that a caller could mistake for success.
    if ($script:CanonicalManifestPublishedByThisRun) {
        Remove-Item -LiteralPath $CanonicalPayloadManifest -Force `
            -ErrorAction SilentlyContinue
    }
    if ($script:CanonicalInstallerPublishedByThisRun) {
        Remove-Item -LiteralPath $CanonicalInstaller -Force `
            -ErrorAction SilentlyContinue
    }
    throw
} finally {
    if ($null -ne $script:Winn3PairCustody) {
        foreach ($name in @('CoreStream', 'RelayStream')) {
            $stream = $script:Winn3PairCustody.$name
            if ($null -ne $stream) { $stream.Dispose() }
        }
        $script:Winn3PairCustody = $null
    }
    if ($script:IsccStageDir -and
        (Test-Path -LiteralPath $script:IsccStageDir)) {
        Remove-Item -LiteralPath $script:IsccStageDir -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
    Exit-ReleaseBuildLock
}
