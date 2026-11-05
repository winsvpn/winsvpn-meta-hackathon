param(
    [Parameter(Mandatory)][string]$Ssh,
    [Parameter(Mandatory)][string]$Identity,
    [Parameter(Mandatory)][string]$KnownHosts,
    [Parameter(Mandatory)][string]$Hub,
    [Parameter(Mandatory)][string]$RemoteEnvironment,
    [Parameter(Mandatory)][string]$HelperPath,
    [Parameter(Mandatory)][string]$CredentialStore,
    [Parameter(Mandatory)][string]$StdoutPath,
    [Parameter(Mandatory)][string]$StderrPath
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$entropy = [Text.Encoding]::UTF8.GetBytes('WinsVPN.B661CoreObserver.v1')
$cipher = $plain = $null
$password = ''
try {
    $cipher = [IO.File]::ReadAllBytes($CredentialStore)
    $plain = [Security.Cryptography.ProtectedData]::Unprotect(
        $cipher, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $password = [Text.Encoding]::UTF8.GetString($plain)
    if ([string]::IsNullOrWhiteSpace($password) -or $password.Length -gt 256) {
        throw 'Protected Core observer credential is invalid.'
    }
    $helper = [IO.File]::ReadAllBytes($HelperPath)
    $encoded = [Convert]::ToBase64String($helper)
    $remote = "$RemoteEnvironment WINS_CORE_SUDO_STDIN=1 python3 -c 'import base64;exec(base64.b64decode(`"$encoded`"))'"
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Ssh
    foreach ($argument in @(
        '-i', $Identity, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=12',
        '-o', 'ConnectionAttempts=1', '-o', 'StrictHostKeyChecking=yes',
        '-o', "UserKnownHostsFile=$KnownHosts", '-o', 'GlobalKnownHostsFile=NUL',
        '-o', 'UpdateHostKeys=no', $Hub, $remote
    )) { [void]$psi.ArgumentList.Add($argument) }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $psi
    if (-not $process.Start()) { throw 'Core observer SSH process did not start.' }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.WriteLine($password)
    $process.StandardInput.Close()
    $process.WaitForExit()
    [IO.File]::WriteAllText($StdoutPath, $stdout.Result, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($StderrPath, $stderr.Result, [Text.UTF8Encoding]::new($false))
    exit $process.ExitCode
}
finally {
    $password = ''
    if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
    if ($cipher) { [Array]::Clear($cipher, 0, $cipher.Length) }
}
