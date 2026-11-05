[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RunRoot,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedGuiSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedVerifierSha256,
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-21-(\d+-){3}\d+$')]
    [string]$TargetUserSid,
    [Parameter(Mandatory)][ValidateRange(1, 255)][int]$TargetSessionId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RunRoot = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
$runLeaf = Split-Path -Leaf $RunRoot
$allowedRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramData 'WinsVPN\PreFreezeMatrix')
).TrimEnd('\') + '\'
$gui = Join-Path $env:ProgramFiles 'WinsVPN\wins_vpn.exe'
$verifier = Join-Path $PSScriptRoot `
    'windows_prefreeze_interactive_gui_verify.ps1'
$watchdogTask = "WinsVPN-PreFreeze-Watchdog-$runLeaf"
$mainTask = "WinsVPN-PreFreeze-Case-$runLeaf"
$launchTask = "WinsVPN-PreFreeze-RecoverGUI-$runLeaf"
$verifyTask = "WinsVPN-PreFreeze-VerifyGUI-$runLeaf"
$watchdogReceipt = Join-Path $RunRoot 'watchdog-receipt.json'
$proofPath = Join-Path $RunRoot 'recovery-gui-proof.json'
$ExpectedGuiSha256 = $ExpectedGuiSha256.ToUpperInvariant()
$ExpectedVerifierSha256 = $ExpectedVerifierSha256.ToUpperInvariant()

if (-not ($RunRoot + '\').StartsWith(
        $allowedRoot, [StringComparison]::OrdinalIgnoreCase
    ) -or $runLeaf -notmatch '^[0-9a-f]{32}$' -or
    [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne
        $TargetUserSid -or
    (Get-FileHash -LiteralPath $gui -Algorithm SHA256).Hash -cne
        $ExpectedGuiSha256 -or
    (Get-FileHash -LiteralPath $verifier -Algorithm SHA256).Hash -cne
        $ExpectedVerifierSha256) {
    throw 'The recovery boundary, identity, or exact payload changed.'
}
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    $verifier, [ref]$tokens, [ref]$errors
) | Out-Null
if (@($errors).Count -ne 0 -or
    -not (Test-Path -LiteralPath $watchdogReceipt -PathType Leaf)) {
    throw 'The verifier or completed watchdog evidence is invalid.'
}
$watchdog = Get-ScheduledTask -TaskName $watchdogTask -ErrorAction Stop
if ($watchdog.State -eq 'Running') {
    throw 'The watchdog still owns recovery.'
}
Unregister-ScheduledTask -TaskName $watchdogTask -Confirm:$false
if (Get-ScheduledTask -TaskName @($mainTask, $launchTask, $verifyTask) `
        -ErrorAction SilentlyContinue) {
    throw 'An unexpected case/recovery task exists.'
}
if (@(Get-Process wins_vpn -ErrorAction SilentlyContinue).Count -ne 0) {
    throw 'A GUI process unexpectedly exists before recovery.'
}

$targetUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (
    [TimeSpan]::Zero
) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$action = New-ScheduledTaskAction -Execute $gui
$principal = New-ScheduledTaskPrincipal -UserId $targetUser `
    -LogonType Interactive -RunLevel Limited
try {
    Register-ScheduledTask -TaskName $launchTask -Action $action `
        -Principal $principal -Settings $settings | Out-Null
    $registered = Get-ScheduledTask -TaskName $launchTask
    $xml = Export-ScheduledTask -TaskName $launchTask
    if ([string]$registered.Principal.LogonType -cne 'Interactive' -or
        [string]$registered.Principal.RunLevel -cne 'Limited' -or
        [string]$registered.Actions[0].Execute -cne $gui -or
        $xml -notmatch '<LogonType>InteractiveToken</LogonType>' -or
        $xml -notmatch (
            '<UserId>' + [regex]::Escape($TargetUserSid) + '</UserId>'
        )) {
        throw 'Recovery GUI task semantic integrity mismatch.'
    }
    Start-ScheduledTask -TaskName $launchTask
    $limit = [DateTime]::UtcNow.AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 250
        $processes = @(Get-Process wins_vpn -ErrorAction SilentlyContinue |
            Where-Object {
                if ($_.SessionId -ne $TargetSessionId) { return $false }
                try {
                    (Get-FileHash -LiteralPath $_.Path -Algorithm SHA256).Hash `
                        -ceq $ExpectedGuiSha256
                } catch { $false }
            })
    } while ($processes.Count -ne 1 -and [DateTime]::UtcNow -lt $limit)
    if ($processes.Count -ne 1 -or -not $processes[0].Responding) {
        throw 'The exact GUI did not start responsively in the target session.'
    }
} finally {
    Unregister-ScheduledTask -TaskName $launchTask -Confirm:$false `
        -ErrorAction SilentlyContinue
}

$verifyArguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
    '-File "' + $verifier + '" -ExpectedGuiSha256 ' +
    $ExpectedGuiSha256 + ' -ExpectedSessionId ' + $TargetSessionId +
    ' -OutputPath "' + $proofPath + '"'
$verifyAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument $verifyArguments
$verifyPrincipal = New-ScheduledTaskPrincipal -UserId $targetUser `
    -LogonType Interactive -RunLevel Highest
$verifySettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (
    New-TimeSpan -Seconds 45
) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
try {
    Register-ScheduledTask -TaskName $verifyTask -Action $verifyAction `
        -Principal $verifyPrincipal -Settings $verifySettings | Out-Null
    $registered = Get-ScheduledTask -TaskName $verifyTask
    if ([string]$registered.Principal.LogonType -cne 'Interactive' -or
        [string]$registered.Principal.RunLevel -cne 'Highest') {
        throw 'The verifier task principal is invalid.'
    }
    Start-ScheduledTask -TaskName $verifyTask
    $limit = [DateTime]::UtcNow.AddSeconds(20)
    do { Start-Sleep -Milliseconds 250 }
    while (-not (Test-Path -LiteralPath $proofPath) -and
        [DateTime]::UtcNow -lt $limit)
    if (-not (Test-Path -LiteralPath $proofPath)) {
        throw 'The Session 1 GUI proof was not written.'
    }
    $proof = Get-Content -LiteralPath $proofPath -Raw | ConvertFrom-Json
    if (-not $proof.verified -or -not $proof.normal_token -or
        -not $proof.exact_visible_flutter_window) {
        throw 'The Session 1 GUI proof failed.'
    }
} finally {
    Unregister-ScheduledTask -TaskName $verifyTask -Confirm:$false `
        -ErrorAction SilentlyContinue
}

[ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-prefreeze-gui-recovery-v1'
    recovered = $true
    verifier_sha256 = (
        Get-FileHash -LiteralPath $verifier -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    proof = $proof
    watchdog_task_removed = $null -eq (
        Get-ScheduledTask -TaskName $watchdogTask -ErrorAction SilentlyContinue
    )
    launch_task_removed = $null -eq (
        Get-ScheduledTask -TaskName $launchTask -ErrorAction SilentlyContinue
    )
    verifier_task_removed = $null -eq (
        Get-ScheduledTask -TaskName $verifyTask -ErrorAction SilentlyContinue
    )
    secret_material_redacted = $true
} | ConvertTo-Json -Depth 8 -Compress
