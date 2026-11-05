[CmdletBinding()]
param([Parameter(Mandatory)][string]$Output)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows_transport_diagnostic_helpers.ps1')

if (-not (Test-WinsAdministrator)) {
    throw 'The loopback capture self-test requires elevation.'
}
$outputPath = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $outputPath) {
    throw 'The loopback capture self-test output already exists.'
}
$root = Join-Path $env:LOCALAPPDATA (
    'WinsVPN\TransportProbeSelfTest\' + [Guid]::NewGuid().ToString('D')
)
[void](New-Item -ItemType Directory -Path $root)
$owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($owner, $system)) {
    [void]$acl.AddAccessRule(
        [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
    )
}
$acl.SetOwner($owner)
Set-Acl -LiteralPath $root -AclObject $acl

$state = New-WinsLoopbackCaptureState -PrivateRoot $root -LocalPort 42110
$summary = $null
$server = $null
$client = $null
try {
    Start-WinsLoopbackCapture -State $state
    if (-not $state.started) {
        throw 'The PktMon loopback capture did not start.'
    }
    $server = [Net.Sockets.UdpClient]::new(
        [Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 42110)
    )
    $server.Client.ReceiveTimeout = 3000
    $client = [Net.Sockets.UdpClient]::new(
        [Net.Sockets.AddressFamily]::InterNetwork
    )
    $client.Client.ReceiveTimeout = 3000
    $client.Connect([Net.IPAddress]::Loopback, 42110)
    $initiation = [byte[]]::new(164)
    [void]$client.Send($initiation, $initiation.Length)
    $remote = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
    $received = $server.Receive([ref]$remote)
    if ($received.Length -ne 164) {
        throw 'The deterministic initiation did not reach the self-test socket.'
    }
    $response = [byte[]]::new(172)
    [void]$server.Send($response, $response.Length, $remote)
    $replyRemote = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
    $reply = $client.Receive([ref]$replyRemote)
    if ($reply.Length -ne 172) {
        throw 'The deterministic response did not return to the self-test socket.'
    }
    Start-Sleep -Milliseconds 500
    $summary = Stop-WinsLoopbackCapture -State $state
} finally {
    if ($client) { $client.Dispose() }
    if ($server) { $server.Dispose() }
    if ($null -eq $summary) {
        try { $summary = Stop-WinsLoopbackCapture -State $state } catch {}
    }
    if (Test-Path -LiteralPath $root -PathType Container) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
$passed = $null -ne $summary -and $summary.parse_ok -and
    $summary.awg_initiation_164_seen -and
    $summary.xray_response_172_seen -and
    $summary.response_returned_to_initiating_socket -and
    $summary.raw_capture_delete_verified
$result = [ordered]@{
    contract = 'winsvpn-windows-loopback-capture-selftest-v1'
    deterministic_payload_only = $true
    private_acl_verified = $true
    raw_capture_preserved = $false
    temporary_root_deleted = -not (Test-Path -LiteralPath $root)
    passed = $passed
    summary = $summary
}
[IO.File]::WriteAllText(
    $outputPath,
    ($result | ConvertTo-Json -Depth 8) + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false)
)
if (-not $passed) {
    throw 'The header-only PktMon loopback self-test failed.'
}
