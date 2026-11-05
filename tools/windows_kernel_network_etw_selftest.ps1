[CmdletBinding()]
param([Parameter(Mandatory)][string]$Output)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows_transport_diagnostic_helpers.ps1')
if (-not (Test-WinsAdministrator)) {
    throw 'The Kernel-Network ETW self-test requires elevation.'
}
$outputPath = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $outputPath) {
    throw 'The Kernel-Network ETW self-test output already exists.'
}

function Invoke-BoundedProcess {
    param([Parameter(Mandatory)][string]$FileName,
          [Parameter(Mandatory)][string]$Arguments)
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $FileName
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $psi
    if (-not $process.Start()) { return -1 }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(30000)) {
        try { $process.Kill() } catch {}
        return -2
    }
    $process.ExitCode
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

$session = 'WinsVpnEtwSelfTest-' + [Guid]::NewGuid().ToString('N')
$etl = Join-Path $root 'kernel-network.etl'
$xml = Join-Path $root 'kernel-network.xml'
$logman = Join-Path $env:SystemRoot 'System32\logman.exe'
$tracerpt = Join-Path $env:SystemRoot 'System32\tracerpt.exe'
$started = $false
$server = $null
$client = $null
$matching = @()
$eventShapes = [ordered]@{}
$errorStage = ''
try {
    $startArgs = 'start "' + $session + '" -p ' +
        'Microsoft-Windows-Kernel-Network 0x10 4 -o "' + $etl + '" -ets'
    if ((Invoke-BoundedProcess $logman $startArgs) -ne 0) {
        $errorStage = 'start'
        throw 'The bounded Kernel-Network ETW session did not start.'
    }
    $started = $true
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
    [void]$server.Receive([ref]$remote)
    $response = [byte[]]::new(172)
    [void]$server.Send($response, $response.Length, $remote)
    $replyRemote = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
    [void]$client.Receive([ref]$replyRemote)
    Start-Sleep -Milliseconds 500
    if ((Invoke-BoundedProcess $logman (
                'stop "' + $session + '" -ets')) -ne 0) {
        $errorStage = 'stop'
        throw 'The bounded Kernel-Network ETW session did not stop.'
    }
    $started = $false
    if ((Invoke-BoundedProcess $tracerpt (
                '"' + $etl + '" -o "' + $xml + '" -of XML -y')) -ne 0) {
        $errorStage = 'convert'
        throw 'The bounded Kernel-Network ETW trace did not convert.'
    }
    [xml]$document = Get-Content -LiteralPath $xml -Raw
    foreach ($event in @($document.SelectNodes(
                '//*[local-name()="Event"]'))) {
        $outer = [string]$event.OuterXml
        if ($outer -notmatch '(?:42110|127\.0\.0\.1)') { continue }
        $eventIdNode = $event.SelectSingleNode(
            './*[local-name()="System"]/*[local-name()="EventID"]'
        )
        $eventId = if ($eventIdNode) { [string]$eventIdNode.InnerText } else { '' }
        $data = [ordered]@{}
        foreach ($node in @($event.SelectNodes(
                    './/*[local-name()="EventData"]/*[local-name()="Data"]'))) {
            $name = if ($node.Attributes['Name']) {
                [string]$node.Attributes['Name'].Value
            } else { 'unnamed' }
            $value = [string]$node.InnerText
            if ($name -ceq 'size') {
                $data[$name] = $value
            } elseif ($value -match '^(?:127\.0\.0\.1|42110)$') {
                $data[$name] = $value
            } else {
                $data[$name] = '[other_metadata]'
            }
        }
        $matching += [pscustomobject]@{ event_id = $eventId; data = $data }
        $eventShapes[$eventId] = @($data.Keys)
    }
} catch {
    if (-not $errorStage) { $errorStage = 'parse_or_exchange' }
} finally {
    if ($client) { $client.Dispose() }
    if ($server) { $server.Dispose() }
    if ($started) {
        [void](Invoke-BoundedProcess $logman (
            'stop "' + $session + '" -ets'))
    }
}
$passed = $matching.Count -gt 0
$result = [ordered]@{
    contract = 'winsvpn-windows-kernel-network-etw-selftest-v1'
    provider = 'Microsoft-Windows-Kernel-Network'
    keyword = '0x10'
    level = 4
    payload_capture_enabled = $false
    matching_event_count = $matching.Count
    matching_events = $matching
    event_shapes = $eventShapes
    error_stage = $errorStage
    passed = $passed
}
foreach ($path in @($xml, $etl)) {
    if (Test-Path -LiteralPath $path) {
        try { Remove-Item -LiteralPath $path -Force } catch {}
    }
}
$result.raw_trace_preserved = [bool](
    (Test-Path -LiteralPath $xml) -or (Test-Path -LiteralPath $etl)
)
if (Test-Path -LiteralPath $root -PathType Container) {
    Remove-Item -LiteralPath $root -Recurse -Force
}
$result.temporary_root_deleted = -not (Test-Path -LiteralPath $root)
[IO.File]::WriteAllText(
    $outputPath,
    ($result | ConvertTo-Json -Depth 10) + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false)
)
if (-not $passed -or $result.raw_trace_preserved -or
    -not $result.temporary_root_deleted) {
    throw 'The bounded Kernel-Network ETW self-test failed.'
}
