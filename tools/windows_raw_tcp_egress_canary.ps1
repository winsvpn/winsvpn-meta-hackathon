[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('api.ipify.org','checkip.amazonaws.com')]
    [string]$HostName,
    [string]$BindAddress = '',
    [string]$RemoteAddress = '',
    [ValidateRange(1,30)][int]$TimeoutSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$client = if ([string]::IsNullOrWhiteSpace($BindAddress)) {
    [Net.Sockets.TcpClient]::new()
} else {
    $parsedBindAddress = $null
    if (-not [Net.IPAddress]::TryParse($BindAddress, [ref]$parsedBindAddress) -or
        $parsedBindAddress.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'BIND_ADDRESS_INVALID'
    }
    [Net.Sockets.TcpClient]::new(
        [Net.IPEndPoint]::new($parsedBindAddress, 0)
    )
}
try {
    $connectTarget = $HostName
    if (-not [string]::IsNullOrWhiteSpace($RemoteAddress)) {
        $parsedRemoteAddress = $null
        if (-not [Net.IPAddress]::TryParse(
                $RemoteAddress,
                [ref]$parsedRemoteAddress
            ) -or $parsedRemoteAddress.AddressFamily -ne
                [Net.Sockets.AddressFamily]::InterNetwork) {
            throw 'REMOTE_ADDRESS_INVALID'
        }
        $connectTarget = $parsedRemoteAddress
    }
    $pending = $client.BeginConnect($connectTarget, 80, $null, $null)
    if (-not $pending.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(
                $TimeoutSeconds))) {
        throw 'TCP_CONNECT_TIMEOUT'
    }
    $client.EndConnect($pending)
    $client.ReceiveTimeout = $TimeoutSeconds * 1000
    $client.SendTimeout = $TimeoutSeconds * 1000
    $stream = $client.GetStream()
    $request = [Text.Encoding]::ASCII.GetBytes(
        "GET / HTTP/1.1`r`nHost: $HostName`r`nConnection: close`r`n" +
        "Accept: text/plain`r`n`r`n"
    )
    $stream.Write($request, 0, $request.Length)
    $stream.Flush()
    $buffer = [byte[]]::new(4096)
    $memory = [IO.MemoryStream]::new()
    try {
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $memory.Write($buffer, 0, $read)
            if ($memory.Length -gt 65536) { throw 'HTTP_RESPONSE_TOO_LARGE' }
        }
        $response = [Text.Encoding]::ASCII.GetString($memory.ToArray())
    } finally {
        $memory.Dispose()
    }
    $separator = $response.IndexOf("`r`n`r`n", [StringComparison]::Ordinal)
    if ($separator -lt 0 -or $response -notmatch '^HTTP/1\.[01] 200\b') {
        throw 'HTTP_RESPONSE_INVALID'
    }
    $body = $response.Substring($separator + 4).Trim()
    if ($body -notmatch '^(?:\d{1,3}\.){3}\d{1,3}$' -or
        @(($body -split '\.') | Where-Object { [int]$_ -gt 255 }).Count -ne 0) {
        throw 'HTTP_BODY_INVALID'
    }
    [Console]::Out.Write($body)
} finally {
    $client.Dispose()
}
