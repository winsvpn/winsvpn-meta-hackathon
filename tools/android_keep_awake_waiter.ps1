[CmdletBinding()]
param(
    [string]$Adb = 'adb',
    [string]$StatusFile = '',
    [ValidateRange(2, 300)]
    [int]$PollSeconds = 5
)

$ErrorActionPreference = 'Continue'

function Get-AuthorizedAndroidSerials {
    $lines = & $Adb devices 2>$null
    @(
        $lines |
            Select-Object -Skip 1 |
            ForEach-Object {
                if ($_ -match '^([^\s]+)\s+device(?:\s|$)') {
                    $Matches[1]
                }
            }
    )
}

function Get-PairedWirelessAndroidEndpoints {
    $lines = & $Adb mdns services 2>$null
    @(
        $lines |
            ForEach-Object {
                if ($_ -match '^\S+\s+_adb-tls-connect\._tcp\s+([^\s]+:\d+)\s*$') {
                    $Matches[1]
                }
            } |
            Sort-Object -Unique
    )
}

function Test-TcpEndpoint {
    param([Parameter(Mandatory)][string]$Endpoint)

    if ($Endpoint -notmatch '^(.+):(\d+)$') {
        return $false
    }

    $client = [Net.Sockets.TcpClient]::new()
    try {
        $pending = $client.ConnectAsync($Matches[1], [int]$Matches[2])
        if (-not $pending.Wait(1500)) {
            return $false
        }
        return $client.Connected
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function Connect-SinglePairedWirelessAndroid {
    # ADB TLS accepts this connection only when this computer already owns the
    # phone's pairing key. Refuse ambiguous discovery instead of choosing a
    # device merely because it advertises on the same LAN.
    $endpoints = @(Get-PairedWirelessAndroidEndpoints)
    if ($endpoints.Count -ne 1 -or -not (Test-TcpEndpoint -Endpoint $endpoints[0])) {
        return
    }

    & $Adb connect $endpoints[0] 2>$null | Out-Null
}

function Write-WaiterStatus {
    param(
        [Parameter(Mandatory)][string]$State,
        [string]$Serial = '',
        [string]$StayOnWhilePluggedIn = '',
        [string]$Message = ''
    )

    if ([string]::IsNullOrWhiteSpace($StatusFile)) {
        return
    }

    $parent = Split-Path -Parent $StatusFile
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Force $parent | Out-Null
    }

    [ordered]@{
        timestampUtc = [DateTimeOffset]::UtcNow.ToString('o')
        state = $State
        serial = $Serial
        stayOnWhilePluggedIn = $StayOnWhilePluggedIn
        message = $Message
    } | ConvertTo-Json | Set-Content -LiteralPath $StatusFile -Encoding utf8
}

$lastConfiguredSerial = ''
Write-WaiterStatus -State 'waiting' -Message 'Waiting for exactly one authorized Android device.'

while ($true) {
    try {
        $serials = @(Get-AuthorizedAndroidSerials)
        if ($serials.Count -eq 0) {
            Connect-SinglePairedWirelessAndroid
            $serials = @(Get-AuthorizedAndroidSerials)
        }
        if ($serials.Count -eq 1) {
            $serial = $serials[0]
            if ($serial -ne $lastConfiguredSerial) {
                & $Adb -s $serial shell svc power stayon true 2>$null | Out-Null
                & $Adb -s $serial shell settings put global stay_on_while_plugged_in 7 2>$null | Out-Null
                & $Adb -s $serial shell input keyevent 224 2>$null | Out-Null
                $configured = (& $Adb -s $serial shell settings get global stay_on_while_plugged_in 2>$null | Out-String).Trim()
                if ($LASTEXITCODE -eq 0 -and $configured -eq '7') {
                    $lastConfiguredSerial = $serial
                    Write-WaiterStatus -State 'configured' -Serial $serial -StayOnWhilePluggedIn $configured -Message 'Android stays awake while connected to USB, AC, or wireless power.'
                } else {
                    $lastConfiguredSerial = ''
                    Write-WaiterStatus -State 'retrying' -Serial $serial -StayOnWhilePluggedIn $configured -Message 'The Android stay-awake setting was not confirmed.'
                }
            }
        } else {
            $lastConfiguredSerial = ''
            $message = if ($serials.Count -eq 0) {
                'No authorized Android device is currently visible to ADB.'
            } else {
                'More than one authorized Android device is visible; refusing to choose one automatically.'
            }
            Write-WaiterStatus -State 'waiting' -Message $message
        }
    } catch {
        $lastConfiguredSerial = ''
        Write-WaiterStatus -State 'retrying' -Message $_.Exception.Message
    }

    Start-Sleep -Seconds $PollSeconds
}
