$ErrorActionPreference = 'Continue'
$Debug = 'C:\src\wins_vpn_build_20260803\build\windows\x64\runner\Debug'
$log = 'C:\fleet\windows-fleet.log'
$step = 'C:\fleet\orchestrator_step.log'
Set-Content -Path $step -Value ('START ' + (Get-Date -Format o))
sc.exe start WinsVpnTunnelManager | Out-Null
Start-Sleep -Seconds 2
Add-Content -Path $step -Value 'SERVICE_STARTED'
Remove-Item $log -Force -ErrorAction SilentlyContinue
Remove-Item 'C:\fleet\windows-fleet.stderr.log' -Force -ErrorAction SilentlyContinue
$p = Start-Process -FilePath "$Debug\wins_vpn.exe" -WorkingDirectory $Debug -RedirectStandardOutput $log -RedirectStandardError 'C:\fleet\windows-fleet.stderr.log' -PassThru
Add-Content -Path $step -Value ('APP_PID=' + $p.Id)
$deadline = (Get-Date).AddSeconds(150)
$accepted = $false
while ((Get-Date) -lt $deadline) {
  if (Test-Path $log) {
    if (Select-String -Path $log -Pattern 'RESULT = native start accepted' -Quiet) { $accepted = $true; break }
  }
  if ($null -eq (Get-Process -Id $p.Id -ErrorAction SilentlyContinue)) { break }
  Start-Sleep -Milliseconds 750
}
Add-Content -Path $step -Value ('ACCEPTED=' + $accepted)
if (-not $accepted) {
  sc.exe query WinsVpnTunnelManager >> $step
  cmd /c route print -4 > C:\fleet\route_notaccepted.txt 2>&1
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  Add-Content -Path $step -Value 'BAILED_NO_ACCEPT'
  exit 1
}
$converged = $false
$deadline2 = (Get-Date).AddSeconds(180)
while ((Get-Date) -lt $deadline2) {
  $awg = & "$Debug\awg.exe" show 2>$null
  $hasTx = $false
  if ($awg) { $hasTx = [bool]($awg | Select-String -Pattern 'transfer:\s*[1-9][0-9]*') }
  $routes = & route.exe print -4 2>$null
  $tunnelRoute = $false
  if ($routes) {
    $tunnelRoute = [bool]($routes | Select-String -Pattern '(0\.0\.0\.0/1|128\.0\.0\.0/1|0\.0\.0\.0/0).*winsvpn')
  }
  if ($hasTx -and $tunnelRoute) { $converged = $true; break }
  Start-Sleep -Seconds 2
}
Add-Content -Path $step -Value ('CONVERGED=' + $converged)
& "$Debug\awg.exe" show > C:\fleet\awg_show_after.txt 2>&1
route.exe print -4 > C:\fleet\route_after.txt 2>&1
cmd /c C:\fleet\after.bat
Add-Content -Path $step -Value 'AFTER_CURL_DONE'
& "$Debug\awg.exe" show winsvpn transfer > C:\fleet\awg_transfer_after.txt 2>&1
& "$Debug\awg.exe" show all > C:\fleet\awg_show_all_after.txt 2>&1
Start-Sleep -Seconds 3
& "$Debug\awg.exe" show winsvpn transfer > C:\fleet\awg_transfer_after2.txt 2>&1
& "$Debug\awg.exe" show > C:\fleet\awg_show_after2.txt 2>&1
Add-Content -Path $step -Value 'COUNTERS_DONE'
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
sc.exe stop WinsVpnTunnelManager | Out-Null
Start-Sleep -Seconds 3
route.exe print -4 > C:\fleet\route_final.txt 2>&1
Add-Content -Path $step -Value ('DONE ' + (Get-Date -Format o))
