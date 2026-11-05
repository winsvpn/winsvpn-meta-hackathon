@echo off
curl.exe -o NUL -s -w "speed_download=%%{speed_download} bytes/s size=%%{size_download} time_total=%%{time_total} remote_ip=%%{remote_ip}" "https://speed.cloudflare.com/__down?bytes=25000000" > C:\fleet\after_speed.txt 2>&1
echo EXIT_%%ERRORLEVEL%% >> C:\fleet\after_speed.txt
