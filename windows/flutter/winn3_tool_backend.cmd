@ECHO off
REM Append the reviewed Winn3 ring onto DART_DEFINES, then run Flutter's
REM tool_backend.bat. Invoked from windows/flutter/CMakeLists.txt via cmake -E env.
REM %2 is the CMake generator expression $<CONFIG> (Debug/Profile/Release).
setlocal EnableDelayedExpansion

if not defined FLUTTER_ROOT (
  echo winn3_tool_backend: FLUTTER_ROOT is unset 1>&2
  exit /b 1
)
if not defined WINN3_RING_DART_DEFINES (
  echo winn3_tool_backend: WINN3_RING_DART_DEFINES is empty 1>&2
  exit /b 1
)

if defined DART_DEFINES (
  set "DART_DEFINES=!DART_DEFINES!,!WINN3_RING_DART_DEFINES!"
) else (
  set "DART_DEFINES=!WINN3_RING_DART_DEFINES!"
)

if /I "%~2"=="Release" (
  if not defined WINN3_WINDOWS_ENABLED_BLOB (
    echo winn3_tool_backend: WINN3_WINDOWS_ENABLED_BLOB is empty 1>&2
    exit /b 1
  )
  set "DART_DEFINES=!DART_DEFINES!,!WINN3_WINDOWS_ENABLED_BLOB!"
)

call "%FLUTTER_ROOT%\packages\flutter_tools\bin\tool_backend.bat" %*
exit /b %ERRORLEVEL%
