@echo off
chcp 65001 >nul
rem =============================================================
rem  mjbwctl v3 three-stage closed-loop verification
rem  (engine: powershell.exe explicitly - does NOT depend on pwsh on PATH)
rem    verify.cmd            = Stage Pre   (arm switch + backup, then REBOOT)
rem    verify.cmd post       = Stage Post  (after 1st reboot: real exit - assert
rem                            - restore - assert - report)
rem    verify.cmd check      = Stage Check (after 2nd reboot: assert full
rem                            auto-restore - final closed-loop verdict)
rem =============================================================
setlocal
set "PS=powershell.exe"
if /i "%~1"=="post" (
  "%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0verify_roundtrip.ps1" -Stage Post
) else if /i "%~1"=="check" (
  "%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0verify_roundtrip.ps1" -Stage Check
) else (
  "%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0verify_roundtrip.ps1" -Stage Pre
)
echo.
pause
endlocal
