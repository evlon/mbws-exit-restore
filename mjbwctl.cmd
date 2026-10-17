@echo off
rem ============================================================
rem  mjbwctl.cmd - MiBaoWeiShi controller launcher
rem  Double-click: requests UAC, then opens the Chinese menu.
rem  (Chinese UI lives inside mjbwctl.ps1; keep this file ASCII.)
rem ============================================================
setlocal
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%~dp0mjbwctl.ps1\" -Interactive'"
    exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0mjbwctl.ps1" -Interactive
echo.
pause
endlocal
