@echo off
rem Starts the WS01 baseline demo menu as Administrator (asks for elevation).
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0LabBaselineMenu.ps1" %*
pause
