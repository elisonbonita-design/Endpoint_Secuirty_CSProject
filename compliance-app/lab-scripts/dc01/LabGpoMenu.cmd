@echo off
rem Starts the DC01 Group Policy baseline menu as Administrator (asks for elevation).
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0LabGpoMenu.ps1" %*
pause
