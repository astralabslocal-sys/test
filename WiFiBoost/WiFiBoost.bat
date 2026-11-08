@echo off
:: WiFiBoost Launcher - auto-elevates to admin if possible
:: Beta v0.1

title WiFiBoost Launcher

:: Check if already admin
net session >nul 2>&1
if %errorLevel% == 0 goto :RUN_ADMIN

:: Not admin - ask user
echo.
echo  +-------------------------------------------+
echo  :           WiFiBoost v0.1-beta             :
echo  +-------------------------------------------+
echo.
echo  [!] For FULL optimization, admin rights are needed.
echo.
echo  [1]  Re-launch as Administrator (recommended)
echo  [2]  Continue with limited features
echo  [Q]  Quit
echo.
set /p CHOICE="  Choose: "

if /i "%CHOICE%"=="1" goto :ELEVATE
if /i "%CHOICE%"=="2" goto :RUN_USER
if /i "%CHOICE%"=="Q" exit /b 0
goto :RUN_USER

:ELEVATE
:: Re-launch this bat as admin via PowerShell elevation
powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
exit /b 0

:RUN_ADMIN
:RUN_USER
:: Run the main PowerShell script
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0WiFiBoost.ps1"
pause
