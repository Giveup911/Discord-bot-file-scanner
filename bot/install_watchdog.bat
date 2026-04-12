@echo off
echo Installing RatScanner Watchdog scheduled task...
schtasks /create /tn "RatScannerWatchdog" /tr "pythonw \"%~dp0watchdog.py\"" /sc onlogon /rl highest /f
if %errorlevel% equ 0 (
    echo SUCCESS: Watchdog will start at every logon.
    echo Starting watchdog now...
    start "" pythonw "%~dp0watchdog.py"
) else (
    echo FAILED: Run this script as Administrator.
)
pause
