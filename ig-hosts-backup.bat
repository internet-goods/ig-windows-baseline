@echo off
ECHO Baseline Hosts file looking for malicious insertions
echo based on ig-schdtasks-backup.bat
:: Get the current date in YYYY-MM-DD format
for /f "tokens=1-3 delims=/ " %%a in ('date /t') do (
    set "CurrentDate=%%c-%%a-%%b"
)
:: 1. Check if the root backup directory exists, if not, create it
IF NOT EXIST "%BackupRoot%" (
    ECHO Creating backup root directory: %BackupRoot%
    mkdir "%BackupRoot%"
)
copy C:\Windows\Temp\ig-windows-baseline\hosts C:\Windows\Temp\ig-windows-baseline\hosts\%COMPUTERNAME%-hosts-%CurrentDate%.txt /Y
