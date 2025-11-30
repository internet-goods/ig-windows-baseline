@echo off
ECHO Baseline Hosts file looking for malicious insertions
SET "SourceFile=%SystemRoot%\System32\drivers\etc\hosts"
:: Define the root directory where all backups will be stored
SET "BackupRoot=C:\Windows\Temp\ig-windows-baseline\hosts"
echo based on ig-schdtasks-backup.bat
echo converted by internet-goods.com for baselining scheduled tasks on windows
:: Get the current date in YYYY-MM-DD format
for /f "tokens=1-3 delims=/ " %%a in ('date /t') do (
    set "CurrentDate=%%c-%%a-%%b"
)
:: 1. Check if the root backup directory exists, if not, create it
IF NOT EXIST "%BackupRoot%" (
    ECHO Creating backup root directory: %BackupRoot%
    mkdir "%BackupRoot%"
)
:: 3. Copy the hosts file to the target directory
ECHO Backing up hosts file...
copy "%SourceFile%" "%BackupRoot%"/%COMPUTERNAME%-hosts-%CurrentDate%.txt /Y

IF EXIST "%BackupRoot%\hosts" (
    ECHO Successfully backed up hosts file to: "%BackupRoot%"
) ELSE (
    ECHO ERROR: Failed to copy the hosts file. Ensure script is run with Administrator rights.
)
ECHO Backup process complete.
pause
