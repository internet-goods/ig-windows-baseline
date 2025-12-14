ECHO Baseline Hosts and other file looking for malicious insertions
echo based on ig-schdtasks-backup.bat
set "BackupDir=C:\Windows\Temp\ig-windows-baseline\copy"
:: Get the current date in YYYY-MM-DD format
for /f "tokens=1-3 delims=/ " %%a in ('date /t') do (
    set "CurrentDate=%%c-%%a-%%b"
)
:: 1. Check if the root backup directory exists, if not, create it
IF NOT EXIST "%BackupDir%" (
    ECHO Creating backup root directory: %BackupDir%
    mkdir "%BackupDir%"
)
copy %WINDIR%\System32\drivers\etc\hosts %BackupDir%\%COMPUTERNAME%-hosts-%CurrentDate%.txt /Y
copy %WINDIR%\win.ini                    %BackupDir%\%COMPUTERNAME%-win.ini-%CurrentDate%.txt /Y
copy %WINDIR%\system.ini                    %BackupDir%\%COMPUTERNAME%-system.ini-%CurrentDate%.txt /Y
echo powershell profiles to investigate
dir C:\Users\*\Documents\WindowsPowerShell\profile.ps1 
