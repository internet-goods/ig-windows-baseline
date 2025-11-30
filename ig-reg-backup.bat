@echo off
setlocal
for /f "tokens=1-3 delims=/ " %%a in ('date /t') do (
    set "CurrentDate=%%c-%%a-%%b"
)
set "BackupDir=C:\Windows\Temp\ig-windows-baseline\reg"
if not exist "%BackupDir%" (
    mkdir "%BackupDir%"
    echo Created directory: %BackupDir%
)
REM set "OutputFilePathTXT=%BackupDir%\%COMPUTERNAME%-reg-query-keyname-%CurrentDate%.txt"
echo Exporting HKLM Registry keys...
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSoftwareMicrosoftWindowsCurrentVersionRun-%CurrentDate%.txt"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSoftwareMicrosoftWindowsCurrentVersionRunOnce-%CurrentDate%.txt"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSoftwareMicrosoftWindowsCurrentVersionPoliciesExplorerRun-%CurrentDate%.txt"
reg query HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSoftwareWOW6432NodeMicrosoftWindowsCurrentVersionRun-%CurrentDate%.txt"
reg query HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSoftwareWOW6432NodeMicrosoftWindowsCurrentVersionRunOnce-%CurrentDate%.txt"

endlocal
