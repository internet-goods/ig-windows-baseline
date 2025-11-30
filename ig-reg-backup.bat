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

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSoftwareMicrosoftWindowsCurrentVersionRun-%CurrentDate%.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSoftwareMicrosoftWindowsCurrentVersionRunOnce-%CurrentDate%.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSoftwareMicrosoftWindowsCurrentVersionPoliciesExplorerRun-%CurrentDate%.txt
reg query HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSoftwareWOW6432NodeMicrosoftWindowsCurrentVersionRun-%CurrentDate%.txt
reg query HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSoftwareWOW6432NodeMicrosoftWindowsCurrentVersionRunOnce-%CurrentDate%.txt
echo Winlogon and Session Manager Keys (System Boot/Logon)
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSoftwareMicrosoftWindowsNTCurrentVersionWinlogonUserinit-%CurrentDate%.txt
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"    > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSoftwareMicrosoftWindowsNTCurrentVersionWinlogonShell-%CurrentDate%.txt
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"    > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSoftwareMicrosoftWindowsNTCurrentVersionWinlogonNotify-%CurrentDate%.txt
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GpExtensions"    > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSoftwareMicrosoftWindowsNTCurrentVersionWinlogonGpExtensions-%CurrentDate%.txt
reg query "HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute" > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSystemCurrentControlSetControlSessionManagerBootExecute-%CurrentDate%.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls" > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSOFTWAREMicrosoftWindowsNTCurrentVersionWindowsAppinit_Dlls-%CurrentDate%.txt
echo shell hijacking
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSOFTWAREMicrosoftWindowsCurrentVersionExplorerShellFolders-%CurrentDate%.txt
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions" > %BackupDir%\%COMPUTERNAME%-reg-query-HKLMSOFTWAREMicrosoftWindowsCurrentVersionExplorerShellExtensions-%CurrentDate%.txt
REM HKCU\Software\Microsoft\Windows\CurrentVersion\Shell Extensions

echo TBD HKCU Registry Key extraction method reg save
REM HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load

endlocal
