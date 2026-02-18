echo logging baseline
#PowerShell script block logging must be enabled on Windows.</title>
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
#PowerShell Transcription must be enabled on Windows.</title>
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription  /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription  /v EnableTranscripting /t REG_DWORD /d 1 /f
#2108   Administrative Templates: PowerShellCore        Turn on PowerShell Module Logging
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging /t REG_DWORD /d 1 /f
#2109   Administrative Templates: PowerShellCore        Turn on PowerShell Module Logging (PowerShell Policy)
#2110   Administrative Templates: PowerShellCore        Turn on PowerShell Module Logging - Module Names
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v ModuleNames /t REG_DWORD /d * /f
reg add HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v ModuleNames /t REG_DWORD /d * /f
#The Application event log size must be configured to 32768 KB or greater.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application /v MaxSize /t REG_DWORD /d 32768 /f
#The Security event log size must be configured to 1024000 KB or greater.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security /v MaxSize /t REG_DWORD /d 1024000 /f
#The System event log size must be configured to 32768 KB or greater.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System /v MaxSize /t REG_DWORD /d 32768 /f
#1774   Administrative Templates: Windows Components    Event Log Service: Microsoft-Windows-PowerShell/Operational: Specify the maximum log file size (KB)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational" /v MaxSize /t REG_DWORD /d 1073741824 /f
#1775   Administrative Templates: Windows Components    Event Log Service: PowerShellCore/Operational: Specify the maximum log file size (KB) 1GB
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\PowerShellCore-Operational" /v MaxSize /t REG_DWORD /d 1073741824 /f
