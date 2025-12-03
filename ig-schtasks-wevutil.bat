echo Create Internet-Goods Baseline Backup Scheduled tasks to backup logs nightly
set "BackupDir=C:\Windows\Temp\ig-windows-baseline\wevtutil"
if not exist "%BackupDir%" (
    mkdir "%BackupDir%"
)
set SECURITYEVTX     = %BackupDir%\%COMPUTERNAME%-Security-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
set APPLICATIONEVTX  = %BackupDir%\%COMPUTERNAME%-Application-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
set SYSTEMEVTX       = %BackupDir%\%COMPUTERNAME%-System-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
set SYSMONEVTX       = %BackupDir%\%COMPUTERNAME%-Sysmon-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
set POWERSHELLEVTX   = %BackupDir%\%COMPUTERNAME%-PowerShell-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
set POWERSHELLOPEVTX = %BackupDir%\%COMPUTERNAME%-PowerShellOp-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
set DIRECTORYSVCEVTX = %BackupDir%\%COMPUTERNAME%-DirectoryService-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
set DFSREPLICATION   = %BackupDir%\%COMPUTERNAME%-DFSReplication-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
schtasks /create /tn "Nightly Security Log Backup" /tr "wevtutil epl Security %SECURITYEVTX%" /sc daily /st 01:00 /ru SYSTEM /RL HIGHEST /f
schtasks /create /tn "Nightly Application Log Backup" /tr "wevtutil epl Application %APPLICATIONEVTX%" /sc daily /st 01:10 /ru SYSTEM /RL HIGHEST /f
schtasks /create /tn "Nightly Application Log Backup" /tr "wevtutil epl ""Microsoft-Windows-Sysmon/Operational"" %SYSMONEVTX%" /sc daily /st 01:10 /ru SYSTEM /RL HIGHEST /f
schtasks /create /tn "Nightly Powershell Log Backup" /tr "wevtutil epl ""Windows PowerShell"" %POWERSHELLEVTX% /sc daily /st 01:20 /ru SYSTEM /RL HIGHEST /f
schtasks /create /tn "Nightly PowershellOp Log Backup" /tr "wevtutil epl ""Microsoft-Windows-PowerShell/Operational"" %POWERSHELLOPEVTX% /sc daily /st 01:30 /ru SYSTEM /RL HIGHEST /f
schtasks /create /tn "Nightly Directory Service Log Backup" /tr "wevtutil epl ""Directory Service"" %DIRECTORYSVCEVTX% /sc daily /st 01:40 /ru SYSTEM /RL HIGHEST /f
schtasks /create /tn "Nightly DFS Replication Log Backup" /tr "wevtutil epl "DFS Replication" %DFSREPLICATION%" /sc daily /st 01:50 /ru SYSTEM /RL HIGHEST /f
