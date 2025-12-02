set "BackupDir=C:\Windows\Temp\ig-windows-baseline\wevtutil"
if not exist "%BackupDir%" (
    mkdir "%BackupDir%"
)
echo Backup Windows Logs
wevtutil epl Security %BackupDir%\%COMPUTERNAME%-Security-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
wevtutil epl Application %BackupDir%\%COMPUTERNAME%-Application-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
wevtutil epl System %BackupDir%\%COMPUTERNAME%-System-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" %BackupDir%\%COMPUTERNAME%-Sysmon-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
wevtutil epl "Windows PowerShell" %BackupDir%\%COMPUTERNAME%-Powershell-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
wevtutil epl "Microsoft-Windows-PowerShell/Operational" %BackupDir%\%COMPUTERNAME%-PowershellOperational-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
echo Backup Domain Controller Logs
wevtutil epl "Directory Service" %BackupDir%\%COMPUTERNAME%-DirectoryService-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
wevtutil epl "DFS Replication" %BackupDir%\%COMPUTERNAME%-DFSReplication-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
