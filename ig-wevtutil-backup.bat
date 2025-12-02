set "BackupDir=C:\Windows\Temp\ig-windows-baseline\wevtutil"
if not exist "%BackupDir%" (
    mkdir "%BackupDir%"
)
echo Backup & Compress Windows Logs
set SECURITYEVTX     = %BackupDir%\%COMPUTERNAME%-Security-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
set APPLICATIONEVTX  = %BackupDir%\%COMPUTERNAME%-Application-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
set SYSTEMEVTX       = %BackupDir%\%COMPUTERNAME%-System-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
set SYSMONEVTX       = %BackupDir%\%COMPUTERNAME%-Sysmon-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
set POWERSHELLEVTX   = %BackupDir%\%COMPUTERNAME%-PowerShell-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
set POWERSHELLOPEVTX = %BackupDir%\%COMPUTERNAME%-PowerShellOp-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
set DIRECTORYSVCEVTX = %BackupDir%\%COMPUTERNAME%-DirectoryService-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
set DFSREPLICATION   = %BackupDir%\%COMPUTERNAME%-DFSReplication-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
wevtutil epl Security %SECURITYEVTX%
wevtutil epl Application %APPLICATIONEVTX%
wevtutil epl System %SYSTEMEVTX%
wevtutil epl "Microsoft-Windows-Sysmon/Operational" %SYSMONEVTX%
wevtutil epl "Windows PowerShell" %POWERSHELLEVTX%
wevtutil epl "Microsoft-Windows-PowerShell/Operational" %POWERSHELLOPEVTX%
echo Backup Domain Controller Logs
wevtutil epl "Directory Service" %DIRECTORYSVCEVTX%
wevtutil epl "DFS Replication" %DFSREPLICATION%
echo compress with TAR
tar -czvf %SECURITYEVTX%.tar.gz --options gzip:compression-level=9 %SECURITYEVTX%
tar -czvf %APPLICATIONEVTX%.tar.gz --options gzip:compression-level=9 %APPLICATIONEVTX%
tar -czvf %SYSTEMEVTX%.tar.gz --options gzip:compression-level=9 %SYSTEMEVTX%
tar -czvf %SYSMONEVTX%.tar.gz --options gzip:compression-level=9 %SYSMONEVTX%
tar -czvf %POWERSHELLEVTX% --options gzip:compression-level=9 %POWERSHELLEVTX%
tar -czvf %POWERSHELLOPEVTX%.tar.gz --options gzip:compression-level=9 %POWERSHELLOPEVTX%
tar -czvf %DIRECTORYSVCEVTX%.tar.gz --options gzip:compression-level=9 %DIRECTORYSVCEVTX%
tar -czvf %DFSREPLICATION%.tar.gz --options gzip:compression-level=9 %DFSREPLICATION%
