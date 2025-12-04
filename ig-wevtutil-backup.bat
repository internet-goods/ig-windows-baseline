set "BackupDir=C:\Windows\Temp\ig-windows-baseline\wevtutil"
if not exist "%BackupDir%" (
    mkdir "%BackupDir%"
)
IF /I "%1"=="-Full" (
wevtutil epl Security %BackupDir%\%COMPUTERNAME%-Security-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
wevtutil epl Application %BackupDir%\%COMPUTERNAME%-Application-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
wevtutil epl System %BackupDir%\%COMPUTERNAME%-System-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" %BackupDir%\%COMPUTERNAME%-Sysmon-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
wevtutil epl "Windows PowerShell" %BackupDir%\%COMPUTERNAME%-PowerShell-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
wevtutil epl "Microsoft-Windows-PowerShell/Operational" %BackupDir%\%COMPUTERNAME%-PowerShellOp-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
wevtutil epl "Directory Service" %BackupDir%\%COMPUTERNAME%-DirectoryService-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
wevtutil epl "DFS Replication" %BackupDir%\%COMPUTERNAME%-DFSReplication-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx
) ELSE IF /I "%1"=="-24h" (
wevtutil epl Security %BackupDir%\%COMPUTERNAME%-Security-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /ow:true
wevtutil epl Application %BackupDir%\%COMPUTERNAME%-Application-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /ow:true
wevtutil epl System %BackupDir%\%COMPUTERNAME%-System-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /ow:true
wevtutil epl "Microsoft-Windows-Sysmon/Operational" %BackupDir%\%COMPUTERNAME%-Sysmon-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /ow:true
wevtutil epl "Windows PowerShell" %BackupDir%\%COMPUTERNAME%-PowerShell-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /ow:true
wevtutil epl "Microsoft-Windows-PowerShell/Operational" %BackupDir%\%COMPUTERNAME%-PowerShellOp-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /ow:true
wevtutil epl "Directory Service" %BackupDir%\%COMPUTERNAME%-DirectoryService-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /ow:true
wevtutil epl "DFS Replication" %BackupDir%\%COMPUTERNAME%-DFSReplication-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /ow:true
) ELSE (
    ECHO Usage: %~n0 [-Full | -24h]
)
