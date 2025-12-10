set "BackupDir=C:\Windows\Temp\ig-windows-baseline\wevtutil\%date:~4,2%%date:~7,2%%date:~10,4%"
echo Extract the Days logs into %BackupDir%
if not exist "%BackupDir%" (
    mkdir "%BackupDir%"
)
IF /I "%1"=="-24h" (
wevtutil epl Security %BackupDir%\%COMPUTERNAME%-Security24h-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /ow:true
wevtutil epl Application %BackupDir%\%COMPUTERNAME%-Application24h-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /ow:true
wevtutil epl System %BackupDir%\%COMPUTERNAME%-System24h-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /ow:true
wevtutil epl "Microsoft-Windows-Sysmon/Operational" %BackupDir%\%COMPUTERNAME%-Sysmon24h-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /ow:true
wevtutil epl "Windows PowerShell" %BackupDir%\%COMPUTERNAME%-PowerShell24h-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /ow:true
wevtutil epl "Microsoft-Windows-PowerShell/Operational" %BackupDir%\%COMPUTERNAME%-PowerShellOp24h-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /ow:true
wevtutil epl "Directory Service" %BackupDir%\%COMPUTERNAME%-DirectoryService24h-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /ow:true
wevtutil epl "DFS Replication" %BackupDir%\%COMPUTERNAME%-DFSReplication24h-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]" /ow:true
) ELSE (
wevtutil epl Security %BackupDir%\%COMPUTERNAME%-Security-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.evtx
wevtutil epl Application %BackupDir%\%COMPUTERNAME%-Application-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.evtx
wevtutil epl System %BackupDir%\%COMPUTERNAME%-System-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" %BackupDir%\%COMPUTERNAME%-Sysmon-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.evtx
wevtutil epl "Windows PowerShell" %BackupDir%\%COMPUTERNAME%-PowerShell-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.evtx
wevtutil epl "Microsoft-Windows-PowerShell/Operational" %BackupDir%\%COMPUTERNAME%-PowerShellOp-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.evtx
wevtutil epl "Directory Service" %BackupDir%\%COMPUTERNAME%-DirectoryService-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.evtx
wevtutil epl "DFS Replication" %BackupDir%\%COMPUTERNAME%-DFSReplication-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.evtx
)
REM Install https://www.7-zip.org/a/7z2501.exe  7zip 7z2301-x64.exe /S
ECHO ZIP the days logs into C:\Windows\Temp\ig-windows-baseline\wevtutil\
"C:\Program Files\7-zip\7z.exe" a -t7z -m0=lzma2 -mx=9 "C:\Windows\Temp\ig-windows-baseline\wevtutil\%COMPUTERNAME%-wevtutil-%date:~4,2%%date:~7,2%%date:~10,4%.7z" "%BackupDir%\*"
REM CLEANUP del %BackupDir%\*
