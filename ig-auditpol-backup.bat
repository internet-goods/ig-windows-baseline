set "BackupDir=C:\Windows\Temp\ig-windows-baseline\auditpol"
if not exist "%BackupDir%" (
    mkdir "%BackupDir%"
    echo Created directory: %BackupDir%
)
auditpol /list /subcategory:* /r > %TargetDir%\%COMPUTERNAME%-auditpol-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.txt
