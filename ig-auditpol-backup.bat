set "BackupDir=C:\Windows\Temp\ig-windows-baseline\auditpol"
if not exist "%BackupDir%" (
    mkdir "%BackupDir%"
    echo Created directory: %BackupDir%
)
REM auditpol /list /subcategory:* /r > %BackupDir%\%COMPUTERNAME%-auditpol-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.txt
auditpol /get /category:* > %BackupDir%\%COMPUTERNAME%-auditpol-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.txt
