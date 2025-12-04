set "BackupDir=C:\Windows\Temp\ig-windows-baseline\dism"
if not exist "%BackupDir%" (
    mkdir "%BackupDir%"
    echo Created directory: %BackupDir%
)
dism /Online /Get-Features /Format:Table > %TargetDir%\%COMPUTERNAME%-dismfeatures-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.txt
REM DEFAULT
copy c:\Windows\Logs\DISM\dism.log %TargetDir%\%COMPUTERNAME%-dism-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.log
findstr /c:%date:~10,4%-%date:~4,2%-%date:~7,2% c:\Windows\Logs\DISM\dism.log > %TargetDir%\%COMPUTERNAME%-dismtoday-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.log
