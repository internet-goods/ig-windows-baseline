set "BackupDir=C:\Windows\Temp\ig-windows-baseline\netaccounts"
if not exist "%BackupDir%" (
    mkdir "%BackupDir%"
    echo Created directory: %BackupDir%
)
echo backup account hardening settings
net accounts > %TargetDir%\%COMPUTERNAME%-netaccounts-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~3,2%%TIME:~6,2%.txt
