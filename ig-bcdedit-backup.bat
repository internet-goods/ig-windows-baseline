set "BackupDir=C:\Windows\Temp\ig-windows-baseline\bcdedit"
if not exist "%BackupDir%" (
    mkdir "%BackupDir%"
)
echo check DEP settings
bcdedit /enum all /v > %BackupDir%\%COMPUTERNAME%-bcdeditenumallv-%date:~4,2%%date:~7,2%%date:~10,4%.txt
