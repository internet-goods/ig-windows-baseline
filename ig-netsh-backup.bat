setlocal
:: Get the current date in YYYY-MM-DD format
for /f "tokens=1-3 delims=/ " %%a in ('date /t') do (
    set "CurrentDate=%%c-%%a-%%b"
)
:: Define the base backup directory (e.g., C:\TaskBackups)
set "BackupDir=C:\Windows\Temp\ig-windows-baseline\netsh"
:: Create the date-specific directory
set "TargetDir=%BackupDir%"
if not exist "%TargetDir%" (
    mkdir "%TargetDir%"
    echo Created directory: %TargetDir%
)
set "OutputFilePathTXT=%TargetDir%\%COMPUTERNAME%-netshwinhttpshowproxy-%CurrentDate%.txt"
netsh winhttp dump > "%OutputFilePathTXT%"
set "OutputFilePathTXT=%TargetDir%\%COMPUTERNAME%-netsinterfacedump-%CurrentDate%.txt"
netsh interface dump > "%OutputFilePathTXT%"
set "OutputFilePathTXT=%TargetDir%\%COMPUTERNAME%-netsadvfirewalldump-%CurrentDate%.txt"
netsh advfirewall dump > "%OutputFilePathTXT%"
endlocal
