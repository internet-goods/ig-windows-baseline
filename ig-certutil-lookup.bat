setlocal
:: Get the current date in YYYY-MM-DD format
for /f "tokens=1-3 delims=/ " %%a in ('date /t') do (
    set "CurrentDate=%%c-%%a-%%b"
)
:: Define the base backup directory (e.g., C:\TaskBackups)
set "BackupDir=C:\Windows\Temp\ig-windows-baseline\certutil"
:: Create the date-specific directory
if not exist "%BackupDir%" (
    mkdir "%BackupDir%"
    echo Created directory: %BackupDir%
)
:: Define the filename for the output
set "OutputFilePathTXT=%BackupDir%\%COMPUTERNAME%-certutilstoreroot-%CurrentDate%.txt"
echo Exporting certutil ca...
certutil -store Root > "%OutputFilePathTXT%"
echo Tasks saved to: %OutputFilePathTXT%
endlocal
