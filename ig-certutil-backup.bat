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
echo Exporting certutil ca...
certutil -store Root > %BackupDir%\%COMPUTERNAME%-certutilstoreroot-%CurrentDate%.txt"
certutil -ping > %BackupDir%\%COMPUTERNAME%-certutilping-%CurrentDate%.txt"
certutil -store -user My "Code Signing" > %BackupDir%\%COMPUTERNAME%-certutilmycodesigning-%CurrentDate%.txt"
certutil -store CA "Code Signing" > %BackupDir%\%COMPUTERNAME%-certutilcacodesigning-%CurrentDate%.txt"
echo Tasks saved to: %OutputFilePathTXT%
endlocal
