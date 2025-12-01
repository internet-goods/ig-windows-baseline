setlocal
:: Get the current date in YYYY-MM-DD format
for /f "tokens=1-3 delims=/ " %%a in ('date /t') do (
    set "CurrentDate=%%c-%%a-%%b"
)
:: Define the base backup directory (e.g., C:\TaskBackups)
set "BackupDir=C:\Windows\Temp\ig-windows-baseline\auditpol"
:: Create the date-specific directory
set "TargetDir=%BackupDir%"
if not exist "%TargetDir%" (
    mkdir "%TargetDir%"
    echo Created directory: %TargetDir%
)
set "OutputFilePathTXT=%TargetDir%\%COMPUTERNAME%-auditpol-%CurrentDate%.txt"
auditpol /list /subcategory:* /r > "%OutputFilePathTXT%"
endlocal
