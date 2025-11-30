@echo off
setlocal
echo google gemini create a bat script that saves current scheduled tasks each day to a directory named after YYYY-MM-DD
echo converted by internet-goods.com for baselining scheduled tasks on windows
:: Get the current date in YYYY-MM-DD format
for /f "tokens=1-3 delims=/ " %%a in ('date /t') do (
    set "CurrentDate=%%c-%%a-%%b"
)

:: Define the base backup directory (e.g., C:\TaskBackups)
set "BackupDir=C:\Windows\Temp\ig-windows-baseline\w32tm"

:: Create the date-specific directory
set "TargetDir=%BackupDir%"
if not exist "%TargetDir%" (
    mkdir "%TargetDir%"
    echo Created directory: %TargetDir%
)

:: Define the filename for the output
set "OutputFilePathTXT=%TargetDir%\%COMPUTERNAME%-w32tm-%CurrentDate%.txt"
echo Exporting w32tm...
w32tm /query /configuration > "%OutputFilePathTXT%"
echo.
echo Backup complete!
echo Tasks saved to: %OutputFilePathTXT%
endlocal
