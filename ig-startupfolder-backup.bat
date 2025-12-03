set "BackupDir=C:\Windows\Temp\ig-windows-baseline\StartupFolder"
if not exist "%BackupDir%" (
    mkdir "%BackupDir%"
    echo Created directory: %BackupDir%
)
REM dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" > %BackupDir%/%COMPUTERNAME%-MachineStartupFolder-%date:~4,2%%date:~7,2%%date:~10,4%-%TIME:~0,2%%TIME:~3,2%.txt
REM dir C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
setlocal

echo.
echo --- Scanning Windows Startup Folders ---
echo.

:: Define the directories to check
set "USER_STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "ALLUSERS_STARTUP=%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\StartUp"

set "HASH_ALGORITHM=SHA256"

:: Function to process a directory
:ProcessDir
    set "TARGET_DIR=%1" 
    echo Checking: %TARGET_DIR%
    
    :: Use a FOR loop to find files recursively (r) in the directory
    :: The %%f variable holds the full path to the file
    for /r "%TARGET_DIR%" %%f in (*) do (
        
        :: Execute certutil to calculate the hash of the file
        :: -hashfile [file] [algorithm]
        certutil -hashfile "%%f" %HASH_ALGORITHM% | findstr /i /v "hashfile" | findstr /v "^$" >> temp_hashes.txt

        :: The output format is: "Hash of file %%f: [HASH_VALUE]"
        :: This is not ideal for clean parsing, so we'll clean it up later.
    )
    echo.
    goto :eof

:: Clear previous temporary file
if exist temp_hashes.txt del temp_hashes.txt

:: --- Execution ---
call :ProcessDir "%USER_STARTUP%"
call :ProcessDir "%ALLUSERS_STARTUP%"

:: --- Output Formatting ---
echo --- Results (File Path and %HASH_ALGORITHM% Hash) ---
echo.

:: Loop through the temporary file and clean up the output
:: Example line: "Hash of file C:\Users\User\...\file.exe: [HASH_VALUE]"
FOR /F "tokens=1* delims=:" %%a IN ('type temp_hashes.txt ^| findstr /v "completed"') DO (
    :: %%a contains "Hash of file C:\Users\User\...\file.exe"
    :: %%b contains " [HASH_VALUE]"
    
    :: Extract the file path
    set "FilePath=%%a"
    setlocal enabledelayedexpansion
    
    :: Remove "Hash of file " and leading/trailing quotes
    set "FilePath=!FilePath:Hash of file =!"
    set "FilePath=!FilePath:~1,-1!"
    
    :: Output the cleaned path and the hash value
    echo !FilePath! : %%b
    endlocal
)

:: Clean up the temporary file
if exist temp_hashes.txt del temp_hashes.txt

endlocal
