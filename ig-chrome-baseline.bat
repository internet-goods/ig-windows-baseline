:: --- SECTION 1: FORCE SYSTEM-WIDE UPDATE ---
echo [+] Triggering System-wide Chrome Update...
IF EXIST "C:\Program Files\Google\Update\GoogleUpdate.exe" (
    "C:\Program Files\Google\Update\GoogleUpdate.exe" /c /n /i "googlechrome"
) ELSE IF EXIST "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" (
    "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /c /n /i "googlechrome"
)

:: --- SECTION 2: REMOVE USER-PROFILE INSTALLS ---
echo [+] Searching for User-level Chrome installations...

FOR /D %%G in ("C:\Users\*") DO (
    SET "USER_CHROME_BIN=%%G\AppData\Local\Google\Chrome\Application"
    
    IF EXIST "!USER_CHROME_BIN!" (
        echo [!] Found User Chrome at: %%G
        echo [!] Removing Application directory, preserving User Data...
        
        :: Remove the Application folder (the binaries)
        RD /S /Q "!USER_CHROME_BIN!" 2>nul
        
        :: Clean up potential Start Menu shortcuts for that specific user
        DEL /F /Q "%%G\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk" 2>nul
    )
)

echo [+] Cleanup Complete.
pause
