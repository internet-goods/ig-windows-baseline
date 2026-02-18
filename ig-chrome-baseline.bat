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


echo chrome STIG
echo V-221558	Medium	Firewall traversal from remote host must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v RemoteAccessHostFirewallTraversal /t REG_DWORD /d 0 /f
echo V-221559	Medium	Site tracking users location must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DefaultGeolocationSetting /t REG_DWORD /d 2 /f
echo V-221561	Medium	Sites ability to show pop-ups must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DefaultPopupsSetting /t REG_DWORD /d 2 /f
echo V-221562	Medium	Extensions installation must be blocklisted by default.
echo reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v ExtensionInstallBlocklist /t REG_DWORD /d 1 /f
echo V-221563	Low	Extensions that are approved for use must be allowlisted.
echo V-221564	Medium	The default search providers name must be set.
echo V-221565	Medium	The default search provider URL must be set to perform encrypted searches.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DefaultSearchProviderSearchURL /t REG_DWORD /d "https://www.google.com/search?q={searchTerms}" /f
echo V-221566	Medium	Default search provider must be enabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DefaultSearchProviderName /t REG_DWORD /d "Google Encrypted" /f
echo V-221567	Medium	The Password Manager must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v PasswordManagerEnabled /t REG_DWORD /d 0 /f
echo V-221570	Medium	Background processing must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v BackgroundModeEnabled /t REG_DWORD /d 0 /f
echo V-221571	Medium	Google Data Synchronization must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v SyncDisabled /t REG_DWORD /d 1 /f
echo V-221572	Medium	The URL protocol schema javascript must be disabled.
echo V-221573	Medium	Cloud print sharing must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v CloudPrintProxyEnabled /t REG_DWORD /d 0 /f
echo V-221574	Medium	Network prediction must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v NetworkPredictionOptions /t REG_DWORD /d 2 /f
echo V-221575	Medium	Metrics reporting to Google must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v MetricsReportingEnabled /t REG_DWORD /d 0 /f
echo V-221576	Medium	Search suggestions must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v SearchSuggestEnabled /t REG_DWORD /d 0 /f
echo V-221577	Medium	Importing of saved passwords must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v ImportSavedPasswords /t REG_DWORD /d 0 /f
echo V-221578	Medium	Incognito mode must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v IncognitoModeAvailability /t REG_DWORD /d 1 /f
echo V-221579	Medium	Online revocation checks must be performed.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v EnableOnlineRevocationChecks /t REG_DWORD /d 1 /f
echo V-221580	Medium	Safe Browsing must be enabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v SafeBrowsingProtectionLevel /t REG_DWORD /d 1 /f
echo V-221581	Medium	Browser history must be saved.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v SavingBrowserHistoryDisabled /t REG_DWORD /d 0 /f
echo V-221584	Medium	The version of Google Chrome running on the system must be a supported version.
echo V-221586	Medium	Deletion of browser history must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v AllowDeletingBrowserHistory /t REG_DWORD /d 0 /f
echo V-221587	Medium	Prompt for download location must be enabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v PromptForDownloadLocation /t REG_DWORD /d 1 /f
echo V-221588	Medium	Download restrictions must be configured.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DownloadRestrictions /t REG_DWORD /d 2 /f
echo V-221590	Medium	Safe Browsing Extended Reporting must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v SafeBrowsingExtendedReportingEnabled /t REG_DWORD /d 0 /f
echo V-221591	Medium	WebUSB must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DefaultWebUsbGuardSetting /t REG_DWORD /d 2 /f
echo V-221592	Medium	Chrome Cleanup must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v ChromeCleanupEnabled /t REG_DWORD /d 0 /f
echo V-221593	Medium	Chrome Cleanup reporting must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v ChromeCleanupReportingEnabled /t REG_DWORD /d 0 /f
echo V-221594	Medium	Google Cast must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v EnableMediaRouter /t REG_DWORD /d 0 /f
echo V-221595	Medium	Autoplay must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v AutoplayAllowed /t REG_DWORD /d 0 /f
echo V-221596	Medium	URLs must be allowlisted for Autoplay use.
echo V-221597	Medium	Anonymized data collection must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v UrlKeyedAnonymizedDataCollectionEnabled /t REG_DWORD /d 0 /f
echo V-221598	Medium	Collection of WebRTC event logs must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v WebRtcEventLogCollectionAllowed /t REG_DWORD /d 0 /f
echo V-221599	Low	Chrome development tools must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DeveloperToolsAvailability /t REG_DWORD /d 0 /f
echo V-226401	Medium	Guest Mode must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v BrowserGuestModeEnabled /t REG_DWORD /d 0 /f
echo V-226402	Medium	AutoFill for credit cards must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v AutofillCreditCardEnabled /t REG_DWORD /d 0 /f
echo V-226403	Medium	AutoFill for addresses must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v AutofillAddressEnabled /t REG_DWORD /d 0 /f
echo V-226404	Medium	Import AutoFill form data must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v ImportAutofillFormData /t REG_DWORD /d 0 /f
echo V-241787	Medium	Web Bluetooth API must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DefaultWebBluetoothGuardSetting REG_DWORD /d 2 /f
echo V-245538	Medium	Use of the QUIC protocol must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v QuicAllowed /t REG_DWORD /d 0 /f
echo V-245539	Medium	Session only based cookies must be enabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DefaultCookiesSetting /t REG_DWORD /d 4 /f
