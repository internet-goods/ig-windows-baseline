:: Hardening Windows NTP Baseline non domain joined
:: Target: time.google.com
echo [1/3] Setting W32Time service to Automatic start...
:: Sets the start type to 2 (Automatic)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time" /v "Start" /t REG_DWORD /d 2 /f

echo [2/3] Triggering service start...
:: This ensures the service is actually running right now
sc query w32time
sc start w32time

echo [1/5] Setting NTP Server to time.google.com...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" /v "NtpServer" /t REG_SZ /d "time.google.com,0x1" /f

echo [2/5] Setting Configuration Type to NTP...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" /v "Type" /t REG_SZ /d "NTP" /f

echo [3/5] Increasing Polling Interval (Hardening against drift)...
:: MinPollInterval 10 (2^10 = 1024s), MaxPollInterval 15 (2^15 = 32768s)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Config" /v "MinPollInterval" /t REG_DWORD /d 10 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Config" /v "MaxPollInterval" /t REG_DWORD /d 15 /f

echo [4/5] Enabling Special Poll Interval (3600 seconds / 1 hour)...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" /v "SpecialPollInterval" /t REG_DWORD /d 3600 /f

echo [5/5] Restarting W32Time Service to apply changes...
net stop w32time && net start w32time
w32tm /resync /force

echo Baseline Applied Successfully.
