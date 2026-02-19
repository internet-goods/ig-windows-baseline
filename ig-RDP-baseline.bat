echo what kind of rdp hardening, windows firewall hardening could be applied to make host survive scans without changing scanner
echo 1. Force Network Level Authentication (NLA)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f

echo 2. Set Security Layer to SSL (TLS Only)
echo 0 = RDP Security, 1 = Negotiate, 2 = SSL (TLS)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 2 /f

echo 3. Set Encryption Level to High (128-bit)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel /t REG_DWORD /d 3 /f

echo 4. Firewall Hardening via netsh
echo This limits RDP access to a specific IP (e.g., 192.168.1.50). 
echo Note: This modifies the built-in rule.
echo netsh advfirewall firewall set rule name="Remote Desktop - User Mode (TCP-In)" new remoteip=192.168.1.50
