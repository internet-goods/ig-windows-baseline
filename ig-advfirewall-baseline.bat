:: Check for administrative privileges, code by gemini
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running with Administrator privileges.
) else (
    echo [ERROR] Please run this script as an Administrator.
    pause
    exit /b
)

echo Hardening Windows Firewall to DISA STIG Standards...

:: 1. Enable Firewall for All Profiles (Domain, Private, Public)
:: STIG V-253303, V-253304, V-253305
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "EnableFirewall" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d 1 /f

:: 2. Set Default Inbound Action to Block and Outbound to Allow (unless restricted)
:: STIG V-253306, V-253308, V-253310
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DefaultInboundAction" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DefaultInboundAction" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DefaultInboundAction" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DefaultOutboundAction" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DefaultOutboundAction" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DefaultOutboundAction" /t REG_DWORD /d 0 /f

:: 3. Disable Allow Local Policy Merge (Prevents local users from creating rules)
:: STIG V-253313, V-253314, V-253315
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d 0 /f

:: 4. Enable Logging for Dropped Packets
:: STIG V-253318, V-253320, V-253322
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v "LogDroppedPackets" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" /v "LogDroppedPackets" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" /v "LogDroppedPackets" /t REG_DWORD /d 1 /f

:: 5. Enable Logging for Successful Connections (Optional but recommended by some STIGs)
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v "LogSuccessConnections" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" /v "LogSuccessConnections" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" /v "LogSuccessConnections" /t REG_DWORD /d 1 /f

:: 6. Set Log File Size (Max 16MB per STIG recommendation)
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v "LogFileSize" /t REG_DWORD /d 16384 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" /v "LogFileSize" /t REG_DWORD /d 16384 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" /v "LogFileSize" /t REG_DWORD /d 16384 /f

:: 7. Prevent Windows Firewall from being disabled via UI
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Firewall and network protection" /v "UILockdown" /t REG_DWORD /d 1 /f
:: 8. others maye for oldwin
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DisableNotifications" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DisableNotifications" /t REG_DWORD /d 1 /f
:: 9. defender for Windows 10 (version 1803 and later) and Windows 11
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v DisableNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v DisableEnhancedNotifications /t REG_DWORD /d 1 /f

:: 10. multicast Unless you have a specific, known application that requires this communication method, you should keep the setting enabled for better security.
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DisableUnicastResponsesToMulticastBroadcast" /t REG_DWORD /d 1 /f
:: 11. block problematic protocols explicitly
ECHO tbd clear the rules then rebuild
netsh advfirewall firewall add rule name="Network Discovery (LLMNR-UDP-In)" dir=in action=block protocol=UDP localport=5355 profile=public
netsh advfirewall firewall add rule name="Network Discovery (LLMNR-UDP-In)" dir=in action=block protocol=UDP localport=5355 profile=private
netsh advfirewall firewall add rule name="Network Discovery (LLMNR-UDP-In)" dir=in action=block protocol=UDP localport=5355 profile=domain
netsh advfirewall firewall add rule name="Network Discovery (NB-Datagram-In)" dir=in action=block protocol=UDP localport=138 profile=public
netsh advfirewall firewall add rule name="Network Discovery (NB-Datagram-In)" dir=in action=block protocol=UDP localport=138 profile=private
netsh advfirewall firewall add rule name="Network Discovery (NB-Datagram-In)" dir=in action=block protocol=UDP localport=138 profile=domain
netsh advfirewall firewall add rule name="Network Discovery (NB-Name-In)" dir=in action=block protocol=UDP localport=137 profile=public
netsh advfirewall firewall add rule name="Network Discovery (NB-Name-In)" dir=in action=block protocol=UDP localport=137 profile=private
netsh advfirewall firewall add rule name="Network Discovery (NB-Name-In)" dir=in action=block protocol=UDP localport=137 profile=domain
netsh advfirewall firewall add rule name="Network Discovery (UPnP-In)" dir=in action=block protocol=TCP localport=2869 profile=public
netsh advfirewall firewall add rule name="Network Discovery (UPnP-In)" dir=in action=block protocol=TCP localport=2869 profile=private
netsh advfirewall firewall add rule name="Network Discovery (UPnP-In)" dir=in action=block protocol=TCP localport=2869 profile=domain
netsh advfirewall firewall add rule name="Network Discovery (SSDP-In)" dir=in action=block protocol=UDP localport=1900 profile=public
netsh advfirewall firewall add rule name="Network Discovery (SSDP-In)" dir=in action=block protocol=UDP localport=1900 profile=private
netsh advfirewall firewall add rule name="Network Discovery (SSDP-In)" dir=in action=block protocol=UDP localport=1900 profile=domain
netsh advfirewall firewall add rule name="File and Printer Sharing (SMB-In)" dir=in action=block protocol=TCP localport=445 profile=private
netsh advfirewall firewall add rule name="File and Printer Sharing (SMB-In)" dir=in action=block protocol=TCP localport=445 profile=public
netsh advfirewall firewall add rule name="File and Printer Sharing (SMB-In)" dir=in action=block protocol=TCP localport=445 profile=domain
netsh advfirewall firewall add rule name="File and Printer Sharing (NB-Session-In)" dir=in action=block protocol=TCP localport=139 profile=private
netsh advfirewall firewall add rule name="File and Printer Sharing (NB-Session-In)" dir=in action=block protocol=TCP localport=139 profile=public
netsh advfirewall firewall add rule name="File and Printer Sharing (NB-Session-In)" dir=in action=block protocol=TCP localport=139 profile=domain


echo or enable existing
REM netsh advfirewall firewall set rule name="Block NB-Name-In" new enable=yes profile=public
