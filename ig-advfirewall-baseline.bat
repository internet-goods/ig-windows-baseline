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
:: 11. Domain Profile
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v LogFilePath /t REG_SZ /d "%%systemroot%%\system32\LogFiles\Firewall\domainfw.log" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" /v LogFilePath /t REG_SZ /d "%%systemroot%%\system32\LogFiles\Firewall\privatefw.log" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" /v LogFilePath /t REG_SZ /d "%%systemroot%%\system32\LogFiles\Firewall\publicfw.log" /f

:: 12 disabled rules
netsh advfirewall firewall set rule name="Core Networking - Router Advertisement (ICMPv6-In)" dir=in new enable=No
ECHO tbd clear the rules then rebuild, no, keep defaults, dont test them just turn them on/off, test them with powershell script
ECHO IN DISABLE
netsh advfirewall firewall add rule name="Core Networking - Destination Unreachable (ICMPv6-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - Destination Unreachable Fragmentation Needed (ICMPv4-In)" dir=in new enable=No
REM Core Networking - Dynamic Host Configuration Protocol (DHCP-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - Internet Group Management Protocol (IGMP-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - IPHTTPS (TCP-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - IPv6 (IPv6-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - Multicast Listener Done (ICMPv6-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - Multicast Listener Query (ICMPv6-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - Multicast Listener Report (ICMPv6-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - Multicast Listener Report v2 (ICMPv6-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - Neighbor Discovery Advertisement (ICMPv6-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - Neighbor Discovery Solicitation (ICMPv6-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - Packet Too Big (ICMPv6-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - Parameter Problem (ICMPv6-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - Parameter Problem (ICMPv6-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - Router Advertisement (ICMPv6-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - Router Solicitation (ICMPv6-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - Teredo (UDP-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Core Networking - Time Exceeded (ICMPv6-In)" dir=in new enable=No

netsh advfirewall firewall add rule name="File and Printer Sharing (Echo Request - ICMPv4)" dir=in profile=public new enable=No
netsh advfirewall firewall add rule name="File and Printer Sharing (Echo Request - ICMPv4)" dir=in profile=private new enable=Yes
netsh advfirewall firewall add rule name="File and Printer Sharing (Echo Request - ICMPv4)" dir=in profile=domain new enable=Yes
netsh advfirewall firewall add rule name="File and Printer Sharing (Echo Request - ICMPv6)" dir=in new enable=No
netsh advfirewall firewall add rule name="File and Printer Sharing (LLMNR-UDP-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="File and Printer Sharing (NB-Datagram-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="File and Printer Sharing (NB-Name-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="File and Printer Sharing (NB-Session-In)" new enable=No
netsh advfirewall firewall add rule name="File and Printer Sharing (SMB-In)" dir=in profile=public new enable=No
netsh advfirewall firewall add rule name="File and Printer Sharing (SMB-In)" dir=in profile=private new enable=Yes
netsh advfirewall firewall add rule name="File and Printer Sharing (SMB-In)" dir=in profile=domain new enable=Yes
netsh advfirewall firewall add rule name="File and Printer Sharing (Spooler Service - RPC)" dir=in profile=public new enable=No
netsh advfirewall firewall add rule name="File and Printer Sharing (Spooler Service - RPC)" dir=in profile=private new enable=Yes
netsh advfirewall firewall add rule name="File and Printer Sharing (Spooler Service - RPC)" dir=in profile=domain new enable=Yes
netsh advfirewall firewall add rule name="File and Printer Sharing (Spooler Service - RPC-EPMAP)" dir=in profile=public new enable=No
netsh advfirewall firewall add rule name="File and Printer Sharing (Spooler Service - RPC-EPMAP)" dir=in profile=private new enable=Yes
netsh advfirewall firewall add rule name="File and Printer Sharing (Spooler Service - RPC-EPMAP)" dir=in profile=private new enable=Yes

netsh advfirewall firewall add rule name="Network Discovery (LLMNR-UDP-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Network Discovery (NB-Datagram-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Network Discovery (NB-Name-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Network Discovery (Pub-WSD-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Network Discovery (SSDP-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Network Discovery (UPnP-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Network Discovery (WSD Events-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Network Discovery (WSD EventsSecure-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Network Discovery (WSD-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Performance Logs and Alerts (DCOM-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Performance Logs and Alerts (TCP-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Remote Assistance (DCOM-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Remote Assistance (PNRP-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Remote Assistance (RA Server TCP-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Remote Assistance (SSDP TCP-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Remote Assistance (SSDP UDP-In)" dir=in new enable=No
netsh advfirewall firewall add rule name="Remote Assistance (TCP-In)" dir=in new enable=No



ECHO OUT
netsh advfirewall firewall add rule name="Network Discovery (LLMNR-UDP-Out)" dir=out new enable=No
netsh advfirewall firewall add rule name="Network Discovery (NB-Datagram-Out)" dir=out new enable=No
netsh advfirewall firewall add rule name="Network Discovery (NB-Name-Out)" dir=out new enable=No
netsh advfirewall firewall add rule name="Network Discovery (UPnP-Out)" dir=out new enable=No
netsh advfirewall firewall add rule name="Network Discovery (SSDP-Out)" dir=out new enable=No
netsh advfirewall firewall add rule name="File and Printer Sharing (NB-Session-Out)" dir=out new enable=No
netsh advfirewall firewall add rule name="File and Printer Sharing (Echo Request - ICMPv6)" dir=out new enable=No

ECHO BLOCK ON PUBLIC

netsh advfirewall firewall add rule name="File and Printer Sharing (Echo Request - ICMPv4)" dir=in profile=public new enable=No 


echo enabled rules
netsh advfirewall firewall set rule name="Core Networking - Dynamic Host Configuration Protocol (DHCP-In)" new enable=Yes




