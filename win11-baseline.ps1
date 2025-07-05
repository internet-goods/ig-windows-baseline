#https://stackoverflow.com/questions/25917637/create-folder-with-current-date-as-name-in-powershell
New-Item -ItemType Directory -Path ".\$((Get-Date).ToShortDateString())"
cd ".\$((Get-Date).ToShortDateString())"
#services
sc DoSvc stop
sc DoSvc start= disabled
sc upnphost stop
sc upnphost start= disabled
#modules
Install-Module -Name SpeculationControl
Import-Module -Name SpeculationControl
#dism
dism /online /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64
#auditpol
auditpol.exe /get /category:* > auditpol_beforehardening.txt
#dostuff
auditpol.exe /get /category:* > auditpol_afterhardening.txt
#instrumentation
#Invoke-WebRequest https://pkg.osquery.io/windows/osquery-5.16.0.msi
#https://www.blumira.com/blog/enable-sysmon
#Invoke-WebRequest -Uri https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml -OutFile sysmonconfig.xml
#sysmon64.exe –accepteula –i config.xml
#winget
Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile winget.msixbundle
Add-AppxPackage winget.msixbundle
winget install --id Microsoft.Powershell --source winget
#AV
#Invoke-WebRequest https://clamav-site.s3.amazonaws.com/production/release_files/files/000/001/821/original/clamav-1.4.2.win.arm64.msi
#Invoke-WebRequest https://objects.githubusercontent.com/github-production-release-asset-2e65be/7037996/8793b738-3bc5-4dd8-91ef-4fdd1dac418e?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250303%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250303T015750Z&X-Amz-Expires=300&X-Amz-Signature=753c038a0702cd300b89f3a761982e958abed79fa26e0733549ca3d71a423f6a&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dyara-v4.5.2-2326-win64.zip&response-content-type=application%2Foctet-stream
#Invoke-WebRequest https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.0-1.msi
#elasticagent
#user apps
#https://dl1.cdn.filezilla-project.org/client/FileZilla_3.68.1_x86_64-linux-gnu.tar.xz?h=zuW-H_2uBTephsSUVampWQ&x=1740971160
#Invoke-WebRequest https://download.gimp.org/gimp/v2.10/windows/gimp-2.10.38-setup-1.exe
#Invoke-WebRequest https://get.videolan.org/vlc/3.0.21/win32/vlc-3.0.21-win32.exe
#Invoke-WebRequest https://downloads.realvnc.com/download/file/viewer.files/VNC-Viewer-7.13.1-Windows.exe?lai_vid=LazLae45JInq&lai_sr=5-9&lai_sl=l
#RIPInvoke-WebRequest https://www.cygwin.com/setup-x86_64.exe
#Invoke-WebRequest https://www.libreoffice.org/donate/dl/win-x86_64/25.2.1/en-US/LibreOffice_25.2.1_Win_x86-64.msi
#Set-ProcessMitigation -System -Enable DEP,SEHOP,HighEntropy,ForceRelocateImages,BottomUp,TerminateOnError,DisableWin32kSystemCalls,DisableExtensionPoints,BlockDynamicCode,StrictHandle
#git

#downloads
Invoke-WebRequest https://github.com/mitre/saf/releases/download/1.4.21/saf-v1.4.21-x64.exe
Invoke-WebRequest https://download.sysinternals.com/files/ProcessExplorer.zip
Invoke-WebRequest https://github.com/git-for-windows/git/releases/download/v2.48.1.windows.1/Git-2.48.1-64-bit.exe
git clome https://github.com/Sneakysecdoggo/Wynis
git clone https://github.com/scipag/HardeningKitty
Invoke-WebRequest https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/scc-5.10.1_Windows_bundle.zip
Invoke-WebRequest https://raw.githubusercontent.com/gnh1201/welsonjs/014c1eaa59acdb35d603af0dfee1ef20110def96/app/assets/bat/clean_chrome_pup.bat
Invoke-WebRequest https://raw.githubusercontent.com/dennyhalim/cfg/c9e53971aad5c5dd1fe38fabdee4724ce2b2eb6b/apps/securedns.cmd
Invoke-WebRequest https://raw.githubusercontent.com/iam-py-test/my_filters_001/a99614ebb27af18ae05a34c82f91546b4383e2bb/wiki/fix-browser-problem.md
git clone https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat
git clone https://github.com/mitre/google-chrome-v2r6-stig-baseline
git clone https://github.com/milgradesec/windows-settings
#https://github.com/fishilico/generic-config/blob/2593f3f7d5f0a891e278d773c0cd3b2120b656f0/windows/hardening_script.bat#L113
git clone https://github.com/fishilico/generic-config
git clone https://github.com/ZephrFish/WindowsHardeningScript
git clone https://github.com/jkerai1/WindowsHardeningScripts
git clone https://github.com/dend/windows-dev-box/
git clone https://github.com/michalzobec/PS-STIG-Scanner
git clone https://github.com/blue101010/WindowsDebloater
git clone https://github.com/azurejoga/Aurora-Windows-Optimizer
git clone https://github.com/Harvester57/Windows-PolicyRules
#https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10#what-is-the-policy-analyzer-tool
#https://www.microsoft.com/en-us/download/details.aspx?id=55319
git clone https://github.com/PusPC/Pus
git clone https://github.com/itsNileshHere/devkit-lab
git clone https://github.com/SysadminWorld/Bloatynosy
git clone https://github.com/Scrut1ny/Windows-Debloating-Script
git clone https://github.com/markkerry/Proactive-Remediations
git clone https://github.com/azurejoga/Aurora-Windows-Optimizer
git clone https://github.com/zoicware/RemoveWindowsAI
#TOP
git clone https://github.com/TheSPEEDO/URLRunner
#STIG
#Domain-joined systems must use Windows Enterprise Edition 64-bit version.</title>
#Windows information systems must use BitLocker to encrypt all disks to protect the confidentiality and integrity of all information at rest.</title>
#Windows systems must use a BitLocker PIN for pre-boot authentication.</title>
#Windows systems must use a BitLocker PIN with a minimum length of six digits for pre-boot authentication.</title>
#Windows systems must be maintained at a supported servicing level.</title>
#Local volumes must be formatted using NTFS.</title>
#Internet Information System (IIS) or its subcomponents must not be installed on a workstation.</title>
Uninstall-WindowsFeature -Remove Web-Server
#Simple TCP/IP Services must not be installed on the system.</title>
Disable-WindowsOptionalFeature -Online -FeatureName Simple-TCPIP -Remove
#The Telnet Client must not be installed on the system.</title>
Uninstall-WindowsFeature -Name Telnet-Client
#The TFTP Client must not be installed on the system.</title>
Disable-WindowsOptionalFeature -Online -FeatureName "TFTPClient" -Remove
#Data Execution Prevention (DEP) must be configured to at least OptOut.</title>
#Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.</title>
#The Windows PowerShell 2.0 feature must be disabled on the system.</title>
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowershellV2 -Remove 
#The Server Message Block (SMB) v1 protocol must be disabled on the system.</title>
#The Server Message Block (SMB) v1 protocol must be disabled on the SMB server.</title>
#The Server Message Block (SMB) v1 protocol must be disabled on the SMB client.</title>
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
#The Secondary Logon service must be disabled on Windows.</title>
#Windows account lockout duration must be configured to 15 minutes or greater.</title>
net accounts /lockoutduration:30
#The number of allowed bad logon attempts must be configured to three or less.</title>
net accounts /lockoutthreshold:3
#The period of time before the bad logon counter is reset must be configured to 15 minutes.</title>
net accounts /lockoutwindow:15
#The password history must be configured to 24 passwords remembered.</title>
net accounts /uniquepw:24
#The maximum password age must be configured to 60 days or less.</title>
#so annoyingnet accounts /maxpwage:60
#The minimum password age must be configured to at least 1 day.</title>
net accounts /minpwage:1
#Passwords must, at a minimum, be 14 characters.</title>
net accounts /minpwlen:14
#The built-in Microsoft password complexity filter must be enabled.</title>
#Reversible password encryption must be disabled.</title>
#The system must be configured to audit Account Logon - Credential Validation failures.</title>
#The system must be configured to audit Account Logon - Credential Validation successes.</title>
Auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
#The system must be configured to audit Account Management - Security Group Management successes.</title>
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
#The system must be configured to audit Account Management - User Account Management failures.</title>
#The system must be configured to audit Account Management - User Account Management successes.</title>
Auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
#The system must be configured to audit Detailed Tracking - Process Creation successes.</title>
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
#The system must be configured to audit Logon/Logoff - Account Lockout failures.</title>
Auditpol /set /subcategory:"Account Lockout" /success:enable
#The system must be configured to audit Logon/Logoff - Logoff successes.</title>
Auditpol /set /subcategory:"Logoff" /success:enable
#The system must be configured to audit Logon/Logoff - Logon failures.</title>
#The system must be configured to audit Logon/Logoff - Logon successes.</title>
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable
#The system must be configured to audit Logon/Logoff - Special Logon successes.</title>
Auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
#Windows must be configured to audit Object Access - File Share failures.</title>
#Windows must be configured to audit Object Access - File Share successes.</title>
Auditpol /set /subcategory:"File Share" /success:enable /failure:enable
#Windows must be configured to audit Object Access - Other Object Access Events successes.</title>
#Windows must be configured to audit Object Access - Other Object Access Events failures.</title>
Auditpol /set /subcategory:"Account Lockout" /success:enable
#The system must be configured to audit Policy Change - Audit Policy Change successes.</title>
Auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
#The system must be configured to audit Policy Change - Authentication Policy Change successes.</title>
Auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
#The system must be configured to audit Policy Change - Authorization Policy Change successes.</title>
Auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
#The system must be configured to audit Privilege Use - Sensitive Privilege Use failures.</title>
#The system must be configured to audit Privilege Use - Sensitive Privilege Use successes.</title>
#The system must be configured to audit System - IPsec Driver failures.</title>
#The system must be configured to audit System - Other System Events successes.</title>
#The system must be configured to audit System - Other System Events failures.</title>
Auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
#The system must be configured to audit System - Security State Change successes.</title>
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
#The system must be configured to audit System - Security System Extension successes.</title>
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
#The system must be configured to audit System - System Integrity failures.</title>
#The system must be configured to audit System - System Integrity successes.</title>
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
#The Application event log size must be configured to 32768 KB or greater.</title>
#The Security event log size must be configured to 1024000 KB or greater.</title>
#The System event log size must be configured to 32768 KB or greater.</title>
#Windows permissions for the Application event log must prevent access by non-privileged accounts.</title>
#Windows permissions for the Security event log must prevent access by non-privileged accounts.</title>
#Windows permissions for the System event log must prevent access by non-privileged accounts.</title>
#Windows must be configured to audit Other Policy Change Events Successes.</title>
#Windows must be configured to audit Other Policy Change Events Failures.</title>
auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable
#Windows must be configured to audit other Logon/Logoff Events Successes.</title>
#Windows must be configured to audit other Logon/Logoff Events Failures.</title>
uditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
#Windows must be configured to audit Detailed File Share Failures.</title>
auditpol /set /subcategory:"Detailed File Share" /failure:enable
#Windows must be configured to audit MPSSVC Rule-Level Policy Change Successes.</title>
#Windows must be configured to audit MPSSVC Rule-Level Policy Change Failures.</title>
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
#The display of slide shows on the lock screen must be disabled.</title>
#IPv6 source routing must be configured to highest protection.</title>
#The system must be configured to prevent IP source routing.</title>
#The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes.</title>
#The system must be configured to ignore NetBIOS name release requests except from WINS servers.</title>
#Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems.</title>
#WDigest Authentication must be disabled.</title>
#Run as different user must be removed from context menus.</title>
#Insecure logons to an SMB server must be disabled.</title>
#Internet connection sharing must be disabled.</title>
#Hardened UNC Paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares.</title>
#Simultaneous connections to the internet or a Windows domain must be limited.</title>
#Connections to non-domain networks when connected to a domain authenticated network must be blocked.</title>
#Wi-Fi Sense must be disabled.</title>
#Command line data must be included in process creation events.</title>
#Windows must be configured to enable Remote host allows delegation of non-exportable credentials.</title>
#Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers.</title>
#Group Policy objects must be reprocessed even if they have not changed.</title>
#Downloading print driver packages over HTTP must be prevented.</title>
#Web publishing and online ordering wizards must be prevented from downloading a list of providers.</title>
#Printing over HTTP must be prevented.</title>
#Systems must at least attempt device authentication using certificates.</title>
#The network selection user interface (UI) must not be displayed on the logon screen.</title>
#Local users on domain-joined computers must not be enumerated.</title>
#Users must be prompted for a password on resume from sleep (on battery).</title>
#The user must be prompted for a password on resume from sleep (plugged in).</title>
#Solicited Remote Assistance must not be allowed.</title>
#Unauthenticated RPC clients must be restricted from connecting to the RPC server.</title>
#The setting to allow Microsoft accounts to be optional for modern style apps must be enabled.</title>
#The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.</title>
#Autoplay must be turned off for non-volume devices.</title>
#The default autorun behavior must be configured to prevent autorun commands.</title>
#Autoplay must be disabled for all drives.</title>
#Enhanced anti-spoofing for facial recognition must be enabled on Windows.</title>
#Microsoft consumer experiences must be turned off.</title>
#Administrator accounts must not be enumerated during elevation.</title>
#Windows Telemetry must not be configured to Full.</title>
#Windows Update for workstations must not obtain updates from other PCs on the internet.</title>
#The Microsoft Defender SmartScreen for Explorer must be enabled.</title>
#Explorer Data Execution Prevention must be enabled.</title>
#File Explorer heap termination on corruption must be disabled.</title>
#File Explorer shell protocol must run in protected mode.</title>
#Windows must be configured to disable Windows Game Recording and Broadcasting.</title>
#The use of a hardware security device with Windows Hello for Business must be enabled.</title>
#Windows must be configured to require a minimum pin length of six characters or greater.</title>
#Passwords must not be saved in the Remote Desktop Client.</title>
#Local drives must be prevented from sharing with Remote Desktop Session Hosts.</title>
#Remote Desktop Services must always prompt a client for passwords upon connection.</title>
#The Remote Desktop Session Host must require secure RPC communications.</title>
#Remote Desktop Services must be configured with the client connection encryption set to the required level.</title>
#Attachments must be prevented from being downloaded from RSS feeds.</title>
#Basic authentication for RSS feeds over HTTP must not be used.</title>
#Indexing of encrypted files must be turned off.</title>
#Users must be prevented from changing installation options.</title>
#The Windows Installer feature "Always install with elevated privileges" must be disabled.</title>
#Users must be notified if a web-based program attempts to install software.</title>
#Automatically signing in the last interactive user after a system-initiated restart must be disabled.</title>
#PowerShell script block logging must be enabled on Windows.</title>
#PowerShell Transcription must be enabled on Windows.</title>
#The Windows Remote Management (WinRM) client must not use Basic authentication.</title>
#The Windows Remote Management (WinRM) client must not allow unencrypted traffic.</title>
#The Windows Remote Management (WinRM) service must not use Basic authentication.</title>
#The Windows Remote Management (WinRM) service must not store RunAs credentials.</title>
#The Windows Remote Management (WinRM) client must not use Digest authentication.</title>
#Windows must be configured to prevent Windows apps from being activated by voice while the system is locked.</title>
#The convenience PIN for Windows must be disabled.</title>
#Windows Ink Workspace must be configured to disallow access above the lock.</title>
#Windows Kernel (Direct Memory Access) DMA Protection must be enabled.</title>
#The IG Root CA certificates must be installed in the Trusted Root Store.</title>
#The built-in administrator account must be disabled.</title>
#The built-in guest account must be disabled.</title>
#Local accounts with blank passwords must be restricted to prevent access from the network.</title>
#The built-in administrator account must be renamed.</title>
#The built-in guest account must be renamed.</title>
#Audit policy using subcategories must be enabled.</title>
#Outgoing secure channel traffic must be encrypted or signed.</title>
#Outgoing secure channel traffic must be encrypted.</title>
#Outgoing secure channel traffic must be signed.</title>
#The computer account password must not be prevented from being reset.</title>
#The maximum age for machine account passwords must be configured to 30 days or less.</title>
#The system must be configured to require a strong session key.</title>
#The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.</title>
#Caching of logon credentials must be limited.</title>
#The Smart Card removal option must be configured to Force Logoff or Lock Workstation.</title>
#The Windows SMB client must be configured to always perform SMB packet signing.</title>
#Unencrypted passwords must not be sent to third-party SMB Servers.</title>
#The Windows SMB server must be configured to always perform SMB packet signing.</title>
#Anonymous enumeration of SAM accounts must not be allowed.</title>
#Anonymous enumeration of shares must be restricted.</title>
#The system must be configured to prevent anonymous users from having the same rights as the Everyone group.</title>
#Anonymous access to Named Pipes and Shares must be restricted.</title>
#Remote calls to the Security Account Manager (SAM) must be restricted to Administrators.</title>
#NTLM must be prevented from falling back to a Null session.</title>
#PKU2U authentication using online identities must be prevented.</title>
#Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.</title>
#The system must be configured to prevent the storage of the LAN Manager hash of passwords.</title>
#The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.</title>
#The system must be configured to the required LDAP client signing level.</title>
#The system must be configured to meet the minimum session security requirement for NTLM SSP based clients.</title>
#The system must be configured to meet the minimum session security requirement for NTLM SSP based servers.</title>
#The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.</title>
#The default permissions of global system objects must be increased.</title>
#User Account Control approval mode for the built-in Administrator must be enabled.</title>
#User Account Control must prompt administrators for consent on the secure desktop.</title>
#Windows must use multifactor authentication for local and network access to privileged and non-privileged accounts.</title>
#User Account Control must automatically deny elevation requests for standard users.</title>
#User Account Control must be configured to detect application installations and prompt for elevation.</title>
#User Account Control must only elevate UIAccess applications that are installed in secure locations.</title>
#User Account Control must run all administrators in Admin Approval Mode, enabling UAC.</title>
#User Account Control must virtualize file and registry write failures to per-user locations.</title>
#The "Access Credential Manager as a trusted caller" user right must not be assigned to any groups or accounts.</title>
#The "Access this computer from the network" user right must only be assigned to the Administrators and Remote Desktop Users groups.</title>
#The "Act as part of the operating system" user right must not be assigned to any groups or accounts.</title>
#The "Allow log on locally" user right must only be assigned to the Administrators and Users groups.</title>
#The "Back up files and directories" user right must only be assigned to the Administrators group.</title>
#The "Change the system time" user right must only be assigned to Administrators and Local Service.</title>
#The "Create a pagefile" user right must only be assigned to the Administrators group.</title>
#The "Create a token object" user right must not be assigned to any groups or accounts.</title>
#The "Create global objects" user right must only be assigned to Administrators, Service, Local Service, and Network Service.</title>
#The "Create permanent shared objects" user right must not be assigned to any groups or accounts.</title>
#The "Create symbolic links" user right must only be assigned to the Administrators group.</title>
#The "Debug programs" user right must only be assigned to the Administrators group.</title>
#The "Deny access to this computer from the network" user right on workstations must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems and unauthenticated access on all systems.</title>
#The "Deny log on as a batch job" user right on domain-joined workstations must be configured to prevent access from highly privileged domain accounts.</title>
#The "Deny log on as a service" user right on Windows domain-joined workstations must be configured to prevent access from highly privileged domain accounts.</title>
#The "Deny log on locally" user right on workstations must be configured to prevent access from highly privileged domain accounts on domain systems and unauthenticated access on all systems.</title>
#The "Deny log on through Remote Desktop Services" user right on Windows workstations must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems and unauthenticated access on all systems.</title>
#The "Enable computer and user accounts to be trusted for delegation" user right must not be assigned to any groups or accounts.</title>
#The "Force shutdown from a remote system" user right must only be assigned to the Administrators group.</title>
#The "Impersonate a client after authentication" user right must only be assigned to Administrators, Service, Local Service, and Network Service.</title>
#The "Load and unload device drivers" user right must only be assigned to the Administrators group.</title>
#The "Lock pages in memory" user right must not be assigned to any groups or accounts.</title>
#The "Manage auditing and security log" user right must only be assigned to the Administrators group.</title>
#The "Modify firmware environment values" user right must only be assigned to the Administrators group.</title>
#The "Perform volume maintenance tasks" user right must only be assigned to the Administrators group.</title>
#The "Profile single process" user right must only be assigned to the Administrators group.</title>
#The "Restore files and directories" user right must only be assigned to the Administrators group.</title>
#The "Take ownership of files or other objects" user right must only be assigned to the Administrators group.</title>
#Windows Update must not obtain updates from other PCs on the internet.</title>
#The Windows Remote Management (WinRM) service must not allow unencrypted traffic.</title>
#Internet Explorer must be disabled for Windows.</title>
#The system must be configured to audit Detailed Tracking - Process Creation failures.</title>

