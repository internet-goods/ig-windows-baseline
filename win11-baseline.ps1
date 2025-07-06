#https://stackoverflow.com/questions/25917637/create-folder-with-current-date-as-name-in-powershell
New-Item -ItemType Directory -Path ".\$((Get-Date).ToShortDateString())"
cd ".\$((Get-Date).ToShortDateString())"
#services
sc DoSvc stop
sc DoSvc start= disabled
sc upnphost stop
sc upnphost start= disabled

sc XboxGipSvc stop
sc XboxGipSvc start= disabled
sc XblAuthManager stop
sc XblAuthManager start= disabled
sc XblGameSave stop
sc XblGameSave start= disabled
sc XboxNetApiSvc stop
sc XboxNetApiSvc start= disabled
sc xbgm stop
sc xbgm start=disabled
#modules
Install-Module -Name SpeculationControl
Import-Module -Name SpeculationControl
#dism

#auditpol
auditpol.exe /get /category:* > auditpol_beforehardening.txt

#instrumentation
#Invoke-WebRequest https://pkg.osquery.io/windows/osquery-5.16.0.msi
#https://www.blumira.com/blog/enable-sysmon
#Invoke-WebRequest -Uri https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml -OutFile sysmonconfig.xml
#sysmon64.exe –accepteula –i config.xml
#winget
Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile winget.msixbundle
Add-AppxPackage winget.msixbundle
winget install --id Microsoft.Powershell --source winget
winget install --id Git.Git -e --source winget
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
Set-ProcessMitigation -System -Enable DEP
bcdedit.exe /set "{current}" nx AlwaysOn
Set-ProcessMitigation -System -Enable SEHOP
#Control flow guard (CFG)
Set-ProcessMitigation -System -Enable CFG
#ASLR
Set-ProcessMitigation -System -Eanble HighEntropy,ForceRelocateImages,BottomUp
#Heap integrity
Set-ProcessMitigation -System -Enable TerminateOnError

#downloads
Invoke-WebRequest https://github.com/mitre/saf/releases/download/1.4.21/saf-v1.4.21-x64.exe
Invoke-WebRequest https://download.sysinternals.com/files/ProcessExplorer.zip
Invoke-WebRequest https://github.com/git-for-windows/git/releases/download/v2.48.1.windows.1/Git-2.48.1-64-bit.exe


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
#The system must be configured to audit Detailed Tracking - Process Creation failures.</title>
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
auditpol /set /subcategory:'Sensitive Privilege Use' /success:enable /failure:enable
#The system must be configured to audit System - IPsec Driver failures.</title>
auditpol /set /subcategory:"IPsec Driver" /failure:enable
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
reg add HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application /v MaxSize /t REG_DWORD /d 32768 /f
#The Security event log size must be configured to 1024000 KB or greater.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security /v MaxSize /t REG_DWORD /d 1024000 /f
#The System event log size must be configured to 32768 KB or greater.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System /v MaxSize /t REG_DWORD /d 32768 /f
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
reg add HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters /v DisableIpSourcesRouting /t REG_DWORD /d 2 /f
#The system must be configured to prevent IP source routing.</title>
reg add HKLM\System\CurrentControlSet\Services\Tcpip\Parameters /v DisableIpSourcesRouting /t REG_DWORD /d 2 /f
#The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes.</title>
#The system must be configured to ignore NetBIOS name release requests except from WINS servers.</title>
reg add HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netbt\Parameters /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f
#Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems.</title>
#WDigest Authentication must be disabled.</title>
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f
#Run as different user must be removed from context menus.</title>
#Insecure logons to an SMB server must be disabled.</title>
reg add HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LanmanWorkstation /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f
#Internet connection sharing must be disabled.</title>
#Hardened UNC Paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares.</title>
#Simultaneous connections to the internet or a Windows domain must be limited.</title>
#Connections to non-domain networks when connected to a domain authenticated network must be blocked.</title>
#Wi-Fi Sense must be disabled.</title>
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f
#Command line data must be included in process creation events.</title>
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
#Windows must be configured to enable Remote host allows delegation of non-exportable credentials.</title>
#Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers.</title>
#Group Policy objects must be reprocessed even if they have not changed.</title>
#Downloading print driver packages over HTTP must be prevented.</title>
reg add HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers /v DisableHTTPPrinting /t REG_DWORD /d 1 /f
#Web publishing and online ordering wizards must be prevented from downloading a list of providers.</title>
#Printing over HTTP must be prevented.</title>
#Systems must at least attempt device authentication using certificates.</title>
#The network selection user interface (UI) must not be displayed on the logon screen.</title>
#Local users on domain-joined computers must not be enumerated.</title>
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\System /v EnumerateLocalUsers /t REG_DWORD /d 0 /f
#Users must be prompted for a password on resume from sleep (on battery).</title>
#The user must be prompted for a password on resume from sleep (plugged in).</title>
#Solicited Remote Assistance must not be allowed.</title>
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance /v fAllowToGetHelp /t REG_DWORD /d 0 /f
#Unauthenticated RPC clients must be restricted from connecting to the RPC server.</title>
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -Name RestrictRemoteClients -Value 2
#The setting to allow Microsoft accounts to be optional for modern style apps must be enabled.</title>
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v MSAOptional /t REG_DWORD /d 1 /f
#The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.</title>
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat /v DisablePropPage /t REG_DWORD /d 1 /f
#Autoplay must be turned off for non-volume devices.</title>
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f
#The default autorun behavior must be configured to prevent autorun commands.</title>
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoAutorun /t REG_DWORD /d 1 /f
#Autoplay must be disabled for all drives.</title>
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 0x000000ff /f
#Enhanced anti-spoofing for facial recognition must be enabled on Windows.</title>
reg add HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f
#Microsoft consumer experiences must be turned off.</title>
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
#Administrator accounts must not be enumerated during elevation.</title>
#Windows Telemetry must not be configured to Full.</title>
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection /v AllowTelemetry /t REG_DWORD /d 0 /f
#Windows Update for workstations must not obtain updates from other PCs on the internet.</title>
#The Microsoft Defender SmartScreen for Explorer must be enabled.</title>
#Explorer Data Execution Prevention must be enabled.</title>
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer /v NoDataExecutionPrevention /t REG_DWORD /d 0 /f
#File Explorer heap termination on corruption must be disabled.</title>
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer /v NoHeapTerminationOnCorruption /t REG_DWORD /d 1 /f
#File Explorer shell protocol must run in protected mode.</title>
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v PreXPSP2ShellProtocolBehavior /t REG_DWORD /d 0 /f
#Windows must be configured to disable Windows Game Recording and Broadcasting.</title>
reg add HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR /v AppCaptureEnabled /t REG_DWORD /d 0 /f
#The use of a hardware security device with Windows Hello for Business must be enabled.</title>
#Windows must be configured to require a minimum pin length of six characters or greater.</title>
#Passwords must not be saved in the Remote Desktop Client.</title>
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services" /v DisablePasswordSaving /t REG_DWORD /d 1 /f
#Local drives must be prevented from sharing with Remote Desktop Session Hosts.</title>
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f
#Remote Desktop Services must always prompt a client for passwords upon connection.</title>
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fPromptForPassword /t REG_DWORD /d 1 /f
#The Remote Desktop Session Host must require secure RPC communications.</title>
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
#Remote Desktop Services must be configured with the client connection encryption set to the required level.</title>
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MinEncryptionLevel /t REG_DWORD /d 3 /f
#Attachments must be prevented from being downloaded from RSS feeds.</title>
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" /v DisableEnclosureDownload /t REG_DWORD /d 1 /f
#Basic authentication for RSS feeds over HTTP must not be used.</title>
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" /v AllowBasicAuthInClear /t REG_DWORD /d 0 /f
#Indexing of encrypted files must be turned off.</title>
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f
#Users must be prevented from changing installation options.</title>
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v EnableUserControl /t REG_DWORD /d 0 /f
#The Windows Installer feature "Always install with elevated privileges" must be disabled.</title>
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f
#Users must be notified if a web-based program attempts to install software.</title>
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v SafeForScripting /t REG_DWORD /d 0 /f
#Automatically signing in the last interactive user after a system-initiated restart must be disabled.</title>
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription  /v EnableTranscripting /t REG_DWORD /d 1 /f
#PowerShell script block logging must be enabled on Windows.</title>
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
#PowerShell Transcription must be enabled on Windows.</title>
#The Windows Remote Management (WinRM) client must not use Basic authentication.</title>
reg add HKLM\Software\Policies\Microsoft\Windows\WinRM\Client /v AllowBasic /t REG_DWORD /d 0 /f
#The Windows Remote Management (WinRM) client must not allow unencrypted traffic.</title>
reg add HKLM\Software\Policies\Microsoft\Windows\WinRM\Client /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f
#The Windows Remote Management (WinRM) service must not use Basic authentication.</title>
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service /v AllowBasic /t REG_DWORD /d 0 /f
#The Windowr Remote Management (WinRM) service must not store RunAs credentials.</title>
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service /v DisableRunAs /t REG_DWORD /d 1 /f
#The Windows Remote Management (WinRM) client must not use Digest authentication.</title>
reg add HKLM\Software\Policies\Microsoft\Windows\WinRM\Client /v AllowDigest /t REG_DWORD /d 0 /f
#Windows must be configured to prevent Windows apps from being activated by voice while the system is locked.</title>
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy /v LetAppsActivateWithVoice /t REG_DWORD /d 0 /f
#The convenience PIN for Windows must be disabled.</title>
#Windows Ink Workspace must be configured to disallow access above the lock.</title>
reg add HKLM\Software\Policies\Microsoft\WindowsInkWorkspace /v AllowWindowsInkWorkspace /t REG_DWORD /d 1 /f
#Windows Kernel (Direct Memory Access) DMA Protection must be enabled.</title>
reg add "HKLM\Software\Policies\Microsoft\Windows\Kernel DMA Protection" /v DeviceEnumerationPolicy /t REG_DWORD /d 0 /f
#The IG Root CA certificates must be installed in the Trusted Root Store.</title>
#The built-in administrator account must be disabled.</title>
net user administrator /active:no
#The built-in guest account must be disabled.</title>
net user Guest /active:no
#Local accounts with blank passwords must be restricted to prevent access from the network.</title>
#The built-in administrator account must be renamed.</title>
wmic useraccount where name='Administrator' rename 'IGAdministrator'
#The built-in guest account must be renamed.</title>
wmic useraccount where name='Guest' rename 'IGGuest'
#Audit policy using subcategories must be enabled.</title>
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
#Outgoing secure channel traffic must be encrypted or signed.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
#Outgoing secure channel traffic must be encrypted.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
#Outgoing secure channel traffic must be signed.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
#The computer account password must not be prevented from being reset.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 0 /f
#The maximum age for machine account passwords must be configured to 30 days or less.</title>
#The system must be configured to require a strong session key.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
#The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.</title>
#Caching of logon credentials must be limited.</title>
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_DWORD /d 0 /f
#The Smart Card removal option must be configured to Force Logoff or Lock Workstation.</title>
reg add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v SCRemoveOption -t REG_SZ /d 2 /f
#The Windows SMB client must be configured to always perform SMB packet signing.</title>
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters /v RequireSecuritySignature /t REG_DWORD /d 1 /f
#Unencrypted passwords must not be sent to third-party SMB Servers.</title>
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
#The Windows SMB server must be configured to always perform SMB packet signing.</title>
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters /v RequireSecuritySignature /t REG_DWORD /d 1 /f
#Anonymous enumeration of SAM accounts must not be allowed.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
#Anonymous enumeration of shares must be restricted.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictAnonymous /t REG_DWORD /d 2 /f
#The system must be configured to prevent anonymous users from having the same rights as the Everyone group.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f
#Anonymous access to Named Pipes and Shares must be restricted.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters /v RestrictNullSessAccess /t REG_DWORD /d 1 /f
#Remote calls to the Security Account Manager (SAM) must be restricted to Administrators.</title>
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f
#NTLM must be prevented from falling back to a Null session.</title>
reg add HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0 /v allownullsessionfallback /t REG_DWORD /d 0 /f
#PKU2U authentication using online identities must be prevented.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u /v AllowOnlineID /t REG_DWORD /d 0 /f
#Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.</title>
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters /v REG_DWORD /d 0x7ffffff8 /f
#The system must be configured to prevent the storage of the LAN Manager hash of passwords.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v NoLMHash /t REG_DWORD /d 1 /f
#The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
#The system must be configured to the required LDAP client signing level.</title>
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP /v LDAPClientIntegrity /t REG_DWORD /d 2 /f
#The system must be configured to meet the minimum session security requirement for NTLM SSP based clients.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 /v NTLMMinClientSec /t REG_DWORD /d 0x20080000 /f
#The system must be configured to meet the minimum session security requirement for NTLM SSP based servers.</title>
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 /v NTLMMinServerSec /t REG_DWORD /d 0x20080000 /f
#The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.</title>
reg add HKLM\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolic /v Enabled /t REG_DWORD /d 1 /f
#The default permissions of global system objects must be increased.</title>
reg aDd HKLM\SYSTEM\CurrentControlSet\Control\Session Manager /v ProtectionMode /t REG_DWORD /d 1 /f
#User Account Control approval mode for the built-in Administrator must be enabled.</title>
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v FilterAdministratorToken /t REG_DWORD /d 1 /f
#User Account Control must prompt administrators for consent on the secure desktop.</title>
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
#Windows must use multifactor authentication for local and network access to privileged and non-privileged accounts.</title>
#User Account Control must automatically deny elevation requests for standard users.</title>
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f
#User Account Control must be configured to detect application installations and prompt for elevation.</title>
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
#User Account Control must only elevate UIAccess applications that are installed in secure locations.</title>
#User Account Control must run all administrators in Admin Approval Mode, enabling UAC.</title>
#User Account Control must virtualize file and registry write failures to per-user locations.</title>
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableVirtualization /t REG_DWORD /d 1 /f
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
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization /v DODownloadMode /t REG_DWORD /d 0 /f
#The Windows Remote Management (WinRM) service must not allow unencrypted traffic.</title>
#Internet Explorer must be disabled for Windows.</title>
dism /online /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64
#firewall
#Windows Defender Firewall with Advanced Security must be enabled when connected to a domain.</xccdf:title>
#Windows Defender Firewall with Advanced Security must be enabled when connected to a private network.</xccdf:title>
#Windows Defender Firewall with Advanced Security must be enabled when connected to a public network.</xccdf:title>
#Windows Defender Firewall with Advanced Security must block unsolicited inbound connections when connected to a domain.</xccdf:title>
#Windows Defender Firewall with Advanced Security must allow outbound connections, unless a rule explicitly blocks the connection when connected to a domain.</xccdf:title>
#Windows Defender Firewall with Advanced Security log size must be configured for domain connections.</xccdf:title>
#Windows Defender Firewall with Advanced Security must log dropped packets when connected to a domain.</xccdf:title>
#Windows Defender Firewall with Advanced Security must log successful connections when connected to a domain.</xccdf:title>
#Windows Defender Firewall with Advanced Security must block unsolicited inbound connections when connected to a private network.</xccdf:title>
#Windows Defender Firewall with Advanced Security must allow outbound connections, unless a rule explicitly blocks the connection when connected to a private network.</xccdf:title>
#Windows Defender Firewall with Advanced Security log size must be configured for private network connections.</xccdf:title>
#Windows Defender Firewall with Advanced Security must log dropped packets when connected to a private network.</xccdf:title>
#Windows Defender Firewall with Advanced Security must log successful connections when connected to a private network.</xccdf:title>
#Windows Defender Firewall with Advanced Security must block unsolicited inbound connections when connected to a public network.</xccdf:title>
#Windows Defender Firewall with Advanced Security must allow outbound connections, unless a rule explicitly blocks the connection when connected to a public network.</xccdf:title>
#Windows Defender Firewall with Advanced Security local firewall rules must not be merged with Group Policy settings when connected to a public network.</xccdf:title>
#Windows Defender Firewall with Advanced Security local connection rules must not be merged with Group Policy settings when connected to a public network.</xccdf:title>
#Windows Defender Firewall with Advanced Security log size must be configured for public network connections.</xccdf:title>
#Windows Defender Firewall with Advanced Security must log dropped packets when connected to a public network.</xccdf:title>
#Windows Defender Firewall with Advanced Security must log successful connections when connected to a public network.</xccdf:title>
#chrome STIG
#V-221558	Medium	Firewall traversal from remote host must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v RemoteAccessHostFirewallTraversal /t REG_DWORD /d 0 /f
#V-221559	Medium	Site tracking users location must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DefaultGeolocationSetting /t REG_DWORD /d 2 /f
#V-221561	Medium	Sites ability to show pop-ups must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DefaultPopupsSetting /t REG_DWORD /d 2 /f
#V-221562	Medium	Extensions installation must be blocklisted by default.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v ExtensionInstallBlocklist /t REG_DWORD /d 1 /f
#V-221563	Low	Extensions that are approved for use must be allowlisted.
#V-221564	Medium	The default search providers name must be set.
#V-221565	Medium	The default search provider URL must be set to perform encrypted searches.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DefaultSearchProviderSearchURL /t REG_DWORD /d "https://www.google.com/search?q={searchTerms}" /f
#V-221566	Medium	Default search provider must be enabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DefaultSearchProviderName /t REG_DWORD /d "Google Encrypted" /f
#V-221567	Medium	The Password Manager must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v PasswordManagerEnabled /t REG_DWORD /d 0 /f
#V-221570	Medium	Background processing must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v BackgroundModeEnabled /t REG_DWORD /d 0 /f
#V-221571	Medium	Google Data Synchronization must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v SyncDisabled /t REG_DWORD /d 1 /f
#V-221572	Medium	The URL protocol schema javascript must be disabled.
#V-221573	Medium	Cloud print sharing must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v CloudPrintProxyEnabled /t REG_DWORD /d 0 /f
#V-221574	Medium	Network prediction must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v NetworkPredictionOptions /t REG_DWORD /d 2 /f
#V-221575	Medium	Metrics reporting to Google must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v MetricsReportingEnabled /t REG_DWORD /d 0 /f
#V-221576	Medium	Search suggestions must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v SearchSuggestEnabled /t REG_DWORD /d 0 /f
#V-221577	Medium	Importing of saved passwords must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v ImportSavedPasswords /t REG_DWORD /d 0 /f
#V-221578	Medium	Incognito mode must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v IncognitoModeAvailability /t REG_DWORD /d 1 /f
#V-221579	Medium	Online revocation checks must be performed.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v EnableOnlineRevocationChecks /t REG_DWORD /d 1 /f
#V-221580	Medium	Safe Browsing must be enabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v SafeBrowsingProtectionLevel /t REG_DWORD /d 1 /f
#V-221581	Medium	Browser history must be saved.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v SavingBrowserHistoryDisabled /t REG_DWORD /d 0 /f
#V-221584	Medium	The version of Google Chrome running on the system must be a supported version.
#V-221586	Medium	Deletion of browser history must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v AllowDeletingBrowserHistory /t REG_DWORD /d 0 /f
#V-221587	Medium	Prompt for download location must be enabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v PromptForDownloadLocation /t REG_DWORD /d 1 /f
#V-221588	Medium	Download restrictions must be configured.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DownloadRestrictions /t REG_DWORD /d 2 /f
#V-221590	Medium	Safe Browsing Extended Reporting must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v SafeBrowsingExtendedReportingEnabled /t REG_DWORD /d 0 /f
#V-221591	Medium	WebUSB must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DefaultWebUsbGuardSetting /t REG_DWORD /d 2 /f
#V-221592	Medium	Chrome Cleanup must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v ChromeCleanupEnabled /t REG_DWORD /d 0 /f
#V-221593	Medium	Chrome Cleanup reporting must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v ChromeCleanupReportingEnabled /t REG_DWORD /d 0 /f
#V-221594	Medium	Google Cast must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v EnableMediaRouter /t REG_DWORD /d 0 /f
#V-221595	Medium	Autoplay must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v AutoplayAllowed /t REG_DWORD /d 0 /f
#V-221596	Medium	URLs must be allowlisted for Autoplay use.
#V-221597	Medium	Anonymized data collection must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v UrlKeyedAnonymizedDataCollectionEnabled /t REG_DWORD /d 0 /f
#V-221598	Medium	Collection of WebRTC event logs must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v WebRtcEventLogCollectionAllowed /t REG_DWORD /d 0 /f
#V-221599	Low	Chrome development tools must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DeveloperToolsAvailability /t REG_DWORD /d 0 /f
#V-226401	Medium	Guest Mode must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v BrowserGuestModeEnabled /t REG_DWORD /d 0 /f
#V-226402	Medium	AutoFill for credit cards must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v AutofillCreditCardEnabled /t REG_DWORD /d 0 /f
#V-226403	Medium	AutoFill for addresses must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v AutofillAddressEnabled /t REG_DWORD /d 0 /f
#V-226404	Medium	Import AutoFill form data must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v ImportAutofillFormData /t REG_DWORD /d 0 /f
#V-241787	Medium	Web Bluetooth API must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DefaultWebBluetoothGuardSetting REG_DWORD /d 2 /f
#V-245538	Medium	Use of the QUIC protocol must be disabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v QuicAllowed /t REG_DWORD /d 0 /f
#V-245539	Medium	Session only based cookies must be enabled.
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome /v DefaultCookiesSetting /t REG_DWORD /d 4 /f

#assessments
git clone https://github.com/scipag/HardeningKitty
Import-Module HardeningKitty\HardeningKitty.psm1
Invoke-HardeningKitty -EmojiSupport
#1000   Features        SMBv1 Support
#1103   Account Policies        Store passwords using reversible encryption
#1101   Account Policies        Account lockout duration
#1100   Account Policies        Account lockout threshold
#1104   Account Policies        Allow Administrator account lockout
#1102   Account Policies        Reset account lockout counter
#1200   User Rights Assignment  Access this computer from the network
#1201   User Rights Assignment  Allow log on locally
#1202   User Rights Assignment  Debug programs
#1203   User Rights Assignment  Deny access to this computer from the network
#1204   User Rights Assignment  Deny log on as a batch job
#1205   User Rights Assignment  Deny log on as a service
#1206   User Rights Assignment  Deny log on through Remote Desktop Services
#1300   Security Options        Accounts: Block Microsoft accounts
#1301   Security Options        Audit: Force audit policy subcategory settings to override audit policy category settings
#1302   Security Options        Interactive logon: Do not require CTRL+ALT+DEL
#1303   Security Options        Interactive logon: Don't display last signed-in
#1304   Security Options        Interactive logon: Don't display username at sign-in
#1305   Security Options        Microsoft network client: Digitally sign communications (always)
#1306   Security Options        Microsoft network client: Digitally sign communications (if server agrees)
#1307   Security Options        Microsoft network server: Digitally sign communications (always)
#1308   Security Options        Microsoft network server: Digitally sign communications (if client agrees)
#1309   Security Options        Network access: Do not allow anonymous enumeration of SAM accounts
#1310   Security Options        Network access: Do not allow anonymous enumeration of SAM accounts and shares
#1311   Security Options        Network access: Do not allow storage of passwords and credentials for network authentication
#1324   Security Options        Network access: Restrict anonymous access to Named Pipes and Shares
#1325   Security Options        Network access: Restrict clients allowed to make remote calls to SAM
#1312   Security Options        Network security: Allow LocalSystem NULL session fallback
#1326   Security Options        Network security: Do not store LAN Manager hash value on next password change
#1313   Security Options        Network security: LAN Manager authentication level
#1314   Security Options        Network security: LDAP client signing requirements
#1315   Security Options        Network security: Minimum session security for NTLM SSP based (including secure RPC) clients
#1316   Security Options        Network security: Minimum session security for NTLM SSP based (including secure RPC) servers
#1317   Security Options        Network security: Restrict NTLM: Audit Incoming NTLM Traffic
#1318   Security Options        Network security: Restrict NTLM: Audit NTLM authentication in this domain
#1319   Security Options        Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers
#1320   Security Options        Shutdown: Allow system to be shut down without having to log on
#1321   Security Options        User Account Control: Admin Approval Mode for the Built-in Administrator account
#1322   Security Options        User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode
#1323   Security Options        User Account Control: Behavior of the elevation prompt for standard users
#1400   Windows Firewall        EnableFirewall (Domain Profile, Policy)
#1418   Windows Firewall        EnableFirewall (Domain Profile)
#1401   Windows Firewall        Inbound Connections (Domain Profile, Policy)
#1419   Windows Firewall        Inbound Connections (Domain Profile)
#1402   Windows Firewall        Outbound Connections (Domain Profile, Policy)
#1420   Windows Firewall        Outbound Connections (Domain Profile)
#1403   Windows Firewall        Log size limit (Domain Profile, Policy)
#1421   Windows Firewall        Log size limit (Domain Profile)
#1404   Windows Firewall        Log dropped packets (Domain Profile, Policy)
#1422   Windows Firewall        Log dropped packets (Domain Profile)
#1405   Windows Firewall        Log successful connections (Domain Profile, Policy)
#1423   Windows Firewall        Log successful connections (Domain Profile)
#1406   Windows Firewall        EnableFirewall (Private Profile, Policy)
#1424   Windows Firewall        EnableFirewall (Private Profile)
#1407   Windows Firewall        Inbound Connections (Private Profile, Policy)
#1425   Windows Firewall        Inbound Connections (Private Profile)
#1408   Windows Firewall        Outbound Connections (Private Profile, Policy)
#1426   Windows Firewall        Outbound Connections (Private Profile)
#1409   Windows Firewall        Log size limit (Private Profile, Policy)
#1427   Windows Firewall        Log size limit (Private Profile)
#1410   Windows Firewall        Log dropped packets (Private Profile, Policy)
#1428   Windows Firewall        Log dropped packets (Private Profile)
#1411   Windows Firewall        Log successful connections (Private Profile, Policy)
#1429   Windows Firewall        Log successful connections (Private Profile)
#1412   Windows Firewall        EnableFirewall (Public Profile, Policy)
#1430   Windows Firewall        EnableFirewall (Public Profile)
#1413   Windows Firewall        Inbound Connections (Public Profile, Policy)
#1431   Windows Firewall        Inbound Connections (Public Profile)
#1414   Windows Firewall        Outbound Connections (Public Profile, Policy)
#1432   Windows Firewall        Outbound Connections (Public Profile)
#1415   Windows Firewall        Log size limit (Public Profile, Policy)
#1433   Windows Firewall        Log size limit (Public Profile)
#1416   Windows Firewall        Log dropped packets (Public Profile, Policy)
#1434   Windows Firewall        Log dropped packets (Public Profile)
#1417   Windows Firewall        Log successful connections (Public Profile, Policy)
#1435   Windows Firewall        Log successful connections (Public Profile)
#1500   Advanced Audit Policy Configuration     Credential Validation
#1501   Advanced Audit Policy Configuration     Security Group Management
#1502   Advanced Audit Policy Configuration     User Account Management
#1503   Advanced Audit Policy Configuration     DPAPI Activity
#1504   Advanced Audit Policy Configuration     Plug and Play Events
#1505   Advanced Audit Policy Configuration     Process Creation
#1506   Advanced Audit Policy Configuration     Account Lockout
#1507   Advanced Audit Policy Configuration     Group Membership
#1508   Advanced Audit Policy Configuration     Logon
#1509   Advanced Audit Policy Configuration     Other Logon/Logoff Events
#1510   Advanced Audit Policy Configuration     Special Logon
#1511   Advanced Audit Policy Configuration     Detailed File Share
#1512   Advanced Audit Policy Configuration     File Share
#1513   Advanced Audit Policy Configuration     Kernel Object
#1514   Advanced Audit Policy Configuration     Other Object Access Events
#1515   Advanced Audit Policy Configuration     Removable Storage
#1516   Advanced Audit Policy Configuration     SAM
#1517   Advanced Audit Policy Configuration     Audit Policy Change
#1518   Advanced Audit Policy Configuration     Authentication Policy Change
#1519   Advanced Audit Policy Configuration     MPSSVC Rule-Level Policy Change
#1520   Advanced Audit Policy Configuration     Other Policy Change Events
#1521   Advanced Audit Policy Configuration     Sensitive Privilege Use
#1522   Advanced Audit Policy Configuration     Other System Events
#1523   Advanced Audit Policy Configuration     Security State Change
#1524   Advanced Audit Policy Configuration     Security System Extension
#1525   Advanced Audit Policy Configuration     System Integrity
#1600   Administrative Templates: Control Panel Personalization: Prevent enabling lock screen camera
#1601   Administrative Templates: Network       DNS Client: Turn off multicast name resolution (LLMNR)
#1602   Administrative Templates: Network       Lanman Workstation: Enable insecure guest logons
#1603   Administrative Templates: Network       Turn off Microsoft Peer-to-Peer Networking Services
#1604   Administrative Templates: Network       WLAN Settings: Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services
#2108   Administrative Templates: PowerShellCore        Turn on PowerShell Module Logging
#2109   Administrative Templates: PowerShellCore        Turn on PowerShell Module Logging (PowerShell Policy)
#2110   Administrative Templates: PowerShellCore        Turn on PowerShell Module Logging - Module Names
#2111   Administrative Templates: PowerShellCore        Turn on PowerShell Script Block Logging
#2112   Administrative Templates: PowerShellCore        Turn on PowerShell Script Block Logging (Invocation)
#2113   Administrative Templates: PowerShellCore        Turn on PowerShell Script Block Logging (PowerShell Policy)
#2116   Administrative Templates: PowerShellCore        Turn on PowerShell Transcription
#2114   Administrative Templates: PowerShellCore        Turn on PowerShell Transcription (Invocation)
#2115   Administrative Templates: PowerShellCore        Turn on PowerShell Transcription (PowerShell Policy)
#1772   Administrative Templates: Printers      Configure Redirection Guard
#1768   Administrative Templates: Printers      Only use Package Point and Print (CVE-2021-36958)
#1769   Administrative Templates: Printers      Package Point and Print - Approved servers (CVE-2021-36958)
#1764   Administrative Templates: Printers      Point and Print Restrictions: When installing drivers for a new connection (CVE-2021-34527)
#1765   Administrative Templates: Printers      Point and Print Restrictions: When updating drivers for an existing connection (CVE-2021-34527)
#1771   Administrative Templates: Start Menu and Taskbar        Notifications: Turn off notifications network usage
#1605   Administrative Templates: System        Credentials Delegation: Allow delegation default credentials
#1606   Administrative Templates: System        Credentials Delegation: Encryption Oracle Remediation
#1699   Administrative Templates: System        Credentials Delegation: Remote host allows delegation of non-exportable credentials
#1607   Administrative Templates: System        Device Installation: Device Installation Restrictions: Prevent installation of devices that match an ID
#1608   Administrative Templates: System        Device Installation: Device Installation Restrictions: Prevent installation of devices that match an ID (Retroactive)
#1609   Administrative Templates: System        Device Installation: Device Installation Restrictions: Prevent installation of devices that match ID PCI\CC_0C0010 (Firewire)
#1610   Administrative Templates: System        Device Installation: Device Installation Restrictions: Prevent installation of devices that match ID PCI\CC_0C0A (Thunderbolt)
#1611   Administrative Templates: System        Device Installation: Device Installation Restrictions: Prevent installation of devices using drivers that match an device setup class
#1612   Administrative Templates: System        Device Installation: Device Installation Restrictions: Prevent installation of devices using drivers that match an device setup class (Retroactive)
#1613   Administrative Templates: System        Device Installation: Device Installation Restrictions: Prevent installation of devices using drivers that match d48179be-ec20-11d1-b6b8-00c04fa372a7 (SBP-2 drive)
#1614   Administrative Templates: System        Device Guard: Virtualization Based Security Status
#1615   Administrative Templates: System        Device Guard: Available Security Properties: Secure Boot
#1616   Administrative Templates: System        Device Guard: Available Security Properties: DMA protection
#1617   Administrative Templates: System        Device Guard: Security Services Configured: Credential Guard
#1619   Administrative Templates: System        Device Guard: Security Services Running: Credential Guard
#1618   Administrative Templates: System        Device Guard: Security Services Configured: HVCI
#1620   Administrative Templates: System        Device Guard: Security Services Running: HVCI
#1623   Administrative Templates: System        Device Guard: Require UEFI Memory Attributes Table (Policy)
#1621   Administrative Templates: System        Device Guard: Secure Launch Configuration (Policy)
#1622   Administrative Templates: System        Device Guard: Windows Defender Application Control deployed (Policy)
#1630   Administrative Templates: System        Early Launch Antimalware: Boot-Start Driver Initialization Policy
#1631   Administrative Templates: System        Group Policy: Process even if the Group Policy objects have not changed
#1632   Administrative Templates: System        Group Policy: Do not apply during periodic background processing
#1640   Administrative Templates: System        Internet Communication Management: Internet Communication settings: Turn off the Windows Messenger Customer Experience Improvement Program
#1641   Administrative Templates: System        Internet Communication Management: Internet Communication settings: Turn off downloading of print drivers over HTTP
#1642   Administrative Templates: System        Internet Communication Management: Internet Communication settings: Turn off Windows Error Reporting 1
#1643   Administrative Templates: System        Internet Communication Management: Internet Communication settings: Turn off Windows Error Reporting 2
#1644   Administrative Templates: System        Internet Communication Management: Internet Communication settings: Turn off Internet download for Web publishing and online ordering wizards
#1645   Administrative Templates: System        Internet Communication Management: Internet Communication settings: Turn off Windows Customer Experience Improvement Program
#1650   Administrative Templates: System        Kernel DMA Protection: Enumeration policy for external devices incompatible with Kernel DMA Protection
#1660   Administrative Templates: System        Logon: Turn on convenience PIN sign-in
#1661   Administrative Templates: System        Logon: Turn off app notifications on the lock screen
#1662   Administrative Templates: System        Logon: Do not display network selection UI
#1670   Administrative Templates: System        Mitigation Options: Untrusted Font Blocking
#1680   Administrative Templates: System        OS Policies: Allow Clipboard synchronization across devices
#1685   Administrative Templates: System        Sleep Settings: Require a password when a computer wakes (plugged in)
#1686   Administrative Templates: System        Sleep Settings: Require a password when a computer wakes (on battery)
#1687   Administrative Templates: System        Sleep Settings: Allow standby states (S1-S3) when sleeping (plugged in)
#1688   Administrative Templates: System        Sleep Settings: Allow standby states (S1-S3) when sleeping (on battery)
#1690   Administrative Templates: System        Remote Assistance: Configure Offer Remote Assistance
#1691   Administrative Templates: System        Remote Assistance: Configure Solicited Remote Assistance
#1692   Administrative Templates: System        Remote Procedure Call: Enable RPC Endpoint Mapper Client Authentication
#1693   Administrative Templates: System        Remote Procedure Call: Restrict Unauthenticated RPC clients
#1694   Administrative Templates: System        Security Settings: Enable svchost.exe mitigation options
#1695   Administrative Templates: System        Windows Performance PerfTrack: Enable/Disable PerfTrack
#1696   Administrative Templates: System        User Profiles: Turn off the advertising ID
#1697   Administrative Templates: System        Time Providers: Enable Windows NTP Client
#1698   Administrative Templates: System        Time Providers: Enable Windows NTP Server
#1700   Administrative Templates: Windows Components    App Package Deployment: Allow a Windows app to share application data between users
#1701   Administrative Templates: Windows Components    App Privacy: Let Windows apps activate with voice while the system is locked
#1702   Administrative Templates: Windows Components    App runtime: Block launching Universal Windows apps with Windows Runtime API access from hosted content
#1703   Administrative Templates: Windows Components    Application Compatibility: Turn off Application Telemetry
#1704   Administrative Templates: Windows Components    AutoPlay Policies: Turn off Autoplay
#1705   Administrative Templates: Windows Components    AutoPlay Policies: Disallow Autoplay for non-volume devices
#1706   Administrative Templates: Windows Components    AutoPlay Policies: Set the default behavior for AutoRun
#1707   Administrative Templates: Windows Components    Biometrics: Allow the use of biometrics
#1773   Administrative Templates: Windows Components    Biometrics: Facial Features: Configure enhanced anti-spoofing
#1708   Administrative Templates: Windows Components    BitLocker Drive Encryption: Volume status
#1761   Administrative Templates: Windows Components    BitLocker Drive Encryption: Choose drive encryption method and cipher strength (for operating system drives)
#1762   Administrative Templates: Windows Components    BitLocker Drive Encryption: Drive encryption method (for operating system drives)
#1709   Administrative Templates: Windows Components    BitLocker Drive Encryption: Disable new DMA devices when this computer is locked
#1710   Administrative Templates: Windows Components    BitLocker Drive Encryption: Operating System Drives: Allow Secure Boot for integrity validation
#1711   Administrative Templates: Windows Components    BitLocker Drive Encryption: Operating System Drives: Require additional authentication at startup
#1715   Administrative Templates: Windows Components    BitLocker Drive Encryption: Operating System Drives: Require additional authentication at startup: Allow BitLocker without a compatible TPM
#1716   Administrative Templates: Windows Components    BitLocker Drive Encryption: Operating System Drives: Require additional authentication at startup: Configure TPM startup
#1717   Administrative Templates: Windows Components    BitLocker Drive Encryption: Operating System Drives: Require additional authentication at startup: Configure TPM startup PIN
#1718   Administrative Templates: Windows Components    BitLocker Drive Encryption: Operating System Drives: Require additional authentication at startup: Configure TPM startup key
#1719   Administrative Templates: Windows Components    BitLocker Drive Encryption: Operating System Drives: Require additional authentication at startup: Configure TPM startup key and PIN
#1712   Administrative Templates: Windows Components    BitLocker Drive Encryption: Operating System Drives: Allow enhanced PINs for startup
#1713   Administrative Templates: Windows Components    BitLocker Drive Encryption: Operating System Drives: Configure use of hardware-based encryption for operating system drives
#1763   Administrative Templates: Windows Components    BitLocker Drive Encryption: Operating System Drives: Configure minimum PIN length for startup
#1720   Administrative Templates: Windows Components    Cloud Content: Do not show Windows tips
#1721   Administrative Templates: Windows Components    Cloud Content: Turn off Microsoft consumer experiences
#1722   Administrative Templates: Windows Components    Credential User Interface: Do not display the password reveal button
#1724   Administrative Templates: Windows Components    Credential User Interface: Enumerate administrator accounts on elevation
#1725   Administrative Templates: Windows Components    Data Collection and Preview Builds: Allow Diagnostic Data
#1726   Administrative Templates: Windows Components    Data Collection and Preview Builds: Allow device name to be sent in Windows diagnostic data
#1727   Administrative Templates: Windows Components    Delivery Optimization: Download Mode
#1728   Administrative Templates: Windows Components    Event Log Service: Application: Specify the maximum log file size (KB)
#1729   Administrative Templates: Windows Components    Event Log Service: Security: Specify the maximum log file size (KB)
#1730   Administrative Templates: Windows Components    Event Log Service: System: Specify the maximum log file size (KB)
#1774   Administrative Templates: Windows Components    Event Log Service: Microsoft-Windows-PowerShell/Operational: Specify the maximum log file size (KB)
#1775   Administrative Templates: Windows Components    Event Log Service: PowerShellCore/Operational: Specify the maximum log file size (KB)
#1731   Administrative Templates: Windows Components    File Explorer: Allow the use of remote paths in file shortcut icons
#1732   Administrative Templates: Windows Components    HomeGroup: Prevent the computer from joining a homegroup
#1800   Microsoft Defender Antivirus    Turn off Microsoft Defender Antivirus
#1826   Microsoft Defender Antivirus    Enable Tamper Protection (Status)
#1801   Microsoft Defender Antivirus    Configure detection for potentially unwanted applications
#1806   Microsoft Defender Antivirus    Exclusions: Extension Exclusions (Policy)
#1813   Microsoft Defender Antivirus    Exclusions: Extension Exclusions (Intune)
#1807   Microsoft Defender Antivirus    Exclusions: Extension Exclusions
#1808   Microsoft Defender Antivirus    Exclusions: Path Exclusions (Policy)
#1814   Microsoft Defender Antivirus    Exclusions: Path Exclusions (Intune)
#1809   Microsoft Defender Antivirus    Exclusions: Path Exclusions
#1810   Microsoft Defender Antivirus    Exclusions: Process Exclusions (Policy)
#1815   Microsoft Defender Antivirus    Exclusions: Process Exclusions (Intune)
#1811   Microsoft Defender Antivirus    Exclusions: Process Exclusions
#1816   Microsoft Defender Antivirus    MAPS: Join Microsoft MAPS
#1817   Microsoft Defender Antivirus    MAPS: Configure the 'Block at First Sight' feature
#1818   Microsoft Defender Antivirus    MAPS: Send file samples when further analysis is required
#1819   Microsoft Defender Antivirus    MpEngine: Enable file hash computation feature
#1820   Microsoft Defender Antivirus    MpEngine: Select cloud protection level
#1821   Microsoft Defender Antivirus    Real-time Protection: Scan all downloaded files and attachments
#1822   Microsoft Defender Antivirus    Real-time Protection: Turn off real-time protection
#1823   Microsoft Defender Antivirus    Real-time Protection: Turn on behavior monitoring (Policy)
#1824   Microsoft Defender Antivirus    Real-time Protection: Turn on script scanning
#1825   Microsoft Defender Antivirus    Scan: Scan removable drives
#1812   Microsoft Defender Antivirus    Enable sandboxing for Microsoft Defender Antivirus
#1900   Microsoft Defender Exploit Guard        Attack Surface Reduction rules
#1901   Microsoft Defender Exploit Guard        ASR: Block executable content from email client and webmail (Policy)
#1916   Microsoft Defender Exploit Guard        ASR: Block executable content from email client and webmail
#1933   Microsoft Defender Exploit Guard        ASR: Block executable content from email client and webmail (Intune)
#1902   Microsoft Defender Exploit Guard        ASR: Block all Office applications from creating child processes (Policy)
#1917   Microsoft Defender Exploit Guard        ASR: Block all Office applications from creating child processes
#1934   Microsoft Defender Exploit Guard        ASR: Block all Office applications from creating child processes (Intune)
#1903   Microsoft Defender Exploit Guard        ASR: Block Office applications from creating executable content (Policy)
#1918   Microsoft Defender Exploit Guard        ASR: Block Office applications from creating executable content
#1935   Microsoft Defender Exploit Guard        ASR: Block Office applications from creating executable content (Intune)
#1904   Microsoft Defender Exploit Guard        ASR: Block Office applications from injecting code into other processes (Policy)
#1919   Microsoft Defender Exploit Guard        ASR: Block Office applications from injecting code into other processes
#1936   Microsoft Defender Exploit Guard        ASR: Block Office applications from injecting code into other processes (Intune)
#1905   Microsoft Defender Exploit Guard        ASR: Block JavaScript or VBScript from launching downloaded executable content (Policy)
#1920   Microsoft Defender Exploit Guard        ASR: Block JavaScript or VBScript from launching downloaded executable content
#1937   Microsoft Defender Exploit Guard        ASR: Block JavaScript or VBScript from launching downloaded executable content (Intune)
#1906   Microsoft Defender Exploit Guard        ASR: Block execution of potentially obfuscated scripts (Policy)
#1921   Microsoft Defender Exploit Guard        ASR: Block execution of potentially obfuscated scripts
#1938   Microsoft Defender Exploit Guard        ASR: Block execution of potentially obfuscated scripts (Intune)
#1907   Microsoft Defender Exploit Guard        ASR: Block Win32 API calls from Office macros (Policy)
#1922   Microsoft Defender Exploit Guard        ASR: Block Win32 API calls from Office macros
#1939   Microsoft Defender Exploit Guard        ASR: Block Win32 API calls from Office macros (Intune)
#1908   Microsoft Defender Exploit Guard        ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion (Policy)
#1923   Microsoft Defender Exploit Guard        ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion
#1940   Microsoft Defender Exploit Guard        ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion (Intune)
#1909   Microsoft Defender Exploit Guard        ASR: Use advanced protection against ransomware (Policy)
#1924   Microsoft Defender Exploit Guard        ASR: Use advanced protection against ransomware
#1941   Microsoft Defender Exploit Guard        ASR: Use advanced protection against ransomware (Intune)
#1910   Microsoft Defender Exploit Guard        ASR: Block credential stealing from the Windows local security authority subsystem (lsass.exe) (Policy)
#1925   Microsoft Defender Exploit Guard        ASR: Block credential stealing from the Windows local security authority subsystem (lsass.exe)
#1942   Microsoft Defender Exploit Guard        ASR: Block credential stealing from the Windows local security authority subsystem (lsass.exe) (Intune)
#1911   Microsoft Defender Exploit Guard        ASR: Block process creations originating from PSExec and WMI commands (Policy)
#1926   Microsoft Defender Exploit Guard        ASR: Block process creations originating from PSExec and WMI commands
#1943   Microsoft Defender Exploit Guard        ASR: Block process creations originating from PSExec and WMI commands (Intune)
#1912   Microsoft Defender Exploit Guard        ASR: Block untrusted and unsigned processes that run from USB (Policy)
#1927   Microsoft Defender Exploit Guard        ASR: Block untrusted and unsigned processes that run from USB
#1944   Microsoft Defender Exploit Guard        ASR: Block untrusted and unsigned processes that run from USB (Intune)
#1913   Microsoft Defender Exploit Guard        ASR: Block Office communication application from creating child processes (Policy)
#1928   Microsoft Defender Exploit Guard        ASR: Block Office communication application from creating child processes
#1945   Microsoft Defender Exploit Guard        ASR: Block Office communication application from creating child processes (Intune)
#1914   Microsoft Defender Exploit Guard        ASR: Block Adobe Reader from creating child processes (Policy)
#1929   Microsoft Defender Exploit Guard        ASR: Block Adobe Reader from creating child processes
#1946   Microsoft Defender Exploit Guard        ASR: Block Adobe Reader from creating child processes (Intune)
#1915   Microsoft Defender Exploit Guard        ASR: Block persistence through WMI event subscription (Policy)
#1930   Microsoft Defender Exploit Guard        ASR: Block persistence through WMI event subscription
#1947   Microsoft Defender Exploit Guard        ASR: Block persistence through WMI event subscription (Intune)
#1931   Microsoft Defender Exploit Guard        ASR: Block abuse of exploited vulnerable signed drivers (Policy)
#1932   Microsoft Defender Exploit Guard        ASR: Block abuse of exploited vulnerable signed drivers
#1948   Microsoft Defender Exploit Guard        ASR: Block abuse of exploited vulnerable signed drivers (Intune)
#1966   Microsoft Defender Exploit Guard        ASR: Exclude files and paths from Attack Surface Reduction Rules (Policy)
#1967   Microsoft Defender Exploit Guard        ASR: Exclude files and paths from Attack Surface Reduction Rules
#1968   Microsoft Defender Exploit Guard        ASR: Exclude files and paths from Attack Surface Reduction Rules (Intune)
#1965   Microsoft Defender Exploit Guard        Network Protection: Prevent users and apps from accessing dangerous websites
#1767   Administrative Templates: Windows Components    News and interests: Enable news and interests on the taskbar
#1733   Administrative Templates: Windows Components    OneDrive: Prevent the usage of OneDrive for file storage
#1734   Administrative Templates: Windows Components    Remote Desktop Connection Client: Do not allow passwords to be saved
#1735   Administrative Templates: Windows Components    Remote Desktop Session Host: Allow users to connect remotely by using Remote Desktop Services
#1736   Administrative Templates: Windows Components    Remote Desktop Session Host: Device and Resource Redirection: Do not allow drive redirection
#1737   Administrative Templates: Windows Components    Remote Desktop Session Host: Security: Always prompt for password upon connection
#1738   Administrative Templates: Windows Components    Remote Desktop Session Host: Security: Require secure RPC communication
#1739   Administrative Templates: Windows Components    Remote Desktop Session Host: Security: Set client connection encryption level
#1740   Administrative Templates: Windows Components    Search: Allow Cloud Search
#1741   Administrative Templates: Windows Components    Search: Allow Cortana
#1742   Administrative Templates: Windows Components    Search: Allow Cortana above lock screen
#1743   Administrative Templates: Windows Components    Search: Allow indexing of encrypted files
#1744   Administrative Templates: Windows Components    Search: Allow search and Cortana to use location
#1745   Administrative Templates: Windows Components    Search: Set what information is shared in Search
#1746   Administrative Templates: Windows Components    Windows Error Reporting: Disable Windows Error Reporting
#1747   Administrative Templates: Windows Components    Windows Game Recording and Broadcasting: Enables or disables Windows Game Recording and Broadcasting
#1748   Administrative Templates: Windows Components    Windows Ink Workspace: Allow Windows Ink Workspace
#1749   Administrative Templates: Windows Components    Windows Installer: Always install with elevated privileges
#1750   Administrative Templates: Windows Components    Windows Installer: Allow user control over installs
#1751   Administrative Templates: Windows Components    Windows Installer: Prevent Internet Explorer security prompt for Windows Installer scripts
#1752   Administrative Templates: Windows Components    Windows Logon Options: Sign-in and lock last interactive user automatically after a restart
#1770   Administrative Templates: Windows Components    Windows Installer: Disable Co-Installer (USB AutoInstall)
#1753   Administrative Templates: Windows Components    WinRM Client: Allow Basic authentication
#1754   Administrative Templates: Windows Components    WinRM Client: Allow unencrypted traffic
#1755   Administrative Templates: Windows Components    WinRM Client: Disallow Digest authentication
#1756   Administrative Templates: Windows Components    WinRM Service: Allow remote server management through WinRM
#1757   Administrative Templates: Windows Components    WinRM Service: Allow Basic authentication
#1758   Administrative Templates: Windows Components    WinRM Service: Allow unencrypted traffic
#1759   Administrative Templates: Windows Components    WinRM Service: Disallow WinRM from storing RunAs credentials
#1760   Administrative Templates: Windows Components    Windows Remote Shell: Allow Remote Shell Access
#2000   Administrative Templates: Windows Components    File Explorer: Configure Windows Defender SmartScreen
#2001   Administrative Templates: Windows Components    File Explorer: Configure Windows Defender SmartScreen to warn and prevent bypass
#2105   PowerShell      Turn on PowerShell Module Logging
#2106   PowerShell      Turn on PowerShell Module Logging - Module Names
#2100   PowerShell      Turn on PowerShell Script Block Logging
#2101   PowerShell      Turn on PowerShell Script Block Logging (Invocation)
#2102   PowerShell      Turn on PowerShell Transcription
#2107   PowerShell      Turn on PowerShell Transcription (Invocation)
#2103   PowerShell      Disable PowerShell version 2
#2104   PowerShell      Disable PowerShell version 2 (root)
#2200   MS Security Guide       LSA Protection
#2201   MS Security Guide       Lsass.exe audit mode
#2202   MS Security Guide       NetBT NodeType configuration
#2203   MS Security Guide       WDigest Authentication
#2209   MS Security Guide       Enable Structured Exception Handling Overwrite Protection (SEHOP)
#2210   MS Security Guide       Limits print driver installation to Administrators
#2211   MS Security Guide       Configure RPC packet level privacy setting for incoming connections
#2212   MS Security Guide       Manage processing of Queue-specific files
#2204   MSS (Legacy)    MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)
#2205   MSS (Legacy)    MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)
#2206   MSS (Legacy)    MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)
#2207   MSS (Legacy)    MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes
#2208   MSS (Legacy)    MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers
#2400   Scheduled Task  XblGameSave Standby Task
#2411   System Services Disable mDNS in Dnscache service
#2401   System Services Print Spooler (Spooler)
#2402   System Services Print Spooler (Spooler) (Service Startup type)
#2412   System Services WebClient (WebClient)
#2413   System Services WebClient (WebClient) (Service Startup type)
#2403   System Services Xbox Accessory Management Service (XboxGipSvc)
#2404   System Services Xbox Accessory Management Service (XboxGipSvc) (Service Startup type)
#2405   System Services Xbox Live Auth Manager (XblAuthManager)
#2406   System Services Xbox Live Auth Manager (XblAuthManager) (Service Startup type)
#2407   System Services Xbox Live Game Save (XblGameSave)
#2408   System Services Xbox Live Game Save (XblGameSave) (Service Startup type)
#2409   System Services Xbox Live Networking Service (XboxNetApiSvc)
#2410   System Services Xbox Live Networking Service (XboxNetApiSvc) (Service Startup type)
#1950   Microsoft Defender Exploit Guard        Exploit protection: Control flow guard (CFG)
#1951   Microsoft Defender Exploit Guard        Exploit protection: Data Execution Prevention (DEP)
#1952   Microsoft Defender Exploit Guard        Exploit protection: Override Data Execution Prevention (DEP)
#1954   Microsoft Defender Exploit Guard        Exploit protection: Force randomization for images (Mandatory ASLR)
#1955   Microsoft Defender Exploit Guard        Exploit protection: Override force randomization for images (Mandatory ASLR)
#1956   Microsoft Defender Exploit Guard        Exploit protection: Randomize memory allocations (Bottom-up ASLR)
#1957   Microsoft Defender Exploit Guard        Exploit protection: Override randomize memory allocations (Bottom-up ASLR)
#1958   Microsoft Defender Exploit Guard        Exploit protection: High-entropy ASLR
#1959   Microsoft Defender Exploit Guard        Exploit protection: Override high-entropy ASLR
#1960   Microsoft Defender Exploit Guard        Exploit protection: Validate exception chains (SEHOP)
#1961   Microsoft Defender Exploit Guard        Exploit protection: Validate exception chains (SEHOP (Telemetry only)
#1962   Microsoft Defender Exploit Guard        Exploit protection: Override validate exception chains (SEHOP)
#1963   Microsoft Defender Exploit Guard        Exploit protection: Validate heap integrity
#1964   Microsoft Defender Exploit Guard        Exploit protection: Override validate heap integrity
#1953   Microsoft Defender Exploit Guard        Force use of Data Execution Prevention (DEP)
#2300   Windows Firewall        HardeningKitty-Block-TCP-NetBIOS
#2301   Windows Firewall        HardeningKitty-Block-TCP-RDP
#2302   Windows Firewall        HardeningKitty-Block-TCP-RPC
#2303   Windows Firewall        HardeningKitty-Block-TCP-SMB
#2304   Windows Firewall        HardeningKitty-Block-TCP-WinRM
#2305   Windows Firewall        HardeningKitty-Block-UDP-NetBIOS
#2306   Windows Firewall        HardeningKitty-Block-UDP-RPC
#2307   Windows Firewall        HardeningKitty-Block-calc-x64
#2308   Windows Firewall        HardeningKitty-Block-calc-x86
#2309   Windows Firewall        HardeningKitty-Block-certutil-x64
#2310   Windows Firewall        HardeningKitty-Block-certutil-x86
#2311   Windows Firewall        HardeningKitty-Block-conhost-x64
#2312   Windows Firewall        HardeningKitty-Block-conhost-x86
#2313   Windows Firewall        HardeningKitty-Block-cscript-x64
#2314   Windows Firewall        HardeningKitty-Block-cscript-x86
#2315   Windows Firewall        HardeningKitty-Block-mshta-x64
#2316   Windows Firewall        HardeningKitty-Block-mshta-x86
#2317   Windows Firewall        HardeningKitty-Block-notepad-x64
#2318   Windows Firewall        HardeningKitty-Block-notepad-x86
#2319   Windows Firewall        HardeningKitty-Block-RunScriptHelper-x64
#2320   Windows Firewall        HardeningKitty-Block-RunScriptHelper-x86
#2321   Windows Firewall        HardeningKitty-Block-wscript-x64



auditpol.exe /get /category:* > auditpol_afterhardening.txt

git clone https://github.com/Sneakysecdoggo/Wynis
cd "Wynis\System Audit"
.\WynisWIN11-CISv0.9.ps1"

#PP-1.1.1;(L1)Ensure 'Enforce password history' is set to '24 or more password(s), value must be 24 or More;PasswordHistorySize = 0
#PP-1.1.2;(L1)Maximum password age is set to 365 or fewer days, value must be 365 or less but not 0;MaximumPasswordAge = 42
#PP-1.1.3;(L1)Minimum password age is set to 1 or more day(s), value must be 1 or more but not 0;MinimumPasswordAge = 0
#PP-1.1.4;(L1)Minimum password length is set to 14 or more character(s), value must be 14 or more;MinimumPasswordLength = 0
#PP-1.1.5;(L1)Password must meet complexity requirements is set to Enabled, value must be 1;PasswordComplexity = 0
#PP-1.1.6;(L1)Relax minimum password length limits' is set to Enabled, value must be 1 (Warning this may cause compatibility issues);not configure
#PP-1.1.7;(L1)Store passwords using reversible encryption is set to Disabled, value must be 0;ClearTextPassword = 0
#ALP-1.2.1;(L1)Account lockout duration is set to 15 or more minute(s);Lockout duration (minutes):                           30
#ALP-1.2.2;(L1)Ensure Account lockout threshold is set to 5 or fewer invalid logon attempt(s), but not 0;Lockout threshold:                                    Never
#ALP-1.2.3;(L1)Allow Administrator account lockout is set to Enabled, value must be 1;
#ALP-1.2.4;(L1)Reset account lockout counter after is set to 15 or more minute(s);Lockout observation window (minutes):                 30
#URA-2.2.1;(L1)Acess Credential Manager as a trusted caller is set to No One , value must be empty;
#URA-2.2.2;(L1)Access this computer from the network, Only Administrators, Remote Desktop Users ;SeNetworkLogonRight:Everyone|BUILTIN\Administrators|BUILTIN\Users|BUILTIN\Users|
#URA-2.2.3;(L1)Act as part of the operating system' , Must be empty ;SeTcbPrivilege:
#URA-2.2.4;(L1)Adjust memory quotas for a process , Administrators, LOCAL SERVICE, NETWORK SERVICE ;SeIncreaseQuotaPrivilege:NT AUTHORITY\LOCAL SERVICE|NT AUTHORITY\NETWORK SERVICE|BUILTIN\Administrators|
#URA-2.2.5;(L1)Allow log on locally, Administrators, Users;SeInteractiveLogonRight:BUILTIN\Administrators|BUILTIN\Users|BUILTIN\Users|
#URA-2.2.6;(L1)Allow log on through Remote Desktop Services, Only Administrators, Remote Desktop Users. If Remote Apps or CItrix authentificated users;SeRemoteInteractiveLogonRight:BUILTIN\Administrators|BUILTIN\Administrators|
#URA-2.2.7;(L1)Ensure Back up files and directories, Only Administrators,;SeBackupPrivilege:BUILTIN\Administrators|BUILTIN\Administrators|
#URA-2.2.8;(L1)Change the system time, Only Administrators and local service;SeSystemtimePrivilege:NT AUTHORITY\LOCAL SERVICE|BUILTIN\Administrators|
#URA-2.2.9;(L1)Change the time zone', Only Administrators ,local service and users;SeTimeZonePrivilege:NT AUTHORITY\LOCAL SERVICE|BUILTIN\Administrators|BUILTIN\Users|
#URA-2.2.10;(L1)Create a pagefile, Only Administrators ;SeCreatePagefilePrivilege:BUILTIN\Administrators|
#URA-2.2.11;(L1)Create a token object, No one ;SeCreateTokenPrivilege:
#URA-2.2.12;(L1)Ensure Create global objects is set to Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE;SeCreateGlobalPrivilege:NT AUTHORITY\LOCAL SERVICE|NT AUTHORITY\NETWORK SERVICE|BUILTIN\Administrators|NT AUTHORITY\SERVICE|
#URA2.2.13;(L1)Ensure Create permanent shared objects, No one,value must empty;SeCreatePermanentPrivilege:
#URA2;(L1)Create symbolic links, Administrator and for Hyper V NT VIRTUAL MACHINE\Virtual Machines. ;SeCreateSymbolicLinkPrivilege:BUILTIN\Administrators|
#URA2;(L1)Ensure Debug programs is set to Administrators or no one;SeDebugPrivilege:BUILTIN\Administrators|
#URA2.2.16;(L1)Deny access to this computer from the network,Guest Local Account and member of Domain admin ;SeDenyNetworkLogonRight:
#URA2.2.17;(L1)Deny log on as a batch job, Guest ;SeDenyBatchLogonRight:
#URA2.2.18;(L1)Deny log on as a service, Guest ;SeDenyServiceLogonRight:
#URA2.2.19;(L1)Deny log on locally, Guest and member of Domain admin ;SeDenyInteractiveLogonRight:
#URA2.2.20;(L1)Deny log on through Remote Desktop Services, Guest, Local account and member of Domain admin' ;SeDenyRemoteInteractiveLogonRight:
#URA2.2.21;(L1)Enable computer and user accounts to be trusted for delegation,No one ;SeEnableDelegationPrivilege:
#URA2.2.22;(L1)Force shutdown from a remote system, Only administrators ;SeRemoteShutdownPrivilege:BUILTIN\Administrators|
#URA2.2.23;(L1)Generate security audits is set to LOCAL SERVICE, NETWORK SERVICE ;SeAuditPrivilege:NT AUTHORITY\LOCAL SERVICE|NT AUTHORITY\NETWORK SERVICE|RESTRICTED SERVICES\PrintSpoolerService|
#URA2.2.24;(L1)Impersonate a client after authentication , Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE ;SeImpersonatePrivilege:NT AUTHORITY\LOCAL SERVICE|NT AUTHORITY\NETWORK SERVICE|BUILTIN\Administrators|NT AUTHORITY\SERVICE|RESTRICTED SERVICES\PrintSpoolerService|
#URA2.2.25;(L1)Increase scheduling priority , only Administrator and Window Manager\Window Manager Group;SeIncreaseBasePriorityPrivilege:BUILTIN\Administrators|Window Manager\Window Manager Group|
#URA2.2.26;(L1)Load and unload device drivers' , only Administrator;SeLoadDriverPrivilege:BUILTIN\Administrators|
#URA2.2.27;(L1)Lock pages in memory, No one;SeLockMemoryPrivilege:
#URA2.2.28;(L2)Log on as a batch job',Administrators and very specific account;SeBatchLogonRight:BUILTIN\Administrators|BUILTIN\Administrators|BUILTIN\Performance Log Users|
#URA2.2.29;(L2)Ensure Log on as a service is set to No One and NT VIRTUAL MACHINE\Virtual Machine( When HyperV is installed);SeServiceLogonRight:NT SERVICE\ALL SERVICES|RESTRICTED SERVICES\ALL RESTRICTED SERVICES|
#URA2.2.30;(L1)Manage auditing and security log,Administrators;SeSecurityPrivilege:BUILTIN\Administrators|
#URA2.2.31;(L1)Modify an object label, No one;SeRelabelPrivilege:
#URA2.2.32;(L1)Modify firmware environment values is set to Administrators;SeSystemEnvironmentPrivilege:BUILTIN\Administrators|
#URA2.2.33;(L1)Perform volume maintenance tasks is set to Administrators;SeManageVolumePrivilege:BUILTIN\Administrators|
#URA2.2.34;(L1)Profile single process is set to Administrators;SeProfileSingleProcessPrivilege:BUILTIN\Administrators|
#URA2.2.35;(L1)Profile system performance is set to Administrators, NT SERVICE\WdiServiceHost;SeSystemProfilePrivilege:BUILTIN\Administrators|NT SERVICE\WdiServiceHost|
#URA2.2.36;(L1)Replace a process level token is set to LOCAL SERVICE, NETWORK SERVICE and for IIS server you may have IIS applications pools;SeAssignPrimaryTokenPrivilege:NT AUTHORITY\LOCAL SERVICE|NT AUTHORITY\NETWORK SERVICE|
#URA2.2.37;(L1)Restore files and directories is set to Administrators;SeRestorePrivilege:BUILTIN\Administrators|BUILTIN\Administrators|
#URA2.2.38;(L1)Shut down the system is set to Administrators, Users;SeShutdownPrivilege:BUILTIN\Administrators|BUILTIN\Users|BUILTIN\Users|
#URA2.2.39;(L1)Take ownership of files or other objects is set to Administrators;SeTakeOwnershipPrivilege:BUILTIN\Administrators|
#AA2.3.1.1;(L1)Accounts: Block Microsoft accounts is set to Users cannot add or log on with Microsoft accounts Value must be 3 ;
#AA2.3.1.2;(L1)Ensure Accounts: Guest account status is set to 'Disabled;Default guest Account:Guest,statut : disable
#AA2.3.1.3;(L1)Accounts: Limit local account use of blank passwords to console logon only is set to Enabled, Value must be 1 ;1
#AA2.3.1.4;(L1)Accounts: Rename administrator account;Default local admin Account:Administrator
#AA2.3.1.5;(L1)Accounts: Rename guest account;Default guest Account:Guest
#APA2.3.2.1;(L1)Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings is set to Enabled, Value must be 1 ;
#APA2.3.2.2;(L1)Audit: Shut down system immediately if unable to log security audits is set to Disabled, Value must be 0 ;0
#DEVP2.3.4.1;(L1)Ensure Devices: Allowed to format and eject removable media is set to Administrators and Interactive Users' ;
#DEVP2.3.4.1;(L2)Devices: Prevent users from installing printer drivers is set to Enabled, Value must be 1 ;0
#DMP2.3.6.2;(L1)Domain member: Digitally encrypt secure channel data (when possible) is set to Enabled, Value must be 1 ;1
#DMP2.3.6.3;(L1)Domain member: Domain member: Digitally sign secure channel data (when possible) is set to Enabled, Value must be 1 ;
#DMP2.3.6.4;(L1)Domain member: Disable machine account password changes is set to Disabled, Value must be 0 ;0
#DMP2.3.6.5;(L1)Domain member: Maximum machine account password age is set to 30 or fewer days, but not 0 ;30
#DMP2.3.6.6;(L1)Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled,value must 1 ;1
#IL2.3.7.1;(L1)Ensure Interactive logon: Do not require CTRL+ALT+DEL' is set to Disabled,value must 0 ;
#IL2.3.7.2;(L1)Ensure Interactive logon: Do not display last user name is set to Enabled,value must 1 ;0
#IL2.3.7.3;(L1)Ensure Interactive logon: Machine account lockout threshold' is set to '10 or fewer invalid logon attempts, but not 0',value must 0 ;
#IL2.3.7.4;(L1)Ensure Interactive logon: Machine inactivity limit' is set to 900 or fewer second(s), but not 0 ;
#IL2.3.7.7;(L2)Ensure interactive logon: Number of previous logons to cache (in case domain controller is not available) is set to 4 or fewer logon(s) ;10
#IL2.3.7.8;(L1)Ensure Interactive logon: Prompt user to change password before expiration is set to between 5 and 14 days ;5
#IL2.3.7.9;(L1)Ensure Interactive logon: Smart card removal behavior is set to Lock Workstation or higher,value must be 1 (Lock Workstation) or 2 (Force Logoff) ;0
#MNC2.3.8.1;(L1)Ensure Microsoft network client: Digitally sign communications (always) is set to Enabled,value must be 1 ;0
#MNC2.3.8.2;(L1)Ensure Microsoft network client: Digitally sign communications (if server agrees) is set to Enabled,value must be 1 ;1
#MNC2.3.8.3;(L1)Ensure Microsoft network client: Send unencrypted password to third-party SMB servers is set to Disabled,value must be 0 ;0
#MNS2.3.9.1;(L1)Microsoft network server: Amount of idle time required before suspending session is set to 15 or fewer minute(s) but not 0, ;
#MNS2.3.9.3;(L1)Ensure Microsoft network server: Digitally sign communications (if client agrees) is set to Enabled,must be 1 ;0
#MNS2.3.9.4;(L1)Ensure Microsoft network server: Disconnect clients when logon hours expire is set to Enabled,must be 1 ;1
#NA2.3.10.1;(L1)Ensure Network access: Allow anonymous SID/Name translation is set to Disabled,must be 0 ;
#NA2.3.10.2;(L1)Ensure Network access: Do not allow anonymous enumeration of SAM accounts is set to Enabled,must be 1 ;1
#NA2.3.10.3;(L1)Ensure Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled',must be 1 ;0
#NA2.3.10.4;(L1)Network access: Do not allow storage of passwords and credentials for network authentication is set to Enabled,must be 1 ;0
#NA2.3.10.5;(L1)Ensure Network access: Let Everyone permissions apply to anonymous users is set to Disabled,must be 0 ;0
#NA2.3.10.6;(L1)Configure Network access: Named Pipes that can be accessed anonymously,must be empty ; SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe SoftAPPipe ExtendzUtilityPipe
#NA2.3.10.7;(L1)Network access: Remotely accessible registry paths, musbe System\CurrentControlSet\Control\ProductOptions | System\CurrentControlSet\Control\Server Applications |Software\Microsoft\Windows NT\CurrentVersion ;System\CurrentControlSet\Control\ProductOptions System\CurrentControlSet\Control\Server Applications Software\Microsoft\Windows NT\CurrentVersion
#NA2.3.10.8;(L1)Network access: Remotely accessible registry paths and sub-paths:, check 2.3.10.8 part for the liste;Check NetworkAcces-Allowpath.txt
#NA2.3.10.9;Ensure Network access: Restrict anonymous access to Named Pipes and Shares is set to Enabled,value must be 1;1
#NA2.3.10.10;(L1)Ensure Network access: Restrict clients allowed to make remote calls to SAM is set to Administrators: Remote Access: Allow;
#NA2.3.10.11;(L1)Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None, value must be empty or {};
#NA2.3.10.12;(L1)Ensure Network access: Sharing and security model for local accounts is set to Classic - local users authenticate as themselves,value must be 0;0
#NS2.3.11.1;(L1)Network security: Allow Local System to use computer identity for NTLM is set to 'Enabled,value must be 1;
#NS2.3.11.2;(L1)Ensure Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled,value must be 0;
#NS2.3.11.3;(L1)Network Security: Allow PKU2U authentication requests to this computer to use online identities is set to Disabled,value must be 0;not configure
#NS2.3.11.4;(L1)Ensure Network security: Configure encryption types allowed for Kerberos is set to AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types;not configure
#NS2.3.11.5;(L1)Network security: Do not store LAN Manager hash value on next password change is set to Enabled,value must be 1;1
#NS2.3.11.6;(L1)Network security: Force logoff when logon hours expire is set to Enabled,value must be 1;1
#NS2.3.11.7;(L1)Ensure Network security: LAN Manager authentication level is set to Send NTLMv2 response only. Refuse LM & NTLM,value must be 5;
#NS2.3.11.8;(L1)Ensure Network security: LDAP client signing requirements is set to Negotiate signing or higher,value must be 1 or highter;1
#NS2.3.11.9;(L1)Ensure Network security: Minimum session security for NTLM SSP based (including secure RPC) clients is set to Require NTLMv2 session security, Require 128-bit encryption,value must be 537395200;536870912
#NS2.3.11.10;(L1)Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption', Require 128-bit encryption,value must be 537395200;536870912
#SC2.3.14.1;(L2)System cryptography: Force strong key protection for user keys stored on the computer' is set to 'User is prompted when the key is first used' or higher,value must be 2 ;
#SO2.3.15.1;(L1)Ensure System objects: Require case insensitivity for non-Windows subsystems is set to Enabled,value must be 1;1
#SO2.3.15.2;(L1)Ensure System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links) is set to Enabled,value must be 1;1
#UAC2.3.17.1;(L1)Ensure User Account Control: Admin Approval Mode for the Built-in Administrator account is set to Enabled,value must be 1;
#UAC2.3.17.2;(L1)Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode is set to Prompt for consent on the secure desktop,value must be 2(The value of 2 displays the UAC prompt that needs to be permitted or denied on a secure desktop. No authentication is required) or 1(A value of 1 requires the admin to enter username and password when operations require elevated privileges on a secure desktop);5
#UAC2.3.17.3;(L1)Ensure User Account Control: Behavior of the elevation prompt for standard users is set to Automatically deny elevation requests, value must be 0(A value of 0 will automatically deny any operation that requires elevated privileges if executed by standard users).;3
#UAC2.3.17.4;(L1)Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to Enabled, value must be 1;1
#UAC2.3.17.5;(L1)Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled, value must be 1;1
#2;(L1)Ensure 'User Account Control: Run all administrators in Admin Approval Mode is set to Enabled, value must be 1;1
#UAC2.3.17.7;(L1)Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled', value must be 1;1
#UAC2.3.17.8;(L1)Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled, value must be 1;1
#SS5.1;Ensure 'Bluetooth Audio Gateway Service (BTAGService)' is set to 'Disabled', value must be 4;3
#SS5.2;(L2)Ensure Bluetooth Support Service (bthserv)' is set to 'Disabled', value must be 4;3
#SS5.3;(L1)Ensure 'Computer Browser (Browser)' is set to 'Disabled' or 'Not Installed'', value must be 4 or not installed;3
#SS5.4;(L2)Ensure 'Downloaded Maps Manager (MapsBroker)' is set to 'Disabled', value must be 4 or not installed;2
#SS5.5;(L2)Ensure 'Geolocation Service (lfsvc)' is set to 'Disabled', value must be 4 or not installed;3
#SS5.6;(L1)Ensure 'IIS Admin Service (IISADMIN)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;It s not installed
#SS5.7;(L1)Ensure 'Infrared monitor service (irmon)' is set to 'Disabled', value must be 4 or not installed;It s not installed
#SS5.8;(L1)Ensure 'Internet Connection Sharing (ICS) (SharedAccess) ' is set to 'Disabled', value must be 4 or not installed;3
#SS5.9;(L2)Ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)' is set to 'Disabled', value must be 4 or not installed;3
#SS5.10;(L1)Ensure 'LxssManager (LxssManager)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;It s not installed
#SS5.11;(L1)Ensure 'Microsoft FTP Service (FTPSVC)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;It s not installed
#SS5.12;(L2)Ensure 'Microsoft iSCSI Initiator Service (MSiSCSI)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.14;(L2)Ensure 'Peer Name Resolution Protocol (PNRPsvc)' is set to 'Disabled'or 'Not Installed', value must be 4 or not installed;It s not installed
#SS5.15;(L2)Ensure 'Peer Networking Grouping (p2psvc)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;It s not installed
#SS5.16;Ensure 'Peer Networking Identity Manager (p2pimsvc)' is set to 'Disabled or 'Not Installed', value must be 4 or not installed;It s not installed
#SS5.17;(L2)Ensure 'PNRP Machine Name Publication Service (PNRPAutoReg)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;It s not installed
#SS5.18;(L2)Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (Automated), value must be 4 or not installed;2
#SS5.19;(L2)Ensure 'Problem Reports and Solutions Control Panel Support (wercplsupport)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.20;(L2)Ensure 'Remote Access Auto Connection Manager (RasAuto)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.21;(L2)Ensure 'Remote Desktop Configuration (SessionEnv)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.22;(L2)Ensure 'Remote Desktop Services (TermService)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.23;(L2)Ensure 'Remote Desktop Services UserMode Port Redirector (UmRdpService) is set to Disabled or 'Not Installed', value must be 4 or not installed;3
#SS5.24;sshdEnsure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.25;(L2)Ensure 'Remote Registry (RemoteRegistry)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;4
#SS5.26;(L1)Ensure 'Routing and Remote Access (RemoteAccess)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;4
#SS5.27;(L2)Ensure 'Server (LanmanServer)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;2
#SS5.28;(L1)Ensure 'Simple TCP/IP Services (simptcp)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;It s not installed
#SS5.29;(L2)Ensure 'SNMP Service (SNMP)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;It s not installed
#SS5.30;(L1)Ensure 'Special Administration Console Helper (sacsvr)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;It s not installed
#SS5.31;(L1)Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.32;(L1)Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.33;(L1)Ensure 'Web Management Service (WMSvc)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;It s not installed
#SS5.34;(L2)Ensure 'Windows Error Reporting Service (WerSvc) is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.35;(L2)Ensure 'Windows Event Collector (Wecsvc)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.36;(L1)Ensure 'Windows Media Player Network Sharing Service (WMPNetworkSvc)'' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.37;(L1)Ensure Windows Mobile Hotspot Service (icssvc)'' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.38;(L2)Ensure Windows Push Notifications System Service (WpnService)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;2
#SS5.39;(L2)Ensure 'Windows PushToInstall Service (PushToInstall)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.40;(L2)Ensure Windows Remote Management (WS-Management) (WinRM) is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.41;(L1)Ensure World Wide Web Publishing Service (W3SVC)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;It s not installed
#SS5.42;(L1)Ensure Xbox Accessory Management Service (XboxGipSvc) is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.43;(L1)Ensure Xbox Live Auth Manager (XblAuthManager) s set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.44;(L1)Ensure Xbox Live Game Save (XblGameSave) is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#SS5.45;(L1)Ensure Xbox Live Networking Service (XboxNetApiSvc) is set to 'Disabled' or 'Not Installed', value must be 4 or not installed;3
#WFDP9.1.1;(L1)Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On, value must be True;True
#WFDP9.1.2;(L1)Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default), value must be Block;NotConfigured
#WFDP9.1.3;(L1)Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default), value must be Allow but if it's block it s fucking badass;NotConfigured
#WFDP9.1.4;(L1)Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No', value must false ;True
#WFDP9.1.5;(L1)Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log ;%systemroot%\system32\LogFiles\Firewall\pfirewall.log
#WFDP9.1.6;(L1)Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater, value must 16384 or higthter ;4096
#WFDP9.1.7;(L1)Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes',value must be true ;False
#WFDP9.1.8;(L1)Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes,value must be true ;False
#WFPPRIP9.2.1;(L1)Ensure 'Windows Firewall: Private: Firewall state' is set to 'On, value must be True;True
#WFPPRIP9.2.2;(L1)Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default, value must be Block;NotConfigured
#WFPPRIP9.2.3;(L1)Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)', value must be Allow but if it's block it s fucking badass;NotConfigured
#WFPPRIP9.2.4;(L1)Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No, value must false ;True
#WFPPRIP9.2.5;(L1)Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log ;%systemroot%\system32\LogFiles\Firewall\pfirewall.log
#WFPPRIP9.2.6;(L1)Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater, value must 16384 or higthter ;4096
#WFPPRIP9.2.7;(L1)Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes',value must be true ;False
#WFPPRIP9.2.8;(L1)Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes',value must be true ;False
#WFPPUBP9.3.1;(L1)Ensure 'Windows Firewall: Public: Firewall state' is set to 'On, value must be True;True
#WFPPUBP9.3.2;(L1)Windows Firewall: Public: Inbound connections' is set to 'Block , value must be Block;NotConfigured
#WFPPUBP9.3.3;(L1)Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default), value must be Allow but if it's block it s fucking badass;NotConfigured
#WFPPUBP9.3.4;(L1)Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'Yes, value must false ;True
#WFPPUBP9.3.5;(L1)Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No, value must 0 ;not configure
#WFPPUBP9.3.6;(L1)Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No', value must 0 ;not configure
#WFPPUBP9.3.7;(L1)Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log;%systemroot%\system32\LogFiles\Firewall\pfirewall.log
#WFPPUBP9.3.8;(L1)Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater;4096
#WFPPUBP9.3.9;(L1)Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes',value must be true ;False
#WFPPUBP9.3.10;(L1)Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes',value must be true ;False
#AAAL17.1.1;(L1)Ensure 'Audit Credential Validation' is set to 'Success and Failure;  Credential Validation                   No Auditing
#AAGM17.2.2;(L1)Ensure 'Audit Security Group Management' is set to 'Success and Failure';  Security Group Management               Success
#2;(L1)Ensure 'Audit User Account Management' is set to 'Success and Failure;  User Account Management                 Success
#AADT17.3.1;(L1)Ensure 'Audit PNP Activity' is set to 'Success';
#AADT17.3.2;(L1)Ensure 'Audit Process Creation' is set to 'Success;  Process Creation                        No Auditing
#AALL17.5.1;(L1)Ensure 'Audit Account Lockout' is set to Failure';  Account Lockout                         Success
#AALL17.5.2;(L1)Ensure 'Audit Group Membership' is set to 'Success;  Group Membership                        No Auditing
#AALL17.5.3;(L1)Ensure 'Audit Logoff' is set to 'Success';Logon/Logoff   Logoff                                  Success   Other Logon/Logoff Events               No Auditing
#AALL17.5.4;(L1)Ensure 'Audit Logon' is set to 'Success and Failure';Logon/Logoff   Logon                                   Success and Failure   Special Logon                           Success   Other Logon/Logoff Events               No Auditing Account Logon   Other Account Logon Events              No Auditing
#AALL17.5.5;(L1)Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure';  Other Logon/Logoff Events               No Auditing
#AALL17.5.6;(L1)Ensure 'Audit Special Logon' is set to 'Success';  Special Logon                           Success
#AAOA17.6.1;(L1)Encdsure Audit Detailed File Share is set to Failure';  Detailed File Share                     No Auditing
#AAOA17.6.2;(L1)Ensure 'Audit File Share'' is set to 'Success and Failure';  File Share                              No Auditing   Detailed File Share                     No Auditing
#AAOA17.6.3;(L1)Ensure 'Audit Other Object Access Events''' is set to 'Success and Failure';  Other Object Access Events              No Auditing
#AAOA17.6.4;(L1)Ensure 'Audit Removable Storage' is set to 'Success and Failure';  Removable Storage                       No Auditing
#AAPC17.7.1;(L1)Ensure 'Audit Audit Policy Change' is set to 'Success and Failure';  Audit Policy Change                     Success
#AAPC17.7.2;(L1)Ensure 'Audit Authentication Policy Change' is set to 'Success'';  Authentication Policy Change            Success
#AAPC17.7.3;Ensure 'Audit Authorization Policy Change' is set to 'Success'';  Authorization Policy Change             No Auditing
#AAPU17.7.4;(L1)Ensure 'Audit MPSSVC Rule-Level Policy Change is set to 'Success and Failure';  MPSSVC Rule-Level Policy Change         No Auditing
#AAPU17.7.5;(L1)Ensure 'Audit Other Policy Change Events' is set to include 'Failure';  Other Policy Change Events              No Auditing
#AAPU17.8.1;(L1)Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure';  Non Sensitive Privilege Use             No Auditing   Sensitive Privilege Use                 No Auditing
#AAS17.9.1;(L1)Ensure 'Audit IPsec Driver' is set to 'Success and Failure';  IPsec Driver                            No Auditing
#AAS17.9.2;(L1)Ensure 'Audit Other System Events' is set to 'Success and Failure';  Other System Events                     Success and Failure
#AAS17.9.3;(L1)Ensure 'Audit Security State Change' is set to 'Success;  Security State Change                   Success
#AAS17.9.4;(L1)Ensure 'Audit Security System Extension' is set to 'Success and Failure;  Security System Extension               No Auditing
#AAS17.9.5;(L1)Ensure 'Audit System Integrity' is set to 'Success and Failure';  System Integrity                        Success and Failure
#PA18.1.1.1;(L1)Ensure 'Prevent enabling lock screen camera' is set to 'Enabled, value must 1 ;not configure
#PA18.1.1.2;(L1)Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled', value must 1 ;not configure
#PA18.1.2.2;(L1)Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled', value must 0 ;not configure
#PA18.1.3;(L2)Ensure Allow Online Tips'' is set to 'Disabled', value must 0 ;
#LAPS18.3.1;(L1)Ensure LAPS AdmPwd GPO Extension / CSE is installed, value must true ;not configure
#LAPS18.3.2;(L1)Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled, value must 1 ;not configure
#LAPS18.3.3;(L1)Ensure 'Enable Local Admin Password Management' is set to 'Enabled', value must 1 ;not configure
#LAPS18.3.4;(L1)Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters, value must 1 ;not configure
#LAPS18.3.5;(L1)Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more, value must greater than 15 ;not configure
#LAPS18.3.6;(L1)Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer', value must less than 30 ;not configure
#MSSG18.4.1;(L1)Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled', value must be 0;
#MSSG18.4.2;(L1)Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled', value must be 1;
#MSSG18.4.3;(L1)Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver', value must be 4;2
#MSSG18.4.4;(L1)Ensure Configure SMB v1 server' is set to 'Disabled', value must be 0;
#MSSG18.4.5;(L1)Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled', value must be 0;
#MSSG18.4.6;(L1)Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended), value must be 2;
#MSSG18.4.7;(L1)Ensure 'WDigest Authentication' is set to 'Disabled', value must be 0;
#MSSL18.5.1;(L1)Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled, value must be 0 or empty;
#MSSL18.5.2;(L1)Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled, value must be 2;
#MSSL18.5.3;(L1)Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled, value must be 2;
#MSSL18.5.4;(L2)Ensure 'MSS: (DisableSavePassword) Prevent the dial-up password from being saved' is set to 'Enabled', source routing is completely disabled, value must be 1;
#MSSL18.5.5;(L1)Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled, value must be 0;
#MSSL18.5.6;(L2)Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes, value must be 300000;
#MSSL18.5.7;(L1)Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled, value must be 1;
#MSSL18.5.8;(L2)Ensure MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)', value must be 0;
#MSSL18.5.9;(L1)Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled, value must be 1;
#MSSL18.5.10;(L1)Ensure MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires 'is set to 'Enabled: 5 or fewer seconds (0 recommended)', value must be 5 or less ;
#MSSL18.5.11;(L2)Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3: value must be 3 ;
#MSSL18.5.12;(L2)Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3: value must be 3 ;
#MSSL18.5.13;(L1)Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less ;
#DNSCA18.6.4.1;(L1) Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher, value must be 2 OR 3 could cause issue in domain joined environment ;not configure
#DNSCA18.6.4.2;(L1) Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks, value must be 0;not configure
#DNSCA18.6.4.3;(L1)Ensure 'Turn off multicast name resolution' is set to 'Enabled' (MS Only), value must be 0 ;not configure
#FONT18.6.5.1;(L2)Ensure 'Enable Font Providers' is set to 'Disabled, value must be 0 ;
#LW18.6.8.1;(L1)Ensure 'Enable insecure guest logons' is set to 'Disabled', value must be 0 ;not configure
#LLTDIO18.6.9.1;(L2)Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled', value must be 0 ;not configure
#LLTDIO18.6.9.2;(L2)Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'', value must be 0 ;not configure
#PPNS18.6.10.2;(L2)Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled', value must be 1 ;0
#NC18.6.11.2;(L1)Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled', value must be 1 ;
#NC18.6.11.3;(L1)Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled', value must be 1 ;
#NC18.6.11.4;(L1)Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled, value must be 1 ;
#NP18.6.14.1;(L1)Ensure 'Hardened UNC Paths' is set to 'Enabled, with Require Mutual Authentication and Require Integrity set for all NETLOGON and SYSVOL shares', RequireMutualAuthentication=1, RequireIntegrity=1 ;\\*\SYSVOL:|
#IPV618.6.19.2.1;(L2)Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)'), value must be 255 ;
#WCN18.6.20.1;(L2)Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled, value must be 1 ;\\*\SYSVOL:|
#WCN18.6.20.2;(L2)Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled, value must be 1 ;not configure
#WCM18.6.21.1;(L1)Ensure Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet', value must be 3 ;
#WCM18.6.21.2;(L1)Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'', value must be 1 ;
#WLAN18.6.23.2.1;(L1)Ensure 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled', value must be 0 ;
#PRINT18.7.1;(L1)Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'', value must be 2 ;not configure
#PRINT18.7.2;Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled', value must be 1 , 2 mean audit mode ;not configure
#PRINT18.7.3;(L1) Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP', value must be 1 ;not configure
#PRINT18.7.4;(L1) (L1) Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default', value must be 1 ;not configure
#PRINT18.7.5;(L1) Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP', value must be 0x7 ;not configure
#PRINT18.7.7;(L1) Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0' (Automated) value must be 0 ;not configure
#PRINT18.7.8;(L1) Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0' (Automated) value must be 1 ;not configure
#PRINT18.7.9;(L1)Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles' value must be 1 ;not configure
#PRINT18.7.10;(L1)Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt',value must be 1 ;not configure
#PRINT18.7.11;(L1)Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt',value must be 0 ;not configure
#NOTI18.8.1.1;(L2) Ensure 'Turn off notifications network usage' is set to 'Enabled',value must be 1 ;not configure
#APC18.9.3.1;(L1) Ensure 'Include command line in process creation events' is set to 'Enabled',value must be 1 ;
#2;(L1) Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients', value must be 0 ;not configure
#2;(L1) Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled', value must be 1 ;not configure
#DG18.9.5.1;(L1)Ensure 'Turn On Virtualization Based Security' is set to 'Enabled' (Scored), value must be 1 ;not configure
#DG18.9.5.2;(L1)Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection', value must be 1 ;not configure
#DG18.9.5.3;(L1)Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock' (Scored), value must be 1 ;not configure
#DG18.9.5.4;(L1)Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)', value must be 1 ;not configure
#DG18.9.5.5;(L1)Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock', value must be 1 ;not configure
#DG18.9.5.6;(L1)Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock', value must be 1 ;not configure
#DG18.9.5.7;(L1)Ensure 'Turn On Virtualization Based Security: Kernel-mode Hardware-enforced Stack Protection' is set to 'Enabled: Enabled in enforcement mode', value must be 1 ;not configure
#DIR18.9.7.1.1;(L1)Ensure 'Prevent installation of devices that match any of these device IDs' is set to 'Enabled', value must be 1 ;not configure
#DIR18.9.7.1.2;Ensure 'Prevent installation of devices that match any of these device IDs' is set to 'Enabled', value must be PCI\CC_0C0A ;not configure
#DIR18.9.7.1.3;(L1)Ensure 'Prevent installation of devices that match any of these device IDs' is set to 'Enabled', value must be PCI\CC_0C0A ;not configure
#DIR18.9.7.1.4;(L1)Ensure 'Prevent installation of devices using drivers that match these device setup classes' is set to 'Enabled', value must be 1 ;not configure
#DIR18.9.7.1.5;(L1)Ensure 'Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these device setup' is set to 'IEEE 1394 device setup classes, value must be 1 ;not configure
#DIR18.9.7.1.6;(L1)Ensure 'Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed.' is set to 'True', value must be 1 ;not configure
#DIR18.9.7.2;(L1)Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'' is set to 'True', value must be 1 ;not configure
#ELA18.9.13.1;(L1)Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical, value must be 3 ;not configure
#LT18.9.19.2;(L1)Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE', value must be 1 ;not configure
#LT18.9.19.3;(L1)Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE', value must be 1 ;not configure
#LT18.9.19.4;(L1)Ensure 'Continue experiences on this device' is set to 'Disabled, value must be 0 ;
#LT18.9.19.5;(L1)Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled', value must be 0 ;
#ICS18.9.20.1.1;(L1)Ensure Turn off access to the Store is set to Enabled, value must be 1 ;not configure
#ICS18.9.20.1.2;(L1)Ensure Turn off downloading of print drivers over HTTP, value must be 1 ;not configure
#ICS18.9.20.1.3;(L2)Ensure Turn off handwriting personalization data sharing is set to Enabled, value must be 1 ;not configure
#KDP18.9.24.1;(L1)Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All', value must be 0 ;not configure
#LSA18.9.25.1;(L1) Ensure 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled', value must be 0 ;
#LSA18.9.25.2;(L1) Ensure 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock', value must be 1 ;2
#LOGON18.9.27.1;(L1)Ensure Block user from showing account details on sign-in is set to Enabled, value must be 1 ;
#LOGON18.9.27.2;(L1)Ensure Do not display network selection UI is set to Enabled, value must be 1 ;
#LOGON18.9.27.3;Ensure Do not enumerate connected users on domain-joined computers is set to Enabled, value must be 1 ;
#LOGON18.9.27.4;(L1)Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled', value must be 0 ;
#LOGON18.9.27.5;(L1)Ensure Turn off app notifications on the lock screen is set to Enabled, value must be 1 ;
#LOGON18.9.27.6;(L1)Ensure 'Turn off picture password sign-in' is set to 'Enabled', value must be1 ;
#LOGON18.9.27.7;(L1)Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled', value must be 0 ;
#OP18.9.30.1;(L2) Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled', value must be 0 ;
#OP18.9.30.2;(L2) Ensure 'Allow upload of User Activities' is set to 'Disabled', value must be 0 ;
#SLEEP18.9.32.6.1;(L1) Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled', value must be 0 ;not configure
#SLEEP18.9.32.6.2;(L1) Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled', value must be 0 ;not configure
#SLEEP18.9.32.6.3;(L1) Ensure 'Allow standby states (S1-S3) when sleeping (on battery)' is set to 'Disabled', value must be 0 ;not configure
#SLEEP18.9.32.6.4;(L1) Ensure 'Allow standby states (S1-S3) when sleeping (plugged in)' is set to 'Disabled', value must be 0 ;not configure
#SLEEP18.9.32.6.5;(L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled', value must be 1 ;not configure
#SLEEP18.9.32.6.6;(L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled', value must be 1 ;not configure
#RA18.9.34.1;(L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled, value must be 0 ;
#RA18.9.34.2;(L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'', value must be 0 ;
#RPC18.9.35.1;(L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled, value must be 1 ;not configure
#RPC18.9.35.2;(L1) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated', value must be 1 ;not configure
#MSDT18.9.46.5.1;(L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled, value must be 0 ;not configure
#WPP18.9.46.11.1;(L2) Ensure 'Enable/Disable PerfTrack' is set to 'Disabled', value must be 0 ;not configure
#UP18.9.48.1;(L2) Ensure 'Turn off the advertising ID' is set to 'Enabled', value must be 1 ;not configure
#TP18.9.50.1.1;(L2) Ensure 'Enable Windows NTP Client' is set to 'Enabled', value must be 1 ;not configure
#TP18.9.50.1.2;(L2) Ensure 'Enable Windows NTP Server' is set to 'Disabled', value must be 0 ;not configure
#APD18.10.3.1;(L2) Ensure Allow a Windows app to share application data between users, value must be 0 ;not configure
#APD18.10.3.2;Ensure 'Prevent non-admin users from installing packaged Windows apps' is set to 'Enabled', value must be 1 ;
#APP18.10.4.1;(L1) Ensure 'Let Windows apps activate with voice while the system is locked' is set to 'Enabled: Force Deny', value must be 0 ;not configure
#AR18.10.5.1;(L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled', value must be 1 ;
#AR18.10.5.2;(L2)Ensure 'Block launching Windows Store apps with Windows Runtime API access from hosted content.' is set to 'Enabled', value must be 1 ;
#AP18.10.7.1;(L1)Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled', value must be 1 ;not configure
#AP18.10.7.2;(L1)Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands', value must be 1 ;
#AP18.10.7.3;(L1)Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'', value must be B5 ;
#FF18.10.8.1.1;(L1)Ensure 'Use enhanced anti-spoofing when available' is set to 'Enabled', value must be 1 ;not configure
#BDE18.10.9.1.1;(L1)Ensure 'Allow access to BitLocker-protected fixed data drives from earlier versions of Windows' is set to 'Disabled', value must be 1 ;not configure
#BDE18.10.9.1.2;(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered' is set to 'Enabled', value must be 1 ;not configure
#BDE18.10.9.1.3;(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Allow data recovery agent' is set to 'Enabled: True', value must be 1 ;not configure
#BDE18.10.9.1.4;(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Password' is set to 'Enabled: Allow 48-digit recovery password', value must be 2 ;not configure
#BDE18.10.9.1.5;(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Key' is set to 'Enabled: Allow 256-bit recovery key', value must be 2 ;not configure
#BDE18.10.9.1.6;(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True', value must be 1 ;not configure
#BDE18.10.9.1.7;(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Save BitLocker recovery information to AD DS for fixed data drives' is set to 'Enabled: False', value must be 1 ;not configure
#BDE18.10.9.1.8;(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Configure storage of BitLocker recovery information to AD DS' is set to 'Enabled: Backup recovery passwords and key packages', value must be 1 ;not configure
#BDE18.10.9.1.9;(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives' is set to 'Enabled: False', value must be 0 ;not configure
#BDE18.10.9.1.10;(L1)Ensure 'Configure use of hardware-based encryption for fixed data drives' is set to 'Enabled', value must be 1 ;not configure
#BDE18.10.9.1.11;(L1)Ensure 'Configure use of passwords for fixed data drives' is set to 'Disabled', value must be 0 ;not configure
#BDE18.10.9.1.12;(L1)Ensure 'Configure use of smart cards on fixed data drives' is set to 'Enabled', value must be 1 ;not configure
#BDE18.10.9.1.13;(L1)Ensure 'Configure use of smart cards on fixed data drives: Require use of smart cards on fixed data drives' is set to 'Enabled: True', value must be 1 ;not configure
#OSD18.10.9.2.1;(L1)Ensure 'Allow enhanced PINs for startup' is set to 'Enabled, value must be 1 ;not configure
#OSD18.10.9.2.2;(L1)Ensure 'Allow Secure Boot for integrity validation' is set to 'Enabled', value must be 1 ;not configure
#OSD18.10.9.2.3;(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered' is set to 'Enabled', value must be 1 ;not configure
#OSD18.10.9.2.4;(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Allow data recovery agent' is set to 'Enabled: False', value must be 0 ;not configure
#OSD18.10.9.2.5;(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Password' is set to 'Enabled: Require 48-digit recovery password', value must be 1 ;not configure
#OSD18.10.9.2.6;(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key', value must be 0 ;not configure
#OSD18.10.9.2.7;(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True', value must be 1 ;not configure
#OSD18.10.9.2.8;(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Save BitLocker recovery information to AD DS for operating system drives' is set to 'Enabled: True', value must be 1 ;not configure
#OSD18.10.9.2.9;(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Store recovery passwords and key packages'', value must be 1 ;not configure
#OSD18.10.9.2.10;(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for operating system drives', value must be 1 ;not configure
#OSD18.10.9.2.11;(L1)Ensure 'Configure use of hardware-based encryption for operating system drives' is set to 'Disabled', value must be 0 ;not configure
#OSD18.10.9.2.12;(L1)Ensure 'Configure use of passwords for operating system drives' is set to 'Disabled'', value must be 0 ;not configure
#OSD18.10.9.2.13;Ensure 'Require additional authentication at startup' is set to 'Enabled', value must be 1 ;not configure
#OSD18.10.9.2.14;Ensure 'Require additional authentication at startup: Allow BitLocker without a compatible TPM' is set to 'Enabled: False', value must be 0 ;not configure
#RDD18.10.9.3.1;(L1)Ensure 'Allow access to BitLocker-protected removable data drives from earlier versions of Windows' is set to 'Disabled', value must be empty ;not configure
#RDD18.10.9.3.2;(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered' is set to 'Enabled', value must be 1 ;not configure
#RDD18.10.9.3.3;(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Allow data recovery agent' is set to 'Enabled: True', value must be 1 ;not configure
#RDD18.10.9.3.5;(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key', value must be 0 ;not configure
#RDD18.10.9.3.6;(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True', value must be 1 ;not configure
#RDD18.10.9.3.7;(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Save BitLocker recovery information to AD DS for removable data drives' is set to 'Enabled: False', value must be 1 ;not configure
#RDD18.10.9.3.8;(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Backup recovery passwords and key packages', value must be 1 ;not configure
#RDD18.10.9.3.9;(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for removable data drives' is set to 'Enabled: False', value must be 1 ;not configure
#RDD18.10.9.3.10;(L1)Ensure 'Ensure 'Configure use of hardware-based encryption for removable data drives' is set to 'Disabled'', value must be 0 ;not configure
#RDD18.10.9.3.11;(L1)Ensure 'Configure use of passwords for removable data drives' is set to 'Disable, value must be 0 ;not configure
#RDD18.10.9.3.12;(L1)Ensure 'Configure use of smart cards on removable data drives' is set to 'Enabled', value must be 0 ;not configure
#RDD18.10.9.3.13;(L1)Ensure 'Configure use of smart cards on removable data drives: Require use of smart cards on removable data drives' is set to 'Enabled: True', value must be 1 ;not configure
#RDD18.10.9.3.14;(L1)Ensure 'Deny write access to removable drives not protected by BitLocker' is set to 'Enabled'', value must be 1 ;not configure
#RDD18.10.9.3.15;(L1)Ensure 'Deny write access to removable drives not protected by BitLocker: Do not allow write access to devices configured in another organization' is set to 'Enabled: False', value must be 0 ;not configure
#RDD18.10.9.4;(L1)Ensure 'Disable new DMA devices when this computer is locked' is set to 'Enabled', value must be 1 ;not configure
#CAM18.10.10.1;(L2)Ensure 'Allow Use of Camera' is set to 'Disabled', value must be 0 ;not configure
#CLOUD18.10.12.1;(L2)Ensure 'Turn off cloud consumer account state content' is set to 'Enabled', value must be 1 ;not configure
#CLOUD18.10.12.2;(L2)Ensure 'Turn off cloud optimized content' is set to 'Enabled', value must be 1 ;not configure
#CLOUD18.10.12.3;(L1)Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled', value must be 1 ;not configure
#CONNECT18.10.13.1;(L1)Ensure Require pin for pairing is set to Enabled, value must be 1 ;not configure
#CUI18.10.14.1;(L1)Ensure 'Do not display the password reveal button' is set to 'Enabled', value must be 1 ;not configure
#CUI18.10.14.2;(L1)Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled', value must be 0 ;not configure
#CUI18.10.14.3;(L1)Ensure 'Prevent the use of security questions for local accounts' is set to 'Enabled', value must be 1 ;
#DCPB18.10.15.1;(L1)Ensure'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'' , value must be 0(recommended) or 1;
#DCPB18.10.15.2;(L2)Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage', value must be 1;
#DCPB18.10.15.3;(L1) Ensure 'Disable OneSettings Downloads' is set to 'Enabled', value must be 1 ;
#DCPB18.10.15.4;(L1)Ensure 'Do not show feedback notifications' is set to 'Enabled, value must be 1;
#DCPB18.10.15.5;(L1)Ensure 'Enable OneSettings Auditing' is set to 'Enabled', value must be 1 ;
#DCPB18.10.15.6;(L1)Ensure 'Limit Diagnostic Log Collection is set to 'Enabled', value must be 1 ;
#DCPB18.10.15.7;(L1)Ensure 'Limit Dump Collection' is set to 'Enabled', value must be 1 ;
#DCPB18.10.15.8;(L1)Ensure 'Toggle user control over Insider builds'is set to 'Disabled, value must be 0 ;not configure
#DO18.10.16;Ensure 'Download Mode' is NOT set to 'Enabled: Internet' , value must be anything other than 3;not configure
#DAI18.10.17.1;(L1)Ensure 'Enable App Installer' is set to 'Disabled, value must be 0 ;not configure
#DAI18.10.17.2;Ensure Ensure 'Enable App Installer Experimental Features' is set to 'Disabled', value must be 0 ;not configure
#DAI18.10.17.3;Ensure Ensure 'Enable App Installer Hash Override' is set to 'Disabled', value must be 0 ;not configure
#DAI18.10.17.4;Ensure Ensure 'Enable App Installer Hash Override' is set to 'Disabled', value must be 0 ;not configure
#APP18.10.26.1.1;(L1)Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled', value must be 0 ;not configure
#APP18.10.26.1.2;(L1)Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater', value must be 32,768 or greater ;not configure
#SECL18.10.26.2.1;(L1)Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled', value must be 0 ;not configure
#SECL18.10.26.2.2;(L1)Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater', value must be 196,608 or greater ;not configure
#SETL18.10.26.3.1;(L1)Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled, value must be 0 ;not configure
#SETL18.10.26.3.2;(L1)Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater', value must be 32,768 or greater ;not configure
#SYSL18.10.26.4.1;(L1)Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled', value must be 0 ;not configure
#SYSL18.10.26.4.2;(L1)Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater', value must be 32,768 or greater ;not configure
#FE18.10.29.2;(L1)Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled', value must be 0 ;not configure
#FE18.10.29.3;(L2)Ensure 'Turn off files from Office.com in Quick access view' is set to 'Enabled', value must be 1 ;not configure
#FE18.10.29.4;(L1)Ensure 'Turn off heap termination on corruption' is set to 'Disabled', value must be 0 ;not configure
#FE18.10.29.5;(L1)Ensure 'Turn off shell protocol protected mode' is set to 'Disabled', value must be 0 ;
#HOME18.10.33.1;(L1)Ensure 'Prevent the computer from joining a homegroup' is set to 'Enabled', value must be 1;not configure
#WLP18.10.37.2;(L2)Ensure 'Turn off location' is set to 'Enabled'', value must be 1 ;not configure
#MES18.10.41.1;(L2)Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled', value must be 0 ;not configure
#MA18.10.42.1;(L1)Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled', value must be 1 ;not configure
#MDA18.10.43.5.1;(L1)Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled', value must be 0 ;not configure
#MDA18.10.43.5.2; (L2)Ensure 'Join Microsoft MAPS' is set to 'Disabled', value must be 0 ;not configure
#MDA18.10.43.6.1.1;(L1)Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled', value must be 1 ;not configure
#MDA18.10.43.6.1.2;(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured', value must be 1 foreach key ;not configure
#MDA18.10.43.6.3.1;(L1)Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block', value must be 1 ;not configure
#MDA18.10.43.6.3.1;(L2)Ensure 'Enable file hash computation feature' is set to 'Enabled' value must be 1 ;not configure
#MDA18.10.43.10.1;(L1) Ensure 'Scan all downloaded files and attachments' is set to 'Enabled', value must be 1 or disable if you have another EPP;not configure
#MDA18.10.43.10.2;(L1) Ensure 'Turn off real-time protection' is set to 'Disabled' (Automated), value must be 0 or disable if you have another EPP;not configure
#MDA18.10.43.10.3;(L1) Ensure 'Turn on behavior monitoring' is set to 'Enabled', value must be 0  or disable if you have another EPP ;not configure
#MDA18.10.43.10.4;(L1) Ensure 'Turn on script scanning' is set to 'Enabled', value must be 0  or disable if you have another EPP ;not configure
#MDA18.10.43.12.1;(L2)Ensure 'Configure Watson events' is set to 'Disabled, value must be 0 ;not configure
#MDA18.10.43.13.1;(L1) Ensure 'Scan removable drives' is set to 'Enabled', value must be 0 or disable if you have another EPP;not configure
#MDA18.10.43.13.2;(L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled', value must be 0 or disable if you have another EPP;not configure
#MDA18.10.43.16;(L1) Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block', value must be 1 or disable if you have another EPP ;
#MDA18.10.43.17;(L1)Ensure 'Turn off Windows Defender AntiVirus' is set to 'Disabled', value must be 0 or disable if you have another EPP;
#MDA18.10.44.1;(L1)Ensure 'Allow auditing events in Windows Defender Application Guard' is set to 'Enabled', value must be 1 ;not configure
#MDA18.10.44.2;(L1)Ensure 'Allow camera and microphone access in Windows Defender Application Guard' is set to 'Disabled', value must be 0 ;not configure
#MDA18.10.44.3;(L1)Ensure 'Allow data persistence for Windows Defender Application Guard' is set to 'Disabled', value must be 0 ;not configure
#MDA18.10.44.4;(L1)Ensure 'Allow files to download and save to the host operating system from Windows Defender Application Guard' is set to 'Disabled', value must be 0 ;not configure
#MDA18.10.44.5;(L1)Ensure 'Configure Windows Defender Application Guard clipboard settings: Clipboard behavior setting' is set to 'Enabled: Enable clipboard operation from an isolated session to the host', value must be 1 ;not configure
#MDA18.10.44.6;(L1)Ensure 'Turn on Windows Defender Application Guard in Enterprise Mode' is set to 'Enabled', value must be 3 ;not configure
#NI18.10.50.1;(L2)Ensure 'Enable news and interests on the taskbar' is set to 'Disabled', value must be 0 ;not configure
#OD18.10.50.1;(L1)Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'', value must be 1 ;not configure
#PTI18.10.56.1;(L2)Ensure 'Turn off Push To Install service' is set to 'Enabled, value must be 1 ;not configure
#RDS18.10.57.2.2;(L2)Ensure 'Disable Cloud Clipboard integration for server-to-client data transfer' is set to 'Enabled', value must be 1 ;
#RDS18.10.57.2.3;(L1)Ensure 'Do not allow passwords to be saved' is set to 'Enabled', value must be 1 ;
#RDS18.10.57.3.2.1;(L2)Ensure 'Allow users to connect remotely by using Remote Desktop Services' is set to 'Disabled', value must be 1 ;
#RDS18.10.57.3.3.1;(L2)Ensure 'Allow UI Automation redirection' is set to 'Disabled', value must be 0 ;
#RDS18.10.57.3.3.2;(L2)Ensure 'Do not allow COM port redirection' is set to 'Enabled', value must be 1 ;
#RDS18.10.57.3.3.3;(L1)Ensure 'Do not allow drive redirection' is set to 'Enabled', value must be 1 ;
#RDS18.10.57.3.3.4;(L1)Ensure 'Do not allow location redirection' is set to 'Enabled', value must be 1 ;
#RDS18.10.57.3.3.5;(L2)Ensure 'Do not allow LPT port redirection' is set to 'Enabled'', value must be 1 ;
#RDS18.10.57.3.3.6;(L2)Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'', value must be 1 ;
#RDS18.10.57.3.3.7;(L2)Ensure 'Do not allow WebAuthn redirection' is set to 'Enabled'', value must be 1 ;
#RDS18.10.57.3.9.1;(L1)Ensure 'Always prompt for password upon connection' is set to 'Enabled', value must be 1 ;
#RDS18.10.57.3.9.2;(L1)Ensure 'Require secure RPC communication' is set to 'Enabled', value must be 1 ;
#RDS18.10.57.3.9.2;(L1)Ensure 'Require secure RPC communication' is set to 'Enabled', value must be 1 ;
#RDS18.10.57.3.9.3;(L1)Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL', value must be 2 ;
#RDS18.10.57.3.9.4;(L1)Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'', value must be 1 ;
#RDS18.10.57.3.9.5;(L1)Ensure 'Set client connection encryption level' is set to 'Enabled: High Level', value must be 3 ;
#RDS18.10.57.3.10.1;(L1)Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less', value must be 15 or less ;
#RDS18.10.57.3.10.2;(L2)Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute', value must 1 ;
#RDS18.10.57.3.11.1;(L1)Ensure 'Do not delete temp folders upon exit' is set to 'Disabled', value must 0 ;
#RSS18.10.58.1;(L1)Ensure 'Prevent downloading of enclosures' is set to 'Enabled', value must be 1 ;not configure
#OCR18.10.59.2;(L2)Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search', value must be 0 ;not configure
#OCR18.10.59.3;(L1)Ensure 'Allow Cortana' is set to 'Disabled', value must be 0 ;not configure
#OCR18.10.59.4;(L1)Ensure 'Allow Cortana above lock screen' is set to 'Disabled', value must be 0 ;not configure
#OCR18.10.59.5;(L1)Ensure 'Allow indexing of encrypted files' is set to 'Disabled', value must be 0 ;not configure
#OCR18.10.59.6;(L1)Ensure 'Allow search and Cortana to use location' is set to 'Disabled', value must be 0 ;not configure
#OCR18.10.59.7;(L2)'Ensure 'Allow search highlights' is set to 'Disabled', value must be 0 ;not configure
#SPP18.10.63.1;(L2)Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled', value must be 1 ;not configure
#STORE18.10.66.1;(L2)Ensure 'Disable all apps from Windows Store' is set to 'Enabled', value must be 1 ;not configure
#STORE18.10.66.2;(L1) Ensure 'Only display the private store within the Microsoft Store' is set to 'Enabled', value must be 1 ;not configure
#STORE18.10.66.3;(L1) Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled', value must be 0 ;not configure
#STORE18.10.66.4; (L1)Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled, value must be 1 ;not configure
#STORE18.10.66.5;(L2)Ensure 'Turn off the Store application' is set to 'Enabled', value must be 1 ;not configure
#WID18.10.72.1;(L1)Ensure 'Allow widgets' is set to 'Disabled', value must be 0 ;not configure
#WDS18.10.72.1;(L1)Ensure 'Notify Malicious' is set to 'Enabled', value must be 1;not configure
#WDS18.10.72.2;(L1)Ensure 'Notify Password Reuse' is set to 'Enabled', value must be 1;not configure
#WDS18.10.72.3;(L1)Ensure 'Notify Unsafe App'' is set to 'Enabled', value must be 1;not configure
#WDS18.10.72.3;(L1)Ensure 'Service Enabled' is set to 'Enabled', value must be 1;not configure
#WDS18.10.76.2.1;(L1)Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass, value must be 0 ;EnableSmartScreen:|ShellSmartScreenLevel:|
#ME18.10.76.3.1;(L1)Ensure Configure Windows Defender SmartScreen is set to 'Enabled', value must be 1;not configure
#ME18.10.76.3.1;(L1)Ensure Prevent bypassing Windows Defender SmartScreen prompts for sites is set to 'Enabled', value must be 1;not configure
#WGRB18.10.78.1;(L1)Ensure 'Enables or disables Windows Game Recording and Broadcasting' is set to 'Disabled', value must be 0 ;not configure
#WGRB18.10.78.1;(L1)Ensure 'Enable ESS with Supported Peripherals' is set to 'Enabled: 1', value must be 1 ;not configure
#WIW18.10.80.1;(L2)Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled, value must be 0 ;not configure
#WIW18.10.80.2;(L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On', value must be 0 or 1 but not 2 ;not configure
#WI18.10.81.1;Ensure 'Allow user control over installs' is set to 'Disabled', value must be 0 ;not configure
#WI18.10.81.2;(L1)Ensure 'Always install with elevated privileges' is set to 'Disabled', value must be 0 ;not configure
#WI18.10.81.3;(L2)Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled', value must be 0 ;not configure
#WLO18.10.82.1;(L1)Ensure ''Enable MPR notifications for the system' is set to 'Disabled', value must be 0 ;
#WLO18.10.82.2;(L1)Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled', value must be 1 ;
#WP18.10.87.1;Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled', value must be 1 ;not configure
#WP18.10.87.2;Ensure 'urn on PowerShell Transcription' is set to 'Enabled', value must be 1;not configure
#WRR18.10.89.1.1;(L1)Ensure 'Allow Basic authentication' is set to 'Disabled', value must be 0;not configure
#WRR18.10.89.1.2;(L1)Ensure 'Allow unencrypted traffic' is set to 'Disabled', value must be 0;not configure
#WRR18.10.89.1.3;(L1)Ensure 'Disallow Digest authentication' is set to 'Enabled', value must be 0;not configure
#WRR18.10.89.2.1;(L1)Ensure 'Allow Basic authentication' is set to 'Disabled', value must be 0;not configure
#WRR18.10.89.2.2;(L2)Ensure 'Allow remote server management through WinRM' is set to 'Disabled', value must be 0;not configure
#WRR18.10.89.2.3;(L1)Ensure 'Allow unencrypted traffic' is set to 'Disabled', value must be 0;not configure
#WRR18.10.89.2.4;(L1)Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled', value must be 1;not configure
#WRS18.10.90.1;(L2)Ensure 'Allow Remote Shell Access' is set to 'Disabled, value must be 0;not configure
#WS18.10.90.1;(L1)Ensure 'Allow clipboard sharing with Windows Sandbox' is set to 'Disabled' value must be 0;not configure
#WS18.10.90.2;(L1)Ensure 'Allow networking in Windows Sandbox' is set to 'Disabled', value must be 0;not configure
#ABP18.10.92.2.1;(L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled', value must be 1 ;not configure
#WU18.10.93.2.1;(L1)Ensure 'Configure Automatic Updates' is set to 'Enabled', value must be 0;not configure
#WU18.10.93.2.2;(L1)Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'', value must be 0;not configure
#WU18.10.93.2.3;(L1)Ensure 'Remove access to â€œPause updatesâ€ feature' is set to 'Enabled', value must be 1;not configure
#WU18.10.93.4.1;(L1)Ensure 'Manage preview builds' is set to 'Enabled: Disable preview builds' value must be 0 foreach key;not configure
#WU18.10.93.4.2;(L2)Ensure 'Select when Feature Updates are received' is set to 'Enabled: Current Branch for Business, 180 days' ;not configure
#WU18.10.93.4.3;(L1)Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days''' ;not configure
#PERS19.1.3.1;(L1)Ensure 'Enable screen saver' is set to 'Enabled', value must be 1;not configure
#PERS19.1.3.2;(L1)Ensure 'Password protect the screen saver' is set to 'Enabled', value must be 1;not configure
#PERS19.1.3.3;(L1)Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0', value must be 900 or less but not 0;not configure
#NOTIF19.5.1.1;(L1)Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled, value must be 1;not configure
#ICC19.6.6.1.1;(L2)Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled', value must be 1;not configure
#ATTM19.7.4.1;(L1)Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled', value must be 0;not configure
#ATTM19.7.4.2;(L1)Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled', value must be 1;not configure
#CLOUDC19.7.7.1;(L1)Ensure 'Configure Windows spotlight on lock screen' is set to Disabled, value must be 0;
#CLOUDC19.7.7.2;(L1)Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled', value must be 1;
#CLOUDC19.7.7.3;(L2)Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'', value must be 1;
#CLOUDC19.7.7.4;(L2)Ensure 'Turn off all Windows spotlight features' is set to 'Enabled', value must be 1;
#CLOUDC19.7.7.5;(L1)Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled', value must be 1;
#NSHARE19.7.25.1;(L1)Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled', value must be 1;not configure
#UWI19.7.40.1;(L1)Ensure 'Always install with elevated privileges' is set to 'Disabled', value must be 0;not configure
#PLB19.7.42.2.1;(L2)Ensure 'Prevent Codec Download' is set to 'Enabled', value must be 1;not configure




cd ../..
#https://learn.microsoft.com/en-us/answers/questions/241800/completely-disable-and-remove-xbox-apps-and-relate
reg add HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassID\Windows.GameBar.PresenceServer.Internal.PresenceWriter /v ActivationType /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Service\xbgm
Get-AppxPackage -allusers Microsoft.XboxGamingOverlay | Remove-AppxPackage
Get-AppxPackage Microsoft.XboxApp | Remove-AppxPackage
Get-AppxPackage XboxOneSmartGlass | Remove-AppxPackage
Get-AppxPackage Microsoft.XboxSpeechToTextOverlay | Remove-AppxPackage
Get-AppxPackage Microsoft.XboxIdentityProvider | Remove-AppxPackage
