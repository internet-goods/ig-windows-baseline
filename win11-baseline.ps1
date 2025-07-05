
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

#auditpol
auditpol.exe /get /category:* > auditpol_beforehardening.txt
#dostuff
auditpol.exe /get /category:* > auditpol_afterhardening.txt
#instrumentation
Invoke-WebRequest https://download.sysinternals.com/files/ProcessExplorer.zip
Invoke-WebRequest https://pkg.osquery.io/windows/osquery-5.16.0.msi
#https://www.blumira.com/blog/enable-sysmon
Invoke-WebRequest -Uri https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml -OutFile sysmonconfig.xml
#sysmon64.exe –accepteula –i config.xml

#AV
Invoke-WebRequest https://clamav-site.s3.amazonaws.com/production/release_files/files/000/001/821/original/clamav-1.4.2.win.arm64.msi
Invoke-WebRequest https://objects.githubusercontent.com/github-production-release-asset-2e65be/7037996/8793b738-3bc5-4dd8-91ef-4fdd1dac418e?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250303%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250303T015750Z&X-Amz-Expires=300&X-Amz-Signature=753c038a0702cd300b89f3a761982e958abed79fa26e0733549ca3d71a423f6a&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dyara-v4.5.2-2326-win64.zip&response-content-type=application%2Foctet-stream
Invoke-WebRequest https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.0-1.msi
#elasticagent
#user apps
#https://dl1.cdn.filezilla-project.org/client/FileZilla_3.68.1_x86_64-linux-gnu.tar.xz?h=zuW-H_2uBTephsSUVampWQ&x=1740971160
Invoke-WebRequest https://download.gimp.org/gimp/v2.10/windows/gimp-2.10.38-setup-1.exe
Invoke-WebRequest https://get.videolan.org/vlc/3.0.21/win32/vlc-3.0.21-win32.exe
Invoke-WebRequest https://downloads.realvnc.com/download/file/viewer.files/VNC-Viewer-7.13.1-Windows.exe?lai_vid=LazLae45JInq&lai_sr=5-9&lai_sl=l
Invoke-WebRequest https://www.cygwin.com/setup-x86_64.exe
Invoke-WebRequest https://www.libreoffice.org/donate/dl/win-x86_64/25.2.1/en-US/LibreOffice_25.2.1_Win_x86-64.msi
Invoke-WebRequest https://github.com/mitre/saf/releases/download/1.4.21/saf-v1.4.21-x64.exe
#harden System
#winget install --id Microsoft.Powershell --source winget
#Set-ProcessMitigation -System -Enable DEP,SEHOP,HighEntropy,ForceRelocateImages,BottomUp,TerminateOnError,DisableWin32kSystemCalls,DisableExtensionPoints,BlockDynamicCode,StrictHandle
#git
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
#TOP
git clone https://github.com/TheSPEEDO/URLRunner
