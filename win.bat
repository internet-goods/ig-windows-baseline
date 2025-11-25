#IG Windows Baseline
#Install Apps
mkdir ig
cd ig
#winget
curl https://aka.ms/getwinget > winget.msixbundle
#Add-AppxPackage winget.msixbundle
#install git
#winget install --id Git.Git -e --source winget
#hardening


curl https://github.com/niwc-atlantic/scap-scc/blob/main/release_archive/SCC_5.8/scc-5.8_Windows_bundle.zip > scc-5.8_Windows_bundle.zip

#monitoring
winget install --id=osquery.osquery -e
winget install --id=Microsoft.Sysinternals.Sysmon -e
winget install -e --id smartmontools.smartmontools
#languages
winget install --id=Oracle.JDK.21 -e
winget install -e --id Python.Python.3.13 --scope machine
winget install --id=StrawberryPerl.StrawberryPerl -e
winget install RubyInstallerTeam.Ruby.3.2
#ham
curl https://github.com/gqrx-sdr/gqrx/releases/download/v2.17.7/Gqrx-2.17.7-Windows.zip > Gqrx-2.17.7-Windows.zip
#apps
winget install -e --id GNU.Wget2
winget install -e --id Rufus.Rufus
winget install FileZilla.FileZillaClient
winget install -e --id PuTTY.PuTTY
winget install -e --id 7zip.7zip
winget install -e --id Piriform.CCleaner
winget install -e --id Cisco.ClamAV
winget install -e --id VirusTotal.YARA
winget install -e --id Malwarebytes.Malwarebytes
winget install -e --id Microsoft.Sysinternals.ProcessExplorer
winget install -e --id Microsoft.Sysinternals.Autoruns
winget install -e --id Microsoft.Sysinternals.Coreinfo

#run apps to produce baseline
#HK
#wynis
#osquery locally
#https://attack.mitre.org/tactics/TA0003/
#test localsystem
#https://github.com/redcanaryco/atomic-red-team/
#test domain
curl https://github.com/SpecterOps/SharpHound/releases/download/v2.8.0/SharpHound_v2.8.0_windows_x86.zip > SharpHound_v2.8.0_windows_x86.zip
#unzip sharphound
SharpHound.exe -c All
curl https://github.com/netwrix/pingcastle/releases/download/3.4.2.66/PingCastle_3.4.2.66.zip > PingCastle_3.4.2.66.zip
#unzip pingcastle
PingCastle.exe --healthcheck

git clone https://github.com/Sneakysecdoggo/Wynis
Wynis\wynis.exe audit
git clone https://github.com/scipag/HardeningKitty
HardeningKitty\HardeningKitty.ps1 -Mode Analysis -Log

#IG Baselines

