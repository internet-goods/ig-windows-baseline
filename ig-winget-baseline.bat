#IG winget Baseline
curl https://aka.ms/getwinget > winget.msixbundle
Add-AppxPackage winget.msixbundle
winget install --id Git.Git -e --source winget
winget install --id=osquery.osquery -e
winget install --id=Microsoft.Sysinternals.Sysmon -e
winget install -e --id smartmontools.smartmontools
winget install --id=Oracle.JDK.21 -e
winget install -e --id Python.Python.3.13 --scope machine
winget install --id=StrawberryPerl.StrawberryPerl -e
winget install RubyInstallerTeam.Ruby.3.2
winget install -e --id GNU.Wget2
winget install -e --id Rufus.Rufus
winget install -e --id FileZilla.FileZillaClient
winget install -e --id PuTTY.PuTTY
winget install -e --id 7zip.7zip
winget install -e --id Piriform.CCleaner
winget install -e --id Cisco.ClamAV
winget install -e --id VirusTotal.YARA
winget install -e --id Malwarebytes.Malwarebytes
winget install -e --id Microsoft.Sysinternals.ProcessExplorer
winget install -e --id Microsoft.Sysinternals.Autoruns
winget install -e --id Microsoft.Sysinternals.Coreinfo
winget install -e --id Microsoft.Sysintermals.Sigcheck
winget install -e --id OISF.Suricata
