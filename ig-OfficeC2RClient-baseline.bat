"%ProgramFiles%\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe" /update user displaylevel=false forceappshutdown=true
"%ProgramFiles%\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe" /changesetting Channel=MonthlyEnterprise
"%ProgramFiles%\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe" /update user
echo Current Channel,Current,Default. Newest features as soon as they are ready.
echo Monthly Enterprise,MonthlyEnterprise,Predictable once-a-month updates (2nd Tuesday).
echo Semi-Annual Enterprise,SemiAnnual,Feature updates twice a year (Jan/July).
echo Semi-Annual (Preview),SemiAnnualPreview,Early access to the next Semi-Annual release.
echo Current (Preview),CurrentPreview,Early access to the next Current Channel release.
echo Beta Channel,BetaChannel,"Experimental features for testing (formerly ""Insiders"")."
echo Which Office editions use it?
echo If Office was installed via Click-to-Run (C2R), it uses OfficeC2RClient.exe for patching. That includes:
echo Microsoft 365 Apps (formerly Office 365 ProPlus)
echo Office 2019
echo Office 2021
echo Office LTSC 2021
echo Office LTSC 2024
echo Visio & Project (C2R editions)
echo Which Office editions do NOT use it?
echo These don’t use OfficeC2RClient.exe for patching:
echo MSI-based installs (Office 2010 / 2013 MSI)
echo Office patched purely by WSUS/MSI mechanisms
echo Office installed inside some legacy VDI images using MSI
echo What it actually does
echo OfficeC2RClient.exe is the command-line control plane for Office updates. It:
echo Talks to Microsoft CDN, WSUS, SCCM, or a local update source
echo Enforces update channels (Current, Monthly Enterprise, Semi-Annual, LTSC)
echo Applies delta patches (not full reinstalls)
echo Handles repair / rollback / version pinning
