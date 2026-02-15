echo WBAdmin (wbadmin.exe) is a powerful command-line utility in Windows (Vista/7 and Server 2008+) 
echo used to back up and restore operating systems, volumes, files, folders, and applications. 
echo It enables advanced data protection, including "bare-metal" backups, by leveraging Volume Shadow Copy Service (VSS) to create VHD/VHDX file
echo backup wrapper, to backup C to D for example, run ig-wbadmin-backup.bat C: D:
echo wbadmin start backup -backupTarget:D: -include:C: -allCritical -quiet
set arg1=%2
set arg2=%1
REM wbadmin start backup -backupTarget:%1 -include:%2 -allCritical -quiet
wbadmin start backup -backupTarget:D: -include:C: -allCritical -quiet
