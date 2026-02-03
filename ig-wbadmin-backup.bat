echo backup wrapper, to backup C to D for example, run ig-wbadmin-backup.bat C: D:
echo wbadmin start backup -backupTarget:D: -include:C: -allCritical -quiet
set arg1=%2
set arg2=%1
wbadmin start backup -backupTarget:%1 -include:%2 -allCritical -quiet
