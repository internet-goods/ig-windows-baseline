setlocal enabledelayedexpansion

set "output=services_report.csv"

:: Create the CSV Header
echo ServiceName,Status,StartupType,ExecutablePath > %output%

echo Scanning services... please wait.

:: Loop through all service names
for /f "tokens=2" %%s in ('sc query state^= all ^| findstr /C:"SERVICE_NAME"') do (
    set "serviceName=%%s"
    
    :: Get Status
    for /f "tokens=3" %%a in ('sc query !serviceName! ^| findstr "STATE"') do set "status=%%a"
    
    :: Get Startup Type
    for /f "tokens=3" %%b in ('sc qc !serviceName! ^| findstr "START_TYPE"') do set "startType=%%b"
    
    :: Get Executable Path from Registry
    set "exepath=N/A"
    for /f "tokens=2*" %%c in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\!serviceName!" /v ImagePath 2^>nul') do (
        set "exepath=%%d"
    )

    :: Clean up commas in paths to avoid breaking CSV format
    set "exepath=!exepath:,=!"

    :: Append to CSV
    echo !serviceName!,!status!,!startType!,"!exepath!" >> %output%
)

echo Report generated: %output%
