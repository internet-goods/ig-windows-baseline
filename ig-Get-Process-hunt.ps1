# --------------------------------------------------------------------------
# Multi-Method Injection Hunter
# Run as Administrator for full visibility
# --------------------------------------------------------------------------
#Method	Target Technique	Why it works
#DLL Path Check	DLL Side-loading	System binaries should only load system DLLs from System32.
#RWX Scanning	Shellcode Injection	Legitimate code is usually Read/Execute. Write/Execute is a red flag.
#Empty CmdLine	Process Hollowing	When a process is "hollowed," the metadata in the PEB (Command Line) is often lost or blank.
#Unsigned Modules	DLL Injection	Lists DLLs running from \Temp\ or \Users\Public\.
Write-Host "[+] Starting Injection Hunt..." -ForegroundColor Cyan

# --- METHOD 1: DLL Side-Loading & Path Anomalies ---
# Checks if core Windows DLLs are being loaded from unusual locations.
Write-Host "`n[*] Checking for DLL Path Anomalies..." -Yellow
$TargetDLLs = "kernel32.dll|ntdll.dll|user32.dll|ws2_32.dll"
Get-Process | ForEach-Object {
    $proc = $_
    try {
        $proc.Modules | Where-Object { $_.ModuleName -match $TargetDLLs } | ForEach-Object {
            if ($_.FileName -notlike "C:\Windows\System32\*" -and $_.FileName -notlike "C:\Windows\SysWOW64\*") {
                Write-Host "[!] ALERT: Suspicious DLL Path Found!" -ForegroundColor Red
                Write-Host "    Process: $($proc.Name) (PID: $($proc.Id))"
                Write-Host "    DLL: $($_.ModuleName) Path: $($_.FileName)"
            }
        }
    } catch { }
}

# --- METHOD 2: Hunt for RWX Memory Regions (Advanced) ---
# Note: This requires the NtObjectManager module or manual Win32 API calls.
# Below is a simplified check for Unsigned Modules which often accompany basic injection.
Write-Host "`n[*] Scanning for Unsigned/Unmapped Modules..." -Yellow
Get-Process | Where-Object { $_.Modules } | ForEach-Object {
    $p = $_
    $p.Modules | Where-Object { $_.FileName -notlike "C:\Windows\*" -and $_.FileName -notlike "C:\Program Files*" } | 
    Select-Object @{N='Process';E={$p.Name}}, ModuleName, FileName | Unique
}

# --- METHOD 3: Process Hollowing Indicators ---
# Legitimate system processes started by malware often lack Command Lines or have "orphaned" parents.
Write-Host "`n[*] Checking for Hollowed Process Indicators (Empty Command Lines)..." -Yellow
Get-CimInstance Win32_Process | Where-Object { 
    ($_.Name -eq "svchost.exe" -or $_.Name -eq "explorer.exe" -or $_.Name -eq "lsass.exe") -and 
    [string]::IsNullOrWhiteSpace($_.CommandLine) 
} | Select-Object Name, ProcessId, ParentProcessId


# Fileless Malware Indicator Scanner
# Focus: Process Behavior, WMI Persistence, and Hidden Registry Scripts

Write-Host "--- Scanning for Fileless Malware Indicators ---" -ForegroundColor Cyan

### 1. Check for Suspicious PowerShell Processes
# Look for hidden windows, encoded commands, or IEX (Invoke-Expression)
Write-Host "[*] Auditing active PowerShell processes..." -ForegroundColor Yellow
$SuspiciousPS = Get-WmiObject Win32_Process | Where-Object { 
    $_.Name -eq "powershell.exe" -and (
        $_.CommandLine -like "*hidden*" -or 
        $_.CommandLine -like "*-enc*" -or 
        $_.CommandLine -like "*bypass*" -or
        $_.CommandLine -like "*IEX*"
    )
}

if ($SuspiciousPS) {
    $SuspiciousPS | Select-Object ProcessId, CommandLine | Format-Table -AutoSize
} else {
    Write-Host "No obvious suspicious PowerShell flags found." -ForegroundColor Green
}

### 2. Check WMI Persistence (Common for Fileless Backdoors)
# Fileless malware often creates "Event Consumers" to run code on startup
Write-Host "`n[*] Auditing WMI Event Consumers (Persistence Check)..." -ForegroundColor Yellow
$WmiConsumers = Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer

# We look for 'CommandLineEventConsumer' which contains actual commands
$CmdConsumers = $WmiConsumers | Where-Object { $_.__CLASS -eq "CommandLineEventConsumer" }

foreach ($cons in $CmdConsumers) {
    Write-Host "Found WMI Consumer: $($cons.Name)" -ForegroundColor Red
    Write-Host "Command: $($cons.CommandLineTemplate)"
}

### 3. Check Registry 'Run' Keys for Script Execution
# Attackers often put short PowerShell scripts directly into the registry
Write-Host "`n[*] Auditing Registry Autoruns for encoded scripts..." -ForegroundColor Yellow
$Paths = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"

foreach ($path in $Paths) {
    if (Test-Path $path) {
        $Values = Get-ItemProperty -Path $path
        foreach ($val in $Values.PSObject.Properties) {
            if ($val.Value -like "*powershell*" -or $val.Value -like "*base64*") {
                Write-Host "Suspicious Registry Key in $path" -ForegroundColor Red
                Write-Host "Name: $($val.Name) | Value: $($val.Value)"
            }
        }
    }
}

Write-Host "`n--- Scan Complete ---" -ForegroundColor Cyan
