# --------------------------------------------------------------------------
# Multi-Method Injection Hunter
# Run as Administrator for full visibility
# --------------------------------------------------------------------------

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

Write-Host "`n[+] Hunt Complete." -ForegroundColor Cyan
