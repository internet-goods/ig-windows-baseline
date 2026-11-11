<#
.SYNOPSIS
    Pip-Boy 3000 Terminal Interface for Windows 11 DISA STIG Registry Compliance
.DESCRIPTION
    ASCII TUI for auditing and applying key DISA STIG V1R2 Windows 11 Security Registry Controls.
    Requires Administrative Privileges.
#>

# Requires Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsPrincipal]::AdminRole)) {
    Write-Host "[!] ERROR: PIP-BOY SYSTEM REQUIRES OVERSEER PRIVILEGES (RUN AS ADMINISTRATOR)." -ForegroundColor Red
    Exit
}

# --- STIG DEFINITIONS ---
$STIGs = @(
    @{
        ID          = "WN11-SO-000010"
        Title       = "Prevent Anonymous SID Translation"
        RegPath     = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        ValueName   = "TurnOffAnonymousBlock"
        STIGValue   = 1
        Type        = "DWord"
        Desc        = "Blocks anonymous users from enumerating SIDs/Names."
    },
    @{
        ID          = "WN11-CC-000035"
        Title       = "Disable LLMNR Protocol"
        RegPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        ValueName   = "EnableMulticast"
        STIGValue   = 0
        Type        = "DWord"
        Desc        = "Mitigates credential harvesting/spoofing via Link-Local Multicast Name Resolution."
    },
    @{
        ID          = "WN11-CC-000190"
        Title       = "Disable Remote Desktop Blank Passwords"
        RegPath     = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        ValueName   = "LimitBlankPasswordUse"
        STIGValue   = 1
        Type        = "DWord"
        Desc        = "Restricts local accounts with blank passwords to console access only."
    },
    @{
        ID          = "WN11-CC-000200"
        Title       = "Disable UAC Auto-Approve Elevation"
        RegPath     = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        ValueName   = "ConsentPromptBehaviorAdmin"
        STIGValue   = 2
        Type        = "DWord"
        Desc        = "Forces credentials prompt on Secure Desktop for administrative elevations."
    },
    @{
        ID          = "WN11-EP-000120"
        Title       = "Enable Windows Defender Real-Time Protection"
        RegPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        ValueName   = "DisableRealtimeMonitoring"
        STIGValue   = 0
        Type        = "DWord"
        Desc        = "Ensures Real-Time Antivirus Scanning is continuously enforced."
    },
    @{
        ID          = "WN11-RG-000010"
        Title       = "Disable Remote Registry Service"
        RegPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry"
        ValueName   = "Start"
        STIGValue   = 4
        Type        = "DWord"
        Desc        = "Disables the network accessible registry service."
    }
)

# --- HELPER FUNCTIONS ---

function Play-PipClick {
    [console]::beep(800, 30)
}

function Play-PipToggle {
    [console]::beep(1200, 40)
    [console]::beep(600, 40)
}

function Get-STIGStatus ($stig) {
    if (-not (Test-Path $stig.RegPath)) { return $false }
    $val = Get-ItemPropertyValue -Path $stig.RegPath -Name $stig.ValueName -ErrorAction SilentlyContinue
    return ($val -eq $stig.STIGValue)
}

function Set-STIGState ($stig, [bool]$Enable) {
    if (-not (Test-Path $stig.RegPath)) {
        New-Item -Path $stig.RegPath -Force | Out-Null
    }
    
    $targetValue = if ($Enable) { $stig.STIGValue } else { 
        # Default fallback non-compliant state toggle
        if ($stig.STIGValue -eq 0) { 1 } else { 0 }
    }

    Set-ItemProperty -Path $stig.RegPath -Name $stig.ValueName -Value $targetValue -Type $stig.Type -Force | Out-Null
}

# --- ASCII UI RENDERING ---

function Draw-Header ($selectedIndex) {
    Clear-Host
    $green = "Green"
    
    Write-Host "==========================================================================================" -ForegroundColor $green
    Write-Host "  VAULT-TEC CORPORATION (TM) PIP-BOY 3000 MARK IV  --  WINDOWS 11 DISA STIG CONFIGURATOR " -ForegroundColor $green
    Write-Host "==========================================================================================" -ForegroundColor $green
    Write-Host "   [ STAT ]           [ INV ]           [ DATA ]           [ REGS ]           [ AUDIT ]   " -ForegroundColor $green
    Write-Host "------------------------------------------------------------------------------------------" -ForegroundColor $green
}

function Draw-VaultBoy ($compliantCount, $total) {
    $ratio = $compliantCount / $total
    $color = "Green"
    if ($ratio -lt 0.5) { $color = "Red" }
    elseif ($ratio -lt 1.0) { $color = "Yellow" }

    Write-Host "    /~~~~~~~~~\   " -ForegroundColor $color
    Write-Host "   |  (o) (o)  |  " -ForegroundColor $color
    if ($ratio -eq 1.0) {
        Write-Host "   |   \___/   |  --- SYSTEM COMPLIANCE STATUS: 100% SECURE (OVERSEER APPROVED)" -ForegroundColor $color
    } elseif ($ratio -ge 0.5) {
        Write-Host "   |    ---    |  --- SYSTEM COMPLIANCE STATUS: $compliantCount/$total STIGS APPLIED (WARNING)" -ForegroundColor $color
    } else {
        Write-Host "   |   /---\   |  --- SYSTEM COMPLIANCE STATUS: CRITICAL RISK DETECTED ($compliantCount/$total)" -ForegroundColor $color
    }
    Write-Host "    \_________/   " -ForegroundColor $color
    Write-Host ""
}

# --- MAIN LOOP ---

$currentIndex = 0
$running = $true

# Set console title & green text
$host.UI.RawUI.WindowTitle = "PIP-BOY 3000: Windows 11 DISA STIG Switchboard"
$Host.UI.RawUI.ForegroundColor = "Green"

while ($running) {
    Draw-Header -selectedIndex $currentIndex

    # Calculate compliance
    $compliantCount = 0
    foreach ($s in $STIGs) {
        if (Get-STIGStatus $s) { $compliantCount++ }
    }
    
    Draw-VaultBoy -compliantCount $compliantCount -total $STIGs.Count
    
    Write-Host "  MANUAL STIG REGISTRY SWITCHES:" -ForegroundColor Green
    Write-Host "  --------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    
    for ($i = 0; $i -lt $STIGs.Count; $i++) {
        $stig = $STIGs[$i]
        $isCompliant = Get-STIGStatus $stig
        
        $switchGraphic = if ($isCompliant) { "[ ON  ] (COMPLIANT)    " } else { "[ OFF ] (NON-COMPLIANT)" }
        $switchColor   = if ($isCompliant) { "Green" } else { "DarkGray" }
        $pointer       = if ($i -eq $currentIndex) { "==> " } else { "    " }
        $pointerColor  = if ($i -eq $currentIndex) { "Yellow" } else { "Green" }
        
        Write-Host $pointer -NoNewline -ForegroundColor $pointerColor
        Write-Host "$($stig.ID) | " -NoNewline -ForegroundColor Green
        Write-Host "$switchGraphic " -NoNewline -ForegroundColor $switchColor
        Write-Host "| $($stig.Title)" -ForegroundColor White
    }

    Write-Host "  --------------------------------------------------------------------------------------" -ForegroundColor DarkGreen
    
    # Show active selection details
    $selectedSTIG = $STIGs[$currentIndex]
    Write-Host ""
    Write-Host "  [ CONTROL DETAILS: $($selectedSTIG.ID) ]" -ForegroundColor Yellow
    Write-Host "  Description : $($selectedSTIG.Desc)" -ForegroundColor Green
    Write-Host "  Target Path : $($selectedSTIG.RegPath)" -ForegroundColor DarkGray
    Write-Host "  Target Key  : $($selectedSTIG.ValueName) = $($selectedSTIG.STIGValue) ($($selectedSTIG.Type))" -ForegroundColor DarkGray
    
    Write-Host ""
    Write-Host "==========================================================================================" -ForegroundColor Green
    Write-Host " [UP/DOWN Arrow] Navigate  |  [SPACE/ENTER] Toggle Switch  |  [A] Apply All  |  [Q] Quit" -ForegroundColor Yellow
    Write-Host "==========================================================================================" -ForegroundColor Green

    # Capture key inputs
    $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    
    switch ($key.VirtualKeyCode) {
        38 { # Up Arrow
            Play-PipClick
            if ($currentIndex -gt 0) { $currentIndex-- } else { $currentIndex = $STIGs.Count - 1 }
        }
        40 { # Down Arrow
            Play-PipClick
            if ($currentIndex -lt ($STIGs.Count - 1)) { $currentIndex++ } else { $currentIndex = 0 }
        }
        32 { # Space
            Play-PipToggle
            $currentState = Get-STIGStatus $selectedSTIG
            Set-STIGState -stig $selectedSTIG -Enable (-not $currentState)
        }
        13 { # Enter
            Play-PipToggle
            $currentState = Get-STIGStatus $selectedSTIG
            Set-STIGState -stig $selectedSTIG -Enable (-not $currentState)
        }
        65 { # 'A' Key - Apply All
            Play-PipToggle
            foreach ($s in $STIGs) {
                Set-STIGState -stig $s -Enable $true
            }
        }
        81 { # 'Q' Key - Quit
            Play-PipClick
            $running = $false
        }
    }
}

Clear-Host
Write-Host "PIP-BOY TERMINAL DISCONNECTED." -ForegroundColor DarkGreen
