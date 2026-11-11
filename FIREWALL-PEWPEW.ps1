<#
.SYNOPSIS
    DISA STIG Firewall Compliance & Space Invaders Packet Monitor Console
.DESCRIPTION
    Evaluates Windows Firewall DISA STIG settings and launches an interactive 
    retro arcade packet visualizer mapped to local ports.
#>

# Ensure ANSI support in console
$host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size(120, 40)
$host.UI.RawUI.WindowSize = New-Object Management.Automation.Host.Size(120, 40)

function Get-StigCompliance {
    $profiles = Get-NetFirewallProfile
    $results = foreach ($p in $profiles) {
        $enabled = $p.Enabled -eq 'True'
        $inbound = $p.DefaultInboundAction -eq 'Block'
        $outbound = $p.DefaultOutboundAction -eq 'Allow' # STIG typically allows outbound, but logs/restricts in hardened environments
        $logging = ($p.LogAllowed -eq 'True') -or ($p.LogBlocked -eq 'True')
        
        [PSCustomObject]@{
            Profile       = $p.Name
            State         = if ($enabled) { "$([char]27)[32mCOMPLIANT (Enabled)$([char]27)[0m" } else { "$([char]27)[31mNON-COMPLIANT (Disabled)$([char]27)[0m" }
            InboundAction = if ($inbound) { "$([char]27)[32mBLOCK (STIG OK)$([char]27)[0m" } else { "$([char]27)[31mALLOW (Violation)$([char]27)[0m" }
            AuditLogging  = if ($logging) { "$([char]27)[32mACTIVE$([char]27)[0m" } else { "$([char]27)[33mDISABLED$([char]27)[0m" }
        }
    }
    return $results
}

# Clear screen & hide cursor approximation
[Console]::CursorVisible = $false
Clear-Host

# Define ports for bottom defense nodes
$defensePorts = @(21, 22, 80, 443, 3389, 8080)
$packetGrid = @()

# Initialize random incoming packets
for ($i = 0; $i -lt 8; $i++) {
    $packetGrid += [PSCustomObject]@{
        X = Get-Random -Minimum 10 -Maximum 110
        Y = Get-Random -Minimum 2 -Maximum 15
        Port = $defensePorts[(Get-Random -Minimum 0 -Maximum $defensePorts.Length)]
        Blocked = (Get-Random -Minimum 0 -Maximum 10) -gt 3 # 70% block rate per STIG rules
        Symbol = if ((Get-Random -Minimum 0 -Maximum 2) -eq 0) { "👾" } else { "🛸" }
    }
}

try {
    while ($true) {
        [Console]::SetCursorPosition(0, 0)
        
        # --- HEADER / STIG STATUS CONSOLE ---
        Write-Host "$([char]27)[1m$([char]27)[36m=========================================================================================================="
        Write-Host " [CYBERCOM DEFENSE CONSOLE] - WINDOWS FIREWALL DISA STIG COMPLIANCE & LIVE PACKET INTERCEPTOR"
        Write-Host "==========================================================================================================$([char]27)[0m"
        
        $stigStatus = Get-StigCompliance
        foreach ($s in $stigStatus) {
            Write-Host " [$($s.Profile.ToUpper()) PROFILE] -> Status: $($s.State) | Inbound: $($s.InboundAction) | Audit: $($s.AuditLogging)"
        }
        Write-Host "----------------------------------------------------------------------------------------------------------"
        Write-Host "$([char]27)[33m [PEW-PEW RADAR] Mapped Ports: 21(FTP) 22(SSH) 80(HTTP) 443(HTTPS) 3389(RDP) 8080(ALT-HTTP) $([char]27)[0m"
        Write-Host "----------------------------------------------------------------------------------------------------------"

        # --- SPACE INVADERS ARENA RENDERING ---
        # Draw game frame box (Rows 10 to 32)
        $arenaHeight = 20
        $arenaWidth = 118

        # Create blank canvas buffer
        $canvas = foreach ($r in 1..$arenaHeight) { 
            [System.Text.StringBuilder]::new(''.PadRight($arenaWidth)) 
        }

        # Update and draw packets
        foreach ($pkt in $packetGrid) {
            $pkt.Y++
            if ($pkt.Y -ge ($arenaHeight - 2)) {
                # Reset packet at top with new random attributes
                $pkt.Y = 2
                $pkt.X = Get-Random -Minimum 5 -Maximum ($arenaWidth - 5)
                $pkt.Port = $defensePorts[(Get-Random -Minimum 0 -Maximum $defensePorts.Length)]
                $pkt.Blocked = (Get-Random -Minimum 0 -Maximum 10) -gt 3
            }

            # Place packet on canvas
            if ($pkt.Y -lt $arenaHeight - 2) {
                $statusChar = if ($pkt.Blocked) { "$([char]27)[31mX$([char]27)[0m" } else { "$([char]27)[32mO$([char]27)[0m" }
                # Draw character at position
                $rowStr = $canvas[$pkt.Y].ToString()
                if ($pkt.X -lt $rowStr.Length) {
                    $canvas[$pkt.Y][$pkt.X] = if ($pkt.Blocked) { [char]'X' } else { [char]'V' }
                }
            }
        }

        # Render Canvas to Screen
        for ($r = 0; $r -lt $canvas.Count; $r++) {
            $line = $canvas[$r].ToString()
            # Highlight blocked vs allowed colors
            $line = $line -replace 'X', "$([char]27)[31m[BLOCKED:STIG]$([char]27)[0m"
            $line = $line -replace 'V', "$([char]27)[32m[ALLOWED:PASS]$([char]27)[0m"
            Write-Host "| $line |"
        }

        # --- BOTTOM DEFENSE WALL & PORTS ---
        Write-Host "+--------------------------------------------------------------------------------------------------------+"
        Write-Host " |  PORT 21  |  PORT 22  |  PORT 80  |  PORT 443  |  PORT 3389  |  PORT 8080  | [ FIREWALL SHIELD: ACTIVE ] |"
        Write-Host "+--------------------------------------------------------------------------------------------------------+"
        Write-Host " Press [CTRL+C] to abort tactical monitoring session." -ForegroundColor DarkGray

        Start-Sleep -Milliseconds 150
    }
}
finally {
    [Console]::CursorVisible = $true
}
