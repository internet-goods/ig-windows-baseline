function Enforce-BlockFirewallRules {
    param (
        [Parameter(Mandatory=$true)]
        [array]$RuleList
    )

    foreach ($Rule in $RuleList) {
        Write-Host "--- Hardening: $($Rule.DisplayName) ---" -ForegroundColor Cyan
        
        # 1. Look for existing rules (by Name or DisplayName)
        $Existing = Get-NetFirewallRule -Name $Rule.Name -ErrorAction SilentlyContinue
        if (!$Existing) {
            $Existing = Get-NetFirewallRule -DisplayName $Rule.DisplayName -ErrorAction SilentlyContinue
        }

        if ($Existing) {
            # 2. Integrity Check: Ensure it is Enabled and set to BLOCK
            $Filter = $Existing | Get-NetFirewallPortFilter
            
            $Mismatch = $false
            if ($Existing.Action -ne "Block") { $Mismatch = $true }
            if ($Existing.Enabled -ne "True") { $Mismatch = $true }
            if ($Filter.LocalPort -ne $Rule.Port) { $Mismatch = $true }

            if ($Mismatch) {
                Write-Host "Rule exists but is not restrictive enough. Fixing..." -ForegroundColor Yellow
                Set-NetFirewallRule -Name $Existing.Name -Action Block -Enabled True
                Set-NetFirewallPortFilter -RuleName $Existing.Name -Protocol $Rule.Protocol -LocalPort $Rule.Port
                Write-Host "Repair complete: Protocol is now BLOCKED." -ForegroundColor Green
            } else {
                Write-Host "Integrity check passed: Already blocked." -ForegroundColor Green
            }
        } else {
            # 3. Create a new Block rule if it doesn't exist
            Write-Host "No rule found. Creating new Block rule..." -ForegroundColor White
            New-NetFirewallRule -Name $Rule.Name `
                                -DisplayName $Rule.DisplayName `
                                -Direction $Rule.Direction `
                                -Protocol $Rule.Protocol `
                                -LocalPort $Rule.Port `
                                -Action Block `
                                -Enabled True `
                                -Group "IG Security"
            Write-Host "New Block rule created." -ForegroundColor Green
        }
    }
}

# --- Define the Master Block List ---
$HardeningRules = @(
    # LLMNR (Link-Local Multicast Name Resolution)
    @{ Name="Block-LLMNR-UDP-In";  DisplayName="Network Discovery (LLMNR-UDP-In)";  Direction="Inbound";  Protocol="UDP"; Port="5355" },
    @{ Name="Block-LLMNR-UDP-Out"; DisplayName="Network Discovery (LLMNR-UDP-Out)"; Direction="Outbound"; Protocol="UDP"; Port="5355" },
    
    # NetBIOS (Name Service / Datagram)
    @{ Name="Block-NetBIOS-NS-In";  DisplayName="Network Discovery (NB-Name-In)";     Direction="Inbound";  Protocol="UDP"; Port="137" },
    @{ Name="Block-NetBIOS-NS-In";  DisplayName="Network Discovery (NB-Name-Out)";     Direction="Outbound";  Protocol="UDP"; Port="137" },
    @{ Name="Block-NetBIOS-DG-In";  DisplayName="Network Discovery (NB-Datagram-In)"; Direction="Inbound"; Protocol="UDP"; Port="138" },
    @{ Name="Block-NetBIOS-DG-Out";  DisplayName="Network Discovery (NB-Datagram-Out)"; Direction="Outbound"; Protocol="UDP"; Port="138" },
    # SSDP / UPnP (Simple Service Discovery Protocol)
    @{ Name="Block-SSDP-In";        DisplayName="Hardening: Block SSDP Inbound";   Direction="Inbound";  Protocol="UDP"; Port="1900" },
    @{ Name="Block-UPnP-TCP-In";    DisplayName="Hardening: Block UPnP TCP In";    Direction="Inbound";  Protocol="TCP"; Port="2869" }
    # mDNS (Multicast DNS) not a default
    @{ Name="Block-mDNS-In";        DisplayName="Hardening: Block mDNS Inbound";   Direction="Inbound";  Protocol="UDP"; Port="5353" },
    @{ Name="Block-mDNS-Out";       DisplayName="Hardening: Block mDNS Outbound";  Direction="Outbound"; Protocol="UDP"; Port="5353" },
    @{ Name="Block-QUIC-Out";       DisplayName="Hardening: Block QUIC Outbound";  Direction="Outbound"; Protocol="UDP"; Port="443" },

)

# --- Execute ---
Enforce-BlockFirewallRules -RuleList $HardeningRules
