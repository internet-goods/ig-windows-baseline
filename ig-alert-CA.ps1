# 1. Define the known Microsoft Root Thumbprints (Baseline)
# This is a sample list of common MS Roots. 
$MSRoots = @(
    "CDD4EE0B084510B5272635398B18A57A43B2217E", # Microsoft Root Certificate Authority
    "3B1EFD3A000F2906103003A600A632007B001F00", # Microsoft Root Authority
    "28CC3A25BFBA44AC449A9B586B4339AA",         # Microsoft Root Certificate Authority 2010
    "3F8BC8B5FC9FB29643B569D66C42E144"          # Microsoft Root Certificate Authority 2011
)

# 2. Get all certificates in the Local Machine Trusted Root Store
$CurrentRoots = Get-ChildItem -Path Cert:\LocalMachine\Root

# 3. Filter for non-Microsoft / Non-Default CAs
$NonDefaultCAs = $CurrentRoots | Where-Object {
    # Filter out by Thumbprint baseline
    $MSRoots -notcontains $_.Thumbprint -and 
    # Filter out common Microsoft-signed infrastructure certs
    $_.Subject -notmatch "Microsoft" -and
    # Exclude basic hardware/OEM certs (optional, remove if you want strict audit)
    $_.Subject -notmatch "Windows"
}

# 4. Report results
if ($NonDefaultCAs) {
    Write-Host "--- NON-DEFAULT OR THIRD-PARTY CAs FOUND ---" -ForegroundColor Yellow
    $NonDefaultCAs | Select-Object FriendlyName, Subject, Thumbprint, NotAfter | Format-Table -AutoSize
} else {
    Write-Host "No non-default CAs detected in the Root Store." -ForegroundColor Green
}
