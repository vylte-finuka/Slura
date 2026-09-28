# Firewall rule for Slura OS Testnet - UDP Port 30315
# Run as Administrator in PowerShell

# Create inbound rule for UDP 30315
New-NetFirewallRule -DisplayName "Slura OS Testnet P2P UDP 30315" `
    -Direction Inbound -Protocol UDP -LocalPort 30315 -Action Allow `
    -Profile Private,Public -Description "Allow Slura OS Testnet P2P communication on UDP 30315"

# Create outbound rule for UDP 30315
New-NetFirewallRule -DisplayName "Slura OS Testnet P2P UDP 30315 Outbound" `
    -Direction Outbound -Protocol UDP -LocalPort 30315 -Action Allow `
    -Profile Private,Public -Description "Allow Slura OS Testnet P2P communication outbound on UDP 30315"

Write-Host "Firewall rules created for Slura OS Testnet UDP 30315" -ForegroundColor Green