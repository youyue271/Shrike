# Configure guest network for ResultServer communication
# This script runs at guest startup to configure the internal network adapter

$ErrorActionPreference = "Continue"

$ipAddress = "192.168.100.2"
$prefixLength = 24
$gateway = "192.168.100.1"

try {
    # Find the network adapter (may be named differently)
    $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1

    if (-not $adapter) {
        Write-Host "No active network adapter found, skipping network config"
        exit 0
    }

    Write-Host "Configuring adapter: $($adapter.Name)"

    # Remove existing IP configuration
    Remove-NetIPAddress -InterfaceAlias $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetRoute -InterfaceAlias $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue

    # Set static IP
    New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $ipAddress -PrefixLength $prefixLength -DefaultGateway $gateway -ErrorAction SilentlyContinue

    Write-Host "Network configured: $ipAddress"

} catch {
    Write-Host "Network configuration failed (non-fatal): $_"
}

exit 0
