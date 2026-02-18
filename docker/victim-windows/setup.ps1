# setup.ps1 - Configure Windows victim machine for EDR benchmarking

# Set execution policy
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Force

# Install NuGet provider (required for PowerShell module installation)
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

# Install Atomic Red Team via Invoke-AtomicRedTeam
Write-Host "[setup] Installing Atomic Red Team..."
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1')
Install-AtomicRedTeam -getAtomics -Force

Write-Host "[setup] Atomic Red Team installation complete."

# Create log directory for EDR telemetry
New-Item -ItemType Directory -Path C:\edr-logs -Force | Out-Null

Write-Host "[setup] Windows victim setup complete."
