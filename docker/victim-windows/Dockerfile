# NOTE: This Dockerfile requires a Windows Docker host to build and run.
# It will NOT work on Linux or macOS Docker hosts.
FROM mcr.microsoft.com/windows/servercore:ltsc2022

# Install Chocolatey
RUN powershell -NoProfile -ExecutionPolicy Bypass -Command \
    "Set-ExecutionPolicy Bypass -Scope Process -Force; \
     [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; \
     iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"

# Install packages via Chocolatey
RUN choco install -y python3 git curl

# Copy setup script
COPY setup.ps1 C:\\setup.ps1

# Run setup
RUN powershell -NoProfile -ExecutionPolicy Bypass -File C:\\setup.ps1

CMD ["powershell", "-NoProfile", "-Command", "Start-Sleep -Seconds 2147483"]
