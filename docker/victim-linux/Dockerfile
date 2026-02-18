FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# Install base packages
RUN apt-get update && apt-get install -y \
    xfce4 \
    xfce4-goodies \
    tightvncserver \
    novnc \
    websockify \
    firefox \
    curl \
    wget \
    net-tools \
    python3 \
    python3-pip \
    git \
    supervisor \
    apt-transport-https \
    software-properties-common \
    gnupg2 \
    dbus-x11 \
    && rm -rf /var/lib/apt/lists/*

# Install PowerShell from Microsoft repository
RUN curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-archive-keyring.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-archive-keyring.gpg] https://packages.microsoft.com/repos/microsoft-ubuntu-22.04-prod jammy main" \
       > /etc/apt/sources.list.d/microsoft.list \
    && apt-get update \
    && apt-get install -y powershell \
    && rm -rf /var/lib/apt/lists/*

# Clone Atomic Red Team
RUN git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git /opt/atomic-red-team

# Create log directories
RUN mkdir -p /var/log/edr /root/.vnc

# Copy configuration files
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# NOTE: Make entrypoint.sh executable. If building on a system where file
# permissions are not preserved, run: chmod +x docker/victim-linux/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 5900 6080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
