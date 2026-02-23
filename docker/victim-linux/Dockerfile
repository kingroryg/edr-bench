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
    openssh-client \
    sshpass \
    iproute2 \
    iptables \
    iputils-ping \
    zip \
    unzip \
    jq \
    xxd \
    ncat \
    dnsutils \
    util-linux \
    cups \
    cups-pdf \
    imagemagick \
    xclip \
    xdotool \
    syncthing \
    cron \
    sudo \
    auditd \
    audispd-plugins \
    && rm -rf /var/lib/apt/lists/*

# Install Firefox ESR from Mozilla tarball (Ubuntu 22.04's "firefox" package
# is a snap shim that doesn't work in Docker containers)
RUN FF_ARCH=$(case $(dpkg --print-architecture) in arm64) echo "linux64-aarch64";; *) echo "linux64";; esac) \
    && curl -fsSL "https://download.mozilla.org/?product=firefox-esr-latest-ssl&os=${FF_ARCH}&lang=en-US" -o /tmp/firefox.tar.xz \
    && tar xJf /tmp/firefox.tar.xz -C /opt/ \
    && rm /tmp/firefox.tar.xz \
    && mv /usr/bin/firefox /usr/bin/firefox.snap-shim 2>/dev/null || true \
    && printf '#!/bin/bash\nexec /opt/firefox/firefox --no-sandbox "$@"\n' > /usr/bin/firefox \
    && chmod +x /usr/bin/firefox

# Install Node.js + npm (for typosquat / package install scenarios)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install Terraform (for infrastructure misconfiguration scenarios)
RUN TF_ARCH=$(dpkg --print-architecture) \
    && curl -fsSL "https://releases.hashicorp.com/terraform/1.7.5/terraform_1.7.5_linux_${TF_ARCH}.zip" -o /tmp/tf.zip \
    && unzip /tmp/tf.zip -d /usr/local/bin/ \
    && rm /tmp/tf.zip

# Install PowerShell (amd64 via MS repo, arm64 via tarball)
RUN if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-archive-keyring.gpg \
        && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-archive-keyring.gpg] https://packages.microsoft.com/repos/microsoft-ubuntu-22.04-prod jammy main" \
           > /etc/apt/sources.list.d/microsoft.list \
        && apt-get update \
        && apt-get install -y powershell \
        && rm -rf /var/lib/apt/lists/*; \
    elif [ "$(dpkg --print-architecture)" = "arm64" ]; then \
        curl -fsSL https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/powershell-7.4.6-linux-arm64.tar.gz \
           -o /tmp/pwsh.tar.gz \
        && mkdir -p /opt/pwsh \
        && tar xzf /tmp/pwsh.tar.gz -C /opt/pwsh \
        && chmod +x /opt/pwsh/pwsh \
        && ln -sf /opt/pwsh/pwsh /usr/local/bin/pwsh \
        && rm /tmp/pwsh.tar.gz; \
    else echo "Skipping PowerShell install (unsupported arch)"; fi

# Install Wazuh agent (started conditionally via supervisord)
RUN curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh-archive-keyring.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
       > /etc/apt/sources.list.d/wazuh.list \
    && WAZUH_MANAGER="172.28.6.10" apt-get update \
    && WAZUH_MANAGER="172.28.6.10" apt-get install -y wazuh-agent \
    && rm -rf /var/lib/apt/lists/* \
    && systemctl disable wazuh-agent 2>/dev/null || true

# Clone Atomic Red Team
RUN git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git /opt/atomic-red-team

# Create log directories
RUN mkdir -p /var/log/edr /root/.vnc /var/log/audit

# Install VS Code for extension install scenarios (COACH-037)
RUN VSCODE_ARCH=$(dpkg --print-architecture) \
    && curl -fsSL "https://update.code.visualstudio.com/latest/linux-deb-${VSCODE_ARCH}/stable" -o /tmp/code.deb \
    && dpkg -i /tmp/code.deb || apt-get install -f -y \
    && rm /tmp/code.deb

# Copy configuration files
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# NOTE: Make entrypoint.sh executable. If building on a system where file
# permissions are not preserved, run: chmod +x docker/victim-linux/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 5900 6080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
