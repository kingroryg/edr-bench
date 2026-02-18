#!/bin/bash
set -e

# Set VNC password
mkdir -p /root/.vnc
echo "${VNC_PASSWORD:-changeme}" | vncpasswd -f > /root/.vnc/passwd
chmod 600 /root/.vnc/passwd

# Configure HTTP proxy to route traffic through mitmproxy
export HTTP_PROXY=http://172.28.2.20:8080
export HTTPS_PROXY=http://172.28.2.20:8080
export http_proxy=http://172.28.2.20:8080
export https_proxy=http://172.28.2.20:8080

# Write proxy config for child processes
cat > /etc/environment <<EOF
HTTP_PROXY=http://172.28.2.20:8080
HTTPS_PROXY=http://172.28.2.20:8080
http_proxy=http://172.28.2.20:8080
https_proxy=http://172.28.2.20:8080
EOF

# ---------------------------------------------------------------------------
# Network sandbox: route external IPs and DNS through mocknet
# ---------------------------------------------------------------------------
# Scenarios reference external IPs (203.0.113.x, 192.168.1.x) for exfil
# targets. DNAT redirects them to the mocknet container so the commands
# actually succeed and we can capture ground truth.
echo "[entrypoint] Setting up iptables DNAT rules..."
iptables -t nat -A OUTPUT -d 203.0.113.0/24 -j DNAT --to-destination 172.28.2.10 || true
iptables -t nat -A OUTPUT -d 192.168.1.0/24 -j DNAT --to-destination 172.28.2.10 || true

# Redirect all outgoing DNS (port 53) to dnsmasq on mocknet so even
# explicit @8.8.8.8 queries in exfil scenarios get logged.
iptables -t nat -A OUTPUT -p udp --dport 53 ! -d 172.28.2.10 -j DNAT --to-destination 172.28.2.10:53 || true
iptables -t nat -A OUTPUT -p tcp --dport 53 ! -d 172.28.2.10 -j DNAT --to-destination 172.28.2.10:53 || true

# ---------------------------------------------------------------------------
# SSH config: accept all host keys (test environment only)
# ---------------------------------------------------------------------------
mkdir -p /root/.ssh
chmod 700 /root/.ssh
cat >> /etc/ssh/ssh_config <<SSHEOF
Host *
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
SSHEOF

# Create user home directory structure
mkdir -p /home/user/Downloads /home/user/Documents /home/user/.ssh /home/user/PDF
chmod 700 /home/user/.ssh

# ---------------------------------------------------------------------------
# Configure CUPS-PDF virtual printer
# ---------------------------------------------------------------------------
echo "[entrypoint] Configuring CUPS-PDF printer..."
mkdir -p /var/spool/cups-pdf/ANONYMOUS
# Add a virtual PDF printer if it doesn't already exist
if ! lpstat -p PDF 2>/dev/null; then
    lpadmin -p PDF -v cups-pdf:/ -E -m lsb/usr/cups-pdf/CUPS-PDF_opt.ppd 2>/dev/null || \
    lpadmin -p PDF -v cups-pdf:/ -E -m raw 2>/dev/null || \
    echo "[entrypoint] CUPS-PDF printer setup deferred to cupsd start"
fi
# Set PDF output directory
mkdir -p /etc/cups
if [ -f /etc/cups/cups-pdf.conf ]; then
    sed -i 's|^Out .*|Out /home/user/PDF|' /etc/cups/cups-pdf.conf
else
    echo "Out /home/user/PDF" > /etc/cups/cups-pdf.conf
fi

# Set up git config for test scenarios
git config --global user.email "testuser@acme.com"
git config --global user.name "Test User"
git config --global init.defaultBranch main

# Set up xstartup for VNC
cat > /root/.vnc/xstartup <<EOF
#!/bin/bash
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
exec startxfce4
EOF
chmod +x /root/.vnc/xstartup

echo "[entrypoint] Starting supervisord..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
