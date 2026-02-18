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
