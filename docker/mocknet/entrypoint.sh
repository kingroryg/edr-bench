#!/bin/bash
set -e

# Trap SIGTERM/SIGINT and forward to child processes
cleanup() {
    echo "[entrypoint] Shutting down services..."
    kill "$DNSMASQ_PID" "$NGINX_PID" "$FLASK_PID" 2>/dev/null || true
    wait "$DNSMASQ_PID" "$NGINX_PID" "$FLASK_PID" 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

# Start SSH daemon
/usr/sbin/sshd

# Start dnsmasq in background
dnsmasq --keep-in-foreground &
DNSMASQ_PID=$!

# Start nginx in background (daemon off handled by default config)
nginx &
NGINX_PID=$!

# Start Flask app in background
python3 /app/app.py &
FLASK_PID=$!

echo "[entrypoint] All services started (dnsmasq=$DNSMASQ_PID, nginx=$NGINX_PID, flask=$FLASK_PID)"

# Wait for any child to exit; if one dies, shut down all
wait -n "$DNSMASQ_PID" "$NGINX_PID" "$FLASK_PID" 2>/dev/null || true
echo "[entrypoint] A service exited unexpectedly, shutting down..."
cleanup
