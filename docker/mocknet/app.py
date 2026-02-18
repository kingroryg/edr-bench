"""
Mock network Flask application for edr-bench.

Provides fake API endpoints that log all traffic for analysis.
Simulates credential harvesting, data exfiltration, and C2 endpoints.
"""

import json
import os
import time
import uuid
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request

app = Flask(__name__)

LOG_DIR = "/var/log/mocknet"
LOG_FILE = os.path.join(LOG_DIR, "traffic.jsonl")


def _ensure_log_dir() -> None:
    os.makedirs(LOG_DIR, exist_ok=True)


def _log_request(endpoint: str, data: dict) -> None:
    """Append a structured log entry to the traffic JSONL file."""
    _ensure_log_dir()
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint": endpoint,
        "method": request.method,
        "remote_addr": request.remote_addr,
        "host": request.host,
        "user_agent": request.headers.get("User-Agent", ""),
        "data": data,
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


@app.route("/api/login", methods=["POST"])
def login():
    """Simulate a login endpoint. Logs submitted credentials and returns a fake token."""
    if request.is_json:
        creds = request.get_json(silent=True) or {}
    else:
        creds = {
            "username": request.form.get("username", request.form.get("email", "")),
            "password": request.form.get("password", ""),
        }

    _log_request("/api/login", creds)

    return jsonify(
        {
            "status": "success",
            "token": f"fake-jwt-{uuid.uuid4().hex[:16]}",
            "expires_in": 3600,
        }
    )


@app.route("/api/data", methods=["POST"])
def data():
    """Simulate a data exfiltration endpoint. Logs all posted data."""
    if request.is_json:
        payload = request.get_json(silent=True) or {}
    else:
        payload = dict(request.form)

    _log_request("/api/data", payload)

    return jsonify(
        {
            "status": "success",
            "received_bytes": request.content_length or 0,
        }
    )


@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok", "timestamp": time.time()})


if __name__ == "__main__":
    _ensure_log_dir()
    app.run(host="0.0.0.0", port=5000)
