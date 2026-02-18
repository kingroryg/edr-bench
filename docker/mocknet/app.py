"""
MockNet Flask app for edr-bench.

This is the ground truth backbone. Every mock site in the sandbox posts
user actions here, and we log exactly what happened -- what content was
sent, where it went, and what the user did. No truncation, no sampling.
An EDR tool's job is to detect these actions. Our job is to record them
faithfully so we can score the EDR later.
"""

import json
import os
import time
import uuid
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

LOG_DIR = "/var/log/mocknet"
LOG_FILE = os.path.join(LOG_DIR, "traffic.jsonl")
UPLOAD_DIR = "/var/log/mocknet/uploads"


def _ensure_dirs() -> None:
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)


def _log_event(event: dict) -> None:
    """Write one ground-truth event to the traffic log. No truncation."""
    _ensure_dirs()
    event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    event.setdefault("event_id", uuid.uuid4().hex[:16])
    event.setdefault("remote_addr", request.remote_addr)
    event.setdefault("user_agent", request.headers.get("User-Agent", ""))
    event.setdefault("host", request.host)

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event, default=str) + "\n")


# -------------------------------------------------------------------
# Main capture endpoint -- all mock sites post here
# -------------------------------------------------------------------

@app.route("/api/capture", methods=["POST"])
def capture():
    """
    Universal content capture. Every mock site sends user actions here.

    Accepts JSON, form data, or multipart file uploads.
    Logs everything with full content -- this IS the ground truth.

    Expected fields (all optional, sites send what they have):
        site        - which mock site (chatgpt.com, drive.google.com, etc)
        action      - what happened (paste_text, upload_file, share_link, send_message, etc)
        content     - the actual text/data the user entered
        filename    - for file uploads
        metadata    - any extra context (channel, recipient, share_scope, etc)
    """
    event = {
        "endpoint": "/api/capture",
        "method": "POST",
        "content_type": request.content_type or "",
    }

    # Handle file uploads (multipart/form-data)
    saved_files = []
    if request.files:
        for key, f in request.files.items():
            fname = secure_filename(f.filename or "unnamed")
            # Add a unique prefix so files don't overwrite each other
            save_name = f"{uuid.uuid4().hex[:8]}_{fname}"
            save_path = os.path.join(UPLOAD_DIR, save_name)
            f.save(save_path)
            file_size = os.path.getsize(save_path)
            saved_files.append({
                "field": key,
                "original_name": f.filename,
                "saved_as": save_name,
                "size_bytes": file_size,
                "content_type": f.content_type or "",
            })
        event["uploaded_files"] = saved_files

    # Handle JSON body
    if request.is_json:
        body = request.get_json(silent=True) or {}
        event["data"] = body
    else:
        # Form data (may coexist with file uploads)
        form_data = dict(request.form)
        if form_data:
            event["data"] = form_data

    # Pull out key fields for easy querying
    data = event.get("data", {})
    event["site"] = data.get("site", request.headers.get("X-Mock-Site", request.host))
    event["action"] = data.get("action", "unknown")
    event["content_length"] = request.content_length or 0

    _log_event(event)

    return jsonify({
        "status": "captured",
        "event_id": event["event_id"],
        "files_saved": len(saved_files),
    })


# -------------------------------------------------------------------
# Legacy endpoints (still used by some classic scenarios)
# -------------------------------------------------------------------

@app.route("/api/login", methods=["POST"])
def login():
    """Fake login page. Logs whatever credentials are submitted."""
    if request.is_json:
        creds = request.get_json(silent=True) or {}
    else:
        creds = {
            "username": request.form.get("username", request.form.get("email", "")),
            "password": request.form.get("password", ""),
        }

    _log_event({
        "endpoint": "/api/login",
        "site": request.host,
        "action": "credential_submit",
        "data": creds,
    })

    return jsonify({
        "status": "success",
        "token": f"fake-jwt-{uuid.uuid4().hex[:16]}",
        "expires_in": 3600,
    })


@app.route("/api/data", methods=["POST"])
def data():
    """Generic data exfil endpoint. Logs the full body."""
    if request.is_json:
        payload = request.get_json(silent=True) or {}
    else:
        payload = dict(request.form)

    # Also grab raw body for non-JSON posts (tar files, binaries, etc)
    raw_body = None
    if not request.is_json and request.data:
        raw_body = request.data.hex()[:10000]  # hex encode first 5KB of binary

    event_data = {"form_or_json": payload}
    if raw_body:
        event_data["raw_body_hex_preview"] = raw_body

    _log_event({
        "endpoint": "/api/data",
        "site": request.host,
        "action": "data_exfil",
        "data": event_data,
        "content_length": request.content_length or 0,
    })

    return jsonify({
        "status": "success",
        "received_bytes": request.content_length or 0,
    })


# -------------------------------------------------------------------
# Scenario-specific mock endpoints
# -------------------------------------------------------------------

@app.route("/api/share", methods=["POST"])
def share():
    """Mock sharing endpoint for Google Drive, GitHub, etc."""
    data = request.get_json(silent=True) or dict(request.form)
    _log_event({
        "endpoint": "/api/share",
        "site": request.host,
        "action": "share_resource",
        "data": data,
    })
    return jsonify({"status": "shared", "share_id": uuid.uuid4().hex[:12]})


@app.route("/api/send", methods=["POST"])
def send_message():
    """Mock messaging endpoint for Slack, WhatsApp, Gmail, etc."""
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = dict(request.form)

    # Handle file attachments in messages
    saved_files = []
    if request.files:
        for key, f in request.files.items():
            fname = secure_filename(f.filename or "unnamed")
            save_name = f"{uuid.uuid4().hex[:8]}_{fname}"
            save_path = os.path.join(UPLOAD_DIR, save_name)
            f.save(save_path)
            saved_files.append({
                "field": key,
                "original_name": f.filename,
                "saved_as": save_name,
                "size_bytes": os.path.getsize(save_path),
            })

    _log_event({
        "endpoint": "/api/send",
        "site": request.host,
        "action": "send_message",
        "data": data,
        "attached_files": saved_files,
    })

    return jsonify({"status": "sent", "message_id": uuid.uuid4().hex[:12]})


@app.route("/api/install", methods=["POST"])
def install():
    """Mock install endpoint for extensions, packages, etc."""
    data = request.get_json(silent=True) or dict(request.form)
    _log_event({
        "endpoint": "/api/install",
        "site": request.host,
        "action": "install_software",
        "data": data,
    })
    return jsonify({"status": "installed"})


@app.route("/api/oauth/authorize", methods=["POST"])
def oauth_authorize():
    """Mock OAuth consent. Logs what scopes were granted."""
    data = request.get_json(silent=True) or dict(request.form)
    _log_event({
        "endpoint": "/api/oauth/authorize",
        "site": request.host,
        "action": "oauth_consent",
        "data": data,
    })
    return jsonify({
        "status": "authorized",
        "access_token": f"fake-token-{uuid.uuid4().hex[:16]}",
    })


@app.route("/api/wire-transfer", methods=["POST"])
def wire_transfer():
    """Mock banking wire transfer."""
    data = request.get_json(silent=True) or dict(request.form)
    _log_event({
        "endpoint": "/api/wire-transfer",
        "site": request.host,
        "action": "wire_transfer",
        "data": data,
    })
    return jsonify({"status": "pending", "reference": f"WT-{uuid.uuid4().hex[:8].upper()}"})


@app.route("/api/visibility", methods=["POST"])
def change_visibility():
    """Mock repo/doc visibility change (GitHub, Google Drive)."""
    data = request.get_json(silent=True) or dict(request.form)
    _log_event({
        "endpoint": "/api/visibility",
        "site": request.host,
        "action": "visibility_change",
        "data": data,
    })
    return jsonify({"status": "changed"})


@app.route("/api/provision", methods=["POST"])
def provision_access():
    """Mock IAM provisioning (Okta, GitHub org, Azure AD)."""
    data = request.get_json(silent=True) or dict(request.form)
    _log_event({
        "endpoint": "/api/provision",
        "site": request.host,
        "action": "provision_access",
        "data": data,
    })
    return jsonify({"status": "provisioned"})


@app.route("/api/review", methods=["POST"])
def access_review():
    """Mock access review submission."""
    data = request.get_json(silent=True) or dict(request.form)
    _log_event({
        "endpoint": "/api/review",
        "site": request.host,
        "action": "access_review",
        "data": data,
    })
    return jsonify({"status": "submitted"})


@app.route("/api/print", methods=["POST"])
def print_document():
    """Mock print spooler."""
    data = request.get_json(silent=True) or dict(request.form)
    saved_files = []
    if request.files:
        for key, f in request.files.items():
            fname = secure_filename(f.filename or "unnamed")
            save_name = f"{uuid.uuid4().hex[:8]}_{fname}"
            save_path = os.path.join(UPLOAD_DIR, save_name)
            f.save(save_path)
            saved_files.append({
                "original_name": f.filename,
                "saved_as": save_name,
                "size_bytes": os.path.getsize(save_path),
            })

    _log_event({
        "endpoint": "/api/print",
        "site": request.host,
        "action": "print_document",
        "data": data,
        "printed_files": saved_files,
    })
    return jsonify({"status": "printed", "job_id": f"PRINT-{uuid.uuid4().hex[:8].upper()}"})


# -------------------------------------------------------------------
# Health check
# -------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "timestamp": time.time()})


# -------------------------------------------------------------------
# Serve test fixture files (loaded into victim container)
# -------------------------------------------------------------------

@app.route("/fixtures/<path:filename>", methods=["GET"])
def serve_fixture(filename):
    """Serve test data fixtures so scenarios can load them."""
    fixtures_dir = "/var/www/fixtures"
    if os.path.isdir(fixtures_dir):
        return send_from_directory(fixtures_dir, filename)
    return Response("No fixtures loaded", status=404)


if __name__ == "__main__":
    _ensure_dirs()
    app.run(host="0.0.0.0", port=5000)
