"""
MockNet Flask app for edr-bench.

This is the ground truth backbone. Every mock site in the sandbox posts
user actions here, and we log exactly what happened -- what content was
sent, where it went, and what the user did. No truncation, no sampling.
An EDR tool's job is to detect these actions. Our job is to record them
faithfully so we can score the EDR later.
"""

import io
import json
import os
import tarfile
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
# File upload catch-all (for curl-to-IP exfil scenarios)
# -------------------------------------------------------------------

@app.route("/upload", methods=["POST", "PUT"])
def upload():
    """
    Catch-all upload endpoint for exfil scenarios that POST files
    to external IPs (which iptables DNAT redirects here).
    """
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

    payload = {}
    if request.is_json:
        payload = request.get_json(silent=True) or {}
    elif request.form:
        payload = dict(request.form)

    _log_event({
        "endpoint": "/upload",
        "site": request.host,
        "action": "file_upload_exfil",
        "data": payload,
        "uploaded_files": saved_files,
        "content_length": request.content_length or 0,
    })

    return jsonify({"status": "uploaded", "files": len(saved_files)})


# -------------------------------------------------------------------
# Git pkt-line helpers
# -------------------------------------------------------------------

def _pkt_line(data: str) -> bytes:
    """Encode a string as a git pkt-line (4-hex-digit length prefix)."""
    encoded = data.encode()
    length = len(encoded) + 4
    return f"{length:04x}".encode() + encoded


def _flush_pkt() -> bytes:
    """Return a git flush packet."""
    return b"0000"


# -------------------------------------------------------------------
# Mock git HTTP protocol (for git push scenarios)
# -------------------------------------------------------------------

@app.route("/<path:repo_path>/info/refs", methods=["GET"])
def git_info_refs(repo_path):
    """Mock git smart HTTP service advertisement for push scenarios.

    Implements the git smart HTTP discovery protocol:
      1. Service announcement pkt-line
      2. Flush packet
      3. Capabilities line (zero-hash for empty repo)
      4. Flush packet
    """
    service = request.args.get("service", "git-upload-pack")

    _log_event({
        "endpoint": f"/{repo_path}/info/refs",
        "site": request.host,
        "action": "git_service_discovery",
        "data": {"repo": repo_path, "service": service},
    })

    if service == "git-receive-pack":
        # Step 1: service announcement + flush
        body = _pkt_line("# service=git-receive-pack\n") + _flush_pkt()

        # Step 2: capabilities for empty repo (zero-hash) + flush
        zero_hash = "0" * 40
        cap_line = (
            f"{zero_hash} capabilities^{{}}\0"
            " report-status delete-refs ofs-delta side-band-64k\n"
        )
        body += _pkt_line(cap_line) + _flush_pkt()

        return Response(
            body,
            content_type="application/x-git-receive-pack-advertisement",
            status=200,
        )

    return Response("service not available", status=403)


@app.route("/<path:repo_path>/git-receive-pack", methods=["POST"])
def git_receive_pack(repo_path):
    """Mock git-receive-pack (handles git push).

    Reads the pack data sent by the client, logs the push event and
    pack data size, then returns a valid report-status response.
    """
    pack_data = request.data or b""
    pack_size = request.content_length or len(pack_data)

    _log_event({
        "endpoint": f"/{repo_path}/git-receive-pack",
        "site": request.host,
        "action": "git_push",
        "data": {
            "repo": repo_path,
            "pack_size_bytes": pack_size,
        },
        "content_length": pack_size,
    })

    # Build report-status response in pkt-line format
    body = _pkt_line("unpack ok\n")
    body += _pkt_line("ok refs/heads/main\n")
    body += _flush_pkt()

    return Response(
        body,
        content_type="application/x-git-receive-pack-result",
        status=200,
    )


# -------------------------------------------------------------------
# Mock npm registry (for typosquat / supply-chain scenarios)
# -------------------------------------------------------------------

@app.route("/<package_name>", methods=["GET"])
def npm_package_lookup(package_name):
    """Mock npm registry lookup for typosquat scenarios.

    npm does GET https://registry.npmjs.org/<package-name> and expects
    a JSON package manifest.  We only respond when the Host header
    indicates registry.npmjs.org so we don't interfere with other
    mock sites.
    """
    if "registry.npmjs.org" not in request.host:
        return Response("Not found", status=404)

    _log_event({
        "endpoint": f"/{package_name}",
        "site": "registry.npmjs.org",
        "action": "npm_package_lookup",
        "data": {"package": package_name},
    })

    return jsonify({
        "name": package_name,
        "description": f"A package called {package_name}",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "name": package_name,
                "version": "1.0.0",
                "description": f"A package called {package_name}",
                "dist": {
                    "tarball": f"http://registry.npmjs.org/{package_name}/-/{package_name}-1.0.0.tgz",
                    "shasum": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                },
            }
        },
        "time": {
            "created": "2026-02-17T00:00:00.000Z",
            "modified": "2026-02-17T00:00:00.000Z",
            "1.0.0": "2026-02-17T00:00:00.000Z",
        },
    })


@app.route("/<package_name>/-/<filename>", methods=["GET"])
def npm_package_tarball(package_name, filename):
    """Serve a minimal valid npm package tarball.

    npm fetches the tarball URL from the manifest and expects a gzipped
    tar archive containing at least ``package/package.json``.
    """
    if "registry.npmjs.org" not in request.host:
        return Response("Not found", status=404)

    _log_event({
        "endpoint": f"/{package_name}/-/{filename}",
        "site": "registry.npmjs.org",
        "action": "npm_package_download",
        "data": {"package": package_name, "filename": filename},
    })

    # Build a minimal valid gzipped tarball containing package.json
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        pkg_json = json.dumps({
            "name": package_name,
            "version": "1.0.0",
        }).encode()
        info = tarfile.TarInfo(name="package/package.json")
        info.size = len(pkg_json)
        tar.addfile(info, io.BytesIO(pkg_json))
    buf.seek(0)

    return Response(buf.read(), content_type="application/octet-stream")


# -------------------------------------------------------------------
# Mock PyPI (for typosquat / supply-chain scenarios)
# -------------------------------------------------------------------

@app.route("/simple/<package_name>/", methods=["GET"])
def pypi_simple(package_name):
    """Mock PyPI simple index for typosquat scenarios.

    pip does GET https://pypi.org/simple/<package-name>/ and expects
    an HTML page with download links.
    """
    if "pypi.org" not in request.host:
        return Response("Not found", status=404)

    _log_event({
        "endpoint": f"/simple/{package_name}/",
        "site": "pypi.org",
        "action": "pypi_package_lookup",
        "data": {"package": package_name},
    })

    html = (
        "<!DOCTYPE html>\n"
        "<html><body>\n"
        f'<a href="http://files.pythonhosted.org/packages/'
        f'{package_name}-1.0.0.tar.gz#sha256='
        f'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855">'
        f"{package_name}-1.0.0.tar.gz</a>\n"
        "</body></html>"
    )
    return Response(html, content_type="text/html")


@app.route("/packages/<path:filename>", methods=["GET"])
def pypi_file(filename):
    """Serve a minimal Python sdist tarball.

    pip downloads from files.pythonhosted.org/packages/<path>.  We
    return a valid gzipped tar containing a minimal setup.py.
    """
    if "files.pythonhosted.org" not in request.host:
        return Response("Not found", status=404)

    # Derive package name from filename (e.g. "somepackage-1.0.0.tar.gz")
    base = filename.rsplit("/", 1)[-1] if "/" in filename else filename
    pkg_name = base.split("-")[0] if "-" in base else base

    _log_event({
        "endpoint": f"/packages/{filename}",
        "site": "files.pythonhosted.org",
        "action": "pypi_package_download",
        "data": {"filename": filename, "package": pkg_name},
    })

    # Build a minimal valid sdist tarball
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # setup.py
        setup_py = (
            f"from setuptools import setup\n"
            f"setup(name='{pkg_name}', version='1.0.0')\n"
        ).encode()
        info = tarfile.TarInfo(name=f"{pkg_name}-1.0.0/setup.py")
        info.size = len(setup_py)
        tar.addfile(info, io.BytesIO(setup_py))

        # PKG-INFO (pip may expect this)
        pkg_info = (
            f"Metadata-Version: 1.0\n"
            f"Name: {pkg_name}\n"
            f"Version: 1.0.0\n"
        ).encode()
        info2 = tarfile.TarInfo(name=f"{pkg_name}-1.0.0/PKG-INFO")
        info2.size = len(pkg_info)
        tar.addfile(info2, io.BytesIO(pkg_info))
    buf.seek(0)

    return Response(buf.read(), content_type="application/octet-stream")


# -------------------------------------------------------------------
# Catch-all for any path (logs everything nginx proxies here)
# -------------------------------------------------------------------

@app.route("/<path:path>", methods=["POST", "PUT"])
def catch_all(path):
    """Log any POST/PUT that doesn't match a specific endpoint."""
    payload = {}
    if request.is_json:
        payload = request.get_json(silent=True) or {}
    elif request.form:
        payload = dict(request.form)

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
        "endpoint": f"/{path}",
        "site": request.host,
        "action": "catch_all",
        "data": payload,
        "uploaded_files": saved_files,
        "content_length": request.content_length or 0,
    })

    return jsonify({"status": "ok"})


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
