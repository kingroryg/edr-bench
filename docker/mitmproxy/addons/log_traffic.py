"""
mitmproxy addon that logs all HTTP flows to a structured JSONL file.

Each line in the output file is a JSON object containing:
- timestamp: ISO 8601 UTC timestamp
- method: HTTP method
- url: full request URL
- request_headers: dict of request headers
- request_body: request body (truncated to 4096 bytes)
- status_code: HTTP response status code
- response_content_type: Content-Type of the response
- response_size: size of the response body in bytes
"""

import json
import os
from datetime import datetime, timezone

from mitmproxy import http

LOG_FILE = "/flows/traffic.jsonl"
MAX_BODY_LENGTH = 4096


class TrafficLogger:
    def __init__(self) -> None:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    def response(self, flow: http.HTTPFlow) -> None:
        """Called when a full HTTP response has been received."""
        request = flow.request
        response = flow.response

        # Extract request body, truncating if necessary
        request_body = ""
        if request.content:
            try:
                raw = request.content[:MAX_BODY_LENGTH]
                request_body = raw.decode("utf-8", errors="replace")
            except Exception:
                request_body = f"<binary, {len(request.content)} bytes>"

        # Build request headers dict
        request_headers = dict(request.headers)

        # Build log entry
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": request.method,
            "url": request.pretty_url,
            "request_headers": request_headers,
            "request_body": request_body,
            "status_code": response.status_code if response else None,
            "response_content_type": (
                response.headers.get("Content-Type", "") if response else ""
            ),
            "response_size": len(response.content) if response and response.content else 0,
        }

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")


addons = [TrafficLogger()]
