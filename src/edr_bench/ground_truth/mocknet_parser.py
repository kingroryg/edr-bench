"""Parse MockNet traffic.jsonl for content-level ground truth."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from edr_bench.models.enums import GroundTruthSource
from edr_bench.models.ground_truth import GroundTruthEvent

logger = structlog.get_logger(__name__)

# Site -> destination type mapping
_DESTINATION_TYPES: dict[str, str] = {
    "chatgpt.com": "ai_service",
    "drive.google.com": "personal_cloud",
    "docs.google.com": "personal_cloud",
    "mail.google.com": "personal_email",
    "gmail.com": "personal_email",
    "slack.com": "messaging",
    "app.slack.com": "messaging",
    "web.whatsapp.com": "messaging",
    "telegram.org": "messaging",
    "discord.com": "messaging",
    "linkedin.com": "social_media",
    "indeed.com": "job_site",
    "github.com": "code_repository",
    "webtransfer.com": "file_sharing",
    "wetransfer.com": "file_sharing",
    "zoom.us": "video_conferencing",
    "accounts.google.com": "oauth_provider",
    "addons.mozilla.org": "extension_store",
    "chrome.google.com": "extension_store",
    "banking.example.com": "banking",
    "banking-portal.example.com": "banking",
    "okta.example.com": "identity_provider",
    "shadowy-saas-tool.com": "shadow_saas",
    "salesforce.com": "corporate_crm",
    "phishing.example.com": "phishing",
    "mail.company.com": "corporate_email",
    "app.company.com": "corporate_portal",
}

# Keywords that indicate sensitive content
_CLASSIFICATION_KEYWORDS: dict[str, list[str]] = {
    "pii": [
        "customer", "ssn", "social_security", "phone", "address",
        "email", "name", "dob", "date_of_birth",
    ],
    "credentials": [
        "password", "api_key", "secret", "token", "credential",
        "ssh_key", "private_key", "access_key",
    ],
    "financial": [
        "revenue", "salary", "balance", "payment", "wire_transfer",
        "account_number", "routing",
    ],
    "proprietary_code": [
        "source_code", "proprietary", "import ", "def ", "class ",
        "function", "algorithm",
    ],
    "internal_docs": [
        "confidential", "internal", "nda", "acquisition", "merger", "board",
    ],
}


class MockNetParser:
    """Parse MockNet traffic.jsonl for content-level ground truth."""

    def parse_for_scenario(
        self,
        traffic_log_path: Path,
        scenario_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> list[GroundTruthEvent]:
        """Read the JSONL traffic log and return events within the time window.

        Parameters
        ----------
        traffic_log_path:
            Path to the ``traffic.jsonl`` file produced by MockNet.
        scenario_id:
            Identifier of the scenario being executed.
        start_time:
            Start of the collection window (inclusive).
        end_time:
            End of the collection window (inclusive).
        """
        events: list[GroundTruthEvent] = []
        path = Path(traffic_log_path)

        if not path.exists():
            logger.warning("mocknet_parser.file_not_found", path=str(path))
            return events

        with path.open("r") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry: dict[str, Any] = json.loads(line)
                except json.JSONDecodeError:
                    logger.debug(
                        "mocknet_parser.invalid_json",
                        path=str(path),
                        line_no=line_no,
                    )
                    continue

                # Filter by time window
                ts = _parse_timestamp(entry.get("timestamp"))
                if ts < start_time or ts > end_time:
                    continue

                event = self._entry_to_event(entry, scenario_id=scenario_id, timestamp=ts)
                if event is not None:
                    events.append(event)

        logger.info(
            "mocknet_parser.parsed",
            path=str(path),
            scenario_id=scenario_id,
            events=len(events),
        )
        return events

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _entry_to_event(
        self,
        entry: dict[str, Any],
        *,
        scenario_id: str,
        timestamp: datetime,
    ) -> GroundTruthEvent | None:
        """Convert a single MockNet JSON entry to a GroundTruthEvent."""
        try:
            site: str = entry.get("site") or entry.get("host") or ""
            endpoint: str = entry.get("endpoint", "")
            action: str = entry.get("action", "")
            data: dict[str, Any] = entry.get("data") or {}
            uploaded_files: list[dict[str, Any]] = entry.get("uploaded_files") or []
            content_length: int | None = entry.get("content_length")
            user_agent: str = entry.get("user_agent", "")

            # Derive event_type from the endpoint
            event_type = self._derive_event_type(endpoint, action)

            # Classify content
            classification, summary = self._classify_content(data, uploaded_files)

            # Destination type
            destination_type = self._get_destination_type(site)

            # Data volume: prefer explicit content_length, fall back to summing
            # uploaded file sizes
            data_volume: int | None = None
            if content_length is not None:
                data_volume = int(content_length)
            elif uploaded_files:
                total = sum(f.get("size", 0) for f in uploaded_files)
                if total > 0:
                    data_volume = total

            # Source app heuristic from user_agent
            source_app = self._guess_source_app(user_agent)

            return GroundTruthEvent(
                timestamp=timestamp,
                source=GroundTruthSource.MOCKNET,
                scenario_id=scenario_id,
                event_type=event_type,
                http_method=entry.get("method", "POST"),
                http_url=f"https://{site}{endpoint}" if site else endpoint,
                network_dst=site or None,
                content_summary=summary,
                data_classification=classification,
                data_volume_bytes=data_volume,
                source_app=source_app,
                destination_type=destination_type,
                destination_site=site or None,
                action_type=action or None,
                details=entry,
            )
        except Exception:
            logger.exception("mocknet_parser.event_conversion_error")
            return None

    @staticmethod
    def _classify_content(
        data: dict[str, Any],
        uploaded_files: list[dict[str, Any]],
    ) -> tuple[str | None, str | None]:
        """Scan data dict and file info for classification keywords.

        Returns
        -------
        (classification, summary) -- both may be ``None`` if nothing matches.
        """
        # Build a single searchable blob from all data values
        text_parts: list[str] = []
        for value in data.values():
            text_parts.append(str(value).lower())
        for file_info in uploaded_files:
            text_parts.append(str(file_info.get("filename", "")).lower())
            text_parts.append(str(file_info.get("content_type", "")).lower())
        blob = " ".join(text_parts)

        matched_classifications: list[str] = []
        matched_keywords: list[str] = []

        for classification, keywords in _CLASSIFICATION_KEYWORDS.items():
            for kw in keywords:
                if kw in blob:
                    if classification not in matched_classifications:
                        matched_classifications.append(classification)
                    matched_keywords.append(kw)

        if not matched_classifications:
            return None, None

        # Use the first (highest-priority) classification
        primary = matched_classifications[0]
        unique_keywords = list(dict.fromkeys(matched_keywords))  # dedupe preserving order
        summary = f"{primary}: matched keywords [{', '.join(unique_keywords[:5])}]"
        return primary, summary

    @staticmethod
    def _get_destination_type(site: str) -> str | None:
        """Look up the destination type for a site.

        Falls back to checking whether the site is a subdomain of a known
        entry (e.g. ``foo.slack.com`` matches ``slack.com``).
        """
        if not site:
            return None

        # Direct lookup
        if site in _DESTINATION_TYPES:
            return _DESTINATION_TYPES[site]

        # Subdomain fallback: try progressively shorter domain suffixes
        parts = site.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in _DESTINATION_TYPES:
                return _DESTINATION_TYPES[parent]

        return "external"

    @staticmethod
    def _derive_event_type(endpoint: str, action: str) -> str:
        """Map endpoint/action to a human-readable event type."""
        if action:
            return f"mocknet_{action}"
        endpoint_map: dict[str, str] = {
            "/api/capture": "mocknet_capture",
            "/api/send": "mocknet_send",
            "/api/login": "mocknet_login",
            "/upload": "mocknet_upload",
        }
        return endpoint_map.get(endpoint, "mocknet_request")

    @staticmethod
    def _guess_source_app(user_agent: str) -> str | None:
        """Best-effort extraction of source application from User-Agent."""
        ua = user_agent.lower()
        if "firefox" in ua:
            return "firefox"
        if "chrome" in ua and "edg" not in ua:
            return "chrome"
        if "edg" in ua:
            return "edge"
        if "safari" in ua and "chrome" not in ua:
            return "safari"
        if "curl" in ua:
            return "curl"
        if "python" in ua:
            return "python"
        if "wget" in ua:
            return "wget"
        return None


def _parse_timestamp(value: Any) -> datetime:
    """Best-effort timestamp parsing."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
    return datetime.now(tz=timezone.utc)
