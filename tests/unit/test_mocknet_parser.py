"""Tests for MockNetParser."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from edr_bench.ground_truth.mocknet_parser import MockNetParser


@pytest.fixture
def parser() -> MockNetParser:
    return MockNetParser()


def _write_jsonl(path: Path, entries: list[dict]) -> None:
    with path.open("w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


def _make_entry(
    ts: datetime,
    site: str = "chatgpt.com",
    endpoint: str = "/api/capture",
    action: str = "",
    data: dict | None = None,
) -> dict:
    return {
        "timestamp": ts.isoformat(),
        "site": site,
        "endpoint": endpoint,
        "action": action,
        "data": data or {},
        "user_agent": "Mozilla/5.0 Firefox/120.0",
    }


@pytest.mark.unit
class TestParseForScenario:
    def test_valid_jsonl(self, parser: MockNetParser, tmp_path: Path):
        ts = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        entries = [_make_entry(ts, data={"message": "customer SSN data"})]
        log = tmp_path / "traffic.jsonl"
        _write_jsonl(log, entries)

        events = parser.parse_for_scenario(
            log, "COACH-001", ts - timedelta(minutes=1), ts + timedelta(minutes=1)
        )
        assert len(events) == 1
        assert events[0].scenario_id == "COACH-001"
        assert events[0].source == "mocknet"

    def test_filters_by_time_window(self, parser: MockNetParser, tmp_path: Path):
        ts_in = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        ts_out = datetime(2024, 6, 15, 14, 0, 0, tzinfo=timezone.utc)
        entries = [_make_entry(ts_in), _make_entry(ts_out)]
        log = tmp_path / "traffic.jsonl"
        _write_jsonl(log, entries)

        events = parser.parse_for_scenario(
            log, "T1", ts_in - timedelta(seconds=1), ts_in + timedelta(seconds=1)
        )
        assert len(events) == 1

    def test_empty_file(self, parser: MockNetParser, tmp_path: Path):
        log = tmp_path / "traffic.jsonl"
        log.write_text("")
        events = parser.parse_for_scenario(
            log, "T1",
            datetime(2024, 1, 1, tzinfo=timezone.utc),
            datetime(2024, 12, 31, tzinfo=timezone.utc),
        )
        assert events == []

    def test_nonexistent_file(self, parser: MockNetParser, tmp_path: Path):
        log = tmp_path / "does_not_exist.jsonl"
        events = parser.parse_for_scenario(
            log, "T1",
            datetime(2024, 1, 1, tzinfo=timezone.utc),
            datetime(2024, 12, 31, tzinfo=timezone.utc),
        )
        assert events == []

    def test_malformed_json_lines_skipped(self, parser: MockNetParser, tmp_path: Path):
        ts = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        log = tmp_path / "traffic.jsonl"
        with log.open("w") as f:
            f.write("not valid json\n")
            f.write(json.dumps(_make_entry(ts)) + "\n")
            f.write("{broken json\n")

        events = parser.parse_for_scenario(
            log, "T1", ts - timedelta(minutes=1), ts + timedelta(minutes=1)
        )
        assert len(events) == 1


@pytest.mark.unit
class TestClassifyContent:
    def test_detects_pii(self):
        classification, summary = MockNetParser._classify_content(
            {"field": "customer SSN data"}, []
        )
        assert classification == "pii"
        assert summary is not None
        assert "customer" in summary

    def test_detects_credentials(self):
        classification, _ = MockNetParser._classify_content(
            {"field": "api_key=sk_test_FAKE123"}, []
        )
        assert classification == "credentials"

    def test_no_match_returns_none(self):
        classification, summary = MockNetParser._classify_content(
            {"field": "hello world"}, []
        )
        assert classification is None
        assert summary is None

    def test_uploaded_files_classified(self):
        classification, _ = MockNetParser._classify_content(
            {}, [{"filename": "customer_records.csv", "content_type": "text/csv"}]
        )
        assert classification == "pii"


@pytest.mark.unit
class TestGetDestinationType:
    def test_known_domain(self):
        assert MockNetParser._get_destination_type("drive.google.com") == "personal_cloud"
        assert MockNetParser._get_destination_type("slack.com") == "messaging"
        assert MockNetParser._get_destination_type("github.com") == "code_repository"

    def test_subdomain_fallback(self):
        assert MockNetParser._get_destination_type("foo.slack.com") == "messaging"

    def test_unknown_domain(self):
        assert MockNetParser._get_destination_type("random-site.example.org") == "external"

    def test_empty_string(self):
        assert MockNetParser._get_destination_type("") is None


@pytest.mark.unit
class TestDeriveEventType:
    def test_with_action(self):
        assert MockNetParser._derive_event_type("/api/capture", "paste_text") == "mocknet_paste_text"

    def test_endpoint_mapping(self):
        assert MockNetParser._derive_event_type("/api/capture", "") == "mocknet_capture"
        assert MockNetParser._derive_event_type("/api/send", "") == "mocknet_send"
        assert MockNetParser._derive_event_type("/api/login", "") == "mocknet_login"
        assert MockNetParser._derive_event_type("/upload", "") == "mocknet_upload"

    def test_unknown_endpoint(self):
        assert MockNetParser._derive_event_type("/api/unknown", "") == "mocknet_request"


@pytest.mark.unit
class TestGuessSourceApp:
    def test_firefox(self):
        assert MockNetParser._guess_source_app("Mozilla/5.0 Firefox/120.0") == "firefox"

    def test_curl(self):
        assert MockNetParser._guess_source_app("curl/7.88.1") == "curl"

    def test_python(self):
        assert MockNetParser._guess_source_app("python-requests/2.31.0") == "python"

    def test_unknown(self):
        assert MockNetParser._guess_source_app("SomeObscureAgent/1.0") is None
