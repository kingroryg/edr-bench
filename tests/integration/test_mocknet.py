"""Integration tests for MockNet service.

These tests need the mocknet container running.
"""

from __future__ import annotations

import pytest
import httpx


MOCKNET_URL = "http://172.28.2.10"


@pytest.mark.integration
class TestMockNet:
    async def test_health_endpoint(self):
        """MockNet should respond to health checks."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{MOCKNET_URL}/api/health")
            assert resp.status_code == 200

    async def test_login_endpoint_logs_credentials(self):
        """MockNet login endpoint should accept and log credentials."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{MOCKNET_URL}/api/login",
                json={"username": "test@example.com", "password": "testpass"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "token" in data

    async def test_data_endpoint(self):
        """MockNet data endpoint should accept POST data."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{MOCKNET_URL}/api/data",
                json={"exfil": "sensitive_data"},
            )
            assert resp.status_code == 200

    async def test_fake_site_chatgpt(self):
        """The fake ChatGPT site should serve an HTML page."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{MOCKNET_URL}/",
                headers={"Host": "chatgpt.com"},
            )
            assert resp.status_code == 200
            assert "html" in resp.text.lower()

    async def test_fake_site_salesforce(self):
        """The fake Salesforce site should serve an HTML page."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{MOCKNET_URL}/",
                headers={"Host": "salesforce.com"},
            )
            assert resp.status_code == 200
            assert "html" in resp.text.lower()
