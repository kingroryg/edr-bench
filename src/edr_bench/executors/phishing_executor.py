"""GoPhish-based phishing campaign executor."""

from __future__ import annotations

import json

import httpx
import structlog

from edr_bench.config.settings import Settings
from edr_bench.executors.base import AttackExecutor
from edr_bench.models import Scenario, SimulationStep

logger = structlog.get_logger(__name__)


class PhishingExecutor(AttackExecutor):
    """Integrates with the GoPhish API to create and launch phishing campaigns.

    The step command is expected to contain a JSON object with the campaign
    configuration, including keys such as ``smtp_host``, ``smtp_from``,
    ``template_name``, ``template_subject``, ``template_html``,
    ``page_name``, ``page_html``, ``campaign_name``, ``groups``, and
    ``url``.
    """

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.api_key: str = getattr(settings.gophish, "api_key", "")
        self.admin_url: str = getattr(settings.gophish, "admin_url", "")

    async def execute(self, step: SimulationStep, scenario: Scenario) -> None:
        config = json.loads(step.command)

        log = logger.bind(
            step_order=step.order,
            scenario_id=scenario.id,
            campaign_name=config.get("campaign_name", "unnamed"),
        )
        log.info("phishing_executor_starting")

        base_url = self.admin_url.rstrip("/")
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            verify=False,
            timeout=httpx.Timeout(30.0),
        ) as client:
            # Step 1: Create a sending profile (SMTP configuration).
            smtp_payload = {
                "name": f"edr-bench-smtp-{scenario.id}-{step.order}",
                "host": config.get("smtp_host", "localhost:25"),
                "from_address": config.get("smtp_from", "attacker@example.com"),
                "ignore_cert_errors": True,
            }
            log.debug("phishing_creating_smtp_profile", payload=smtp_payload)
            smtp_response = await client.post("/api/smtp/", json=smtp_payload)
            smtp_response.raise_for_status()
            smtp_profile = smtp_response.json()
            smtp_id: int = smtp_profile["id"]
            log.info("phishing_smtp_profile_created", smtp_id=smtp_id)

            # Step 2: Create an email template.
            template_payload = {
                "name": config.get(
                    "template_name",
                    f"edr-bench-template-{scenario.id}-{step.order}",
                ),
                "subject": config.get("template_subject", "Important Update"),
                "html": config.get(
                    "template_html",
                    "<html><body><p>Please click {{.URL}}</p></body></html>",
                ),
            }
            log.debug("phishing_creating_template", name=template_payload["name"])
            template_response = await client.post(
                "/api/templates/", json=template_payload
            )
            template_response.raise_for_status()
            template = template_response.json()
            template_id: int = template["id"]
            log.info("phishing_template_created", template_id=template_id)

            # Step 3: Create a landing page.
            page_payload = {
                "name": config.get(
                    "page_name",
                    f"edr-bench-page-{scenario.id}-{step.order}",
                ),
                "html": config.get(
                    "page_html",
                    "<html><body><h1>Landing Page</h1></body></html>",
                ),
                "capture_credentials": config.get("capture_credentials", True),
                "capture_passwords": config.get("capture_passwords", False),
            }
            log.debug("phishing_creating_page", name=page_payload["name"])
            page_response = await client.post("/api/pages/", json=page_payload)
            page_response.raise_for_status()
            page = page_response.json()
            page_id: int = page["id"]
            log.info("phishing_page_created", page_id=page_id)

            # Step 4: Create and launch the campaign.
            campaign_payload = {
                "name": config.get(
                    "campaign_name",
                    f"edr-bench-campaign-{scenario.id}-{step.order}",
                ),
                "template": {"id": template_id},
                "page": {"id": page_id},
                "smtp": {"id": smtp_id},
                "url": config.get("url", f"{base_url}"),
                "groups": [
                    {"name": group_name}
                    for group_name in config.get("groups", [])
                ],
            }
            log.debug("phishing_creating_campaign", name=campaign_payload["name"])
            campaign_response = await client.post(
                "/api/campaigns/", json=campaign_payload
            )
            campaign_response.raise_for_status()
            campaign = campaign_response.json()
            campaign_id: int = campaign["id"]
            log.info(
                "phishing_campaign_launched",
                campaign_id=campaign_id,
                status=campaign.get("status"),
            )

    async def validate(self, step: SimulationStep) -> list[str]:
        errors: list[str] = []

        if not self.api_key:
            errors.append("GoPhish API key is not configured.")

        if not self.admin_url:
            errors.append("GoPhish admin URL is not configured.")

        if not step.command:
            errors.append(
                "Step command must contain a JSON configuration for the "
                "phishing campaign."
            )
        else:
            try:
                config = json.loads(step.command)
                if not isinstance(config, dict):
                    errors.append(
                        "Step command JSON must be an object, "
                        f"got {type(config).__name__}."
                    )
            except json.JSONDecodeError as exc:
                errors.append(
                    f"Step command is not valid JSON: {exc}"
                )

        return errors
