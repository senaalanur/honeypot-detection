import asyncio
import json
from datetime import UTC, datetime

import aiosmtplib
import httpx
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from src.core.config import get_settings
from src.core.events import AttackEvent, Severity
from src.core.logging import get_logger

logger = get_logger(__name__)

# Severity levels that trigger alerts
ALERT_SEVERITIES = {Severity.HIGH, Severity.CRITICAL}


class AlertManager:
    """
    Sends alerts via Slack webhook and/or Gmail when high-severity
    events are detected. Rate-limited to avoid notification spam.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._last_alert: dict[str, datetime] = {}
        self._cooldown_seconds = 300  # 5 min cooldown per source IP

    def _is_rate_limited(self, source_ip: str) -> bool:
        last = self._last_alert.get(source_ip)
        if not last:
            return False
        elapsed = (datetime.now(UTC) - last).total_seconds()
        return elapsed < self._cooldown_seconds

    def _mark_alerted(self, source_ip: str) -> None:
        self._last_alert[source_ip] = datetime.now(UTC)

    async def handle_event(self, event: AttackEvent) -> None:
        """Called for every enriched event — only alerts on high/critical."""
        if event.severity not in ALERT_SEVERITIES:
            return

        if event.threat_score < self._settings.ai_min_severity_to_alert:
            return

        if self._is_rate_limited(event.source_ip):
            logger.info(
                "alert_rate_limited",
                source_ip=event.source_ip,
            )
            return

        self._mark_alerted(event.source_ip)

        # Fire both alert channels concurrently
        await asyncio.gather(
            self._send_slack(event),
            self._send_email(event),
            return_exceptions=True,  # Never let an alert failure crash the pipeline
        )

    async def _send_slack(self, event: AttackEvent) -> None:
        if not self._settings.slack_webhook_url:
            return

        severity_emoji = {
            Severity.LOW: "🟢",
            Severity.MEDIUM: "🟡",
            Severity.HIGH: "🔴",
            Severity.CRITICAL: "🚨",
        }

        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{severity_emoji[event.severity]} Honeypot Alert — {event.severity.value.upper()}",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Source IP:*\n{event.source_ip}"},
                        {"type": "mrkdwn", "text": f"*Service:*\n{event.target_service.upper()}"},
                        {"type": "mrkdwn", "text": f"*Attack Type:*\n{event.attack_type.value}"},
                        {"type": "mrkdwn", "text": f"*Threat Score:*\n{event.threat_score}/10"},
                        {"type": "mrkdwn", "text": f"*Intent:*\n{event.attacker_intent}"},
                        {"type": "mrkdwn", "text": f"*Location:*\n{event.city}, {event.country}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Summary:*\n{event.summary}"},
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*IOCs:*\n```{', '.join(event.iocs[:10])}```",
                    },
                },
            ]
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self._settings.slack_webhook_url,
                json=payload,
                timeout=10.0,
            )
            response.raise_for_status()

        logger.info("slack_alert_sent", event_id=str(event.event_id))

    async def _send_email(self, event: AttackEvent) -> None:
        if not all([
            self._settings.email_user,
            self._settings.email_password,
            self._settings.email_recipient,
        ]):
            return

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[Honeypot] {event.severity.value.upper()} — {event.attack_type.value} from {event.source_ip}"
        msg["From"] = self._settings.email_user
        msg["To"] = self._settings.email_recipient

        body = f"""
HONEYPOT SECURITY ALERT
=======================
Severity:     {event.severity.value.upper()}
Threat Score: {event.threat_score}/10
Timestamp:    {event.timestamp.isoformat()}

ATTACKER
--------
IP:       {event.source_ip}:{event.source_port}
Location: {event.city}, {event.country}
Intent:   {event.attacker_intent}

ATTACK
------
Service:     {event.target_service.upper()}
Attack Type: {event.attack_type.value}

SUMMARY
-------
{event.summary}

INDICATORS OF COMPROMISE
------------------------
{chr(10).join(f"  - {ioc}" for ioc in event.iocs)}

DECEPTION RESPONSE DEPLOYED
----------------------------
{event.deception_response}
        """.strip()

        msg.attach(MIMEText(body, "plain"))

        await aiosmtplib.send(
            msg,
            hostname="smtp.gmail.com",
            port=465,
            use_tls=True,
            username=self._settings.email_user,
            password=self._settings.email_password,
        )

        logger.info("email_alert_sent", event_id=str(event.event_id))