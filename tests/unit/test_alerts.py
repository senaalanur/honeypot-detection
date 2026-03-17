from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from src.alerts.manager import AlertManager
from src.core.events import AttackEvent, AttackType, Severity


def make_event(severity: Severity, threat_score: float) -> AttackEvent:
    return AttackEvent(
        source_ip="185.220.101.45",
        source_port=54321,
        target_service="ssh",
        raw_payload="test",
        attack_type=AttackType.SSH_BRUTE_FORCE,
        severity=severity,
        threat_score=threat_score,
        summary="Test attack",
        attacker_intent="credential_theft",
        iocs=["root", "admin"],
        deception_response="Fake response",
    )


class TestAlertManager:
    def _make_manager(self) -> AlertManager:
        with patch("src.alerts.manager.get_settings") as mock:
            mock.return_value = MagicMock(
                slack_webhook_url="https://hooks.slack.com/test",
                email_user="",
                email_password="",
                email_recipient="",
                ai_min_severity_to_alert=7,
            )
            return AlertManager()

    async def test_ignores_low_severity(self) -> None:
        manager = self._make_manager()
        event = make_event(Severity.LOW, threat_score=3.0)
        with patch.object(manager, "_send_slack", new_callable=AsyncMock) as mock_slack:
            await manager.handle_event(event)
            mock_slack.assert_not_called()

    async def test_ignores_below_threshold(self) -> None:
        manager = self._make_manager()
        event = make_event(Severity.HIGH, threat_score=5.0)
        with patch.object(manager, "_send_slack", new_callable=AsyncMock) as mock_slack:
            await manager.handle_event(event)
            mock_slack.assert_not_called()

    async def test_alerts_on_high_severity(self) -> None:
        manager = self._make_manager()
        event = make_event(Severity.HIGH, threat_score=8.0)
        with patch.object(manager, "_send_slack", new_callable=AsyncMock) as mock_slack:
            await manager.handle_event(event)
            mock_slack.assert_called_once()

    async def test_rate_limits_same_ip(self) -> None:
        manager = self._make_manager()
        event = make_event(Severity.HIGH, threat_score=8.0)
        with patch.object(manager, "_send_slack", new_callable=AsyncMock) as mock_slack:
            await manager.handle_event(event)
            await manager.handle_event(event)  # Same IP, should be suppressed
            mock_slack.assert_called_once()  # Only once despite two events