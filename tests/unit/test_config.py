import pytest

from src.core.config import Environment, Settings
from src.core.events import AttackEvent, AttackType, Severity


class TestSettings:
    def test_rejects_empty_api_key(self) -> None:
        with pytest.raises(Exception):
            Settings(anthropic_api_key="")

    def test_defaults_are_sane(self) -> None:
        settings = Settings(anthropic_api_key="sk-ant-test")
        assert settings.environment == Environment.DEVELOPMENT
        assert settings.ssh_port == 2222
        assert settings.ai_min_severity_to_alert == 7


class TestAttackEvent:
    def test_json_roundtrip(self) -> None:
        event = AttackEvent(
            source_ip="192.168.1.1",
            source_port=54321,
            target_service="ssh",
            raw_payload="SSH-2.0-OpenSSH_7.4",
        )
        restored = AttackEvent.from_json(event.to_json())
        assert restored.event_id == event.event_id
        assert restored.source_ip == event.source_ip
        assert restored.timestamp == event.timestamp

    def test_default_severity_is_low(self) -> None:
        event = AttackEvent(
            source_ip="10.0.0.1",
            source_port=22,
            target_service="ssh",
            raw_payload="test",
        )
        assert event.severity == Severity.LOW
        assert event.attack_type == AttackType.UNKNOWN