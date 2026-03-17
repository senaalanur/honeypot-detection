import json
import re

from anthropic import AsyncAnthropic

from src.core.config import get_settings
from src.core.events import AttackEvent, AttackType, Severity
from src.core.logging import get_logger

logger = get_logger(__name__)

SYSTEM_PROMPT = """You are an expert cybersecurity analyst embedded in a honeypot system.
Your job is to analyse raw attack data captured from honeypot services and produce
structured threat intelligence.

You must respond with valid JSON only — no markdown, no explanation, just the JSON object.

Your analysis must be precise, technical, and actionable. Think like a SOC analyst
who needs to triage this event and decide whether to escalate it."""

ANALYSIS_PROMPT = """Analyse this honeypot attack event and return a JSON object.

Service targeted: {service}
Source IP: {source_ip}
Raw captured data:
{raw_payload}

Return this exact JSON structure:
{{
    "attack_type": "<one of: ssh_brute_force, ssh_command_exec, http_scan, http_exploit, ftp_brute_force, port_scan, unknown>",
    "severity": "<one of: low, medium, high, critical>",
    "threat_score": <integer 1-10>,
    "summary": "<2-3 sentence technical summary of what the attacker did and why it matters>",
    "attacker_intent": "<one of: reconnaissance, credential_theft, data_exfiltration, backdoor_installation, cryptomining, ransomware, unknown>",
    "iocs": ["<list of extracted indicators: IPs, domains, usernames, commands, file paths, hashes>"],
    "ttps": ["<MITRE ATT&CK technique IDs if applicable, e.g. T1110.001>"],
    "deception_response": "<what fake data or misleading response we should show this attacker next to waste their time and gather more intelligence>",
    "recommended_action": "<one of: monitor, block, escalate, investigate>"
}}

Scoring guide:
- 1-3: Low — automated scan, no real threat
- 4-6: Medium — targeted attempt, some sophistication
- 7-9: High — successful auth, command execution, or data access
- 10: Critical — active exploitation, lateral movement, or data exfiltration"""


class AttackClassifier:
    def __init__(self) -> None:
        self._client = AsyncAnthropic(api_key=get_settings().anthropic_api_key)
        self._model = get_settings().ai_model

    async def analyse(self, event: AttackEvent) -> AttackEvent:
        """
        Runs the event through the AI pipeline and returns
        an enriched copy with all intelligence fields populated.
        """
        logger.info(
            "analysis_started",
            event_id=str(event.event_id),
            service=event.target_service,
            source_ip=event.source_ip,
        )

        try:
            prompt = ANALYSIS_PROMPT.format(
                service=event.target_service,
                source_ip=event.source_ip,
                raw_payload=event.raw_payload[:3000],  # Stay within context limits
            )

            message = await self._client.messages.create(
                model=self._model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )

            raw_response = message.content[0].text
            analysis = self._parse_response(raw_response)
            enriched = self._apply_analysis(event, analysis)

            logger.info(
                "analysis_complete",
                event_id=str(event.event_id),
                threat_score=enriched.threat_score,
                severity=enriched.severity,
                attack_type=enriched.attack_type,
                attacker_intent=enriched.attacker_intent,
            )

            return enriched

        except Exception as e:
            logger.error(
                "analysis_failed",
                event_id=str(event.event_id),
                error=str(e),
            )
            # Return the original event unmodified — never crash the pipeline
            return event

    def _parse_response(self, raw: str) -> dict:
        """Robustly parse JSON from the AI response."""
        # Strip any accidental markdown fences
        cleaned = re.sub(r"```(?:json)?\n?", "", raw).strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            # Try extracting just the JSON object if there's surrounding text
            match = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if match:
                return json.loads(match.group())
            logger.warning("ai_response_parse_failed", raw=raw[:200])
            return {}

    def _apply_analysis(self, event: AttackEvent, analysis: dict) -> AttackEvent:
        """Apply AI analysis results back onto the event dataclass."""
        if not analysis:
            return event

        # Safely map string values to enums with fallbacks
        try:
            attack_type = AttackType(analysis.get("attack_type", "unknown"))
        except ValueError:
            attack_type = AttackType.UNKNOWN

        try:
            severity = Severity(analysis.get("severity", "low"))
        except ValueError:
            severity = Severity.LOW

        threat_score = float(analysis.get("threat_score", 0))
        threat_score = max(0.0, min(10.0, threat_score))  # Clamp to 0-10

        from dataclasses import replace
        return replace(
            event,
            attack_type=attack_type,
            severity=severity,
            threat_score=threat_score,
            summary=analysis.get("summary", ""),
            attacker_intent=analysis.get("attacker_intent", "unknown"),
            iocs=analysis.get("iocs", []),
            deception_response=analysis.get("deception_response", ""),
        )