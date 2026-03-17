import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

import redis.asyncio as aioredis

from src.core.config import get_settings
from src.core.logging import get_logger

logger = get_logger(__name__)


class AttackType(StrEnum):
    SSH_BRUTE_FORCE = "ssh_brute_force"
    SSH_COMMAND_EXEC = "ssh_command_exec"
    HTTP_SCAN = "http_scan"
    HTTP_EXPLOIT = "http_exploit"
    FTP_BRUTE_FORCE = "ftp_brute_force"
    PORT_SCAN = "port_scan"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AttackEvent:
    source_ip: str
    source_port: int
    target_service: str
    raw_payload: str

    attack_type: AttackType = AttackType.UNKNOWN
    severity: Severity = Severity.LOW
    threat_score: float = 0.0
    summary: str = ""
    iocs: list[str] = field(default_factory=list)
    attacker_intent: str = ""
    deception_response: str = ""

    event_id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    country: str = ""
    city: str = ""

    def to_json(self) -> str:
        data = asdict(self)
        data["event_id"] = str(data["event_id"])
        data["timestamp"] = data["timestamp"].isoformat()
        return json.dumps(data)

    @classmethod
    def from_json(cls, raw: str) -> "AttackEvent":
        data = json.loads(raw)
        data["event_id"] = UUID(data["event_id"])
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        data["attack_type"] = AttackType(data["attack_type"])
        data["severity"] = Severity(data["severity"])
        return cls(**data)


class EventBus:
    def __init__(self, redis_client: aioredis.Redis) -> None:
        self._redis = redis_client
        self._channel = get_settings().redis_event_channel

    async def publish(self, event: AttackEvent) -> None:
        await self._redis.publish(self._channel, event.to_json())
        logger.info(
            "event_published",
            event_id=str(event.event_id),
            source_ip=event.source_ip,
            service=event.target_service,
        )

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[aioredis.client.PubSub]:
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(self._channel)
        try:
            yield pubsub
        finally:
            await pubsub.unsubscribe(self._channel)
            await pubsub.aclose()


async def create_redis_client() -> aioredis.Redis:
    settings = get_settings()
    return aioredis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
    )