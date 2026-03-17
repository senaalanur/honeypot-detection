import asyncio

import redis.asyncio as aioredis

from src.analysis.classifier import AttackClassifier
from src.core.events import AttackEvent, EventBus
from src.core.logging import get_logger

logger = get_logger(__name__)

ENRICHED_CHANNEL = "honeypot:enriched"


class AnalysisEngine:
    """
    Subscribes to raw attack events, runs each through the AI classifier,
    and publishes enriched events to a separate channel for downstream consumers.
    """

    def __init__(self, event_bus: EventBus, redis_client: aioredis.Redis) -> None:
        self._event_bus = event_bus
        self._redis = redis_client
        self._classifier = AttackClassifier()
        self._running = False

    async def run(self) -> None:
        self._running = True
        logger.info("analysis_engine_started")

        async with self._event_bus.subscribe() as pubsub:
            async for message in pubsub.listen():
                if not self._running:
                    break

                if message["type"] != "message":
                    continue

                try:
                    raw_event = AttackEvent.from_json(message["data"])
                    enriched = await self._classifier.analyse(raw_event)
                    await self._publish_enriched(enriched)
                except Exception as e:
                    logger.error("engine_processing_error", error=str(e))

    async def _publish_enriched(self, event: AttackEvent) -> None:
        """Publish enriched event to a separate channel for storage + alerts."""
        await self._redis.publish(ENRICHED_CHANNEL, event.to_json())
        logger.info(
            "enriched_event_published",
            event_id=str(event.event_id),
            threat_score=event.threat_score,
            severity=event.severity,
        )

    def stop(self) -> None:
        self._running = False
        logger.info("analysis_engine_stopping")