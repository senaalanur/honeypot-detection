import asyncpg

from src.core.events import AttackEvent
from src.core.logging import get_logger

logger = get_logger(__name__)

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS attack_events (
    event_id        UUID PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL,
    source_ip       TEXT NOT NULL,
    source_port     INTEGER NOT NULL,
    target_service  TEXT NOT NULL,
    attack_type     TEXT NOT NULL,
    severity        TEXT NOT NULL,
    threat_score    FLOAT NOT NULL,
    summary         TEXT,
    attacker_intent TEXT,
    iocs            TEXT[],
    deception_response TEXT,
    country         TEXT,
    city            TEXT,
    raw_payload     TEXT
);

CREATE INDEX IF NOT EXISTS idx_attack_events_timestamp ON attack_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_attack_events_source_ip ON attack_events (source_ip);
CREATE INDEX IF NOT EXISTS idx_attack_events_severity  ON attack_events (severity);
"""


class PostgresStorage:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        self._pool = await asyncpg.create_pool(self._dsn, min_size=2, max_size=10)
        async with self._pool.acquire() as conn:
            await conn.execute(CREATE_TABLE_SQL)
        logger.info("postgres_connected")

    async def disconnect(self) -> None:
        if self._pool:
            await self._pool.close()
            logger.info("postgres_disconnected")

    async def save_event(self, event: AttackEvent) -> None:
        if not self._pool:
            raise RuntimeError("Not connected — call connect() first")

        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO attack_events (
                    event_id, timestamp, source_ip, source_port,
                    target_service, attack_type, severity, threat_score,
                    summary, attacker_intent, iocs, deception_response,
                    country, city, raw_payload
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8,
                    $9, $10, $11, $12, $13, $14, $15
                )
                ON CONFLICT (event_id) DO NOTHING
                """,
                event.event_id,
                event.timestamp,
                event.source_ip,
                event.source_port,
                event.target_service,
                event.attack_type.value,
                event.severity.value,
                event.threat_score,
                event.summary,
                event.attacker_intent,
                event.iocs,
                event.deception_response,
                event.country,
                event.city,
                event.raw_payload[:5000],
            )

        logger.info(
            "event_saved_postgres",
            event_id=str(event.event_id),
            severity=event.severity,
        )

    async def get_recent_events(self, limit: int = 100) -> list[dict]:
        if not self._pool:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT event_id, timestamp, source_ip, target_service,
                       attack_type, severity, threat_score, summary,
                       attacker_intent, iocs, country, city
                FROM attack_events
                ORDER BY timestamp DESC
                LIMIT $1
                """,
                limit,
            )
        return [dict(row) for row in rows]

    async def get_stats(self) -> dict:
        if not self._pool:
            return {}
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT
                    COUNT(*)                                         AS total_events,
                    COUNT(DISTINCT source_ip)                        AS unique_attackers,
                    AVG(threat_score)                                AS avg_threat_score,
                    COUNT(*) FILTER (WHERE severity = 'critical')   AS critical_count,
                    COUNT(*) FILTER (WHERE severity = 'high')        AS high_count,
                    COUNT(*) FILTER (WHERE severity = 'medium')      AS medium_count,
                    COUNT(*) FILTER (WHERE severity = 'low')         AS low_count
                FROM attack_events
                WHERE timestamp > NOW() - INTERVAL '24 hours'
                """
            )
        return dict(row) if row else {}