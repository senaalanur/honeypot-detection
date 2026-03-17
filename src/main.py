import asyncio

import redis.asyncio as aioredis
import uvicorn

from src.alerts.manager import AlertManager
from src.analysis.engine import AnalysisEngine, ENRICHED_CHANNEL
from src.api.routes import app, set_storage
from src.core.config import get_settings
from src.core.events import AttackEvent, EventBus, create_redis_client
from src.core.logging import configure_logging, get_logger
from src.honeypot.ftp import FTPHoneypot
from src.honeypot.http import HTTPHoneypot
from src.honeypot.ssh import SSHHoneypot
from src.storage.elasticsearch import ElasticsearchStorage
from src.storage.postgres import PostgresStorage

configure_logging()
logger = get_logger(__name__)


async def storage_and_alert_worker(
    redis_client: aioredis.Redis,
    postgres: PostgresStorage,
    es: ElasticsearchStorage,
    alert_manager: AlertManager,
) -> None:
    """
    Subscribes to the enriched events channel and fans out to
    PostgreSQL, Elasticsearch, and the alert manager concurrently.
    """
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(ENRICHED_CHANNEL)
    logger.info("storage_worker_started")

    async for message in pubsub.listen():
        if message["type"] != "message":
            continue
        try:
            event = AttackEvent.from_json(message["data"])
            await asyncio.gather(
                postgres.save_event(event),
                es.save_event(event),
                alert_manager.handle_event(event),
                return_exceptions=True,
            )
        except Exception as e:
            logger.error("storage_worker_error", error=str(e))


async def main() -> None:
    settings = get_settings()
    logger.info("honeypot_starting", environment=settings.environment)

    # Storage
    postgres = PostgresStorage(settings.postgres_dsn)
    es = ElasticsearchStorage(settings.elasticsearch_url, settings.elasticsearch_index)
    await postgres.connect()
    await es.connect()
    set_storage(postgres, es)

    # Event bus
    redis_client = await create_redis_client()
    event_bus = EventBus(redis_client)

    # Services
    alert_manager = AlertManager()
    analysis_engine = AnalysisEngine(event_bus, redis_client)

    ssh  = SSHHoneypot("0.0.0.0", settings.ssh_port, event_bus)
    http = HTTPHoneypot("0.0.0.0", settings.http_port, event_bus)
    ftp  = FTPHoneypot("0.0.0.0", settings.ftp_port, event_bus)

    await asyncio.gather(ssh.start(), http.start(), ftp.start())

    logger.info(
        "honeypot_ready",
        ssh_port=settings.ssh_port,
        http_port=settings.http_port,
        ftp_port=settings.ftp_port,
    )

    # Run everything concurrently
    api_config = uvicorn.Config(app, host="0.0.0.0", port=8000, log_level="warning")
    api_server = uvicorn.Server(api_config)

    try:
        await asyncio.gather(
            analysis_engine.run(),
            storage_and_alert_worker(redis_client, postgres, es, alert_manager),
            api_server.serve(),
        )
    except KeyboardInterrupt:
        logger.info("honeypot_stopping")
    finally:
        await asyncio.gather(ssh.stop(), http.stop(), ftp.stop())
        await postgres.disconnect()
        await es.disconnect()
        await redis_client.aclose()
        logger.info("honeypot_stopped")


if __name__ == "__main__":
    asyncio.run(main())