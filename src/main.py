import asyncio

import redis.asyncio as aioredis

from src.core.config import get_settings
from src.core.events import EventBus, create_redis_client
from src.core.logging import configure_logging, get_logger
from src.honeypot.ftp import FTPHoneypot
from src.honeypot.http import HTTPHoneypot
from src.honeypot.ssh import SSHHoneypot

configure_logging()
logger = get_logger(__name__)


async def main() -> None:
    settings = get_settings()
    logger.info(
        "honeypot_starting",
        environment=settings.environment,
        ssh_port=settings.ssh_port,
        http_port=settings.http_port,
        ftp_port=settings.ftp_port,
    )

    redis_client = await create_redis_client()
    event_bus = EventBus(redis_client)

    ssh = SSHHoneypot("0.0.0.0", settings.ssh_port, event_bus)
    http = HTTPHoneypot("0.0.0.0", settings.http_port, event_bus)
    ftp = FTPHoneypot("0.0.0.0", settings.ftp_port, event_bus)

    await asyncio.gather(
        ssh.start(),
        http.start(),
        ftp.start(),
    )

    logger.info(
        "honeypot_ready",
        ssh_port=settings.ssh_port,
        http_port=settings.http_port,
        ftp_port=settings.ftp_port,
    )

    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logger.info("honeypot_stopping")
    finally:
        await asyncio.gather(
            ssh.stop(),
            http.stop(),
            ftp.stop(),
        )
        await redis_client.aclose()
        logger.info("honeypot_stopped")


if __name__ == "__main__":
    asyncio.run(main())