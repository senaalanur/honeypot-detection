import asyncio

from src.core.config import get_settings
from src.core.logging import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)


async def main() -> None:
    settings = get_settings()
    logger.info(
        "honeypot_starting",
        environment=settings.environment,
        ssh_port=settings.ssh_port,
        http_port=settings.http_port,
    )

    try:
        logger.info("honeypot_ready")
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logger.info("honeypot_stopping")


if __name__ == "__main__":
    asyncio.run(main())