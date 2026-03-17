import asyncio

from src.core.events import AttackEvent, AttackType, EventBus
from src.core.logging import get_logger

logger = get_logger(__name__)

FTP_BANNER = b"220 FTP server ready\r\n"
FTP_RESPONSES: dict[str, bytes] = {
    "USER": b"331 Password required\r\n",
    "PASS": b"230 Login successful\r\n",
    "PWD":  b'257 "/" is current directory\r\n',
    "LIST": b"150 Here comes the directory listing.\r\ndrwxr-xr-x backup\r\ndrwxr-xr-x data\r\n226 Directory send OK.\r\n",
    "SYST": b"215 UNIX Type: L8\r\n",
    "FEAT": b"211-Features:\r\n PASV\r\n211 End\r\n",
    "QUIT": b"221 Goodbye\r\n",
}
DEFAULT_FTP_RESPONSE = b"200 OK\r\n"


class FTPHoneypot:
    def __init__(self, host: str, port: int, event_bus: EventBus) -> None:
        self.host = host
        self.port = port
        self.event_bus = event_bus
        self._server: asyncio.Server | None = None

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "unknown"
        source_port = peer[1] if peer else 0

        logger.info("ftp_connection", source_ip=source_ip)
        session_data: list[str] = []

        try:
            writer.write(FTP_BANNER)
            await writer.drain()

            deadline = asyncio.get_event_loop().time() + 60.0
            while asyncio.get_event_loop().time() < deadline:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=30.0)
                    if not line:
                        break

                    command_line = line.decode("utf-8", errors="ignore").strip()
                    if not command_line:
                        continue

                    session_data.append(command_line)
                    command = command_line.split()[0].upper()

                    logger.info(
                        "ftp_command",
                        source_ip=source_ip,
                        command=command_line,
                    )

                    response = FTP_RESPONSES.get(command, DEFAULT_FTP_RESPONSE)
                    writer.write(response)
                    await writer.drain()

                    if command == "QUIT":
                        break

                except asyncio.TimeoutError:
                    break

            event = AttackEvent(
                source_ip=source_ip,
                source_port=source_port,
                target_service="ftp",
                raw_payload="\n".join(session_data),
                attack_type=AttackType.FTP_BRUTE_FORCE,
            )
            await self.event_bus.publish(event)

        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            logger.info("ftp_connection_closed", source_ip=source_ip)
        except Exception as e:
            logger.error("ftp_error", source_ip=source_ip, error=str(e))
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_connection, self.host, self.port
        )
        logger.info("ftp_honeypot_started", host=self.host, port=self.port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("ftp_honeypot_stopped")