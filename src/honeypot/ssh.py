import asyncio
import re
from datetime import UTC, datetime

from src.core.events import AttackEvent, AttackType, EventBus
from src.core.logging import get_logger

logger = get_logger(__name__)

# Fake banner — looks like a real outdated server to attract attackers
SSH_BANNER = b"SSH-2.0-OpenSSH_7.4\r\n"

# Commands attackers commonly run — we log these and return fake output
FAKE_RESPONSES: dict[str, bytes] = {
    "whoami": b"root\r\n",
    "id": b"uid=0(root) gid=0(root) groups=0(root)\r\n",
    "uname -a": b"Linux ubuntu 4.15.0-112-generic #113-Ubuntu SMP x86_64 GNU/Linux\r\n",
    "ls": b"bin  boot  dev  etc  home  lib  media  opt  proc  root  run  srv  sys  tmp  usr  var\r\n",
    "pwd": b"/root\r\n",
    "cat /etc/passwd": b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n",
    "ifconfig": b"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500\n        inet 10.0.2.15  netmask 255.255.255.0\r\n",
    "ps aux": b"USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1  37400  5500 ?        Ss   00:00   0:01 /sbin/init\r\n",
}

DEFAULT_RESPONSE = b"bash: command not found\r\n"
PROMPT = b"root@ubuntu:~# "


class SSHHoneypot:
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

        logger.info("ssh_connection", source_ip=source_ip, source_port=source_port)

        try:
            # Send fake SSH banner
            writer.write(SSH_BANNER)
            await writer.drain()

            # Collect login attempts and commands
            session_data: list[str] = []
            writer.write(b"login: ")
            await writer.drain()

            username = await self._read_line(reader)
            session_data.append(f"username: {username}")

            writer.write(b"Password: ")
            await writer.drain()

            password = await self._read_line(reader)
            session_data.append(f"password: {password}")

            logger.warning(
                "ssh_login_attempt",
                source_ip=source_ip,
                username=username,
                password=password,
            )

            # Let them "in" — more data = better intelligence
            writer.write(b"\r\nWelcome to Ubuntu 18.04.5 LTS\r\n\r\n")
            writer.write(PROMPT)
            await writer.drain()

            # Capture commands for up to 60 seconds
            deadline = asyncio.get_event_loop().time() + 60.0
            while asyncio.get_event_loop().time() < deadline:
                try:
                    command = await asyncio.wait_for(
                        self._read_line(reader), timeout=30.0
                    )
                    if not command:
                        break

                    session_data.append(f"command: {command}")
                    logger.info(
                        "ssh_command", source_ip=source_ip, command=command
                    )

                    response = FAKE_RESPONSES.get(command.strip(), DEFAULT_RESPONSE)
                    writer.write(response)
                    writer.write(PROMPT)
                    await writer.drain()

                except asyncio.TimeoutError:
                    break

            # Publish event to Redis
            raw_payload = "\n".join(session_data)
            attack_type = (
                AttackType.SSH_COMMAND_EXEC
                if any("command:" in d for d in session_data)
                else AttackType.SSH_BRUTE_FORCE
            )

            event = AttackEvent(
                source_ip=source_ip,
                source_port=source_port,
                target_service="ssh",
                raw_payload=raw_payload,
                attack_type=attack_type,
            )
            await self.event_bus.publish(event)

        except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError):
            logger.info("ssh_connection_closed", source_ip=source_ip)
        except Exception as e:
            logger.error("ssh_error", source_ip=source_ip, error=str(e))
        finally:
            writer.close()
            await writer.wait_closed()

    async def _read_line(self, reader: asyncio.StreamReader) -> str:
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=10.0)
            return data.decode("utf-8", errors="ignore").strip()
        except asyncio.TimeoutError:
            return ""

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_connection, self.host, self.port
        )
        logger.info("ssh_honeypot_started", host=self.host, port=self.port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("ssh_honeypot_stopped")