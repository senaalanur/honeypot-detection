import asyncio
import json
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlparse

from src.core.events import AttackEvent, AttackType, EventBus
from src.core.logging import get_logger

logger = get_logger(__name__)

# Paths that look juicy to attackers — returns fake sensitive content
HONEYPOT_PATHS: dict[str, tuple[int, str, str]] = {
    "/admin": (200, "text/html", "<html><body><h1>Admin Panel</h1><form>User:<input name='user'> Pass:<input name='pass' type='password'><button>Login</button></form></body></html>"),
    "/wp-login.php": (200, "text/html", "<html><body><h1>WordPress Login</h1></body></html>"),
    "/phpMyAdmin": (200, "text/html", "<html><body><h1>phpMyAdmin</h1></body></html>"),
    "/.env": (200, "text/plain", "DB_HOST=localhost\nDB_USER=root\nDB_PASS=supersecret123\nAPP_KEY=base64:fakekey=="),
    "/config.php": (200, "text/plain", "<?php $db_pass = 'hunter2'; ?>"),
    "/backup.zip": (200, "application/zip", "PK\x03\x04fake zip content"),
    "/api/v1/users": (200, "application/json", json.dumps({"users": [{"id": 1, "email": "admin@company.com", "role": "admin"}]})),
}

DEFAULT_404 = (404, "text/html", "<html><body><h1>404 Not Found</h1></body></html>")

HTTP_RESPONSE_TEMPLATE = (
    "HTTP/1.1 {status} {status_text}\r\n"
    "Server: Apache/2.4.41 (Ubuntu)\r\n"
    "Content-Type: {content_type}\r\n"
    "Content-Length: {content_length}\r\n"
    "X-Powered-By: PHP/7.4.3\r\n"
    "\r\n"
)

STATUS_TEXTS = {200: "OK", 404: "Not Found", 401: "Unauthorized"}


class HTTPHoneypot:
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

        try:
            # Read HTTP request
            raw_request = b""
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=10.0)
                if not chunk:
                    break
                raw_request += chunk
                if b"\r\n\r\n" in raw_request:
                    break

            if not raw_request:
                return

            request_text = raw_request.decode("utf-8", errors="ignore")
            lines = request_text.split("\r\n")
            request_line = lines[0] if lines else ""

            # Parse method and path
            parts = request_line.split(" ")
            method = parts[0] if len(parts) > 0 else "UNKNOWN"
            path = parts[1] if len(parts) > 1 else "/"
            parsed_path = urlparse(path).path

            # Extract headers for intelligence
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if ": " in line:
                    key, _, value = line.partition(": ")
                    headers[key.lower()] = value

            user_agent = headers.get("user-agent", "unknown")

            logger.info(
                "http_request",
                source_ip=source_ip,
                method=method,
                path=parsed_path,
                user_agent=user_agent,
            )

            # Determine attack type
            attack_type = AttackType.HTTP_SCAN
            suspicious_paths = ["/admin", "/.env", "/config", "/backup", "/shell", "/cmd"]
            if any(s in parsed_path.lower() for s in suspicious_paths):
                attack_type = AttackType.HTTP_EXPLOIT

            # Build and send response
            status, content_type, body = HONEYPOT_PATHS.get(parsed_path, DEFAULT_404)
            body_bytes = body.encode("utf-8", errors="ignore")

            response_header = HTTP_RESPONSE_TEMPLATE.format(
                status=status,
                status_text=STATUS_TEXTS.get(status, "OK"),
                content_type=content_type,
                content_length=len(body_bytes),
            )
            writer.write(response_header.encode() + body_bytes)
            await writer.drain()

            # Publish event
            event = AttackEvent(
                source_ip=source_ip,
                source_port=source_port,
                target_service="http",
                raw_payload=request_text[:2000],
                attack_type=attack_type,
            )
            await self.event_bus.publish(event)

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.error("http_error", source_ip=source_ip, error=str(e))
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_connection, self.host, self.port
        )
        logger.info("http_honeypot_started", host=self.host, port=self.port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("http_honeypot_stopped")