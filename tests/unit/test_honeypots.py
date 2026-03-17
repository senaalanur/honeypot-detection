import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.events import AttackEvent, AttackType, EventBus
from src.honeypot.http import HTTPHoneypot
from src.honeypot.ssh import SSHHoneypot


class TestSSHHoneypot:
    async def test_publishes_event_on_connection(self) -> None:
        event_bus = MagicMock(spec=EventBus)
        event_bus.publish = AsyncMock()
        honeypot = SSHHoneypot("127.0.0.1", 9922, event_bus)

        # Simulate a reader that sends username, password, then closes
        reader = asyncio.StreamReader()
        reader.feed_data(b"admin\npassword123\n")
        reader.feed_eof()

        writer = MagicMock()
        writer.get_extra_info = MagicMock(return_value=("192.168.1.100", 54321))
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await honeypot._handle_connection(reader, writer)

        event_bus.publish.assert_called_once()
        event: AttackEvent = event_bus.publish.call_args[0][0]
        assert event.source_ip == "192.168.1.100"
        assert event.target_service == "ssh"
        assert "admin" in event.raw_payload
        assert event.attack_type == AttackType.SSH_BRUTE_FORCE

    async def test_detects_command_execution(self) -> None:
        event_bus = MagicMock(spec=EventBus)
        event_bus.publish = AsyncMock()
        honeypot = SSHHoneypot("127.0.0.1", 9922, event_bus)

        reader = asyncio.StreamReader()
        reader.feed_data(b"root\npassword\nwhoami\n")
        reader.feed_eof()

        writer = MagicMock()
        writer.get_extra_info = MagicMock(return_value=("10.0.0.1", 12345))
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await honeypot._handle_connection(reader, writer)

        event: AttackEvent = event_bus.publish.call_args[0][0]
        assert event.attack_type == AttackType.SSH_COMMAND_EXEC


class TestHTTPHoneypot:
    async def test_publishes_event_on_request(self) -> None:
        event_bus = MagicMock(spec=EventBus)
        event_bus.publish = AsyncMock()
        honeypot = HTTPHoneypot("127.0.0.1", 9980, event_bus)

        reader = asyncio.StreamReader()
        reader.feed_data(
            b"GET /.env HTTP/1.1\r\nHost: target.com\r\nUser-Agent: nmap\r\n\r\n"
        )
        reader.feed_eof()

        writer = MagicMock()
        writer.get_extra_info = MagicMock(return_value=("172.16.0.1", 54321))
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await honeypot._handle_connection(reader, writer)

        event_bus.publish.assert_called_once()
        event: AttackEvent = event_bus.publish.call_args[0][0]
        assert event.source_ip == "172.16.0.1"
        assert event.target_service == "http"
        assert event.attack_type == AttackType.HTTP_EXPLOIT