import asyncio
import logging
import argparse
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict, Callable, Tuple, List, Any

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class UDPStatus(Enum):
    """Enum for common UDP response status codes."""
    OK = 'OK'
    ERROR = 'ERROR'
    NOT_FOUND = 'NOT_FOUND'


@dataclass
class UDPRequest:
    """Represents a UDP request with message and client address."""
    data: bytes
    addr: Tuple[str, int]
    command: str = ''
    params: Dict[str, Any] = None

    def __post_init__(self):
        """Parse the command and parameters from the received data."""
        try:
            decoded_data = self.data.decode('utf-8').strip()
            parts = decoded_data.split(' ', 1)
            self.command = parts[0].upper()
            self.params = {'payload': parts[1]} if len(parts) > 1 else {}
        except Exception as e:
            logger.error(f"Error parsing request: {e}")
            self.command = 'INVALID'


@dataclass
class UDPResponse:
    """Represents a UDP response."""
    status: UDPStatus
    data: bytes = b''

    def serialize(self) -> bytes:
        """Convert response to bytes for transmission."""
        status_bytes = self.status.value.encode('utf-8')
        if self.data:
            return status_bytes + b' ' + self.data
        return status_bytes


class AsyncUDPServer:
    """Asynchronous UDP server implementation."""

    def __init__(self, host: str = "localhost", port: int = 4221):
        self.host = host
        self.port = port
        self.transport = None
        self.protocol = None
        self.handlers: Dict[str, Callable] = {}
        self.running = False

    def register_handler(self, command: str) -> Callable:
        """Decorator to register command handlers."""

        def decorator(handler: Callable) -> Callable:
            self.handlers[command.upper()] = handler
            return handler

        return decorator

    class UDPServerProtocol(asyncio.DatagramProtocol):
        """UDP Protocol implementation."""

        def __init__(self, server: 'AsyncUDPServer'):
            self.server = server
            self.transport = None

        def connection_made(self, transport: asyncio.DatagramTransport):
            self.transport = transport

        def datagram_received(self, data: bytes, addr: Tuple[str, int]):
            """Handle incoming UDP datagrams."""
            asyncio.create_task(self.process_datagram(data, addr))

        async def process_datagram(self, data: bytes, addr: Tuple[str, int]):
            """Process received datagram and send response."""
            request = UDPRequest(data, addr)
            try:
                handler = self.server.handlers.get(request.command)
                if handler:
                    response = await handler(request)
                else:
                    response = UDPResponse(UDPStatus.NOT_FOUND, b'Command not found')
            except Exception as e:
                logger.error(f"Error processing request: {e}")
                response = UDPResponse(UDPStatus.ERROR, str(e).encode('utf-8'))

            self.transport.sendto(response.serialize(), addr)

    async def start_server(self):
        """Start the UDP server."""
        try:
            loop = asyncio.get_running_loop()
            self.transport, self.protocol = await loop.create_datagram_endpoint(
                lambda: self.UDPServerProtocol(self),
                local_addr=(self.host, self.port)
            )
            self.running = True
            logger.info(f"UDP Server listening on {self.host}:{self.port}")

            # Keep the server running
            while self.running:
                await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            if self.transport:
                self.transport.close()
                logger.info("Server stopped")

    def stop(self):
        """Stop the UDP server."""
        self.running = False
        if self.transport:
            self.transport.close()


def create_app(**kwargs) -> AsyncUDPServer:
    """Create and configure the UDP server application."""
    app = AsyncUDPServer(**kwargs)

    @app.register_handler('ECHO')
    async def handle_echo(request: UDPRequest) -> UDPResponse:
        """Echo the received message back to the client."""
        return UDPResponse(UDPStatus.OK, request.params.get('payload', '').encode('utf-8'))

    @app.register_handler('PING')
    async def handle_ping(request: UDPRequest) -> UDPResponse:
        """Simple ping handler."""
        return UDPResponse(UDPStatus.OK, b'PONG')

    @app.register_handler('TIME')
    async def handle_time(request: UDPRequest) -> UDPResponse:
        """Return current server time."""
        from datetime import datetime
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S').encode('utf-8')
        return UDPResponse(UDPStatus.OK, current_time)

    return app


async def main(**kwargs):
    """Main entry point for the UDP server."""
    server = create_app(**kwargs)

    try:
        await server.start_server()
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
        server.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="localhost", help="Host to listen on")
    parser.add_argument("--port", type=int, default=2053, help="Port to listen on")
    parser.add_argument("--resolver", default="127.0.0.1:5354", help="DNS resolver to use")
    args = parser.parse_args()

    asyncio.run(main(**vars(args)))
