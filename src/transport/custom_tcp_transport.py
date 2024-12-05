from .transport_interface import Transport, SecureUpgradable
from typing import Tuple, Any, Optional
import ssl
import logging
from src.core.tcp.tcp import TCPConnection, ConnectionState
import sys


class CustomTCPTransport(Transport, SecureUpgradable):
    def __init__(self):
        # abort if not on Linux
        if not sys.platform.startswith('linux'):
            raise NotImplementedError("Custom TCP transport only supported on Linux")
        
        self.tcp_connection = None
        self.is_secure = False
        self.ssl_session: Optional[ssl.SSLSession] = None
        self.logger = logging.getLogger(__name__)

    def connect(self, host: str, port: int) -> None:
        # Configure your TCP connection parameters
        interface = 'eth0'  # Change as needed
        source_MAC = "00:15:5d:69:b4:e5"  # Change to your MAC
        dest_MAC = "00:15:5d:ac:5f:57"    # Change to target MAC
        source_ip = "172.18.121.202"      # Change to your IP
        source_port = 12345               # Change or randomize

        self.tcp_connection = TCPConnection(
            source_MAC=source_MAC,
            dest_MAC=dest_MAC, 
            source_ip=source_ip,
            dest_ip=host,
            source_port=source_port,
            dest_port=port,
            interface=interface
        )
        
        # Open connection with timeout
        self.tcp_connection.open(wait_until_established=True, timeout=10)
        
        if self.tcp_connection.status() != ConnectionState.ESTABLISHED:
            raise ConnectionError("Failed to establish TCP connection")

    def send(self, data: bytes) -> int:
        if not self.tcp_connection:
            raise Exception("Not connected")
        
        self.tcp_connection.send(data)
        return len(data)

    def receive(self, buffer_size: int) -> bytes:
        if not self.tcp_connection:
            raise Exception("Not connected")
            
        try:
            return self.tcp_connection.receive(timeout=5)
        except TimeoutError:
            return b''

    def close(self) -> None:
        if self.tcp_connection:
            self.tcp_connection.close()
            self.tcp_connection = None

    def bind(self, host: str, port: int) -> None:
        raise NotImplementedError("Server-side operations not implemented")

    def listen(self, backlog: int = 1) -> None: 
        raise NotImplementedError("Server-side operations not implemented")

    def accept(self) -> Tuple["Transport", Any]:
        raise NotImplementedError("Server-side operations not implemented")

    def upgrade_to_secure(self,
                         ssl_context: ssl.SSLContext = None,
                         do_handshake_on_connect: bool = True,
                         server_side: bool = False,
                         session: ssl.SSLSession = None) -> "Transport":
        raise NotImplementedError("SSL/TLS not implemented in custom TCP")