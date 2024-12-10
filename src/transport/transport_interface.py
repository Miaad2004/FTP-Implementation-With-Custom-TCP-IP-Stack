from abc import ABC, abstractmethod
import ssl
from typing import Tuple, Any


class Transport(ABC):
    """Abstract base class for transport implementations"""

    @abstractmethod
    def connect(self, host: str, port: int) -> None:
        """Establish connection to remote host"""
        pass

    @abstractmethod
    def send(self, data: bytes) -> int:
        """Send data over the transport"""
        pass

    @abstractmethod
    def receive(self, buffer_size: int) -> bytes:
        """Receive data from the transport"""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close the transport connection"""
        pass

    @abstractmethod
    def bind(self, host: str, port: int) -> None:
        """Bind to specified address"""
        pass

    @abstractmethod
    def listen(self, backlog: int = 1) -> None:
        """Listen for incoming connections"""
        pass

    @abstractmethod
    def accept(self) -> Tuple["Transport", Any]:
        """Accept incoming connection"""
        pass
    
    @abstractmethod
    def getsockname(self) -> Tuple[str, int]:
        """Return the local address to which the socket is bound"""
        pass


class SecureUpgradable(ABC):
    """Interface for transports that can be upgraded to secure connection"""

    @abstractmethod
    def upgrade_to_secure(
        self, ssl_context: ssl.SSLContext = None, server_side: bool = False
    ) -> "Transport":
        """Upgrade connection to use SSL/TLS"""
        pass
