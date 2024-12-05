import socket
import ssl
from ssl import SSLContext, PROTOCOL_TLS_SERVER
from typing import Tuple, Any, Optional
from pathlib import Path
import logging

from .transport_interface import Transport, SecureUpgradable


class PythonSocketTransport(Transport, SecureUpgradable):
    """
    A class to handle socket transport with optional SSL/TLS support.
    """

    def __init__(self, sock=None):
        """
        Initialize the PythonSocketTransport.

        :param sock: Optional socket object to use.
                     If not provided, a new socket will be created.
        """
        self._socket = (
            sock if sock else socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        )
        self._ssl_context = None
        self._is_secure = False
        self.logger = logging.getLogger(__name__)

    def connect(self, host: str, port: int) -> None:
        """
        Connect to a remote socket at the given address.

        :param host: The remote host to connect to.
        :param port: The port to connect to.
        """
        self._socket.connect((host, port))

    def send(self, data: bytes) -> int:
        """
        Send data to the connected socket.

        :param data: The data to send.
        :return: The number of bytes sent.
        """
        return self._socket.send(data)

    def receive(self, buffer_size: int) -> bytes:
        """
        Receive data from the connected socket.

        :param buffer_size: The maximum amount of data to be received at once.
        :return: The data received.
        """
        return self._socket.recv(buffer_size)

    def close(self) -> None:
        """
        Close the socket connection.
        """
        try:
            if self._is_secure:
                self._socket.unwrap()

        except Exception as e:
            self.logger.error(f"Error during SSL shutdown: {e}")

        try:
            if self._socket:
                self._socket.close()

        except Exception as e:
            self.logger.error(f"Error closing socket: {e}")

    def bind(self, host: str, port: int) -> None:
        """
        Bind the socket to a local address.

        :param host: The local host to bind to.
        :param port: The port to bind to.
        """
        self._socket.bind((host, port))

    def listen(self, backlog: int = 1) -> None:
        """
        Listen for incoming connections.

        :param backlog: The maximum number of queued connections.
        """
        self._socket.listen(backlog)

    def accept(self) -> Tuple["PythonSocketTransport", Any]:
        """
        Accept a connection. The socket must be bound to an address and
        listening for connections.

        :return: A tuple containing the new transport object and
                 the address of the client.
        """
        client_socket, addr = self._socket.accept()
        transport = PythonSocketTransport(client_socket)

        return transport, addr

    @staticmethod
    def create_ssl_context_server(
        certificate_path: str, key_path: str
    ) -> SSLContext:
        """
        Create an SSL context for a server.

        :param certificate_path: Path to the certificate file.
        :param key_path: Path to the key file.
        :return: An SSLContext object configured for server use.
        """
        certificate_path = Path(certificate_path)
        key_path = Path(key_path)

        assert (
            certificate_path.exists()
        ), f"Certificate file not found: {certificate_path}"
        assert key_path.exists(), f"Key file not found: {key_path}"

        ssl_context = SSLContext(PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(str(certificate_path), str(key_path))
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.set_ciphers(
            "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK"
        )
        ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        return ssl_context

    def upgrade_to_secure(
        self, ssl_context: Optional[SSLContext]
    ) -> "PythonSocketTransport":
        """
        Upgrade the connection to use SSL/TLS.

        :param ssl_context: The SSL context to use for the secure connection.
        :return: The transport object itself.
        """
        if self._is_secure:
            return self

        try:
            self._socket = ssl_context.wrap_socket(self._socket,
                                                   server_side=True)
            self._ssl_context = ssl_context
            self._is_secure = True
            return self

        except Exception as e:
            raise ssl.SSLError(f"SSL upgrade failed: {str(e)}") from e

    def downgrade_to_insecure(self) -> "PythonSocketTransport":
        """
        Downgrade the connection to remove SSL/TLS.

        :return: The transport object itself.
        """
        if not self._is_secure:
            return self

        try:
            self._socket.unwrap()
            self._is_secure = False
            return self

        except Exception as e:
            raise ssl.SSLError(f"SSL downgrade failed: {str(e)}") from e

    @property
    def is_secure(self) -> bool:
        """
        Check if the connection is secure.

        :return: True if the connection is secure, False otherwise.
        """
        return self._is_secure
