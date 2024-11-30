from .transport_interface import Transport, SecureUpgradable
import socket
import ssl
from typing import Tuple, Any, Optional
from src.common.config import config_handler
import logging

class PythonSocketTransport(Transport, SecureUpgradable):
    def __init__(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.is_secure = False
        self.ssl_session: Optional[ssl.SSLSession] = None
        self.logger = logging.getLogger(__name__)

    def connect(self, host: str, port: int) -> None:
        self._socket.connect((host, port))

    def send(self, data: bytes) -> int:
        return self._socket.send(data)

    def receive(self, buffer_size: int) -> bytes:
        return self._socket.recv(buffer_size)

    def close(self) -> None:
        self._socket.close()

    def bind(self, host: str, port: int) -> None:
        self._socket.bind((host, port))

    def listen(self, backlog: int = 1) -> None:
        self._socket.listen(backlog)

    def accept(self) -> Tuple["Transport", Any]:
        sock, addr = self._socket.accept()
        transport = PythonSocketTransport()
        transport._socket = sock
        if self.is_secure:
            transport.ssl_session = self.ssl_session
        return transport, addr

    @staticmethod
    def _create_default_ctx() -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(
            certfile=config_handler.get('ssl_cert_path'),
            keyfile=config_handler.get('ssl_key_path')
        )
        
        # Enhanced TLS configuration
        ctx.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256')
        ctx.options |= (
            ssl.OP_NO_TLSv1 | 
            ssl.OP_NO_TLSv1_1 |
            ssl.OP_NO_COMPRESSION |
            ssl.OP_CIPHER_SERVER_PREFERENCE |
            ssl.OP_NO_TICKET  # Enable session resumption by disabling tickets
        )
        
        ctx.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK')
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def upgrade_to_secure(self,
                          ssl_context: ssl.SSLContext = None,
                          do_handshake_on_connect: bool = True,
                          server_side: bool = True,
                          session: ssl.SSLSession = None) -> "Transport":
        if self.is_secure:
            return self
            
        if ssl_context is None:
            ssl_context = self._create_default_ctx()

        try:
            kwargs = {
                'server_side': server_side,
                'do_handshake_on_connect': do_handshake_on_connect
            }
            
            if session:
                kwargs['session'] = session
                
            secure_socket = ssl_context.wrap_socket(
                self._socket,
                **kwargs
            )
            
            self._socket = secure_socket
            self.is_secure = True
            
            if isinstance(self._socket, ssl.SSLSocket):
                self.ssl_session = self._socket.session
            
            return self
            
        except ssl.SSLError as e:
            self.logger.error(f"SSL Error: {e}")
            self._socket.close()
            raise
        except OSError as e:
            self.logger.error(f"Socket Error: {e}") 
            self._socket.close()
            raise
        except Exception as e:
            self.logger.error(f"Unexpected Error: {e}")
            self._socket.close()
            raise
