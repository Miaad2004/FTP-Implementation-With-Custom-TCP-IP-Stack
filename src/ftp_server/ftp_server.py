from src.common.config import config_handler
from src.transport.socket_transport import PythonSocketTransport
import logging
import threading
from .client_handler import ClientHandler

logging.basicConfig(level=logging.INFO)


class FTPServer:
    def __init__(self, host=None, port=None):
        if host is None:
            self.host = config_handler.get("ftp_host")

        if port is None:
            self.port = config_handler.get("ftp_port")

        self.logger = logging.getLogger(__name__)

        self.transport = PythonSocketTransport()
        self.implicit_tls = config_handler.get("implicit_tls")
        
        if self.implicit_tls:
            self.logger.info("Implicit TLS enabled")
            self.transport.upgrade_to_secure()

    def start(self):
        self.transport.bind(self.host, self.port)
        self.transport.listen()
        self.logger.info(f"FTP Server listening on {self.host}:{self.port}")

        while 1:
            client, addr = self.transport.accept()
            self.logger.info(f"New connection from {addr}")
            client_handler = ClientHandler(client, addr)
            client_handler = client_handler.run() #threading.Thread(target=client_handler.run)
