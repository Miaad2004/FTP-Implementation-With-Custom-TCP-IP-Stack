import logging
import threading
from datetime import datetime
import sys
import atexit

import pyfiglet
from colorama import Fore, init

from src.common.utils import clear_console, block_linux_reset_packets, unblock_linux_reset_packets
from src.common.config import config_handler
from src.transport.socket_transport import PythonSocketTransport
from src.transport.custom_tcp_transport import CustomTCPTransport
from .client_handler import ClientHandler

init()

VERSION = "1.0.0"


class FTPServer:
    """
    A class to represent an FTP server.

    Attributes:
    -----------
    host : str
        The hostname or IP address of the server.
    port : int
        The port number on which the server listens.
    logger : logging.Logger
        Logger instance for logging server activities.
    transport : PythonSocketTransport
        Transport layer for handling socket connections.
    certificate_path : str
        Path to the SSL certificate file.
    key_path : str
        Path to the SSL key file.
    implicit_tls : bool
        Flag to indicate if implicit TLS is enabled.
    support_FTPS : bool
        Flag to indicate if FTPS is supported.
    ssl_context : ssl.SSLContext
        SSL context for secure connections.
    """

    def __init__(self, host=None, port=None):
        """
        Constructs all the necessary attributes for the FTPServer object.

        Parameters:
        -----------
        host : str, optional
            The hostname or IP address of the server (default is None).
        port : int, optional
            The port number on which the server listens (default is None).
        """
        atexit.register(self.at_exit)
        self.print_banner()

        if host is None:
            self.host = config_handler.get("ftp_host")

        if port is None:
            self.port = config_handler.get("ftp_port")

        self.logger = logging.getLogger(__name__)
        
        self.certificate_path = config_handler.get("ssl_cert_path")
        self.key_path = config_handler.get("ssl_key_path")
        self.implicit_tls = config_handler.get("implicit_tls")
        self.support_FTPS = config_handler.get("support_FTPS")
        self.ssl_context = PythonSocketTransport.create_ssl_context_server(
            self.certificate_path, self.key_path
        )

        if config_handler.get("use_custom_transport"):
            if self.support_FTPS or self.implicit_tls:
                raise Exception(
                    "Custom transport not supported with FTPS or implicit TLS"
                )
            
            else:
                atexit.register(unblock_linux_reset_packets)
                block_linux_reset_packets()
                self.transport = CustomTCPTransport()
                self.logger.info("Using custom TCP transport")
        
        else:
            self.transport = PythonSocketTransport()
        
        if self.implicit_tls and self.support_FTPS:
            self.logger.info("Implicit TLS enabled")
            self.transport.upgrade_to_secure(self.ssl_context)

    def start(self):
        """
        Starts the FTP server and listens for incoming connections.
        """
        self.transport.bind(self.host, self.port)
        self.transport.listen()
        self.logger.info(f"FTP Server listening on {self.host}:{self.port}")

        while True:
            client, addr = self.transport.accept()
            self.logger.info(f"New connection from {addr}")
            thread = threading.Thread(
                target=self.handle_client, args=(client, addr)
            )
            thread.start()

    def handle_client(self, client, addr):
        """
        Handles the client connection.

        Parameters:
        -----------
        client : socket
            The client socket object.
        addr : tuple
            The address of the client.
        """
        client_handler = ClientHandler(client, addr, server=self)
        client_handler.run()

    def at_exit(self):
        self.logger.debug("Exiting server")
        try:
            self.transport.close()
        
        except:
            pass
    
    @staticmethod
    def print_banner():
        """
        Prints the server banner with version and start time.
        """
        clear_console()
        ascii_banner = pyfiglet.figlet_format("Swift File")
        print(Fore.CYAN + ascii_banner + Fore.RESET)
        print(
            Fore.GREEN
            + f"SwiftFile FTP Server v{VERSION} started at: "
            + f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            + f"on python {sys.version.split()[0]}"
            + Fore.RESET
        )
        print("-" * 60 + "\n")
