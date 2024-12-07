import socket
import logging
import os
import ssl
from typing import Tuple, Optional

class FTPClient:
    def __init__(self, host: str, port: int = 21):
        self.host = host
        self.port = port
        self.control_socket = None
        self.data_socket = None
        self.secured_control = False
        self.secured_data = False
        self.ssl_context = None
        self.logging_setup()
        
    def logging_setup(self):
        logging.basicConfig(
            filename='ftp_client.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        
    def connect(self) -> bool:
        """Establish control connection to FTP server"""
        try:
            self.control_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            self.control_socket.connect((self.host, self.port))
            response = self.read_response()
            logging.info(f"Connected to server: {response}")
            return True
        except Exception as e:
            logging.error(f"Connection failed: {str(e)}")
            return False
        
    def create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for TLS connections"""
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        return ssl_context

    def auth_tls(self) -> bool:
        """Initialize TLS security on control channel"""
        if self.secured_control:
            return True

        try:
            response = self.send_command("AUTH TLS")
            if not response.startswith('234'):
                return False

            # Create SSL context if not exists
            if not self.ssl_context:
                self.ssl_context = self.create_ssl_context()

            # Upgrade control socket to TLS
            self.control_socket = self.ssl_context.wrap_socket(
                self.control_socket,
                server_hostname=self.host
            )
            self.secured_control = True

            # Set protection buffer size to 0
            response = self.send_command("PBSZ 0")
            if not response.startswith('200'):
                return False

            # Set protection level to private
            response = self.send_command("PROT P")
            if not response.startswith('200'):
                return False

            self.secured_data = True
            return True

        except Exception as e:
            logging.error(f"TLS initialization failed: {e}")
            return False

    def create_data_connection(self) -> Optional[socket.socket]:
        """Create data connection for file transfers"""
        # Send PASV command
        response = self.send_command('PASV')
        if not response.startswith('227'):
            return None

        # Parse PASV response for IP and port
        import re
        numbers = re.findall(
            r'(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)', response)[0]
        ip = '.'.join(numbers[:4])
        port = (int(numbers[4]) * 256) + int(numbers[5])

        # Create data connection
        try:
            data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            data_sock.connect((ip, port))

            return data_sock

        except Exception as e:
            logging.error(f"Data connection failed: {str(e)}")
            if data_sock:
                data_sock.close()
            return None