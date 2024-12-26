import socket
import logging
import os
import ssl
from typing import Optional


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
        
    def send_command(self, command: str) -> str:
        """Send command to server and return response"""
        logging.info(f"Sending command: {command}")
        self.control_socket.send(f"{command}\r\n".encode())
        return self.read_response()

    def read_response(self) -> str:
        """Read response from server"""
        response = self.control_socket.recv(8192).decode()
        logging.info(f"Server response: {response}")
        return response

    def login(self, username: str, password: str) -> bool:
        """Handle FTP authentication"""
        # Send USERNAME
        response = self.send_command(f"USER {username}")
        if not response.startswith('331'):
            return False

        # Send PASSWORD
        response = self.send_command(f"PASS {password}")
        return response.startswith('230')
    
    def quit(self) -> bool:
        """QUIT command - terminate session"""
        if self.data_socket:
            print("421 File transfer in progress, please wait")
            return False

        try:
            # Send QUIT command and get response
            response = self.send_command('QUIT')
            success = response.startswith('221')

            # Close sockets
            if self.data_socket:
                self.data_socket.close()
                self.data_socket = None
            if self.control_socket:
                self.control_socket.close()
                self.control_socket = None

            # Log disconnect
            logging.info("Disconnected from FTP server")

            return success

        except Exception as e:
            logging.error(f"Error during quit: {str(e)}")
            return False

    def user(self, username: str) -> bool:
        """USER command - send username"""
        response = self.send_command(f"USER {username}")
        return response.startswith('331') or response.startswith('230')

    def pass_(self, password: str) -> bool:
        """PASS command - send password"""
        response = self.send_command(f"PASS {password}")
        return response.startswith('230')
    
    def rein(self) -> bool:
        """REIN command - reinitialize connection"""
        response = self.send_command("REIN")
        return response.startswith('220')

    def noop(self) -> bool:
        """NOOP command - no operation"""
        response = self.send_command("NOOP")
        return response.startswith('200')

    def help(self, command: str = "") -> str:
        """HELP command - show available commands"""
        response = self.send_command(f"HELP {command}".strip())
        return response

    def feat(self) -> str:
        """FEAT command - list supported features"""
        response = self.send_command("FEAT")
        return response
    
    def cwd(self, path: str) -> bool:
        """CWD command - change working directory"""
        response = self.send_command(f"CWD {path}")
        return response.startswith('250')

    def cdup(self) -> bool:
        """CDUP command - change to parent directory"""
        response = self.send_command("CDUP")
        return response.startswith('250')
    
    def mkd(self, dirname: str) -> bool:
        """MKD command - make directory"""
        response = self.send_command(f"MKD {dirname}")
        return response.startswith('257')

    def rmd(self, dirname: str) -> bool:
        """RMD command - remove directory"""
        response = self.send_command(f"RMD {dirname}")
        return response.startswith('250')

    def pwd(self) -> str:
        """PWD command - print working directory"""
        response = self.send_command("PWD")
        if response.startswith('257'):
            # Extract path from response (usually in quotes)
            import re
            match = re.search(r'"([^"]*)"', response)
            return match.group(1) if match else ""
        return ""

    def list_files(self) -> str:
        """LIST command implementation"""
        try:
            data_socket = self.create_data_connection()
            if not data_socket:
                return "Failed to create data connection"

            # Wrap socket with TLS BEFORE sending LIST command
            if self.secured_data and self.ssl_context:
                data_socket = self.ssl_context.wrap_socket(
                    data_socket,
                    server_hostname=self.host,
                    do_handshake_on_connect=False,
                    session=self.control_socket.session,
                )

            response = self.send_command('LIST')
            if not response.startswith('150'):
                if data_socket:
                    data_socket.close()
                return "Failed to initiate LIST"

            chunks = []
            data_socket.settimeout(10)
            try:
                while True:
                    data = data_socket.recv(8192)
                    if not data:
                        break
                    chunks.append(data.decode())
            except socket.timeout:
                pass
            finally:
                if self.secured_data:
                    data_socket.unwrap()
                data_socket.close()

            self.read_response()
            return ''.join(chunks)

        except Exception as e:
            logging.error(f"LIST failed: {str(e)}")
            if data_socket:
                data_socket.close()
            return f"LIST failed: {str(e)}"
        
    def download_file(self, filename: str) -> bool:
        """RETR command implementation"""
        data_socket = None
        try:
            data_socket = self.create_data_connection()
            if not data_socket:
                return False

            response = self.send_command(f'RETR {filename}')
            if not response.startswith('150'):
                if data_socket:
                    data_socket.close()
                return False

            if self.secured_data and self.ssl_context:
                data_socket = self.ssl_context.wrap_socket(
                    data_socket,
                    server_hostname=self.host,
                    do_handshake_on_connect=False,
                    session=self.control_socket.session,
                )

            data_socket.settimeout(10)
            with open(filename, 'wb') as file:
                try:
                    while True:
                        data = data_socket.recv(8192)
                        if not data:
                            break
                        file.write(data)
                except socket.timeout:
                    logging.error(f"Timeout while downloading {filename}")
                    return False

        except Exception as e:
            logging.error(f"Download failed for {filename}: {str(e)}")
            return False
        finally:
            if data_socket:
                try:
                    if self.secured_data:
                        data_socket.unwrap()
                    data_socket.close()
                except Exception as e:
                    logging.error(f"Error closing data socket: {str(e)}")

        return self.read_response().startswith('226')

    def upload_file(self, filepath: str) -> bool:
        """STOR command implementation for uploading files"""
        data_socket = None
        try:
            if not os.path.exists(filepath):
                logging.error(f"File not found: {filepath}")
                return False

            filename = os.path.basename(filepath)
            data_socket = self.create_data_connection()
            if not data_socket:
                return False

            response = self.send_command(f'STOR {filename}')
            if not response.startswith('150'):
                if data_socket:
                    data_socket.close()
                return False

            if self.secured_data and self.ssl_context:
                data_socket = self.ssl_context.wrap_socket(
                    data_socket,
                    server_hostname=self.host,
                    do_handshake_on_connect=False,
                    session=self.control_socket.session,
                )

            data_socket.settimeout(10)
            with open(filepath, 'rb') as file:
                try:
                    data_socket.sendall(file.read())
                except socket.timeout:
                    logging.error(f"Timeout while uploading {filename}")
                    return False

        except Exception as e:
            logging.error(f"Upload failed for {filename}: {str(e)}")
            return False
        finally:
            if data_socket:
                try:
                    if self.secured_data:
                        data_socket.unwrap()
                    data_socket.close()
                except Exception as e:
                    logging.error(f"Error closing data socket: {str(e)}")

        return self.read_response().startswith('226')

    def dele(self, filename: str) -> bool:
        """DELE command - delete file"""
        response = self.send_command(f"DELE {filename}")
        return response.startswith('250')

    def rnfr(self, filename: str) -> bool:
        """RNFR command - rename from (specify source file)"""
        response = self.send_command(f"RNFR {filename}")
        return response.startswith('350')

    def rnto(self, filename: str) -> bool:
        """RNTO command - rename to (specify destination file)"""
        response = self.send_command(f"RNTO {filename}")
        return response.startswith('250')

    def type(self, type_code: str) -> bool:
        """TYPE command - set transfer type"""
        response = self.send_command(f"TYPE {type_code}")
        return response.startswith('200')

    def opts(self, option: str) -> bool:
        """OPTS command - set options"""
        response = self.send_command(f"OPTS {option}")
        return response.startswith('200')
    
    def syst(self) -> str:
        """SYST command - get system type"""
        response = self.send_command("SYST")
        return response

    def site_chmod(self, mode: str, filename: str) -> bool:
        """SITE CHMOD command - change file permissions"""
        response = self.send_command(f"SITE CHMOD {mode} {filename}")
        return response.startswith('200')