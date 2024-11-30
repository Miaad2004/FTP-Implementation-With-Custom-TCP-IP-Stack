import logging
from functools import wraps
from src.file_system.file_system import FileSystem
from src.transport.socket_transport import PythonSocketTransport
from filelock import FileLock
from src.common.config import config_handler

logging.basicConfig(level=logging.INFO)


class ClientHandler:
    def __init__(self,
                 tranport: PythonSocketTransport,
                 addr):
        self.control_transport = tranport
        self.data_transport = None
        self.addr = addr
        self.file_sytem = FileSystem()
        self.logger = logging.getLogger(f"ClientHandler-{addr}")

        self.authenticated = False
        self.username = None
        self.secured_data = False
        self.secured_control = False
        self.got_pbsz = False

        self.in_pasv_mode = False

        self.features = ["AUTH TLS", "PBSZ", "PROT", "UTF8", "PASV"]
        
        if config_handler.get("implicit_tls"):
            self.secured_control = True

    def requires_auth(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if not self.authenticated:
                self.send_res("530 Not logged in.")
                return

            return func(self, *args, **kwargs)

        return wrapper

    def send_res(self, res):
        self.logger.info(f"Sending res: {res}")
        encoded_res = (res + "\r\n").encode("utf-8")
        self.control_transport.send(encoded_res)

    def run(self):
        self.send_res("220 Welcome to FTP server")

        while 1:
            try:
                data = self.control_transport.receive(1024)
                data = data.decode("utf-8").strip()
                if not data:
                    break

                self.logger.info(f"Received cmd {data}")
                self.handle_cmd(data)

            except Exception as e:
                self.logger.error(f"Error: {e}")
                raise

        self.control_transport.close()

    def handle_cmd(self, cmd):
        try:
            cmd, *args = cmd.split()
            cmd = cmd.upper()
            handler_func = getattr(self, f"handle_{cmd}", None)

            if handler_func:
                handler_func(*args)

            else:
                self.send_res("502 Command not implemented")

        except Exception as e:
            self.logger.error(f"Error: {e}")
            self.send_res("500 Syntax error, command unrecognized")

    def handle_USER(self, username):
        try:
            if self.file_sytem.get_user(username):
                self.username = username
                self.authenticated = False
                self.send_res("331 User name okay, need password.")

            else:
                self.send_res("530 Invalid username.")

        except Exception as e:
            self.logger.error(f"Error in USER: {e}")
            self.send_res("530 invalid username")

    def handle_PASS(self, password):
        try:
            if not self.username:
                self.send_res("503 Bad sequence of commands.")
                return

            if self.file_sytem.login(self.username, password):
                self.authenticated = True
                self.send_res("230 User logged in, proceed.")

            else:
                self.send_res("530 invalid password")

        except Exception as e:
            self.logger.error(f"Error in PASS: {e}")
            self.send_res("530 invalid password")

    def handle_AUTH(self, *args):
        if args[0].upper() == "TLS":
            try:
                self.send_res("234 Ready for TLS")
                self.control_transport.upgrade_to_secure()
                self.secured_control = True
                self.send_res("200 TLS connection established")
            except Exception as e:
                self.logger.error(f"TLS negotiation failed: {e}")
                if not self.control_transport._socket._closed:
                    self.send_res("550 TLS negotiation failed")
                raise

        else:
            self.send_res("502 Command not implemented")

    def handle_PBSZ(self, *args):
        try:
            if not self.secured_control:
                self.send_res("503 Bad sequence of commands")
                return

            if args[0] == "0":
                self.got_pbsz = True
                self.send_res("200 PBSZ=0")

            else:
                self.send_res("501 Invalid parameter")

        except Exception as e:
            self.logger.error(f"Error in PBSZ: {e}")
            self.send_res("501 Invalid parameter")

    def handle_PROT(self, *args):
        try:
            if not self.secured_control or not self.got_pbsz:
                self.send_res("503 Bad sequence of commands")
                return

            if args[0].upper() == "P":
                self.secured_data = True
                self.send_res("200 Protection level set to Private")

            elif args[0].upper() == "C":
                self.secured_data = False
                self.send_res("200 Protection level set to Clear")

            else:
                self.send_res("504 Protection level not supported")

        except Exception as e:
            self.logger.error(f"Error in PROT: {e}")
            self.send_res("504 Protection level not supported")

    @requires_auth
    def handle_PASV(self):
        self.data_transport = PythonSocketTransport()

        try:
            self.data_transport.bind(self.addr[0], 0)
            self.data_transport.listen()
            ip, port = self.data_transport._socket.getsockname()

            if self.secured_data:
                self.data_transport.upgrade_to_secure()

            ip_parts = ip.split(".")
            port_parts = [str(port >> 8), str(port & 0xFF)]

            ip_str = ','.join(ip_parts)
            port_str = ','.join(port_parts)
            response = f"227 Entering Passive Mode ({ip_str},{port_str})"
            self.send_res(response)
            self.in_pasv_mode = True

        except Exception as e:
            self.logger.error(f"Error in PASV: {e}")
            self.send_res("425 Can't open data connection")
            if self.data_transport:
                self.data_transport.close()
                self.data_transport = None

    @requires_auth
    def handle_RETR(self, file_name):
        try:
            if not self.in_pasv_mode:
                self.send_res("425 Use PASV first")
                return

            self.send_res("150 Opening data connection")
            conn, _ = self.data_transport.accept()
            file_path = self.file_sytem.get_file(file_name)

            with FileLock(file_path):
                with open(file_path, "rb") as f:
                    data = f.read(1024)
                    while data:
                        conn.send(data)
                        data = f.read(1024)

            conn.close()
            self.send_res("226 Transfer complete")

        except Exception as e:
            self.logger.error(f"Error in RETR: {e}")
            self.send_res("425 Can't open data connection")
            conn.close()

        finally:
            if self.data_transport:
                self.data_transport.close()
                self.data_transport = None

            self.in_pasv_mode = False

    @requires_auth
    def handle_STOR(self, file_name):
        try:
            if not self.in_pasv_mode:
                self.send_res("425 Use PASV first")
                return

            self.send_res("150 Opening data connection")
            conn, _ = self.data_transport.accept()
            file_path = self.file_sytem.create_file(self.file_sytem.current_ftp_dir,
                                                    file_name)

            print(file_path)
            with FileLock(f"{file_path}.lock"):
                with open(file_path, "wb") as f:
                    data = conn.receive(1024)
                    if not data:
                        pass
                    
                    while data:
                        f.write(data)
                        data = conn.receive(1024)

            conn.close()
            self.send_res("226 Transfer complete")

        except Exception as e:
            self.logger.error(f"Error in STOR: {e}")
            self.send_res("425 Can't open data connection")
            conn.close()

        finally:
            if self.data_transport:
                self.data_transport.close()
                self.data_transport = None

            self.in_pasv_mode = False

    @requires_auth
    def handle_LIST(self, path=None):
        if not path:
            path = self.file_sytem.current_ftp_dir

        self.send_res("150 Opening data connection")

        try:
            if self.in_pasv_mode:
                conn, _ = self.data_transport.accept()

            else:
                self.send_res("425 Use PASV first")
                return

            file_list = self.file_sytem.list_dir(path)
            
            listing = '\n'.join([
            f"{file['type']}{''.join(file['permissions'])} 1 {file['owner']} {file['group']} {file['size']} {file['date']} {file['name']}" 
            for file in file_list
        ])
            
            if listing:
                listing += '\n'

            conn.send(listing.encode("utf-8"))

            conn.close()
            self.data_transport.close()
            self.send_res("226 Transfer complete")

        except Exception as e:
            self.logger.error(f"Error in LIST: {e}")
            self.send_res("425 Can't open data connection")

    @requires_auth
    def handle_PWD(self):
        self.send_res(f"257 {self.file_sytem.current_ftp_dir}")
    
    @requires_auth
    def handle_TYPE(self, type_code):
        self.send_res("200 Type set to: " + type_code)

    @requires_auth
    def handle_CWD(self, path):
        try:
            self.file_sytem.change_dir(path)
            self.send_res("250 Directory successfully changed")

        except Exception as e:
            self.logger.error(f"Error in CWD: {e}")
            self.send_res("550 Failed to change directory")

    @requires_auth
    def handle_CDUP(self):
        try:
            self.file_sytem.change_dir("..")
            self.send_res("250 Directory successfully changed")

        except Exception as e:
            self.logger.error(f"Error in CDUP: {e}")
            self.send_res("550 Failed to change directory")

    @requires_auth
    def handle_MKD(self, *args):
        try:
            name = ' '.join(args)
            self.file_sytem.mkdir(name)
            self.send_res("257 Directory created")

        except Exception as e:
            self.logger.error(f"Error in MKD: {e}")
            self.send_res("550 Failed to create directory")

    @requires_auth
    def handle_RMD(self, path):
        try:
            self.file_sytem.remove_dir(path)
            self.send_res("250 Directory removed")

        except Exception as e:
            self.logger.error(f"Error in RMD: {e}")
            self.send_res("550 Failed to remove directory")

    @requires_auth
    def handle_DELETE(self, path):
        try:
            self.file_sytem.remove_file(path)
            self.send_res("250 File removed")

        except Exception as e:
            self.logger.error(f"Error in DELETE: {e}")
            self.send_res("550 Failed to remove file")

    def handle_FEAT(self):
        self.send_res("211-Features")
        for feature in self.features:
            self.send_res(f" {feature}")
        self.send_res("211 End")

    def handle_QUIT(self):
        self.send_res("221 Goodbye")
        self.control_transport.close()
