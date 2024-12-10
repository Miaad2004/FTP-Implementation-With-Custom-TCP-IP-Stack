import logging
import random
from functools import wraps
import time
import atexit

from filelock import FileLock

from src.common.config import config_handler
from src.file_system.file_system import FileSystem
from src.transport.transport_interface import Transport

logging.basicConfig(level=logging.INFO)


class ClientHandler:
    """
    Handles client connections and commands for an FTP server.

    Attributes:
        transport (PythonSocketTransport): The transport layer for control
        connection.
        addr (tuple): The address of the client.
        server: The server instance.
        logger (logging.Logger): Logger for the client handler.
        authenticated (bool): Whether the client is authenticated.
        username (str): The username of the authenticated client.
        secured_data (bool): Whether the data connection is secured.
        secured_control (bool): Whether the control connection is secured.
        got_pbsz (bool): Whether the PBSZ command has been received.
        in_pasv_mode (bool): Whether the client is in passive mode.
        rename_from (str): The file to be renamed.
        show_hidden_files (bool): Whether to show hidden files in listings.
        use_mlsd_for_list (bool): Whether to use MLSD for directory listings.
        pasv_port_range_start (int): The start of the passive mode port range.
        pasv_port_range_end (int): The end of the passive mode port range.
        debug (bool): Whether debug mode is enabled.
        features (list): List of supported FTP features.
    """

    def __init__(self, transport: Transport, addr, server):
        """
        Initializes the ClientHandler.

        Args:
            transport (PythonSocketTransport): The transport layer for control
            connection.
            addr (tuple): The address of the client.
            server: The server instance.
        """
        atexit.register(self.at_exit)
        
        self.transport = transport.__class__
        self.control_transport = transport
        self.data_transport = None
        self.addr = addr
        self.server = server

        self.logger = logging.getLogger(f"ClientHandler-{addr}")

        self.authenticated = False
        self.username = None
        self.secured_data = False
        self.secured_control = False
        self.got_pbsz = False

        self.in_pasv_mode = False

        self.rename_from = None

        listing_options = config_handler.get("listing_options")
        self.show_hidden_files = listing_options.get("show_hidden")
        self.use_mlsd_for_list = listing_options.get("use_MLSD_for_LIST")

        pasv_ports = config_handler.get("pasv_ports")
        self.pasv_port_range_start = pasv_ports.get("start")
        self.pasv_port_range_end = pasv_ports.get("end")

        self.debug = config_handler.get("debug_mode")
        self.features = [
            "URF8",
            "PASV",
            "RNFR",
            "RNTO",
            "SITE CHMOD",
            "MLST type*;size*;modify*;perm*;unix.owner*;unix.group*",
        ]

        if config_handler.get("support_FTPS"):
            self.features.extend(["AUTH TLS", "PBSZ", "PROT"])

        if config_handler.get("implicit_tls") and \
           config_handler.get("support_FTPS"):
            self.secured_control = True

    def requires_auth(func):
        """
        Decorator to ensure the client is authenticated before executing the
        command.
        """

        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if not self.authenticated:
                self.send_res("530 Not logged in.")
                return

            return func(self, *args, **kwargs)

        return wrapper

    def send_res(self, res):
        """
        Sends a response to the client.

        Args:
            res (str): The response message.
        """
        self.logger.info(f"Sending res: {res}")
        encoded_res = (res + "\r\n").encode("utf-8")
        self.control_transport.send(encoded_res)

    def run(self):
        """
        Runs the client handler, processing commands from the client.
        """
        with FileSystem() as fs:
            self.file_system = fs
            self.send_res("220 Welcome to FTP server")

            while True:
                try:
                    data = self.control_transport.receive(1024)
                    if not data:
                        continue
                    
                    data = data.decode("utf-8").strip()

                    self.logger.info(f"Received cmd {data}")
                    self.handle_cmd(data)

                except Exception as e:
                    self.logger.error(f"Error: {e}")

                    if self.debug:
                        raise e

            self.control_transport.close()

    def handle_cmd(self, cmd):
        """
        Handles a command from the client.

        Args:
            cmd (str): The command string.
        """
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

            if self.debug:
                raise e

    def handle_USER(self, username):
        """
        Handles the USER command.

        Args:
            username (str): The username provided by the client.
        """
        try:
            if not self.authenticated:
                self.send_res("331 User name okay, need password.")

            else:
                self.flush_session()
                msg = "Previous authentication flushed."
                self.send_res(f"331 {msg} User name okay, need password.")

            self.username = username

        except Exception as e:
            self.logger.error(f"Error in USER: {e}")

            if self.debug:
                raise e

    def handle_PASS(self, password):
        """
        Handles the PASS command.

        Args:
            password (str): The password provided by the client.
        """
        try:
            if not self.username:
                self.send_res("503 Bad sequence of commands.")
                return

            if self.authenticated:
                self.send_res("503 Bad sequence of commands.")
                return

            if self.file_system.auth_login(self.username, password):
                self.authenticated = True
                self.send_res("230 User logged in, proceed.")

            else:
                self.send_res("530 invalid password")

        except Exception as e:
            self.logger.error(f"Error in PASS: {e}")
            self.send_res("530 invalid password")

            if self.debug:
                raise e

    def handle_AUTH(self, *args):
        """
        Handles the AUTH command.

        Args:
            args: The arguments provided with the AUTH command.
        """
        if not config_handler.get("support_FTPS"):
            self.send_res("502 Command not implemented")
            return

        if args[0].upper() == "TLS":
            try:
                self.flush_session()
                self.send_res("234 Ready for TLS")
                self.control_transport.upgrade_to_secure(
                    self.server.ssl_context
                )
                self.secured_control = True

            except Exception as e:
                self.logger.error(f"TLS negotiation failed: {e}")
                self.send_res("550 TLS negotiation failed")

                if self.debug:
                    raise e

        else:
            self.send_res("502 Unrecognized AUTH type")

    def handle_PBSZ(self, *args):
        """
        Handles the PBSZ command.

        Args:
            args: The arguments provided with the PBSZ command.
        """
        if not config_handler.get("support_FTPS"):
            self.send_res("502 Command not implemented")
            return

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

            if self.debug:
                raise e

    def handle_PROT(self, *args):
        """
        Handles the PROT command.

        Args:
            args: The arguments provided with the PROT command.
        """
        if not config_handler.get("support_FTPS"):
            self.send_res("502 Command not implemented")
            return

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

            if self.debug:
                raise e

    @requires_auth
    def handle_PASV(self):
        """
        Handles the PASV command, entering passive mode.
        """
        max_attempts = 10
        attempt = 0

        while attempt < max_attempts:
            try:
                self.data_transport = self.transport()
                if not self.data_transport:
                    raise RuntimeError("Failed to create data transport")

                port = random.randint(
                    self.pasv_port_range_start, self.pasv_port_range_end
                )
                self.logger.info(
                    f"Listening for passive mode connection on  {self.server.host}:{port}"
                )

                self.data_transport.bind(self.server.host, port)
                self.data_transport.listen()
                ip, port = self.data_transport.getsockname()
                self.in_pasv_mode = True

                ip_parts = ip.split(".")
                port_parts = [str(port >> 8), str(port & 0xFF)]

                ip_str = ",".join(ip_parts)
                port_str = ",".join(port_parts)
                response = f"227 Entering Passive Mode ({ip_str},{port_str})"
                self.send_res(response)
                return

            except Exception as e:
                self.logger.error(
                    f"PASV attempt {attempt + 1} failed: {str(e)}"
                )
                if self.data_transport:
                    self.data_transport.close()
                    self.data_transport = None

                attempt += 1
                if attempt >= max_attempts:
                    self.send_res("425 Can't open data connection")
                    return

        self.send_res("425 Can't open data connection")

    @requires_auth
    def handle_RETR(self, file_path):
        """
        Handles the RETR command, retrieving a file.

        Args:
            file_path (str): The path of the file to retrieve.
        """
        try:
            if not self.in_pasv_mode:
                self.send_res("425 Use PASV first")
                return

            self.send_res("150 Opening data connection")
            conn, _ = self.data_transport.accept()

            if self.secured_data:
                conn.upgrade_to_secure(self.server.ssl_context)

            file_info = self.file_system.read_file(file_path)
            file_path = str(file_info["path"])

            with open(file_path, "rb") as f:
                while True:
                    data = f.read(1024)
                    if not data:
                        break

                    conn.send(data)

            self.send_res("226 Transfer complete")

        except Exception as e:
            self.logger.error(f"Error in RETR: {e}")
            self.send_res("425 Can't open data connection")

            if self.debug:
                raise e

        finally:
            conn.close()

            if self.data_transport:
                self.data_transport.close()
                self.data_transport = None

            self.in_pasv_mode = False

    @requires_auth
    def handle_STOR(self, *args):
        """
        Handles the STOR command, storing a file.

        Args:
            args: The arguments provided with the STOR command.
        """
        try:
            if not self.in_pasv_mode:
                self.send_res("425 Use PASV first")
                return

            path = " ".join(args)

            self.send_res("150 Opening data connection")
            conn, _ = self.data_transport.accept()

            if self.secured_data:
                conn.upgrade_to_secure(self.server.ssl_context)

            file_info = self.file_system.create_file(
                path, anonymous_accesslevel="r--"
            )
            file_path = file_info["path"]

            with FileLock(f"{file_path}.lock"):
                with open(file_path, "wb") as f:
                    while True:
                        data = conn.receive(20048)
                        if not data:
                            break
                        f.write(data)

            self.send_res("226 Transfer complete")

        except Exception as e:
            self.logger.error(f"Error in STOR: {e}")
            self.send_res("425 Can't open data connection")

            if self.debug:
                raise e

        finally:
            conn.close()

            if self.data_transport:
                self.data_transport.close()
                self.data_transport = None

            self.in_pasv_mode = False

    @requires_auth
    def handle_MLSD(self, path=None):
        """
        Handles the MLSD command, listing directory contents in machine-
        readable format.

        Args:
            path (str, optional): The path of the directory to list.
                Defaults to None.
        """
        self.send_res("150 Opening data connection")

        try:
            if self.in_pasv_mode:
                conn, _ = self.data_transport.accept()

                if self.secured_data:
                    conn.upgrade_to_secure(self.server.ssl_context)

            else:
                self.send_res("425 Use PASV first")
                return

            # Get machine readable directory listing
            mlsd_list = self.file_system.mlsd_dir(path)

            for f in mlsd_list:
                f += "\r\n"
                conn.send(f.encode("utf-8"))

            self.send_res("226 Transfer complete")

        except Exception as e:
            self.logger.error(f"Error in MLSD: {e}")
            self.send_res("425 Can't open data connection")

            if self.debug:
                raise e

        finally:
            time.sleep(0.5)
            conn.close()

            if self.data_transport:
                self.data_transport.close()
                self.data_transport = None

            self.in_pasv_mode = False

    @requires_auth
    def handle_LIST(self, path=None):
        """
        Handles the LIST command, listing directory contents.

        Args:
            path (str, optional): The path of the directory to list.
                Defaults to None.
        """
        if self.use_mlsd_for_list:
            self.handle_MLSD(path)
            return

        self.send_res("150 Opening data connection")

        try:
            if self.in_pasv_mode:
                conn, _ = self.data_transport.accept()

                if self.secured_data:
                    conn.upgrade_to_secure(self.server.ssl_context)

            else:
                self.send_res("425 Use PASV first")
                return

            file_list = self.file_system.list_dir(path)

            for file in file_list:
                info = (
                    f"{file['type']}{''.join(file['permissions'])} 1 "
                    f"{file['owner']} {file['group']} {file['size']} "
                    f"{file['date']} {file['name']}\r\n"
                )
                conn.send(info.encode("utf-8"))

            self.send_res("226 Transfer complete")

        except Exception as e:
            self.logger.error(f"Error in LIST: {e}")
            self.send_res("425 Can't open data connection")

            if self.debug:
                raise e

        finally:
            conn.close()

            if self.data_transport:
                self.data_transport.close()
                self.data_transport = None

            self.in_pasv_mode = False

    @requires_auth
    def handle_PWD(self):
        """
        Handles the PWD command, printing the current directory.
        """
        self.send_res(
            f'257 "{self.file_system.current_ftp_dir}" '
            f'is the current directory'
        )

    @requires_auth
    def handle_TYPE(self, type_code):
        """
        Handles the TYPE command, setting the transfer type.

        Args:
            type_code (str): The type code to set.
        """
        self.send_res("200 Type set to " + type_code)

    @requires_auth
    def handle_CWD(self, *args):
        """
        Handles the CWD command, changing the current directory.

        Args:
            args: The path to change to.
        """
        try:
            path = " ".join(args)
            self.file_system.change_dir(path)
            self.send_res("250 Directory successfully changed")

        except Exception as e:
            self.logger.error(f"Error in CWD: {e}")
            self.send_res("550 Failed to change directory")

            if self.debug:
                raise e

    @requires_auth
    def handle_CDUP(self):
        """
        Handles the CDUP command, changing to the parent directory.
        """
        try:
            self.file_system.change_dir("..")
            self.send_res("250 Directory successfully changed")

        except Exception as e:
            self.logger.error(f"Error in CDUP: {e}")
            self.send_res("550 Failed to change directory")

            if self.debug:
                raise e

    @requires_auth
    def handle_MKD(self, *args):
        """
        Handles the MKD command, creating a new directory.

        Args:
            args: The name of the directory to create.
        """
        try:
            name = " ".join(args)
            self.file_system.mkdir(name, anonymous_accesslevel="r--")
            self.send_res("257 Directory created")

        except Exception as e:
            self.logger.error(f"Error in MKD: {e}")
            self.send_res("550 Failed to create directory")

            if self.debug:
                raise e

    @requires_auth
    def handle_RMD(self, path):
        """
        Handles the RMD command, removing a directory.

        Args:
            path (str): The path of the directory to remove.
        """
        try:
            self.file_system.rmdir(path)
            self.send_res("250 Directory removed")

        except Exception as e:
            self.logger.error(f"Error in RMD: {e}")
            self.send_res("550 Failed to remove directory")

            if self.debug:
                raise e

    @requires_auth
    def handle_DELE(self, path):
        """
        Handles the DELE command, deleting a file.

        Args:
            path (str): The path of the file to delete.
        """
        try:
            self.file_system.delete_file(path)
            self.send_res("250 File removed")

        except Exception as e:
            self.logger.error(f"Error in DELETE: {e}")
            self.send_res("550 Failed to remove file")

            if self.debug:
                raise e

    def handle_FEAT(self):
        """
        Handles the FEAT command, listing supported features.
        """
        self.send_res("211-Features")
        for feature in self.features:
            self.send_res(f" {feature}")
        self.send_res("211 End")

    def handle_QUIT(self):
        """
        Handles the QUIT command, closing the connection.
        """
        self.send_res("221 Goodbye")
        self.control_transport.close()

    @requires_auth
    def handle_SYST(self):
        """
        Handles the SYST command, returning system type.
        """
        self.send_res("215 UNIX Type: L8")

    @requires_auth
    def handle_OPTS(self, *args):
        """
        Handles the OPTS command, setting options.

        Args:
            args: The options to set.
        """
        try:
            if (len(args) == 2 and
                    args[0].upper() == "UTF8" and
                    args[1].upper() == "ON"):
                self.send_res("200 Always in UTF8 mode")

            else:
                self.send_res("501 Option not supported")

        except Exception as e:
            self.logger.error(f"Error in OPTS: {e}")
            self.send_res("501 Option not supported")

            if self.debug:
                raise e

    @requires_auth
    def handle_HELP(self, *args):
        """
        Handles the HELP command, listing available commands or providing help
        for a specific command.

        Args:
            args: The command to provide help for.
        """
        if not args:
            commands = [
                cmd[7:] for cmd in dir(self) if cmd.startswith("handle_")
            ]
            self.send_res("214-The following commands are supported:")
            for cmd in commands:
                self.send_res(f" {cmd}")
            self.send_res("214 End of help.")

        else:
            cmd = args[0].upper()
            handler = getattr(self, f"handle_{cmd}", None)
            if handler and handler.__doc__:
                self.send_res(f"214 {handler.__doc__}")
            else:
                self.send_res(f"504 Command {cmd} not implemented")

    @requires_auth
    def handle_RNFR(self, *args):
        """
        Handles the RNFR command, specifying the file to rename.

        Args:
            args: The path of the file to rename.
        """
        try:
            path = " ".join(args)
            # Verify file exists
            _ = self.file_system.read_file(path)
            self.rename_from = path
            self.send_res("350 Ready for RNTO")

        except Exception as e:
            self.logger.error(f"Error in RNFR: {e}")
            self.send_res("550 RNFR command failed")
            self.rename_from = None

            if self.debug:
                raise e

    @requires_auth
    def handle_RNTO(self, *args):
        """
        Handles the RNTO command, renaming a file.

        Args:
            args: The new name for the file.
        """
        try:
            if not self.rename_from:
                self.send_res("503 Bad sequence of commands - use RNFR first")
                return

            new_name = " ".join(args)
            self.file_system.rename(self.rename_from, new_name)
            self.send_res("250 Rename successful")

        except Exception as e:
            self.logger.error(f"Error in RNTO: {e}")
            self.send_res("553 RNTO command failed")
            if self.debug:
                raise e

        finally:
            self.rename_from = None

    @requires_auth
    def handle_SITE(self, *args):
        """
        Handles the SITE command, executing site-specific commands.

        Args:
            args: The site-specific command and its arguments.
        """
        if not args:
            self.send_res("501 Syntax error in parameters")
            return

        cmd = args[0].upper()
        if cmd == "CHMOD":
            try:
                if len(args) < 3:
                    self.send_res("501 Syntax error in parameters")
                    return

                mode = args[1]
                path = " ".join(args[2:])

                try:
                    mode_int = int(mode, 8)

                    user = (mode_int & 0o700) >> 6
                    group = (mode_int & 0o070) >> 3
                    others = mode_int & 0o007

                    def octal_to_rwx(num):
                        r = "r" if num & 0o4 else "-"
                        w = "w" if num & 0o2 else "-"
                        x = "x" if num & 0o1 else "-"
                        return r + w + x

                    user_perms = octal_to_rwx(user)
                    _ = octal_to_rwx(group)
                    others_perms = octal_to_rwx(others)

                    self.file_system.chmod(
                        target_path=path,
                        target_username=self.username,
                        permissions=user_perms,
                        public_permissions=others_perms,
                    )

                    self.send_res("200 SITE CHMOD command successful")

                except ValueError:
                    self.send_res("501 Invalid mode format")

            except Exception as e:
                self.logger.error(f"Error in SITE CHMOD: {e}")
                self.send_res("550 SITE CHMOD command failed")

                if self.debug:
                    raise e
        else:
            self.send_res(
                "504 SITE command not implemented for this parameter"
            )

    def flush_session(self):
        """
        Flushes the current session, resetting authentication and security
        states.
        """
        # Authentication state
        self.authenticated = False
        self.username = None

        # Security flags
        self.secured_data = False
        self.secured_control = False
        self.got_pbsz = False

        # Data transfer state
        self.in_pasv_mode = False
        if self.data_transport:
            self.data_transport.close()
            self.data_transport = None

        # Clear rename operation
        self.rename_from = None

        # Log the flush
        self.logger.info("Session flushed")

        try:
            # Reset filesystem state
            self.file_system.auth_logout()
        except Exception as e:
            self.logger.error(f"Error during filesystem logout: {e}")
            if self.debug:
                raise e

    def handle_REIN(self):
        """
        Handles the REIN command, reinitializing the session.
        """
        self.flush_session()
        self.send_res("220 Service ready for new user.")

    def handle_NOOP(self, *args):
        """
        Handles the NOOP command, doing nothing.

        Args:
            args: The arguments provided with the NOOP command.
        """
        self.send_res("200 NOOP command successful")

    def handle_ALLONE(self, *args):
        """
        Handles the ALLONE command, indicating it is not implemented.

        Args:
            args: The arguments provided with the ALLONE command.
        """
        self.send_res("202 Command not implemented, superfluous at this site.")
    
    def at_exit(self):
        self.logger.debug("Trying to close all sockets....")
        try:
            self.control_transport.close()
        
        except Exception:
            pass
        
        try:
            self.data_transport.close()
        
        except Exception:
            pass
