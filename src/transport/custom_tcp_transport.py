from .transport_interface import Transport
from typing import Tuple, Any
import logging
from src.core.tcp.tcp import TCPConnection
from src.common.utils import get_iface_ip, get_iface_mac, get_gateway_info
import os
from src.common.config import config_handler


class CustomTCPTransport(Transport):
    def __init__(self, tcp_connection=None):
        # abort if not on posix
        if not os.name == "posix":
            raise Exception(
                "Custom TCP transport only supported on POSIX systems"
            )

        self.addr = None
        self.tcp_connection = tcp_connection
        self.logger = logging.getLogger(__name__)
        self.sockname = None

    def connect(self, host: str, port: int) -> None:
        # for client
        raise NotImplementedError(
            "Client-side operations not implemented in custom TCP transport"
        )

    def send(self, data: bytes, push: bool = True) -> None:
        if not self.tcp_connection:
            raise Exception("Not connected")

        try:
            self.tcp_connection.send(data)

        except Exception as e:
            self.logger.error(f"Error sending data: {e}")
            raise

    def receive(self, buffer_size: int, time_out=5) -> bytes:
        if not self.tcp_connection:
            raise Exception("Not connected")

        try:
            return self.tcp_connection.receive(timeout=5)

        except Exception as e:
            self.logger.error(f"Error receiving data: {e}")
            raise

    def close(self) -> None:
        if self.tcp_connection:
            self.tcp_connection.close()
            self.tcp_connection = None

    def bind(self, host: str, port: int, interface: str = None) -> None:
        iface_config = config_handler.get("interface")
        
        if not interface and not iface_config:
            raise Exception("Interface not specified")
        
        if not interface:
            interface = iface_config
        
        iface_ip = get_iface_ip(interface)
        iface_mac = get_iface_mac(interface)
        _, gateway_mac = get_gateway_info(interface)

        self.tcp_connection = TCPConnection(
            iface=interface,
            iface_mac=iface_mac,
            iface_ip=iface_ip,
            gateway_mac=gateway_mac,
            listen_ip=host,
            listen_port=port,
            is_server=True,
            timeout=None,
        )
        
        self.sockname = (host, port)
        

    def listen(self, backlog: int = 1) -> None:
        if not self.tcp_connection:
            raise Exception("Not bound")

        try:
            self.tcp_connection.listen(backlog=backlog)

        except Exception as e:
            self.logger.error(f"Error listening: {e}")
            raise

    def accept(self) -> Tuple["CustomTCPTransport", Any]:
        if not self.tcp_connection:
            raise Exception("Not bound")

        try:
            client, addr = self.tcp_connection.accept()
            client = CustomTCPTransport(tcp_connection=client)
            client.sockname = self.sockname
            return client, addr

        except Exception as e:
            self.logger.error(f"Error accepting connection: {e}")
            raise
    
    def getsockname(self) -> Tuple[str, int]:
        if not self.sockname:
            raise Exception("Not bound")
        
        return self.sockname