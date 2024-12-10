import socket
import random
import time
import threading
import signal
import logging
from typing import List, Optional, Dict
import heapq

from src.core.ipv4.ip_header import IPHeader
from src.core.ipv4.ip_protocol import IPProtocol
from src.core.ipv4.ip_packet import IPPacket
from src.core.ethernet.frame import EthernetFrame
from src.core.ethernet.ether_type import EthernetType
from src.common.utils import get_current_time, get_gateway_info, get_iface_ip, get_iface_mac

from .tcp_header import TCPHeader
from .connection_state import ConnectionState
from .tcp_packet import TCPPacket


# set log level
logging.basicConfig(level=logging.DEBUG)

class TCB:
    def __init__(self):
        """
        Initializes a new Transmission Control Block (TCB) instance.
        """
        self.send_buffer: List[bytes] = []
        self.receive_buffer: Dict[int, bytes] = {}
        self.current_segment: Optional[bytes] = None
        self.connection_state: int = ConnectionState.NOT_INITIALIZED
        
        self._initial_our_seq_number: int = random.randint(0, 2**32 - 1)
        self.our_seq_number: int = self._initial_our_seq_number
        self._initial_peer_seq_number: Optional[int] = None
        self._peer_seq_number: Optional[int] = None
        self.peer_seq_number: Optional[int] = None
        self.last_received_ack: int = self.our_seq_number
        
        self.max_retransmissions: int = 5
        self.retransmission_timeout: int = 5
        self.keep_alive_timeout: int = 50
        self.last_activity_time: Optional[float] = None
        
        self.send_window: int = 0  
        self.recv_window: int = 65535 
    
    @property
    def initial_our_seq_number(self) -> int:
        """
        Returns the initial sequence number for our side of the connection.
        """
        return self._initial_our_seq_number
    
    @property
    def initial_peer_seq_number(self) -> Optional[int]:
        """
        Returns the initial sequence number for the peer side of the connection.
        """
        return self._initial_peer_seq_number
    
    @property
    def peer_seq_number(self) -> Optional[int]:
        """
        Returns the current sequence number for the peer side of the connection.
        """
        return self._peer_seq_number
    
    @peer_seq_number.setter
    def peer_seq_number(self, value: Optional[int]) -> None:
        """
        Sets the sequence number for the peer side of the connection.
        If the initial peer sequence number is not set, it will be set to the given value.
        
        :param value: The sequence number to set for the peer side.
        """
        if self._initial_peer_seq_number is None and value is not None:
            self._initial_peer_seq_number = value
            
        self._peer_seq_number = value


class TCPConnection:
    """
    Simple TCP implementation using raw sockets.

    * Doesn't support packet fragmentation
    * Doesn't support flow control
    * Doesn't support congestion control
    * Doesn't support options in TCP header
    * Supports handshaking, simple data transfer, graceful close, retransmission, and abort
    """

    def __init__(
        self,
        iface: str,
        iface_mac: str,
        iface_ip: str,
        gateway_mac: str,
        is_server: bool,
        listen_ip: Optional[str] = None,
        listen_port: Optional[int] = None,
        dest_ip: Optional[str] = None,
        source_port: Optional[int] = None,
        dest_port: Optional[int] = None,
        timeout: Optional[int] = None,
    ):
        """
        Initialize a TCPConnection instance.

        :param iface: Network interface name.
        :param iface_mac: MAC address of the network interface.
        :param iface_ip: IP address of the network interface.
        :param gateway_mac: MAC address of the gateway.
        :param is_server: Boolean indicating if the instance is a server.
        :param listen_ip: IP address to listen on (server mode).
        :param listen_port: Port to listen on (server mode).
        :param dest_ip: Destination IP address (client mode).
        :param source_port: Source port (client mode).
        :param dest_port: Destination port (client mode).
        :param timeout: Timeout for socket operations.
        """
        if is_server and (not listen_ip or not listen_port):
            raise ValueError("Server mode requires listen IP and port")
        
        if not is_server and (not dest_ip or not source_port or not dest_port):
            raise ValueError("Client mode requires destination IP, source port, and destination port")
        
        self.is_server = is_server
        
        if is_server:
            self.logger = logging.getLogger(f"TCPListener-{listen_ip}:{listen_port}")
        
        else:
            self.logger = logging.getLogger(f"TCPConnection-{source_port}:{dest_ip}:{dest_port}")
        
        # iface and gateway details
        self.interface = iface
        self.iface_mac = iface_mac
        self.iface_ip = iface_ip
        self.gateway_mac = gateway_mac
        
        # Connection details
        self.listen_ip = listen_ip 
        self.listen_port = listen_port
        
        self.dest_ip = dest_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.timeout = timeout
        
        # TCB (Transmission Control Block)
        self.tcb = TCB()
        
        # Threads for listening and timing (retransmission, keep alive, etc.)
        self.listener_thread = threading.Thread(target=self._listen, args=(timeout,))
        self.timer_thread = threading.Thread(target=self._timer)
        
        # In Linux "Receiving of all IP protocols via IPPROTO_RAW is not possible using raw sockets."
        # Source: https://stackoverflow.com/questions/40795772/cant-receive-packets-to-raw-socket
        # So I used one raw socket (IPPROTO_RAW) for sending (with custom IP header)
        # and another raw socket (IPPROTO_TCP) for receiving TCP packets
        self.send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    @property
    def receive_buffer(self) -> bytes:
        """
        Get the receive buffer.

        :return: The receive buffer.
        """
        return self.tcb.receive_buffer
    
    @property
    def connection_state(self) -> ConnectionState:
        """
        Get the connection state.

        :return: The connection state.
        """
        return self.tcb.connection_state
    
    @connection_state.setter
    def connection_state(self, state: ConnectionState) -> None:
        """
        Set the connection state.

        :param state: The new connection state.
        """
        self.tcb.connection_state = state
    
    def create_packet(self, SYN: bool, ACK: bool, FIN: bool, RST: bool, payload: bytes = b"") -> TCPPacket:
        """
        Create a TCP packet.

        :param SYN: SYN flag.
        :param ACK: ACK flag.
        :param FIN: FIN flag.
        :param RST: RST flag.
        :param payload: Payload data.
        :return: The created TCP packet.
        """
        tcp_header = TCPHeader(self.iface_ip,
                               self.dest_ip,
                               self.source_port,
                               self.dest_port)

        tcp_header.SYN = SYN
        tcp_header.ACK = ACK
        tcp_header.FIN = FIN
        tcp_header.RST = RST
        tcp_header.window = self.tcb.recv_window - len(self.tcb.receive_buffer)
        tcp_header.sequence_number = self.tcb.our_seq_number

        if ACK:
            tcp_header.ack_number = self.tcb.peer_seq_number

        tcp_packet = TCPPacket(tcp_header, payload)

        return tcp_packet

    def send_packet(self, tcp_packet: TCPPacket, is_retransmission: bool = False) -> None:
        """
        Send a TCP packet.

        :param tcp_packet: The TCP packet to send.
        :param is_retransmission: Boolean indicating if the packet is a retransmission.
        """
        tcp_packet.send_or_recv_time = time.time()
        tcp_packet_built = tcp_packet.build_packet()

        # Create IP header
        ip_header = IPHeader(self.iface_ip, self.dest_ip, IPProtocol.TCP)
        ip_packet = IPPacket(ip_header, tcp_packet_built).packet

        # create Ethernet header
        frame = EthernetFrame(
            self.iface_mac,
            self.gateway_mac,
            ip_packet,
            EthernetType.IPv4,
            use_software_crc=False,
        ).frame

        # port is set to 0 because we are sending raw IP packets
        self.send_sock.sendto(frame, (self.interface, 0))

        if not is_retransmission:
            # update our sequence number
            if tcp_packet.header.SYN or tcp_packet.header.FIN:
                self.tcb.our_seq_number += 1

            if len(tcp_packet.payload) > 0:
                self.tcb.our_seq_number += len(tcp_packet.payload)

        # # Schedule retransmission
        # timer = threading.Timer(self.retransmission_timeout, self._retransmit_packet, args=(tcp_packet,))
        # tcp_packet.timer = timer
        # timer.start()

    def _listen(self, timeout: int = 1, bind: bool = False) -> None:
        """
        Listen for incoming packets.

        :param timeout: Timeout for socket operations.
        :param bind: Boolean indicating if the socket should be bound.
        """
        self.recv_socket.settimeout(timeout)
        
        if self.is_server:
            try:
                self.recv_socket.bind((self.listen_ip, self.listen_port))
                
            except OSError as e:
                self.logger.error(f"Error binding socket: {e}")
                raise
            
            self.logger.info(f"Listening for incoming connections on {self.listen_ip}:{self.listen_port}")

        while self.connection_state != ConnectionState.CLOSED:
            try:
                packet = self.recv_socket.recv(4096)
                ip_header, tcp_header, payload, checksums_correct = self._parse_packet(packet)
                
                if not checksums_correct:
                    #self.logger.warning("a packet with an incorrect IP or TCP checksum was received")
                    continue
                
                # Filter packets based on mode
                if self.is_server:
                    # In server mode, accept packets to our listening port
                    if tcp_header.dest_port != self.listen_port:
                        continue
                else:
                    # In client mode, verify source/dest ports match connection
                    if (tcp_header.source_port != self.dest_port or 
                        tcp_header.dest_port != self.source_port):
                        continue

                # packet verified
                self.tcb.last_activity_time = time.time()

                if self.tcb.initial_peer_seq_number:
                    self.logger.debug(f"Packet received. seq number: {tcp_header.sequence_number - self.tcb.initial_peer_seq_number}")

                threading.Thread(target=self._handle_packet, args=(ip_header, tcp_header, payload)).start()

            except socket.timeout:
                self.logger.warning("Timeout occurred")    
                continue

    def _timer(self):
        while self.connection_state != ConnectionState.CLOSED:
            # Handle keep-alive
            if self.connection_state == ConnectionState.ESTABLISHED:
                if (time.time() - self.tcb.last_activity_time > self.tcb.keep_alive_timeout):
                    packet = self.create_packet(SYN=False, ACK=True, FIN=False, RST=False)
                    packet.header.sequence_number = self.tcb.our_seq_number - 1
                    self.send_packet(packet)
                    self.tcb.last_activity_time = time.time()

                    self.logger.info("Keep-alive packet sent")

    def _handle_packet(self, ip_header, tcp_header, payload):
        if tcp_header.SYN and not tcp_header.ACK:
            self.logger.debug("SYN packet received")
            self.on_SYN_received(ip_header, tcp_header, payload)
            return
    
        # Check sequence number
        if self.connection_state == ConnectionState.ESTABLISHED:
            # check for incoming keep-alive packets
            if tcp_header.sequence_number == self.tcb.peer_seq_number - 1:
                self.logger.debug("Keep-alive packet received")
                self.on_keep_alive_received(ip_header, tcp_header, payload)
                return

            elif tcp_header.sequence_number != self.tcb.peer_seq_number:
                self.logger.warning(f"Invalid sequence number. Expected: {self.tcb.peer_seq_number - self.tcb.initial_peer_seq_number}, got: {tcp_header.sequence_number - self.tcb.initial_peer_seq_number}")
                #return

        # Check ack number if ack is set
        if tcp_header.ACK:
            if tcp_header.ack_number != self.tcb.our_seq_number:
                self.logger.warning(f"Invalid ack number. Expected: {self.tcb.our_seq_number}, got: {tcp_header.ack_number}")
                #return
        
        # RST
        if tcp_header.RST:
            self.on_reset_received(ip_header, tcp_header, payload)
            return

        # SYN-ACK
        if tcp_header.SYN and tcp_header.ACK:
            self.on_SYN_ACK_received(ip_header, tcp_header, payload)
            self.logger.debug("SYN-ACK received")

        # ACK
        if tcp_header.ACK:
            self.on_ACK_received(ip_header, tcp_header, payload)

        # Data
        if len(payload) > 0:
            self.on_data_received(ip_header, tcp_header, payload)
            self.logger.debug("Data received")

        # FIN
        if tcp_header.FIN:
            self.on_FIN_received(ip_header, tcp_header, payload)
            self.logger.debug("FIN received")
            return

    def on_SYN_received(self, ip_header: IPHeader, tcp_header: TCPHeader, payload: bytes):
        if self.connection_state != ConnectionState.LISTEN:
            return
    
        # Create new connection for client
        client_conn = TCPConnection(iface=self.interface,
                                    iface_ip=self.iface_ip,
                                    iface_mac=self.iface_mac,
                                    gateway_mac=self.gateway_mac,
                                    is_server=False,
                                    dest_ip=ip_header.source_ip,
                                    source_port=self.listen_port,
                                    dest_port=tcp_header.source_port)

        # Update the cleint's TCB
        client_conn.tcb.peer_seq_number = tcp_header.sequence_number  + 1
        client_conn.connection_state = ConnectionState.SYN_RECEIVED
    
        client_conn.on_conn_accepted()
        self.pending_connections.append(client_conn)
    
    def on_keep_alive_received(self, ip_header, tcp_header, payload):
        # send ack
        packet = self.create_packet(SYN=False, ACK=True, FIN=False, RST=False)
        self.send_packet(packet)

    def on_reset_received(self, ip_header, tcp_header, payload):
        self.logger.critical("Connection reset by peer")
        self.connection_state = ConnectionState.CLOSED
    
    def on_SYN_ACK_received(self, ip_header, tcp_header, payload):
        if self.connection_state == ConnectionState.SYN_SENT:
            # set server sequence number
            self.tcb.peer_seq_number = tcp_header.sequence_number

            # Add one because server sent SYN
            self.tcb.peer_seq_number += 1

            self.logger.debug(f"server seq number after SYN-ACK: {self.tcb.peer_seq_number - self.tcb.initial_peer_seq_number}")
            ack_packet = self.create_packet(SYN=False, ACK=True, FIN=False, RST=False)
            self.send_packet(ack_packet)

            self.connection_state = ConnectionState.ESTABLISHED

            self.logger.info("Connection established")

        else:
            self.logger.warning("Invalid SYN-ACK received. (state is not SYN_SENT)")

    def on_ACK_received(self, ip_header, tcp_header, payload):
        self.tcb.send_window = tcp_header.window
        
        # Update server sequence number
        if self.connection_state == ConnectionState.ESTABLISHED:
            # self.tcb.peer_seq_number = tcp_header.sequence_number
            # To DO: handle retransmission
            self.logger.debug(f"ACK received. seq number: {self.tcb.peer_seq_number - self.tcb.initial_peer_seq_number}")


        # handle ACK to our FIN-ACK
        if self.connection_state == ConnectionState.WAITING_FOR_FINAL_ACK:
            self.connection_state = ConnectionState.CLOSED
            self.logger.info("Connection closed")
        
        # handle ACK to our SYN-ACK
        elif self.connection_state == ConnectionState.SYN_ACK_SENT:
            self.connection_state = ConnectionState.ESTABLISHED
            self.logger.info("Connection established")

    def on_data_received(self, ip_header, tcp_header, payload):
        if self.connection_state == ConnectionState.ESTABLISHED:
            if tcp_header.sequence_number < self.tcb.peer_seq_number:
                self.logger.debug("Duplicate data segment received")
                return
            
            #self.tcb.recv_window -= len(payload)
            
            self.tcb.peer_seq_number += len(payload)
            self.receive_buffer[tcp_header.sequence_number] = payload
            
            # send ACK
            packet = self.create_packet(SYN=False, ACK=True, FIN=False, RST=False)
            self.send_packet(packet)

    def on_FIN_received(self, ip_header, tcp_header, payload):
        if self.connection_state == ConnectionState.ESTABLISHED:
            self.logger.debug("FIN received")

            self.tcb.peer_seq_number += 1

            # send FIN-ACK
            packet = self.create_packet(SYN=False, ACK=True, FIN=True, RST=False)
            self.send_packet(packet)

            self.connection_state = ConnectionState.WAITING_FOR_FINAL_ACK
            self.logger.debug("Transitioned to WAITING_FOR_FINAL_ACK")

        elif self.connection_state == ConnectionState.CLOSING:
            self.tcb.peer_seq_number += 1

            # send final ACK
            packet = self.create_packet(SYN=False, ACK=True, FIN=False, RST=False)
            self.send_packet(packet)

            self.connection_state = ConnectionState.CLOSED
            self.logger.info("Connection closed")

        else:
            self.logger.warning("Invalid FIN received. (state is not ESTABLISHED/CLOSING)")
    
    def on_conn_accepted(self):
        if not self.connection_state == ConnectionState.SYN_RECEIVED:
            return 
        
        self.listener_thread.start()
        self.timer_thread.start()
        
        # send SYN-ACK
        self.connection_state = ConnectionState.SYN_ACK_SENT
        packet = self.create_packet(SYN=True, ACK=True, FIN=False, RST=False)
        self.send_packet(packet)
    
    @staticmethod
    def _parse_packet(packet):
        if len(packet) < 40:
            raise ValueError("Packet is too small to be a TCP packet")
        
        ip_header_length = IPHeader.get_header_length(packet)
        ip_header, ih_checksum_correct = IPHeader.from_bytes(packet[:ip_header_length])
        tcp_packet_encoded = packet[ip_header_length:]
        tcp_packet_decoded, is_tcp_checksum_correct = TCPPacket.from_bytes(tcp_packet_encoded, ip_header.source_ip, ip_header.destination_ip)
        
        is_packet_valid = ih_checksum_correct and is_tcp_checksum_correct

        return ip_header, tcp_packet_decoded.header, tcp_packet_decoded.payload, is_packet_valid

    def on_terminate_signal(self):
        try:
            self.abort()
            self.send_sock.close()
            self.recv_socket.close()
            self.connection_state = ConnectionState.CLOSED
        
        except Exception as e:
            self.logger.error(f"Error terminating connection: {e}")
            pass

    # *** User methods ***
    def listen(self, backlog=1):
        if not self.is_server:
            raise Exception("Server mode required to listen")
        
        if self.connection_state not in [ConnectionState.CLOSED, ConnectionState.NOT_INITIALIZED]:
            raise Exception("Connection already in use")
        
        self.backlog = backlog
        self.pending_connections = []
        
        self.connection_state = ConnectionState.LISTEN
        
        if not self.listener_thread.is_alive():
            self.listener_thread.start()
            self.timer_thread.start()

    def accept(self, timeout=None) -> 'TCPConnection':
        if not self.is_server:
            raise Exception("Server mode required to accept connections")
        
        if self.connection_state != ConnectionState.LISTEN:
            raise Exception("Socket not listening")
    
        start_time = time.time()
    
        while True:
            # Check for pending connections that have completed the handshake
            for client in self.pending_connections.copy():
                if client.connection_state == ConnectionState.ESTABLISHED:
                    self.pending_connections.remove(client)
                    addr = (client.dest_ip, client.dest_port)
                    return client, addr
    
            if timeout and (time.time() - start_time > timeout):
                raise TimeoutError("Accept timed out")
    
            time.sleep(0.1)
        
    def open(self, wait_until_established=True, timeout=5):
        if self.is_server:
            raise Exception("Server mode cannot open connection")
        
        if self.connection_state not in [ConnectionState.CLOSED,ConnectionState.NOT_INITIALIZED,]:
            raise Exception("Connection already open")

        self.listener_thread.start()
        self.timer_thread.start()

        send_time = time.time()
        self.connection_state = ConnectionState.SYN_SENT
        packet = self.create_packet(SYN=True, ACK=False, FIN=False, RST=False)
        self.send_packet(packet)

        if wait_until_established:
            while self.connection_state != ConnectionState.ESTABLISHED:
                if time.time() - send_time > timeout:
                    raise TimeoutError("Connection establishment timed out")

                time.sleep(0.1)

    def close(self):
        if self.connection_state != ConnectionState.ESTABLISHED:
            raise Exception("Connection not established")

        packet = self.create_packet(SYN=False, ACK=True, FIN=True, RST=False)
        self.send_packet(packet)
        self.connection_state = ConnectionState.CLOSING

        # Wait for the final ACK to be received
        while self.connection_state != ConnectionState.CLOSED:
            time.sleep(0.1)

    def send(self, payload: bytes):
        if self.connection_state != ConnectionState.ESTABLISHED:
            raise Exception("Connection not established")

        bytes_sent = 0
        while bytes_sent < len(payload):
            window = self.tcb.send_window# - (self.tcb.our_seq_number - self.tcb.last_received_ack)
            if window <= 0:
                # Wait for window update
                print("waiting for window update")
                time.sleep(0.1)
                continue

            segment = payload[bytes_sent:bytes_sent + window]
            packet = self.create_packet(SYN=False, ACK=True, FIN=False, RST=False, payload=segment)
            self.send_packet(packet)
            bytes_sent += len(segment)

    def receive(self, max_size=4096, timeout=None) -> bytes:
        start_time = time.time()
        # while not self.receive_buffer:
        #     if timeout and time.time() - start_time > timeout:
        #         raise TimeoutError("Receive operation timed out")
        #     time.sleep(0.2)

        sorted_keys = sorted(self.receive_buffer.keys())
        data = b""
        
        for key in sorted_keys:
            if len(data) + len(self.receive_buffer[key]) > max_size:
                break
            
            data += self.receive_buffer[key]
            self.receive_buffer.pop(key)
        
        #self.tcb.recv_window += len(data)
        if len(data) != 0:
            self.logger.debug(f"Passed {len(data)} bytes of data to application.")
        
        return data

    def abort(self):
        packet = self.create_packet(SYN=False, ACK=False, FIN=False, RST=True)
        self.send_packet(packet)
        self.connection_state = ConnectionState.CLOSED
    
    # def _retransmit_packet(self, tcp_packet: TCPPacket):
    #     if self.connection_state == ConnectionState.CLOSED:
    #         return

    #     if tcp_packet.retransmission_count >= self.max_retransmissions:
    #         dsaasif self.verbose:
    #             print(f"Max retransmissions reached for Seq {tcp_packet.header.sequence_number - self.initial_our_seq_number}")
    #             print("aborting")

    #         self.abort()
    #         return

    #     # cehck if ack was received
    #     if tcp_packet.header.sequence_number < self.tcb.peer_seq_number:
    #         return

    #     tcp_packet.retransmission_count += 1

    #     # Resend the packet
    #     self.send_packet(tcp_packet, is_retransmission=True)

    #     dassdaif self.verbose:
    #         print(f"Retransmission {tcp_packet.retransmission_count}: Seq {tcp_packet.header.sequence_number - self.initial_our_seq_number}")


# =======================================================================
# Tests

# http_server.py

def main():
    # Get network interface details
    interface = "eth0"  # Change to your interface
    source_ip = get_iface_ip(interface)
    source_mac = get_iface_mac(interface)
    gateway_ip, gateway_mac = get_gateway_info(interface)

    # Create TCP server
    server = TCPConnection(
        source_MAC=source_mac,
        dest_MAC=gateway_mac,
        source_ip=source_ip,
        dest_ip="0.0.0.0",  # Accept connections from any IP
        source_port=8080,   # HTTP port
        dest_port=0,        # Any port
        interface=interface
    )

    # Handle graceful shutdown
    def handle_signal(signum, frame):
        print("\nShutting down server...")
        server.on_terminate_signal()
        exit(0)

    signal.signal(signal.SIGINT, handle_signal)

    try:
        print(f"Starting HTTP server on {source_ip}:8080")
        server.listen(backlog=5)

        while True:
            # Accept client connection
            client = server.accept()
            
            # Receive HTTP request
            data = client.receive_buffer.decode('utf-8')
            print(f"Received request:\n{data}")

            # Send HTTP response
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 13\r\n"
                "\r\n"
                "Hello, World!"
            )
            client.send(response.encode())
            client.close()

    except Exception as e:
        print(f"Error: {e}")
        server.on_terminate_signal()


if __name__ == "__main__":
    main()
    
def test():
    def termination_handler(sig, frame):
        tcp_connection.on_terminate_signal()
        # exit
        exit(0)

    signal.signal(signal.SIGINT, termination_handler)

    interface = "eth0"
    source_MAC = get_iface_mac(interface)
    _, gateway_mac = get_gateway_info(interface)
    source_ip = get_iface_ip(interface)
    dest_ip = "192.168.1.1"
    source_port = random.randint(1024, 65535)
    dest_port = 80

    tcp_connection = TCPConnection(
        source_MAC, gateway_mac, source_ip, dest_ip, source_port, dest_port, interface
    )
    # print(tcp_connection.is_port_open_stealth())
    tcp_connection.open()
    while not tcp_connection.connection_state == ConnectionState.ESTABLISHED:
        time.sleep(0.3)
    print("sending get")
    http_get_request = b"GET / HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n"
    tcp_connection.send(http_get_request)
    print("=" * 50)

    response = tcp_connection.receive()
    print(response.decode())
    print("=" * 50)

    tcp_connection.close()
    time.sleep(5)
    tcp_connection.abort()


if __name__ == "__main__":
    test()
