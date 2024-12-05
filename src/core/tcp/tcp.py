from src.core.ipv4.ip_header import IPHeader
from src.core.ipv4.ip_protocol import IPProtocol
from src.core.ipv4.ip_packet import IPPacket
from src.core.ethernet.frame import EthernetFrame
import struct
import socket
import random
from src.common.utils import Utils
from enum import Enum
import time
import threading
import signal


class TCPHeader:
    def __init__(self, source_ip: str, dest_ip: str, source_port: int, dest_port: int):
        self.source_ip = source_ip  # 32 bits
        self.dest_ip = dest_ip  # 32 bits
        self.source_port = source_port  # 16 bits
        self.dest_port = dest_port  # 16 bits

        self.sequence_number = 0  # 32 bits
        self.ack_number = 0  # 32 bits
        self.data_offset = 5  # 4 bits (default TCP header size without options)
        self.reserved = 0  # 4 bits
        self.CWR = 0  # 1 bit
        self.ECE = 0  # 1 bit
        self.URG = 0  # 1 bit
        self.ACK = 0  # 1 bit
        self.PSH = 0  # 1 bit
        self.RST = 0  # 1 bit
        self.SYN = 0  # 1 bit
        self.FIN = 0  # 1 bit
        self.window = 8192  # 16 bits (default value)
        self.checksum = 0  # 16 bits
        self.urgent_pointer = 0  # 16 bits
        self.payload = b""  # Initialize payload as empty bytes
        self.options = b""  # Variable-length options

    def _get_pseudo_header(self, tcp_packet_length):
        pseudo_header = struct.pack(
            "!4s4sBBH",
            Utils.ip_to_bytes(self.source_ip),
            Utils.ip_to_bytes(self.dest_ip),
            0,
            IPProtocol.TCP.value,
            tcp_packet_length,
        )
        return pseudo_header

    def build_header(self):
        flags = (
            (self.data_offset << 12)
            + (self.reserved << 8)
            + (self.CWR << 7)
            + (self.ECE << 6)
            + (self.URG << 5)
            + (self.ACK << 4)
            + (self.PSH << 3)
            + (self.RST << 2)
            + (self.SYN << 1)
            + self.FIN
        )

        # Pack header with a placeholder checksum
        header = struct.pack(
            "!HHIIHHHH",
            self.source_port,
            self.dest_port,
            self.sequence_number,
            self.ack_number,
            flags,
            self.window,
            self.checksum,
            self.urgent_pointer,
        )

        header += self.options
        total_length = len(header) + len(self.payload)
        pseudo_header = self._get_pseudo_header(total_length)
        self.checksum = Utils.calculate_checksum(pseudo_header + header + self.payload)

        header = struct.pack(
            "!HHIIHHHH",
            self.source_port,
            self.dest_port,
            self.sequence_number,
            self.ack_number,
            flags,
            self.window,
            self.checksum,
            self.urgent_pointer,
        )

        header += self.options

        return header


class ConnectionState(Enum):
    CLOSED = 0
    SYN_SENT = 2
    ESTABLISHED = 4
    CLOSING = 8
    WAITING_FOR_FINAL_ACK = 10
    NOT_INITIALIZED = 11


class TCPPacket:
    def __init__(self, header: TCPHeader, payload: bytes = b""):
        self.header = header
        self.payload = payload
        self.header.payload = payload
        self.send_or_recv_time = None
        self.retransmission_count = 0

    def build_packet(self):
        tcp_header = self.header.build_header()
        return tcp_header + self.payload

    @staticmethod
    def from_bytes(tcp_packet_encoded: bytes):
        fixed_header_size = 20  # 5 * 4 bytes
        (
            source_port,
            dest_port,
            sequence_number,
            ack_number,
            flags,
            window,
            checksum,
            urgent_pointer,
        ) = struct.unpack("!HHIIHHHH", tcp_packet_encoded[:fixed_header_size])

        data_offset = (flags >> 12) & 0xF
        header_length = data_offset * 4
        options_length = header_length - fixed_header_size

        options = (
            tcp_packet_encoded[fixed_header_size:header_length]
            if options_length > 0
            else b""
        )
        payload = tcp_packet_encoded[header_length:]

        tcp_header = TCPHeader("", "", source_port, dest_port)
        tcp_header.sequence_number = sequence_number
        tcp_header.ack_number = ack_number
        tcp_header.data_offset = data_offset
        tcp_header.reserved = (flags >> 8) & 0xF
        tcp_header.CWR = (flags >> 7) & 1
        tcp_header.ECE = (flags >> 6) & 1
        tcp_header.URG = (flags >> 5) & 1
        tcp_header.ACK = (flags >> 4) & 1
        tcp_header.PSH = (flags >> 3) & 1
        tcp_header.RST = (flags >> 2) & 1
        tcp_header.SYN = (flags >> 1) & 1
        tcp_header.FIN = flags & 1
        tcp_header.window = window
        tcp_header.checksum = checksum
        tcp_header.urgent_pointer = urgent_pointer
        tcp_header.options = options
        tcp_header.payload = payload

        tcp_packet_decoded = TCPPacket(tcp_header, payload)

        return tcp_packet_decoded


class TCPConnection:
    """
    simple tcp implementation using raw sockets

    * Doesn't support packet fragmentation
    * Doesn't support flow control
    * Doesn't support congestion control
    * Doesn't support options in TCP header
    * Supports handshaking, simple data transfer, graceful close, retransmission, and abort

    """

    def __init__(
        self,
        source_MAC: str,
        dest_MAC: str,
        source_ip: str,
        dest_ip: str,
        source_port: int,
        dest_port: int,
        interface: str,
    ):
        self.source_MAC = source_MAC
        self.dest_MAC = dest_MAC
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.interface = interface

        self.verbose = 1

        # TCB (Transmission Control Block)
        self.send_buffer = []
        self.receive_buffer = bytearray()
        self.current_segment = None
        self.connection_state = ConnectionState.NOT_INITIALIZED

        self.initial_seq_number = random.randint(0, 2**32 - 1)
        self.our_seq_number = self.initial_seq_number
        self.initial_server_seq_number = None
        self.server_seq_number = None
        self.last_received_ack = self.our_seq_number

        self.max_retransmissions = 5
        self.retransmission_timeout = 5
        self.keep_alive_timeout = 50
        self.last_activity_time = None

        self.all_data_received = False

        # Threads
        self.listener_thread = threading.Thread(target=self._listen)
        self.timer_thread = threading.Thread(
            target=self._timer
        )  # for retransmission, keep alive etc.

        # In Linux "Receiving of all IP protocols via IPPROTO_RAW is not possible using raw sockets."
        # source: https://stackoverflow.com/questions/40795772/cant-receive-packets-to-raw-socket
        # So I used one raw socket (IPPROTO_RAW) for sending (with custom IP header)
        # and another raw socket (IPPROTO_TCP) for receiving TCP packets
        self.send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.recv_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
        )

    def create_packet(
        self, SYN: bool, ACK: bool, FIN: bool, RST: bool, payload: bytes = b""
    ):
        tcp_header = TCPHeader(
            self.source_ip, self.dest_ip, self.source_port, self.dest_port
        )
        tcp_header.SYN = SYN
        tcp_header.ACK = ACK
        tcp_header.FIN = FIN
        tcp_header.RST = RST
        tcp_header.sequence_number = self.our_seq_number
        if ACK:
            tcp_header.ack_number = self.server_seq_number
        tcp_packet = TCPPacket(tcp_header, payload)
        return tcp_packet

    # **** Main Thread methods ****
    def send_packet(self, tcp_packet: TCPPacket, is_retransmission=False):
        tcp_packet.send_or_recv_time = Utils.get_current_time()
        tcp_packet_built = tcp_packet.build_packet()

        # Create IP header
        ip_header = IPHeader(self.source_ip, self.dest_ip, IPProtocol.TCP)
        ip_packet = IPPacket(ip_header, tcp_packet_built).build_packet()

        # create Ethernet header
        frame = EthernetFrame.EthernetFrame(
            self.source_MAC,
            self.dest_MAC,
            ip_packet,
            EthernetFrame.EthernetType.IPv4,
            use_software_crc=False,
        ).build_frame()

        # port is set to 0 because we are sending raw IP packets
        self.send_sock.sendto(frame, (self.interface, 0))

        if not is_retransmission:
            # update our sequence number
            if tcp_packet.header.SYN or tcp_packet.header.FIN:
                self.our_seq_number += 1

            if len(tcp_packet.payload) > 0:
                self.our_seq_number += len(tcp_packet.payload)

        # # Schedule retransmission
        # timer = threading.Timer(self.retransmission_timeout, self._retransmit_packet, args=(tcp_packet,))
        # tcp_packet.timer = timer
        # timer.start()

    def _listen(self, timeout: int = 1):
        self.recv_socket.settimeout(timeout)

        while self.connection_state != ConnectionState.CLOSED:
            try:
                packet = self.recv_socket.recv(4096)
                ip_header, tcp_header, payload = self._parse_packet(packet)

                # check ports
                if (
                    tcp_header.source_port != self.dest_port
                    or tcp_header.dest_port != self.source_port
                ):
                    continue

                # packet verified
                self.last_activity_time = Utils.get_current_time()
                if self.verbose:
                    if self.initial_server_seq_number:
                        print(
                            f"Packet received. seq number: {tcp_header.sequence_number - self.initial_server_seq_number}"
                        )

                # self._handle_packet(tcp_header, payload)
                threading.Thread(
                    target=self._handle_packet, args=(ip_header, tcp_header, payload)
                ).start()

            except socket.timeout:
                if self.verbose:
                    print("Timeout waiting for packet")
                continue

    def _timer(self):
        while self.connection_state != ConnectionState.CLOSED:
            # Handle keep-alive
            if self.connection_state == ConnectionState.ESTABLISHED:
                if (
                    Utils.get_current_time() - self.last_activity_time
                    > self.keep_alive_timeout
                ):
                    packet = self.create_packet(
                        SYN=False, ACK=True, FIN=False, RST=False
                    )
                    packet.header.sequence_number = self.our_seq_number - 1
                    self.send_packet(packet)
                    self.last_activity_time = Utils.get_current_time()

                    if self.verbose:
                        print("Keep-alive packet sent")

    # def _retransmit_packet(self, tcp_packet: TCPPacket):
    #     if self.connection_state == ConnectionState.CLOSED:
    #         return

    #     if tcp_packet.retransmission_count >= self.max_retransmissions:
    #         if self.verbose:
    #             print(f"Max retransmissions reached for Seq {tcp_packet.header.sequence_number - self.initial_seq_number}")
    #             print("aborting")

    #         self.abort()
    #         return

    #     # cehck if ack was received
    #     if tcp_packet.header.sequence_number < self.server_seq_number:
    #         return

    #     tcp_packet.retransmission_count += 1

    #     # Resend the packet
    #     self.send_packet(tcp_packet, is_retransmission=True)

    #     if self.verbose:
    #         print(f"Retransmission {tcp_packet.retransmission_count}: Seq {tcp_packet.header.sequence_number - self.initial_seq_number}")

    def _handle_packet(self, ip_header, tcp_header, payload):
        # Check sequence number
        if self.connection_state == ConnectionState.ESTABLISHED:
            # check for incoming keep-alive packets
            if tcp_header.sequence_number == self.server_seq_number - 1:
                if self.verbose:
                    print("Keep-alive packet received")

                self.on_keep_alive_received(ip_header, tcp_header, payload)
                return

            elif tcp_header.sequence_number != self.server_seq_number:
                if self.verbose:
                    print(
                        f"Incoming: Invalid sequence number. Expected: {self.server_seq_number - self.initial_server_seq_number}, got: {tcp_header.sequence_number - self.initial_server_seq_number}"
                    )

                return

        # Check ack number if ack is set
        if tcp_header.ACK:
            if tcp_header.ack_number != self.our_seq_number:
                if self.verbose:
                    print(
                        f"Incoming: Invalid ack number. Expected: {self.our_seq_number}, got: {tcp_header.ack_number}"
                    )

                return

        # RST
        if tcp_header.RST:
            self.on_reset_received(ip_header, tcp_header, payload)
            if self.verbose:
                print(f"RESET received")

            return

        # SYN-ACK
        if tcp_header.SYN and tcp_header.ACK:
            self.on_SYN_ACK_received(ip_header, tcp_header, payload)
            if self.verbose:
                print("SYN-ACK received")

        # ACK
        if tcp_header.ACK:
            self.on_ACK_received(ip_header, tcp_header, payload)
            if self.verbose:
                print("ACK received")

        # Data
        if len(payload) > 0:
            self.on_data_received(ip_header, tcp_header, payload)
            if self.verbose:
                print("Data received")

        # FIN
        if tcp_header.FIN:
            self.on_FIN_received(ip_header, tcp_header, payload)
            if self.verbose:
                print("FIN received")

            return

    # *** Event Handlers ***
    def on_keep_alive_received(self, ip_header, tcp_header, payload):
        # send ack
        packet = self.create_packet(SYN=False, ACK=True, FIN=False, RST=False)
        self.send_packet(packet)

    def on_reset_received(self, ip_header, tcp_header, payload):
        if self.verbose:
            print("Connection reset by peer")

        self.connection_state = ConnectionState.CLOSED

    def on_SYN_ACK_received(self, ip_header, tcp_header, payload):
        if self.connection_state == ConnectionState.SYN_SENT:
            # set server sequence number
            self.initial_server_seq_number = tcp_header.sequence_number
            self.server_seq_number = tcp_header.sequence_number

            # Add one because server sent SYN
            self.server_seq_number += 1

            if self.verbose:
                print(
                    f"server seq number after SYN-ACK: {self.server_seq_number - self.initial_server_seq_number}"
                )

            ack_packet = self.create_packet(SYN=False, ACK=True, FIN=False, RST=False)
            self.send_packet(ack_packet)

            self.connection_state = ConnectionState.ESTABLISHED

            if self.verbose:
                print("Connection established")

        else:
            if self.verbose:
                print("Invalid SYN-ACK received. (state is not SYN_SENT)")

    def on_ACK_received(self, ip_header, tcp_header, payload):
        # Update server sequence number
        if self.connection_state == ConnectionState.ESTABLISHED:
            # self.server_seq_number = tcp_header.sequence_number
            if self.verbose:
                print(
                    f"ACK received. seq number: {self.server_seq_number - self.initial_server_seq_number}"
                )

        # handle ACK to our FIN-ACK
        if self.connection_state == ConnectionState.WAITING_FOR_FINAL_ACK:
            self.connection_state = ConnectionState.CLOSED
            if self.verbose:
                print("Connection closed")

    def on_data_received(self, ip_header, tcp_header, payload):
        if self.connection_state == ConnectionState.ESTABLISHED:
            self.server_seq_number += len(payload)
            self.receive_buffer.extend(payload)

            # send ACK
            packet = self.create_packet(SYN=False, ACK=True, FIN=False, RST=False)
            self.send_packet(packet)

            if self.verbose:
                print("Data segment received")

    def on_FIN_received(self, ip_header, tcp_header, payload):

        if self.connection_state == ConnectionState.ESTABLISHED:
            if self.verbose:
                print("FIN received")
                print("All data received")

            self.all_data_received = True

            self.server_seq_number += 1

            # send FIN-ACK
            packet = self.create_packet(SYN=False, ACK=True, FIN=True, RST=False)
            self.send_packet(packet)

            self.connection_state = ConnectionState.WAITING_FOR_FINAL_ACK

            if self.verbose:
                print("Transitioned to WAITING_FOR_FINAL_ACK")

        elif self.connection_state == ConnectionState.CLOSING:
            self.server_seq_number += 1

            # send final ACK
            packet = self.create_packet(SYN=False, ACK=True, FIN=False, RST=False)
            self.send_packet(packet)

            self.connection_state = ConnectionState.CLOSED
            if self.verbose:
                print("Connection closed")

        else:
            if self.verbose:
                print("Invalid FIN received. (state is not ESTABLISHED/CLOSING)")

    @staticmethod
    def _parse_packet(packet):
        if len(packet) < 40:
            raise ValueError("Packet is too small to be a TCP packet")

        ip_header = IPHeader.from_bytes(packet[:20])
        tcp_packet_encoded = packet[20:]
        tcp_packet_decoded = TCPPacket.from_bytes(tcp_packet_encoded)

        return ip_header, tcp_packet_decoded.header, tcp_packet_decoded.payload

    def on_terminate_signal(self):
        self.abort()
        self.send_sock.close()
        self.recv_socket.close()
        self.connection_state = ConnectionState.CLOSED

    # *** User methods ***
    def open(self, wait_until_established=True, timeout=5):
        if self.connection_state not in [
            ConnectionState.CLOSED,
            ConnectionState.NOT_INITIALIZED,
        ]:
            raise Exception("Connection already open")

        self.listener_thread.start()
        self.timer_thread.start()

        send_time = Utils.get_current_time()
        self.connection_state = ConnectionState.SYN_SENT
        packet = self.create_packet(SYN=True, ACK=False, FIN=False, RST=False)
        self.send_packet(packet)

        if wait_until_established:
            while self.connection_state != ConnectionState.ESTABLISHED:
                if Utils.get_current_time() - send_time > timeout:
                    raise TimeoutError("Connection establishment timed out")

                time.sleep(0.1)

    def close(self):
        if self.connection_state != ConnectionState.ESTABLISHED:
            raise Exception("Connection not established")

        packet = self.create_packet(SYN=False, ACK=False, FIN=True, RST=False)
        self.send_packet(packet)
        self.connection_state = ConnectionState.CLOSING

        # Wait for the final ACK to be received
        while self.connection_state != ConnectionState.CLOSED:
            time.sleep(0.1)

    def send(self, payload: bytes):
        if self.connection_state != ConnectionState.ESTABLISHED:
            raise Exception("Connection not established")

        packet = self.create_packet(
            SYN=False, ACK=True, FIN=False, RST=False, payload=payload
        )
        self.send_packet(packet)

    def receive(self, timeout=5) -> bytes:
        start_time = time.time()
        while not self.receive_buffer and not self.all_data_received:
            if time.time() - start_time > timeout:
                raise TimeoutError("Receive operation timed out")
            time.sleep(0.2)

        data = bytes(self.receive_buffer)
        self.receive_buffer.clear()
        return data

    def abort(self):
        packet = self.create_packet(SYN=False, ACK=False, FIN=False, RST=True)
        self.send_packet(packet)
        self.connection_state = ConnectionState.CLOSED

    def status(self):
        return self.connection_state

    def is_port_open_stealth(self, port_timeout=5, socket_timeout=1):
        if self.connection_state == ConnectionState.ESTABLISHED:
            return True

        delay = None

        try:
            # send syn
            packet = self.create_packet(SYN=True, ACK=False, FIN=False, RST=False)
            send_time = Utils.get_current_time()
            self.send_packet(packet)

            # wait for syn-ack
            start_time = Utils.get_current_time()

            self.recv_socket.settimeout(socket_timeout)
            while Utils.get_current_time() - start_time < port_timeout:
                try:
                    packet = self.recv_socket.recv(4096)
                    ip_header, tcp_header, payload = self._parse_packet(packet)

                    # check ports
                    if (
                        tcp_header.source_port != self.dest_port
                        and tcp_header.dest_port != self.source_port
                    ):
                        continue

                    # packet verified
                    delay = (Utils.get_current_time() - send_time) * 1000
                    if self.verbose:
                        print(
                            f"Packet received. seq number: {tcp_header.sequence_number}"
                        )

                    # SYN-ACK
                    if tcp_header.ACK and tcp_header.SYN:
                        if self.verbose:
                            print("SYN-ACK received")

                        return True, delay

                    # RST
                    if tcp_header.RST:
                        if self.verbose:
                            print("Connection reset by peer")
                        return False, delay

                except socket.timeout:
                    if self.verbose:
                        print("Timeout waiting for packet")

                    return False, delay
        finally:
            self.send_sock.close()
            self.recv_socket.close()
        return False, delay


# =======================================================================
# Tests
def test():
    def termination_handler(sig, frame):
        tcp_connection.on_terminate_signal()
        # exit
        exit(0)

    signal.signal(signal.SIGINT, termination_handler)

    interface = "eth0"
    source_MAC = "00:15:5d:69:b4:e5"
    dest_MAC = "00:15:5d:ac:5f:57"
    source_ip = "172.18.121.202"
    dest_ip = "192.168.1.1"
    source_port = random.randint(1024, 65535)
    dest_port = 80

    tcp_connection = TCPConnection(
        source_MAC, dest_MAC, source_ip, dest_ip, source_port, dest_port, interface
    )
    # print(tcp_connection.is_port_open_stealth())
    tcp_connection.open()
    while not tcp_connection.status() == ConnectionState.ESTABLISHED:
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
