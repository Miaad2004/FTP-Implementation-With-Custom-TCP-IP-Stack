from src.common.utils import ip_to_bytes, calculate_checksum
from src.core.ipv4.ip_protocol import IPProtocol
import struct


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
            ip_to_bytes(self.source_ip),
            ip_to_bytes(self.dest_ip),
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
        self.checksum = calculate_checksum(pseudo_header + header + self.payload)

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