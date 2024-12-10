import struct
from .tcp_header import TCPHeader
from src.common.utils import calculate_checksum
from typing import Tuple


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
    def from_bytes(tcp_packet_encoded: bytes, source_ip, dest_ip) -> Tuple['TCPPacket', bool]: 
        if len(tcp_packet_encoded) < 20:
            raise ValueError("Invalid TCP packet")
        
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
        tcp_header.source_ip = source_ip
        tcp_header.dest_ip = dest_ip

        tcp_packet_decoded = TCPPacket(tcp_header, payload)
        
        # verify checksum
        
        pseudo_header = tcp_header._get_pseudo_header(tcp_packet_length=len(tcp_packet_encoded))
        is_valid = calculate_checksum(pseudo_header + tcp_packet_encoded) == 0

        return tcp_packet_decoded, is_valid
