import random
from .ip_protocol import IPProtocol
import struct
from src.common.utils import ip_to_bytes, ip_to_str, calculate_checksum
from typing import Tuple


class IPHeader:
    """
    Represents an IP header for IPv4 packets.
    """

    def __init__(
        self,
        source_ip: str,
        dest_ip: str,
        protocol: IPProtocol ,
        ttl: int = 128
    ):
        """
        Initializes an IPHeader instance.

        :param source_ip: Source IP address as a string.
        :param dest_ip: Destination IP address as a string.
        :param protocol: Protocol used in the IP packet.
        :param ttl: Time to live value, default is 128.
        """
        self.version: int = 4  # 4 bits
        self.internet_header_length: int = 20  # 4 bits, min is 20 (no options)
        self.DSCP: int = 0  # 6 bits
        self.ECN: int = 0  # 2 bits
        self.total_length: int = 0  # 16 bits

        self.identification: int = random.randint(0, 2**14)  # 16 bits
        self.flag_reserved: int = 0  # 1 bit
        self.flag_dont_fragment: int = 1  # 1 bit
        self.flag_more_fragments: int = 0  # 1 bit
        self.fragment_offset: int = 0  # 13 bits

        self.ttl: int = ttl  # 8 bits
        self.header_checksum: int = 0  # 16 bits

        if isinstance(protocol, IPProtocol):
            self.protocol: int = protocol.value  # 8 bits
        else:
            self.protocol: int = protocol

        self.source_ip: str = source_ip  # 32 bits
        self.destination_ip: str = dest_ip  # 32 bits

    def build_header(self, payload_length_bytes: int) -> bytes:
        """
        Builds the IP header.

        :param payload_length_bytes: Length of the payload in bytes.
        :return: The IP header as bytes.
        """
        ihl_words = self.internet_header_length // 4
        self.total_length = self.internet_header_length + payload_length_bytes
        source_ip = ip_to_bytes(self.source_ip)
        dest_ip = ip_to_bytes(self.destination_ip)

        flags = (
            (self.flag_reserved << 2)
            + (self.flag_dont_fragment << 1)
            + self.flag_more_fragments
        )  # 3 bits

        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            (self.version << 4) + ihl_words,
            (self.DSCP << 2) + self.ECN,
            self.total_length,
            self.identification,
            (flags << 13) + self.fragment_offset,
            self.ttl,
            self.protocol,
            self.header_checksum,
            source_ip,
            dest_ip,
        )

        self.header_checksum = calculate_checksum(ip_header)

        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            (self.version << 4) + ihl_words,
            (self.DSCP << 2) + self.ECN,
            self.total_length,
            self.identification,
            (flags << 13) + self.fragment_offset,
            self.ttl,
            self.protocol,
            self.header_checksum,
            source_ip,
            dest_ip,
        )

        return ip_header

    @staticmethod
    def from_bytes(ip_header_bytes: bytes) -> Tuple['IPHeader', bool]:
        """
        Creates an IPHeader instance from raw bytes.

        :param ip_header_bytes: The IP header as bytes.
        :return: A tuple containing the IPHeader instance and a boolean indicating if the checksum is valid.
        """
        if len(ip_header_bytes) < 20:
            raise ValueError("IP header is too short.")
        
        is_valid = calculate_checksum(ip_header_bytes) == 0
        
        (
            version_ihl,
            dscp_ecn,
            total_length,
            identification,
            flags_fragment_offset,
            ttl,
            protocol,
            header_checksum,
            source_ip,
            dest_ip,
        ) = struct.unpack("!BBHHHBBH4s4s", ip_header_bytes)
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4
        dscp = dscp_ecn >> 2
        ecn = dscp_ecn & 0x03
        flags = flags_fragment_offset >> 13
        dont_fragment = (flags_fragment_offset >> 1) & 0x01
        more_fragments = flags_fragment_offset & 0x01
        fragment_offset = flags_fragment_offset & 0x1FFF
        source_ip_str = ip_to_str(source_ip)
        dest_ip_str = ip_to_str(dest_ip)

        ip_header = IPHeader(source_ip_str, dest_ip_str, protocol)
        ip_header.version = version
        ip_header.internet_header_length = ihl
        ip_header.DSCP = dscp
        ip_header.ECN = ecn
        ip_header.total_length = total_length
        ip_header.identification = identification
        ip_header.flag_reserved = flags
        ip_header.flag_dont_fragment = dont_fragment
        ip_header.flag_more_fragments = more_fragments
        ip_header.fragment_offset = fragment_offset
        ip_header.ttl = ttl
        ip_header.protocol = protocol
        ip_header.header_checksum = header_checksum
        return ip_header, is_valid
    
    @staticmethod
    def get_header_length(packet: bytes) -> int:
        """
        Extracts the header length from the whole packet.

        :param packet: The whole packet as bytes.
        :return: The header length in bytes.
        """
        if len(packet) < 1:
            raise ValueError("Packet is too short to contain an IP header.")
        
        version_ihl = packet[0]
        ihl = (version_ihl & 0x0F) * 4
        return ihl
