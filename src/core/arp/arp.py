import struct
import socket
from src.common.utils import mac_addr_to_bytes, ip_to_bytes, get_gateway_info, get_iface_ip, get_iface_mac
from src.core.ethernet.frame import EthernetFrame
from src.core.ethernet.ether_type import EthernetType
from src.common.config import config_handler


class ARPPacket:
    def __init__(self, hw_type: int, proto_type: int, hw_size: int, proto_size: int, opcode: int,
                 src_mac: str, src_ip: str, dest_mac: str, dest_ip: str):
        self.hw_type = hw_type
        self.proto_type = proto_type
        self.hw_size = hw_size
        self.proto_size = proto_size
        self.opcode = opcode
        self.src_mac = src_mac
        self.src_ip = src_ip
        self.dest_mac = dest_mac
        self.dest_ip = dest_ip

    def build_packet(self) -> bytes:
        src_mac_bytes = mac_addr_to_bytes(self.src_mac)
        src_ip_bytes = ip_to_bytes(self.src_ip)
        dest_mac_bytes = mac_addr_to_bytes(self.dest_mac)
        dest_ip_bytes = ip_to_bytes(self.dest_ip)

        arp_packet = struct.pack(
            "!HHBBH6s4s6s4s",
            self.hw_type,
            self.proto_type,
            self.hw_size,
            self.proto_size,
            self.opcode,
            src_mac_bytes,
            src_ip_bytes,
            dest_mac_bytes,
            dest_ip_bytes
        )

        return arp_packet

    @classmethod
    def from_bytes(cls, packet: bytes):
        unpacked_data = struct.unpack("!HHBBH6s4s6s4s", packet)
        hw_type = unpacked_data[0]
        proto_type = unpacked_data[1]
        hw_size = unpacked_data[2]
        proto_size = unpacked_data[3]
        opcode = unpacked_data[4]
        src_mac = ':'.join(format(b, '02x') for b in unpacked_data[5])
        src_ip = socket.inet_ntoa(unpacked_data[6])
        dest_mac = ':'.join(format(b, '02x') for b in unpacked_data[7])
        dest_ip = socket.inet_ntoa(unpacked_data[8])
        return cls(hw_type, proto_type, hw_size, proto_size, opcode, src_mac, src_ip, dest_mac, dest_ip)

class ARP:
    @staticmethod
    def create_arp_request(src_mac: str, src_ip: str, dest_ip: str, proto_type: EthernetType = EthernetType.IPv4) -> bytes:
        hw_type = 1  # Ethernet
        proto_type = proto_type.value  # IPv4
        hw_size = 6  # MAC address length
        proto_size = 4  # IPv4 address length
        opcode = 1  # ARP request

        arp_packet = ARPPacket(
            hw_type=hw_type,
            proto_type=proto_type,
            hw_size=hw_size,
            proto_size=proto_size,
            opcode=opcode,
            src_mac=src_mac,
            src_ip=src_ip,
            dest_mac='00:00:00:00:00:00',
            dest_ip=dest_ip
        )

        return arp_packet.build_packet()

    @staticmethod
    def send_arp_request(dest_ip: str, interface: str = None) -> str:
        default_iface = config_handler.get("interface")
        if not interface and default_iface:
            interface = default_iface
        
        elif not interface:
            raise Exception("No interface specified")
        
        src_mac = get_iface_mac(interface)
        src_ip = get_iface_ip(interface)
        
        arp_payload = ARP.create_arp_request(src_mac, src_ip, dest_ip)

        ethernet_frame = EthernetFrame(
            source_mac=src_mac,
            dest_mac='ff:ff:ff:ff:ff:ff', 
            payload=arp_payload,
            ether_type=EthernetType.ARP
        )

        # Create raw socket
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        sock.bind((interface, 0))

        sock.send(ethernet_frame.frame)

        return "ARP request sent"

    @staticmethod
    def resolve_ip_to_mac(dest_ip: str, interface: str = None, timeout: int = 5) -> str:
        default_iface = config_handler.get("interface")
        if not interface and default_iface:
            interface = default_iface
        if not interface:
            raise Exception("No interface specified")
        
        ARP.send_arp_request(dest_ip, interface)
    
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) 
        sock.bind((interface, 0))
        sock.settimeout(timeout)
    
        try:
            while True:
                packet = sock.recv(65535)
                eth_header = packet[0:14]
                eth = struct.unpack('!6s6sH', eth_header)
                eth_proto = socket.ntohs(eth[2])
                if eth_proto == 0x0806:  # ARP packet
                    arp_packet = ARPPacket.from_bytes(packet[14:42])
                    if arp_packet.opcode == 2 and arp_packet.dest_ip == dest_ip: 
                        return arp_packet.src_mac
        except socket.timeout:
            return "Timeout: No ARP reply received"
    
        return "Failed to resolve IP to MAC"