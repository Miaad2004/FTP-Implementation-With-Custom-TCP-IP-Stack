import os
import subprocess
import time
from scapy.all import Ether, ARP, srp1

def mac_addr_to_bytes(mac_addr: str) -> bytes:
    """
    Convert a MAC address string to bytes.

    :param mac_addr: The MAC address as a string.
    :return: The MAC address as bytes.
    """
    assert len(mac_addr.split(":")) == 6, "Invalid MAC address format"

    parts = mac_addr.split(":")
    parts = [int(part, 16) for part in parts]
    return bytes(parts)


def mac_addr_to_str(mac_addr: bytes) -> str:
    """
    Convert a MAC address bytes to a string.

    :param mac_addr: The MAC address as bytes.
    :return: The MAC address as a string.
    """
    assert len(mac_addr) == 6, "Invalid MAC address length"

    parts = [f"{part:02x}" for part in mac_addr]
    return ":".join(parts)


def ip_to_bytes(ip: str) -> bytes:
    """
    Convert an IP address string to bytes.

    :param ip: The IP address as a string.
    :return: The IP address as bytes.
    """
    parts = ip.split(".")
    parts = [int(part) for part in parts]
    return bytes(parts)


def ip_to_str(ip: bytes) -> str:
    """
    Convert an IP address bytes to a string.

    :param ip: The IP address as bytes.
    :return: The IP address as a string.
    """
    parts = [str(part) for part in ip]
    return ".".join(parts)


def calculate_checksum(data: bytes) -> int:
    """
    Calculate the checksum of the given data.

    :param data: The data to calculate the checksum for.
    :return: The checksum as an integer.
    """
    # pad even packets
    if len(data) % 2 == 1:
        data += b'\x00'     # add a zero byte

    checksum = 0
    for i in range(0, len(data), 2):
        # add 2 bytes by 2 bytes
        checksum += (data[i] << 8) + data[i + 1]
        carry = checksum >> 16

        # mask to 16 bits and wrap around carry
        checksum = (checksum & 0xFFFF) + carry

    # one's complement and mask to 16 bits
    checksum = ~checksum & 0xFFFF
    
    return checksum


def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')


def get_current_time():
    return time.perf_counter()


def install_package(package_name: str):
    input_ = input(f"The '{package_name}' module is required. Install it? (y/n): ")
    if input_.lower() == 'y':
        os.system(f'pip install {package_name}')
    else:
        raise Exception(f"The '{package_name}' module is required.")


def get_iface_mac(interface):
    # since netifaces needs build tools on windows I removed it from reqirements.txt
    if os.name != 'posix':
        raise Exception("This function is only supported on Unix-based systems.")
    
    try:
        import netifaces
    
    except ImportError:
        install_package('netifaces')
        import netifaces
    
    return netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']


def get_iface_ip(interface):
    # since netifaces needs build tools on windows I removed it from reqirements.txt
    if os.name != 'posix':
        raise Exception("This function is only supported on Unix-based systems.")
    
    try:
        import netifaces
        
    except ImportError:
        install_package('netifaces')
        import netifaces
    
    # Get IPv4 address from interface
    addresses = netifaces.ifaddresses(interface)
    if netifaces.AF_INET in addresses:
        return addresses[netifaces.AF_INET][0]['addr']
    else:
        raise Exception(f"No IPv4 address found for interface {interface}")

def arp(ip_addr: str, interface: str, use_scapy=True) -> str:
    """
    Get MAC address of a destination IP using ARP.
    
    :param ip_addr: Destination IP address
    :param interface: Network interface to use
    :return: MAC address as string
    """
    if use_scapy:
        # Create ARP request
        arp = ARP(pdst=ip_addr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        try:
            result = srp1(packet, timeout=3, verbose=False, iface=interface)
            if result:
                return result.hwsrc
            
            else:
                raise Exception(f"No response from {ip_addr}")
            
        except Exception as e:
            raise Exception(f"Failed to get MAC address: {str(e)}")
    
    else:
        pass
        

def get_gateway_info(interface: str) -> tuple:
    """
    Get gateway IP and MAC address for outbound traffic.
    
    :param interface: Network interface to use
    :return: Tuple of (gateway_ip, gateway_mac)
    """
    if os.name != 'posix':
        raise Exception("This function is only supported on Unix-based systems.")
    
    try:
        import netifaces
        
    except ImportError:
        install_package('netifaces')
        import netifaces
        
    gateways = netifaces.gateways()
    
    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
        gateway_ip = gateways['default'][netifaces.AF_INET][0]
        
    else:
        raise Exception("Could not find default gateway")

    # Get MAC using arp
    gateway_mac = arp(gateway_ip, interface)
    
    return gateway_ip, gateway_mac

def block_linux_reset_packets():
    """
    Block outgoing RST packets on Linux.
    """
    if os.name != 'posix':
        raise Exception("This function is only supported on Unix-based systems.")
    
    cmd = ['sudo', 'iptables', '-A', 'OUTPUT', '-p', 'tcp', '--tcp-flags', 'RST', 'RST', '-j', 'DROP']
    
    try:
        subprocess.check_call(cmd)
        print("Blocked kernel RST packets successfully.")
        
    except subprocess.CalledProcessError as e:
        print(f"Failed to block RST packets: {e}")

def unblock_linux_reset_packets():
    """
    Unblock outgoing RST packets on Linux.
    """
    if os.name != 'posix':
        raise Exception("This function is only supported on Unix-based systems.")
    
    cmd = ['sudo', 'iptables', '-D', 'OUTPUT', '-p', 'tcp', '--tcp-flags', 'RST', 'RST', '-j', 'DROP']
    try:
        subprocess.check_call(cmd)
        print("Unblocked kernel RST packets successfully.")
        
    except subprocess.CalledProcessError as e:
        print(f"Failed to unblock RST packets: {e}")