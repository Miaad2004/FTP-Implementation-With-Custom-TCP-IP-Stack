def mac_addr_to_bytes(mac_addr: str) -> bytes:
    """
    Convert a MAC address string to bytes.

    :param mac_addr: The MAC address as a string.
    :return: The MAC address as bytes.
    """
    assert len(bytes(mac_addr, encoding="utf-8")) == 6

    parts = mac_addr.split(":")
    parts = [int(part, 16) for part in parts]
    return bytes(parts)


def mac_addr_to_str(mac_addr: bytes) -> str:
    """
    Convert a MAC address bytes to a string.

    :param mac_addr: The MAC address as bytes.
    :return: The MAC address as a string.
    """
    assert len(bytes(mac_addr, encoding="utf-8")) == 6

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
