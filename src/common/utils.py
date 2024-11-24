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
