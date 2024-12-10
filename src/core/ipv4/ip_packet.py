from .ip_header import IPHeader


class IPPacket:
    """
    Represents an IP packet with a header and payload.

    Attributes:
        header (IPHeader): The IP header of the packet.
        payload (bytes): The payload of the packet.
    """

    def __init__(self, header: 'IPHeader', payload: bytes) -> None:
        """
        Initializes an IPPacket instance.

        Args:
            header (IPHeader): The IP header of the packet.
            payload (bytes): The payload of the packet.
        """
        self.header = header
        self.payload = payload
        self._packet = self._build_packet()

    def _build_packet(self) -> bytes:
        """
        Builds the complete IP packet by combining the header and payload.

        Returns:
            bytes: The complete IP packet.
        """
        ip_header = self.header.build_header(len(self.payload))
        return ip_header + self.payload

    @property
    def packet(self) -> bytes:
        """
        Returns the complete IP packet.

        Returns:
            bytes: The complete IP packet.
        """
        return self._packet
