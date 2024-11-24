import struct
from .ether_type import EthernetType
from src.common.utils import mac_addr_to_bytes


class EthernetFrame:
    def __init__(
        self,
        source_mac: str,
        dest_mac: str,
        payload: bytes,
        ether_type: EthernetType,
        use_software_crc: bool = True,
    ):
        """
        Initialize an EthernetFrame instance.

        :param source_mac: Source MAC address as a string.
        :param dest_mac: Destination MAC address as a string.
        :param payload: Payload data as bytes.
        :param ether_type: Ethernet type as an instance of EthernetType.
        :param use_software_crc: Boolean indicating whether
                                 to use software CRC.
        """
        self.source_mac: str = source_mac
        self.dest_mac: str = dest_mac
        self.ether_type: EthernetType = ether_type
        self.payload: bytes = payload
        self.use_software_crc: bool = use_software_crc
        self._frame: bytes = self._build_frame()

    def _build_frame(self) -> bytes:
        """
        Build the Ethernet frame.

        :return: The complete Ethernet frame as bytes.
        """
        header: bytes = struct.pack(
            "!6s6sH",
            mac_addr_to_bytes(self.dest_mac),
            mac_addr_to_bytes(self.source_mac),
            self.ether_type.value,
        )

        frame: bytes = header + self.payload

        if self.use_software_crc:
            crc: bytes = self._calculate_CRC(frame)
            frame += crc

        return frame

    @property
    def frame(self) -> bytes:
        """
        Get the Ethernet frame.

        :return: The complete Ethernet frame as bytes.
        """
        return self._frame

    @staticmethod
    def _calculate_CRC(frame: bytes) -> bytes:
        """
        Calculate the CRC for the given frame.

        :param frame: The Ethernet frame as bytes.
        :return: The CRC as bytes.
        """
        raise NotImplementedError("CRC calculation not implemented yet.")
