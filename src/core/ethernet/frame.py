import struct
from .ether_type import EthernetType
from src.common.utils import mac_addr_to_bytes


class EthernetFrame:
    IEEE802_3_CRC_GENERATOR = 0xEDB88320

    def __init__(
        self,
        source_mac: str,
        dest_mac: str,
        payload: bytes,
        ether_type: EthernetType,
        use_software_crc: bool = True,
    ):        
        self.source_mac: str = source_mac
        self.dest_mac: str = dest_mac
        self.ether_type: EthernetType = ether_type
        self.payload: bytes = payload
        self.use_software_crc: bool = use_software_crc
        self._frame: bytes = self._build_frame()

    def _build_frame(self) -> bytes:
        header: bytes = struct.pack(
            "!6s6sH",
            mac_addr_to_bytes(self.dest_mac),
            mac_addr_to_bytes(self.source_mac),
            self.ether_type.value,
        )

        frame: bytes = header + self.payload

        # Calculate and append CRC
        if not self.use_software_crc:
            crc: bytes = self._calculate_CRC(frame)
            frame += crc

        return frame

    @property
    def frame(self) -> bytes:
        return self._frame

    @staticmethod
    def _calculate_CRC(frame: bytes) -> bytes:
        crc = 0xFFFFFFFF
        for byte in frame:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ EthernetFrame.IEEE802_3_CRC_GENERATOR
                else:
                    crc >>= 1
        crc ^= 0xFFFFFFFF
        return struct.pack('<I', crc)