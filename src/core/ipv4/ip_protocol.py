from enum import Enum


class IPProtocol(Enum):
    # Based on https://en.wikipedia.org/wiki/IPv4#DSCP
    ICMP = 1
    IGMP = 2
    TCP = 6
    UDP = 17
    ENCAP = 41
    OSPF = 89
    SCTP = 132
