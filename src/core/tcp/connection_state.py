from enum import Enum, auto

class ConnectionState(Enum):
    # http://www.tcpipguide.com/free/t_TCPOperationalOverviewandtheTCPFiniteStateMachineF-2.htm
    CLOSED = 0    # -> LISTEN or SYN-SENT
    
    SYN_SENT = auto()   # -> ESTABLISHED
    
    LISTEN = auto()      # -> SYN_RECEIVED
    SYN_RECEIVED = auto() # -> ESTABLISHED
    
    ESTABLISHED = auto()   # -> FIN-WAIT-1 or CLOSE-WAIT
    FIN_WAIT_ONE = auto()  # -> FIN_WAIT_2 or CLOSING
    FIN_WAIT_2 = auto()
    
    CLOSING = auto()
    
    CLOSE_WAIT = auto()   # -> LAST_ACK
    LAST_ACK = auto()
    
    NOT_INITIALIZED = auto()
    
    SYN_ACK_SENT = auto()  # -> ESTABLABLISHED
    
    WAITING_FOR_FINAL_ACK = auto()
