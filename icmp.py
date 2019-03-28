
from util import *

def calculate_checksum(pkt):
    pkt = pkt[:]
    pkt[2:4] = b'\0\0' # checksum is 0 for the purpose of this

    return ones_comp_16b_sum(pkt)


class ICMPPacket:
    def __init__(self, bytes):
        self.bytes = bytes

    type = one_byte_accessor_property(0)
    code = one_byte_accessor_property(1)

    @property
    def checksum(self) -> bytes:
        return self.bytes[2:4]

    def set_checksum(self):
        self.bytes[2:4] = calculate_checksum(self.bytes)

    def validate_checksum(self):
        return calculate_checksum(self.bytes) == self.checksum

    ident = two_byte_accessor_property(4)
    seq = two_byte_accessor_property(6)
    body = body_accessor_property(8)

