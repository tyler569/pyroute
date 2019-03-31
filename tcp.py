
from util import *

def calculate_checksum(udp, src_ip, dst_ip):
    return None


class TCPPacket:
    def __init__(self, bytes=b'\0' * 8):
        self.bytes = bytearray(bytes)

    src = two_byte_accessor_property(0)
    dst = two_byte_accessor_property(2)
    seq = four_byte_accessor_property(4)
    ack = four_byte_accessor_property(4)
    ns = bit_accessor_property(12, 0)
    cwr = bit_accessor_property(13, 7)
    ece = bit_accessor_property(13, 6)
    urg = bit_accessor_property(13, 5)
    ack = bit_accessor_property(13, 4)
    psh = bit_accessor_property(13, 3)
    rst = bit_accessor_property(13, 2)
    syn = bit_accessor_property(13, 1)
    fin = bit_accessor_property(13, 0)
    window = two_byte_accessor_property(14)

    @property
    def checksum(self):
        return self.bytes[16:18]

    def set_checksum(self, src_ip, dst_ip):
        self.bytes[16:88] = calculate_checksum(self, src_ip, dst_ip)

    def validate_checksum(self, src_ip, dst_ip):
        real = calculate_checksum(self, src_ip, dst_ip)
        seen = self.checksum
        if seen != real:
            # print("observed checksum:", seen)
            # print("calculated:       ", real)
            pass
        return real == seen
        #return calculate_checksum(self, src_ip, dst_ip) == self.checksum

    urg_ptr = two_byte_accessor_property(18)
    body = body_accessor_property(20, delta=20)

