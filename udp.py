
from util import *

def calculate_checksum(udp, src_ip, dst_ip):
    extra_pad = b'\0' if len(udp.bytes) % 2 == 1 else b'\0'

    pkt = (
        bytes(src_ip) +
        bytes(dst_ip) +
        b'\0' +             # pad
        b'\x11' +           # 17 = UDP
        udp.bytes[4:6] +    # UDP length
        udp.bytes[0:2] +    # source port
        udp.bytes[2:4] +    # dest port
        udp.bytes[4:6] +    # length
        b'\0\0' +           # checksum field
        udp.bytes[8:] +     # data
        extra_pad
    )

    # print('pseudo-header:', ':'.join(('{:02X}'.format(b) for b in pkt)))

    csum = ones_comp_16b_sum(pkt)
    if csum == 0:
        csum = 0xFFFF

    return csum


class UDPPacket:
    def __init__(self, bytes=b'\0' * 8):
        self.bytes = bytearray(bytes)

    src = two_byte_accessor_property(0)
    dst = two_byte_accessor_property(2)
    length = two_byte_accessor_property(4)

    @property
    def checksum(self):
        return self.bytes[6:8]

    def set_checksum(self, src_ip, dst_ip):
        self.bytes[6:8] = calculate_checksum(self, src_ip, dst_ip)

    def validate_checksum(self, src_ip, dst_ip):
        real = calculate_checksum(self, src_ip, dst_ip)
        seen = self.checksum
        if seen != real:
            # print("observed checksum:", seen)
            # print("calculated:       ", real)
            pass
        return real == seen
        #return calculate_checksum(self, src_ip, dst_ip) == self.checksum

    body = body_accessor_property(8, delta=8)

