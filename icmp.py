
from util import *
from ip import IP4Packet

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


def icmp_echo(pkt):
    icmp = ICMPPacket(pkt.body)
    if icmp.type != 8: # echo request
        # only respond to echo requests
        return

    if not icmp.validate_checksum():
        print("bad checksum icmp")
        return

    resp_icmp = ICMPPacket(pkt.body)
    resp_icmp.type = 0 # echo reply
    resp_icmp.set_checksum()

    resp = IP4Packet.new()
    resp.dst = pkt.src
    resp.src = pkt.dst
    resp.ttl = pkt.ttl
    resp.proto = 1 # ICMP
    resp.ident = pkt.ident
    resp.body = resp_icmp.bytes

    resp.set_checksum()
    return resp

