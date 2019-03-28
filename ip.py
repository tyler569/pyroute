
from util import *

def parse_ip4(st):
    tup = tuple(map(int, st.split('.')))
    if len(tup) != 4:
        raise ValueError("bad IP address")
    return tup

def ip_to_int(ip):
    if type(ip) is IP4Addr:
        ip = ip.value
    if type(ip) is not tuple:
        raise TypeError("ip_to_int needs an IP4Addr or a tuple")
    
    int_v = (ip[0]<<24) + (ip[1]<<16) + (ip[2]<<8) + ip[3]
    return int_v

def is_ip4(pkt):
    return pkt[0] & 0xF0 == 0x40

def calculate_checksum(pkt: bytearray):
    header = pkt[:20]
    header = header[:]
    header[10:12] = b'\0\0' # checksum is 0 for the purposes of this

    return ones_comp_16b_sum(header)


protocols = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

class IP4Addr:
    def __init__(self, value):
        if type(value) is str:
            self.value = parse_ip4(value)
        elif type(value) is tuple:
            self.value = value
        else:
            raise TypeError("bad IP address type")

    def __bytes__(self) -> bytes:
        return bytes(self.value)

    def __str__(self) -> str:
        return '.'.join(map(str, self.value))


class IP4Range:
    def __init__(self, ip, mask_bits):
        if type(ip) is str:
            self.ip = parse_ip4(ip)
        elif type(ip) is tuple:
            self.ip = ip 
        else:
            raise TypeError("bad IP address type")

        self.ip_int = ip_to_int(self.ip)
        self.mask_bits = mask_bits
        self.mask = sum(1<<i for i in range(31, (31-mask_bits), -1))

    def __str__(self) -> str:
        s = '.'.join(map(str, self.ip))
        s += '/' + str(self.mask_bits)
        return s

    def contains(self, ip):
        othr_ip_int = ip_to_int(ip)
        return othr_ip_int & self.mask == self.ip_int


class IP4Packet:
    def __init__(self, bytes):
        self.bytes = bytearray(bytes)

    def new():
        # some sensible defaults.
        # intends you to set src, dst, and body after-thr-fact
        pkt = IP4Packet(b'\0' * 64)
        pkt.version = 4
        pkt.ihl = 5
        pkt.length = 64
        pkt.ttl = 64
        return pkt

    @property
    def version(self) -> int:
        return self.bytes[0] >> 4

    @version.setter
    def version(self, version):
        self.bytes[0] &= 0x0F
        self.bytes[0] |= (version << 4)

    @property
    def ihl(self) -> int:
        return self.bytes[0] & 0x0F

    @ihl.setter
    def ihl(self, ihl):
        if ihl != 5:
            raise ValueError("I definitely don't support IP header tags")
        self.bytes[0] &= 0xF0
        self.bytes[0] |= ihl

    @property
    def dscp(self) -> int:
        return self.bytes[1] >> 2

    @dscp.setter
    def dscp(self, value):
        self.bytes[1] &= 0x03
        self.bytes[1] |= (value << 2)

    @property
    def ecn(self) -> int:
        return self.bytes[1] & 0x03

    @ecn.setter
    def ecn(self, value):
        self.bytes[1] &= 0xFC
        self.bytes[1] |= value

    length = two_byte_accessor_property(2)
    ident = two_byte_accessor_property(4)

    @property
    def dnf(self) -> bool:
        return self.bytes[6] & 0x80 > 0

    @dnf.setter
    def dnf(self, value):
        self.bytes[6] &= 0x7F
        if value:
            self.bytes[6] |= 0x80

    @property
    def mf(self) -> bool:
        return self.bytes[6] & 0x40 > 0

    @mf.setter
    def mf(self, value):
        self.bytes[6] &= 0xBF
        if value:
            self.bytes[6] |= 0x40

    @property
    def frag_offset(self) -> int:
        return int.from_bytes(self.bytes[6:8], "big") & 0x1FFF

    ttl = one_byte_accessor_property(8)
    proto = one_byte_accessor_property(9)

    @property
    def checksum(self) -> bytes:
        return self.bytes[10:12]

    def set_checksum(self):
        self.bytes[10:12] = calculate_checksum(self.bytes)

    def validate_checksum(self):
        return calculate_checksum(self.bytes) == self.checksum

    @property
    def src(self) -> IP4Addr:
        return IP4Addr(tuple(self.bytes[12:16]))

    @src.setter
    def src(self, ip):
        self.bytes[12:16] = bytes(ip)

    @property
    def dst(self) -> IP4Addr:
        return IP4Addr(tuple(self.bytes[16:20]))

    @dst.setter
    def dst(self, ip):
        self.bytes[16:20] = bytes(ip)

    body = body_accessor_property(20, delta=20)

    def format_bytes(self):
        s = ''.join(('{:02X}'.format(i) for i in self.bytes))
        return s

    def __str__(self):
        s = ' '.join(('[',
                      str(self.src), '->', str(self.dst),
                      protocols[self.proto],
                      '(' + str(self.proto) + ')',
                      ']'))
        return s

