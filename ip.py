
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
        self.bytes = bytes

    @property
    def version(self) -> int:
        return self.bytes[0] >> 4

    @version.setter
    def set_version(self, version):
        self.bytes[0] &= 0x0F
        self.bytes[0] |= version << 4

    @property
    def ihl(self) -> int:
        return self.bytes[0] & 0x0F

    @ihl.setter
    def set_ihl(self, ihl):
        self.bytes[0] &= 0xF0
        self.bytes[0] |= ihl

    @property
    def dscp(self) -> int:
        return self.bytes[1] >> 2

    @property
    def ecn(self) -> int:
        return self.bytes[1] & 0x03

    @property
    def length(self) -> int:
        return int.from_bytes(self.bytes[2:4], "big")

    @property
    def ident(self) -> int:
        return int.from_bytes(self.bytes[4:6], "big")

    @property
    def dnf(self) -> bool:
        return self.bytes[6] & 0x80 > 0

    @property
    def mf(self) -> bool:
        return self.bytes[6] & 0x40 > 0

    @property
    def frag_offset(self) -> int:
        return int.from_bytes(self.bytes[6:8], "big") & 0x1FFF

    @property
    def ttl(self) -> int:
        return self.bytes[8]

    @ttl.setter
    def set_ttl(self, value):
        self.bytes[8] = value

    @property
    def proto(self) -> int:
        return self.bytes[9]

    @property
    def checksum(self) -> bytes:
        return self.bytes[10:12]

    @checksum.setter
    def set_checksum(self):
        # TODO: calculate checksum
        pass

    @property
    def src(self) -> IP4Addr:
        return IP4Addr(tuple(self.bytes[12:16]))

    @src.setter
    def set_src(self, ip):
        self.bytes[12:16] = bytes(ip)

    @property
    def dst(self) -> IP4Addr:
        return IP4Addr(tuple(self.bytes[16:20]))

    @dst.setter
    def set_dst(self, ip):
        self.bytes[16:20] = bytes(ip)

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

