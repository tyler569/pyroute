
def calculate_checksum(pkt):
    pkt[2:4] = b'\0\0' # checksum is 0 for the purpose of this

    # this is basically copypasta from ipv4 checksum
    # factor out?
    pairs = zip(pkt[::2], pkt[1::2])
    pairs = map(lambda x: bytes(x), pairs)
    pairs = map(lambda x: int.from_bytes(x, 'big'), pairs)
    pairs = list(pairs)

    return ((~sum(pairs) & 0xFFFF) - 1).to_bytes(2, 'big')


class ICMPPacket:
    def __init__(self, bytes):
        self.bytes = bytes

    @property
    def type(self) -> int:
        return self.bytes[0]

    @type.setter
    def type(self, value):
        self.bytes[0] = value

    @property
    def code(self) -> int:
        return self.bytes[1]

    @code.setter
    def code(self, value):
        self.bytes[1] = value

    @property
    def checksum(self) -> bytes:
        return self.bytes[2:4]

    def set_checksum(self):
        self.bytes[2:4] = calculate_checksum(self.bytes)

    def validate_checksum(self):
        return calculate_checksum(self) == self.checksum

    @property
    def ident(self) -> int:
        return int.from_bytes(self.bytes[4:6], 'big')

    @ident.setter
    def ident(self, value):
        self.bytes[4:6] = value.to_bytes(2, 'big')

    @property
    def seq(self) -> int:
        return int.from_bytes(self.bytes[6:8])

    @seq.setter
    def seq(self, value):
        self.bytes[6:8] = value.bytes(2, 'big')

    @property
    def body(self) -> bytes:
        return self.bytes[8:]

