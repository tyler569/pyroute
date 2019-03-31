
def ones_comp_16b_sum(b: bytes) -> bytes:
    pairs = zip(b[::2], b[1::2])
    pairs = map(lambda x: bytes(x), pairs)
    pairs = map(lambda x: int.from_bytes(x, 'big'), pairs)
    pairs = list(pairs)

    s = sum(pairs)
    v = s & 0xFFFF
    rest = s >> 16
    v += rest

    return (~v & 0xFFFF).to_bytes(2, 'big')

def one_byte_accessor_property(offset) -> property:
    def _get(self) -> int:
        return self.bytes[offset]

    def _set(self, value):
        self.bytes[offset] = value

    return property(_get, _set)

def two_byte_accessor_property(offset) -> property:
    def _get(self) -> int:
        return int.from_bytes(self.bytes[offset:offset+2], 'big')

    def _set(self, value):
        self.bytes[offset:offset+2] = value.to_bytes(2, 'big')

    return property(_get, _set)

def four_byte_accessor_property(offset) -> property:
    def _get(self) -> int:
        return int.from_bytes(self.bytes[offset:offset+4], 'big')

    def _set(self, value):
        self.bytes[offset:offset+4] = value.to_bytes(4, 'big')

    return property(_get, _set)

def bit_accessor_property(offset, bit) -> property:
    def _get(self) -> bool:
        return self.bytes[offset] & (1 << bit) > 0

    def _set(self, value):
        self.bytes[offset] &= (~(1 << bit)) & 0xFF
        if value:
            self.bytes[offset] |= (1 << bit)

    return property(_get, _set)

def body_accessor_property(offset, delta=None) -> property:
    def _get(self) -> bytes:
        return self.bytes[offset:]

    def _set(self, value):
        self.bytes[offset:] = value
        if delta is not None:
            self.length = len(value) + delta

    return property(_get, _set)

