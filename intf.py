
import ctypes

dll = ctypes.CDLL("./libtun_alloc.so")

class TunInterface:
    # at this time, I don't have a way to return to the
    # default network namespace after changing to another.
    # I can still swap namespaces, but for now allocate
    # all default namespace interfaces first.
    netns_set = False

    def __init__(self, name, netns=None):
        if not netns and self.netns_set:
            raise ValueError("Cannot set default ns after changing ns")
        if netns:
            dll.set_netns(bytes(netns, "latin1"))
            self.netns_set = True
        self.fd = dll.tun_alloc(bytes(name, "latin1"))
        if self.fd == -1:
            raise ValueError("Error creating interface")
        self.name_ = name
        self.netns = netns

    def fileno(self):
        return self.fd

    @property
    def name(self):
        if self.netns:
            return self.netns + ":" + self.name_
        else:
            return self.name_

