
import ctypes
import os
from socket import look_up_socket_and_forward

dll = ctypes.CDLL("./libtun_alloc.so")

class Interface:
    def __init__(self, name):
        self.name_ = name
        self.netns = None

    def send_to(self, pkt):
        raise NotImplemented

    @property
    def name(self):
        if self.netns:
            return self.netns + ":" + self.name_
        else:
            return self.name_


class TunInterface(Interface):
    # at this time, I don't have a way to return to the
    # default network namespace after changing to another.
    # I can still swap namespaces, but for now allocate
    # all default namespace interfaces first.
    netns_set = False

    def __init__(self, name, netns=None):
        super().__init__(name)

        if not netns and self.netns_set:
            raise ValueError("Cannot set default ns after changing ns")

        if netns:
            dll.set_netns(bytes(netns, "latin1"))
            self.netns_set = True
        self.fd = dll.tun_alloc(bytes(name, "latin1"))
        if self.fd == -1:
            raise ValueError("Error creating interface")

    def fileno(self):
        return self.fd

    def read_packet(self):
        return os.read(self.fd, 2048)

    def write_packet(self, pkt: bytes):
        return os.write(self.fd, pkt)

    def send_to(self, pkt):
        return self.write_packet(pkt)


class LocalInterface(Interface):
    def send_to(self, pkt):
        return look_up_socket_and_forward(pkt)

