
from ip import *
from udp import *

route_packet = None

class Socket:
    def __init__(self, proto, bind, connect):
        self.proto = proto
        self.bind = bind
        self.connect = connect
        self.ident = 3838

    def match(self, ip):
        udp = UDPPacket(ip.body)
        return self.proto == ip.proto and self.bind == (ip.dst, udp.dst) and self.connect == (ip.src, udp.src)

    def handle(self, pkt_data):
        raise NotImplemented

    def recv_pkt(self, ip: IP4Packet):
        self.ident = ip.ident
        udp = UDPPacket(ip.body)
        self.handle(udp.body)

    def send_pkt(self, data: bytes):
        if self.proto != 17: # udp
            raise ValueError('unsupported protocol')

        udp = UDPPacket()
        udp.dst = self.connect[1]
        udp.src = self.bind[1]
        udp.body = data
        udp.length = len(data) + 8
        udp.set_checksum(self.connect[0], self.bind[0])

        ip = IP4Packet.new()
        ip.src = self.bind[0]
        ip.dst = self.connect[0]
        ip.ttl = 64
        ip.ident = self.ident
        ip.proto = self.proto
        ip.body = udp.bytes
        ip.set_checksum()

        route_packet(ip.bytes)

    def __str__(self):
        return (
            self.__class__.__name__ + "(" +
            str(self.proto) + ", " +
            str(self.bind) + ", " +
            str(self.connect) + ")"
        )


class ListeningSocket(Socket):
    def __init__(self, proto, bind, next, *next_args, **next_kwargs):
        super().__init__(proto, bind, None)
        self.next_type = next
        self.next_args = next_args
        self.next_kwargs = next_kwargs

    def match(self, ip):
        udp = UDPPacket(ip.body)
        return self.bind == udp.dst

    def recv_pkt(self, ip: IP4Packet):
        udp = UDPPacket(ip.body)
        new_socket = self.next_type(self.proto, (ip.dst, udp.dst), (ip.src, udp.src), *self.next_args, **self.next_kwargs)
        socket_table.append(new_socket)
        new_socket.recv_pkt(ip)


class EchoServer(Socket):
    def __init__(self, proto, bind, connect, add_str):
        super().__init__(proto, bind, connect)
        self.add_str = bytes(add_str, 'utf8')

    def handle(self, pkt_data):
        print("echo handling packet")
        self.send_pkt(self.add_str + pkt_data)

udp = 17

socket_table = [
    ListeningSocket(udp, 1000, EchoServer, "1000"),
    ListeningSocket(udp, 1001, EchoServer, "1001"),
]

def look_up_socket_and_forward(pkt):
    ip = IP4Packet(pkt)
    if ip.proto != 17: #udp
        return

    # checksum or not

    udp = UDPPacket(ip.body)

    # ensure that listening sockets are hit last
    socket_table.sort(key=lambda s: type(s) is ListeningSocket)

    for socket in socket_table:
        if socket.match(ip):
            socket.recv_pkt(ip)
            break
    else:
        print('there was no match')

