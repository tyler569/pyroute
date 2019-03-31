
import os
import select

from ip import *
from icmp import ICMPPacket
from udp import UDPPacket
import intf

outer = intf.TunInterface("tun0")
inner = intf.TunInterface("tun0", "blue")

debug = False

def wait_for(*interfaces):
    ready = select.select(interfaces, [], [])
    return ready[0]

forward, drop, local = range(3)

routes = [
    # ( src,  dst,  ( action, params ) )
    ( IP4Range('0.0.0.0', 0), IP4Range('10.51.1.2', 32), (local,) ),
    ( IP4Range('0.0.0.0', 0), IP4Range('10.52.1.2', 32), (local,) ),
    ( IP4Range("0.0.0.0", 0), IP4Range("0.0.0.0",    0), (forward, outer) ),
    ( IP4Range('0.0.0.0', 0), IP4Range("10.52.0.0", 16), (forward, inner) ),
]


def route_packet(pkt: bytes):
    if not is_ip4(pkt):
        # nothing to do yet
        return

    ip4 = IP4Packet(pkt)
    if debug:
        print(ip4)
        print(ip4.format_bytes())

    if not ip4.validate_checksum():
        print("bad checksum, dropping")
        return

    if ip4.proto == 17: # UDP
        udp = UDPPacket(ip4.body)
        if not udp.validate_checksum(ip4.src, ip4.dst):
            print("bad udp checksum")
            return

    ip4.ttl -= 1
    if ip4.ttl <= 0:
        print("ttl expired, could send an ICMP ttl expired")
        return

    rs = routes[:]
    # pick routes that include the source
    rs = filter(lambda r: r[0].contains(ip4.src), rs)
    # pick routes that include the destination
    rs = filter(lambda r: r[1].contains(ip4.dst), rs)
    rs = list(rs)
    # sort by longest match
    rs.sort(key=lambda r: r[1].mask_bits, reverse=True)

    if len(rs) == 0:
        print('no route, dropping')
        return

    route = rs[0]
    rule = route[2][0]

    if rule == drop:
        print("explicit drop")

    elif rule == forward:
        if debug:
            print("sent to", route[2][1].name)
        os.write(route[2][1].fd, pkt)

    elif rule == local:
        if debug:
            print("local packet")
        local_packet(ip4)

    else:
        print("todo!")

def local_packet(pkt):
    if type(pkt) is not IP4Packet:
        raise TypeError('Local packets are only IPv4 for now')

    # respond to pings
    # respond to UDP state queries

    # general format:
    # craft a IP4Packet
    # route_packet(resp.bytes)

    if pkt.proto == 1: # ICMP
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
        route_packet(resp.bytes)
    elif pkt.proto == 17: # UDP
        udp = UDPPacket(pkt.body)
        print("UDP:", udp.src, '->', udp.dst)
        print("", str(udp.body))

        if udp.dst == 1500:
            resp_udp = UDPPacket()
            resp_udp.dst = udp.src
            resp_udp.src = udp.dst
            resp_udp.body = udp.body
            resp_udp.set_checksum(pkt.dst, pkt.src)

            resp = IP4Packet.new()
            resp.dst = pkt.src
            resp.src = pkt.dst
            resp.proto = 17 # UDP
            resp.ident = pkt.ident
            resp.body = resp_udp.bytes

            resp.set_checksum()
            route_packet(resp.bytes)

    else:
        print('local packet unhandled')


if __name__ == '__main__':
    while True:
        ready_intf = wait_for(outer, inner)
        intf = ready_intf[0]
        pkt = os.read(intf.fd, 2048)
        if debug:
            print("from:", intf.name, end=' : ')
        route_packet(pkt)

