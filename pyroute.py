
import os
import select

from ip import *
import intf

outer = intf.TunInterface("tun0")
inner = intf.TunInterface("tun0", "blue")

def wait_for(*interfaces):
    ready = select.select(interfaces, [], [])
    return ready[0]

forward, drop = range(2)

routes = [
    # ( src,  dst,  ( action, params ) )
    ( IP4Range("0.0.0.0", 0), IP4Range("0.0.0.0",    0), (forward, outer) ),
    ( IP4Range('0.0.0.0', 0), IP4Range("10.52.0.0", 16), (forward, inner) ),
]

while True:
    ready_intf = wait_for(outer, inner)
    intf = ready_intf[0]
    pkt = os.read(intf.fd, 2048)

    print("from:", intf.name, end=' : ')

    if not is_ip4(pkt):
        # nothing to do yet
        continue

    ip4 = IP4Packet(pkt)
    print(ip4)
    print(ip4.format_bytes())

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
        continue

    rule = rs[0]

    if rule[2][0] == drop:
        print("explicit drop")
    elif rule[2][0] == forward:
        if rule[2][1] is intf:
            print("not returning to sender")
            continue
        os.write(rule[2][1].fd, pkt)
        print("sent to", rule[2][1].name)
    else:
        print("todo!")

