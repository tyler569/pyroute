#!/bin/sh

TUN_NAME=${1:-tun0}
IP_RANGE=${2:-"10.50.1.1/24"}

ip tuntap add $TUN_NAME mode tun
ip link set dev $TUN_NAME up
ip addr add $IP_RANGE dev $TUN_NAME

