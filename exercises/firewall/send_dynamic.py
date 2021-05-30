#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP, DNS, ICMP

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<1:
        print('pass 1 arguments: <destination>')
        exit(1)

    addr = socket.gethostbyname("10.0.1.1")
    iface = get_if()

    print(("sending on interface %s to %s" % (iface, str(addr))))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt_dns = pkt / IP(dst=addr) / UDP(dport=53) / DNS(id = 111,qr = 0,opcode = 0,rd = 1) / "attack"
    pkt_udp = pkt / IP(dst=addr) / UDP(sport=53)/ "attack"
    pkt_tcp = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / "attack"
    pkt_icmp = pkt /IP(dst=addr) / ICMP(type=0) / "attack"
    for pac in range(1000):
        # 20 packets per sec
        # 60 packets per sec
        sendp(pkt_dns, iface=iface, verbose=False)
        sendp(pkt_udp, iface=iface, verbose=False)
        sendp(pkt_tcp, iface=iface, verbose=False)
    #pkt.show2()
    #sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
