#!/usr/bin/python

import argparse
from scapy.all import *
from sys import exit

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i','--iface', dest='iface', required=True, help='Interface to sniff on')

    return parser.parse_args()


# Return array of found virtual MAC addresses
# Google CID DA:A1:19 prefix
def virtual_check(pkt):
    global vMACS
    
    # Check to see if the packet is a management Dot11 frame 
    if pkt.haslayer(Dot11) and pkt.type == 0:
        # Make sure the local bit is set in the MAC
        if bin(int(pkt.addr2[:2],16))[2:].zfill(8)[-2] == "1":
            if pkt.addr2 not in vMACS:
                print pkt.addr2
                vMACS.append(pkt.addr2)
            

def main():
    args = parse_args()
    global vMACS
    vMACS = []
    print '[*] Ctrl+C to stop capturing'
    sniff(prn=virtual_check, iface=args.iface, store=0)

    exit(0)


if __name__ == '__main__':
    main()

