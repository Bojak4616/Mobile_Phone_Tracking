#!/usr/bin/python
import argparse
import os
from multiprocessing import Process
from scapy.all import *

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--iface', dest='iface', required=True, help="Interface to sniff on")
    parser.add_argument('-m', '--mac', dest='rMAC', required=True, help="Globally unique hardware MAC of the device to track")

    return parser.parse_args()


def _listen(iface, rMAC):
    try:
        sniff(prn=virtual_check(rMAC), iface=iface, store=0)
    except KeyboardInterrupt:
        exit('Exiting Process...')


def virtual_check(rMAC):
    def _virtual_check(pkt):
        if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.getlayer(Dot11).subtype == 4:
            # Make sure the local bit is set in the MAC
            if pkt.addr2 == rMAC:
                # Write to pipe
                with open('/tmp/pkts','wb') as PKT:
                    PKT.write(str(pkt))
                #MACS.append(pkt)
            if bin(int(pkt.addr2[:2],16))[2:].zfill(8)[-2] == "1":
                # Write to pipe
                with open('/tmp/pkts','wb') as PKT:
                    PKT.write(str(pkt))
                #MACS.append(pkt)
    return _virtual_check
        

def fingerprint(pkt):
    _fingerprint = ''
    try:
        for element in xrange(len(pkt.payload[Dot11Elt])/12):
            simple_pkt = pkt.payload[Dot11Elt][element]
            _fingerprint += '{}'.format(simple_pkt.ID)
    except IndexError:
        return _fingerprint

    return _fingerprint


# Function not used, but kept here for future use.
def send_resProbe(vMAC, iface, channel):
    subprocess.call(['iwconfig', iface, 'channel', str(channel)])
    rand_mac = "12:34:56:78:9a:bc"
    sendp(RadioTap()/Dot11(addr1=vMAC, addr2=rand_mac, addr3=rand_mac, subtype=5)/
      Dot11ProbeResp(cap="ESS")/
      Dot11Elt(ID="SSID",info="Give_MAC_Pls")/
      Dot11Elt(ID="DSset",info=chr(channel))/
      Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16')/
      Dot11Elt(ID="TIM",info="\x00\x01\x00\x00"), iface=iface)


def compare(rMAC):
    # This has to be one line for reasons unknown...
    base_pkt = RadioTap()/Dot11(addr1=RandMAC(), addr2=RandMAC(), addr3=RandMAC(), subtype=4)/Dot11ProbeReq()/Dot11Elt(ID=0, info='BASE')/Dot11Elt(ID=1, info='\x82\x84\x0b\x16\x24\x30\x48\x6c')/Dot11Elt(ID=50, info='\x0c\x12\x18\x60')

    vMAC_fingerprint = ''
    base_seq = -1
    curr_seq = 0
    # Send probe req to vMAC to get rMAC. if rMAC == args.rMAC: fingerprint packet
    try:
        while True:
            pkt = None
            with open('/tmp/pkts','rb') as PKT:
                    pkt = PKT.read()
                    # Reconstruct the packet
                    pkt = base_pkt.__class__(pkt)
            
            if not pkt:
                continue


            if pkt.addr2 == rMAC:
                print "MAC: {} still in range!".format(rMAC)
                # Rebase the sequence number, get first 3 bytes of the Sequence field
                base_seq = int(hex(pkt.SC)[2:5], 16)
                continue

            if base_seq == -1:
                # Need to wait for rMAC packet to begin fingerprinting vMACs
                continue

            # Make sure it is virtual before setting current
            if bin(int(pkt.addr2[:2],16))[2:].zfill(8)[-2] == "1":
                curr_seq = int(hex(pkt.SC)[2:5], 16)
            else:
                continue

            # Play with the appropriate threshold for optimization
            if  curr_seq - base_seq <= 25:

                # Have to take a bit of gamble making the initial fingerprint. No previous fingerprint to compare to.
                if not vMAC_fingerprint:
                    vMAC_fingerprint = fingerprint(pkt)

                print "within seq number, this is the fingerprint of vMAC: {} , currMAC:{}".format(vMAC_fingerprint, fingerprint(pkt))
                if vMAC_fingerprint == fingerprint(pkt):
                    base_seq = curr_seq
                    print "MAC: {} still in range using vMAC: {}!".format(rMAC, pkt.addr2)
            
                continue


            if curr_seq - base_seq <= 0 and vMAC_fingerprint == fingerprint(pkt):
                # Reabse again
                base_seq = curr_seq
                print "NEG -- MAC: {} still in range using vMAC: {}!".format(rMAC, pkt.addr2)
                continue

        print "Never"
    except KeyboardInterrupt:
        exit('Exiting...')


def main():
    args = parse_args()
    print args.iface, args.rMAC
    try:
        # Create a fresh pipe, deleting anything that was previously in there
        # Limit permissions so that other users can not read the pipe
        os.mkfifo('/tmp/pkts', 0600)
    except OSError:
        os.unlink('/tmp/pkts')
        os.mkfifo('/tmp/pkts', 0600)

    # Constant Listening for packets
    Process(target=_listen, args=(args.iface, args.rMAC,)).start()
    compare(args.rMAC)

    exit('Exiting main.py...')

if __name__ == '__main__':
        main()

