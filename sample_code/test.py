import socket
import fcntl
import struct
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Elt, Dot11ProbeReq
from scapy.sendrecv import sniff, sendp

def get_hw_addr(ifname):
    """
    Return the MAC address associated with a network interface, available only on Linux
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

def send_probe_req(essid):
    interface = "wlp0s20u6mon"
    bssid = get_hw_addr(interface)
    source_mac = get_hw_addr(interface)
    timeout = 1.5
    sendp(
        RadioTap()/
        Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=source_mac, addr3=bssid, subtype=4)/
        Dot11ProbeReq()/
        Dot11Elt(ID=0, info=essid)/
        Dot11Elt(ID=1, info='\x82\x84\x0b\x16\x24\x30\x48\x6c')/
        Dot11Elt(ID=50, info='\x0c\x12\x18\x60'),
        iface=interface,
        verbose=True
    )
    sniff(iface=interface, store=0, timeout=timeout)

send_probe_req("RIT")
