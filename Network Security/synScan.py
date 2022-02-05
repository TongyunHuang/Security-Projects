from scapy.all import *

import sys
# python3 synScan.py eth0 10.4.22.125

def debug(s):
    print('#{0}'.format(s))
    sys.stdout.flush()

if __name__ == "__main__":
    conf.iface = sys.argv[1]
    ip_addr = sys.argv[2]

    my_ip = get_if_addr(sys.argv[1])
    
    # SYN scan
    # sending one packet and receive on back
    
    for i in range(1,1025):
        resp = sr1( IP(dst=ip_addr) / TCP(flags="S", dport=i), verbose=0, timeout=10 )

        # on success, 
        if resp.getlayer("TCP").flags == 'SA':
            sendp(Ether() / IP(dst=ip_addr) / TCP(flags="R", dport=i ))
            print(ip_addr + ',' + str(i) )
        
    
