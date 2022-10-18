#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http


def get_mac(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,
                              timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def sniffer(interface):
    scapy.sniff(iface=interface, store=False,
                prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = get_mac(packet[scapy.ARP].hwsrc)
            if real_mac != response_mac:
                print('[+] You\'re under attack!')
        except IndexError:
            pass


sniffer('eth0')
